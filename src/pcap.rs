use std::net::Ipv4Addr;
use std::path::Path;

use anyhow::{Context, Result, ensure};

use crate::activity::Execution;
use crate::scenario::Protocol;

const GLOBAL_HEADER_LEN: usize = 24;
const PACKET_HEADER_LEN: usize = 16;
const ETHERNET_HEADER_LEN: usize = 14;
const IPV4_MIN_HEADER_LEN: usize = 20;
const ETHERTYPE_IPV4: u16 = 0x0800;
const IP_PROTO_TCP: u8 = 6;
const IP_PROTO_UDP: u8 = 17;
const IP_PROTO_ICMP: u8 = 1;

/// Extracts source ports from pcap captures and fills them into the
/// corresponding executions.
///
/// For each execution, finds the first packet in any `.pcap` file under
/// `net_dir` whose (`src_ip`, `dst_ip`, `dst_port`, `protocol`) tuple matches
/// within the execution's time window.
pub(crate) fn enrich_src_ports(net_dir: &Path, executions: &mut [Execution]) -> Result<()> {
    let packets = read_all_packets(net_dir)?;
    for exec in executions.iter_mut() {
        let start_ts = exec.start.timestamp();
        let end_ts = exec.end.timestamp();
        exec.src_port = packets
            .iter()
            .find(|p| {
                p.src_ip == exec.src_ip
                    && p.dst_ip == exec.dst_ip
                    && p.dst_port == exec.dst_port
                    && p.protocol == exec.protocol
                    && p.ts >= start_ts
                    && p.ts <= end_ts + 1
            })
            .map(|p| p.src_port)
            .with_context(|| {
                format!(
                    "no packet in pcap matching {} -> {}:{} ({:?}) between {} and {}",
                    exec.src_ip, exec.dst_ip, exec.dst_port, exec.protocol, exec.start, exec.end,
                )
            })?;
    }
    Ok(())
}

struct Packet {
    ts: i64,
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    protocol: Protocol,
    src_port: u16,
    dst_port: u16,
}

fn read_all_packets(net_dir: &Path) -> Result<Vec<Packet>> {
    let mut packets = Vec::new();
    for entry in std::fs::read_dir(net_dir)
        .with_context(|| format!("failed to read net dir: {}", net_dir.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) == Some("pcap") {
            packets.extend(parse_pcap(&path)?);
        }
    }
    Ok(packets)
}

fn parse_pcap(path: &Path) -> Result<Vec<Packet>> {
    let data =
        std::fs::read(path).with_context(|| format!("failed to read pcap: {}", path.display()))?;
    ensure!(
        data.len() >= GLOBAL_HEADER_LEN,
        "pcap file too short: {}",
        path.display(),
    );

    let le = match data.get(..4) {
        Some([0xd4, 0xc3, 0xb2, 0xa1]) => true,
        Some([0xa1, 0xb2, 0xc3, 0xd4]) => false,
        _ => anyhow::bail!("not a valid pcap file: {}", path.display()),
    };

    let mut offset = GLOBAL_HEADER_LEN;
    let mut packets = Vec::new();

    while offset + PACKET_HEADER_LEN <= data.len() {
        let ts_sec = read_u32(&data, offset, le);
        let incl_len = read_u32(&data, offset + 8, le);

        let Some(incl_len) = usize::try_from(incl_len).ok() else {
            break;
        };
        let pkt_start = offset + PACKET_HEADER_LEN;
        if pkt_start + incl_len > data.len() {
            break; // truncated (file may still be written by tcpdump)
        }

        if let Some(pkt_data) = data.get(pkt_start..pkt_start + incl_len)
            && let Some(pkt) = parse_ethernet_packet(pkt_data, i64::from(ts_sec))
        {
            packets.push(pkt);
        }

        offset = pkt_start + incl_len;
    }

    Ok(packets)
}

/// Reads a little- or big-endian `u32` at the given offset.
///
/// Returns 0 if the slice is too short (caller bounds-checks via the
/// while-loop condition, so this is a defensive fallback).
fn read_u32(data: &[u8], offset: usize, le: bool) -> u32 {
    let Some(bytes) = data.get(offset..offset + 4) else {
        return 0;
    };
    // Safety: slice is exactly 4 bytes, try_into always succeeds.
    let arr: [u8; 4] = bytes.try_into().expect("slice is guaranteed to be 4 bytes");
    if le {
        u32::from_le_bytes(arr)
    } else {
        u32::from_be_bytes(arr)
    }
}

fn parse_ethernet_packet(data: &[u8], ts: i64) -> Option<Packet> {
    if data.len() < ETHERNET_HEADER_LEN + IPV4_MIN_HEADER_LEN {
        return None;
    }

    let ethertype = u16::from_be_bytes([*data.get(12)?, *data.get(13)?]);
    if ethertype != ETHERTYPE_IPV4 {
        return None;
    }

    let ip = data.get(ETHERNET_HEADER_LEN..)?;
    let ihl = usize::from(ip.first()? & 0x0f) * 4;
    if ip.len() < ihl + 4 {
        return None;
    }

    let ip_proto = *ip.get(9)?;
    let src_ip = Ipv4Addr::new(*ip.get(12)?, *ip.get(13)?, *ip.get(14)?, *ip.get(15)?);
    let dst_ip = Ipv4Addr::new(*ip.get(16)?, *ip.get(17)?, *ip.get(18)?, *ip.get(19)?);

    let transport = ip.get(ihl..)?;

    match ip_proto {
        IP_PROTO_TCP | IP_PROTO_UDP if transport.len() >= 4 => {
            let src_port = u16::from_be_bytes([*transport.first()?, *transport.get(1)?]);
            let dst_port = u16::from_be_bytes([*transport.get(2)?, *transport.get(3)?]);
            let protocol = if ip_proto == IP_PROTO_TCP {
                Protocol::Tcp
            } else {
                Protocol::Udp
            };
            Some(Packet {
                ts,
                src_ip,
                dst_ip,
                protocol,
                src_port,
                dst_port,
            })
        }
        IP_PROTO_ICMP => Some(Packet {
            ts,
            src_ip,
            dst_ip,
            protocol: Protocol::Icmp,
            src_port: 0,
            dst_port: 0,
        }),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── pcap file construction helpers ────────────────────────────

    fn pcap_global_header() -> Vec<u8> {
        let mut buf = Vec::with_capacity(GLOBAL_HEADER_LEN);
        buf.extend_from_slice(&0xa1b2_c3d4_u32.to_le_bytes()); // magic (LE)
        buf.extend_from_slice(&2u16.to_le_bytes()); // version major
        buf.extend_from_slice(&4u16.to_le_bytes()); // version minor
        buf.extend_from_slice(&0i32.to_le_bytes()); // thiszone
        buf.extend_from_slice(&0u32.to_le_bytes()); // sigfigs
        buf.extend_from_slice(&65535u32.to_le_bytes()); // snaplen
        buf.extend_from_slice(&1u32.to_le_bytes()); // link type (Ethernet)
        buf
    }

    fn pcap_packet_record(ts_sec: u32, payload: &[u8]) -> Vec<u8> {
        let len = u32::try_from(payload.len()).unwrap();
        let mut buf = Vec::with_capacity(PACKET_HEADER_LEN + payload.len());
        buf.extend_from_slice(&ts_sec.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes()); // ts_usec
        buf.extend_from_slice(&len.to_le_bytes()); // incl_len
        buf.extend_from_slice(&len.to_le_bytes()); // orig_len
        buf.extend_from_slice(payload);
        buf
    }

    fn tcp_frame(src_ip: [u8; 4], dst_ip: [u8; 4], src_port: u16, dst_port: u16) -> Vec<u8> {
        let mut pkt = Vec::new();
        // Ethernet header
        pkt.extend_from_slice(&[0u8; 12]); // dst + src MAC
        pkt.extend_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
        // IPv4 header (20 bytes, IHL=5)
        pkt.push(0x45); // version=4, ihl=5
        pkt.push(0); // tos
        pkt.extend_from_slice(&40u16.to_be_bytes()); // total_len = 20 IP + 20 TCP
        pkt.extend_from_slice(&[0; 4]); // id + flags/frag
        pkt.push(64); // ttl
        pkt.push(IP_PROTO_TCP);
        pkt.extend_from_slice(&[0; 2]); // checksum
        pkt.extend_from_slice(&src_ip);
        pkt.extend_from_slice(&dst_ip);
        // TCP header (20 bytes)
        pkt.extend_from_slice(&src_port.to_be_bytes());
        pkt.extend_from_slice(&dst_port.to_be_bytes());
        pkt.extend_from_slice(&[0; 16]); // seq, ack, offset/flags, window, checksum, urg
        pkt
    }

    fn udp_frame(src_ip: [u8; 4], dst_ip: [u8; 4], src_port: u16, dst_port: u16) -> Vec<u8> {
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&[0u8; 12]);
        pkt.extend_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
        pkt.push(0x45);
        pkt.push(0);
        pkt.extend_from_slice(&28u16.to_be_bytes()); // 20 IP + 8 UDP
        pkt.extend_from_slice(&[0; 4]);
        pkt.push(64);
        pkt.push(IP_PROTO_UDP);
        pkt.extend_from_slice(&[0; 2]);
        pkt.extend_from_slice(&src_ip);
        pkt.extend_from_slice(&dst_ip);
        pkt.extend_from_slice(&src_port.to_be_bytes());
        pkt.extend_from_slice(&dst_port.to_be_bytes());
        pkt.extend_from_slice(&[0; 4]); // length + checksum
        pkt
    }

    fn write_pcap(dir: &Path, name: &str, packets: &[(u32, Vec<u8>)]) {
        let mut data = pcap_global_header();
        for (ts, payload) in packets {
            data.extend(pcap_packet_record(*ts, payload));
        }
        std::fs::write(dir.join(name), data).unwrap();
    }

    // ── parse_ethernet_packet ────────────────────────────────────

    #[test]
    fn parse_tcp_packet() {
        let frame = tcp_frame([10, 0, 0, 2], [10, 0, 0, 3], 49152, 80);
        let pkt = parse_ethernet_packet(&frame, 1000).unwrap();
        assert_eq!(pkt.src_ip, Ipv4Addr::new(10, 0, 0, 2));
        assert_eq!(pkt.dst_ip, Ipv4Addr::new(10, 0, 0, 3));
        assert_eq!(pkt.src_port, 49152);
        assert_eq!(pkt.dst_port, 80);
        assert_eq!(pkt.protocol, Protocol::Tcp);
        assert_eq!(pkt.ts, 1000);
    }

    #[test]
    fn parse_udp_packet() {
        let frame = udp_frame([172, 16, 0, 1], [172, 16, 0, 2], 5353, 53);
        let pkt = parse_ethernet_packet(&frame, 2000).unwrap();
        assert_eq!(pkt.protocol, Protocol::Udp);
        assert_eq!(pkt.src_port, 5353);
        assert_eq!(pkt.dst_port, 53);
    }

    #[test]
    fn parse_non_ipv4_returns_none() {
        let mut frame = tcp_frame([10, 0, 0, 1], [10, 0, 0, 2], 100, 200);
        // Change ethertype to IPv6 (0x86DD)
        frame[12] = 0x86;
        frame[13] = 0xDD;
        assert!(parse_ethernet_packet(&frame, 0).is_none());
    }

    #[test]
    fn parse_truncated_frame_returns_none() {
        assert!(parse_ethernet_packet(&[0; 10], 0).is_none());
    }

    #[test]
    fn parse_truncated_transport_returns_none() {
        let mut frame = tcp_frame([10, 0, 0, 1], [10, 0, 0, 2], 100, 200);
        // Truncate to just past IP header (no TCP data)
        frame.truncate(ETHERNET_HEADER_LEN + IPV4_MIN_HEADER_LEN + 2);
        assert!(parse_ethernet_packet(&frame, 0).is_none());
    }

    // ── parse_pcap ───────────────────────────────────────────────

    #[test]
    fn parse_pcap_reads_multiple_packets() {
        let dir = tempfile::tempdir().unwrap();
        let pkt1 = tcp_frame([10, 0, 0, 2], [10, 0, 0, 3], 49152, 80);
        let pkt2 = tcp_frame([10, 0, 0, 2], [10, 0, 0, 3], 50000, 443);
        write_pcap(dir.path(), "test.pcap", &[(100, pkt1), (200, pkt2)]);

        let packets = parse_pcap(&dir.path().join("test.pcap")).unwrap();
        assert_eq!(packets.len(), 2);
        assert_eq!(packets[0].src_port, 49152);
        assert_eq!(packets[1].src_port, 50000);
    }

    #[test]
    fn parse_pcap_empty_file_errors() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("empty.pcap"), []).unwrap();
        assert!(parse_pcap(&dir.path().join("empty.pcap")).is_err());
    }

    #[test]
    fn parse_pcap_invalid_magic_errors() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("bad.pcap"), [0u8; 24]).unwrap();
        assert!(parse_pcap(&dir.path().join("bad.pcap")).is_err());
    }

    #[test]
    fn parse_pcap_header_only_returns_empty() {
        let dir = tempfile::tempdir().unwrap();
        write_pcap(dir.path(), "header-only.pcap", &[]);
        let packets = parse_pcap(&dir.path().join("header-only.pcap")).unwrap();
        assert!(packets.is_empty());
    }

    #[test]
    fn parse_pcap_tolerates_truncated_packet_at_end() {
        let dir = tempfile::tempdir().unwrap();
        let pkt = tcp_frame([10, 0, 0, 2], [10, 0, 0, 3], 49152, 80);
        let mut data = pcap_global_header();
        data.extend(pcap_packet_record(100, &pkt));
        // Append a truncated packet header (only 8 of 16 bytes)
        data.extend_from_slice(&[0u8; 8]);
        std::fs::write(dir.path().join("trunc.pcap"), data).unwrap();

        let packets = parse_pcap(&dir.path().join("trunc.pcap")).unwrap();
        assert_eq!(packets.len(), 1);
    }

    // ── enrich_src_ports ─────────────────────────────────────────

    fn make_execution(
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        dst_port: u16,
        protocol: Protocol,
        ts: i64,
    ) -> Execution {
        use chrono::TimeZone;
        let start = chrono::Utc.timestamp_opt(ts, 0).unwrap();
        let end = chrono::Utc.timestamp_opt(ts + 1, 0).unwrap();
        Execution {
            start,
            end,
            source: "src".to_owned(),
            target: "dst".to_owned(),
            protocol,
            src_ip,
            dst_ip,
            dst_port,
            src_port: 0,
            attack: None,
        }
    }

    #[test]
    fn enrich_fills_src_port_from_pcap() {
        let dir = tempfile::tempdir().unwrap();
        let pkt = tcp_frame([10, 0, 0, 2], [10, 0, 0, 3], 49152, 80);
        write_pcap(dir.path(), "capture.pcap", &[(1000, pkt)]);

        let mut execs = vec![make_execution(
            Ipv4Addr::new(10, 0, 0, 2),
            Ipv4Addr::new(10, 0, 0, 3),
            80,
            Protocol::Tcp,
            1000,
        )];
        enrich_src_ports(dir.path(), &mut execs).unwrap();
        assert_eq!(execs[0].src_port, 49152);
    }

    #[test]
    fn enrich_matches_by_time_window() {
        let dir = tempfile::tempdir().unwrap();
        // Two packets to same dst, different times and src_ports.
        let pkt1 = tcp_frame([10, 0, 0, 2], [10, 0, 0, 3], 49152, 80);
        let pkt2 = tcp_frame([10, 0, 0, 2], [10, 0, 0, 3], 50000, 80);
        write_pcap(dir.path(), "capture.pcap", &[(1000, pkt1), (2000, pkt2)]);

        let mut execs = vec![
            make_execution(
                Ipv4Addr::new(10, 0, 0, 2),
                Ipv4Addr::new(10, 0, 0, 3),
                80,
                Protocol::Tcp,
                1000,
            ),
            make_execution(
                Ipv4Addr::new(10, 0, 0, 2),
                Ipv4Addr::new(10, 0, 0, 3),
                80,
                Protocol::Tcp,
                2000,
            ),
        ];
        enrich_src_ports(dir.path(), &mut execs).unwrap();
        assert_eq!(execs[0].src_port, 49152);
        assert_eq!(execs[1].src_port, 50000);
    }

    #[test]
    fn enrich_errors_when_no_matching_packet() {
        let dir = tempfile::tempdir().unwrap();
        // Packet to port 443, but execution expects port 80.
        let pkt = tcp_frame([10, 0, 0, 2], [10, 0, 0, 3], 49152, 443);
        write_pcap(dir.path(), "capture.pcap", &[(1000, pkt)]);

        let mut execs = vec![make_execution(
            Ipv4Addr::new(10, 0, 0, 2),
            Ipv4Addr::new(10, 0, 0, 3),
            80,
            Protocol::Tcp,
            1000,
        )];
        assert!(enrich_src_ports(dir.path(), &mut execs).is_err());
    }

    #[test]
    fn enrich_empty_executions_succeeds() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path()).unwrap();
        let mut execs: Vec<Execution> = vec![];
        enrich_src_ports(dir.path(), &mut execs).unwrap();
    }

    #[test]
    fn enrich_reads_multiple_pcap_files() {
        let dir = tempfile::tempdir().unwrap();
        let pkt1 = tcp_frame([10, 0, 0, 2], [10, 0, 0, 3], 49152, 80);
        let pkt2 = tcp_frame([172, 16, 0, 2], [172, 16, 0, 3], 51000, 443);
        write_pcap(dir.path(), "capture-lan.pcap", &[(1000, pkt1)]);
        write_pcap(dir.path(), "capture-dmz.pcap", &[(1000, pkt2)]);

        let mut execs = vec![
            make_execution(
                Ipv4Addr::new(10, 0, 0, 2),
                Ipv4Addr::new(10, 0, 0, 3),
                80,
                Protocol::Tcp,
                1000,
            ),
            make_execution(
                Ipv4Addr::new(172, 16, 0, 2),
                Ipv4Addr::new(172, 16, 0, 3),
                443,
                Protocol::Tcp,
                1000,
            ),
        ];
        enrich_src_ports(dir.path(), &mut execs).unwrap();
        assert_eq!(execs[0].src_port, 49152);
        assert_eq!(execs[1].src_port, 51000);
    }

    #[test]
    fn enrich_ignores_non_pcap_files() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("readme.txt"), "not a pcap").unwrap();
        let pkt = tcp_frame([10, 0, 0, 2], [10, 0, 0, 3], 49152, 80);
        write_pcap(dir.path(), "capture.pcap", &[(1000, pkt)]);

        let mut execs = vec![make_execution(
            Ipv4Addr::new(10, 0, 0, 2),
            Ipv4Addr::new(10, 0, 0, 3),
            80,
            Protocol::Tcp,
            1000,
        )];
        enrich_src_ports(dir.path(), &mut execs).unwrap();
        assert_eq!(execs[0].src_port, 49152);
    }
}
