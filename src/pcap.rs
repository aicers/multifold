use std::net::Ipv4Addr;
use std::path::Path;

use anyhow::{Context, Result, anyhow, bail, ensure};
use chrono::{DateTime, Utc};

use crate::activity::Execution;
use crate::scenario::Protocol;
use crate::time::{ExecAnchor, TimeMap, rewrite_ts};

const GLOBAL_HEADER_LEN: usize = 24;
const PACKET_HEADER_LEN: usize = 16;
const ETHERNET_HEADER_LEN: usize = 14;
const IPV4_MIN_HEADER_LEN: usize = 20;
const ETHERTYPE_IPV4: u16 = 0x0800;
const IP_PROTO_TCP: u8 = 6;
const IP_PROTO_UDP: u8 = 17;
const IP_PROTO_ICMP: u8 = 1;

// Microsecond-resolution PCAP magics (the existing reader handles
// both endians; reuse the same byte patterns for the rewriter).
const PCAP_MAGIC_US_LE: [u8; 4] = [0xd4, 0xc3, 0xb2, 0xa1];
const PCAP_MAGIC_US_BE: [u8; 4] = [0xa1, 0xb2, 0xc3, 0xd4];
// Nanosecond-resolution PCAP magics (out of scope; rejected
// distinctly so authors don't silently corrupt sub-second timing).
const PCAP_MAGIC_NS_LE: [u8; 4] = [0x4d, 0x3c, 0xb2, 0xa1];
const PCAP_MAGIC_NS_BE: [u8; 4] = [0xa1, 0xb2, 0x3c, 0x4d];
// pcapng Section Header Block type (endian-independent).
const PCAPNG_SHB_MAGIC: [u8; 4] = [0x0a, 0x0d, 0x0d, 0x0a];

const TS_USEC_MAX_EXCLUSIVE: u32 = 1_000_000;
const U32_MAX_AS_I64: i64 = u32::MAX as i64;

/// Extracts source ports from pcap captures and fills them into the
/// corresponding executions.
///
/// For each execution, finds the first packet in any `.pcap` file under
/// `net_dir` whose (`src_ip`, `dst_ip`, `dst_port`, `protocol`) tuple matches
/// within the execution's time window.  Matched packets are consumed so
/// that no single packet is reused across executions.  Timestamps are
/// compared at microsecond precision.
pub(crate) fn enrich_src_ports(net_dir: &Path, executions: &mut [Execution]) -> Result<()> {
    let mut packets = read_all_packets(net_dir)?;
    for exec in executions.iter_mut() {
        if exec.exit_code != 0 {
            continue;
        }
        let start_us = exec.start.timestamp_micros();
        let end_us = exec.end.timestamp_micros() + 1_000_000;
        let idx = packets
            .iter()
            .position(|p| {
                p.ts_us >= start_us
                    && p.ts_us <= end_us
                    && p.src_ip == exec.src_ip
                    && p.dst_ip == exec.dst_ip
                    && p.dst_port == exec.dst_port
                    && p.protocol == exec.protocol
            })
            .with_context(|| {
                format!(
                    "no packet in pcap matching {} -> {}:{} ({:?}) between {} and {}",
                    exec.src_ip, exec.dst_ip, exec.dst_port, exec.protocol, exec.start, exec.end,
                )
            })?;
        exec.src_port = packets[idx].src_port;
        packets.remove(idx);
    }
    Ok(())
}

pub(crate) struct Packet {
    pub(crate) ts_us: i64,
    pub(crate) src_ip: Ipv4Addr,
    pub(crate) dst_ip: Ipv4Addr,
    pub(crate) protocol: Protocol,
    pub(crate) src_port: u16,
    pub(crate) dst_port: u16,
}

pub(crate) fn read_all_packets(net_dir: &Path) -> Result<Vec<Packet>> {
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

#[allow(clippy::similar_names)] // ts_sec / ts_usec are pcap spec field names
pub(crate) fn parse_pcap(path: &Path) -> Result<Vec<Packet>> {
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
        let ts_usec = read_u32(&data, offset + 4, le);
        let ts_us = i64::from(ts_sec) * 1_000_000 + i64::from(ts_usec);
        let incl_len = read_u32(&data, offset + 8, le);

        let Some(incl_len) = usize::try_from(incl_len).ok() else {
            break;
        };
        let pkt_start = offset + PACKET_HEADER_LEN;
        if pkt_start + incl_len > data.len() {
            break; // truncated (file may still be written by tcpdump)
        }

        if let Some(pkt_data) = data.get(pkt_start..pkt_start + incl_len)
            && let Some(pkt) = parse_ethernet_packet(pkt_data, ts_us)
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

/// Writes a `u32` at the given offset in the requested endianness.
///
/// Silently no-ops if the slice is too short; callers bounds-check the
/// record-header window before invoking.
fn write_u32(data: &mut [u8], offset: usize, value: u32, le: bool) {
    let bytes = if le {
        value.to_le_bytes()
    } else {
        value.to_be_bytes()
    };
    if let Some(slot) = data.get_mut(offset..offset + 4) {
        slot.copy_from_slice(&bytes);
    }
}

/// Rewrites every packet record's `(ts_sec, ts_usec)` in `path` from
/// real wall-clock to the logical timeline via [`rewrite_ts`].
///
/// Returns the maximum rewritten timestamp seen, or `None` if the file
/// has zero packet records. The aggregator in `assemble_bundle` folds
/// this in with the GT max to seed `meta.actual_end`.
///
/// Walks the raw byte stream (not [`parse_ethernet_packet`]) so non-IPv4
/// records (ARP, IPv6, LLDP, …) are also rewritten — the output file
/// stays byte-identical to the input except for the eight rewritten
/// timestamp bytes per record. `incl_len`, `orig_len`, and packet
/// payloads are left untouched.
#[allow(clippy::similar_names)] // ts_sec / ts_usec are pcap spec field names
pub(crate) fn rewrite_timestamps(
    path: &Path,
    time_map: &TimeMap,
    anchors: &[ExecAnchor],
) -> Result<Option<DateTime<Utc>>> {
    let mut data =
        std::fs::read(path).with_context(|| format!("failed to read pcap: {}", path.display()))?;
    ensure!(
        data.len() >= GLOBAL_HEADER_LEN,
        "pcap file too short: {}",
        path.display(),
    );

    let magic: [u8; 4] = data
        .get(..4)
        .expect("len >= GLOBAL_HEADER_LEN guarantees four bytes")
        .try_into()
        .expect("slice is guaranteed to be 4 bytes");
    let le = match magic {
        PCAP_MAGIC_US_LE => true,
        PCAP_MAGIC_US_BE => false,
        PCAP_MAGIC_NS_LE | PCAP_MAGIC_NS_BE => bail!(
            "nanosecond-resolution PCAP is not supported (rewriter assumes microsecond precision): {}",
            path.display(),
        ),
        PCAPNG_SHB_MAGIC => bail!(
            "pcapng is not supported by the rewriter: {}",
            path.display()
        ),
        _ => bail!("not a valid pcap file: {}", path.display()),
    };

    let mut offset = GLOBAL_HEADER_LEN;
    let mut max_ts: Option<DateTime<Utc>> = None;
    let mut out_of_range_seen = false;
    let logical_end = time_map
        .start_at()
        .checked_add_signed(chrono::Duration::microseconds(time_map.logical_us()));

    while offset + PACKET_HEADER_LEN <= data.len() {
        let ts_sec = read_u32(&data, offset, le);
        let ts_usec = read_u32(&data, offset + 4, le);
        let incl_len = read_u32(&data, offset + 8, le);

        let Ok(incl_len_us) = usize::try_from(incl_len) else {
            break;
        };
        let pkt_start = offset + PACKET_HEADER_LEN;
        if pkt_start + incl_len_us > data.len() {
            break; // truncated trailer; preserve existing reader behavior
        }

        ensure!(
            ts_usec < TS_USEC_MAX_EXCLUSIVE,
            "malformed pcap record in {}: ts_usec={ts_usec} >= 1_000_000",
            path.display(),
        );
        let usec_nanos = ts_usec
            .checked_mul(1_000)
            .expect("ts_usec < 1_000_000 so *1_000 fits in u32");
        let real_ts =
            DateTime::<Utc>::from_timestamp(i64::from(ts_sec), usec_nanos).ok_or_else(|| {
                anyhow!(
                    "invalid timestamp in {}: ts_sec={ts_sec}, ts_usec={ts_usec}",
                    path.display(),
                )
            })?;

        let logical_ts = rewrite_ts(real_ts, time_map, anchors)?;

        let secs = logical_ts.timestamp();
        ensure!(
            (0..=U32_MAX_AS_I64).contains(&secs),
            "logical timestamp {} for record in {} does not fit in u32 unix seconds",
            logical_ts.format("%Y-%m-%dT%H:%M:%S%.fZ"),
            path.display(),
        );
        let new_ts_sec = u32::try_from(secs).expect("range checked above");
        let new_ts_usec = logical_ts.timestamp_subsec_micros();

        write_u32(&mut data, offset, new_ts_sec, le);
        write_u32(&mut data, offset + 4, new_ts_usec, le);

        if logical_ts < time_map.start_at() || logical_end.is_some_and(|end| logical_ts > end) {
            out_of_range_seen = true;
        }
        if max_ts.is_none_or(|m| logical_ts > m) {
            max_ts = Some(logical_ts);
        }

        offset = pkt_start + incl_len_us;
    }

    if out_of_range_seen {
        eprintln!(
            "info: {}: rewrote packet timestamps outside [start_at, start_at + logical_duration]; this is allowed per overrun policy",
            path.display(),
        );
    }

    write_atomic(path, &data)
        .with_context(|| format!("failed to write pcap: {}", path.display()))?;

    Ok(max_ts)
}

/// Atomically replaces `path` with `data` by writing to a sibling
/// temp file and renaming over the original.
///
/// Captures from the tcpdump sidecar are owned by root (UID 0) and
/// not writable by the host user, so a direct `fs::write` would fail
/// with `EACCES`. Renaming only requires write+execute on the parent
/// directory, which the host user does own, and is atomic so a crash
/// mid-write cannot leave a half-rewritten PCAP behind.
fn write_atomic(path: &Path, data: &[u8]) -> std::io::Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path.file_name().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "path has no file name")
    })?;
    let mut tmp_name = std::ffi::OsString::from(".");
    tmp_name.push(file_name);
    tmp_name.push(".rewrite-tmp");
    let tmp_path = parent.join(&tmp_name);

    // Best-effort cleanup of a stale tmp from a previous crash.
    let _ = std::fs::remove_file(&tmp_path);

    if let Err(e) = std::fs::write(&tmp_path, data) {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(e);
    }
    if let Err(e) = std::fs::rename(&tmp_path, path) {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(e);
    }
    Ok(())
}

fn parse_ethernet_packet(data: &[u8], ts_us: i64) -> Option<Packet> {
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
                ts_us,
                src_ip,
                dst_ip,
                protocol,
                src_port,
                dst_port,
            })
        }
        IP_PROTO_ICMP => Some(Packet {
            ts_us,
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

    #[allow(clippy::similar_names)] // pcap spec field names
    fn pcap_packet_record(ts_sec: u32, ts_usec: u32, payload: &[u8]) -> Vec<u8> {
        let len = u32::try_from(payload.len()).unwrap();
        let mut buf = Vec::with_capacity(PACKET_HEADER_LEN + payload.len());
        buf.extend_from_slice(&ts_sec.to_le_bytes());
        buf.extend_from_slice(&ts_usec.to_le_bytes());
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

    fn write_pcap(dir: &Path, name: &str, packets: &[(u32, u32, Vec<u8>)]) {
        let mut data = pcap_global_header();
        for (ts_sec, ts_usec, payload) in packets {
            data.extend(pcap_packet_record(*ts_sec, *ts_usec, payload));
        }
        std::fs::write(dir.join(name), data).unwrap();
    }

    // ── parse_ethernet_packet ────────────────────────────────────

    #[test]
    fn parse_tcp_packet() {
        let frame = tcp_frame([10, 0, 0, 2], [10, 0, 0, 3], 49152, 80);
        let pkt = parse_ethernet_packet(&frame, 1_000_000_000).unwrap();
        assert_eq!(pkt.src_ip, Ipv4Addr::new(10, 0, 0, 2));
        assert_eq!(pkt.dst_ip, Ipv4Addr::new(10, 0, 0, 3));
        assert_eq!(pkt.src_port, 49152);
        assert_eq!(pkt.dst_port, 80);
        assert_eq!(pkt.protocol, Protocol::Tcp);
        assert_eq!(pkt.ts_us, 1_000_000_000);
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
        write_pcap(dir.path(), "test.pcap", &[(100, 0, pkt1), (200, 0, pkt2)]);

        let packets = parse_pcap(&dir.path().join("test.pcap")).unwrap();
        assert_eq!(packets.len(), 2);
        assert_eq!(packets[0].src_port, 49152);
        assert_eq!(packets[1].src_port, 50000);
    }

    #[test]
    fn parse_pcap_preserves_microsecond_timestamp() {
        let dir = tempfile::tempdir().unwrap();
        let pkt = tcp_frame([10, 0, 0, 2], [10, 0, 0, 3], 49152, 80);
        write_pcap(dir.path(), "us.pcap", &[(1000, 500_000, pkt)]);

        let packets = parse_pcap(&dir.path().join("us.pcap")).unwrap();
        assert_eq!(packets.len(), 1);
        assert_eq!(packets[0].ts_us, 1_000_500_000);
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
        data.extend(pcap_packet_record(100, 0, &pkt));
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
        make_execution_us(src_ip, dst_ip, dst_port, protocol, ts * 1_000_000)
    }

    fn make_execution_us(
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        dst_port: u16,
        protocol: Protocol,
        start_us: i64,
    ) -> Execution {
        use chrono::TimeZone;
        let start = chrono::Utc
            .timestamp_opt(
                start_us / 1_000_000,
                u32::try_from(start_us % 1_000_000 * 1_000).unwrap(),
            )
            .unwrap();
        let end_us = start_us + 1_000_000;
        let end = chrono::Utc
            .timestamp_opt(
                end_us / 1_000_000,
                u32::try_from(end_us % 1_000_000 * 1_000).unwrap(),
            )
            .unwrap();
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
            exit_code: 0,
            command: String::new(),
        }
    }

    #[test]
    fn enrich_fills_src_port_from_pcap() {
        let dir = tempfile::tempdir().unwrap();
        let pkt = tcp_frame([10, 0, 0, 2], [10, 0, 0, 3], 49152, 80);
        write_pcap(dir.path(), "capture.pcap", &[(1000, 0, pkt)]);

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
        write_pcap(
            dir.path(),
            "capture.pcap",
            &[(1000, 0, pkt1), (2000, 0, pkt2)],
        );

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
        write_pcap(dir.path(), "capture.pcap", &[(1000, 0, pkt)]);

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
    fn enrich_skips_failed_executions() {
        let dir = tempfile::tempdir().unwrap();
        write_pcap(dir.path(), "capture.pcap", &[]);

        let mut exec = make_execution(
            Ipv4Addr::new(10, 0, 0, 2),
            Ipv4Addr::new(10, 0, 0, 3),
            80,
            Protocol::Tcp,
            1000,
        );
        exec.exit_code = 7;
        let mut execs = vec![exec];
        enrich_src_ports(dir.path(), &mut execs).unwrap();
        assert_eq!(execs[0].src_port, 0);
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
        write_pcap(dir.path(), "lan.pcap", &[(1000, 0, pkt1)]);
        write_pcap(dir.path(), "dmz.pcap", &[(1000, 0, pkt2)]);

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
        write_pcap(dir.path(), "capture.pcap", &[(1000, 0, pkt)]);

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
    fn enrich_consumed_packet_not_reused() {
        let dir = tempfile::tempdir().unwrap();
        // Only one packet, but two executions want it — second must fail.
        let pkt = tcp_frame([10, 0, 0, 2], [10, 0, 0, 3], 49152, 80);
        write_pcap(dir.path(), "capture.pcap", &[(1000, 0, pkt)]);

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
                1000,
            ),
        ];
        assert!(enrich_src_ports(dir.path(), &mut execs).is_err());
    }

    #[test]
    fn enrich_three_overlapping_executions_preserve_order() {
        let dir = tempfile::tempdir().unwrap();
        // Three same-4-tuple packets at sub-second offsets within one second.
        let pkt0 = tcp_frame([10, 0, 0, 2], [10, 0, 0, 3], 49000, 80);
        let pkt1 = tcp_frame([10, 0, 0, 2], [10, 0, 0, 3], 49001, 80);
        let pkt2 = tcp_frame([10, 0, 0, 2], [10, 0, 0, 3], 49002, 80);
        write_pcap(
            dir.path(),
            "capture.pcap",
            &[
                (1000, 100_000, pkt0),
                (1000, 500_000, pkt1),
                (1000, 900_000, pkt2),
            ],
        );

        // Three executions with staggered sub-second windows:
        //   E0 starts at 1000.0s → window [1000.0, 1002.0)
        //   E1 starts at 1000.4s → window [1000.4, 1002.4)
        //   E2 starts at 1000.8s → window [1000.8, 1002.8)
        // Correct assignment: E0→P0, E1→P1, E2→P2 (capture order).
        let ip_src = Ipv4Addr::new(10, 0, 0, 2);
        let ip_dst = Ipv4Addr::new(10, 0, 0, 3);
        let mut execs = vec![
            make_execution_us(ip_src, ip_dst, 80, Protocol::Tcp, 1_000_000_000),
            make_execution_us(ip_src, ip_dst, 80, Protocol::Tcp, 1_000_400_000),
            make_execution_us(ip_src, ip_dst, 80, Protocol::Tcp, 1_000_800_000),
        ];
        enrich_src_ports(dir.path(), &mut execs).unwrap();
        assert_eq!(execs[0].src_port, 49000);
        assert_eq!(execs[1].src_port, 49001);
        assert_eq!(execs[2].src_port, 49002);
    }

    #[test]
    fn enrich_same_second_distinct_src_ports() {
        let dir = tempfile::tempdir().unwrap();
        // Two same-4-tuple packets at the same second but different microseconds.
        let pkt1 = tcp_frame([10, 0, 0, 2], [10, 0, 0, 3], 49152, 80);
        let pkt2 = tcp_frame([10, 0, 0, 2], [10, 0, 0, 3], 50000, 80);
        write_pcap(
            dir.path(),
            "capture.pcap",
            &[(1000, 100_000, pkt1), (1000, 600_000, pkt2)],
        );

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
                1000,
            ),
        ];
        enrich_src_ports(dir.path(), &mut execs).unwrap();
        // Each execution must get a distinct src_port — the matched packet is
        // consumed and cannot be reused.
        assert_ne!(execs[0].src_port, execs[1].src_port);
        assert!(execs[0].src_port == 49152 || execs[0].src_port == 50000);
        assert!(execs[1].src_port == 49152 || execs[1].src_port == 50000);
    }

    // ── rewrite_timestamps ───────────────────────────────────────

    use chrono::Duration;

    use crate::time::build_anchors;

    fn fixed_ts(secs: i64) -> DateTime<Utc> {
        DateTime::<Utc>::from_timestamp(secs, 0).unwrap()
    }

    fn identity_map_for(start: DateTime<Utc>) -> TimeMap {
        let d = Duration::try_seconds(300).unwrap();
        TimeMap::new(start, start, d, d).unwrap()
    }

    /// Builds a packet record header in the requested endianness with
    /// the given payload. Used to construct BE captures, which the
    /// other helpers in this module do not produce.
    #[allow(clippy::similar_names)] // pcap spec field names
    fn pcap_packet_record_endian(ts_sec: u32, ts_usec: u32, payload: &[u8], le: bool) -> Vec<u8> {
        let len = u32::try_from(payload.len()).unwrap();
        let mut buf = Vec::with_capacity(PACKET_HEADER_LEN + payload.len());
        let to_bytes = |v: u32| -> [u8; 4] { if le { v.to_le_bytes() } else { v.to_be_bytes() } };
        buf.extend_from_slice(&to_bytes(ts_sec));
        buf.extend_from_slice(&to_bytes(ts_usec));
        buf.extend_from_slice(&to_bytes(len)); // incl_len
        buf.extend_from_slice(&to_bytes(len)); // orig_len
        buf.extend_from_slice(payload);
        buf
    }

    fn pcap_global_header_endian(le: bool) -> Vec<u8> {
        if le {
            pcap_global_header()
        } else {
            let mut buf = Vec::with_capacity(GLOBAL_HEADER_LEN);
            buf.extend_from_slice(&0xa1b2_c3d4_u32.to_be_bytes()); // magic (BE)
            buf.extend_from_slice(&2u16.to_be_bytes()); // version major
            buf.extend_from_slice(&4u16.to_be_bytes()); // version minor
            buf.extend_from_slice(&0i32.to_be_bytes()); // thiszone
            buf.extend_from_slice(&0u32.to_be_bytes()); // sigfigs
            buf.extend_from_slice(&65535u32.to_be_bytes()); // snaplen
            buf.extend_from_slice(&1u32.to_be_bytes()); // link type
            buf
        }
    }

    #[test]
    fn rewrite_identity_is_byte_identical() {
        let dir = tempfile::tempdir().unwrap();
        let pkt = tcp_frame([10, 0, 0, 2], [10, 0, 0, 3], 49152, 80);
        write_pcap(dir.path(), "capture.pcap", &[(1_737_000_000, 123_456, pkt)]);
        let path = dir.path().join("capture.pcap");
        let before = std::fs::read(&path).unwrap();

        let start = fixed_ts(1_737_000_000);
        let tm = identity_map_for(start);
        let max_ts = rewrite_timestamps(&path, &tm, &[]).unwrap();
        let after = std::fs::read(&path).unwrap();

        assert_eq!(before, after);
        assert_eq!(max_ts, Some(start + Duration::microseconds(123_456)));
    }

    #[test]
    fn rewrite_preserves_intra_session_spacing_under_compression() {
        // 30 real minutes → 14 logical days (factor 672). Inside the
        // anchor window the rewriter must use scale = 1, so a 100 ms
        // real gap maps to a 100 ms logical gap.
        let dir = tempfile::tempdir().unwrap();
        let pkt_a = tcp_frame([10, 0, 0, 2], [10, 0, 0, 3], 49152, 80);
        let pkt_b = tcp_frame([10, 0, 0, 2], [10, 0, 0, 3], 49152, 80);
        let real_start = fixed_ts(1_000_000_000);
        // Two packets inside the execution window with 100 ms spacing.
        let p1_ts = real_start + Duration::milliseconds(100);
        let p2_ts = real_start + Duration::milliseconds(200);
        let p1_sec = u32::try_from(p1_ts.timestamp()).unwrap();
        let p2_sec = u32::try_from(p2_ts.timestamp()).unwrap();
        write_pcap(
            dir.path(),
            "lan.pcap",
            &[
                (p1_sec, p1_ts.timestamp_subsec_micros(), pkt_a),
                (p2_sec, p2_ts.timestamp_subsec_micros(), pkt_b),
            ],
        );

        let logical_start = fixed_ts(2_000_000_000);
        let tm = TimeMap::new(
            logical_start,
            real_start,
            Duration::try_minutes(30).unwrap(),
            Duration::try_days(14).unwrap(),
        )
        .unwrap();
        let exec_start = real_start + Duration::milliseconds(50);
        let exec_end = real_start + Duration::milliseconds(300);
        let exec = Execution {
            start: exec_start,
            end: exec_end,
            source: "a".into(),
            target: "b".into(),
            protocol: Protocol::Tcp,
            src_ip: Ipv4Addr::new(10, 0, 0, 2),
            src_port: 0,
            dst_ip: Ipv4Addr::new(10, 0, 0, 3),
            dst_port: 80,
            attack: None,
            exit_code: 0,
            command: String::new(),
        };
        let (anchors, _) = build_anchors(std::slice::from_ref(&exec), &tm).unwrap();

        rewrite_timestamps(&dir.path().join("lan.pcap"), &tm, &anchors).unwrap();
        let pkts = parse_pcap(&dir.path().join("lan.pcap")).unwrap();
        assert_eq!(pkts.len(), 2);
        // 100 ms in real time stays 100 ms in logical time.
        assert_eq!(pkts[1].ts_us - pkts[0].ts_us, 100_000);
    }

    #[test]
    fn rewrite_two_executions_with_background_between() {
        // Two non-overlapping execution windows under heavy compression
        // with a background packet between them. Intra-execution
        // packets keep their real spacing; the background packet
        // follows the global TimeMap.
        let dir = tempfile::tempdir().unwrap();
        let pkt = tcp_frame([10, 0, 0, 2], [10, 0, 0, 3], 49152, 80);

        let real_start = fixed_ts(1_000_000_000);
        // Exec A: starts at real_start + 60s, packet at +60.1s.
        let a_start = real_start + Duration::try_seconds(60).unwrap();
        let a_pkt_ts = a_start + Duration::milliseconds(100);
        // Background: at real_start + 5m (outside any anchor window
        // once anchors are clamped — sits in the global TimeMap fallback).
        let bg_ts = real_start + Duration::try_minutes(5).unwrap();
        // Exec B: starts at real_start + 10m, packet at +10m+50ms.
        let b_start = real_start + Duration::try_minutes(10).unwrap();
        let b_pkt_ts = b_start + Duration::milliseconds(50);
        let to_pair = |t: DateTime<Utc>| -> (u32, u32) {
            (
                u32::try_from(t.timestamp()).unwrap(),
                t.timestamp_subsec_micros(),
            )
        };
        let (a_sec, a_us) = to_pair(a_pkt_ts);
        let (background_sec, background_us) = to_pair(bg_ts);
        let (b_sec, b_us) = to_pair(b_pkt_ts);
        write_pcap(
            dir.path(),
            "lan.pcap",
            &[
                (a_sec, a_us, pkt.clone()),
                (background_sec, background_us, pkt.clone()),
                (b_sec, b_us, pkt),
            ],
        );

        let logical_start = fixed_ts(2_000_000_000);
        let tm = TimeMap::new(
            logical_start,
            real_start,
            Duration::try_minutes(30).unwrap(),
            Duration::try_days(14).unwrap(),
        )
        .unwrap();
        let mk_exec = |start, end, src, dst| Execution {
            start,
            end,
            source: src,
            target: dst,
            protocol: Protocol::Tcp,
            src_ip: Ipv4Addr::new(10, 0, 0, 2),
            src_port: 0,
            dst_ip: Ipv4Addr::new(10, 0, 0, 3),
            dst_port: 80,
            attack: None,
            exit_code: 0,
            command: String::new(),
        };
        let exec_a = mk_exec(
            a_start,
            a_start + Duration::try_seconds(1).unwrap(),
            "src".into(),
            "dst-a".into(),
        );
        let exec_b = mk_exec(
            b_start,
            b_start + Duration::try_seconds(1).unwrap(),
            "src".into(),
            "dst-b".into(),
        );
        let (anchors, _) = build_anchors(&[exec_a, exec_b], &tm).unwrap();

        rewrite_timestamps(&dir.path().join("lan.pcap"), &tm, &anchors).unwrap();
        let pkts = parse_pcap(&dir.path().join("lan.pcap")).unwrap();
        assert_eq!(pkts.len(), 3);

        // Background packet must follow the global TimeMap, not be
        // anchored. Verify by computing its expected logical timestamp.
        let bg_logical_us = tm.to_logical(bg_ts).unwrap().timestamp_micros();
        assert_eq!(pkts[1].ts_us, bg_logical_us);

        // Each anchor's packet keeps its real spacing relative to the
        // anchor's logical_start.
        let a_logical_start_us = anchors[0].logical_start.timestamp_micros();
        let b_logical_start_us = anchors[1].logical_start.timestamp_micros();
        assert_eq!(pkts[0].ts_us - a_logical_start_us, 100_000);
        assert_eq!(pkts[2].ts_us - b_logical_start_us, 50_000);
    }

    #[test]
    fn rewrite_microsecond_carry_boundary() {
        // Construct a real timestamp at ts_usec = 999_999 and let the
        // identity TimeMap leave it in place — proves the chrono
        // pipeline carries from µs to seconds correctly (no manual
        // carry handling needed).
        let dir = tempfile::tempdir().unwrap();
        let pkt = tcp_frame([10, 0, 0, 2], [10, 0, 0, 3], 49152, 80);
        write_pcap(dir.path(), "carry.pcap", &[(1_737_000_000, 999_999, pkt)]);
        let path = dir.path().join("carry.pcap");

        let start = fixed_ts(1_737_000_000);
        let tm = identity_map_for(start);
        rewrite_timestamps(&path, &tm, &[]).unwrap();
        let pkts = parse_pcap(&path).unwrap();
        assert_eq!(pkts[0].ts_us, 1_737_000_000 * 1_000_000 + 999_999);

        // Just past the boundary: a +1 µs translation via the global
        // TimeMap should turn ts_usec=999_999 into ts_usec=0 of the
        // next second (chrono's timestamp_subsec_micros carries the
        // overflow into the seconds field automatically).
        let dir2 = tempfile::tempdir().unwrap();
        let frame = tcp_frame([10, 0, 0, 2], [10, 0, 0, 3], 49152, 80);
        write_pcap(
            dir2.path(),
            "carry2.pcap",
            &[(1_737_000_000, 999_999, frame)],
        );
        let path2 = dir2.path().join("carry2.pcap");

        let real_start = fixed_ts(1_737_000_000);
        let logical_start = real_start + Duration::microseconds(1);
        let tm = TimeMap::new(
            logical_start,
            real_start,
            Duration::try_seconds(300).unwrap(),
            Duration::try_seconds(300).unwrap(),
        )
        .unwrap();
        rewrite_timestamps(&path2, &tm, &[]).unwrap();
        let raw = std::fs::read(&path2).unwrap();
        let written_sec = read_u32(&raw, GLOBAL_HEADER_LEN, true);
        let written_subsec = read_u32(&raw, GLOBAL_HEADER_LEN + 4, true);
        assert_eq!(written_sec, 1_737_000_001);
        assert_eq!(written_subsec, 0);
    }

    #[test]
    fn rewrite_passes_through_non_ipv4_record() {
        // Construct a record whose payload has ethertype 0x86DD (IPv6).
        // parse_pcap drops it, but the rewriter must touch its
        // timestamp and leave its bytes intact.
        let dir = tempfile::tempdir().unwrap();
        let mut ipv6_frame = tcp_frame([10, 0, 0, 1], [10, 0, 0, 2], 100, 200);
        ipv6_frame[12] = 0x86;
        ipv6_frame[13] = 0xDD;
        let body_bytes = ipv6_frame.clone();
        write_pcap(dir.path(), "v6.pcap", &[(1_737_000_000, 0, ipv6_frame)]);
        let path = dir.path().join("v6.pcap");

        let real_start = fixed_ts(1_737_000_000);
        let logical_start = fixed_ts(2_000_000_000);
        let tm = TimeMap::new(
            logical_start,
            real_start,
            Duration::try_minutes(30).unwrap(),
            Duration::try_minutes(30).unwrap(),
        )
        .unwrap();
        let max_ts = rewrite_timestamps(&path, &tm, &[]).unwrap();
        assert_eq!(max_ts, Some(logical_start));

        // After rewrite, the packet header timestamp is shifted, but
        // the IPv6 frame bytes are still in the file in the same place.
        let raw = std::fs::read(&path).unwrap();
        let payload_offset = GLOBAL_HEADER_LEN + PACKET_HEADER_LEN;
        assert_eq!(
            &raw[payload_offset..payload_offset + body_bytes.len()],
            &body_bytes[..]
        );
    }

    #[test]
    fn rewrite_handles_big_endian_magic() {
        // BE capture: one packet, identity TimeMap → header bytes
        // unchanged.
        let dir = tempfile::tempdir().unwrap();
        let pkt = tcp_frame([10, 0, 0, 2], [10, 0, 0, 3], 49152, 80);
        let mut data = pcap_global_header_endian(false);
        data.extend(pcap_packet_record_endian(
            1_737_000_000,
            250_000,
            &pkt,
            false,
        ));
        let path = dir.path().join("be.pcap");
        std::fs::write(&path, &data).unwrap();
        let before = std::fs::read(&path).unwrap();

        let start = fixed_ts(1_737_000_000);
        let tm = identity_map_for(start);
        let max_ts = rewrite_timestamps(&path, &tm, &[]).unwrap();
        let after = std::fs::read(&path).unwrap();

        assert_eq!(before, after);
        assert_eq!(max_ts, Some(start + Duration::microseconds(250_000)));
    }

    #[test]
    fn rewrite_be_compression_writes_be_bytes() {
        // BE capture with compression: confirm endianness is preserved
        // by parsing the rewritten timestamp back as BE.
        let dir = tempfile::tempdir().unwrap();
        let pkt = tcp_frame([10, 0, 0, 2], [10, 0, 0, 3], 49152, 80);
        let mut data = pcap_global_header_endian(false);
        data.extend(pcap_packet_record_endian(1_000_000_000, 0, &pkt, false));
        let path = dir.path().join("be.pcap");
        std::fs::write(&path, &data).unwrap();

        let real_start = fixed_ts(1_000_000_000);
        let logical_start = fixed_ts(2_000_000_000);
        let tm = TimeMap::new(
            logical_start,
            real_start,
            Duration::try_minutes(30).unwrap(),
            Duration::try_minutes(30).unwrap(),
        )
        .unwrap();
        rewrite_timestamps(&path, &tm, &[]).unwrap();
        let pkts = parse_pcap(&path).unwrap();
        assert_eq!(pkts.len(), 1);
        assert_eq!(pkts[0].ts_us, logical_start.timestamp_micros());
    }

    #[test]
    fn rewrite_rejects_nanosecond_magic() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ns.pcap");
        let mut data = Vec::new();
        data.extend_from_slice(&PCAP_MAGIC_NS_LE);
        data.extend_from_slice(&[0u8; GLOBAL_HEADER_LEN - 4]);
        std::fs::write(&path, data).unwrap();

        let tm = identity_map_for(fixed_ts(1_000_000_000));
        let err = rewrite_timestamps(&path, &tm, &[]).unwrap_err();
        assert!(
            err.to_string().contains("nanosecond"),
            "unexpected error: {err}",
        );
    }

    #[test]
    fn rewrite_rejects_pcapng() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ng.pcap");
        let mut data = Vec::new();
        data.extend_from_slice(&PCAPNG_SHB_MAGIC);
        data.extend_from_slice(&[0u8; GLOBAL_HEADER_LEN - 4]);
        std::fs::write(&path, data).unwrap();

        let tm = identity_map_for(fixed_ts(1_000_000_000));
        let err = rewrite_timestamps(&path, &tm, &[]).unwrap_err();
        assert!(
            err.to_string().contains("pcapng"),
            "unexpected error: {err}",
        );
    }

    #[test]
    fn rewrite_rejects_invalid_magic() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.pcap");
        std::fs::write(&path, [0u8; GLOBAL_HEADER_LEN]).unwrap();

        let tm = identity_map_for(fixed_ts(1_000_000_000));
        let err = rewrite_timestamps(&path, &tm, &[]).unwrap_err();
        assert!(
            err.to_string().contains("not a valid pcap"),
            "unexpected error: {err}",
        );
    }

    #[test]
    fn rewrite_rejects_malformed_ts_usec() {
        // ts_usec = 1_000_000 is invalid — record must be rejected
        // distinctly rather than silently coerced by chrono.
        let dir = tempfile::tempdir().unwrap();
        let pkt = tcp_frame([10, 0, 0, 2], [10, 0, 0, 3], 49152, 80);
        write_pcap(dir.path(), "bad.pcap", &[(1_737_000_000, 1_000_000, pkt)]);

        let tm = identity_map_for(fixed_ts(1_737_000_000));
        let err = rewrite_timestamps(&dir.path().join("bad.pcap"), &tm, &[]).unwrap_err();
        assert!(
            err.to_string().contains("ts_usec"),
            "unexpected error: {err}",
        );
    }

    #[test]
    fn rewrite_rejects_logical_timestamp_past_u32() {
        // Logical timeline lands past 2106-02-07 06:28:15 UTC, so
        // ts_sec would not fit in u32.
        let dir = tempfile::tempdir().unwrap();
        let pkt = tcp_frame([10, 0, 0, 2], [10, 0, 0, 3], 49152, 80);
        write_pcap(dir.path(), "over.pcap", &[(1_000_000_000, 0, pkt)]);

        let real_start = fixed_ts(1_000_000_000);
        // 2200-01-01 is well past 2106.
        let logical_start = chrono::DateTime::parse_from_rfc3339("2200-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let tm = TimeMap::new(
            logical_start,
            real_start,
            Duration::try_minutes(30).unwrap(),
            Duration::try_minutes(30).unwrap(),
        )
        .unwrap();
        let err = rewrite_timestamps(&dir.path().join("over.pcap"), &tm, &[]).unwrap_err();
        assert!(
            err.to_string().contains("u32 unix seconds"),
            "unexpected error: {err}",
        );
    }

    #[test]
    fn rewrite_rejects_logical_timestamp_before_epoch() {
        let dir = tempfile::tempdir().unwrap();
        let pkt = tcp_frame([10, 0, 0, 2], [10, 0, 0, 3], 49152, 80);
        write_pcap(dir.path(), "neg.pcap", &[(1_000_000_000, 0, pkt)]);

        let real_start = fixed_ts(1_000_000_000);
        // 1960 < 1970: any logical timestamp before the epoch overflows
        // u32 unix seconds.
        let logical_start = chrono::DateTime::parse_from_rfc3339("1960-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let tm = TimeMap::new(
            logical_start,
            real_start,
            Duration::try_minutes(30).unwrap(),
            Duration::try_minutes(30).unwrap(),
        )
        .unwrap();
        let err = rewrite_timestamps(&dir.path().join("neg.pcap"), &tm, &[]).unwrap_err();
        assert!(
            err.to_string().contains("u32 unix seconds"),
            "unexpected error: {err}",
        );
    }

    #[test]
    fn rewrite_returns_none_for_zero_packets() {
        let dir = tempfile::tempdir().unwrap();
        write_pcap(dir.path(), "empty.pcap", &[]);
        let path = dir.path().join("empty.pcap");
        let before = std::fs::read(&path).unwrap();

        let tm = identity_map_for(fixed_ts(1_000_000_000));
        let max_ts = rewrite_timestamps(&path, &tm, &[]).unwrap();
        assert_eq!(max_ts, None);

        // Header is unchanged.
        let after = std::fs::read(&path).unwrap();
        assert_eq!(before, after);
    }

    #[test]
    fn rewrite_returns_max_timestamp_across_records() {
        let dir = tempfile::tempdir().unwrap();
        let p1 = tcp_frame([10, 0, 0, 2], [10, 0, 0, 3], 49152, 80);
        let p2 = tcp_frame([10, 0, 0, 2], [10, 0, 0, 3], 49152, 80);
        let p3 = tcp_frame([10, 0, 0, 2], [10, 0, 0, 3], 49152, 80);
        write_pcap(
            dir.path(),
            "many.pcap",
            &[
                (1_000_000_000, 0, p1),
                (1_000_000_010, 0, p2),
                (1_000_000_005, 0, p3),
            ],
        );

        let start = fixed_ts(1_000_000_000);
        let tm = identity_map_for(start);
        let max_ts = rewrite_timestamps(&dir.path().join("many.pcap"), &tm, &[]).unwrap();
        assert_eq!(max_ts, Some(fixed_ts(1_000_000_010)));
    }

    #[test]
    fn rewrite_then_parse_pcap_returns_same_packet_set() {
        // After identity rewrite, parse_pcap should produce the same
        // packet set as before (non-IPv4 records still filtered).
        let dir = tempfile::tempdir().unwrap();
        let tcp = tcp_frame([10, 0, 0, 2], [10, 0, 0, 3], 49152, 80);
        let udp = udp_frame([172, 16, 0, 1], [172, 16, 0, 2], 5353, 53);
        write_pcap(
            dir.path(),
            "mixed.pcap",
            &[(1_000_000_000, 0, tcp), (1_000_000_001, 0, udp)],
        );
        let path = dir.path().join("mixed.pcap");

        let pkts_before = parse_pcap(&path).unwrap();
        let tm = identity_map_for(fixed_ts(1_000_000_000));
        rewrite_timestamps(&path, &tm, &[]).unwrap();
        let pkts_after = parse_pcap(&path).unwrap();

        assert_eq!(pkts_before.len(), pkts_after.len());
        for (a, b) in pkts_before.iter().zip(pkts_after.iter()) {
            assert_eq!(a.ts_us, b.ts_us);
            assert_eq!(a.src_ip, b.src_ip);
            assert_eq!(a.dst_ip, b.dst_ip);
            assert_eq!(a.src_port, b.src_port);
            assert_eq!(a.dst_port, b.dst_port);
            assert_eq!(a.protocol, b.protocol);
        }
    }
}
