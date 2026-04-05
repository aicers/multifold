use std::collections::HashSet;
use std::fs;
use std::net::Ipv4Addr;
use std::path::Path;
use std::process::ExitCode;

use anyhow::{Result, ensure};
use serde::Serialize;
use serde_json::Value;

use crate::pcap;
use crate::scenario::Protocol;

const META_REQUIRED: &[&str] = &[
    "schema_version",
    "scenario",
    "scenario_version",
    "generated_at",
    "duration",
    "environment",
    "hosts",
    "network",
    "capture",
];

const GT_COMMON_REQUIRED: &[&str] = &[
    "scope",
    "label",
    "start",
    "end",
    "source",
    "target",
    "session_type",
];

const GT_NETWORK_REQUIRED: &[&str] = &["protocol", "src_ip", "src_port", "dst_ip", "dst_port"];

const VALID_PHASES: &[&str] = &[
    "reconnaissance",
    "initial_access",
    "credential_access",
    "lateral_movement",
    "c2",
    "exfiltration",
];

const PCAP_MAGIC_LE: [u8; 4] = [0xd4, 0xc3, 0xb2, 0xa1];
const PCAP_MAGIC_BE: [u8; 4] = [0xa1, 0xb2, 0xc3, 0xd4];
const PCAPNG_MAGIC: [u8; 4] = [0x0a, 0x0d, 0x0d, 0x0a];

// ── Report types ────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub(crate) struct Report {
    checks: Vec<Check>,
    summary: Summary,
}

#[derive(Debug, Serialize)]
struct Check {
    id: &'static str,
    status: Status,
    message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
enum Status {
    Pass,
    Fail,
    Warn,
}

#[derive(Debug, Serialize)]
struct Summary {
    total: usize,
    passed: usize,
    failed: usize,
    warned: usize,
}

impl Report {
    fn new(checks: Vec<Check>) -> Self {
        let total = checks.len();
        let passed = checks.iter().filter(|c| c.status == Status::Pass).count();
        let failed = checks.iter().filter(|c| c.status == Status::Fail).count();
        let warned = checks.iter().filter(|c| c.status == Status::Warn).count();
        Self {
            checks,
            summary: Summary {
                total,
                passed,
                failed,
                warned,
            },
        }
    }

    pub(crate) fn exit_code(&self) -> ExitCode {
        if self.summary.failed > 0 {
            ExitCode::from(2)
        } else if self.summary.warned > 0 {
            ExitCode::from(1)
        } else {
            ExitCode::SUCCESS
        }
    }

    #[cfg(test)]
    pub(crate) fn has_failures(&self) -> bool {
        self.summary.failed > 0
    }
}

fn pass(id: &'static str, message: impl Into<String>) -> Check {
    Check {
        id,
        status: Status::Pass,
        message: message.into(),
    }
}

fn fail(id: &'static str, message: impl Into<String>) -> Check {
    Check {
        id,
        status: Status::Fail,
        message: message.into(),
    }
}

// ── Main entry point ────────────────────────────────────────

/// Validates a dataset bundle and returns a structured report.
pub(crate) fn run(bundle: &Path) -> Result<Report> {
    ensure!(
        bundle.is_dir(),
        "bundle path is not a directory: {}",
        bundle.display(),
    );

    let mut checks = Vec::new();

    // L1-001 + L2-001 + L2-002: meta.json
    let meta = validate_meta(bundle, &mut checks);

    // L1-002 + L2-003 + L2-005: ground truth
    let gt_records = validate_ground_truth(bundle, &mut checks);

    // L1-003 + L2-004: PCAP files
    if let Some(m) = &meta {
        validate_pcaps(bundle, m, &mut checks);
    }

    // L1-004: host directories
    if let Some(m) = &meta {
        validate_host_dirs(bundle, m, &mut checks);
    }

    // L3: ground truth integrity
    if !gt_records.is_empty() {
        validate_gt_integrity(meta.as_ref(), &gt_records, &mut checks);
    }

    // L4-001: cross-artifact matching
    if !gt_records.is_empty() {
        validate_l4_lite(bundle, &gt_records, &mut checks);
    }

    // L1-005 + L2-006: host telemetry files
    if let Some(m) = &meta {
        validate_host_telemetry(bundle, m, &mut checks);
    }

    checks.sort_by_key(|c| c.id);
    Ok(Report::new(checks))
}

// ── L1-001 + L2-001 + L2-002 ───────────────────────────────

fn validate_meta(bundle: &Path, checks: &mut Vec<Check>) -> Option<Value> {
    let path = bundle.join("meta.json");

    // L1-001
    let bytes = match fs::read(&path) {
        Ok(b) if !b.is_empty() => {
            checks.push(pass("L1-001", "meta.json exists and is non-empty"));
            b
        }
        Ok(_) => {
            checks.push(fail("L1-001", "meta.json is empty"));
            return None;
        }
        Err(e) => {
            checks.push(fail("L1-001", format!("meta.json not found: {e}")));
            return None;
        }
    };

    // L2-001
    let value: Value = match serde_json::from_slice(&bytes) {
        Ok(v) => {
            checks.push(pass("L2-001", "meta.json is valid JSON"));
            v
        }
        Err(e) => {
            checks.push(fail("L2-001", format!("meta.json is not valid JSON: {e}")));
            return None;
        }
    };

    // L2-002
    let missing: Vec<&str> = META_REQUIRED
        .iter()
        .copied()
        .filter(|f| value.get(*f).is_none())
        .collect();
    if missing.is_empty() {
        checks.push(pass("L2-002", "meta.json contains all required fields"));
    } else {
        checks.push(fail(
            "L2-002",
            format!("meta.json missing required fields: {}", missing.join(", "),),
        ));
    }

    Some(value)
}

// ── L1-002 + L2-003 + L2-005 ───────────────────────────────

fn validate_ground_truth(bundle: &Path, checks: &mut Vec<Check>) -> Vec<Value> {
    let path = bundle.join("ground_truth").join("manifest.jsonl");

    // L1-002
    let content = match fs::read_to_string(&path) {
        Ok(s) if !s.is_empty() => {
            checks.push(pass(
                "L1-002",
                "ground_truth/manifest.jsonl exists and is non-empty",
            ));
            s
        }
        Ok(_) => {
            checks.push(fail("L1-002", "ground_truth/manifest.jsonl is empty"));
            return Vec::new();
        }
        Err(e) => {
            checks.push(fail(
                "L1-002",
                format!("ground_truth/manifest.jsonl not found: {e}"),
            ));
            return Vec::new();
        }
    };

    // L2-003
    let lines: Vec<&str> = content.lines().filter(|l| !l.is_empty()).collect();
    let mut records = Vec::with_capacity(lines.len());
    let mut bad_lines = Vec::new();

    for (i, line) in lines.iter().enumerate() {
        match serde_json::from_str::<Value>(line) {
            Ok(v) => records.push(v),
            Err(e) => bad_lines.push(format!("line {}: {e}", i + 1)),
        }
    }

    if bad_lines.is_empty() {
        checks.push(pass(
            "L2-003",
            format!("all {} GT line(s) are valid JSON", records.len()),
        ));
    } else {
        checks.push(fail(
            "L2-003",
            format!("invalid JSON lines: {}", bad_lines.join("; ")),
        ));
        return Vec::new();
    }

    // L2-005
    let mut missing_fields = Vec::new();
    for (i, record) in records.iter().enumerate() {
        for field in GT_COMMON_REQUIRED {
            if record.get(*field).is_none() {
                missing_fields.push(format!("record {}: missing '{field}'", i + 1));
            }
        }
    }

    if missing_fields.is_empty() {
        checks.push(pass("L2-005", "all GT records have required common fields"));
    } else {
        checks.push(fail(
            "L2-005",
            format!("missing common fields: {}", missing_fields.join("; ")),
        ));
    }

    records
}

// ── L1-003 + L2-004 ────────────────────────────────────────

fn validate_pcaps(bundle: &Path, meta: &Value, checks: &mut Vec<Check>) {
    let pcap_entries = meta
        .get("capture")
        .and_then(|c| c.get("pcaps"))
        .and_then(Value::as_array);

    let Some(entries) = pcap_entries else {
        checks.push(fail("L1-003", "no PCAP entries in meta.json"));
        return;
    };

    // L1-003: existence
    let mut existing = Vec::new();
    let mut missing = Vec::new();

    for entry in entries {
        let Some(path_str) = entry.get("path").and_then(Value::as_str) else {
            continue;
        };
        if bundle.join(path_str).exists() {
            existing.push(path_str);
        } else {
            missing.push(path_str);
        }
    }

    if missing.is_empty() && !existing.is_empty() {
        checks.push(pass("L1-003", "all PCAP files exist"));
    } else if existing.is_empty() && missing.is_empty() {
        checks.push(fail("L1-003", "no PCAP paths declared in meta.json"));
    } else {
        checks.push(fail(
            "L1-003",
            format!("PCAP files not found: {}", missing.join(", ")),
        ));
    }

    // L2-004: magic bytes
    if existing.is_empty() {
        return;
    }

    let mut bad = Vec::new();
    for path_str in &existing {
        let full_path = bundle.join(path_str);
        let valid = fs::read(&full_path)
            .ok()
            .and_then(|bytes| {
                bytes
                    .get(..4)
                    .map(|m| m == PCAP_MAGIC_LE || m == PCAP_MAGIC_BE || m == PCAPNG_MAGIC)
            })
            .unwrap_or(false);
        if !valid {
            bad.push(*path_str);
        }
    }

    if bad.is_empty() {
        checks.push(pass("L2-004", "all PCAP files have valid magic bytes"));
    } else {
        checks.push(fail(
            "L2-004",
            format!("invalid PCAP magic bytes: {}", bad.join(", ")),
        ));
    }
}

// ── L1-004 ──────────────────────────────────────────────────

fn validate_host_dirs(bundle: &Path, meta: &Value, checks: &mut Vec<Check>) {
    let Some(host_list) = meta.get("hosts").and_then(Value::as_array) else {
        checks.push(fail("L1-004", "no hosts array in meta.json"));
        return;
    };

    let mut missing = Vec::new();
    for host in host_list {
        if let Some(name) = host.get("name").and_then(Value::as_str)
            && !bundle.join("host").join(name).is_dir()
        {
            missing.push(name);
        }
    }

    if missing.is_empty() {
        checks.push(pass("L1-004", "all host directories exist"));
    } else {
        checks.push(fail(
            "L1-004",
            format!("missing host directories: {}", missing.join(", ")),
        ));
    }
}

// ── L3 ──────────────────────────────────────────────────────

fn validate_gt_integrity(meta: Option<&Value>, records: &[Value], checks: &mut Vec<Check>) {
    check_l3_timestamps(records, checks);
    check_l3_sorted(records, checks);
    check_l3_network_fields(records, checks);
    check_l3_anomaly_fields(records, checks);
    check_l3_attack_fields(records, checks);
    check_l3_phases(records, checks);
    if let Some(m) = meta {
        check_l3_hosts(m, records, checks);
    }
}

/// L3-001: start <= end for all records.
fn check_l3_timestamps(records: &[Value], checks: &mut Vec<Check>) {
    let mut bad = Vec::new();
    for (i, r) in records.iter().enumerate() {
        let start = r
            .get("start")
            .and_then(Value::as_str)
            .and_then(parse_timestamp_us);
        let end = r
            .get("end")
            .and_then(Value::as_str)
            .and_then(parse_timestamp_us);
        match (start, end) {
            (Some(s), Some(e)) if s <= e => {}
            _ => bad.push(i + 1),
        }
    }
    if bad.is_empty() {
        checks.push(pass("L3-001", "all records have start <= end"));
    } else {
        checks.push(fail("L3-001", format!("records with start > end: {bad:?}")));
    }
}

/// L3-002: records sorted by start time.
fn check_l3_sorted(records: &[Value], checks: &mut Vec<Check>) {
    let is_sorted = records.windows(2).all(|w| {
        let a = w
            .first()
            .and_then(|r| r.get("start"))
            .and_then(Value::as_str)
            .and_then(parse_timestamp_us);
        let b = w
            .get(1)
            .and_then(|r| r.get("start"))
            .and_then(Value::as_str)
            .and_then(parse_timestamp_us);
        match (a, b) {
            (Some(a), Some(b)) => a <= b,
            _ => true,
        }
    });
    if is_sorted {
        checks.push(pass("L3-002", "records are sorted by start time"));
    } else {
        checks.push(fail("L3-002", "records are not sorted by start time"));
    }
}

/// L3-003: network sessions have required fields.
fn check_l3_network_fields(records: &[Value], checks: &mut Vec<Check>) {
    let mut missing = Vec::new();
    for (i, r) in records.iter().enumerate() {
        if r.get("session_type").and_then(Value::as_str) == Some("network") {
            for field in GT_NETWORK_REQUIRED {
                if r.get(*field).is_none() {
                    missing.push(format!("record {}: missing '{field}'", i + 1));
                }
            }
        }
    }
    if missing.is_empty() {
        checks.push(pass("L3-003", "all network sessions have required fields"));
    } else {
        checks.push(fail(
            "L3-003",
            format!("missing network fields: {}", missing.join("; ")),
        ));
    }
}

/// L3-005: anomaly records have category.
fn check_l3_anomaly_fields(records: &[Value], checks: &mut Vec<Check>) {
    let mut missing_cat = Vec::new();
    for (i, r) in records.iter().enumerate() {
        if r.get("label").and_then(Value::as_str) == Some("anomaly") && r.get("category").is_none()
        {
            missing_cat.push(i + 1);
        }
    }
    if missing_cat.is_empty() {
        checks.push(pass("L3-005", "all anomaly records have category"));
    } else {
        checks.push(fail(
            "L3-005",
            format!("anomaly records missing category: {missing_cat:?}"),
        ));
    }
}

/// L3-006: attack records have technique, phase, tool.
fn check_l3_attack_fields(records: &[Value], checks: &mut Vec<Check>) {
    let attack_required = ["technique", "phase", "tool"];
    let mut missing = Vec::new();
    for (i, r) in records.iter().enumerate() {
        if r.get("category").and_then(Value::as_str) == Some("attack") {
            for field in &attack_required {
                if r.get(*field).is_none() {
                    missing.push(format!("record {}: missing '{field}'", i + 1));
                }
            }
        }
    }
    if missing.is_empty() {
        checks.push(pass(
            "L3-006",
            "all attack records have technique, phase, and tool",
        ));
    } else {
        checks.push(fail(
            "L3-006",
            format!("attack records missing fields: {}", missing.join("; ")),
        ));
    }
}

/// L3-007: phase values are valid kill chain values.
fn check_l3_phases(records: &[Value], checks: &mut Vec<Check>) {
    let mut bad = Vec::new();
    for (i, r) in records.iter().enumerate() {
        if let Some(phase) = r.get("phase").and_then(Value::as_str)
            && !VALID_PHASES.contains(&phase)
        {
            bad.push(format!("record {}: '{phase}'", i + 1));
        }
    }
    if bad.is_empty() {
        checks.push(pass("L3-007", "all phase values are valid"));
    } else {
        checks.push(fail(
            "L3-007",
            format!("invalid phase values: {}", bad.join(", ")),
        ));
    }
}

/// L3-008: source and target exist in meta.json host list.
fn check_l3_hosts(meta: &Value, records: &[Value], checks: &mut Vec<Check>) {
    let host_names: HashSet<&str> = meta
        .get("hosts")
        .and_then(Value::as_array)
        .map(|hosts| {
            hosts
                .iter()
                .filter_map(|h| h.get("name").and_then(Value::as_str))
                .collect()
        })
        .unwrap_or_default();

    let mut unknown = Vec::new();
    for (i, r) in records.iter().enumerate() {
        if let Some(src) = r.get("source").and_then(Value::as_str)
            && !host_names.contains(src)
        {
            unknown.push(format!("record {}: source '{src}'", i + 1));
        }
        if let Some(tgt) = r.get("target").and_then(Value::as_str)
            && !host_names.contains(tgt)
        {
            unknown.push(format!("record {}: target '{tgt}'", i + 1));
        }
    }

    if unknown.is_empty() {
        checks.push(pass("L3-008", "all source/target hosts exist in meta.json"));
    } else {
        checks.push(fail(
            "L3-008",
            format!("unknown hosts: {}", unknown.join("; ")),
        ));
    }
}

// ── L1-005 + L2-006: host telemetry ─────────────────────────

/// Validates host telemetry files referenced in meta.json.
///
/// Checks are skipped silently when no `host_telemetry` array is
/// present, so Docker-only bundles remain valid without warnings.
fn validate_host_telemetry(bundle: &Path, meta: &Value, checks: &mut Vec<Check>) {
    let Some(entries) = meta.get("host_telemetry").and_then(Value::as_array) else {
        return;
    };
    if entries.is_empty() {
        return;
    }

    // L1-005: all referenced telemetry files exist.
    let mut missing = Vec::new();
    let mut existing_paths = Vec::new();
    for entry in entries {
        let Some(path_str) = entry.get("path").and_then(Value::as_str) else {
            continue;
        };
        if bundle.join(path_str).exists() {
            existing_paths.push(path_str);
        } else {
            missing.push(path_str);
        }
    }

    if missing.is_empty() && !existing_paths.is_empty() {
        checks.push(pass(
            "L1-005",
            format!("all {} telemetry file(s) exist", existing_paths.len()),
        ));
    } else if !missing.is_empty() {
        checks.push(fail(
            "L1-005",
            format!("telemetry files not found: {}", missing.join(", ")),
        ));
    }

    // L2-006: each telemetry JSONL file contains valid JSON lines.
    let mut bad_files = Vec::new();
    for path_str in &existing_paths {
        let full_path = bundle.join(path_str);
        if let Ok(content) = fs::read_to_string(&full_path) {
            let has_bad_line = content
                .lines()
                .filter(|l| !l.is_empty())
                .any(|l| serde_json::from_str::<Value>(l).is_err());
            if has_bad_line {
                bad_files.push(*path_str);
            }
        } else {
            bad_files.push(*path_str);
        }
    }

    if bad_files.is_empty() && !existing_paths.is_empty() {
        checks.push(pass(
            "L2-006",
            "all telemetry JSONL files contain valid JSON",
        ));
    } else if !bad_files.is_empty() {
        checks.push(fail(
            "L2-006",
            format!("invalid JSON in telemetry files: {}", bad_files.join(", ")),
        ));
    }
}

// ── L4-001 ──────────────────────────────────────────────────

fn validate_l4_lite(bundle: &Path, records: &[Value], checks: &mut Vec<Check>) {
    let net_dir = bundle.join("net");
    if !net_dir.is_dir() {
        checks.push(fail("L4-001", "net/ directory not found"));
        return;
    }

    let packets = match pcap::read_all_packets(&net_dir) {
        Ok(p) => p,
        Err(e) => {
            checks.push(fail("L4-001", format!("failed to read PCAP files: {e}")));
            return;
        }
    };

    if packets.is_empty() {
        checks.push(fail("L4-001", "no packets found in PCAP files"));
        return;
    }

    let network_records: Vec<&Value> = records
        .iter()
        .filter(|r| r.get("session_type").and_then(Value::as_str) == Some("network"))
        .collect();

    if network_records.is_empty() {
        checks.push(fail("L4-001", "no network sessions found in GT"));
        return;
    }

    let mut unmatched = Vec::new();
    for (i, record) in network_records.iter().enumerate() {
        if !matches_any_packet(record, &packets) {
            unmatched.push(i + 1);
        }
    }

    if unmatched.is_empty() {
        checks.push(pass(
            "L4-001",
            format!(
                "all {} GT network session(s) match a PCAP flow",
                network_records.len(),
            ),
        ));
    } else {
        checks.push(fail(
            "L4-001",
            format!(
                "{}/{} GT network session(s) have no matching PCAP flow: records {unmatched:?}",
                unmatched.len(),
                network_records.len(),
            ),
        ));
    }
}

fn matches_any_packet(record: &Value, packets: &[pcap::Packet]) -> bool {
    let start_us = record
        .get("start")
        .and_then(Value::as_str)
        .and_then(parse_timestamp_us);
    let end_us = record
        .get("end")
        .and_then(Value::as_str)
        .and_then(parse_timestamp_us);

    let (Some(start_us), Some(end_us)) = (start_us, end_us) else {
        return false;
    };
    let end_us = end_us + 1_000_000;

    let src_ip = record
        .get("src_ip")
        .and_then(Value::as_str)
        .and_then(|s| s.parse::<Ipv4Addr>().ok());
    let dst_ip = record
        .get("dst_ip")
        .and_then(Value::as_str)
        .and_then(|s| s.parse::<Ipv4Addr>().ok());
    let src_port = record
        .get("src_port")
        .and_then(Value::as_u64)
        .and_then(|p| u16::try_from(p).ok());
    let dst_port = record
        .get("dst_port")
        .and_then(Value::as_u64)
        .and_then(|p| u16::try_from(p).ok());
    let protocol = record
        .get("protocol")
        .and_then(Value::as_str)
        .and_then(parse_protocol);

    let (Some(src_ip), Some(dst_ip), Some(src_port), Some(dst_port), Some(protocol)) =
        (src_ip, dst_ip, src_port, dst_port, protocol)
    else {
        return false;
    };

    packets.iter().any(|p| {
        p.ts_us >= start_us
            && p.ts_us <= end_us
            && p.src_ip == src_ip
            && p.dst_ip == dst_ip
            && p.src_port == src_port
            && p.dst_port == dst_port
            && p.protocol == protocol
    })
}

fn parse_timestamp_us(s: &str) -> Option<i64> {
    chrono::DateTime::parse_from_rfc3339(s)
        .ok()
        .map(|dt| dt.timestamp_micros())
}

fn parse_protocol(s: &str) -> Option<Protocol> {
    match s {
        "tcp" => Some(Protocol::Tcp),
        "udp" => Some(Protocol::Udp),
        "icmp" => Some(Protocol::Icmp),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── helpers ──────────────────────────────────────────────

    const NORMAL_RECORD: &str = r#"{"scope":"session","label":"normal","start":"2026-01-15T09:00:30Z","end":"2026-01-15T09:00:31Z","source":"attacker-001","target":"target-001","session_type":"network","protocol":"tcp","src_ip":"10.100.0.2","src_port":49152,"dst_ip":"10.100.0.3","dst_port":80}"#;

    const ATTACK_RECORD: &str = r#"{"scope":"session","label":"anomaly","start":"2026-01-15T09:02:00Z","end":"2026-01-15T09:02:01Z","source":"attacker-001","target":"target-001","session_type":"network","protocol":"tcp","src_ip":"10.100.0.2","src_port":50000,"dst_ip":"10.100.0.3","dst_port":80,"category":"attack","technique":"T1046","phase":"reconnaissance","tool":"nmap"}"#;

    fn meta_json() -> &'static str {
        include_str!("../scenarios/ac-0-expected/meta.json")
    }

    fn gt_content() -> String {
        format!("{NORMAL_RECORD}\n{ATTACK_RECORD}\n")
    }

    fn ts_for(s: &str) -> u32 {
        u32::try_from(chrono::DateTime::parse_from_rfc3339(s).unwrap().timestamp()).unwrap()
    }

    fn pcap_global_header() -> Vec<u8> {
        let mut hdr = Vec::new();
        hdr.extend_from_slice(&PCAP_MAGIC_LE);
        hdr.extend_from_slice(&2u16.to_le_bytes());
        hdr.extend_from_slice(&4u16.to_le_bytes());
        hdr.extend_from_slice(&0i32.to_le_bytes());
        hdr.extend_from_slice(&0u32.to_le_bytes());
        hdr.extend_from_slice(&65535u32.to_le_bytes());
        hdr.extend_from_slice(&1u32.to_le_bytes());
        hdr
    }

    struct PcapFlow {
        ts: u32,
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        src_port: u16,
        dst_port: u16,
    }

    fn build_pcap(packets: &[PcapFlow]) -> Vec<u8> {
        let mut data = pcap_global_header();
        for p in packets {
            data.extend(tcp_packet_record(
                p.ts, p.src_ip, p.dst_ip, p.src_port, p.dst_port,
            ));
        }
        data
    }

    fn synthetic_pcap() -> Vec<u8> {
        build_pcap(&[
            PcapFlow {
                ts: ts_for("2026-01-15T09:00:30Z"),
                src_ip: [10, 100, 0, 2],
                dst_ip: [10, 100, 0, 3],
                src_port: 49152,
                dst_port: 80,
            },
            PcapFlow {
                ts: ts_for("2026-01-15T09:02:00Z"),
                src_ip: [10, 100, 0, 2],
                dst_ip: [10, 100, 0, 3],
                src_port: 50000,
                dst_port: 80,
            },
        ])
    }

    fn tcp_packet_record(
        ts_sec: u32,
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        src_port: u16,
        dst_port: u16,
    ) -> Vec<u8> {
        let mut pkt = Vec::new();
        // Ethernet
        pkt.extend_from_slice(&[0u8; 12]);
        pkt.extend_from_slice(&0x0800u16.to_be_bytes());
        // IPv4
        pkt.push(0x45);
        pkt.push(0);
        pkt.extend_from_slice(&40u16.to_be_bytes());
        pkt.extend_from_slice(&[0; 4]);
        pkt.push(64);
        pkt.push(6);
        pkt.extend_from_slice(&[0; 2]);
        pkt.extend_from_slice(&src_ip);
        pkt.extend_from_slice(&dst_ip);
        // TCP
        pkt.extend_from_slice(&src_port.to_be_bytes());
        pkt.extend_from_slice(&dst_port.to_be_bytes());
        pkt.extend_from_slice(&[0; 16]);

        let pkt_len = u32::try_from(pkt.len()).unwrap();
        let mut record = Vec::new();
        record.extend_from_slice(&ts_sec.to_le_bytes());
        record.extend_from_slice(&0u32.to_le_bytes());
        record.extend_from_slice(&pkt_len.to_le_bytes());
        record.extend_from_slice(&pkt_len.to_le_bytes());
        record.extend(pkt);
        record
    }

    fn create_valid_bundle(dir: &Path) {
        fs::create_dir_all(dir.join("ground_truth")).unwrap();
        fs::create_dir_all(dir.join("net")).unwrap();
        fs::create_dir_all(dir.join("host/attacker-001")).unwrap();
        fs::create_dir_all(dir.join("host/target-001")).unwrap();
        fs::write(dir.join("meta.json"), meta_json()).unwrap();
        fs::write(dir.join("ground_truth/manifest.jsonl"), gt_content()).unwrap();
        fs::write(dir.join("net/capture-lan.pcap"), synthetic_pcap()).unwrap();
    }

    fn find_check<'a>(report: &'a Report, id: &str) -> Option<&'a Check> {
        report.checks.iter().find(|c| c.id == id)
    }

    fn assert_pass(report: &Report, id: &str) {
        let check =
            find_check(report, id).unwrap_or_else(|| panic!("check {id} not found in report"));
        assert_eq!(
            check.status,
            Status::Pass,
            "expected {id} to pass: {}",
            check.message,
        );
    }

    fn assert_fail(report: &Report, id: &str) {
        let check =
            find_check(report, id).unwrap_or_else(|| panic!("check {id} not found in report"));
        assert_eq!(
            check.status,
            Status::Fail,
            "expected {id} to fail: {}",
            check.message,
        );
    }

    // ── valid bundle ────────────────────────────────────────

    #[test]
    fn valid_bundle_passes_all_checks() {
        let dir = tempfile::tempdir().unwrap();
        create_valid_bundle(dir.path());
        let report = run(dir.path()).unwrap();

        assert_eq!(
            report.summary.failed, 0,
            "expected no failures: {:#?}",
            report.checks,
        );
        for id in [
            "L1-001", "L1-002", "L1-003", "L1-004", "L2-001", "L2-002", "L2-003", "L2-004",
            "L2-005", "L3-001", "L3-002", "L3-003", "L3-005", "L3-006", "L3-007", "L3-008",
            "L4-001",
        ] {
            assert_pass(&report, id);
        }
    }

    #[test]
    fn exit_code_zero_when_all_pass() {
        let dir = tempfile::tempdir().unwrap();
        create_valid_bundle(dir.path());
        let report = run(dir.path()).unwrap();
        assert_eq!(report.exit_code(), ExitCode::SUCCESS);
    }

    #[test]
    fn report_serializes_to_valid_json() {
        let dir = tempfile::tempdir().unwrap();
        create_valid_bundle(dir.path());
        let report = run(dir.path()).unwrap();
        let json = serde_json::to_string_pretty(&report).unwrap();
        let parsed: Value = serde_json::from_str(&json).unwrap();
        assert!(parsed.get("checks").unwrap().is_array());
        assert!(parsed.get("summary").unwrap().is_object());
    }

    // ── L1 failures ─────────────────────────────────────────

    #[test]
    fn missing_meta_json_fails_l1_001() {
        let dir = tempfile::tempdir().unwrap();
        create_valid_bundle(dir.path());
        fs::remove_file(dir.path().join("meta.json")).unwrap();
        let report = run(dir.path()).unwrap();
        assert_fail(&report, "L1-001");
    }

    #[test]
    fn empty_meta_json_fails_l1_001() {
        let dir = tempfile::tempdir().unwrap();
        create_valid_bundle(dir.path());
        fs::write(dir.path().join("meta.json"), "").unwrap();
        let report = run(dir.path()).unwrap();
        assert_fail(&report, "L1-001");
    }

    #[test]
    fn missing_manifest_fails_l1_002() {
        let dir = tempfile::tempdir().unwrap();
        create_valid_bundle(dir.path());
        fs::remove_file(dir.path().join("ground_truth/manifest.jsonl")).unwrap();
        let report = run(dir.path()).unwrap();
        assert_fail(&report, "L1-002");
    }

    #[test]
    fn missing_pcap_fails_l1_003() {
        let dir = tempfile::tempdir().unwrap();
        create_valid_bundle(dir.path());
        fs::remove_file(dir.path().join("net/capture-lan.pcap")).unwrap();
        let report = run(dir.path()).unwrap();
        assert_fail(&report, "L1-003");
    }

    #[test]
    fn missing_host_dir_fails_l1_004() {
        let dir = tempfile::tempdir().unwrap();
        create_valid_bundle(dir.path());
        fs::remove_dir(dir.path().join("host/target-001")).unwrap();
        let report = run(dir.path()).unwrap();
        assert_fail(&report, "L1-004");
    }

    // ── L2 failures ─────────────────────────────────────────

    #[test]
    fn invalid_json_meta_fails_l2_001() {
        let dir = tempfile::tempdir().unwrap();
        create_valid_bundle(dir.path());
        fs::write(dir.path().join("meta.json"), "not json{").unwrap();
        let report = run(dir.path()).unwrap();
        assert_pass(&report, "L1-001");
        assert_fail(&report, "L2-001");
    }

    #[test]
    fn missing_meta_field_fails_l2_002() {
        let dir = tempfile::tempdir().unwrap();
        create_valid_bundle(dir.path());
        fs::write(
            dir.path().join("meta.json"),
            r#"{"schema_version":"1","scenario":"t","scenario_version":"1","generated_at":"x","duration":{},"environment":{},"hosts":[],"network":{}}"#,
        )
        .unwrap();
        let report = run(dir.path()).unwrap();
        assert_pass(&report, "L2-001");
        assert_fail(&report, "L2-002");
    }

    #[test]
    fn invalid_json_gt_line_fails_l2_003() {
        let dir = tempfile::tempdir().unwrap();
        create_valid_bundle(dir.path());
        fs::write(dir.path().join("ground_truth/manifest.jsonl"), "not json\n").unwrap();
        let report = run(dir.path()).unwrap();
        assert_pass(&report, "L1-002");
        assert_fail(&report, "L2-003");
    }

    #[test]
    fn invalid_pcap_magic_fails_l2_004() {
        let dir = tempfile::tempdir().unwrap();
        create_valid_bundle(dir.path());
        fs::write(dir.path().join("net/capture-lan.pcap"), [0u8; 24]).unwrap();
        let report = run(dir.path()).unwrap();
        assert_pass(&report, "L1-003");
        assert_fail(&report, "L2-004");
    }

    #[test]
    fn missing_gt_common_field_fails_l2_005() {
        let dir = tempfile::tempdir().unwrap();
        create_valid_bundle(dir.path());
        fs::write(
            dir.path().join("ground_truth/manifest.jsonl"),
            concat!(
                r#"{"scope":"session","label":"normal","start":"2026-01-15T09:00:30Z","#,
                r#""end":"2026-01-15T09:00:31Z","source":"attacker-001","target":"target-001"}"#,
                "\n",
            ),
        )
        .unwrap();
        let report = run(dir.path()).unwrap();
        assert_pass(&report, "L2-003");
        assert_fail(&report, "L2-005");
    }

    // ── L3 failures ─────────────────────────────────────────

    #[test]
    fn start_not_before_end_fails_l3_001() {
        let dir = tempfile::tempdir().unwrap();
        create_valid_bundle(dir.path());
        let bad = NORMAL_RECORD.replace(
            "\"start\":\"2026-01-15T09:00:30Z\"",
            "\"start\":\"2026-01-15T09:00:32Z\"",
        );
        fs::write(
            dir.path().join("ground_truth/manifest.jsonl"),
            format!("{bad}\n"),
        )
        .unwrap();
        let report = run(dir.path()).unwrap();
        assert_fail(&report, "L3-001");
    }

    #[test]
    fn unsorted_records_fails_l3_002() {
        let dir = tempfile::tempdir().unwrap();
        create_valid_bundle(dir.path());
        fs::write(
            dir.path().join("ground_truth/manifest.jsonl"),
            format!("{ATTACK_RECORD}\n{NORMAL_RECORD}\n"),
        )
        .unwrap();
        let report = run(dir.path()).unwrap();
        assert_fail(&report, "L3-002");
    }

    #[test]
    fn missing_network_field_fails_l3_003() {
        let dir = tempfile::tempdir().unwrap();
        create_valid_bundle(dir.path());
        let bad = concat!(
            r#"{"scope":"session","label":"normal","start":"2026-01-15T09:00:30Z","#,
            r#""end":"2026-01-15T09:00:31Z","source":"attacker-001","target":"target-001","#,
            r#""session_type":"network","protocol":"tcp","src_ip":"10.100.0.2","#,
            r#""dst_ip":"10.100.0.3","dst_port":80}"#,
        );
        fs::write(
            dir.path().join("ground_truth/manifest.jsonl"),
            format!("{bad}\n"),
        )
        .unwrap();
        let report = run(dir.path()).unwrap();
        assert_fail(&report, "L3-003");
    }

    #[test]
    fn anomaly_without_category_fails_l3_005() {
        let dir = tempfile::tempdir().unwrap();
        create_valid_bundle(dir.path());
        let bad = concat!(
            r#"{"scope":"session","label":"anomaly","start":"2026-01-15T09:02:00Z","#,
            r#""end":"2026-01-15T09:02:01Z","source":"attacker-001","target":"target-001","#,
            r#""session_type":"network","protocol":"tcp","src_ip":"10.100.0.2","#,
            r#""src_port":50000,"dst_ip":"10.100.0.3","dst_port":80}"#,
        );
        fs::write(
            dir.path().join("ground_truth/manifest.jsonl"),
            format!("{NORMAL_RECORD}\n{bad}\n"),
        )
        .unwrap();
        let report = run(dir.path()).unwrap();
        assert_fail(&report, "L3-005");
    }

    #[test]
    fn attack_without_technique_fails_l3_006() {
        let dir = tempfile::tempdir().unwrap();
        create_valid_bundle(dir.path());
        let bad = concat!(
            r#"{"scope":"session","label":"anomaly","start":"2026-01-15T09:02:00Z","#,
            r#""end":"2026-01-15T09:02:01Z","source":"attacker-001","target":"target-001","#,
            r#""session_type":"network","protocol":"tcp","src_ip":"10.100.0.2","#,
            r#""src_port":50000,"dst_ip":"10.100.0.3","dst_port":80,"category":"attack"}"#,
        );
        fs::write(
            dir.path().join("ground_truth/manifest.jsonl"),
            format!("{NORMAL_RECORD}\n{bad}\n"),
        )
        .unwrap();
        let report = run(dir.path()).unwrap();
        assert_fail(&report, "L3-006");
    }

    #[test]
    fn invalid_phase_fails_l3_007() {
        let dir = tempfile::tempdir().unwrap();
        create_valid_bundle(dir.path());
        let bad = ATTACK_RECORD.replace("reconnaissance", "invalid_phase");
        fs::write(
            dir.path().join("ground_truth/manifest.jsonl"),
            format!("{NORMAL_RECORD}\n{bad}\n"),
        )
        .unwrap();
        let report = run(dir.path()).unwrap();
        assert_fail(&report, "L3-007");
    }

    #[test]
    fn unknown_host_fails_l3_008() {
        let dir = tempfile::tempdir().unwrap();
        create_valid_bundle(dir.path());
        let bad = NORMAL_RECORD.replace("attacker-001", "unknown-host");
        fs::write(
            dir.path().join("ground_truth/manifest.jsonl"),
            format!("{bad}\n"),
        )
        .unwrap();
        let report = run(dir.path()).unwrap();
        assert_fail(&report, "L3-008");
    }

    // ── L4 failures ─────────────────────────────────────────

    #[test]
    fn partial_pcap_match_fails_l4_001() {
        let dir = tempfile::tempdir().unwrap();
        create_valid_bundle(dir.path());
        // PCAP matches only the normal record (port 80 at 09:00:30Z),
        // but not the attack record (port 80 at 09:02:00Z).
        let data = build_pcap(&[PcapFlow {
            ts: ts_for("2026-01-15T09:00:30Z"),
            src_ip: [10, 100, 0, 2],
            dst_ip: [10, 100, 0, 3],
            src_port: 49152,
            dst_port: 80,
        }]);
        fs::write(dir.path().join("net/capture-lan.pcap"), data).unwrap();
        let report = run(dir.path()).unwrap();
        assert_fail(&report, "L4-001");
    }

    #[test]
    fn no_matching_pcap_flow_fails_l4_001() {
        let dir = tempfile::tempdir().unwrap();
        create_valid_bundle(dir.path());
        // Replace pcap with one that has wrong dst_port (443 instead of 80).
        let data = build_pcap(&[PcapFlow {
            ts: ts_for("2026-01-15T09:00:30Z"),
            src_ip: [10, 100, 0, 2],
            dst_ip: [10, 100, 0, 3],
            src_port: 49152,
            dst_port: 443,
        }]);
        fs::write(dir.path().join("net/capture-lan.pcap"), data).unwrap();
        let report = run(dir.path()).unwrap();
        assert_fail(&report, "L4-001");
    }

    #[test]
    fn empty_pcap_fails_l4_001() {
        let dir = tempfile::tempdir().unwrap();
        create_valid_bundle(dir.path());
        fs::write(
            dir.path().join("net/capture-lan.pcap"),
            pcap_global_header(),
        )
        .unwrap();
        let report = run(dir.path()).unwrap();
        assert_fail(&report, "L4-001");
    }

    // ── exit codes ──────────────────────────────────────────

    #[test]
    fn exit_code_two_on_failure() {
        let dir = tempfile::tempdir().unwrap();
        create_valid_bundle(dir.path());
        fs::remove_file(dir.path().join("meta.json")).unwrap();
        let report = run(dir.path()).unwrap();
        assert_eq!(report.exit_code(), ExitCode::from(2));
    }

    // ── edge cases ──────────────────────────────────────────

    #[test]
    fn non_directory_bundle_errors() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("not-a-dir");
        fs::write(&file_path, "hello").unwrap();
        assert!(run(&file_path).is_err());
    }

    #[test]
    fn equal_start_end_passes_l3_001() {
        let dir = tempfile::tempdir().unwrap();
        create_valid_bundle(dir.path());
        let zero_dur = NORMAL_RECORD.replace(
            "\"end\":\"2026-01-15T09:00:31Z\"",
            "\"end\":\"2026-01-15T09:00:30Z\"",
        );
        fs::write(
            dir.path().join("ground_truth/manifest.jsonl"),
            format!("{zero_dur}\n"),
        )
        .unwrap();
        let report = run(dir.path()).unwrap();
        assert_pass(&report, "L3-001");
    }

    #[test]
    fn end_before_start_fails_l3_001() {
        let dir = tempfile::tempdir().unwrap();
        create_valid_bundle(dir.path());
        let bad = NORMAL_RECORD.replace(
            "\"end\":\"2026-01-15T09:00:31Z\"",
            "\"end\":\"2026-01-15T09:00:29Z\"",
        );
        fs::write(
            dir.path().join("ground_truth/manifest.jsonl"),
            format!("{bad}\n"),
        )
        .unwrap();
        let report = run(dir.path()).unwrap();
        assert_fail(&report, "L3-001");
    }

    #[test]
    fn equal_start_times_pass_l3_002() {
        let dir = tempfile::tempdir().unwrap();
        create_valid_bundle(dir.path());
        let r2 = NORMAL_RECORD.replace("49152", "49153");
        fs::write(
            dir.path().join("ground_truth/manifest.jsonl"),
            format!("{NORMAL_RECORD}\n{r2}\n"),
        )
        .unwrap();
        let report = run(dir.path()).unwrap();
        assert_pass(&report, "L3-002");
    }

    #[test]
    fn normal_only_records_pass_anomaly_checks() {
        let dir = tempfile::tempdir().unwrap();
        create_valid_bundle(dir.path());
        fs::write(
            dir.path().join("ground_truth/manifest.jsonl"),
            format!("{NORMAL_RECORD}\n"),
        )
        .unwrap();
        let report = run(dir.path()).unwrap();
        assert_pass(&report, "L3-005");
        assert_pass(&report, "L3-006");
        assert_pass(&report, "L3-007");
    }

    #[test]
    fn unknown_target_only_fails_l3_008() {
        let dir = tempfile::tempdir().unwrap();
        create_valid_bundle(dir.path());
        let bad = NORMAL_RECORD.replace("\"target\":\"target-001\"", "\"target\":\"ghost\"");
        fs::write(
            dir.path().join("ground_truth/manifest.jsonl"),
            format!("{bad}\n"),
        )
        .unwrap();
        let report = run(dir.path()).unwrap();
        assert_fail(&report, "L3-008");
    }

    #[test]
    fn multiple_checks_fail_simultaneously() {
        let dir = tempfile::tempdir().unwrap();
        create_valid_bundle(dir.path());
        // Bad GT: unsorted, start > end, missing network field, unknown host.
        let bad1 = concat!(
            r#"{"scope":"session","label":"normal","start":"2026-01-15T09:05:00Z","#,
            r#""end":"2026-01-15T09:04:00Z","source":"ghost","target":"target-001","#,
            r#""session_type":"network","protocol":"tcp","src_ip":"10.100.0.2","#,
            r#""dst_ip":"10.100.0.3","dst_port":80}"#,
        );
        let bad2 = concat!(
            r#"{"scope":"session","label":"normal","start":"2026-01-15T09:00:30Z","#,
            r#""end":"2026-01-15T09:00:31Z","source":"attacker-001","target":"target-001","#,
            r#""session_type":"network","protocol":"tcp","src_ip":"10.100.0.2","#,
            r#""src_port":49152,"dst_ip":"10.100.0.3","dst_port":80}"#,
        );
        fs::write(
            dir.path().join("ground_truth/manifest.jsonl"),
            format!("{bad1}\n{bad2}\n"),
        )
        .unwrap();
        let report = run(dir.path()).unwrap();
        assert_fail(&report, "L3-001");
        assert_fail(&report, "L3-002");
        assert_fail(&report, "L3-003");
        assert_fail(&report, "L3-008");
        assert!(
            report.summary.failed >= 4,
            "expected at least 4 failures, got {}",
            report.summary.failed,
        );
    }

    #[test]
    fn empty_manifest_fails_l1_002() {
        let dir = tempfile::tempdir().unwrap();
        create_valid_bundle(dir.path());
        fs::write(dir.path().join("ground_truth/manifest.jsonl"), "").unwrap();
        let report = run(dir.path()).unwrap();
        assert_fail(&report, "L1-002");
    }

    #[test]
    fn mixed_valid_and_invalid_json_lines_fails_l2_003() {
        let dir = tempfile::tempdir().unwrap();
        create_valid_bundle(dir.path());
        fs::write(
            dir.path().join("ground_truth/manifest.jsonl"),
            format!("{NORMAL_RECORD}\nnot json\n{ATTACK_RECORD}\n"),
        )
        .unwrap();
        let report = run(dir.path()).unwrap();
        assert_pass(&report, "L1-002");
        assert_fail(&report, "L2-003");
    }

    #[test]
    fn report_summary_counts_are_correct() {
        let dir = tempfile::tempdir().unwrap();
        create_valid_bundle(dir.path());
        let report = run(dir.path()).unwrap();
        let json = serde_json::to_string(&report).unwrap();
        let parsed: Value = serde_json::from_str(&json).unwrap();
        let summary = parsed.get("summary").unwrap();
        assert_eq!(summary["total"], report.checks.len());
        assert_eq!(summary["passed"], report.checks.len());
        assert_eq!(summary["failed"], 0);
        assert_eq!(summary["warned"], 0);
    }

    #[test]
    fn l3_008_skipped_when_meta_missing() {
        let dir = tempfile::tempdir().unwrap();
        create_valid_bundle(dir.path());
        fs::remove_file(dir.path().join("meta.json")).unwrap();
        let report = run(dir.path()).unwrap();
        assert!(
            find_check(&report, "L3-008").is_none(),
            "L3-008 should be skipped when meta.json is missing",
        );
    }

    // ── timezone-aware comparisons ────────────────────────────

    #[test]
    fn different_utc_offsets_same_instant_passes_l3_001() {
        let dir = tempfile::tempdir().unwrap();
        create_valid_bundle(dir.path());
        // +09:00 offset: 2026-01-15T18:00:30+09:00 == 2026-01-15T09:00:30Z
        let record = NORMAL_RECORD
            .replace(
                "\"start\":\"2026-01-15T09:00:30Z\"",
                "\"start\":\"2026-01-15T18:00:30+09:00\"",
            )
            .replace(
                "\"end\":\"2026-01-15T09:00:31Z\"",
                "\"end\":\"2026-01-15T18:00:31+09:00\"",
            );
        fs::write(
            dir.path().join("ground_truth/manifest.jsonl"),
            format!("{record}\n"),
        )
        .unwrap();
        let report = run(dir.path()).unwrap();
        assert_pass(&report, "L3-001");
        assert_pass(&report, "L3-002");
    }

    #[test]
    fn mixed_offsets_correct_order_passes_l3_002() {
        let dir = tempfile::tempdir().unwrap();
        create_valid_bundle(dir.path());
        // First record in +09:00, second in UTC — but first is earlier as an instant.
        let r1 = NORMAL_RECORD
            .replace(
                "\"start\":\"2026-01-15T09:00:30Z\"",
                "\"start\":\"2026-01-15T18:00:30+09:00\"",
            )
            .replace(
                "\"end\":\"2026-01-15T09:00:31Z\"",
                "\"end\":\"2026-01-15T18:00:31+09:00\"",
            );
        let r2 = ATTACK_RECORD; // starts at 09:02:00Z, after 09:00:30Z
        fs::write(
            dir.path().join("ground_truth/manifest.jsonl"),
            format!("{r1}\n{r2}\n"),
        )
        .unwrap();
        let report = run(dir.path()).unwrap();
        assert_pass(&report, "L3-002");
    }

    // ── L4 session_type gating ──────────────────────────────

    #[test]
    fn l4_001_ignores_non_network_sessions() {
        let dir = tempfile::tempdir().unwrap();
        create_valid_bundle(dir.path());
        // Replace GT with a record that has matching 5-tuple but session_type=host.
        let non_network =
            NORMAL_RECORD.replace("\"session_type\":\"network\"", "\"session_type\":\"host\"");
        fs::write(
            dir.path().join("ground_truth/manifest.jsonl"),
            format!("{non_network}\n"),
        )
        .unwrap();
        let report = run(dir.path()).unwrap();
        assert_fail(&report, "L4-001");
    }

    // ── AC-0 reference bundle ───────────────────────────────

    #[test]
    fn validate_ac0_reference_bundle() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("scenarios/ac-0-expected");
        let report = run(&dir).unwrap();
        assert_eq!(
            report.summary.failed, 0,
            "AC-0 reference bundle has failures: {:#?}",
            report.checks,
        );
        for id in [
            "L1-001", "L1-002", "L1-003", "L1-004", "L2-001", "L2-002", "L2-003", "L2-004",
            "L2-005", "L3-001", "L3-002", "L3-003", "L3-005", "L3-006", "L3-007", "L3-008",
            "L4-001",
        ] {
            assert_pass(&report, id);
        }
    }

    // ── L1-005 + L2-006: host telemetry ──────────────────────────

    #[test]
    fn telemetry_checks_skipped_when_no_host_telemetry() {
        let dir = tempfile::tempdir().unwrap();
        create_valid_bundle(dir.path());
        let report = run(dir.path()).unwrap();
        // No L1-005 or L2-006 checks should appear at all.
        assert!(
            find_check(&report, "L1-005").is_none(),
            "L1-005 should be absent when no host_telemetry",
        );
        assert!(
            find_check(&report, "L2-006").is_none(),
            "L2-006 should be absent when no host_telemetry",
        );
    }

    #[test]
    fn telemetry_files_pass_when_present_and_valid() {
        let dir = tempfile::tempdir().unwrap();
        create_valid_bundle(dir.path());

        // Add host_telemetry to meta.json.
        let meta_path = dir.path().join("meta.json");
        let mut meta: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&meta_path).unwrap()).unwrap();
        meta["host_telemetry"] = serde_json::json!([
            {"host": "target-001", "kind": "sysmon", "path": "host/target-001/sysmon.jsonl"}
        ]);
        fs::write(&meta_path, serde_json::to_string_pretty(&meta).unwrap()).unwrap();

        // Create the sysmon.jsonl file with valid JSON.
        let sysmon_path = dir.path().join("host/target-001/sysmon.jsonl");
        fs::write(&sysmon_path, "{\"EventID\":1}\n{\"EventID\":3}\n").unwrap();

        let report = run(dir.path()).unwrap();
        assert_pass(&report, "L1-005");
        assert_pass(&report, "L2-006");
    }

    #[test]
    fn missing_telemetry_file_fails_l1_005() {
        let dir = tempfile::tempdir().unwrap();
        create_valid_bundle(dir.path());

        let meta_path = dir.path().join("meta.json");
        let mut meta: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&meta_path).unwrap()).unwrap();
        meta["host_telemetry"] = serde_json::json!([
            {"host": "target-001", "kind": "sysmon", "path": "host/target-001/sysmon.jsonl"}
        ]);
        fs::write(&meta_path, serde_json::to_string_pretty(&meta).unwrap()).unwrap();

        // Do NOT create the file.
        let report = run(dir.path()).unwrap();
        assert_fail(&report, "L1-005");
    }

    #[test]
    fn invalid_telemetry_json_fails_l2_006() {
        let dir = tempfile::tempdir().unwrap();
        create_valid_bundle(dir.path());

        let meta_path = dir.path().join("meta.json");
        let mut meta: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&meta_path).unwrap()).unwrap();
        meta["host_telemetry"] = serde_json::json!([
            {"host": "target-001", "kind": "sysmon", "path": "host/target-001/sysmon.jsonl"}
        ]);
        fs::write(&meta_path, serde_json::to_string_pretty(&meta).unwrap()).unwrap();

        // Write invalid JSON.
        let sysmon_path = dir.path().join("host/target-001/sysmon.jsonl");
        fs::write(&sysmon_path, "not valid json\n").unwrap();

        let report = run(dir.path()).unwrap();
        assert_pass(&report, "L1-005");
        assert_fail(&report, "L2-006");
    }
}
