use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;

use anyhow::{Context, Result};
use serde::Serialize;

use crate::activity::Execution;
use crate::scenario::{Phase, Protocol};

/// A single ground-truth record in the v1 JSONL format.
#[derive(Serialize)]
struct Record {
    scope: &'static str,
    label: &'static str,
    start: String,
    end: String,
    source: String,
    target: String,
    session_type: &'static str,
    protocol: Protocol,
    src_ip: String,
    dst_ip: String,
    dst_port: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    category: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    technique: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    phase: Option<Phase>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tool: Option<String>,
}

/// Writes ground-truth records to `ground_truth/manifest.jsonl` inside
/// the output directory, one JSON object per line sorted by start time.
pub(crate) fn write(output_dir: &Path, executions: &[Execution]) -> Result<()> {
    let path = output_dir.join("ground_truth").join("manifest.jsonl");
    let file =
        File::create(&path).with_context(|| format!("failed to create {}", path.display()))?;
    let mut writer = BufWriter::new(file);

    for exec in executions {
        let (label, category, technique, phase, tool) = match &exec.attack {
            None => ("normal", None, None, None, None),
            Some(detail) => (
                "anomaly",
                Some("attack"),
                Some(detail.technique.clone()),
                Some(detail.phase),
                Some(detail.tool.clone()),
            ),
        };

        let record = Record {
            scope: "session",
            label,
            start: format_ts(exec.start),
            end: format_ts(exec.end),
            source: exec.source.clone(),
            target: exec.target.clone(),
            session_type: "network",
            protocol: exec.protocol,
            src_ip: exec.src_ip.to_string(),
            dst_ip: exec.dst_ip.to_string(),
            dst_port: exec.dst_port,
            category,
            technique,
            phase,
            tool,
        };

        let json =
            serde_json::to_string(&record).context("failed to serialize ground truth record")?;
        writeln!(writer, "{json}").context("failed to write ground truth record")?;
    }

    writer
        .flush()
        .context("failed to flush ground truth file")?;
    Ok(())
}

/// Formats a `DateTime<Utc>` as an ISO 8601 string without sub-second
/// precision, matching the v1 ground-truth timestamp convention.
fn format_ts(dt: chrono::DateTime<chrono::Utc>) -> String {
    dt.format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use chrono::TimeZone;

    use super::*;
    use crate::activity::AttackDetail;

    fn normal_execution() -> Execution {
        Execution {
            start: chrono::Utc.with_ymd_and_hms(2026, 1, 15, 9, 0, 30).unwrap(),
            end: chrono::Utc.with_ymd_and_hms(2026, 1, 15, 9, 0, 31).unwrap(),
            source: "attacker-001".to_owned(),
            target: "target-001".to_owned(),
            protocol: Protocol::Tcp,
            src_ip: Ipv4Addr::new(10, 100, 0, 2),
            dst_ip: Ipv4Addr::new(10, 100, 0, 3),
            dst_port: 80,
            attack: None,
        }
    }

    fn attack_execution() -> Execution {
        Execution {
            start: chrono::Utc.with_ymd_and_hms(2026, 1, 15, 9, 2, 0).unwrap(),
            end: chrono::Utc.with_ymd_and_hms(2026, 1, 15, 9, 2, 1).unwrap(),
            source: "attacker-001".to_owned(),
            target: "target-001".to_owned(),
            protocol: Protocol::Tcp,
            src_ip: Ipv4Addr::new(10, 100, 0, 2),
            dst_ip: Ipv4Addr::new(10, 100, 0, 3),
            dst_port: 80,
            attack: Some(AttackDetail {
                technique: "T1046".to_owned(),
                phase: Phase::Reconnaissance,
                tool: "nmap".to_owned(),
            }),
        }
    }

    fn write_and_read(executions: &[Execution]) -> String {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("ground_truth")).unwrap();
        write(dir.path(), executions).unwrap();
        std::fs::read_to_string(dir.path().join("ground_truth/manifest.jsonl")).unwrap()
    }

    // ── format_ts ─────────────────────────────────────────────────

    #[test]
    fn format_ts_omits_subseconds() {
        let dt = chrono::Utc.with_ymd_and_hms(2026, 1, 15, 9, 0, 30).unwrap();
        assert_eq!(format_ts(dt), "2026-01-15T09:00:30Z");
    }

    #[test]
    fn format_ts_midnight() {
        let dt = chrono::Utc.with_ymd_and_hms(2026, 3, 1, 0, 0, 0).unwrap();
        assert_eq!(format_ts(dt), "2026-03-01T00:00:00Z");
    }

    // ── empty executions ──────────────────────────────────────────

    #[test]
    fn write_empty_executions_produces_empty_file() {
        let content = write_and_read(&[]);
        assert!(content.is_empty());
    }

    // ── normal record ─────────────────────────────────────────────

    #[test]
    fn normal_record_has_all_required_fields() {
        let content = write_and_read(&[normal_execution()]);
        let record: serde_json::Value = serde_json::from_str(content.trim()).unwrap();

        assert_eq!(record["scope"], "session");
        assert_eq!(record["label"], "normal");
        assert_eq!(record["start"], "2026-01-15T09:00:30Z");
        assert_eq!(record["end"], "2026-01-15T09:00:31Z");
        assert_eq!(record["source"], "attacker-001");
        assert_eq!(record["target"], "target-001");
        assert_eq!(record["session_type"], "network");
        assert_eq!(record["protocol"], "tcp");
        assert_eq!(record["src_ip"], "10.100.0.2");
        assert_eq!(record["dst_ip"], "10.100.0.3");
        assert_eq!(record["dst_port"], 80);
    }

    #[test]
    fn normal_record_omits_attack_fields() {
        let content = write_and_read(&[normal_execution()]);
        let record: serde_json::Value = serde_json::from_str(content.trim()).unwrap();

        assert!(record.get("category").is_none());
        assert!(record.get("technique").is_none());
        assert!(record.get("phase").is_none());
        assert!(record.get("tool").is_none());
    }

    // ── anomaly record ────────────────────────────────────────────

    #[test]
    fn attack_record_has_all_required_fields() {
        let content = write_and_read(&[attack_execution()]);
        let record: serde_json::Value = serde_json::from_str(content.trim()).unwrap();

        assert_eq!(record["scope"], "session");
        assert_eq!(record["label"], "anomaly");
        assert_eq!(record["start"], "2026-01-15T09:02:00Z");
        assert_eq!(record["end"], "2026-01-15T09:02:01Z");
        assert_eq!(record["source"], "attacker-001");
        assert_eq!(record["target"], "target-001");
        assert_eq!(record["session_type"], "network");
        assert_eq!(record["protocol"], "tcp");
        assert_eq!(record["src_ip"], "10.100.0.2");
        assert_eq!(record["dst_ip"], "10.100.0.3");
        assert_eq!(record["dst_port"], 80);
        assert_eq!(record["category"], "attack");
        assert_eq!(record["technique"], "T1046");
        assert_eq!(record["phase"], "reconnaissance");
        assert_eq!(record["tool"], "nmap");
    }

    // ── multi-record ──────────────────────────────────────────────

    #[test]
    fn write_produces_one_json_line_per_execution() {
        let content = write_and_read(&[normal_execution(), attack_execution()]);
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 2);

        // Each line must be valid JSON.
        for line in &lines {
            let parsed: Result<serde_json::Value, _> = serde_json::from_str(line);
            assert!(parsed.is_ok(), "invalid JSON: {line}");
        }
    }

    #[test]
    fn write_preserves_execution_order() {
        let content = write_and_read(&[normal_execution(), attack_execution()]);
        let lines: Vec<&str> = content.lines().collect();

        let r0: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        let r1: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(r0["label"], "normal", "first record should be normal");
        assert_eq!(r1["label"], "anomaly", "second record should be anomaly");
    }

    // ── field order ───────────────────────────────────────────────

    #[test]
    fn normal_record_field_order_matches_v1_schema() {
        let content = write_and_read(&[normal_execution()]);
        let raw = content.trim();

        // serde_json preserves struct field order. Verify the keys
        // appear in the v1 canonical order by checking substring positions.
        let expected_order = [
            "scope",
            "label",
            "start",
            "end",
            "source",
            "target",
            "session_type",
            "protocol",
            "src_ip",
            "dst_ip",
            "dst_port",
        ];
        let mut last_pos = 0;
        for key in &expected_order {
            let pattern = format!("\"{key}\":");
            let pos = raw.find(&pattern).unwrap_or_else(|| {
                panic!("field '{key}' not found in record: {raw}");
            });
            assert!(
                pos >= last_pos,
                "field '{key}' at {pos} appears before previous field at {last_pos}: {raw}",
            );
            last_pos = pos;
        }
    }

    #[test]
    fn attack_record_field_order_matches_v1_schema() {
        let content = write_and_read(&[attack_execution()]);
        let raw = content.trim();

        let expected_order = [
            "scope",
            "label",
            "start",
            "end",
            "source",
            "target",
            "session_type",
            "protocol",
            "src_ip",
            "dst_ip",
            "dst_port",
            "category",
            "technique",
            "phase",
            "tool",
        ];
        let mut last_pos = 0;
        for key in &expected_order {
            let pattern = format!("\"{key}\":");
            let pos = raw.find(&pattern).unwrap_or_else(|| {
                panic!("field '{key}' not found in record: {raw}");
            });
            assert!(
                pos >= last_pos,
                "field '{key}' at {pos} appears before previous field at {last_pos}: {raw}",
            );
            last_pos = pos;
        }
    }

    // ── protocol variants ─────────────────────────────────────────

    #[test]
    fn write_serializes_udp_protocol() {
        let mut exec = normal_execution();
        exec.protocol = Protocol::Udp;
        let content = write_and_read(&[exec]);
        let record: serde_json::Value = serde_json::from_str(content.trim()).unwrap();
        assert_eq!(record["protocol"], "udp");
    }

    #[test]
    fn write_serializes_icmp_protocol() {
        let mut exec = normal_execution();
        exec.protocol = Protocol::Icmp;
        let content = write_and_read(&[exec]);
        let record: serde_json::Value = serde_json::from_str(content.trim()).unwrap();
        assert_eq!(record["protocol"], "icmp");
    }

    // ── phase variants ────────────────────────────────────────────

    #[test]
    fn write_serializes_all_phase_variants() {
        let phases = [
            (Phase::Reconnaissance, "reconnaissance"),
            (Phase::InitialAccess, "initial_access"),
            (Phase::CredentialAccess, "credential_access"),
            (Phase::LateralMovement, "lateral_movement"),
            (Phase::C2, "c2"),
            (Phase::Exfiltration, "exfiltration"),
        ];
        for (phase, expected) in &phases {
            let mut exec = attack_execution();
            exec.attack.as_mut().unwrap().phase = *phase;
            let content = write_and_read(&[exec]);
            let record: serde_json::Value = serde_json::from_str(content.trim()).unwrap();
            assert_eq!(
                record["phase"], *expected,
                "phase {phase:?} should serialize as '{expected}'",
            );
        }
    }
}
