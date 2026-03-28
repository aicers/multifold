use std::fs;
use std::net::Ipv4Addr;
use std::path::Path;

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use serde::Serialize;

use crate::scenario::{self, Attacker, Encryption, Os, Role, Scale, Scenario, Threat, Workload};

const SCHEMA_VERSION: &str = "1";

/// Writes `meta.json` into the output directory.
pub(crate) fn write(
    output_dir: &Path,
    scenario_filename: &str,
    scenario: &Scenario,
    host_ips: &[(String, Vec<Ipv4Addr>)],
    start: DateTime<Utc>,
) -> Result<()> {
    let meta = build(scenario_filename, scenario, host_ips, start)?;
    let json = serde_json::to_string_pretty(&meta).context("failed to serialise meta.json")?;
    let path = output_dir.join("meta.json");
    fs::write(&path, json).with_context(|| format!("failed to write {}", path.display()))?;
    Ok(())
}

fn build(
    scenario_filename: &str,
    scenario: &Scenario,
    host_ips: &[(String, Vec<Ipv4Addr>)],
    start: DateTime<Utc>,
) -> Result<BundleMeta> {
    let total_duration = scenario::parse_duration(&scenario.duration)?;
    let end = start + total_duration;

    let hosts: Vec<MetaHost> = host_ips
        .iter()
        .map(|(name, ips)| {
            let host = scenario
                .infrastructure
                .hosts
                .iter()
                .find(|h| h.name == *name);
            match host {
                Some(h) => Ok(MetaHost {
                    name: name.clone(),
                    os: h.os,
                    role: h.role,
                    ips: ips.iter().map(Ipv4Addr::to_string).collect(),
                }),
                None => bail!("host '{name}' not found in scenario"),
            }
        })
        .collect::<Result<_>>()?;

    let segments = scenario
        .infrastructure
        .network
        .segments
        .iter()
        .map(|s| MetaSegment {
            name: s.name.clone(),
            subnet: s.subnet.clone(),
        })
        .collect();

    Ok(BundleMeta {
        schema_version: SCHEMA_VERSION.to_owned(),
        scenario: scenario_filename.to_owned(),
        scenario_version: scenario.version.clone(),
        generated_at: fmt_time(start),
        duration: MetaDuration {
            total: scenario.duration.clone(),
            actual_start: fmt_time(start),
            actual_end: fmt_time(end),
        },
        environment: MetaEnvironment {
            scale: scenario.environment.scale,
            encryption: scenario.environment.encryption,
            workload: scenario.environment.workload,
            threat: scenario.environment.threat,
            attacker: scenario.environment.attacker,
        },
        hosts,
        network: MetaNetwork { segments },
        capture: MetaCapture {
            pcaps: scenario
                .infrastructure
                .network
                .segments
                .iter()
                .map(|s| MetaPcapEntry {
                    segment: s.name.clone(),
                    path: format!("net/capture-{}.pcap", s.name),
                })
                .collect(),
        },
    })
}

fn fmt_time(t: DateTime<Utc>) -> String {
    t.format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

#[derive(Debug, Serialize)]
struct BundleMeta {
    schema_version: String,
    scenario: String,
    scenario_version: String,
    generated_at: String,
    duration: MetaDuration,
    environment: MetaEnvironment,
    hosts: Vec<MetaHost>,
    network: MetaNetwork,
    capture: MetaCapture,
}

#[derive(Debug, Serialize)]
struct MetaDuration {
    total: String,
    actual_start: String,
    actual_end: String,
}

#[derive(Debug, Serialize)]
struct MetaEnvironment {
    scale: Scale,
    encryption: Encryption,
    workload: Workload,
    threat: Threat,
    attacker: Attacker,
}

#[derive(Debug, Serialize)]
struct MetaHost {
    name: String,
    os: Os,
    role: Role,
    ips: Vec<String>,
}

#[derive(Debug, Serialize)]
struct MetaNetwork {
    segments: Vec<MetaSegment>,
}

#[derive(Debug, Serialize)]
struct MetaSegment {
    name: String,
    subnet: String,
}

#[derive(Debug, Serialize)]
struct MetaCapture {
    pcaps: Vec<MetaPcapEntry>,
}

#[derive(Debug, Serialize)]
struct MetaPcapEntry {
    segment: String,
    path: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    type HostIps = Vec<(String, Vec<Ipv4Addr>)>;

    fn ac0_test_inputs() -> (Scenario, HostIps, DateTime<Utc>) {
        let yaml = include_str!("../scenarios/ac-0.scenario.yaml");
        let scenario: Scenario = serde_yaml::from_str(yaml).unwrap();
        let host_ips = vec![
            (
                "attacker-001".to_owned(),
                vec![Ipv4Addr::new(10, 100, 0, 2)],
            ),
            ("target-001".to_owned(), vec![Ipv4Addr::new(10, 100, 0, 3)]),
        ];
        let start = DateTime::parse_from_rfc3339("2026-01-15T09:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        (scenario, host_ips, start)
    }

    #[test]
    fn build_meta_matches_expected_structure() {
        let (scenario, host_ips, start) = ac0_test_inputs();
        let meta = build("ac-0.scenario.yaml", &scenario, &host_ips, start).unwrap();

        assert_eq!(meta.schema_version, "1");
        assert_eq!(meta.scenario, "ac-0.scenario.yaml");
        assert_eq!(meta.scenario_version, "1");
        assert_eq!(meta.generated_at, "2026-01-15T09:00:00Z");
        assert_eq!(meta.duration.total, "5m");
        assert_eq!(meta.duration.actual_start, "2026-01-15T09:00:00Z");
        assert_eq!(meta.duration.actual_end, "2026-01-15T09:05:00Z");
        assert_eq!(meta.hosts.len(), 2);
        assert_eq!(meta.hosts[0].name, "attacker-001");
        assert_eq!(meta.hosts[0].ips, vec!["10.100.0.2"]);
        assert_eq!(meta.hosts[1].name, "target-001");
        assert_eq!(meta.hosts[1].ips, vec!["10.100.0.3"]);
        assert_eq!(meta.network.segments.len(), 1);
        assert_eq!(meta.network.segments[0].name, "lan");
        assert_eq!(meta.capture.pcaps.len(), 1);
        assert_eq!(meta.capture.pcaps[0].segment, "lan");
        assert_eq!(meta.capture.pcaps[0].path, "net/capture-lan.pcap");
    }

    #[test]
    fn build_meta_json_roundtrip() {
        let (scenario, host_ips, start) = ac0_test_inputs();
        let meta = build("ac-0.scenario.yaml", &scenario, &host_ips, start).unwrap();
        let json = serde_json::to_string_pretty(&meta).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(value["hosts"][0]["ips"][0], "10.100.0.2");
        assert_eq!(value["hosts"][1]["ips"][0], "10.100.0.3");
        assert_eq!(value["environment"]["scale"], "minimal");
        assert_eq!(value["capture"]["pcaps"][0]["segment"], "lan");
        assert_eq!(value["capture"]["pcaps"][0]["path"], "net/capture-lan.pcap");
    }

    #[test]
    fn build_meta_matches_ac0_reference() {
        let (scenario, host_ips, start) = ac0_test_inputs();
        let meta = build("ac-0.scenario.yaml", &scenario, &host_ips, start).unwrap();
        let actual: serde_json::Value =
            serde_json::from_str(&serde_json::to_string_pretty(&meta).unwrap()).unwrap();

        let expected_str = include_str!("../scenarios/ac-0-expected/meta.json");
        let expected: serde_json::Value = serde_json::from_str(expected_str).unwrap();

        assert_eq!(actual, expected, "meta.json does not match reference");
    }

    #[test]
    fn write_creates_valid_json_file() {
        let (scenario, host_ips, start) = ac0_test_inputs();
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            "ac-0.scenario.yaml",
            &scenario,
            &host_ips,
            start,
        )
        .unwrap();

        let path = dir.path().join("meta.json");
        assert!(path.exists(), "meta.json was not created");

        let content = std::fs::read_to_string(&path).unwrap();
        let value: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert_eq!(value["schema_version"], "1");
        assert_eq!(value["hosts"][0]["name"], "attacker-001");
    }

    #[test]
    fn build_meta_rejects_unknown_host() {
        let (scenario, _, start) = ac0_test_inputs();
        let host_ips = vec![("ghost-host".to_owned(), vec![Ipv4Addr::new(10, 100, 0, 99)])];

        let err = build("ac-0.scenario.yaml", &scenario, &host_ips, start).unwrap_err();
        assert!(
            err.to_string().contains("not found in scenario"),
            "unexpected error: {err}",
        );
    }
}
