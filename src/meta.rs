use std::fs;
use std::net::Ipv4Addr;
use std::path::Path;

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use serde::Serialize;

use crate::scenario::{
    Attacker, Encryption, Os, Role, Scale, Scenario, Threat, VantagePoint, Workload,
};
use crate::time::TimeMap;

const SCHEMA_VERSION: &str = "1";

/// Writes `meta.json` into the output directory.
///
/// `actual_end` is the maximum rewritten timestamp aggregated by the
/// caller across every artifact rewrite pass; this function does not
/// recompute it from the scenario duration.
pub(crate) fn write(
    output_dir: &Path,
    scenario_filename: &str,
    scenario: &Scenario,
    host_ips: &[(String, Vec<Ipv4Addr>)],
    time_map: &TimeMap,
    actual_end: DateTime<Utc>,
    telemetry: &[(String, String, String)],
) -> Result<()> {
    let meta = build(
        scenario_filename,
        scenario,
        host_ips,
        time_map,
        actual_end,
        telemetry,
    )?;
    let json = serde_json::to_string_pretty(&meta).context("failed to serialise meta.json")?;
    let path = output_dir.join("meta.json");
    fs::write(&path, json).with_context(|| format!("failed to write {}", path.display()))?;
    Ok(())
}

fn build(
    scenario_filename: &str,
    scenario: &Scenario,
    host_ips: &[(String, Vec<Ipv4Addr>)],
    time_map: &TimeMap,
    actual_end: DateTime<Utc>,
    telemetry: &[(String, String, String)],
) -> Result<BundleMeta> {
    let total = scenario
        .logical_duration
        .clone()
        .unwrap_or_else(|| scenario.duration.clone());

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

    let host_telemetry: Vec<MetaTelemetryEntry> = telemetry
        .iter()
        .map(|(host, kind, path)| MetaTelemetryEntry {
            host: host.clone(),
            kind: kind.clone(),
            path: path.clone(),
        })
        .collect();

    Ok(BundleMeta {
        schema_version: SCHEMA_VERSION.to_owned(),
        scenario: scenario_filename.to_owned(),
        scenario_version: scenario.version.clone(),
        generated_at: fmt_time(time_map.real_generation_start()),
        duration: MetaDuration {
            total,
            actual_start: fmt_time(time_map.start_at()),
            actual_end: fmt_time(actual_end),
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
                    path: format!("net/{}.pcap", s.name),
                    vantage_point: s.vantage_point,
                })
                .collect(),
        },
        host_telemetry,
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
    #[serde(skip_serializing_if = "Vec::is_empty")]
    host_telemetry: Vec<MetaTelemetryEntry>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    vantage_point: Option<VantagePoint>,
}

#[derive(Debug, Serialize)]
struct MetaTelemetryEntry {
    host: String,
    kind: String,
    path: String,
}

#[cfg(test)]
mod tests {
    use chrono::Duration;

    use super::*;
    use crate::scenario::parse_duration;

    type HostIps = Vec<(String, Vec<Ipv4Addr>)>;

    /// Builds an identity (no-compression) `TimeMap` rooted at the
    /// given timestamp, sized to the scenario's declared duration.
    fn identity_time_map(start: DateTime<Utc>, scenario: &Scenario) -> TimeMap {
        let dur = parse_duration(&scenario.duration).unwrap();
        TimeMap::new(start, start, dur, dur).unwrap()
    }

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

    fn ac0_build(scenario: &Scenario, host_ips: &HostIps, start: DateTime<Utc>) -> BundleMeta {
        let tm = identity_time_map(start, scenario);
        let actual_end = start + Duration::try_minutes(5).unwrap();
        build(
            "ac-0.scenario.yaml",
            scenario,
            host_ips,
            &tm,
            actual_end,
            &[],
        )
        .unwrap()
    }

    #[test]
    fn build_meta_matches_expected_structure() {
        let (scenario, host_ips, start) = ac0_test_inputs();
        let meta = ac0_build(&scenario, &host_ips, start);

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
        assert_eq!(meta.capture.pcaps[0].path, "net/lan.pcap");
    }

    #[test]
    fn build_meta_json_roundtrip() {
        let (scenario, host_ips, start) = ac0_test_inputs();
        let meta = ac0_build(&scenario, &host_ips, start);
        let json = serde_json::to_string_pretty(&meta).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(value["hosts"][0]["ips"][0], "10.100.0.2");
        assert_eq!(value["hosts"][1]["ips"][0], "10.100.0.3");
        assert_eq!(value["environment"]["scale"], "minimal");
        assert_eq!(value["capture"]["pcaps"][0]["segment"], "lan");
        assert_eq!(value["capture"]["pcaps"][0]["path"], "net/lan.pcap");
    }

    #[test]
    fn build_meta_matches_ac0_reference() {
        let (scenario, host_ips, start) = ac0_test_inputs();
        let meta = ac0_build(&scenario, &host_ips, start);
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
        let tm = identity_time_map(start, &scenario);
        let actual_end = start + Duration::try_minutes(5).unwrap();
        write(
            dir.path(),
            "ac-0.scenario.yaml",
            &scenario,
            &host_ips,
            &tm,
            actual_end,
            &[],
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
        let tm = identity_time_map(start, &scenario);
        let actual_end = start + Duration::try_minutes(5).unwrap();

        let err = build(
            "ac-0.scenario.yaml",
            &scenario,
            &host_ips,
            &tm,
            actual_end,
            &[],
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("not found in scenario"),
            "unexpected error: {err}",
        );
    }

    #[test]
    fn build_meta_omits_vantage_point_when_absent() {
        let (scenario, host_ips, start) = ac0_test_inputs();
        let meta = ac0_build(&scenario, &host_ips, start);
        let json = serde_json::to_string_pretty(&meta).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert!(
            value["capture"]["pcaps"][0].get("vantage_point").is_none(),
            "vantage_point should be omitted when not set",
        );
    }

    fn ac2_tls_test_inputs() -> (Scenario, HostIps, DateTime<Utc>) {
        let yaml = include_str!("../scenarios/ac-2-tls.scenario.yaml");
        let scenario: Scenario = serde_yaml::from_str(yaml).unwrap();
        let host_ips = vec![
            (
                "attacker-001".to_owned(),
                vec![Ipv4Addr::new(10, 200, 0, 2)],
            ),
            (
                "proxy-001".to_owned(),
                vec![Ipv4Addr::new(10, 200, 0, 3), Ipv4Addr::new(10, 200, 1, 2)],
            ),
            ("backend-001".to_owned(), vec![Ipv4Addr::new(10, 200, 1, 3)]),
        ];
        let start = DateTime::parse_from_rfc3339("2026-01-15T09:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        (scenario, host_ips, start)
    }

    fn ac2_build(scenario: &Scenario, host_ips: &HostIps, start: DateTime<Utc>) -> BundleMeta {
        let tm = identity_time_map(start, scenario);
        let total = parse_duration(&scenario.duration).unwrap();
        build(
            "ac-2-tls.scenario.yaml",
            scenario,
            host_ips,
            &tm,
            start + total,
            &[],
        )
        .unwrap()
    }

    #[test]
    fn build_meta_includes_vantage_points() {
        let (scenario, host_ips, start) = ac2_tls_test_inputs();
        let meta = ac2_build(&scenario, &host_ips, start);
        let json = serde_json::to_string_pretty(&meta).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();

        let pcaps = value["capture"]["pcaps"].as_array().unwrap();
        assert_eq!(pcaps.len(), 2);

        assert_eq!(pcaps[0]["segment"], "edge");
        assert_eq!(pcaps[0]["path"], "net/edge.pcap");
        assert_eq!(pcaps[0]["vantage_point"], "pre_tls_termination");

        assert_eq!(pcaps[1]["segment"], "inner");
        assert_eq!(pcaps[1]["path"], "net/inner.pcap");
        assert_eq!(pcaps[1]["vantage_point"], "post_tls_termination");
    }

    #[test]
    fn build_meta_tls_has_correct_encryption() {
        let (scenario, host_ips, start) = ac2_tls_test_inputs();
        let meta = ac2_build(&scenario, &host_ips, start);
        let json = serde_json::to_string_pretty(&meta).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(value["environment"]["encryption"], "tls");
    }

    #[test]
    fn build_meta_tls_segments_have_subnets() {
        let (scenario, host_ips, start) = ac2_tls_test_inputs();
        let meta = ac2_build(&scenario, &host_ips, start);
        let json = serde_json::to_string_pretty(&meta).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();

        let segments = value["network"]["segments"].as_array().unwrap();
        assert_eq!(segments.len(), 2);
        assert_eq!(segments[0]["name"], "edge");
        assert_eq!(segments[0]["subnet"], "10.200.0.0/24");
        assert_eq!(segments[1]["name"], "inner");
        assert_eq!(segments[1]["subnet"], "10.200.1.0/24");
    }

    #[test]
    fn build_meta_uses_logical_duration_when_present() {
        let (mut scenario, host_ips, start) = ac0_test_inputs();
        scenario.logical_duration = Some("14d".to_owned());
        let logical_start = DateTime::parse_from_rfc3339("2026-05-03T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let tm = TimeMap::new(
            logical_start,
            start,
            parse_duration(&scenario.duration).unwrap(),
            parse_duration("14d").unwrap(),
        )
        .unwrap();
        let actual_end = logical_start + Duration::try_days(14).unwrap();
        let meta = build(
            "ac-0.scenario.yaml",
            &scenario,
            &host_ips,
            &tm,
            actual_end,
            &[],
        )
        .unwrap();
        assert_eq!(meta.generated_at, "2026-01-15T09:00:00Z");
        assert_eq!(meta.duration.total, "14d");
        assert_eq!(meta.duration.actual_start, "2026-05-03T00:00:00Z");
        assert_eq!(meta.duration.actual_end, "2026-05-17T00:00:00Z");
    }

    #[test]
    fn build_meta_empty_actual_end_equals_actual_start() {
        // When the aggregator never observes a rewritten timestamp,
        // callers seed it with `actual_start` and pass it back here.
        let (scenario, host_ips, start) = ac0_test_inputs();
        let tm = identity_time_map(start, &scenario);
        let meta = build(
            "ac-0.scenario.yaml",
            &scenario,
            &host_ips,
            &tm,
            tm.start_at(),
            &[],
        )
        .unwrap();
        assert_eq!(meta.duration.actual_end, meta.duration.actual_start);
    }

    /// Loads the compressed AC-0 scenario together with the canonical
    /// non-identity inputs the meta tests need:
    ///
    /// * `start` — the run's `real_generation_start` (`Utc::now()` stand-in).
    /// * `logical_start` — the scenario's declared `start_at`.
    fn ac0_compressed_test_inputs() -> (Scenario, HostIps, DateTime<Utc>, DateTime<Utc>) {
        let yaml = include_str!("../scenarios/ac-0-compressed.scenario.yaml");
        let scenario: Scenario = serde_yaml::from_str(yaml).unwrap();
        let host_ips = vec![
            (
                "attacker-001".to_owned(),
                vec![Ipv4Addr::new(10, 101, 0, 2)],
            ),
            ("target-001".to_owned(), vec![Ipv4Addr::new(10, 101, 0, 3)]),
        ];
        let start = DateTime::parse_from_rfc3339("2026-01-15T09:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let logical_start = scenario.start_at.unwrap();
        (scenario, host_ips, start, logical_start)
    }

    fn ac0_compressed_time_map(
        scenario: &Scenario,
        real_generation_start: DateTime<Utc>,
        logical_start: DateTime<Utc>,
    ) -> TimeMap {
        let real_duration = parse_duration(&scenario.duration).unwrap();
        let logical_duration =
            parse_duration(scenario.logical_duration.as_deref().unwrap()).unwrap();
        TimeMap::new(
            logical_start,
            real_generation_start,
            real_duration,
            logical_duration,
        )
        .unwrap()
    }

    #[test]
    fn build_meta_compressed_generated_at_is_real_not_logical() {
        let (scenario, host_ips, start, logical_start) = ac0_compressed_test_inputs();
        let tm = ac0_compressed_time_map(&scenario, start, logical_start);
        let meta = build(
            "ac-0-compressed.scenario.yaml",
            &scenario,
            &host_ips,
            &tm,
            logical_start,
            &[],
        )
        .unwrap();
        // generated_at carries the real wall-clock at run start, not the
        // scenario's logical start_at.
        assert_eq!(meta.generated_at, "2026-01-15T09:00:00Z");
        assert_ne!(meta.generated_at, "2026-05-03T00:00:00Z");
    }

    #[test]
    fn build_meta_compressed_actual_start_equals_start_at() {
        let (scenario, host_ips, start, logical_start) = ac0_compressed_test_inputs();
        let tm = ac0_compressed_time_map(&scenario, start, logical_start);
        let meta = build(
            "ac-0-compressed.scenario.yaml",
            &scenario,
            &host_ips,
            &tm,
            logical_start,
            &[],
        )
        .unwrap();
        assert_eq!(meta.duration.actual_start, "2026-05-03T00:00:00Z");
    }

    #[test]
    fn build_meta_compressed_total_is_logical_duration() {
        let (scenario, host_ips, start, logical_start) = ac0_compressed_test_inputs();
        let tm = ac0_compressed_time_map(&scenario, start, logical_start);
        let meta = build(
            "ac-0-compressed.scenario.yaml",
            &scenario,
            &host_ips,
            &tm,
            logical_start,
            &[],
        )
        .unwrap();
        assert_eq!(meta.duration.total, "14d");
    }

    #[test]
    fn build_meta_compressed_actual_end_within_logical_window() {
        let (scenario, host_ips, start, logical_start) = ac0_compressed_test_inputs();
        let tm = ac0_compressed_time_map(&scenario, start, logical_start);
        // Caller-aggregated end: 10 logical days past start_at — within
        // the second activity's anchor window for a typical normal run.
        let aggregated_end = logical_start + Duration::try_days(10).unwrap();
        let meta = build(
            "ac-0-compressed.scenario.yaml",
            &scenario,
            &host_ips,
            &tm,
            aggregated_end,
            &[],
        )
        .unwrap();
        assert_eq!(meta.duration.actual_end, "2026-05-13T00:00:00Z");

        let parsed_end = DateTime::parse_from_rfc3339(&meta.duration.actual_end)
            .unwrap()
            .with_timezone(&Utc);
        let parsed_start = DateTime::parse_from_rfc3339(&meta.duration.actual_start)
            .unwrap()
            .with_timezone(&Utc);
        let upper = logical_start + Duration::try_days(14).unwrap();
        assert!(parsed_end >= parsed_start && parsed_end <= upper);
    }
}
