use std::collections::HashSet;
use std::fs;
use std::path::Path;

use anyhow::{Context, Result, ensure};
use serde::Deserialize;

const SUPPORTED_VERSION: &str = "1";

/// Loads and validates a scenario from a YAML file.
pub(crate) fn load(path: &Path) -> Result<Scenario> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("failed to read scenario file: {}", path.display()))?;
    let scenario: Scenario = serde_yaml::from_str(&content)
        .with_context(|| format!("failed to parse scenario YAML: {}", path.display()))?;
    scenario.validate()?;
    Ok(scenario)
}

#[derive(Debug, Deserialize)]
pub(crate) struct Scenario {
    version: String,
    pub(crate) metadata: Metadata,
    // Pipeline will consume these once generation is implemented.
    #[allow(dead_code)]
    environment: Environment,
    #[allow(dead_code)]
    duration: String,
    pub(crate) infrastructure: Infrastructure,
    pub(crate) activities: Activities,
}

#[derive(Debug, Deserialize)]
pub(crate) struct Metadata {
    pub(crate) name: String,
    // Pipeline will consume this once generation is implemented.
    #[allow(dead_code)]
    description: String,
}

// Pipeline will consume these fields once generation is implemented.
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub(crate) struct Environment {
    scale: Scale,
    encryption: Encryption,
    workload: Workload,
    threat: Threat,
    attacker: Attacker,
}

#[derive(Debug, Deserialize)]
pub(crate) struct Infrastructure {
    pub(crate) hosts: Vec<Host>,
    pub(crate) network: Network,
}

// Pipeline will consume os, role, and image once generation is implemented.
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub(crate) struct Host {
    name: String,
    os: Os,
    role: Role,
    image: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct Network {
    pub(crate) segments: Vec<Segment>,
}

// Pipeline will consume subnet once generation is implemented.
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub(crate) struct Segment {
    name: String,
    subnet: String,
    hosts: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct Activities {
    #[serde(default)]
    pub(crate) normal: Vec<NormalActivity>,
    #[serde(default)]
    pub(crate) attack: Vec<AttackActivity>,
}

// Pipeline will consume command, protocol, dst_port, and start_offset
// once generation is implemented.
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub(crate) struct NormalActivity {
    name: String,
    source: String,
    target: String,
    command: String,
    protocol: Protocol,
    dst_port: u16,
    start_offset: String,
}

// Pipeline will consume command, protocol, dst_port, technique, phase,
// tool, and start_offset once generation is implemented.
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub(crate) struct AttackActivity {
    name: String,
    source: String,
    target: String,
    command: String,
    protocol: Protocol,
    dst_port: u16,
    technique: String,
    phase: Phase,
    tool: String,
    start_offset: String,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Scale {
    Minimal,
    Small,
    Medium,
    Large,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Encryption {
    None,
    Tls,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Workload {
    Light,
    Medium,
    Heavy,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Threat {
    Single,
    Multi,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Attacker {
    Scripted,
    Adaptive,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Os {
    Linux,
    Windows,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Role {
    Attacker,
    Target,
    Observer,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Protocol {
    Tcp,
    Udp,
    Icmp,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Phase {
    Reconnaissance,
    InitialAccess,
    CredentialAccess,
    LateralMovement,
    C2,
    Exfiltration,
}

/// Returns `true` if the name contains only lowercase ASCII alphanumeric
/// characters and hyphens, and is non-empty.
fn is_valid_hostname(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// Validates that `source` and `target` refer to known hosts.
fn validate_host_refs(
    host_names: &HashSet<&str>,
    kind: &str,
    name: &str,
    source: &str,
    target: &str,
) -> Result<()> {
    ensure!(
        host_names.contains(source),
        "{kind} activity '{name}' references unknown source '{source}'",
    );
    ensure!(
        host_names.contains(target),
        "{kind} activity '{name}' references unknown target '{target}'",
    );
    Ok(())
}

impl Scenario {
    /// Validates semantic constraints that serde cannot enforce.
    fn validate(&self) -> Result<()> {
        ensure!(
            self.version == SUPPORTED_VERSION,
            "unsupported scenario version '{}', expected '{SUPPORTED_VERSION}'",
            self.version,
        );

        ensure!(
            !self.infrastructure.hosts.is_empty(),
            "scenario must define at least one host",
        );

        ensure!(
            !self.infrastructure.network.segments.is_empty(),
            "scenario must define at least one network segment",
        );

        let mut host_names = HashSet::new();
        for host in &self.infrastructure.hosts {
            ensure!(
                is_valid_hostname(&host.name),
                "invalid host name '{}': must be lowercase alphanumeric and hyphens only",
                host.name,
            );
            ensure!(
                host_names.insert(host.name.as_str()),
                "duplicate host name '{}'",
                host.name,
            );
        }

        let mut segment_names = HashSet::new();
        for segment in &self.infrastructure.network.segments {
            ensure!(
                segment_names.insert(segment.name.as_str()),
                "duplicate segment name '{}'",
                segment.name,
            );
            for host_ref in &segment.hosts {
                ensure!(
                    host_names.contains(host_ref.as_str()),
                    "network segment '{}' references unknown host '{host_ref}'",
                    segment.name,
                );
            }
        }

        for a in &self.activities.normal {
            validate_host_refs(&host_names, "normal", &a.name, &a.source, &a.target)?;
        }
        for a in &self.activities.attack {
            validate_host_refs(&host_names, "attack", &a.name, &a.source, &a.target)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const AC0_YAML: &str = include_str!("../scenarios/ac-0.scenario.yaml");

    const MINIMAL_YAML: &str = "\
version: '1'
metadata:
  name: test
  description: test scenario
environment:
  scale: minimal
  encryption: none
  workload: light
  threat: single
  attacker: scripted
duration: 1m
infrastructure:
  hosts:
    - name: h1
      os: linux
      role: target
      image: alpine:3.19
  network:
    segments:
      - name: net
        subnet: 10.0.0.0/24
        hosts:
          - h1
activities:
  normal: []
  attack: []
";

    /// Builds a scenario YAML with custom activities block.
    fn yaml_with_activities(activities: &str) -> String {
        let base = "\
version: '1'
metadata:
  name: test
  description: test scenario
environment:
  scale: minimal
  encryption: none
  workload: light
  threat: single
  attacker: scripted
duration: 1m
infrastructure:
  hosts:
    - name: h1
      os: linux
      role: target
      image: alpine:3.19
    - name: h2
      os: linux
      role: attacker
      image: alpine:3.19
  network:
    segments:
      - name: net
        subnet: 10.0.0.0/24
        hosts:
          - h1
          - h2
activities:
";
        format!("{base}{activities}")
    }

    // ── AC-0 full-field coverage ──────────────────────────────────

    #[test]
    fn ac0_metadata() {
        let s: Scenario = serde_yaml::from_str(AC0_YAML).unwrap();
        s.validate().unwrap();
        assert_eq!(s.metadata.name, "ac-0");
        assert!(s.metadata.description.contains("Minimal acceptance"));
    }

    #[test]
    fn ac0_environment() {
        let s: Scenario = serde_yaml::from_str(AC0_YAML).unwrap();
        assert_eq!(s.environment.scale, Scale::Minimal);
        assert_eq!(s.environment.encryption, Encryption::None);
        assert_eq!(s.environment.workload, Workload::Light);
        assert_eq!(s.environment.threat, Threat::Single);
        assert_eq!(s.environment.attacker, Attacker::Scripted);
    }

    #[test]
    fn ac0_duration() {
        let s: Scenario = serde_yaml::from_str(AC0_YAML).unwrap();
        assert_eq!(s.duration, "5m");
    }

    #[test]
    fn ac0_hosts() {
        let s: Scenario = serde_yaml::from_str(AC0_YAML).unwrap();
        assert_eq!(s.infrastructure.hosts.len(), 2);

        let attacker = &s.infrastructure.hosts[0];
        assert_eq!(attacker.name, "attacker-001");
        assert_eq!(attacker.os, Os::Linux);
        assert_eq!(attacker.role, Role::Attacker);
        assert_eq!(attacker.image, "alpine:3.19");

        let target = &s.infrastructure.hosts[1];
        assert_eq!(target.name, "target-001");
        assert_eq!(target.os, Os::Linux);
        assert_eq!(target.role, Role::Target);
        assert_eq!(target.image, "alpine:3.19");
    }

    #[test]
    fn ac0_network() {
        let s: Scenario = serde_yaml::from_str(AC0_YAML).unwrap();
        assert_eq!(s.infrastructure.network.segments.len(), 1);

        let seg = &s.infrastructure.network.segments[0];
        assert_eq!(seg.name, "lan");
        assert_eq!(seg.subnet, "10.100.0.0/24");
        assert_eq!(seg.hosts, vec!["attacker-001", "target-001"]);
    }

    #[test]
    fn ac0_normal_activity() {
        let s: Scenario = serde_yaml::from_str(AC0_YAML).unwrap();
        assert_eq!(s.activities.normal.len(), 1);

        let a = &s.activities.normal[0];
        assert_eq!(a.name, "http-health-check");
        assert_eq!(a.source, "attacker-001");
        assert_eq!(a.target, "target-001");
        assert!(a.command.contains("curl"));
        assert_eq!(a.protocol, Protocol::Tcp);
        assert_eq!(a.dst_port, 80);
        assert_eq!(a.start_offset, "30s");
    }

    #[test]
    fn ac0_attack_activity() {
        let s: Scenario = serde_yaml::from_str(AC0_YAML).unwrap();
        assert_eq!(s.activities.attack.len(), 1);

        let a = &s.activities.attack[0];
        assert_eq!(a.name, "nmap-port-scan");
        assert_eq!(a.source, "attacker-001");
        assert_eq!(a.target, "target-001");
        assert!(a.command.contains("nmap"));
        assert_eq!(a.protocol, Protocol::Tcp);
        assert_eq!(a.dst_port, 80);
        assert_eq!(a.technique, "T1046");
        assert_eq!(a.phase, Phase::Reconnaissance);
        assert_eq!(a.tool, "nmap");
        assert_eq!(a.start_offset, "120s");
    }

    // ── Minimal scenario ──────────────────────────────────────────

    #[test]
    fn parse_minimal_scenario() {
        let s: Scenario = serde_yaml::from_str(MINIMAL_YAML).unwrap();
        s.validate().unwrap();
        assert_eq!(s.infrastructure.hosts.len(), 1);
        assert!(s.activities.normal.is_empty());
        assert!(s.activities.attack.is_empty());
    }

    // ── Version validation ────────────────────────────────────────

    #[test]
    fn reject_unsupported_version() {
        let yaml = MINIMAL_YAML.replace("version: '1'", "version: '99'");
        let s: Scenario = serde_yaml::from_str(&yaml).unwrap();
        let err = s.validate().unwrap_err();
        assert!(
            err.to_string()
                .contains("unsupported scenario version '99'"),
            "unexpected error: {err}",
        );
    }

    // ── Host validation ───────────────────────────────────────────

    #[test]
    fn reject_empty_hosts() {
        let yaml = MINIMAL_YAML.replace(
            "  hosts:\n    - name: h1\n      os: linux\n      role: target\n      image: alpine:3.19",
            "  hosts: []",
        );
        let s: Scenario = serde_yaml::from_str(&yaml).unwrap();
        let err = s.validate().unwrap_err();
        assert!(
            err.to_string().contains("at least one host"),
            "unexpected error: {err}",
        );
    }

    #[test]
    fn reject_uppercase_host_name() {
        let yaml = MINIMAL_YAML.replace("name: h1", "name: Bad-Name");
        let s: Scenario = serde_yaml::from_str(&yaml).unwrap();
        let err = s.validate().unwrap_err();
        assert!(
            err.to_string().contains("invalid host name"),
            "unexpected error: {err}",
        );
    }

    #[test]
    fn reject_underscore_in_host_name() {
        let yaml = MINIMAL_YAML.replace("name: h1", "name: bad_name");
        let s: Scenario = serde_yaml::from_str(&yaml).unwrap();
        let err = s.validate().unwrap_err();
        assert!(
            err.to_string().contains("invalid host name"),
            "unexpected error: {err}",
        );
    }

    #[test]
    fn reject_duplicate_host_names() {
        let yaml = "\
version: '1'
metadata:
  name: test
  description: test
environment:
  scale: minimal
  encryption: none
  workload: light
  threat: single
  attacker: scripted
duration: 1m
infrastructure:
  hosts:
    - name: dup
      os: linux
      role: target
      image: alpine:3.19
    - name: dup
      os: linux
      role: attacker
      image: alpine:3.19
  network:
    segments:
      - name: net
        subnet: 10.0.0.0/24
        hosts:
          - dup
activities:
  normal: []
  attack: []
";
        let s: Scenario = serde_yaml::from_str(yaml).unwrap();
        let err = s.validate().unwrap_err();
        assert!(
            err.to_string().contains("duplicate host name 'dup'"),
            "unexpected error: {err}",
        );
    }

    // ── Segment validation ────────────────────────────────────────

    #[test]
    fn reject_duplicate_segment_names() {
        let yaml = "\
version: '1'
metadata:
  name: test
  description: test
environment:
  scale: minimal
  encryption: none
  workload: light
  threat: single
  attacker: scripted
duration: 1m
infrastructure:
  hosts:
    - name: h1
      os: linux
      role: target
      image: alpine:3.19
  network:
    segments:
      - name: dup
        subnet: 10.0.0.0/24
        hosts:
          - h1
      - name: dup
        subnet: 10.1.0.0/24
        hosts: []
activities:
  normal: []
  attack: []
";
        let s: Scenario = serde_yaml::from_str(yaml).unwrap();
        let err = s.validate().unwrap_err();
        assert!(
            err.to_string().contains("duplicate segment name 'dup'"),
            "unexpected error: {err}",
        );
    }

    #[test]
    fn reject_empty_segments() {
        let yaml = MINIMAL_YAML.replace(
            "    segments:\n      - name: net\n        subnet: 10.0.0.0/24\n        hosts:\n          - h1",
            "    segments: []",
        );
        let s: Scenario = serde_yaml::from_str(&yaml).unwrap();
        let err = s.validate().unwrap_err();
        assert!(
            err.to_string().contains("at least one network segment"),
            "unexpected error: {err}",
        );
    }

    #[test]
    fn reject_unknown_host_in_segment() {
        let yaml = MINIMAL_YAML.replace("- h1", "- ghost");
        let s: Scenario = serde_yaml::from_str(&yaml).unwrap();
        let err = s.validate().unwrap_err();
        assert!(
            err.to_string().contains("unknown host 'ghost'"),
            "unexpected error: {err}",
        );
    }

    // ── Activity host-reference validation ────────────────────────

    #[test]
    fn reject_unknown_source_in_normal_activity() {
        let yaml = yaml_with_activities(
            "  normal:
    - name: bad
      source: ghost
      target: h1
      command: echo
      protocol: tcp
      dst_port: 80
      start_offset: 0s
",
        );
        let s: Scenario = serde_yaml::from_str(&yaml).unwrap();
        let err = s.validate().unwrap_err();
        assert!(
            err.to_string()
                .contains("normal activity 'bad' references unknown source 'ghost'"),
            "unexpected error: {err}",
        );
    }

    #[test]
    fn reject_unknown_target_in_normal_activity() {
        let yaml = yaml_with_activities(
            "  normal:
    - name: bad
      source: h1
      target: ghost
      command: echo
      protocol: tcp
      dst_port: 80
      start_offset: 0s
",
        );
        let s: Scenario = serde_yaml::from_str(&yaml).unwrap();
        let err = s.validate().unwrap_err();
        assert!(
            err.to_string()
                .contains("normal activity 'bad' references unknown target 'ghost'"),
            "unexpected error: {err}",
        );
    }

    #[test]
    fn reject_unknown_source_in_attack_activity() {
        let yaml = yaml_with_activities(
            "  attack:
    - name: bad
      source: ghost
      target: h1
      command: echo
      protocol: tcp
      dst_port: 80
      technique: T0000
      phase: reconnaissance
      tool: test
      start_offset: 0s
",
        );
        let s: Scenario = serde_yaml::from_str(&yaml).unwrap();
        let err = s.validate().unwrap_err();
        assert!(
            err.to_string()
                .contains("attack activity 'bad' references unknown source 'ghost'"),
            "unexpected error: {err}",
        );
    }

    #[test]
    fn reject_unknown_target_in_attack_activity() {
        let yaml = yaml_with_activities(
            "  attack:
    - name: bad
      source: h1
      target: ghost
      command: echo
      protocol: tcp
      dst_port: 80
      technique: T0000
      phase: reconnaissance
      tool: test
      start_offset: 0s
",
        );
        let s: Scenario = serde_yaml::from_str(&yaml).unwrap();
        let err = s.validate().unwrap_err();
        assert!(
            err.to_string()
                .contains("attack activity 'bad' references unknown target 'ghost'"),
            "unexpected error: {err}",
        );
    }

    // ── Serde deserialization errors ──────────────────────────────

    #[test]
    fn reject_unknown_enum_value() {
        let yaml = MINIMAL_YAML.replace("scale: minimal", "scale: gigantic");
        let err = serde_yaml::from_str::<Scenario>(&yaml).unwrap_err();
        assert!(
            err.to_string().contains("unknown variant"),
            "unexpected error: {err}",
        );
    }

    #[test]
    fn reject_missing_required_field() {
        let yaml = MINIMAL_YAML.replace("duration: 1m\n", "");
        let err = serde_yaml::from_str::<Scenario>(&yaml).unwrap_err();
        assert!(
            err.to_string().contains("missing field"),
            "unexpected error: {err}",
        );
    }

    #[test]
    fn reject_malformed_yaml() {
        let yaml = "not: [valid yaml";
        let err = serde_yaml::from_str::<Scenario>(yaml).unwrap_err();
        assert!(!err.to_string().is_empty());
    }

    // ── Required section validation ────────────────────────────────

    #[test]
    fn reject_missing_metadata() {
        let yaml = MINIMAL_YAML.replace(
            "metadata:\n  name: test\n  description: test scenario\n",
            "",
        );
        let err = serde_yaml::from_str::<Scenario>(&yaml).unwrap_err();
        assert!(
            err.to_string().contains("missing field"),
            "unexpected error: {err}",
        );
    }

    #[test]
    fn reject_missing_environment() {
        let yaml = MINIMAL_YAML.replace(
            "environment:\n  scale: minimal\n  encryption: none\n  workload: light\n  threat: single\n  attacker: scripted\n",
            "",
        );
        let err = serde_yaml::from_str::<Scenario>(&yaml).unwrap_err();
        assert!(
            err.to_string().contains("missing field"),
            "unexpected error: {err}",
        );
    }

    #[test]
    fn reject_missing_infrastructure() {
        let yaml = MINIMAL_YAML.replace(
            "infrastructure:\n  hosts:\n    - name: h1\n      os: linux\n      role: target\n      image: alpine:3.19\n  network:\n    segments:\n      - name: net\n        subnet: 10.0.0.0/24\n        hosts:\n          - h1\n",
            "",
        );
        let err = serde_yaml::from_str::<Scenario>(&yaml).unwrap_err();
        assert!(
            err.to_string().contains("missing field"),
            "unexpected error: {err}",
        );
    }

    #[test]
    fn reject_missing_activities() {
        let yaml = MINIMAL_YAML.replace("activities:\n  normal: []\n  attack: []\n", "");
        let err = serde_yaml::from_str::<Scenario>(&yaml).unwrap_err();
        assert!(
            err.to_string().contains("missing field"),
            "unexpected error: {err}",
        );
    }

    // ── Valid edge-case scenarios ──────────────────────────────────

    #[test]
    fn accept_attack_only_scenario() {
        let yaml = yaml_with_activities(
            "  attack:
    - name: scan
      source: h1
      target: h2
      command: nmap
      protocol: tcp
      dst_port: 80
      technique: T1046
      phase: reconnaissance
      tool: nmap
      start_offset: 0s
",
        );
        let s: Scenario = serde_yaml::from_str(&yaml).unwrap();
        s.validate().unwrap();
        assert!(s.activities.normal.is_empty());
        assert_eq!(s.activities.attack.len(), 1);
    }

    #[test]
    fn accept_multiple_activities() {
        let yaml = yaml_with_activities(
            "  normal:
    - name: curl-1
      source: h1
      target: h2
      command: curl
      protocol: tcp
      dst_port: 80
      start_offset: 0s
    - name: curl-2
      source: h2
      target: h1
      command: curl
      protocol: tcp
      dst_port: 443
      start_offset: 10s
  attack:
    - name: scan-1
      source: h1
      target: h2
      command: nmap
      protocol: tcp
      dst_port: 80
      technique: T1046
      phase: reconnaissance
      tool: nmap
      start_offset: 60s
    - name: scan-2
      source: h1
      target: h2
      command: nmap
      protocol: udp
      dst_port: 53
      technique: T1046
      phase: reconnaissance
      tool: nmap
      start_offset: 120s
",
        );
        let s: Scenario = serde_yaml::from_str(&yaml).unwrap();
        s.validate().unwrap();
        assert_eq!(s.activities.normal.len(), 2);
        assert_eq!(s.activities.attack.len(), 2);
    }

    #[test]
    fn accept_multi_segment_scenario() {
        let yaml = "\
version: '1'
metadata:
  name: multi-seg
  description: test
environment:
  scale: minimal
  encryption: none
  workload: light
  threat: single
  attacker: scripted
duration: 1m
infrastructure:
  hosts:
    - name: h1
      os: linux
      role: attacker
      image: alpine:3.19
    - name: h2
      os: linux
      role: target
      image: alpine:3.19
    - name: h3
      os: linux
      role: target
      image: alpine:3.19
  network:
    segments:
      - name: dmz
        subnet: 10.0.0.0/24
        hosts:
          - h1
          - h2
      - name: internal
        subnet: 10.1.0.0/24
        hosts:
          - h2
          - h3
activities:
  normal: []
  attack: []
";
        let s: Scenario = serde_yaml::from_str(yaml).unwrap();
        s.validate().unwrap();
        assert_eq!(s.infrastructure.network.segments.len(), 2);
        assert_eq!(s.infrastructure.hosts.len(), 3);
    }

    // ── Enum variant coverage ─────────────────────────────────────

    #[test]
    fn deserialize_all_scale_variants() {
        for (input, expected) in [
            ("minimal", Scale::Minimal),
            ("small", Scale::Small),
            ("medium", Scale::Medium),
            ("large", Scale::Large),
        ] {
            let yaml = MINIMAL_YAML.replace("scale: minimal", &format!("scale: {input}"));
            let s: Scenario = serde_yaml::from_str(&yaml).unwrap();
            assert_eq!(s.environment.scale, expected);
        }
    }

    #[test]
    fn deserialize_all_encryption_variants() {
        for (input, expected) in [("none", Encryption::None), ("tls", Encryption::Tls)] {
            let yaml = MINIMAL_YAML.replace("encryption: none", &format!("encryption: {input}"));
            let s: Scenario = serde_yaml::from_str(&yaml).unwrap();
            assert_eq!(s.environment.encryption, expected);
        }
    }

    #[test]
    fn deserialize_all_workload_variants() {
        for (input, expected) in [
            ("light", Workload::Light),
            ("medium", Workload::Medium),
            ("heavy", Workload::Heavy),
        ] {
            let yaml = MINIMAL_YAML.replace("workload: light", &format!("workload: {input}"));
            let s: Scenario = serde_yaml::from_str(&yaml).unwrap();
            assert_eq!(s.environment.workload, expected);
        }
    }

    #[test]
    fn deserialize_all_threat_variants() {
        for (input, expected) in [("single", Threat::Single), ("multi", Threat::Multi)] {
            let yaml = MINIMAL_YAML.replace("threat: single", &format!("threat: {input}"));
            let s: Scenario = serde_yaml::from_str(&yaml).unwrap();
            assert_eq!(s.environment.threat, expected);
        }
    }

    #[test]
    fn deserialize_all_attacker_variants() {
        for (input, expected) in [
            ("scripted", Attacker::Scripted),
            ("adaptive", Attacker::Adaptive),
        ] {
            let yaml = MINIMAL_YAML.replace("attacker: scripted", &format!("attacker: {input}"));
            let s: Scenario = serde_yaml::from_str(&yaml).unwrap();
            assert_eq!(s.environment.attacker, expected);
        }
    }

    #[test]
    fn deserialize_all_os_variants() {
        for (input, expected) in [("linux", Os::Linux), ("windows", Os::Windows)] {
            let yaml = MINIMAL_YAML.replace("os: linux", &format!("os: {input}"));
            let s: Scenario = serde_yaml::from_str(&yaml).unwrap();
            assert_eq!(s.infrastructure.hosts[0].os, expected);
        }
    }

    #[test]
    fn deserialize_all_role_variants() {
        for (input, expected) in [
            ("attacker", Role::Attacker),
            ("target", Role::Target),
            ("observer", Role::Observer),
        ] {
            let yaml = MINIMAL_YAML.replace("role: target", &format!("role: {input}"));
            let s: Scenario = serde_yaml::from_str(&yaml).unwrap();
            assert_eq!(s.infrastructure.hosts[0].role, expected);
        }
    }

    #[test]
    fn deserialize_all_protocol_variants() {
        for (input, expected) in [
            ("tcp", Protocol::Tcp),
            ("udp", Protocol::Udp),
            ("icmp", Protocol::Icmp),
        ] {
            let yaml = yaml_with_activities(&format!(
                "  normal:
    - name: proto-test
      source: h1
      target: h2
      command: echo
      protocol: {input}
      dst_port: 80
      start_offset: 0s
"
            ));
            let s: Scenario = serde_yaml::from_str(&yaml).unwrap();
            assert_eq!(s.activities.normal[0].protocol, expected);
        }
    }

    #[test]
    fn deserialize_all_phase_variants() {
        for (input, expected) in [
            ("reconnaissance", Phase::Reconnaissance),
            ("initial_access", Phase::InitialAccess),
            ("credential_access", Phase::CredentialAccess),
            ("lateral_movement", Phase::LateralMovement),
            ("c2", Phase::C2),
            ("exfiltration", Phase::Exfiltration),
        ] {
            let yaml = yaml_with_activities(&format!(
                "  attack:
    - name: phase-test
      source: h1
      target: h2
      command: echo
      protocol: tcp
      dst_port: 80
      technique: T0000
      phase: {input}
      tool: test
      start_offset: 0s
"
            ));
            let s: Scenario = serde_yaml::from_str(&yaml).unwrap();
            assert_eq!(s.activities.attack[0].phase, expected);
        }
    }

    // ── E2E: load() from file ─────────────────────────────────────

    #[test]
    fn load_ac0_from_file() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("scenarios")
            .join("ac-0.scenario.yaml");
        let s = load(&path).unwrap();
        assert_eq!(s.metadata.name, "ac-0");
        assert_eq!(s.version, "1");
        assert_eq!(s.infrastructure.hosts.len(), 2);
        assert_eq!(s.activities.normal.len(), 1);
        assert_eq!(s.activities.attack.len(), 1);
    }

    #[test]
    fn load_nonexistent_file() {
        let err = load(Path::new("/no/such/file.yaml")).unwrap_err();
        assert!(
            err.to_string().contains("failed to read scenario file"),
            "unexpected error: {err}",
        );
    }

    #[test]
    fn load_invalid_yaml_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.yaml");
        fs::write(&path, "not: [valid yaml").unwrap();
        let err = load(&path).unwrap_err();
        assert!(
            err.to_string().contains("failed to parse scenario YAML"),
            "unexpected error: {err}",
        );
    }

    #[test]
    fn load_valid_yaml_but_invalid_scenario() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad-version.yaml");
        let yaml = MINIMAL_YAML.replace("version: '1'", "version: '99'");
        fs::write(&path, yaml).unwrap();
        let err = load(&path).unwrap_err();
        assert!(
            err.to_string().contains("unsupported scenario version"),
            "unexpected error: {err}",
        );
    }
}
