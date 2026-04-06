use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;

use anyhow::{Context, Result, bail, ensure};
use chrono::Duration;
use ipnet::Ipv4Net;
use serde::{Deserialize, Serialize};

const SUPPORTED_VERSION: &str = "1";

/// Parses a human-readable duration string like "5m", "30s", or "2h".
pub(crate) fn parse_duration(s: &str) -> Result<Duration> {
    let s = s.trim();
    if let Some(rest) = s.strip_suffix('s') {
        let secs: i64 = rest.parse().context("invalid seconds in duration")?;
        return Duration::try_seconds(secs).context("duration seconds out of range");
    }
    if let Some(rest) = s.strip_suffix('m') {
        let mins: i64 = rest.parse().context("invalid minutes in duration")?;
        return Duration::try_minutes(mins).context("duration minutes out of range");
    }
    if let Some(rest) = s.strip_suffix('h') {
        let hours: i64 = rest.parse().context("invalid hours in duration")?;
        return Duration::try_hours(hours).context("duration hours out of range");
    }
    bail!("unsupported duration format '{s}': expected suffix s, m, or h")
}

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
    pub(crate) version: String,
    pub(crate) metadata: Metadata,
    pub(crate) environment: Environment,
    pub(crate) duration: String,
    pub(crate) infrastructure: Infrastructure,
    pub(crate) activities: Activities,
}

#[derive(Debug, Deserialize)]
pub(crate) struct Metadata {
    pub(crate) name: String,
    #[allow(dead_code)]
    pub(crate) description: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct Environment {
    pub(crate) scale: Scale,
    pub(crate) encryption: Encryption,
    pub(crate) workload: Workload,
    pub(crate) threat: Threat,
    pub(crate) attacker: Attacker,
}

#[derive(Debug, Deserialize)]
pub(crate) struct Infrastructure {
    pub(crate) hosts: Vec<Host>,
    pub(crate) network: Network,
}

#[derive(Debug, Deserialize)]
pub(crate) struct Host {
    pub(crate) name: String,
    pub(crate) os: Os,
    pub(crate) role: Role,
    #[serde(default)]
    pub(crate) image: String,
    #[serde(default)]
    pub(crate) vm: Option<VmConfig>,
    #[serde(default)]
    pub(crate) setup: Vec<String>,
    /// Whether to install and collect Falco telemetry (default: false).
    ///
    /// Only applies to Linux container hosts.
    #[serde(default)]
    pub(crate) falco: bool,
}

impl Host {
    /// Returns `true` if this host is provisioned as a libvirt VM.
    pub(crate) fn is_vm(&self) -> bool {
        self.vm.is_some()
    }
}

/// Configuration for a libvirt-managed virtual machine.
#[derive(Debug, Deserialize)]
pub(crate) struct VmConfig {
    /// Path to the qcow2 base image on the host.
    pub(crate) base_image: String,
    /// RAM in megabytes (default: 4096).
    #[serde(default = "VmConfig::default_memory_mb")]
    pub(crate) memory_mb: u32,
    /// Number of virtual CPUs (default: 2).
    #[serde(default = "VmConfig::default_vcpus")]
    pub(crate) vcpus: u8,
    /// SSH user for remote command execution.
    pub(crate) ssh_user: String,
    /// SSH password (used with sshpass).
    pub(crate) ssh_password: String,
    /// Whether to install and collect Sysmon telemetry (default: true).
    #[serde(default = "VmConfig::default_sysmon")]
    pub(crate) sysmon: bool,
}

impl VmConfig {
    fn default_memory_mb() -> u32 {
        4096
    }

    fn default_vcpus() -> u8 {
        2
    }

    fn default_sysmon() -> bool {
        true
    }
}

#[derive(Debug, Deserialize)]
pub(crate) struct Network {
    pub(crate) segments: Vec<Segment>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct Segment {
    pub(crate) name: String,
    pub(crate) subnet: String,
    pub(crate) hosts: Vec<String>,
    #[serde(default)]
    pub(crate) vantage_point: Option<VantagePoint>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct Activities {
    #[serde(default)]
    pub(crate) normal: Vec<NormalActivity>,
    #[serde(default)]
    pub(crate) attack: Vec<AttackActivity>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct NormalActivity {
    pub(crate) name: String,
    pub(crate) source: String,
    pub(crate) target: String,
    pub(crate) command: String,
    pub(crate) protocol: Protocol,
    pub(crate) dst_port: u16,
    pub(crate) start_offset: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct AttackActivity {
    pub(crate) name: String,
    pub(crate) source: String,
    pub(crate) target: String,
    pub(crate) command: String,
    pub(crate) protocol: Protocol,
    pub(crate) dst_port: u16,
    pub(crate) technique: String,
    pub(crate) phase: Phase,
    pub(crate) tool: String,
    pub(crate) start_offset: String,
    #[serde(default)]
    pub(crate) campaign_id: Option<String>,
    #[serde(default)]
    pub(crate) step: Option<u32>,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Scale {
    Minimal,
    Small,
    Medium,
    Large,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Encryption {
    None,
    Tls,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Workload {
    Light,
    Medium,
    Heavy,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Threat {
    Single,
    Multi,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Attacker {
    Scripted,
    Adaptive,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Os {
    Linux,
    Windows,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Role {
    Attacker,
    Target,
    Observer,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Protocol {
    Tcp,
    Udp,
    Icmp,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum VantagePoint {
    PreTlsTermination,
    PostTlsTermination,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
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

/// Validates that `campaign_id` and `step` are either both present or both absent.
fn validate_campaign_fields(a: &AttackActivity) -> Result<()> {
    match (&a.campaign_id, a.step) {
        (Some(_), Some(_)) | (None, None) => Ok(()),
        (Some(_), None) => bail!(
            "attack activity '{}' has campaign_id but missing step",
            a.name,
        ),
        (None, Some(_)) => bail!(
            "attack activity '{}' has step but missing campaign_id",
            a.name,
        ),
    }
}

/// Validates that campaign steps start at 1, are contiguous, and that
/// `start_offsets` are non-decreasing within each campaign.
fn validate_campaign_steps(attacks: &[AttackActivity]) -> Result<()> {
    let mut campaigns: HashMap<&str, Vec<(u32, &AttackActivity)>> = HashMap::new();
    for a in attacks {
        if let (Some(cid), Some(step)) = (&a.campaign_id, a.step) {
            campaigns.entry(cid.as_str()).or_default().push((step, a));
        }
    }

    for (cid, mut steps) in campaigns {
        steps.sort_unstable_by_key(|(s, _)| *s);

        for (i, (step, a)) in steps.iter().enumerate() {
            let expected = u32::try_from(i + 1).context("campaign step count exceeds u32 range")?;
            ensure!(
                *step == expected,
                "campaign '{cid}': expected step {expected} but activity '{}' has step {step}",
                a.name,
            );
        }

        for pair in steps.windows(2) {
            let (_, a) = &pair[0];
            let (_, b) = &pair[1];
            let off_a = parse_duration(&a.start_offset)?;
            let off_b = parse_duration(&b.start_offset)?;
            ensure!(
                off_a <= off_b,
                "campaign '{cid}': step {} (offset {}) must not start after step {} (offset {})",
                pair[0].0,
                a.start_offset,
                pair[1].0,
                b.start_offset,
            );
        }
    }

    Ok(())
}

impl Scenario {
    /// Validates semantic constraints that serde cannot enforce.
    #[allow(clippy::too_many_lines)] // validation steps are inherently sequential
    fn validate(&self) -> Result<()> {
        ensure!(
            self.version == SUPPORTED_VERSION,
            "unsupported scenario version '{}', expected '{SUPPORTED_VERSION}'",
            self.version,
        );

        parse_duration(&self.duration)
            .with_context(|| format!("invalid duration '{}'", self.duration))?;

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

            if let Some(vm) = &host.vm {
                ensure!(
                    !vm.base_image.is_empty(),
                    "VM host '{}' requires a non-empty base_image",
                    host.name,
                );
                ensure!(
                    vm.memory_mb >= 512,
                    "VM host '{}' requires at least 512 MB of memory",
                    host.name,
                );
                ensure!(
                    vm.vcpus >= 1,
                    "VM host '{}' requires at least 1 vCPU",
                    host.name,
                );
            } else {
                ensure!(
                    !host.image.is_empty(),
                    "host '{}' requires a Docker image (or a 'vm' config for VMs)",
                    host.name,
                );
            }
        }

        let mut segment_names = HashSet::new();
        for segment in &self.infrastructure.network.segments {
            ensure!(
                segment_names.insert(segment.name.as_str()),
                "duplicate segment name '{}'",
                segment.name,
            );
            ensure!(
                segment.subnet.parse::<Ipv4Net>().is_ok(),
                "segment '{}' has invalid subnet CIDR '{}'",
                segment.name,
                segment.subnet,
            );
            for host_ref in &segment.hosts {
                ensure!(
                    host_names.contains(host_ref.as_str()),
                    "network segment '{}' references unknown host '{host_ref}'",
                    segment.name,
                );
            }
        }

        // VM hosts must appear in exactly one segment (multi-NIC VM
        // provisioning is not yet supported).
        let vm_hosts: HashSet<&str> = self
            .infrastructure
            .hosts
            .iter()
            .filter(|h| h.is_vm())
            .map(|h| h.name.as_str())
            .collect();
        for vm_name in &vm_hosts {
            let count = self
                .infrastructure
                .network
                .segments
                .iter()
                .filter(|seg| seg.hosts.iter().any(|h| h == vm_name))
                .count();
            ensure!(
                count <= 1,
                "VM host '{vm_name}' appears in {count} segments, \
                 but multi-segment VM provisioning is not yet supported",
            );
        }

        for a in &self.activities.normal {
            validate_host_refs(&host_names, "normal", &a.name, &a.source, &a.target)?;
        }
        for a in &self.activities.attack {
            validate_host_refs(&host_names, "attack", &a.name, &a.source, &a.target)?;
            validate_campaign_fields(a)?;
        }

        validate_campaign_steps(&self.activities.attack)?;

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
        assert!(attacker.setup.is_empty());

        let target = &s.infrastructure.hosts[1];
        assert_eq!(target.name, "target-001");
        assert_eq!(target.os, Os::Linux);
        assert_eq!(target.role, Role::Target);
        assert_eq!(target.image, "alpine:3.19");
        assert_eq!(target.setup.len(), 1);
        assert!(target.setup[0].contains("nc -l"));
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

    #[test]
    fn setup_defaults_to_empty_when_omitted() {
        let s: Scenario = serde_yaml::from_str(MINIMAL_YAML).unwrap();
        assert!(s.infrastructure.hosts[0].setup.is_empty());
    }

    // ── Duration validation ───────────────────────────────────────

    #[test]
    fn reject_invalid_duration_format() {
        let yaml = MINIMAL_YAML.replace("duration: 1m", "duration: 5x");
        let s: Scenario = serde_yaml::from_str(&yaml).unwrap();
        let err = s.validate().unwrap_err();
        assert!(
            err.to_string().contains("invalid duration"),
            "unexpected error: {err}",
        );
    }

    #[test]
    fn reject_non_numeric_duration() {
        let yaml = MINIMAL_YAML.replace("duration: 1m", "duration: foom");
        let s: Scenario = serde_yaml::from_str(&yaml).unwrap();
        let err = s.validate().unwrap_err();
        assert!(
            err.to_string().contains("invalid"),
            "unexpected error: {err}",
        );
    }

    // ── Subnet validation ────────────────────────────────────────

    #[test]
    fn reject_invalid_subnet_cidr() {
        let yaml = MINIMAL_YAML.replace("subnet: 10.0.0.0/24", "subnet: not-a-cidr");
        let s: Scenario = serde_yaml::from_str(&yaml).unwrap();
        let err = s.validate().unwrap_err();
        assert!(
            err.to_string().contains("invalid subnet CIDR"),
            "unexpected error: {err}",
        );
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
    fn load_mixed_distro_from_file() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("scenarios")
            .join("ac-1-mixed-distro.scenario.yaml");
        let s = load(&path).unwrap();
        assert_eq!(s.metadata.name, "ac-1-mixed-distro");
        assert_eq!(s.infrastructure.hosts.len(), 3);
        assert_eq!(s.infrastructure.hosts[0].image, "alpine:3.19");
        assert_eq!(s.infrastructure.hosts[1].image, "ubuntu:22.04");
        assert_eq!(s.infrastructure.hosts[2].image, "ubuntu:22.04");
        assert_eq!(s.infrastructure.hosts[2].role, Role::Observer);
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

    // ── Duration parsing ──────────────────────────────────────────

    #[test]
    fn parse_duration_seconds() {
        let d = parse_duration("30s").unwrap();
        assert_eq!(d.num_seconds(), 30);
    }

    #[test]
    fn parse_duration_minutes() {
        let d = parse_duration("5m").unwrap();
        assert_eq!(d.num_seconds(), 300);
    }

    #[test]
    fn parse_duration_hours() {
        let d = parse_duration("2h").unwrap();
        assert_eq!(d.num_seconds(), 7200);
    }

    #[test]
    fn parse_duration_invalid_suffix() {
        let err = parse_duration("10d").unwrap_err();
        assert!(
            err.to_string().contains("unsupported duration format"),
            "unexpected error: {err}",
        );
    }

    #[test]
    fn parse_duration_invalid_number() {
        let err = parse_duration("abcm").unwrap_err();
        assert!(
            err.to_string().contains("invalid"),
            "unexpected error: {err}",
        );
    }

    #[test]
    fn parse_duration_with_whitespace() {
        let d = parse_duration("  5m  ").unwrap();
        assert_eq!(d.num_seconds(), 300);
    }

    #[test]
    fn parse_duration_empty_string() {
        let err = parse_duration("").unwrap_err();
        assert!(
            err.to_string().contains("unsupported duration format"),
            "unexpected error: {err}",
        );
    }

    // ── E2E: load() from file ─────────────────────────────────────

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

    // ── VM / Windows host tests ───────────────────────────────────

    const AC2_YAML: &str = include_str!("../scenarios/ac-2-windows.scenario.yaml");

    #[test]
    fn ac2_windows_parses_and_validates() {
        let s: Scenario = serde_yaml::from_str(AC2_YAML).unwrap();
        s.validate().unwrap();
        assert_eq!(s.metadata.name, "ac-2-windows");
        assert_eq!(s.infrastructure.hosts.len(), 2);
    }

    #[test]
    fn ac2_windows_host_has_vm_config() {
        let s: Scenario = serde_yaml::from_str(AC2_YAML).unwrap();
        let win = &s.infrastructure.hosts[1];
        assert_eq!(win.name, "win-target-001");
        assert_eq!(win.os, Os::Windows);
        assert!(win.is_vm(), "Windows host must have VM config");
        let vm = win.vm.as_ref().unwrap();
        assert_eq!(vm.memory_mb, 4096);
        assert_eq!(vm.vcpus, 2);
        assert_eq!(vm.ssh_user, "admin");
        assert!(vm.sysmon);
    }

    #[test]
    fn ac2_linux_host_is_not_vm() {
        let s: Scenario = serde_yaml::from_str(AC2_YAML).unwrap();
        let linux = &s.infrastructure.hosts[0];
        assert_eq!(linux.name, "attacker-001");
        assert!(!linux.is_vm());
    }

    #[test]
    fn reject_vm_host_without_base_image() {
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
      os: windows
      role: target
      vm:
        base_image: ''
        ssh_user: admin
        ssh_password: pw
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
        let s: Scenario = serde_yaml::from_str(yaml).unwrap();
        let err = s.validate().unwrap_err();
        assert!(
            err.to_string().contains("non-empty base_image"),
            "unexpected error: {err}",
        );
    }

    #[test]
    fn reject_non_vm_host_without_image() {
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
        let s: Scenario = serde_yaml::from_str(yaml).unwrap();
        let err = s.validate().unwrap_err();
        assert!(
            err.to_string().contains("requires a Docker image"),
            "unexpected error: {err}",
        );
    }

    #[test]
    fn reject_vm_host_in_multiple_segments() {
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
    - name: win
      os: windows
      role: target
      vm:
        base_image: /images/win.qcow2
        ssh_user: admin
        ssh_password: pw
    - name: linux
      os: linux
      role: attacker
      image: alpine:3.19
  network:
    segments:
      - name: dmz
        subnet: 10.0.0.0/24
        hosts:
          - win
          - linux
      - name: internal
        subnet: 10.1.0.0/24
        hosts:
          - win
activities:
  normal: []
  attack: []
";
        let s: Scenario = serde_yaml::from_str(yaml).unwrap();
        let err = s.validate().unwrap_err();
        assert!(
            err.to_string()
                .contains("multi-segment VM provisioning is not yet supported"),
            "unexpected error: {err}",
        );
    }

    #[test]
    fn accept_vm_host_in_single_segment() {
        let s: Scenario = serde_yaml::from_str(AC2_YAML).unwrap();
        s.validate().unwrap();
    }

    // ── Campaign validation ──────────────────────────────────────

    const AC0_CAMPAIGN_YAML: &str = include_str!("../scenarios/ac-0-campaign.scenario.yaml");

    #[test]
    fn ac0_campaign_parses_and_validates() {
        let s: Scenario = serde_yaml::from_str(AC0_CAMPAIGN_YAML).unwrap();
        s.validate().unwrap();
        assert_eq!(s.activities.attack.len(), 2);
        assert_eq!(
            s.activities.attack[0].campaign_id.as_deref(),
            Some("campaign-001"),
        );
        assert_eq!(s.activities.attack[0].step, Some(1));
        assert_eq!(s.activities.attack[1].step, Some(2));
    }

    #[test]
    fn campaign_fields_default_to_none() {
        let s: Scenario = serde_yaml::from_str(AC0_YAML).unwrap();
        assert!(s.activities.attack[0].campaign_id.is_none());
        assert!(s.activities.attack[0].step.is_none());
    }

    #[test]
    fn reject_campaign_id_without_step() {
        let yaml = yaml_with_activities(
            "  attack:
    - name: bad
      source: h1
      target: h2
      command: echo
      protocol: tcp
      dst_port: 80
      technique: T0000
      phase: reconnaissance
      tool: test
      start_offset: 0s
      campaign_id: c1
",
        );
        let s: Scenario = serde_yaml::from_str(&yaml).unwrap();
        let err = s.validate().unwrap_err();
        assert!(
            err.to_string().contains("has campaign_id but missing step"),
            "unexpected error: {err}",
        );
    }

    #[test]
    fn reject_step_without_campaign_id() {
        let yaml = yaml_with_activities(
            "  attack:
    - name: bad
      source: h1
      target: h2
      command: echo
      protocol: tcp
      dst_port: 80
      technique: T0000
      phase: reconnaissance
      tool: test
      start_offset: 0s
      step: 1
",
        );
        let s: Scenario = serde_yaml::from_str(&yaml).unwrap();
        let err = s.validate().unwrap_err();
        assert!(
            err.to_string().contains("has step but missing campaign_id"),
            "unexpected error: {err}",
        );
    }

    #[test]
    fn reject_campaign_with_gap_in_steps() {
        let yaml = yaml_with_activities(
            "  attack:
    - name: step1
      source: h1
      target: h2
      command: echo
      protocol: tcp
      dst_port: 80
      technique: T0000
      phase: reconnaissance
      tool: test
      start_offset: 0s
      campaign_id: c1
      step: 1
    - name: step3
      source: h1
      target: h2
      command: echo
      protocol: tcp
      dst_port: 80
      technique: T0000
      phase: reconnaissance
      tool: test
      start_offset: 10s
      campaign_id: c1
      step: 3
",
        );
        let s: Scenario = serde_yaml::from_str(&yaml).unwrap();
        let err = s.validate().unwrap_err();
        assert!(
            err.to_string().contains("expected step 2"),
            "unexpected error: {err}",
        );
    }

    #[test]
    fn reject_campaign_with_decreasing_offsets() {
        let yaml = yaml_with_activities(
            "  attack:
    - name: step1
      source: h1
      target: h2
      command: echo
      protocol: tcp
      dst_port: 80
      technique: T0000
      phase: reconnaissance
      tool: test
      start_offset: 60s
      campaign_id: c1
      step: 1
    - name: step2
      source: h1
      target: h2
      command: echo
      protocol: tcp
      dst_port: 80
      technique: T0000
      phase: reconnaissance
      tool: test
      start_offset: 30s
      campaign_id: c1
      step: 2
",
        );
        let s: Scenario = serde_yaml::from_str(&yaml).unwrap();
        let err = s.validate().unwrap_err();
        assert!(
            err.to_string().contains("must not start after"),
            "unexpected error: {err}",
        );
    }

    #[test]
    fn accept_campaign_with_equal_offsets() {
        let yaml = yaml_with_activities(
            "  attack:
    - name: step1
      source: h1
      target: h2
      command: echo
      protocol: tcp
      dst_port: 80
      technique: T0000
      phase: reconnaissance
      tool: test
      start_offset: 60s
      campaign_id: c1
      step: 1
    - name: step2
      source: h1
      target: h2
      command: echo
      protocol: tcp
      dst_port: 80
      technique: T0000
      phase: reconnaissance
      tool: test
      start_offset: 60s
      campaign_id: c1
      step: 2
",
        );
        let s: Scenario = serde_yaml::from_str(&yaml).unwrap();
        s.validate().unwrap();
    }

    #[test]
    fn load_ac0_campaign_from_file() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("scenarios")
            .join("ac-0-campaign.scenario.yaml");
        let s = load(&path).unwrap();
        assert_eq!(s.metadata.name, "ac-0-campaign");
        assert_eq!(s.activities.attack.len(), 2);
    }

    // ── Vantage point ────────────────────────────────────────────

    #[test]
    fn vantage_point_defaults_to_none() {
        let s: Scenario = serde_yaml::from_str(AC0_YAML).unwrap();
        assert!(
            s.infrastructure.network.segments[0].vantage_point.is_none(),
            "segments without vantage_point should default to None",
        );
    }

    #[test]
    fn load_ac2_tls_from_file() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("scenarios")
            .join("ac-2-tls.scenario.yaml");
        let s = load(&path).unwrap();
        assert_eq!(s.metadata.name, "ac-2-tls");
        assert_eq!(s.environment.encryption, Encryption::Tls);
        assert_eq!(s.infrastructure.hosts.len(), 3);
        assert_eq!(s.infrastructure.network.segments.len(), 2);

        let backend = s
            .infrastructure
            .hosts
            .iter()
            .find(|h| h.name == "backend-001")
            .expect("backend-001 must exist");
        assert!(backend.falco, "backend-001 must have Falco enabled");
    }

    #[test]
    fn ac2_tls_vantage_points() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("scenarios")
            .join("ac-2-tls.scenario.yaml");
        let s = load(&path).unwrap();

        let edge = &s.infrastructure.network.segments[0];
        assert_eq!(edge.name, "edge");
        assert_eq!(edge.vantage_point, Some(VantagePoint::PreTlsTermination));

        let inner = &s.infrastructure.network.segments[1];
        assert_eq!(inner.name, "inner");
        assert_eq!(inner.vantage_point, Some(VantagePoint::PostTlsTermination),);
    }

    #[test]
    fn ac2_tls_proxy_is_multi_homed() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("scenarios")
            .join("ac-2-tls.scenario.yaml");
        let s = load(&path).unwrap();

        let edge_hosts = &s.infrastructure.network.segments[0].hosts;
        let internal_hosts = &s.infrastructure.network.segments[1].hosts;
        assert!(edge_hosts.contains(&"proxy-001".to_owned()));
        assert!(internal_hosts.contains(&"proxy-001".to_owned()));
    }
}
