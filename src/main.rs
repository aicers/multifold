use std::fs;
use std::path::Path;
use std::process::ExitCode;

use anyhow::{Context, Result};
use chrono::Utc;
use clap::{Parser, Subcommand};

mod activity;
mod ground_truth;
mod infra;
mod meta;
mod pcap;
mod scenario;
#[cfg(test)]
mod test_util;
mod validator;

#[derive(Parser)]
#[command(
    name = "multifold",
    about = "Dataset generator and validator for network security AI"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generates a dataset bundle from a scenario definition.
    Generate {
        /// Path to the scenario YAML file.
        #[arg(short, long)]
        scenario: String,

        /// Output directory for the generated bundle.
        #[arg(short, long, default_value = "output")]
        output: String,
    },

    /// Validates a dataset bundle against its ground truth.
    Validate {
        /// Path to the dataset bundle directory.
        #[arg(short, long)]
        bundle: String,
    },
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();

    let result = match cli.command {
        Command::Generate { scenario, output } => generate(&scenario, &output)
            .await
            .map(|()| ExitCode::SUCCESS),
        Command::Validate { bundle } => validate(&bundle),
    };

    match result {
        Ok(code) => code,
        Err(e) => {
            eprintln!("Error: {e:#}");
            ExitCode::FAILURE
        }
    }
}

async fn generate(scenario_path: &str, output: &str) -> Result<()> {
    let scenario = scenario::load(Path::new(scenario_path))?;
    println!(
        "Loaded scenario '{}': {} host(s), {} segment(s), {} normal + {} attack activities",
        scenario.metadata.name,
        scenario.infrastructure.hosts.len(),
        scenario.infrastructure.network.segments.len(),
        scenario.activities.normal.len(),
        scenario.activities.attack.len(),
    );

    let start = Utc::now();
    let output_dir = Path::new(output);
    create_output_dirs(output_dir, &scenario)?;

    // Provision Docker infrastructure.
    println!("Provisioning containers…");
    let net_dir = output_dir.join("net");
    let env = infra::ProvisionedEnv::up(&scenario, &net_dir).await?;
    println!(
        "Provisioned {} container(s) on {} network(s)",
        env.host_ips.len(),
        scenario.infrastructure.network.segments.len(),
    );

    // Run activities, then assemble the bundle; always tear down afterward.
    println!("Running activities…");
    let result = run_and_assemble(&env, &scenario, scenario_path, output_dir, start).await;

    let teardown_result = env.down().await;
    result?;
    teardown_result?;
    println!("Infrastructure torn down");

    Ok(())
}

/// Executes activities, stops collectors, and assembles the output bundle.
async fn run_and_assemble(
    env: &infra::ProvisionedEnv,
    scenario: &scenario::Scenario,
    scenario_path: &str,
    output_dir: &Path,
    start: chrono::DateTime<chrono::Utc>,
) -> Result<()> {
    let mut executions = activity::run(
        &env.docker,
        &env.host_containers,
        &env.host_ips,
        &scenario.activities,
        start,
    )
    .await?;
    println!("Executed {} activity(ies)", executions.len());

    // Stop capture containers so pcap files are flushed and complete.
    env.stop_collectors().await?;
    println!("Stopped collectors");

    // Assemble the bundle: enrich executions from pcap, write ground
    // truth, and write metadata.
    assemble_bundle(
        output_dir,
        scenario_path,
        scenario,
        &env.host_ips,
        start,
        &mut executions,
    )
}

/// Assembles the dataset bundle from collected artifacts.
///
/// Reads pcap captures to enrich execution records with source ports,
/// then writes `ground_truth/manifest.jsonl` and `meta.json` into
/// the output directory.
fn assemble_bundle(
    output_dir: &Path,
    scenario_path: &str,
    scenario: &scenario::Scenario,
    host_ips: &[(String, Vec<std::net::Ipv4Addr>)],
    start: chrono::DateTime<chrono::Utc>,
    executions: &mut [activity::Execution],
) -> Result<()> {
    let net_dir = output_dir.join("net");
    pcap::enrich_src_ports(&net_dir, executions)?;
    println!("Enriched source ports from pcap");

    ground_truth::write(output_dir, executions)?;
    println!("Wrote ground_truth/manifest.jsonl");

    let scenario_filename = Path::new(scenario_path).file_name().map_or_else(
        || scenario_path.to_owned(),
        |n| n.to_string_lossy().into_owned(),
    );
    meta::write(output_dir, &scenario_filename, scenario, host_ips, start)?;
    println!("Wrote meta.json");

    Ok(())
}

/// Creates the output bundle directory structure.
fn create_output_dirs(output_dir: &Path, scenario: &scenario::Scenario) -> Result<()> {
    fs::create_dir_all(output_dir.join("net")).context("failed to create net directory")?;
    for host in &scenario.infrastructure.hosts {
        fs::create_dir_all(output_dir.join("host").join(&host.name))
            .with_context(|| format!("failed to create host directory for '{}'", host.name))?;
    }
    fs::create_dir_all(output_dir.join("ground_truth"))
        .context("failed to create ground_truth directory")?;
    Ok(())
}

fn validate(bundle: &str) -> Result<ExitCode> {
    let report = validator::run(Path::new(bundle))?;
    let json =
        serde_json::to_string_pretty(&report).context("failed to serialize validation report")?;
    println!("{json}");
    Ok(report.exit_code())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::load_ac0;

    // ── assemble_bundle ────────────────────────────────────────

    /// Builds a synthetic pcap with one or more TCP packets.
    fn write_synthetic_pcap(dir: &Path, name: &str, packets: &[(u32, u16)]) {
        let mut data = Vec::new();
        // Global header (little-endian magic).
        data.extend_from_slice(&0xa1b2_c3d4_u32.to_le_bytes());
        data.extend_from_slice(&2u16.to_le_bytes());
        data.extend_from_slice(&4u16.to_le_bytes());
        data.extend_from_slice(&0i32.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&65535u32.to_le_bytes());
        data.extend_from_slice(&1u32.to_le_bytes());
        for &(ts, src_port) in packets {
            // Packet: Ethernet + IPv4 + TCP
            let mut pkt = Vec::new();
            pkt.extend_from_slice(&[0u8; 12]); // MACs
            pkt.extend_from_slice(&0x0800u16.to_be_bytes()); // EtherType IPv4
            pkt.push(0x45); // IPv4, IHL=5
            pkt.push(0);
            pkt.extend_from_slice(&40u16.to_be_bytes());
            pkt.extend_from_slice(&[0; 4]);
            pkt.push(64);
            pkt.push(6); // TCP
            pkt.extend_from_slice(&[0; 2]);
            pkt.extend_from_slice(&[10, 100, 0, 2]); // src_ip
            pkt.extend_from_slice(&[10, 100, 0, 3]); // dst_ip
            pkt.extend_from_slice(&src_port.to_be_bytes());
            pkt.extend_from_slice(&80u16.to_be_bytes());
            pkt.extend_from_slice(&[0; 16]);
            // Packet record header.
            let pkt_len = u32::try_from(pkt.len()).unwrap();
            data.extend_from_slice(&ts.to_le_bytes());
            data.extend_from_slice(&0u32.to_le_bytes());
            data.extend_from_slice(&pkt_len.to_le_bytes());
            data.extend_from_slice(&pkt_len.to_le_bytes());
            data.extend(pkt);
        }
        fs::write(dir.join(name), data).unwrap();
    }

    fn ac0_host_ips() -> Vec<(String, Vec<std::net::Ipv4Addr>)> {
        vec![
            (
                "attacker-001".into(),
                vec![std::net::Ipv4Addr::new(10, 100, 0, 2)],
            ),
            (
                "target-001".into(),
                vec![std::net::Ipv4Addr::new(10, 100, 0, 3)],
            ),
        ]
    }

    fn make_execution(ts: i64, attack: Option<activity::AttackDetail>) -> activity::Execution {
        let start = chrono::TimeZone::timestamp_opt(&chrono::Utc, ts, 0).unwrap();
        activity::Execution {
            start,
            end: start + chrono::Duration::try_seconds(1).unwrap(),
            source: "attacker-001".into(),
            target: "target-001".into(),
            protocol: scenario::Protocol::Tcp,
            src_ip: std::net::Ipv4Addr::new(10, 100, 0, 2),
            src_port: 0,
            dst_ip: std::net::Ipv4Addr::new(10, 100, 0, 3),
            dst_port: 80,
            attack,
        }
    }

    #[test]
    fn assemble_bundle_writes_gt_and_meta() {
        let scenario = load_ac0();
        let dir = tempfile::tempdir().unwrap();
        create_output_dirs(dir.path(), &scenario).unwrap();

        let ts: i64 = 1_737_000_030;
        write_synthetic_pcap(
            &dir.path().join("net"),
            "capture-lan.pcap",
            &[(u32::try_from(ts).unwrap(), 49152)],
        );

        let host_ips = ac0_host_ips();
        let start = chrono::TimeZone::timestamp_opt(&chrono::Utc, ts, 0).unwrap();
        let mut executions = vec![make_execution(ts, None)];

        assemble_bundle(
            dir.path(),
            "ac-0.scenario.yaml",
            &scenario,
            &host_ips,
            start,
            &mut executions,
        )
        .unwrap();

        // src_port should be enriched from pcap.
        assert_eq!(executions[0].src_port, 49152);

        // ground_truth/manifest.jsonl must exist with one record.
        let gt = fs::read_to_string(dir.path().join("ground_truth/manifest.jsonl")).unwrap();
        let record: serde_json::Value = serde_json::from_str(gt.trim()).unwrap();
        assert_eq!(record["label"], "normal");
        assert_eq!(record["src_port"], 49152);

        // meta.json must exist and be valid.
        let meta: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(dir.path().join("meta.json")).unwrap())
                .unwrap();
        assert_eq!(meta["schema_version"], "1");
        assert_eq!(meta["hosts"][0]["name"], "attacker-001");
    }

    #[test]
    fn assemble_bundle_writes_attack_record() {
        let scenario = load_ac0();
        let dir = tempfile::tempdir().unwrap();
        create_output_dirs(dir.path(), &scenario).unwrap();

        let ts: i64 = 1_737_000_120;
        write_synthetic_pcap(
            &dir.path().join("net"),
            "capture-lan.pcap",
            &[(u32::try_from(ts).unwrap(), 50000)],
        );

        let host_ips = ac0_host_ips();
        let start = chrono::TimeZone::timestamp_opt(&chrono::Utc, ts, 0).unwrap();
        let mut executions = vec![make_execution(
            ts,
            Some(activity::AttackDetail {
                technique: "T1046".into(),
                phase: scenario::Phase::Reconnaissance,
                tool: "nmap".into(),
            }),
        )];

        assemble_bundle(
            dir.path(),
            "ac-0.scenario.yaml",
            &scenario,
            &host_ips,
            start,
            &mut executions,
        )
        .unwrap();

        let gt = fs::read_to_string(dir.path().join("ground_truth/manifest.jsonl")).unwrap();
        let record: serde_json::Value = serde_json::from_str(gt.trim()).unwrap();
        assert_eq!(record["label"], "anomaly");
        assert_eq!(record["category"], "attack");
        assert_eq!(record["technique"], "T1046");
        assert_eq!(record["phase"], "reconnaissance");
        assert_eq!(record["tool"], "nmap");
        assert_eq!(record["src_port"], 50000);
    }

    #[test]
    fn assemble_bundle_mixed_normal_and_attack() {
        let scenario = load_ac0();
        let dir = tempfile::tempdir().unwrap();
        create_output_dirs(dir.path(), &scenario).unwrap();

        let ts_normal: i64 = 1_737_000_030;
        let ts_attack: i64 = 1_737_000_120;
        write_synthetic_pcap(
            &dir.path().join("net"),
            "capture-lan.pcap",
            &[
                (u32::try_from(ts_normal).unwrap(), 49152),
                (u32::try_from(ts_attack).unwrap(), 50000),
            ],
        );

        let host_ips = ac0_host_ips();
        let start = chrono::TimeZone::timestamp_opt(&chrono::Utc, ts_normal, 0).unwrap();
        let mut executions = vec![
            make_execution(ts_normal, None),
            make_execution(
                ts_attack,
                Some(activity::AttackDetail {
                    technique: "T1046".into(),
                    phase: scenario::Phase::Reconnaissance,
                    tool: "nmap".into(),
                }),
            ),
        ];

        assemble_bundle(
            dir.path(),
            "ac-0.scenario.yaml",
            &scenario,
            &host_ips,
            start,
            &mut executions,
        )
        .unwrap();

        // Both src_ports enriched.
        assert_eq!(executions[0].src_port, 49152);
        assert_eq!(executions[1].src_port, 50000);

        // Two JSONL records in correct order.
        let gt = fs::read_to_string(dir.path().join("ground_truth/manifest.jsonl")).unwrap();
        let lines: Vec<&str> = gt.lines().collect();
        assert_eq!(lines.len(), 2);

        let r0: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        let r1: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(r0["label"], "normal");
        assert_eq!(r0["src_port"], 49152);
        assert_eq!(r1["label"], "anomaly");
        assert_eq!(r1["src_port"], 50000);

        // Records sorted by start time.
        assert!(
            r0["start"].as_str().unwrap() < r1["start"].as_str().unwrap(),
            "records must be sorted by start time",
        );

        // meta.json written with both hosts.
        let meta: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(dir.path().join("meta.json")).unwrap())
                .unwrap();
        assert_eq!(meta["hosts"].as_array().unwrap().len(), 2);
    }

    // ── create_output_dirs ───────────────────────────────────────

    #[test]
    fn create_output_dirs_creates_expected_structure() {
        let scenario = load_ac0();
        let dir = tempfile::tempdir().unwrap();
        create_output_dirs(dir.path(), &scenario).unwrap();

        assert!(dir.path().join("net").is_dir());
        assert!(dir.path().join("ground_truth").is_dir());
        assert!(dir.path().join("host/attacker-001").is_dir());
        assert!(dir.path().join("host/target-001").is_dir());
    }

    #[test]
    fn create_output_dirs_is_idempotent() {
        let scenario = load_ac0();
        let dir = tempfile::tempdir().unwrap();
        create_output_dirs(dir.path(), &scenario).unwrap();
        create_output_dirs(dir.path(), &scenario).unwrap();
        assert!(dir.path().join("net").is_dir());
    }

    /// Full generate flow — requires a running Docker daemon.
    ///
    /// Note: this test waits for real activity offsets (30 s + 120 s)
    /// so it takes ~2.5 minutes. For a faster Docker test that skips
    /// offset waits, see `activity::tests::exec_activities_in_ac0_containers`.
    #[tokio::test]
    #[ignore = "requires Docker daemon"]
    async fn generate_ac0_produces_valid_bundle() {
        // Create a temp copy of the scenario with a unique subnet.
        let subnet = test_util::unique_subnet();
        let original = fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("scenarios")
                .join("ac-0.scenario.yaml"),
        )
        .unwrap();
        let modified = original.replace("10.100.0.0/24", &subnet);

        let dir = tempfile::tempdir().unwrap();
        let scenario_path = dir.path().join("ac-0.scenario.yaml");
        fs::write(&scenario_path, &modified).unwrap();

        let output_dir = dir.path().join("output");
        generate(
            scenario_path.to_str().unwrap(),
            output_dir.to_str().unwrap(),
        )
        .await
        .unwrap();

        // Derive expected IPs from the assigned subnet.
        let hosts = vec!["attacker-001".to_owned(), "target-001".to_owned()];
        let (_, expected_ips) = infra::assign_ips(&subnet, &hosts).unwrap();
        let attacker_ip = expected_ips[0].1.to_string();
        let target_ip = expected_ips[1].1.to_string();

        // ── Bundle directory structure ────────────────────────────
        assert!(output_dir.join("net").is_dir());
        assert!(output_dir.join("ground_truth").is_dir());
        assert!(output_dir.join("host/attacker-001").is_dir());
        assert!(output_dir.join("host/target-001").is_dir());

        // ── PCAP present and non-empty ───────────────────────────
        let pcap_path = output_dir.join("net/capture-lan.pcap");
        assert!(pcap_path.exists(), "pcap file was not created");
        let pcap_len = fs::metadata(&pcap_path).unwrap().len();
        assert!(pcap_len > 24, "pcap must be larger than the global header");

        // ── meta.json ────────────────────────────────────────────
        let meta_path = output_dir.join("meta.json");
        assert!(meta_path.exists(), "meta.json was not created");
        let meta_content = fs::read_to_string(&meta_path).unwrap();
        let meta: serde_json::Value = serde_json::from_str(&meta_content).unwrap();
        assert_eq!(meta["schema_version"], "1");
        assert_eq!(meta["scenario"], "ac-0.scenario.yaml");
        assert_eq!(meta["duration"]["total"], "5m");
        assert_eq!(meta["hosts"][0]["name"], "attacker-001");
        assert_eq!(meta["hosts"][0]["ips"][0], attacker_ip);
        assert_eq!(meta["hosts"][1]["name"], "target-001");
        assert_eq!(meta["hosts"][1]["ips"][0], target_ip);
        assert_eq!(meta["network"]["segments"][0]["name"], "lan");
        assert_eq!(meta["network"]["segments"][0]["subnet"], subnet);
        assert_eq!(meta["capture"]["pcaps"][0]["segment"], "lan");
        assert_eq!(meta["capture"]["pcaps"][0]["path"], "net/capture-lan.pcap",);

        // ── ground_truth/manifest.jsonl ──────────────────────────
        let gt_path = output_dir.join("ground_truth/manifest.jsonl");
        assert!(gt_path.exists(), "manifest.jsonl was not created");
        let gt_content = fs::read_to_string(&gt_path).unwrap();
        let lines: Vec<&str> = gt_content.lines().collect();
        assert_eq!(lines.len(), 2, "expected 1 normal + 1 attack record");

        let records: Vec<serde_json::Value> = lines
            .iter()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();

        // Find records by label rather than relying on line order.
        let normal = records
            .iter()
            .find(|r| r["label"] == "normal")
            .expect("expected a normal record");
        let anomaly = records
            .iter()
            .find(|r| r["label"] == "anomaly")
            .expect("expected an anomaly record");

        // Normal record — all v1 required fields.
        assert_eq!(normal["scope"], "session");
        assert_eq!(normal["source"], "attacker-001");
        assert_eq!(normal["target"], "target-001");
        assert_eq!(normal["session_type"], "network");
        assert_eq!(normal["protocol"], "tcp");
        assert_eq!(normal["src_ip"], attacker_ip);
        assert!(
            normal["src_port"].as_u64().unwrap() > 0,
            "src_port must be enriched"
        );
        assert_eq!(normal["dst_ip"], target_ip);
        assert_eq!(normal["dst_port"], 80);
        assert!(
            normal.get("category").is_none(),
            "normal record must omit category"
        );

        // Anomaly record — all v1 required fields including attack fields.
        assert_eq!(anomaly["scope"], "session");
        assert_eq!(anomaly["source"], "attacker-001");
        assert_eq!(anomaly["target"], "target-001");
        assert_eq!(anomaly["session_type"], "network");
        assert_eq!(anomaly["protocol"], "tcp");
        assert_eq!(anomaly["src_ip"], attacker_ip);
        assert!(
            anomaly["src_port"].as_u64().unwrap() > 0,
            "src_port must be enriched"
        );
        assert_eq!(anomaly["dst_ip"], target_ip);
        assert_eq!(anomaly["dst_port"], 80);
        assert_eq!(anomaly["category"], "attack");
        assert_eq!(anomaly["technique"], "T1046");
        assert_eq!(anomaly["phase"], "reconnaissance");
        assert_eq!(anomaly["tool"], "nmap");
    }

    /// Generates AC-0 and validates the resulting bundle.
    #[tokio::test]
    #[ignore = "requires Docker daemon"]
    async fn generated_ac0_bundle_passes_validator() {
        let subnet = test_util::unique_subnet();
        let original = fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("scenarios")
                .join("ac-0.scenario.yaml"),
        )
        .unwrap();
        let modified = original.replace("10.100.0.0/24", &subnet);

        let dir = tempfile::tempdir().unwrap();
        let scenario_path = dir.path().join("ac-0.scenario.yaml");
        fs::write(&scenario_path, &modified).unwrap();

        let output_dir = dir.path().join("output");
        generate(
            scenario_path.to_str().unwrap(),
            output_dir.to_str().unwrap(),
        )
        .await
        .unwrap();

        let report = validator::run(&output_dir).unwrap();
        assert!(
            !report.has_failures(),
            "generated AC-0 bundle has validation failures: {:#?}",
            serde_json::to_string_pretty(&report).unwrap(),
        );
        assert_eq!(report.exit_code(), ExitCode::SUCCESS);
    }
}
