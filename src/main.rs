use std::fs;
use std::path::Path;
use std::process::ExitCode;

use anyhow::{Context, Result};
use chrono::Utc;
use clap::{Parser, Subcommand};

mod infra;
mod meta;
mod scenario;

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
        Command::Generate { scenario, output } => generate(&scenario, &output).await,
        Command::Validate { bundle } => validate(&bundle),
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
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

    // Derive the scenario filename for meta.json.
    let scenario_filename = Path::new(scenario_path).file_name().map_or_else(
        || scenario_path.to_owned(),
        |n| n.to_string_lossy().into_owned(),
    );
    let write_result = meta::write(
        output_dir,
        &scenario_filename,
        &scenario,
        &env.host_ips,
        start,
    );

    // Always tear down infrastructure, even if a previous step failed.
    let teardown_result = env.down().await;
    write_result?;
    println!("Wrote meta.json to {output}");
    teardown_result?;
    println!("Infrastructure torn down");

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

#[allow(clippy::unnecessary_wraps)]
fn validate(bundle: &str) -> Result<()> {
    println!("validate: bundle={bundle}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn load_ac0() -> scenario::Scenario {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("scenarios")
            .join("ac-0.scenario.yaml");
        scenario::load(&path).unwrap()
    }

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
    #[tokio::test]
    #[ignore = "requires Docker daemon"]
    async fn generate_ac0_produces_valid_bundle() {
        let scenario_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("scenarios")
            .join("ac-0.scenario.yaml");
        let dir = tempfile::tempdir().unwrap();
        let output = dir.path().to_str().unwrap();

        generate(scenario_path.to_str().unwrap(), output)
            .await
            .unwrap();

        // Verify directory structure.
        assert!(dir.path().join("net").is_dir());
        assert!(dir.path().join("ground_truth").is_dir());
        assert!(dir.path().join("host/attacker-001").is_dir());
        assert!(dir.path().join("host/target-001").is_dir());

        // Verify meta.json exists and contains correct IPs.
        let meta_path = dir.path().join("meta.json");
        assert!(meta_path.exists(), "meta.json was not created");
        let content = fs::read_to_string(&meta_path).unwrap();
        let value: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert_eq!(value["schema_version"], "1");
        assert_eq!(value["hosts"][0]["name"], "attacker-001");
        assert_eq!(value["hosts"][0]["ips"][0], "10.100.0.2");
        assert_eq!(value["hosts"][1]["name"], "target-001");
        assert_eq!(value["hosts"][1]["ips"][0], "10.100.0.3");
        assert_eq!(value["network"]["segments"][0]["subnet"], "10.100.0.0/24");
    }
}
