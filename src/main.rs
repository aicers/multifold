use std::process::ExitCode;

use anyhow::Result;
use clap::{Parser, Subcommand};

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

fn main() -> ExitCode {
    let cli = Cli::parse();

    let result = match cli.command {
        Command::Generate { scenario, output } => generate(&scenario, &output),
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

// Stubs: will contain fallible logic once pipeline is implemented.
#[allow(clippy::unnecessary_wraps)]
fn generate(scenario: &str, output: &str) -> Result<()> {
    println!("generate: scenario={scenario}, output={output}");
    Ok(())
}

#[allow(clippy::unnecessary_wraps)]
fn validate(bundle: &str) -> Result<()> {
    println!("validate: bundle={bundle}");
    Ok(())
}
