use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use bollard::Docker;
use bollard::exec::CreateExecOptions;
use bollard::models::ContainerStateStatusEnum;
use futures_util::StreamExt;

/// Output path inside the Falco sidecar container where JSONL events
/// are written.
pub(crate) const CONTAINER_OUTPUT_PATH: &str = "/var/log/falco.jsonl";

/// Collects Falco JSONL output from a sidecar container into the
/// bundle's `host/<hostname>/falco.jsonl`.
///
/// If the sidecar is no longer running (e.g. eBPF unavailable in CI)
/// or produced no events, writes an empty file so the validator can
/// surface it as a warning (`L2-009`) rather than aborting the whole
/// bundle generation.
///
/// Returns the relative path within the bundle (e.g.
/// `host/target-001/falco.jsonl`).
pub(crate) async fn collect_logs(
    docker: &Docker,
    container_id: &str,
    host_name: &str,
    output_dir: &Path,
) -> Result<PathBuf> {
    let host_dir = output_dir.join("host").join(host_name);
    let local_path = host_dir.join("falco.jsonl");
    let relative = PathBuf::from("host").join(host_name).join("falco.jsonl");

    // If the sidecar exited (e.g. eBPF probe failure), write an empty
    // file so the validator can report L2-009 as a warning.
    if !is_running(docker, container_id).await? {
        eprintln!(
            "  Warning: Falco sidecar for '{host_name}' is not running; \
             writing empty falco.jsonl",
        );
        std::fs::write(&local_path, b"").with_context(|| {
            format!(
                "failed to write falco.jsonl for '{host_name}' at {}",
                local_path.display(),
            )
        })?;
        return Ok(relative);
    }

    // Copy the JSONL file out of the sidecar container via exec + cat.
    let cat_cmd = format!("cat {CONTAINER_OUTPUT_PATH}");
    let output = exec_output(docker, container_id, &cat_cmd)
        .await
        .with_context(|| format!("failed to collect Falco logs from '{host_name}'"))?;

    if output.is_empty() {
        eprintln!(
            "  Warning: Falco log is empty for '{host_name}'; \
             sidecar produced no events",
        );
    }

    std::fs::write(&local_path, &output).with_context(|| {
        format!(
            "failed to write falco.jsonl for '{host_name}' at {}",
            local_path.display(),
        )
    })?;

    println!(
        "  Collected Falco logs from {host_name} -> {}",
        relative.display(),
    );
    Ok(relative)
}

/// Checks whether a container is currently running.
async fn is_running(docker: &Docker, container_id: &str) -> Result<bool> {
    let info = docker
        .inspect_container(container_id, None)
        .await
        .with_context(|| format!("failed to inspect container '{container_id}'"))?;
    let running = info
        .state
        .and_then(|s| s.status)
        .is_some_and(|s| s == ContainerStateStatusEnum::RUNNING);
    Ok(running)
}

/// Executes a command and captures its stdout as bytes.
///
/// Returns an error if the exec exits with a non-zero status code.
async fn exec_output(docker: &Docker, container_id: &str, command: &str) -> Result<Vec<u8>> {
    let config = CreateExecOptions {
        cmd: Some(vec!["/bin/sh", "-c", command]),
        attach_stdout: Some(true),
        attach_stderr: Some(true),
        ..Default::default()
    };
    let exec = docker
        .create_exec(container_id, config)
        .await
        .context("failed to create exec instance")?;
    let result = docker
        .start_exec(&exec.id, None)
        .await
        .context("failed to start exec")?;

    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    if let bollard::exec::StartExecResults::Attached {
        output: mut stream, ..
    } = result
    {
        while let Some(Ok(chunk)) = stream.next().await {
            match chunk {
                bollard::container::LogOutput::StdOut { message } => {
                    stdout.extend_from_slice(&message);
                }
                bollard::container::LogOutput::StdErr { message } => {
                    stderr.extend_from_slice(&message);
                }
                _ => {}
            }
        }
    }

    let inspect = docker
        .inspect_exec(&exec.id)
        .await
        .context("failed to inspect exec")?;
    let exit_code = inspect.exit_code.unwrap_or(0);
    if exit_code != 0 {
        let err_msg = String::from_utf8_lossy(&stderr);
        bail!("command exited with code {exit_code}: {command}\nstderr: {err_msg}",);
    }

    Ok(stdout)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn container_output_path_is_absolute() {
        assert!(
            CONTAINER_OUTPUT_PATH.starts_with('/'),
            "Falco output path must be absolute inside the container",
        );
    }

    #[test]
    fn container_output_path_ends_with_jsonl() {
        assert!(
            Path::new(CONTAINER_OUTPUT_PATH)
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("jsonl")),
            "Falco output must use .jsonl extension",
        );
    }
}
