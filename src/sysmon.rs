use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

use crate::vm::{self, ProvisionedVm};

/// Minimal Sysmon configuration (SwiftOnSecurity-inspired baseline).
///
/// Captures process creation, network connections, file creation, and
/// registry modifications — the core events useful for threat detection
/// datasets.
const SYSMON_CONFIG_XML: &str = r#"<Sysmon schemaversion="4.90">
  <EventFiltering>
    <!-- Event ID 1: Process Create -->
    <ProcessCreate onmatch="exclude" />
    <!-- Event ID 3: Network Connection -->
    <NetworkConnect onmatch="exclude" />
    <!-- Event ID 11: File Create -->
    <FileCreate onmatch="exclude" />
    <!-- Event ID 13: Registry Value Set -->
    <RegistryEvent onmatch="exclude" />
  </EventFiltering>
</Sysmon>"#;

/// Installs Sysmon with a baseline configuration on a Windows VM.
///
/// Assumes the base VM image has Sysmon64.exe pre-installed at
/// `C:\Sysmon\Sysmon64.exe`. Writes the config XML and runs the
/// installer with `-accepteula -i`.
pub(crate) async fn install_and_configure(vm_host: &ProvisionedVm) -> Result<()> {
    // Write config XML to the VM.
    let escaped_xml = SYSMON_CONFIG_XML.replace('\'', "''");
    let write_cmd = format!(
        "powershell -Command \"Set-Content \
         -Path 'C:\\sysmon-config.xml' \
         -Value '{escaped_xml}'\""
    );
    let code = vm::exec_ssh(
        &vm_host.mgmt_ip,
        &vm_host.ssh_user,
        &vm_host.ssh_password,
        &write_cmd,
    )
    .await
    .context("failed to write Sysmon config")?;
    if code != 0 {
        bail!(
            "writing Sysmon config on '{}' exited with code {code}",
            vm_host.host_name,
        );
    }

    // Install Sysmon with the config.
    let install_cmd =
        "powershell -Command \"& 'C:\\Sysmon\\Sysmon64.exe' -accepteula -i C:\\sysmon-config.xml\"";
    let code = vm::exec_ssh(
        &vm_host.mgmt_ip,
        &vm_host.ssh_user,
        &vm_host.ssh_password,
        install_cmd,
    )
    .await
    .context("failed to install Sysmon")?;
    if code != 0 {
        bail!(
            "Sysmon installation on '{}' exited with code {code}",
            vm_host.host_name,
        );
    }

    println!("  Sysmon installed on {}", vm_host.host_name);
    Ok(())
}

/// Exports Sysmon event logs as JSONL and downloads the file to the
/// bundle's `host/<hostname>/sysmon.jsonl`.
///
/// Returns the relative path within the bundle (e.g.
/// `host/win-target-001/sysmon.jsonl`).
pub(crate) async fn collect_logs(vm_host: &ProvisionedVm, output_dir: &Path) -> Result<PathBuf> {
    let host_dir = output_dir.join("host").join(&vm_host.host_name);

    // Export Sysmon event log as JSONL via PowerShell.
    let export_cmd = "powershell -Command \"\
        Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' \
        -ErrorAction SilentlyContinue | \
        ForEach-Object { $_ | ConvertTo-Json -Compress } | \
        Set-Content -Path 'C:\\sysmon_export.jsonl'\"";
    let code = vm::exec_ssh(
        &vm_host.mgmt_ip,
        &vm_host.ssh_user,
        &vm_host.ssh_password,
        export_cmd,
    )
    .await
    .context("failed to export Sysmon logs")?;
    if code != 0 {
        bail!(
            "Sysmon log export on '{}' exited with code {code}",
            vm_host.host_name,
        );
    }

    // Download the exported JSONL file.
    let local_path = host_dir.join("sysmon.jsonl");
    vm::scp_from(vm_host, "C:\\sysmon_export.jsonl", &local_path)
        .await
        .with_context(|| {
            format!(
                "failed to download sysmon.jsonl from '{}'",
                vm_host.host_name,
            )
        })?;

    // Return relative path within the bundle.
    let relative = PathBuf::from("host")
        .join(&vm_host.host_name)
        .join("sysmon.jsonl");
    println!(
        "  Collected Sysmon logs from {} -> {}",
        vm_host.host_name,
        relative.display(),
    );
    Ok(relative)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_xml_is_well_formed_sysmon_element() {
        assert!(
            SYSMON_CONFIG_XML.starts_with("<Sysmon "),
            "config must start with a Sysmon element",
        );
        assert!(
            SYSMON_CONFIG_XML.ends_with("</Sysmon>"),
            "config must end with closing Sysmon tag",
        );
    }

    #[test]
    fn config_xml_contains_expected_event_filters() {
        assert!(SYSMON_CONFIG_XML.contains("ProcessCreate"));
        assert!(SYSMON_CONFIG_XML.contains("NetworkConnect"));
        assert!(SYSMON_CONFIG_XML.contains("FileCreate"));
        assert!(SYSMON_CONFIG_XML.contains("RegistryEvent"));
    }

    #[test]
    fn config_xml_has_no_single_quotes() {
        // The XML is embedded in a PowerShell single-quoted string.
        // Single quotes inside would need escaping (''), so verify
        // none are present to avoid broken commands.
        assert!(
            !SYSMON_CONFIG_XML.contains('\''),
            "config XML must not contain single quotes (breaks PowerShell embedding)",
        );
    }
}
