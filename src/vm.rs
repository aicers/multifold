use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use tokio::process::Command;

use crate::scenario::VmConfig;

/// Maximum time to wait for the VM to obtain a DHCP management IP.
const DHCP_TIMEOUT: Duration = Duration::from_secs(120);

/// Maximum time to wait for SSH to become reachable.
const SSH_TIMEOUT: Duration = Duration::from_secs(300);

/// Interval between SSH readiness polls.
const SSH_POLL_INTERVAL: Duration = Duration::from_secs(5);

/// Represents a provisioned libvirt VM.
pub(crate) struct ProvisionedVm {
    /// Libvirt domain name (e.g. "mf-ac2-abc123-win-target-001").
    pub(crate) domain_name: String,
    /// Scenario host name.
    pub(crate) host_name: String,
    /// Path to the qcow2 overlay (deleted on teardown).
    pub(crate) overlay_path: PathBuf,
    /// Management IP on the libvirt default NAT network (for SSH).
    pub(crate) mgmt_ip: Ipv4Addr,
    /// SSH user.
    pub(crate) ssh_user: String,
    /// SSH password.
    pub(crate) ssh_password: String,
    /// Whether Sysmon telemetry should be collected.
    pub(crate) sysmon: bool,
}

/// Creates and starts a libvirt VM connected to a Docker bridge.
///
/// The VM gets two NICs: one on the libvirt `default` network (for SSH
/// management) and one on the specified Docker bridge (for scenario
/// traffic). A qcow2 overlay is created on top of the base image so
/// the original image is never modified.
pub(crate) async fn create_vm(
    host_name: &str,
    vm_config: &VmConfig,
    domain_prefix: &str,
    bridge_name: &str,
    test_ip: Ipv4Addr,
    prefix_len: u8,
    gateway: Ipv4Addr,
) -> Result<ProvisionedVm> {
    let domain_name = format!("mf-{domain_prefix}-{host_name}");
    let overlay_path = std::env::temp_dir().join(format!("{domain_name}.qcow2"));

    // Create a qcow2 overlay so the base image stays immutable.
    let status = Command::new("qemu-img")
        .args([
            "create",
            "-f",
            "qcow2",
            "-b",
            &vm_config.base_image,
            "-F",
            "qcow2",
        ])
        .arg(&overlay_path)
        .status()
        .await
        .context("failed to run qemu-img")?;
    if !status.success() {
        bail!("qemu-img create failed for {host_name}");
    }

    // Define and start the VM with two NICs.
    let memory = vm_config.memory_mb.to_string();
    let vcpus = vm_config.vcpus.to_string();
    let status = Command::new("virt-install")
        .args([
            "--name",
            &domain_name,
            "--memory",
            &memory,
            "--vcpus",
            &vcpus,
            "--disk",
        ])
        .arg(format!("path={},format=qcow2", overlay_path.display()))
        .args(["--import", "--network", "network=default", "--network"])
        .arg(format!("bridge={bridge_name},model=virtio"))
        .args(["--os-variant", "win10", "--noautoconsole", "--wait", "0"])
        .status()
        .await
        .context("failed to run virt-install")?;
    if !status.success() {
        bail!("virt-install failed for {host_name}");
    }

    // Wait for the VM to get a DHCP address on the management network.
    let mgmt_ip = resolve_mgmt_ip(&domain_name)
        .await
        .with_context(|| format!("failed to get management IP for {host_name}"))?;

    // Wait for SSH to become reachable.
    wait_ssh_ready(&mgmt_ip, &vm_config.ssh_user, &vm_config.ssh_password)
        .await
        .with_context(|| format!("SSH not reachable on {host_name} ({mgmt_ip})"))?;

    // Resolve the MAC address of the scenario NIC so we can identify
    // the correct adapter inside the Windows guest.
    let scenario_mac = resolve_scenario_mac(&domain_name, bridge_name)
        .await
        .with_context(|| format!("failed to get scenario NIC MAC for {host_name}"))?;

    // Windows represents MACs with hyphens in upper-case.
    let win_mac = scenario_mac.to_uppercase().replace(':', "-");

    // Configure the test network interface by matching its MAC address
    // instead of relying on a hard-coded interface alias.
    let configure_cmd = format!(
        "powershell -Command \"\
         $mac = '{win_mac}'; \
         $adapter = Get-NetAdapter | Where-Object {{ $_.MacAddress -eq $mac }}; \
         if (-not $adapter) {{ Write-Error 'no adapter with MAC {win_mac}'; exit 1 }}; \
         New-NetIPAddress \
           -InterfaceIndex $adapter.InterfaceIndex \
           -IPAddress {test_ip} \
           -PrefixLength {prefix_len} \
           -DefaultGateway {gateway}\""
    );
    let code = exec_ssh(
        &mgmt_ip,
        &vm_config.ssh_user,
        &vm_config.ssh_password,
        &configure_cmd,
    )
    .await
    .with_context(|| format!("failed to configure test NIC on {host_name}"))?;
    if code != 0 {
        bail!("test NIC configuration on '{host_name}' exited with code {code}");
    }

    Ok(ProvisionedVm {
        domain_name,
        host_name: host_name.to_owned(),
        overlay_path,
        mgmt_ip,
        ssh_user: vm_config.ssh_user.clone(),
        ssh_password: vm_config.ssh_password.clone(),
        sysmon: vm_config.sysmon,
    })
}

/// Destroys a libvirt VM and removes its overlay disk.
pub(crate) async fn destroy_vm(vm: &ProvisionedVm) -> Result<()> {
    let _ = Command::new("virsh")
        .args(["destroy", &vm.domain_name])
        .status()
        .await;
    let _ = Command::new("virsh")
        .args(["undefine", &vm.domain_name, "--remove-all-storage"])
        .status()
        .await;

    if vm.overlay_path.exists() {
        let _ = std::fs::remove_file(&vm.overlay_path);
    }
    Ok(())
}

/// Executes a command on a VM via SSH and returns the exit code.
pub(crate) async fn exec_ssh(
    ip: &Ipv4Addr,
    user: &str,
    password: &str,
    command: &str,
) -> Result<i64> {
    let output = Command::new("sshpass")
        .args(["-p", password, "ssh"])
        .args([
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "LogLevel=ERROR",
        ])
        .arg(format!("{user}@{ip}"))
        .arg(command)
        .output()
        .await
        .context("failed to run SSH command")?;

    Ok(i64::from(output.status.code().unwrap_or(-1)))
}

/// Copies a file from a VM to the local filesystem via SCP.
pub(crate) async fn scp_from(
    vm: &ProvisionedVm,
    remote_path: &str,
    local_path: &std::path::Path,
) -> Result<()> {
    let status = Command::new("sshpass")
        .args(["-p", &vm.ssh_password, "scp"])
        .args([
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "LogLevel=ERROR",
        ])
        .arg(format!("{}@{}:{}", vm.ssh_user, vm.mgmt_ip, remote_path))
        .arg(local_path)
        .status()
        .await
        .context("failed to run SCP")?;

    if !status.success() {
        bail!("SCP from {}:{} failed", vm.mgmt_ip, remote_path);
    }
    Ok(())
}

/// Polls `virsh domifaddr` until a DHCP IP is assigned on the default
/// network.
async fn resolve_mgmt_ip(domain_name: &str) -> Result<Ipv4Addr> {
    let deadline = tokio::time::Instant::now() + DHCP_TIMEOUT;

    loop {
        let output = Command::new("virsh")
            .args(["domifaddr", domain_name, "--source", "lease"])
            .output()
            .await
            .context("failed to run virsh domifaddr")?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        if let Some(ip) = parse_dhcp_ip(&stdout) {
            return Ok(ip);
        }

        if tokio::time::Instant::now() >= deadline {
            bail!(
                "timeout waiting for DHCP IP for '{domain_name}' \
                 (waited {}s)",
                DHCP_TIMEOUT.as_secs()
            );
        }
        tokio::time::sleep(SSH_POLL_INTERVAL).await;
    }
}

/// Parses the first IPv4 address from `virsh domifaddr` output.
///
/// Example output line:
/// ```text
///  vnet0      52:54:00:xx:xx:xx    ipv4         192.168.122.123/24
/// ```
fn parse_dhcp_ip(output: &str) -> Option<Ipv4Addr> {
    for line in output.lines() {
        for token in line.split_whitespace() {
            // Try stripping the CIDR prefix (e.g. "192.168.122.45/24").
            let ip_str = token.find('/').map_or(token, |i| &token[..i]);
            if let Ok(ip) = ip_str.parse::<Ipv4Addr>() {
                return Some(ip);
            }
        }
    }
    None
}

/// Retrieves the MAC address of the NIC attached to the given bridge.
///
/// Parses `virsh domiflist` output to find the interface connected to
/// the scenario bridge and returns its MAC address.
async fn resolve_scenario_mac(domain_name: &str, bridge_name: &str) -> Result<String> {
    let output = Command::new("virsh")
        .args(["domiflist", domain_name])
        .output()
        .await
        .context("failed to run virsh domiflist")?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_bridge_mac(&stdout, bridge_name).with_context(|| {
        format!("no NIC found on bridge '{bridge_name}' for domain '{domain_name}'")
    })
}

/// Parses a MAC address from `virsh domiflist` output for a given bridge.
///
/// Example output:
/// ```text
///  Interface  Type       Source     Model       MAC
/// -------------------------------------------------------
///  vnet0      network    default    rtl8139     52:54:00:aa:bb:cc
///  vnet1      bridge     mf-br1    virtio      52:54:00:dd:ee:ff
/// ```
fn parse_bridge_mac(output: &str, bridge_name: &str) -> Option<String> {
    for line in output.lines() {
        let tokens: Vec<&str> = line.split_whitespace().collect();
        // Expected columns: Interface, Type, Source, Model, MAC
        if tokens.len() >= 5 && tokens[1] == "bridge" && tokens[2] == bridge_name {
            return Some(tokens[4].to_owned());
        }
    }
    None
}

/// Polls SSH connectivity until the VM is reachable.
async fn wait_ssh_ready(ip: &Ipv4Addr, user: &str, password: &str) -> Result<()> {
    let deadline = tokio::time::Instant::now() + SSH_TIMEOUT;

    loop {
        let result = exec_ssh(ip, user, password, "echo ready").await;
        if let Ok(0) = result {
            return Ok(());
        }

        if tokio::time::Instant::now() >= deadline {
            bail!(
                "timeout waiting for SSH on {ip} (waited {}s)",
                SSH_TIMEOUT.as_secs()
            );
        }
        tokio::time::sleep(SSH_POLL_INTERVAL).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_dhcp_ip_typical_output() {
        let output = " Name       MAC address          Protocol     Address\n\
                       ---------------------------------------------------------------\n\
                        vnet0      52:54:00:ab:cd:ef    ipv4         192.168.122.45/24\n";
        assert_eq!(
            parse_dhcp_ip(output),
            Some(Ipv4Addr::new(192, 168, 122, 45)),
        );
    }

    #[test]
    fn parse_dhcp_ip_no_address() {
        assert_eq!(parse_dhcp_ip(""), None);
        assert_eq!(parse_dhcp_ip("Name   MAC   Protocol   Address\n"), None);
    }

    #[test]
    fn parse_dhcp_ip_different_prefix() {
        let output = " vnet0  52:54:00:ab:cd:ef  ipv4  10.0.0.5/16\n";
        assert_eq!(parse_dhcp_ip(output), Some(Ipv4Addr::new(10, 0, 0, 5)));
    }

    // ── parse_bridge_mac tests ──────────────────────────────────

    #[test]
    fn parse_bridge_mac_finds_matching_bridge() {
        let output = " Interface  Type       Source     Model       MAC\n\
                       -------------------------------------------------------\n\
                        vnet0      network    default    rtl8139     52:54:00:aa:bb:cc\n\
                        vnet1      bridge     mf-br1     virtio      52:54:00:dd:ee:ff\n";
        assert_eq!(
            parse_bridge_mac(output, "mf-br1"),
            Some("52:54:00:dd:ee:ff".to_owned()),
        );
    }

    #[test]
    fn parse_bridge_mac_no_match() {
        let output = " Interface  Type       Source     Model       MAC\n\
                       -------------------------------------------------------\n\
                        vnet0      network    default    rtl8139     52:54:00:aa:bb:cc\n";
        assert_eq!(parse_bridge_mac(output, "mf-br1"), None);
    }

    #[test]
    fn parse_bridge_mac_empty_output() {
        assert_eq!(parse_bridge_mac("", "mf-br1"), None);
    }

    #[test]
    fn parse_bridge_mac_ignores_network_type() {
        let output = " vnet0  network  mf-br1  rtl8139  52:54:00:aa:bb:cc\n";
        assert_eq!(
            parse_bridge_mac(output, "mf-br1"),
            None,
            "should only match type=bridge, not type=network",
        );
    }
}
