use std::collections::{HashMap, HashSet};
use std::hash::Hasher;
use std::net::Ipv4Addr;
use std::path::Path;

use anyhow::{Context, Result, ensure};
use bollard::Docker;
use bollard::container::{
    Config, CreateContainerOptions, NetworkingConfig, RemoveContainerOptions,
};
use bollard::image::CreateImageOptions;
use bollard::models::{EndpointIpamConfig, EndpointSettings, HostConfig, Ipam, IpamConfig};
use bollard::network::{ConnectNetworkOptions, CreateNetworkOptions};
use futures_util::TryStreamExt;
use ipnet::Ipv4Net;

use crate::scenario::Scenario;

const CAPTURE_IMAGE: &str = "alpine:3.19";
const LINUX_IFNAMSIZ: usize = 15;

/// Holds provisioned Docker resources and assigned host IPs.
///
/// Each entry in `host_ips` maps a host name to **all** IPs assigned
/// across every segment the host belongs to (primary first).
pub(crate) struct ProvisionedEnv {
    docker: Docker,
    network_ids: Vec<String>,
    container_ids: Vec<String>,
    pub(crate) host_ips: Vec<(String, Vec<Ipv4Addr>)>,
}

/// Per-segment state accumulated during provisioning.
struct SegmentInfo {
    net_name: String,
    bridge: String,
    ips: Vec<(String, Ipv4Addr)>,
}

/// Assigns IPs to hosts within a CIDR subnet.
///
/// Skips the network address (.0) and gateway (.1), assigning from .2
/// onward. Returns the gateway IP and host-to-IP pairs.
pub(crate) fn assign_ips(
    subnet: &str,
    hosts: &[String],
) -> Result<(Ipv4Addr, Vec<(String, Ipv4Addr)>)> {
    let net: Ipv4Net = subnet
        .parse()
        .with_context(|| format!("invalid subnet CIDR: {subnet}"))?;
    let base = u32::from(net.network());
    let broadcast = u32::from(net.broadcast());
    let gateway = Ipv4Addr::from(base + 1);
    let mut ips = Vec::with_capacity(hosts.len());
    for (i, host) in hosts.iter().enumerate() {
        let offset = u32::try_from(i + 2).context("too many hosts for subnet IP assignment")?;
        let addr = base + offset;
        ensure!(
            addr < broadcast,
            "subnet {subnet} has no room for host '{host}' \
             (need {} addresses, only {} usable)",
            hosts.len(),
            broadcast - base - 2,
        );
        let ip = Ipv4Addr::from(addr);
        ips.push((host.clone(), ip));
    }
    Ok((gateway, ips))
}

/// Derives a Linux bridge interface name that fits within `IFNAMSIZ`.
fn bridge_name(prefix: &str, segment: &str) -> String {
    let candidate = format!("mf-{prefix}-{segment}");
    if candidate.len() <= LINUX_IFNAMSIZ {
        return candidate;
    }
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    hasher.write(candidate.as_bytes());
    format!("mf-{:011x}", hasher.finish() & 0xFFF_FFFF_FFFF)
}

/// Generates a short, per-run identifier to avoid Docker name collisions
/// across concurrent runs of the same scenario.
fn generate_run_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let mut h = std::collections::hash_map::DefaultHasher::new();
    h.write_u128(nanos);
    h.write_u32(std::process::id());
    // Intentionally truncate: we only need 32 bits of entropy for
    // a short collision-resistant suffix, not a full 64-bit hash.
    #[allow(clippy::cast_possible_truncation)]
    let short = h.finish() as u32;
    format!("{short:08x}")
}

impl ProvisionedEnv {
    /// Provisions Docker networks, containers, and capture sidecars
    /// for each network segment in the scenario.
    pub(crate) async fn up(scenario: &Scenario, pcap_dir: &Path) -> Result<Self> {
        let docker =
            Docker::connect_with_local_defaults().context("failed to connect to Docker daemon")?;
        docker
            .ping()
            .await
            .context("Docker daemon is not reachable — is Docker running?")?;

        let mut env = Self {
            docker,
            network_ids: Vec::new(),
            container_ids: Vec::new(),
            host_ips: Vec::new(),
        };

        let run_id = generate_run_id();
        if let Err(e) = env.setup(scenario, pcap_dir, &run_id).await {
            let _ = env.teardown_inner().await;
            return Err(e);
        }

        Ok(env)
    }

    /// Tears down all provisioned Docker resources.
    pub(crate) async fn down(self) -> Result<()> {
        self.teardown_inner().await
    }

    async fn setup(&mut self, scenario: &Scenario, pcap_dir: &Path, run_id: &str) -> Result<()> {
        let prefix = format!("{}-{run_id}", scenario.metadata.name);
        let mut pulled: HashSet<String> = HashSet::new();

        // Phase 1: Create Docker networks and compute IP assignments.
        let mut segments: Vec<SegmentInfo> = Vec::new();
        for seg in &scenario.infrastructure.network.segments {
            let (gateway, seg_ips) = assign_ips(&seg.subnet, &seg.hosts)?;
            let net_name = format!("mf-{prefix}-{}", seg.name);
            let bridge = bridge_name(&prefix, &seg.name);
            let network_id =
                create_network(&self.docker, &net_name, &seg.subnet, gateway, &bridge).await?;
            self.network_ids.push(network_id);
            segments.push(SegmentInfo {
                net_name,
                bridge,
                ips: seg_ips,
            });
        }

        // Phase 2: Create host containers (once each) and connect
        // multi-homed hosts to additional networks.
        let mut created: HashMap<String, String> = HashMap::new();
        for state in &segments {
            for (host_name, ip) in &state.ips {
                if let Some(container_id) = created.get(host_name) {
                    connect_container(&self.docker, &state.net_name, container_id, *ip).await?;
                    // Record the secondary IP for this multi-homed host.
                    if let Some((_, ips)) =
                        self.host_ips.iter_mut().find(|(name, _)| name == host_name)
                    {
                        ips.push(*ip);
                    }
                } else {
                    let host = scenario
                        .infrastructure
                        .hosts
                        .iter()
                        .find(|h| h.name == *host_name)
                        .with_context(|| format!("host '{host_name}' not in scenario"))?;

                    if pulled.insert(host.image.clone()) {
                        pull_image(&self.docker, &host.image).await?;
                    }

                    let container_name = format!("mf-{prefix}-{host_name}");
                    let id = create_host_container(
                        &self.docker,
                        &container_name,
                        &host.image,
                        &state.net_name,
                        &ip.to_string(),
                    )
                    .await?;
                    self.docker
                        .start_container::<String>(&id, None)
                        .await
                        .with_context(|| format!("failed to start container '{container_name}'"))?;
                    self.container_ids.push(id.clone());
                    created.insert(host_name.clone(), id);
                    self.host_ips.push((host_name.clone(), vec![*ip]));
                }
            }
        }

        // Phase 3: Start per-segment capture containers.
        // Each runs on the host network and captures the bridge interface
        // so it observes all unicast traffic between hosts.
        if pulled.insert(CAPTURE_IMAGE.to_owned()) {
            pull_image(&self.docker, CAPTURE_IMAGE).await?;
        }
        for (state, seg) in segments
            .iter()
            .zip(&scenario.infrastructure.network.segments)
        {
            let pcap_file = format!("capture-{}.pcap", seg.name);
            let capture_name = format!("mf-{prefix}-{}-capture", seg.name);
            let capture_id = create_capture_container(
                &self.docker,
                &capture_name,
                &state.bridge,
                pcap_dir,
                &pcap_file,
            )
            .await?;
            self.docker
                .start_container::<String>(&capture_id, None)
                .await
                .context("failed to start capture container")?;
            self.container_ids.push(capture_id);
        }

        Ok(())
    }

    async fn teardown_inner(&self) -> Result<()> {
        let opts = RemoveContainerOptions {
            force: true,
            ..Default::default()
        };
        for id in &self.container_ids {
            let _ = self.docker.stop_container(id, None).await;
            let _ = self.docker.remove_container(id, Some(opts)).await;
        }
        for id in &self.network_ids {
            let _ = self.docker.remove_network(id).await;
        }
        Ok(())
    }
}

async fn pull_image(docker: &Docker, image: &str) -> Result<()> {
    let (repo, tag) = image.split_once(':').unwrap_or((image, "latest"));
    let opts = CreateImageOptions {
        from_image: repo,
        tag,
        ..Default::default()
    };
    docker
        .create_image(Some(opts), None, None)
        .try_collect::<Vec<_>>()
        .await
        .with_context(|| format!("failed to pull image '{image}'"))?;
    Ok(())
}

async fn create_network(
    docker: &Docker,
    name: &str,
    subnet: &str,
    gateway: Ipv4Addr,
    bridge: &str,
) -> Result<String> {
    let options = HashMap::from([(
        String::from("com.docker.network.bridge.name"),
        bridge.to_owned(),
    )]);
    let config = CreateNetworkOptions {
        name: name.to_owned(),
        driver: String::from("bridge"),
        options,
        ipam: Ipam {
            config: Some(vec![IpamConfig {
                subnet: Some(subnet.to_owned()),
                gateway: Some(gateway.to_string()),
                ..Default::default()
            }]),
            ..Default::default()
        },
        ..Default::default()
    };
    let response = docker
        .create_network(config)
        .await
        .with_context(|| format!("failed to create network '{name}'"))?;
    Ok(response.id)
}

async fn create_host_container(
    docker: &Docker,
    name: &str,
    image: &str,
    network: &str,
    ip: &str,
) -> Result<String> {
    let mut endpoints = HashMap::new();
    endpoints.insert(
        network.to_owned(),
        EndpointSettings {
            ipam_config: Some(EndpointIpamConfig {
                ipv4_address: Some(ip.to_owned()),
                ..Default::default()
            }),
            ..Default::default()
        },
    );

    let config = Config {
        image: Some(image.to_owned()),
        cmd: Some(vec!["sleep".to_owned(), "infinity".to_owned()]),
        networking_config: Some(NetworkingConfig::<String> {
            endpoints_config: endpoints,
        }),
        ..Default::default()
    };
    let opts = CreateContainerOptions {
        name: name.to_owned(),
        ..Default::default()
    };
    let response = docker
        .create_container(Some(opts), config)
        .await
        .with_context(|| format!("failed to create container '{name}'"))?;
    Ok(response.id)
}

/// Connects an existing container to an additional Docker network.
async fn connect_container(
    docker: &Docker,
    network: &str,
    container_id: &str,
    ip: Ipv4Addr,
) -> Result<()> {
    let config = ConnectNetworkOptions {
        container: container_id.to_owned(),
        endpoint_config: EndpointSettings {
            ipam_config: Some(EndpointIpamConfig {
                ipv4_address: Some(ip.to_string()),
                ..Default::default()
            }),
            ..Default::default()
        },
    };
    docker
        .connect_network(network, config)
        .await
        .with_context(|| format!("failed to connect container to network '{network}'"))?;
    Ok(())
}

/// Creates a capture container that runs tcpdump on a bridge interface.
///
/// Uses host networking so the container can see the Linux bridge
/// created by Docker, capturing all unicast traffic between hosts.
async fn create_capture_container(
    docker: &Docker,
    name: &str,
    bridge_iface: &str,
    pcap_dir: &Path,
    pcap_filename: &str,
) -> Result<String> {
    let pcap_abs = std::fs::canonicalize(pcap_dir)
        .with_context(|| format!("failed to resolve pcap dir: {}", pcap_dir.display()))?;
    let bind = format!("{}:/capture", pcap_abs.display());

    let config = Config {
        image: Some(CAPTURE_IMAGE.to_owned()),
        cmd: Some(vec![
            "/bin/sh".to_owned(),
            "-c".to_owned(),
            format!(
                "apk add --no-cache tcpdump >/dev/null 2>&1 && \
                 exec tcpdump -i {bridge_iface} -w /capture/{pcap_filename} -U"
            ),
        ]),
        host_config: Some(HostConfig {
            binds: Some(vec![bind]),
            cap_add: Some(vec!["NET_RAW".to_owned(), "NET_ADMIN".to_owned()]),
            network_mode: Some(String::from("host")),
            ..Default::default()
        }),
        ..Default::default()
    };
    let opts = CreateContainerOptions {
        name: name.to_owned(),
        ..Default::default()
    };
    let response = docker
        .create_container(Some(opts), config)
        .await
        .with_context(|| format!("failed to create capture container '{name}'"))?;
    Ok(response.id)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── assign_ips tests ──────────────────────────────────────────

    #[test]
    fn assign_ips_basic() {
        let hosts = vec!["a".to_owned(), "b".to_owned()];
        let (gw, ips) = assign_ips("10.100.0.0/24", &hosts).unwrap();
        assert_eq!(gw, Ipv4Addr::new(10, 100, 0, 1));
        assert_eq!(ips.len(), 2);
        assert_eq!(ips[0], ("a".to_owned(), Ipv4Addr::new(10, 100, 0, 2)));
        assert_eq!(ips[1], ("b".to_owned(), Ipv4Addr::new(10, 100, 0, 3)));
    }

    #[test]
    fn assign_ips_single_host() {
        let hosts = vec!["only".to_owned()];
        let (gw, ips) = assign_ips("192.168.1.0/24", &hosts).unwrap();
        assert_eq!(gw, Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(ips.len(), 1);
        assert_eq!(ips[0], ("only".to_owned(), Ipv4Addr::new(192, 168, 1, 2)));
    }

    #[test]
    fn assign_ips_invalid_cidr() {
        let hosts = vec!["h1".to_owned()];
        let err = assign_ips("not-a-cidr", &hosts).unwrap_err();
        assert!(
            err.to_string().contains("invalid subnet CIDR"),
            "unexpected error: {err}",
        );
    }

    #[test]
    fn assign_ips_empty_hosts() {
        let hosts: Vec<String> = vec![];
        let (gw, ips) = assign_ips("10.0.0.0/24", &hosts).unwrap();
        assert_eq!(gw, Ipv4Addr::new(10, 0, 0, 1));
        assert!(ips.is_empty());
    }

    #[test]
    fn assign_ips_ac0_scenario() {
        let hosts = vec!["attacker-001".to_owned(), "target-001".to_owned()];
        let (gw, ips) = assign_ips("10.100.0.0/24", &hosts).unwrap();
        assert_eq!(gw, Ipv4Addr::new(10, 100, 0, 1));
        assert_eq!(
            ips[0],
            ("attacker-001".to_owned(), Ipv4Addr::new(10, 100, 0, 2))
        );
        assert_eq!(
            ips[1],
            ("target-001".to_owned(), Ipv4Addr::new(10, 100, 0, 3))
        );
    }

    #[test]
    fn assign_ips_subnet_overflow() {
        // /30 gives 4 addresses: .0 (net), .1 (gw), .2 (usable), .3 (broadcast)
        // Only 1 usable host address, so 2 hosts should fail.
        let hosts = vec!["a".to_owned(), "b".to_owned()];
        let err = assign_ips("10.0.0.0/30", &hosts).unwrap_err();
        assert!(
            err.to_string().contains("no room"),
            "unexpected error: {err}",
        );
    }

    #[test]
    fn assign_ips_subnet_exact_fit() {
        // /30 = 4 addresses. .0 net, .1 gw, .2 host, .3 broadcast.
        // Exactly 1 host should fit.
        let hosts = vec!["a".to_owned()];
        let (_, ips) = assign_ips("10.0.0.0/30", &hosts).unwrap();
        assert_eq!(ips.len(), 1);
        assert_eq!(ips[0].1, Ipv4Addr::new(10, 0, 0, 2));
    }

    #[test]
    fn assign_ips_different_subnets() {
        let hosts = vec!["h1".to_owned()];
        let (gw, ips) = assign_ips("172.16.5.0/24", &hosts).unwrap();
        assert_eq!(gw, Ipv4Addr::new(172, 16, 5, 1));
        assert_eq!(ips[0].1, Ipv4Addr::new(172, 16, 5, 2));
    }

    // ── bridge_name tests ─────────────────────────────────────────

    #[test]
    fn bridge_name_short_fits_directly() {
        assert_eq!(bridge_name("ac-0", "lan"), "mf-ac-0-lan");
    }

    #[test]
    fn bridge_name_long_falls_back_to_hash() {
        let name = bridge_name("very-long-scenario", "segment");
        assert!(
            name.len() <= LINUX_IFNAMSIZ,
            "bridge name '{name}' exceeds {LINUX_IFNAMSIZ} chars",
        );
        assert!(name.starts_with("mf-"));
    }

    #[test]
    fn bridge_name_is_deterministic() {
        let a = bridge_name("scenario", "seg");
        let b = bridge_name("scenario", "seg");
        assert_eq!(a, b);
    }

    #[test]
    fn bridge_name_at_exact_limit() {
        // "mf-abcdef-abcde" = 15 chars, right at IFNAMSIZ.
        let name = bridge_name("abcdef", "abcde");
        assert_eq!(name.len(), LINUX_IFNAMSIZ);
        assert_eq!(name, "mf-abcdef-abcde");
    }

    // ── generate_run_id tests ─────────────────────────────────────

    #[test]
    fn run_id_has_expected_length() {
        let id = generate_run_id();
        assert_eq!(id.len(), 8, "run_id should be 8 hex chars: {id}");
    }

    #[test]
    fn run_ids_are_unique_across_calls() {
        let a = generate_run_id();
        // Sleep a tiny bit to ensure different nanos.
        std::thread::sleep(std::time::Duration::from_millis(1));
        let b = generate_run_id();
        assert_ne!(a, b, "consecutive run_ids should differ");
    }

    // ── Docker E2E tests ──────────────────────────────────────────

    fn load_ac0() -> crate::scenario::Scenario {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("scenarios")
            .join("ac-0.scenario.yaml");
        crate::scenario::load(&path).unwrap()
    }

    /// Provisions and tears down ac-0 infrastructure — requires Docker.
    #[tokio::test]
    #[ignore = "requires Docker daemon"]
    async fn provision_ac0_assigns_correct_ips() {
        let scenario = load_ac0();
        let dir = tempfile::tempdir().unwrap();
        let net_dir = dir.path().join("net");
        std::fs::create_dir_all(&net_dir).unwrap();

        let env = ProvisionedEnv::up(&scenario, &net_dir).await.unwrap();

        assert_eq!(env.host_ips.len(), 2);
        assert_eq!(env.host_ips[0].0, "attacker-001");
        assert_eq!(env.host_ips[0].1, vec![Ipv4Addr::new(10, 100, 0, 2)]);
        assert_eq!(env.host_ips[1].0, "target-001");
        assert_eq!(env.host_ips[1].1, vec![Ipv4Addr::new(10, 100, 0, 3)]);

        env.down().await.unwrap();
    }

    /// Verifies containers are reachable after provisioning — requires Docker.
    #[tokio::test]
    #[ignore = "requires Docker daemon"]
    async fn provisioned_containers_have_connectivity() {
        let scenario = load_ac0();
        let dir = tempfile::tempdir().unwrap();
        let net_dir = dir.path().join("net");
        std::fs::create_dir_all(&net_dir).unwrap();

        let env = ProvisionedEnv::up(&scenario, &net_dir).await.unwrap();

        // Exec a ping from attacker to target inside the container.
        let target_ip = env.host_ips[1].1[0].to_string();
        let exec_config = bollard::exec::CreateExecOptions {
            cmd: Some(vec!["ping", "-c", "1", "-W", "2", &target_ip]),
            attach_stdout: Some(true),
            attach_stderr: Some(true),
            ..Default::default()
        };
        let exec = env
            .docker
            .create_exec(&env.container_ids[0], exec_config)
            .await
            .unwrap();
        let output = env.docker.start_exec(&exec.id, None).await.unwrap();

        if let bollard::exec::StartExecResults::Attached {
            output: mut stream, ..
        } = output
        {
            use futures_util::StreamExt;
            let mut stdout = String::new();
            while let Some(Ok(chunk)) = stream.next().await {
                stdout.push_str(&chunk.to_string());
            }
            assert!(
                stdout.contains("1 packets transmitted"),
                "ping failed: {stdout}",
            );
        } else {
            panic!("expected attached exec output");
        }

        env.down().await.unwrap();
    }

    /// Verifies teardown removes all Docker resources — requires Docker.
    #[tokio::test]
    #[ignore = "requires Docker daemon"]
    async fn teardown_removes_containers_and_networks() {
        let scenario = load_ac0();
        let dir = tempfile::tempdir().unwrap();
        let net_dir = dir.path().join("net");
        std::fs::create_dir_all(&net_dir).unwrap();

        let env = ProvisionedEnv::up(&scenario, &net_dir).await.unwrap();
        let container_ids = env.container_ids.clone();
        let network_ids = env.network_ids.clone();
        let docker = Docker::connect_with_local_defaults().unwrap();

        env.down().await.unwrap();

        // Verify containers are gone.
        for id in &container_ids {
            let result = docker.inspect_container(id, None).await;
            assert!(
                result.is_err(),
                "container {id} still exists after teardown"
            );
        }
        // Verify networks are gone.
        for id in &network_ids {
            let result = docker.inspect_network::<String>(id, None).await;
            assert!(result.is_err(), "network {id} still exists after teardown");
        }
    }
}
