use std::collections::HashSet;
use std::net::Ipv4Addr;

use anyhow::{Context, Result};
use bollard::Docker;
use bollard::exec::CreateExecOptions;
use chrono::{DateTime, Utc};
use futures_util::StreamExt;
use tokio::task::JoinSet;

use crate::scenario::{Activities, Host, Phase, Protocol, parse_duration};
use crate::vm::{self, ProvisionedVm};

/// Seconds to wait after the last activity so trailing packets reach
/// the tcpdump capture containers.
const CAPTURE_DRAIN_SECS: u64 = 1;

/// Result of executing a single activity inside a container.
pub(crate) struct Execution {
    pub(crate) start: DateTime<Utc>,
    pub(crate) end: DateTime<Utc>,
    pub(crate) source: String,
    pub(crate) target: String,
    pub(crate) protocol: Protocol,
    pub(crate) src_ip: Ipv4Addr,
    pub(crate) src_port: u16,
    pub(crate) dst_ip: Ipv4Addr,
    pub(crate) dst_port: u16,
    pub(crate) attack: Option<AttackDetail>,
    pub(crate) exit_code: i64,
    pub(crate) command: String,
}

pub(crate) struct AttackDetail {
    pub(crate) technique: String,
    pub(crate) phase: Phase,
    pub(crate) tool: String,
    pub(crate) campaign_id: Option<String>,
    pub(crate) step: Option<u32>,
}

/// A unified activity ready for execution.
struct Scheduled<'a> {
    offset: chrono::Duration,
    source: &'a str,
    target: &'a str,
    command: &'a str,
    protocol: Protocol,
    dst_port: u16,
    attack: Option<AttackRef<'a>>,
}

struct AttackRef<'a> {
    technique: &'a str,
    phase: Phase,
    tool: &'a str,
    campaign_id: Option<&'a str>,
    step: Option<u32>,
}

/// Runs per-host setup commands before any activities start.
///
/// Each command runs sequentially inside the host's container (or via
/// SSH for VM hosts) and must exit with code 0.  Typical use: start a
/// background service (e.g. `busybox httpd`) that activities will
/// target.
pub(crate) async fn run_setup(
    docker: &Docker,
    hosts: &[Host],
    host_containers: &[(String, String)],
    vms: &[ProvisionedVm],
) -> Result<()> {
    for host in hosts {
        if host.setup.is_empty() {
            continue;
        }

        if host.is_vm() {
            let vm_host = lookup_vm(vms, &host.name)?;
            for cmd in &host.setup {
                println!("  Setup {} (VM): {cmd}", host.name);
                let code = vm::exec_ssh(
                    &vm_host.mgmt_ip,
                    &vm_host.ssh_user,
                    &vm_host.ssh_password,
                    cmd,
                )
                .await
                .with_context(|| format!("setup command failed in VM '{}'", host.name))?;
                anyhow::ensure!(
                    code == 0,
                    "setup command failed in VM '{}' (exit code {code}): {cmd}",
                    host.name,
                );
            }
        } else {
            let container_id = lookup_container(host_containers, &host.name)?;
            for cmd in &host.setup {
                println!("  Setup {}: {cmd}", host.name);
                let code = exec_in_container(docker, container_id, cmd)
                    .await
                    .with_context(|| format!("setup command failed in '{}'", host.name))?;
                anyhow::ensure!(
                    code == 0,
                    "setup command failed in '{}' (exit code {code}): {cmd}",
                    host.name,
                );
            }
        }
    }
    Ok(())
}

/// Backend for executing a command during an activity.
enum ExecBackend {
    /// Docker container identified by container ID.
    Docker {
        docker: Docker,
        container_id: String,
    },
    /// Libvirt VM reached via SSH.
    Ssh {
        mgmt_ip: Ipv4Addr,
        ssh_user: String,
        ssh_password: String,
    },
}

/// Executes all activities concurrently and returns execution results.
///
/// Each activity is spawned as an independent task that sleeps until its
/// `start_offset` elapses, then executes the command inside the source
/// host's container via Docker exec (or via SSH for VM hosts).  Tool
/// packages (curl, nmap) are installed in container-based sources
/// before any activity runs.
pub(crate) async fn run(
    docker: &Docker,
    host_containers: &[(String, String)],
    host_ips: &[(String, Vec<Ipv4Addr>)],
    activities: &Activities,
    generation_start: DateTime<Utc>,
    vms: &[ProvisionedVm],
) -> Result<Vec<Execution>> {
    // Install tools only in Docker-based activity sources.
    let sources = activity_sources(activities);
    let source_containers: Vec<_> = host_containers
        .iter()
        .filter(|(name, _)| sources.contains(name.as_str()))
        .map(|(n, id)| (n.clone(), id.clone()))
        .collect();
    install_tools(docker, &source_containers).await?;

    let mut schedule = build_schedule(activities)?;
    schedule.sort_unstable_by_key(|s| s.offset);

    // Resolve IPs and execution backend upfront so errors surface early.
    let prepared: Vec<_> = schedule
        .iter()
        .map(|a| {
            let src_ip = lookup_ip(host_ips, a.source)?;
            let dst_ip = lookup_ip(host_ips, a.target)?;
            let command = a.command.replace("${target_ip}", &dst_ip.to_string());
            let backend = resolve_backend(docker, host_containers, vms, a.source)?;
            Ok((a, src_ip, dst_ip, command, backend))
        })
        .collect::<Result<Vec<_>>>()?;

    // Spawn each activity as an independent task.
    let mut tasks = JoinSet::new();
    for (activity, src_ip, dst_ip, command, backend) in prepared {
        let target_time = generation_start + activity.offset;
        let source = activity.source.to_owned();
        let target = activity.target.to_owned();
        let protocol = activity.protocol;
        let dst_port = activity.dst_port;
        let attack = activity.attack.as_ref().map(|a| AttackDetail {
            technique: a.technique.to_owned(),
            phase: a.phase,
            tool: a.tool.to_owned(),
            campaign_id: a.campaign_id.map(str::to_owned),
            step: a.step,
        });

        tasks.spawn(async move {
            wait_until(target_time).await;

            println!("  Executing: {command}");
            let start = Utc::now();
            let exit_code = match &backend {
                ExecBackend::Docker {
                    docker,
                    container_id,
                } => exec_in_container(docker, container_id, &command)
                    .await
                    .with_context(|| format!("activity exec failed in '{source}'"))?,
                ExecBackend::Ssh {
                    mgmt_ip,
                    ssh_user,
                    ssh_password,
                } => vm::exec_ssh(mgmt_ip, ssh_user, ssh_password, &command)
                    .await
                    .with_context(|| format!("activity SSH exec failed in '{source}'"))?,
            };
            let end = Utc::now();

            if exit_code != 0 {
                eprintln!("  Warning: command exited with code {exit_code}: {command}");
            }

            Ok::<Execution, anyhow::Error>(Execution {
                start,
                end,
                source,
                target,
                protocol,
                src_ip,
                src_port: 0,
                dst_ip,
                dst_port,
                attack,
                exit_code,
                command,
            })
        });
    }

    let mut results = Vec::with_capacity(tasks.len());
    while let Some(outcome) = tasks.join_next().await {
        results.push(outcome.context("activity task panicked")??);
    }
    results.sort_by_key(|e| e.start);

    // Brief pause so trailing packets are captured by tcpdump.
    tokio::time::sleep(std::time::Duration::from_secs(CAPTURE_DRAIN_SECS)).await;

    Ok(results)
}

/// Resolves the execution backend for a given source host.
fn resolve_backend(
    docker: &Docker,
    host_containers: &[(String, String)],
    vms: &[ProvisionedVm],
    source: &str,
) -> Result<ExecBackend> {
    // Check VMs first.
    if let Some(vm_host) = vms.iter().find(|v| v.host_name == source) {
        return Ok(ExecBackend::Ssh {
            mgmt_ip: vm_host.mgmt_ip,
            ssh_user: vm_host.ssh_user.clone(),
            ssh_password: vm_host.ssh_password.clone(),
        });
    }
    // Fall back to Docker container.
    let container_id = lookup_container(host_containers, source)?;
    Ok(ExecBackend::Docker {
        docker: docker.clone(),
        container_id: container_id.to_owned(),
    })
}

fn build_schedule(activities: &Activities) -> Result<Vec<Scheduled<'_>>> {
    let mut schedule = Vec::with_capacity(activities.normal.len() + activities.attack.len());

    for a in &activities.normal {
        let offset = parse_duration(&a.start_offset)?;
        schedule.push(Scheduled {
            offset,
            source: &a.source,
            target: &a.target,
            command: &a.command,
            protocol: a.protocol,
            dst_port: a.dst_port,
            attack: None,
        });
    }

    for a in &activities.attack {
        let offset = parse_duration(&a.start_offset)?;
        schedule.push(Scheduled {
            offset,
            source: &a.source,
            target: &a.target,
            command: &a.command,
            protocol: a.protocol,
            dst_port: a.dst_port,
            attack: Some(AttackRef {
                technique: &a.technique,
                phase: a.phase,
                tool: &a.tool,
                campaign_id: a.campaign_id.as_deref(),
                step: a.step,
            }),
        });
    }

    Ok(schedule)
}

async fn wait_until(target: DateTime<Utc>) {
    let now = Utc::now();
    if target > now
        && let Ok(wait) = (target - now).to_std()
    {
        tokio::time::sleep(wait).await;
    }
}

fn lookup_ip(host_ips: &[(String, Vec<Ipv4Addr>)], host: &str) -> Result<Ipv4Addr> {
    host_ips
        .iter()
        .find(|(name, _)| name == host)
        .and_then(|(_, ips)| ips.first().copied())
        .with_context(|| format!("no IP found for host '{host}'"))
}

fn lookup_container<'a>(host_containers: &'a [(String, String)], host: &str) -> Result<&'a str> {
    host_containers
        .iter()
        .find(|(name, _)| name == host)
        .map(|(_, id)| id.as_str())
        .with_context(|| format!("no container found for host '{host}'"))
}

fn lookup_vm<'a>(vms: &'a [ProvisionedVm], host: &str) -> Result<&'a ProvisionedVm> {
    vms.iter()
        .find(|v| v.host_name == host)
        .with_context(|| format!("no VM found for host '{host}'"))
}

/// Returns the set of host names that appear as activity sources.
fn activity_sources(activities: &Activities) -> HashSet<&str> {
    let mut sources = HashSet::new();
    for a in &activities.normal {
        sources.insert(a.source.as_str());
    }
    for a in &activities.attack {
        sources.insert(a.source.as_str());
    }
    sources
}

/// Installs curl and nmap in each source container, skipping hosts that
/// already have both tools.  Detects the package manager (`apk` vs
/// `apt-get`) at runtime so that both Alpine and Debian/Ubuntu images work.
async fn install_tools(docker: &Docker, host_containers: &[(String, String)]) -> Result<()> {
    for (host, container_id) in host_containers {
        if has_tool(docker, container_id, "curl").await?
            && has_tool(docker, container_id, "nmap").await?
        {
            println!("  Tools already present in {host}, skipping install");
            continue;
        }

        let install_cmd = detect_install_cmd(docker, container_id)
            .await
            .with_context(|| format!("no supported package manager in '{host}'"))?;

        println!("  Installing tools in {host}…");
        let code = exec_in_container(docker, container_id, install_cmd)
            .await
            .with_context(|| format!("failed to install tools in '{host}'"))?;
        anyhow::ensure!(
            code == 0,
            "tool installation failed in '{host}' (exit code {code})",
        );
    }
    Ok(())
}

async fn has_tool(docker: &Docker, container_id: &str, tool: &str) -> Result<bool> {
    let cmd = format!("command -v {tool} >/dev/null 2>&1");
    Ok(exec_in_container(docker, container_id, &cmd).await? == 0)
}

async fn detect_install_cmd(docker: &Docker, container_id: &str) -> Result<&'static str> {
    if has_tool(docker, container_id, "apk").await? {
        return Ok("apk add --no-cache curl nmap >/dev/null 2>&1");
    }
    if has_tool(docker, container_id, "apt-get").await? {
        return Ok(
            "apt-get update -qq >/dev/null 2>&1 && apt-get install -y -qq curl nmap >/dev/null 2>&1",
        );
    }
    anyhow::bail!("expected apk or apt-get")
}

/// Executes a shell command inside a container and waits for completion.
///
/// Returns the process exit code (0 = success). Callers decide how to
/// handle non-zero codes: `install_tools` treats them as fatal while
/// activity commands warn but continue.
async fn exec_in_container(docker: &Docker, container_id: &str, command: &str) -> Result<i64> {
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
    let output = docker
        .start_exec(&exec.id, None)
        .await
        .context("failed to start exec")?;

    // Drain output stream so the exec finishes.
    if let bollard::exec::StartExecResults::Attached {
        output: mut stream, ..
    } = output
    {
        while let Some(Ok(_)) = stream.next().await {}
    }

    let inspect = docker
        .inspect_exec(&exec.id)
        .await
        .context("failed to inspect exec")?;
    Ok(inspect.exit_code.unwrap_or(0))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scenario::{AttackActivity, NormalActivity};

    // ── lookup_ip ─────────────────────────────────────────────────

    #[test]
    fn lookup_ip_finds_first_ip() {
        let host_ips = vec![
            ("a".to_owned(), vec![Ipv4Addr::new(10, 0, 0, 2)]),
            ("b".to_owned(), vec![Ipv4Addr::new(10, 0, 0, 3)]),
        ];
        assert_eq!(
            lookup_ip(&host_ips, "b").unwrap(),
            Ipv4Addr::new(10, 0, 0, 3)
        );
    }

    #[test]
    fn lookup_ip_returns_primary_for_multihomed_host() {
        let host_ips = vec![(
            "multi".to_owned(),
            vec![Ipv4Addr::new(10, 0, 0, 2), Ipv4Addr::new(172, 16, 0, 2)],
        )];
        assert_eq!(
            lookup_ip(&host_ips, "multi").unwrap(),
            Ipv4Addr::new(10, 0, 0, 2),
        );
    }

    #[test]
    fn lookup_ip_missing_host_errors() {
        let host_ips: Vec<(String, Vec<Ipv4Addr>)> = vec![];
        let err = lookup_ip(&host_ips, "nope").unwrap_err();
        assert!(err.to_string().contains("no IP found"), "unexpected: {err}");
    }

    // ── lookup_container ──────────────────────────────────────────

    #[test]
    fn lookup_container_finds_id() {
        let hc = vec![("host-1".to_owned(), "abc123".to_owned())];
        assert_eq!(lookup_container(&hc, "host-1").unwrap(), "abc123");
    }

    #[test]
    fn lookup_container_missing_host_errors() {
        let hc: Vec<(String, String)> = vec![];
        let err = lookup_container(&hc, "nope").unwrap_err();
        assert!(
            err.to_string().contains("no container found"),
            "unexpected: {err}",
        );
    }

    // ── build_schedule ────────────────────────────────────────────

    fn make_normal(name: &str, offset: &str, port: u16) -> NormalActivity {
        NormalActivity {
            name: name.to_owned(),
            source: "src".to_owned(),
            target: "dst".to_owned(),
            command: format!("echo {name}"),
            protocol: Protocol::Tcp,
            dst_port: port,
            start_offset: offset.to_owned(),
        }
    }

    fn make_attack(name: &str, offset: &str) -> AttackActivity {
        AttackActivity {
            name: name.to_owned(),
            source: "src".to_owned(),
            target: "dst".to_owned(),
            command: format!("echo {name}"),
            protocol: Protocol::Tcp,
            dst_port: 80,
            technique: "T1046".to_owned(),
            phase: Phase::Reconnaissance,
            tool: "nmap".to_owned(),
            start_offset: offset.to_owned(),
            campaign_id: None,
            step: None,
        }
    }

    #[test]
    fn build_schedule_empty_activities() {
        let activities = Activities {
            normal: vec![],
            attack: vec![],
        };
        let schedule = build_schedule(&activities).unwrap();
        assert!(schedule.is_empty());
    }

    #[test]
    fn build_schedule_normal_only() {
        let activities = Activities {
            normal: vec![make_normal("a", "10s", 80)],
            attack: vec![],
        };
        let schedule = build_schedule(&activities).unwrap();
        assert_eq!(schedule.len(), 1);
        assert!(schedule[0].attack.is_none());
    }

    #[test]
    fn build_schedule_attack_only() {
        let activities = Activities {
            normal: vec![],
            attack: vec![make_attack("a", "10s")],
        };
        let schedule = build_schedule(&activities).unwrap();
        assert_eq!(schedule.len(), 1);
        assert!(schedule[0].attack.is_some());
    }

    #[test]
    fn build_schedule_orders_by_offset() {
        let activities = Activities {
            normal: vec![make_normal("late", "120s", 80)],
            attack: vec![make_attack("early", "30s")],
        };
        let mut schedule = build_schedule(&activities).unwrap();
        schedule.sort_unstable_by_key(|s| s.offset);

        assert_eq!(schedule.len(), 2);
        assert!(
            schedule[0].attack.is_some(),
            "attack at 30s should be first"
        );
        assert!(
            schedule[1].attack.is_none(),
            "normal at 120s should be second"
        );
    }

    #[test]
    fn build_schedule_same_offset_includes_both() {
        let activities = Activities {
            normal: vec![make_normal("n", "30s", 80)],
            attack: vec![make_attack("a", "30s")],
        };
        let schedule = build_schedule(&activities).unwrap();
        assert_eq!(schedule.len(), 2);
    }

    #[test]
    fn build_schedule_preserves_normal_fields() {
        let activities = Activities {
            normal: vec![NormalActivity {
                name: "http-check".to_owned(),
                source: "attacker-001".to_owned(),
                target: "target-001".to_owned(),
                command: "curl http://${target_ip}:8080/".to_owned(),
                protocol: Protocol::Udp,
                dst_port: 8080,
                start_offset: "45s".to_owned(),
            }],
            attack: vec![],
        };
        let schedule = build_schedule(&activities).unwrap();
        let s = &schedule[0];
        assert_eq!(s.source, "attacker-001");
        assert_eq!(s.target, "target-001");
        assert_eq!(s.command, "curl http://${target_ip}:8080/");
        assert_eq!(s.protocol, Protocol::Udp);
        assert_eq!(s.dst_port, 8080);
        assert_eq!(s.offset, chrono::Duration::try_seconds(45).unwrap());
        assert!(s.attack.is_none());
    }

    #[test]
    fn build_schedule_preserves_attack_fields() {
        let activities = Activities {
            normal: vec![],
            attack: vec![AttackActivity {
                name: "scan".to_owned(),
                source: "a".to_owned(),
                target: "b".to_owned(),
                command: "nmap ${target_ip}".to_owned(),
                protocol: Protocol::Tcp,
                dst_port: 443,
                technique: "T1595".to_owned(),
                phase: Phase::Reconnaissance,
                tool: "nmap".to_owned(),
                start_offset: "2m".to_owned(),
                campaign_id: None,
                step: None,
            }],
        };
        let schedule = build_schedule(&activities).unwrap();
        let s = &schedule[0];
        assert_eq!(s.dst_port, 443);
        assert_eq!(s.offset, chrono::Duration::try_minutes(2).unwrap());
        let attack = s.attack.as_ref().unwrap();
        assert_eq!(attack.technique, "T1595");
        assert_eq!(attack.phase, Phase::Reconnaissance);
        assert_eq!(attack.tool, "nmap");
    }

    #[test]
    fn build_schedule_rejects_invalid_offset() {
        let activities = Activities {
            normal: vec![make_normal("bad", "xyz", 80)],
            attack: vec![],
        };
        assert!(build_schedule(&activities).is_err());
    }

    // ── activity_sources ──────────────────────────────────────────

    #[test]
    fn activity_sources_empty() {
        let activities = Activities {
            normal: vec![],
            attack: vec![],
        };
        assert!(activity_sources(&activities).is_empty());
    }

    #[test]
    fn activity_sources_collects_unique_sources() {
        let activities = Activities {
            normal: vec![make_normal("a", "10s", 80), make_normal("b", "20s", 80)],
            attack: vec![make_attack("c", "30s")],
        };
        let sources = activity_sources(&activities);
        // All three activities share source "src" (from make_normal/make_attack).
        assert_eq!(sources.len(), 1);
        assert!(sources.contains("src"));
    }

    #[test]
    fn activity_sources_includes_both_normal_and_attack() {
        let activities = Activities {
            normal: vec![NormalActivity {
                name: "n".to_owned(),
                source: "host-a".to_owned(),
                target: "host-b".to_owned(),
                command: "echo hi".to_owned(),
                protocol: Protocol::Tcp,
                dst_port: 80,
                start_offset: "10s".to_owned(),
            }],
            attack: vec![AttackActivity {
                name: "a".to_owned(),
                source: "host-c".to_owned(),
                target: "host-a".to_owned(),
                command: "nmap ${target_ip}".to_owned(),
                protocol: Protocol::Tcp,
                dst_port: 80,
                technique: "T1046".to_owned(),
                phase: Phase::Reconnaissance,
                tool: "nmap".to_owned(),
                start_offset: "20s".to_owned(),
                campaign_id: None,
                step: None,
            }],
        };
        let sources = activity_sources(&activities);
        assert_eq!(sources.len(), 2);
        assert!(sources.contains("host-a"));
        assert!(sources.contains("host-c"));
        // host-b is only a target, not a source.
        assert!(!sources.contains("host-b"));
    }

    // ── template substitution ─────────────────────────────────────

    #[test]
    fn template_substitution_replaces_target_ip() {
        let cmd = "curl -s http://${target_ip}:80/";
        let replaced = cmd.replace("${target_ip}", "10.100.0.3");
        assert_eq!(replaced, "curl -s http://10.100.0.3:80/");
    }

    #[test]
    fn template_without_placeholder_unchanged() {
        let cmd = "echo hello world";
        let replaced = cmd.replace("${target_ip}", "10.0.0.1");
        assert_eq!(replaced, "echo hello world");
    }

    #[test]
    fn template_multiple_occurrences_all_replaced() {
        let cmd = "ping ${target_ip} && curl ${target_ip}";
        let replaced = cmd.replace("${target_ip}", "10.0.0.5");
        assert_eq!(replaced, "ping 10.0.0.5 && curl 10.0.0.5");
    }

    // ── Docker E2E tests ──────────────────────────────────────────

    use crate::test_util::{isolate_subnets, load_ac0, load_mixed_distro};

    /// Provisions ac-0 containers, runs both activities immediately
    /// (using a past start time to skip offset waits), and verifies
    /// the execution results.
    #[tokio::test]
    #[ignore = "requires Docker daemon"]
    async fn exec_activities_in_ac0_containers() {
        let mut scenario = load_ac0();
        isolate_subnets(&mut scenario);
        let dir = tempfile::tempdir().unwrap();
        let net_dir = dir.path().join("net");
        std::fs::create_dir_all(&net_dir).unwrap();

        let env = crate::infra::ProvisionedEnv::up(&scenario, &net_dir)
            .await
            .unwrap();

        // Use a start time far in the past so all offsets are already
        // elapsed and activities run immediately.
        let before = Utc::now();
        let past_start = before - chrono::Duration::try_hours(1).unwrap();
        let results = run(
            &env.docker,
            &env.host_containers,
            &env.host_ips,
            &scenario.activities,
            past_start,
            &[],
        )
        .await
        .unwrap();
        let after = Utc::now();

        assert_eq!(results.len(), 2, "expected 1 normal + 1 attack execution");

        let seg = &scenario.infrastructure.network.segments[0];
        let (_, expected_ips) = crate::infra::assign_ips(&seg.subnet, &seg.hosts).unwrap();
        let expected_src = expected_ips[0].1;
        let expected_dst = expected_ips[1].1;

        // Find results by type (concurrent execution means order by
        // start time is non-deterministic when offsets already elapsed).
        let normal = results
            .iter()
            .find(|e| e.attack.is_none())
            .expect("expected a normal execution");
        let attack = results
            .iter()
            .find(|e| e.attack.is_some())
            .expect("expected an attack execution");

        assert_eq!(normal.source, "attacker-001");
        assert_eq!(normal.target, "target-001");
        assert_eq!(normal.protocol, Protocol::Tcp);
        assert_eq!(normal.dst_port, 80);
        assert_eq!(normal.src_ip, expected_src);
        assert_eq!(normal.dst_ip, expected_dst);

        // Timestamps must be actual wall-clock times, not estimated.
        assert!(
            normal.start >= before,
            "start must be actual (after test began)"
        );
        assert!(normal.end >= normal.start, "end must be >= start");
        assert!(
            normal.end <= after,
            "end must be actual (before test ended)"
        );

        let detail = attack.attack.as_ref().unwrap();
        assert_eq!(detail.technique, "T1046");
        assert_eq!(detail.phase, Phase::Reconnaissance);
        assert_eq!(detail.tool, "nmap");
        assert_eq!(attack.src_ip, expected_src);
        assert_eq!(attack.dst_ip, expected_dst);

        assert!(
            attack.start >= before,
            "start must be actual (after test began)"
        );
        assert!(attack.end >= attack.start, "end must be >= start");
        assert!(
            attack.end <= after,
            "end must be actual (before test ended)"
        );

        // target-001 is never a source, so it should not have tools.
        let target_id = lookup_container(&env.host_containers, "target-001").unwrap();
        assert!(
            !has_tool(&env.docker, target_id, "nmap").await.unwrap(),
            "target-only host should not have nmap installed",
        );

        env.down().await.unwrap();
    }

    /// Runs the full activity + ground truth pipeline and verifies
    /// the JSONL output matches the v1 schema.
    #[tokio::test]
    #[ignore = "requires Docker daemon"]
    async fn activities_produce_valid_ground_truth() {
        let mut scenario = load_ac0();
        isolate_subnets(&mut scenario);
        let dir = tempfile::tempdir().unwrap();
        let net_dir = dir.path().join("net");
        let gt_dir = dir.path().join("ground_truth");
        std::fs::create_dir_all(&net_dir).unwrap();
        std::fs::create_dir_all(&gt_dir).unwrap();

        let env = crate::infra::ProvisionedEnv::up(&scenario, &net_dir)
            .await
            .unwrap();

        let before = Utc::now();
        let past_start = before - chrono::Duration::try_hours(1).unwrap();
        let mut results = run(
            &env.docker,
            &env.host_containers,
            &env.host_ips,
            &scenario.activities,
            past_start,
            &[],
        )
        .await
        .unwrap();

        // Stop collectors so pcap files are flushed to disk.
        env.stop_collectors().await.unwrap();

        crate::pcap::enrich_src_ports(&net_dir, &mut results).unwrap();
        crate::ground_truth::write(dir.path(), &results).unwrap();

        let seg = &scenario.infrastructure.network.segments[0];
        let (_, expected_ips) = crate::infra::assign_ips(&seg.subnet, &seg.hosts).unwrap();
        let attacker_ip = expected_ips[0].1.to_string();
        let target_ip = expected_ips[1].1.to_string();

        let content = std::fs::read_to_string(gt_dir.join("manifest.jsonl")).unwrap();
        let records: Vec<serde_json::Value> = content
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(records.len(), 2);

        // Find records by label (concurrent execution means start-time
        // order is non-deterministic when offsets already elapsed).
        let normal = records
            .iter()
            .find(|r| r["label"] == "normal")
            .expect("expected a normal record");
        let anomaly = records
            .iter()
            .find(|r| r["label"] == "anomaly")
            .expect("expected an anomaly record");

        // Verify normal record.
        assert_eq!(normal["scope"], "session");
        assert_eq!(normal["session_type"], "network");
        assert_eq!(normal["protocol"], "tcp");
        assert_eq!(normal["src_ip"], attacker_ip);
        assert!(normal["src_port"].is_number(), "src_port must be present");
        assert_eq!(normal["dst_ip"], target_ip);
        assert_eq!(normal["dst_port"], 80);
        assert!(normal.get("category").is_none());
        assert!(normal.get("technique").is_none());

        // Timestamps are actual wall-clock times, not offset-derived.
        let start_str = normal["start"].as_str().unwrap();
        let start_ts = chrono::DateTime::parse_from_rfc3339(start_str).unwrap();
        assert!(
            start_ts >= before,
            "normal start {start_str} is before test began",
        );

        // Verify anomaly record.
        assert_eq!(anomaly["scope"], "session");
        assert_eq!(anomaly["category"], "attack");
        assert_eq!(anomaly["technique"], "T1046");
        assert_eq!(anomaly["phase"], "reconnaissance");
        assert_eq!(anomaly["tool"], "nmap");
        assert_eq!(anomaly["src_ip"], attacker_ip);
        assert!(
            anomaly["src_port"].is_number(),
            "attack src_port must be present"
        );
        assert_eq!(anomaly["dst_ip"], target_ip);

        env.down().await.unwrap();
    }

    // ── Mixed-distro E2E tests ───────────────────────────────────

    /// Alpine + Ubuntu hosts on the same segment complete without error.
    /// The attacker (Alpine) is the only activity source and must receive
    /// tools via `apk add`; the Ubuntu hosts (target + observer) must
    /// NOT be touched by tool installation.
    #[tokio::test]
    #[ignore = "requires Docker daemon"]
    async fn mixed_distro_installs_tools_only_in_source() {
        let mut scenario = load_mixed_distro();
        isolate_subnets(&mut scenario);
        let dir = tempfile::tempdir().unwrap();
        let net_dir = dir.path().join("net");
        std::fs::create_dir_all(&net_dir).unwrap();

        let env = crate::infra::ProvisionedEnv::up(&scenario, &net_dir)
            .await
            .unwrap();

        let past_start = Utc::now() - chrono::Duration::try_hours(1).unwrap();
        let results = run(
            &env.docker,
            &env.host_containers,
            &env.host_ips,
            &scenario.activities,
            past_start,
            &[],
        )
        .await
        .unwrap();

        assert_eq!(results.len(), 2, "expected 1 normal + 1 attack execution");
        assert!(
            results.iter().all(|e| e.source == "attacker-alpine"),
            "both activities should run from attacker-alpine",
        );

        // The Alpine attacker should now have curl and nmap.
        let attacker_id = lookup_container(&env.host_containers, "attacker-alpine").unwrap();
        assert!(has_tool(&env.docker, attacker_id, "curl").await.unwrap());
        assert!(has_tool(&env.docker, attacker_id, "nmap").await.unwrap());

        // Observer (Ubuntu) is never an activity source, so it should
        // NOT have curl or nmap installed.
        let observer_id = lookup_container(&env.host_containers, "observer-ubuntu").unwrap();
        assert!(
            !has_tool(&env.docker, observer_id, "curl").await.unwrap(),
            "observer should not have curl installed",
        );
        assert!(
            !has_tool(&env.docker, observer_id, "nmap").await.unwrap(),
            "observer should not have nmap installed",
        );

        env.down().await.unwrap();
    }

    /// When an Ubuntu host is an activity source, tools are installed
    /// via `apt-get` without errors.
    #[tokio::test]
    #[ignore = "requires Docker daemon"]
    async fn ubuntu_source_installs_tools_via_apt() {
        let mut scenario = load_mixed_distro();
        isolate_subnets(&mut scenario);

        // Swap source/target so that apt-get is exercised on Ubuntu.
        scenario.activities.normal[0].source = "target-ubuntu".to_owned();
        scenario.activities.normal[0].target = "attacker-alpine".to_owned();
        scenario.activities.attack[0].source = "target-ubuntu".to_owned();
        scenario.activities.attack[0].target = "attacker-alpine".to_owned();

        let dir = tempfile::tempdir().unwrap();
        let net_dir = dir.path().join("net");
        std::fs::create_dir_all(&net_dir).unwrap();

        let env = crate::infra::ProvisionedEnv::up(&scenario, &net_dir)
            .await
            .unwrap();

        let past_start = Utc::now() - chrono::Duration::try_hours(1).unwrap();
        let results = run(
            &env.docker,
            &env.host_containers,
            &env.host_ips,
            &scenario.activities,
            past_start,
            &[],
        )
        .await
        .unwrap();

        assert_eq!(results.len(), 2);

        // The Ubuntu source should now have curl and nmap.
        let ubuntu_id = lookup_container(&env.host_containers, "target-ubuntu").unwrap();
        assert!(has_tool(&env.docker, ubuntu_id, "curl").await.unwrap());
        assert!(has_tool(&env.docker, ubuntu_id, "nmap").await.unwrap());

        // The Alpine host was not a source, so tools were not installed.
        let alpine_id = lookup_container(&env.host_containers, "attacker-alpine").unwrap();
        assert!(
            !has_tool(&env.docker, alpine_id, "curl").await.unwrap(),
            "non-source Alpine host should not have curl",
        );

        env.down().await.unwrap();
    }

    /// Both Alpine and Ubuntu hosts are activity sources simultaneously.
    /// Verifies that `apk` and `apt-get` are both used in a single run
    /// and the observer (not a source) is left untouched.
    #[tokio::test]
    #[ignore = "requires Docker daemon"]
    async fn dual_distro_sources_install_tools_concurrently() {
        let mut scenario = load_mixed_distro();
        isolate_subnets(&mut scenario);

        // Make target-ubuntu also a source (in addition to attacker-alpine).
        scenario.activities.attack[0].source = "target-ubuntu".to_owned();
        scenario.activities.attack[0].target = "attacker-alpine".to_owned();

        let dir = tempfile::tempdir().unwrap();
        let net_dir = dir.path().join("net");
        std::fs::create_dir_all(&net_dir).unwrap();

        let env = crate::infra::ProvisionedEnv::up(&scenario, &net_dir)
            .await
            .unwrap();

        let past_start = Utc::now() - chrono::Duration::try_hours(1).unwrap();
        let results = run(
            &env.docker,
            &env.host_containers,
            &env.host_ips,
            &scenario.activities,
            past_start,
            &[],
        )
        .await
        .unwrap();

        assert_eq!(results.len(), 2);

        let normal = results.iter().find(|e| e.attack.is_none()).unwrap();
        let attack = results.iter().find(|e| e.attack.is_some()).unwrap();
        assert_eq!(normal.source, "attacker-alpine");
        assert_eq!(attack.source, "target-ubuntu");

        // Both sources should have tools.
        let alpine_id = lookup_container(&env.host_containers, "attacker-alpine").unwrap();
        assert!(has_tool(&env.docker, alpine_id, "curl").await.unwrap());
        assert!(has_tool(&env.docker, alpine_id, "nmap").await.unwrap());

        let ubuntu_id = lookup_container(&env.host_containers, "target-ubuntu").unwrap();
        assert!(has_tool(&env.docker, ubuntu_id, "curl").await.unwrap());
        assert!(has_tool(&env.docker, ubuntu_id, "nmap").await.unwrap());

        // Observer is still untouched.
        let observer_id = lookup_container(&env.host_containers, "observer-ubuntu").unwrap();
        assert!(
            !has_tool(&env.docker, observer_id, "nmap").await.unwrap(),
            "observer should not have nmap",
        );

        env.down().await.unwrap();
    }

    /// If tools are already present, `install_tools` skips the install step
    /// and succeeds immediately.
    #[tokio::test]
    #[ignore = "requires Docker daemon"]
    async fn pre_installed_tools_are_skipped() {
        let mut scenario = load_ac0();
        isolate_subnets(&mut scenario);
        let dir = tempfile::tempdir().unwrap();
        let net_dir = dir.path().join("net");
        std::fs::create_dir_all(&net_dir).unwrap();

        let env = crate::infra::ProvisionedEnv::up(&scenario, &net_dir)
            .await
            .unwrap();

        let sources = activity_sources(&scenario.activities);
        let source_containers: Vec<_> = env
            .host_containers
            .iter()
            .filter(|(name, _)| sources.contains(name.as_str()))
            .map(|(n, id)| (n.clone(), id.clone()))
            .collect();

        // First install.
        install_tools(&env.docker, &source_containers)
            .await
            .unwrap();

        // Verify tools are present.
        let id = lookup_container(&env.host_containers, "attacker-001").unwrap();
        assert!(has_tool(&env.docker, id, "curl").await.unwrap());
        assert!(has_tool(&env.docker, id, "nmap").await.unwrap());

        // Second install should skip (and not fail).
        install_tools(&env.docker, &source_containers)
            .await
            .unwrap();

        env.down().await.unwrap();
    }

    // ── Concurrency E2E tests ────────────────────────────────────

    /// Two activities with the same `start_offset` must begin within 1 second
    /// of each other, proving they are launched concurrently rather than
    /// sequentially.
    #[tokio::test]
    #[ignore = "requires Docker daemon"]
    async fn same_offset_activities_start_within_one_second() {
        let mut scenario = load_ac0();
        isolate_subnets(&mut scenario);

        // Give both activities the same offset so they should start
        // at the same time.
        scenario.activities.normal[0].start_offset = "10s".to_owned();
        scenario.activities.attack[0].start_offset = "10s".to_owned();

        let dir = tempfile::tempdir().unwrap();
        let net_dir = dir.path().join("net");
        std::fs::create_dir_all(&net_dir).unwrap();

        let env = crate::infra::ProvisionedEnv::up(&scenario, &net_dir)
            .await
            .unwrap();

        // Use a past start so the shared offset is already elapsed.
        let past_start = Utc::now() - chrono::Duration::try_hours(1).unwrap();
        let results = run(
            &env.docker,
            &env.host_containers,
            &env.host_ips,
            &scenario.activities,
            past_start,
            &[],
        )
        .await
        .unwrap();

        assert_eq!(results.len(), 2);

        let gap = (results[1].start - results[0].start).abs();
        assert!(
            gap < chrono::Duration::try_seconds(1).unwrap(),
            "same-offset activities should start within 1s, but gap was {gap}",
        );

        env.down().await.unwrap();
    }

    /// Full pipeline (run → pcap enrichment → ground truth) with
    /// same-offset activities that execute concurrently.  Verifies
    /// that pcap matching and ground-truth recording produce correct
    /// output even when execution time windows overlap.
    #[tokio::test]
    #[ignore = "requires Docker daemon"]
    async fn concurrent_activities_produce_valid_ground_truth() {
        let mut scenario = load_ac0();
        isolate_subnets(&mut scenario);

        // Same offset so both activities run concurrently.
        scenario.activities.normal[0].start_offset = "10s".to_owned();
        scenario.activities.attack[0].start_offset = "10s".to_owned();

        let dir = tempfile::tempdir().unwrap();
        let net_dir = dir.path().join("net");
        let gt_dir = dir.path().join("ground_truth");
        std::fs::create_dir_all(&net_dir).unwrap();
        std::fs::create_dir_all(&gt_dir).unwrap();

        let env = crate::infra::ProvisionedEnv::up(&scenario, &net_dir)
            .await
            .unwrap();

        let before = Utc::now();
        let past_start = before - chrono::Duration::try_hours(1).unwrap();
        let mut results = run(
            &env.docker,
            &env.host_containers,
            &env.host_ips,
            &scenario.activities,
            past_start,
            &[],
        )
        .await
        .unwrap();

        assert_eq!(results.len(), 2);

        // Stop collectors so pcap files are flushed to disk.
        env.stop_collectors().await.unwrap();

        crate::pcap::enrich_src_ports(&net_dir, &mut results).unwrap();

        // Successful executions must have distinct, non-zero src_ports
        // even though they share the same src_ip, dst_ip, and dst_port.
        // Failed commands (e.g. curl exit-code 7) are skipped during
        // pcap enrichment, so their src_port stays 0.
        let normal = results.iter().find(|e| e.attack.is_none()).unwrap();
        let attack = results.iter().find(|e| e.attack.is_some()).unwrap();
        if normal.exit_code == 0 {
            assert_ne!(normal.src_port, 0, "normal src_port must be enriched");
        }
        if attack.exit_code == 0 {
            assert_ne!(attack.src_port, 0, "attack src_port must be enriched");
        }

        crate::ground_truth::write(dir.path(), &results).unwrap();

        let content = std::fs::read_to_string(gt_dir.join("manifest.jsonl")).unwrap();
        let records: Vec<serde_json::Value> = content
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(records.len(), 2);

        let gt_normal = records
            .iter()
            .find(|r| r["label"] == "normal")
            .expect("expected a normal record");
        let gt_anomaly = records
            .iter()
            .find(|r| r["label"] == "anomaly")
            .expect("expected an anomaly record");

        // Normal record fields.
        assert_eq!(gt_normal["scope"], "session");
        assert_eq!(gt_normal["protocol"], "tcp");
        assert!(gt_normal["src_port"].is_number());
        assert_eq!(gt_normal["dst_port"], 80);
        assert!(gt_normal.get("technique").is_none());

        // Anomaly record fields.
        assert_eq!(gt_anomaly["scope"], "session");
        assert_eq!(gt_anomaly["label"], "anomaly");
        assert_eq!(gt_anomaly["technique"], "T1046");
        assert!(gt_anomaly["src_port"].is_number());

        env.down().await.unwrap();
    }

    /// A long-running activity must not delay a later-offset activity.
    /// Activity A sleeps 4 seconds at offset 0; activity B runs at
    /// offset 2s.  With sequential execution, B would start at ≥4s;
    /// with concurrent execution, B should start near 2s.
    #[tokio::test]
    #[ignore = "requires Docker daemon"]
    async fn long_activity_does_not_delay_later_offset() {
        let mut scenario = load_ac0();
        isolate_subnets(&mut scenario);

        // Activity A: slow command at offset 0.
        scenario.activities.normal[0].command = "sleep 10".to_owned();
        scenario.activities.normal[0].start_offset = "0s".to_owned();

        // Activity B: fast command at offset 2s.
        scenario.activities.attack[0].command = "echo done".to_owned();
        scenario.activities.attack[0].start_offset = "2s".to_owned();

        let dir = tempfile::tempdir().unwrap();
        let net_dir = dir.path().join("net");
        std::fs::create_dir_all(&net_dir).unwrap();

        let env = crate::infra::ProvisionedEnv::up(&scenario, &net_dir)
            .await
            .unwrap();

        let start = Utc::now();
        let results = run(
            &env.docker,
            &env.host_containers,
            &env.host_ips,
            &scenario.activities,
            start,
            &[],
        )
        .await
        .unwrap();

        assert_eq!(results.len(), 2);

        // Find activity B (the "echo done" one that starts at offset 2s).
        let b = results
            .iter()
            .find(|e| e.attack.is_some())
            .expect("attack activity should be present");

        // B should start well before the slow activity A finishes (~10s).
        // We allow up to 8s to accommodate CI Docker overhead on the 2s
        // offset while still proving B did not wait for A.
        let b_delay = b.start - start;
        assert!(
            b_delay < chrono::Duration::try_seconds(8).unwrap(),
            "activity B should start before the slow activity A finishes, \
             but it started {b_delay} after generation start",
        );

        // Activity A (sleep 10) should take at least 8s.
        let a = results
            .iter()
            .find(|e| e.attack.is_none())
            .expect("normal activity should be present");
        let a_duration = a.end - a.start;
        assert!(
            a_duration >= chrono::Duration::try_seconds(8).unwrap(),
            "slow activity should have taken ≥8s, but took {a_duration}",
        );

        // B should have started before A finished (concurrent proof).
        assert!(
            b.start < a.end,
            "activity B should start before activity A finishes",
        );

        env.down().await.unwrap();
    }
}
