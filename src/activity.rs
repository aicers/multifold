use std::net::Ipv4Addr;

use anyhow::{Context, Result};
use bollard::Docker;
use bollard::exec::CreateExecOptions;
use chrono::{DateTime, Utc};
use futures_util::StreamExt;

use crate::scenario::{Activities, Phase, Protocol, parse_duration};

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
    pub(crate) dst_ip: Ipv4Addr,
    pub(crate) dst_port: u16,
    pub(crate) attack: Option<AttackDetail>,
}

pub(crate) struct AttackDetail {
    pub(crate) technique: String,
    pub(crate) phase: Phase,
    pub(crate) tool: String,
}

/// A unified, schedule-ordered activity ready for execution.
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
}

/// Executes all activities in schedule order and returns execution results.
///
/// Activities are sorted by `start_offset` and each command is executed
/// inside the source host's container via Docker exec. Tool packages
/// (curl, nmap) are installed before the first activity runs.
pub(crate) async fn run(
    docker: &Docker,
    host_containers: &[(String, String)],
    host_ips: &[(String, Vec<Ipv4Addr>)],
    activities: &Activities,
    generation_start: DateTime<Utc>,
) -> Result<Vec<Execution>> {
    install_tools(docker, host_containers).await?;

    let mut schedule = build_schedule(activities)?;
    schedule.sort_unstable_by_key(|s| s.offset);

    let mut results = Vec::with_capacity(schedule.len());

    for activity in &schedule {
        wait_until(generation_start + activity.offset).await;

        let src_ip = lookup_ip(host_ips, activity.source)?;
        let dst_ip = lookup_ip(host_ips, activity.target)?;
        let command = activity
            .command
            .replace("${target_ip}", &dst_ip.to_string());
        let container_id = lookup_container(host_containers, activity.source)?;

        println!("  Executing: {command}");
        let start = Utc::now();
        let code = exec_in_container(docker, container_id, &command)
            .await
            .with_context(|| format!("activity exec failed in '{}'", activity.source))?;
        let end = Utc::now();

        // Non-zero is expected for some activities (e.g. curl against a
        // host with no web server), so we warn rather than fail.
        if code != 0 {
            eprintln!("  Warning: command exited with code {code}: {command}");
        }

        results.push(Execution {
            start,
            end,
            source: activity.source.to_owned(),
            target: activity.target.to_owned(),
            protocol: activity.protocol,
            src_ip,
            dst_ip,
            dst_port: activity.dst_port,
            attack: activity.attack.as_ref().map(|a| AttackDetail {
                technique: a.technique.to_owned(),
                phase: a.phase,
                tool: a.tool.to_owned(),
            }),
        });
    }

    // Brief pause so trailing packets are captured by tcpdump.
    tokio::time::sleep(std::time::Duration::from_secs(CAPTURE_DRAIN_SECS)).await;

    Ok(results)
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

async fn install_tools(docker: &Docker, host_containers: &[(String, String)]) -> Result<()> {
    for (host, container_id) in host_containers {
        println!("  Installing tools in {host}…");
        let code = exec_in_container(
            docker,
            container_id,
            "apk add --no-cache curl nmap >/dev/null 2>&1",
        )
        .await
        .with_context(|| format!("failed to install tools in '{host}'"))?;
        anyhow::ensure!(
            code == 0,
            "tool installation failed in '{host}' (exit code {code})",
        );
    }
    Ok(())
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
        assert!(err.to_string().contains("no IP found"), "unexpected: {err}",);
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

    fn load_ac0() -> crate::scenario::Scenario {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("scenarios")
            .join("ac-0.scenario.yaml");
        crate::scenario::load(&path).unwrap()
    }

    /// Provisions ac-0 containers, runs both activities immediately
    /// (using a past start time to skip offset waits), and verifies
    /// the execution results.
    #[tokio::test]
    #[ignore = "requires Docker daemon"]
    async fn exec_activities_in_ac0_containers() {
        let scenario = load_ac0();
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
        )
        .await
        .unwrap();
        let after = Utc::now();

        assert_eq!(results.len(), 2, "expected 1 normal + 1 attack execution");

        // First result (normal — lower offset 30s).
        let normal = &results[0];
        assert!(normal.attack.is_none());
        assert_eq!(normal.source, "attacker-001");
        assert_eq!(normal.target, "target-001");
        assert_eq!(normal.protocol, Protocol::Tcp);
        assert_eq!(normal.dst_port, 80);
        assert_eq!(normal.src_ip, Ipv4Addr::new(10, 100, 0, 2));
        assert_eq!(normal.dst_ip, Ipv4Addr::new(10, 100, 0, 3));

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

        // Second result (attack — higher offset 120s).
        let attack = &results[1];
        let detail = attack.attack.as_ref().expect("should be an attack");
        assert_eq!(detail.technique, "T1046");
        assert_eq!(detail.phase, Phase::Reconnaissance);
        assert_eq!(detail.tool, "nmap");
        assert_eq!(attack.src_ip, Ipv4Addr::new(10, 100, 0, 2));
        assert_eq!(attack.dst_ip, Ipv4Addr::new(10, 100, 0, 3));

        assert!(
            attack.start >= before,
            "start must be actual (after test began)"
        );
        assert!(attack.end >= attack.start, "end must be >= start");
        assert!(
            attack.end <= after,
            "end must be actual (before test ended)"
        );

        // Normal must have run before attack (schedule order).
        assert!(
            normal.end <= attack.start,
            "normal should complete before attack starts",
        );

        env.down().await.unwrap();
    }

    /// Runs the full activity + ground truth pipeline and verifies
    /// the JSONL output matches the v1 schema.
    #[tokio::test]
    #[ignore = "requires Docker daemon"]
    async fn activities_produce_valid_ground_truth() {
        let scenario = load_ac0();
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
        let results = run(
            &env.docker,
            &env.host_containers,
            &env.host_ips,
            &scenario.activities,
            past_start,
        )
        .await
        .unwrap();

        crate::ground_truth::write(dir.path(), &results).unwrap();

        let content = std::fs::read_to_string(gt_dir.join("manifest.jsonl")).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 2);

        // Verify normal record.
        let r0: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(r0["scope"], "session");
        assert_eq!(r0["label"], "normal");
        assert_eq!(r0["session_type"], "network");
        assert_eq!(r0["protocol"], "tcp");
        assert_eq!(r0["src_ip"], "10.100.0.2");
        assert_eq!(r0["dst_ip"], "10.100.0.3");
        assert_eq!(r0["dst_port"], 80);
        assert!(r0.get("category").is_none());
        assert!(r0.get("technique").is_none());

        // Timestamps are actual wall-clock times, not offset-derived.
        let start_str = r0["start"].as_str().unwrap();
        let start_ts = chrono::DateTime::parse_from_rfc3339(start_str).unwrap();
        assert!(
            start_ts >= before,
            "normal start {start_str} is before test began",
        );

        // Verify anomaly record.
        let r1: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(r1["scope"], "session");
        assert_eq!(r1["label"], "anomaly");
        assert_eq!(r1["category"], "attack");
        assert_eq!(r1["technique"], "T1046");
        assert_eq!(r1["phase"], "reconnaissance");
        assert_eq!(r1["tool"], "nmap");
        assert_eq!(r1["src_ip"], "10.100.0.2");
        assert_eq!(r1["dst_ip"], "10.100.0.3");

        let attack_start_str = r1["start"].as_str().unwrap();
        let attack_start_ts = chrono::DateTime::parse_from_rfc3339(attack_start_str).unwrap();
        assert!(
            attack_start_ts >= start_ts,
            "attack should start after normal",
        );

        env.down().await.unwrap();
    }
}
