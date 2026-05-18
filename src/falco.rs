use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use bollard::Docker;
use bollard::exec::CreateExecOptions;
use bollard::models::ContainerStateStatusEnum;
use chrono::{DateTime, FixedOffset, Utc};
use futures_util::StreamExt;

use crate::time::{ExecAnchor, RewriteDiagnostics, TimeMap, logical_window, rewrite_ts};

/// JSON key for the Falco event timestamp.
const TIME_KEY: &str = "time";
/// Format string for Falco's nanosecond-with-numeric-offset form.
/// `%z` emits the offset without a colon (`+0000`), matching Falco's
/// Go default output and the validator fixtures.
const NANOSEC_FMT: &str = "%Y-%m-%dT%H:%M:%S%.9f%z";
/// Format string for Falco's `Z` (UTC, second-precision) form.
const Z_FMT: &str = "%Y-%m-%dT%H:%M:%SZ";

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

/// Rewrites the `time` field of every record in a Falco JSONL file
/// onto the logical timeline. Returns the max rewritten timestamp
/// (or `None` when no record was rewritten) and a diagnostic counter
/// the call site renders into a per-file warning line.
///
/// Malformed lines, records missing the `time` field, and unparseable
/// timestamp values pass through unchanged with their respective
/// counters incremented. Records whose rewritten timestamp lands
/// outside the scenario's logical window are kept and counted via
/// `out_of_window`. Both observed wire formats round-trip byte-for-byte
/// (nanosecond + `+HHMM` offset, and second-precision `Z`).
pub(crate) fn rewrite_timestamps(
    path: &Path,
    time_map: &TimeMap,
    anchors: &[ExecAnchor],
) -> Result<(Option<DateTime<Utc>>, RewriteDiagnostics)> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read {}", path.display()))?;
    let (start, end) = logical_window(time_map)?;

    let mut diag = RewriteDiagnostics::default();
    let mut max_ts: Option<DateTime<Utc>> = None;
    let mut output = String::with_capacity(content.len());

    for raw_line in content.split_inclusive('\n') {
        let (body, eol) = split_eol(raw_line);
        if body.is_empty() {
            output.push_str(raw_line);
            continue;
        }

        let new_body = match rewrite_falco_line(
            body,
            time_map,
            anchors,
            &mut diag,
            &mut max_ts,
            start,
            end,
        )? {
            Some(s) => s,
            None => body.to_owned(),
        };
        output.push_str(&new_body);
        output.push_str(eol);
    }

    std::fs::write(path, &output).with_context(|| format!("failed to write {}", path.display()))?;
    Ok((max_ts, diag))
}

fn split_eol(raw: &str) -> (&str, &str) {
    raw.strip_suffix('\n')
        .map_or((raw, ""), |body| (body, "\n"))
}

/// Rewrites a single Falco JSONL line. Returns `Some(new_body)` when
/// the timestamp was successfully rewritten, `None` when the line was
/// passed through (with the appropriate counter incremented).
fn rewrite_falco_line(
    body: &str,
    time_map: &TimeMap,
    anchors: &[ExecAnchor],
    diag: &mut RewriteDiagnostics,
    max_ts: &mut Option<DateTime<Utc>>,
    window_start: DateTime<Utc>,
    window_end: DateTime<Utc>,
) -> Result<Option<String>> {
    let Ok(parsed) = serde_json::from_str::<serde_json::Value>(body) else {
        diag.malformed_lines += 1;
        return Ok(None);
    };
    if !parsed.is_object() {
        diag.malformed_lines += 1;
        return Ok(None);
    }
    let Some(time_value) = parsed.get(TIME_KEY) else {
        diag.missing_field += 1;
        return Ok(None);
    };
    let Some(time_str) = time_value.as_str() else {
        diag.unparseable_ts += 1;
        return Ok(None);
    };
    let Some((real_ts, style, offset)) = parse_falco_time(time_str) else {
        diag.unparseable_ts += 1;
        return Ok(None);
    };

    let rewritten = rewrite_ts(real_ts, time_map, anchors)?;
    let new_value = format_falco_time(rewritten, style, offset);
    let Some(new_body) = substitute_field_value(body, TIME_KEY, &new_value) else {
        // Field is present per the JSON parse but not locatable by
        // raw substring search — exotic whitespace inside the line.
        // Treat as malformed and leave the line byte-identical rather
        // than emitting an incorrect rewrite.
        diag.malformed_lines += 1;
        return Ok(None);
    };

    if rewritten < window_start || rewritten > window_end {
        diag.out_of_window += 1;
    }
    if max_ts.is_none_or(|m| rewritten > m) {
        *max_ts = Some(rewritten);
    }
    Ok(Some(new_body))
}

#[derive(Clone, Copy)]
enum FalcoStyle {
    /// `2026-01-15T09:01:00.000000000+0000` (nanosecond, numeric offset
    /// without a colon).
    NanoOffsetNoColon,
    /// `2026-01-15T09:01:00Z` (second precision, UTC).
    ZSeconds,
}

fn parse_falco_time(s: &str) -> Option<(DateTime<Utc>, FalcoStyle, FixedOffset)> {
    if s.ends_with('Z')
        && let Ok(dt) = DateTime::parse_from_rfc3339(s)
    {
        return Some((dt.with_timezone(&Utc), FalcoStyle::ZSeconds, *dt.offset()));
    }
    if let Ok(dt) = DateTime::parse_from_str(s, NANOSEC_FMT) {
        return Some((
            dt.with_timezone(&Utc),
            FalcoStyle::NanoOffsetNoColon,
            *dt.offset(),
        ));
    }
    None
}

fn format_falco_time(utc: DateTime<Utc>, style: FalcoStyle, offset: FixedOffset) -> String {
    match style {
        FalcoStyle::ZSeconds => utc.format(Z_FMT).to_string(),
        FalcoStyle::NanoOffsetNoColon => utc.with_timezone(&offset).format(NANOSEC_FMT).to_string(),
    }
}

/// Replaces the string value of `field` in a compact JSON line with
/// `new_value`, byte-for-byte, leaving every other byte intact.
///
/// Searches for the literal `"<field>":"`, then scans forward to the
/// next unescaped `"` (respecting backslash escapes so wire-form
/// `\/Date(…)\/` survives intact in Sysmon). Returns `None` when the
/// pattern is not present.
pub(super) fn substitute_field_value(raw: &str, field: &str, new_value: &str) -> Option<String> {
    let needle = format!("\"{field}\":\"");
    let key_pos = raw.find(&needle)?;
    let value_start = key_pos + needle.len();

    let bytes = raw.as_bytes();
    let mut end = value_start;
    while end < bytes.len() {
        match bytes.get(end)? {
            b'\\' if end + 1 < bytes.len() => end += 2,
            b'"' => break,
            _ => end += 1,
        }
    }
    if end >= bytes.len() {
        return None;
    }

    let mut out = String::with_capacity(raw.len() + new_value.len());
    out.push_str(&raw[..value_start]);
    out.push_str(new_value);
    out.push_str(&raw[end..]);
    Some(out)
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
        bail!("command exited with code {exit_code}: {command}\nstderr: {err_msg}");
    }

    Ok(stdout)
}

#[cfg(test)]
mod tests {
    use chrono::{Duration, TimeZone};

    use super::*;
    use crate::activity::Execution;
    use crate::scenario::Protocol;
    use crate::time::build_anchors;

    // ── helpers ───────────────────────────────────────────────────

    const FALCO_NS: &str = r#"{"time":"2026-01-15T09:01:00.000000000+0000","rule":"r","priority":"Notice","output":"x"}"#;
    const FALCO_Z: &str = r#"{"time":"2026-01-15T09:01:00Z","rule":"r","priority":"Notice"}"#;

    fn identity_map() -> TimeMap {
        let t = Utc.with_ymd_and_hms(2026, 1, 15, 9, 0, 0).unwrap();
        let dur = Duration::try_minutes(5).unwrap();
        TimeMap::new(t, t, dur, dur).unwrap()
    }

    fn write_lines(dir: &Path, lines: &[&str]) -> PathBuf {
        let p = dir.join("falco.jsonl");
        let mut content = String::new();
        for l in lines {
            content.push_str(l);
            content.push('\n');
        }
        std::fs::write(&p, content).unwrap();
        p
    }

    fn make_exec(start: DateTime<Utc>, end: DateTime<Utc>) -> Execution {
        Execution {
            start,
            end,
            source: "a".into(),
            target: "b".into(),
            protocol: Protocol::Tcp,
            src_ip: std::net::Ipv4Addr::new(10, 0, 0, 2),
            src_port: 0,
            dst_ip: std::net::Ipv4Addr::new(10, 0, 0, 3),
            dst_port: 80,
            attack: None,
            exit_code: 0,
            command: String::new(),
        }
    }

    // ── round-trip under identity ─────────────────────────────────

    #[test]
    fn identity_preserves_nanosecond_format_byte_for_byte() {
        let dir = tempfile::tempdir().unwrap();
        let p = write_lines(dir.path(), &[FALCO_NS]);
        let original = std::fs::read(&p).unwrap();
        let (max_ts, diag) = rewrite_timestamps(&p, &identity_map(), &[]).unwrap();
        assert!(diag.is_empty());
        assert!(max_ts.is_some());
        assert_eq!(std::fs::read(&p).unwrap(), original);
    }

    #[test]
    fn identity_preserves_nonzero_nanosecond_fraction_byte_for_byte() {
        // Real Falco emits full nanosecond precision; under identity
        // the rewrite must not truncate the sub-microsecond tail.
        let dir = tempfile::tempdir().unwrap();
        let line =
            r#"{"time":"2026-01-15T09:01:00.123456789+0000","rule":"r","priority":"Notice"}"#;
        let p = write_lines(dir.path(), &[line]);
        let original = std::fs::read(&p).unwrap();
        let (max_ts, diag) = rewrite_timestamps(&p, &identity_map(), &[]).unwrap();
        assert!(diag.is_empty());
        assert_eq!(
            max_ts.unwrap().timestamp_subsec_nanos(),
            123_456_789,
            "identity rewrite must preserve nanosecond precision",
        );
        assert_eq!(std::fs::read(&p).unwrap(), original);
    }

    #[test]
    fn identity_preserves_z_format_byte_for_byte() {
        let dir = tempfile::tempdir().unwrap();
        let p = write_lines(dir.path(), &[FALCO_Z]);
        let original = std::fs::read(&p).unwrap();
        let (max_ts, diag) = rewrite_timestamps(&p, &identity_map(), &[]).unwrap();
        assert!(diag.is_empty());
        assert!(max_ts.is_some());
        assert_eq!(std::fs::read(&p).unwrap(), original);
    }

    // ── anchor preservation ───────────────────────────────────────

    #[test]
    fn anchor_burst_preserves_intra_session_spacing() {
        // 30 real minutes → 14 logical days. Two Falco records inside
        // one execution window must keep their real 100 ms spacing
        // and land at the execution's logical_start.
        let real_start = Utc.with_ymd_and_hms(2026, 1, 15, 9, 0, 0).unwrap();
        let logical_start = Utc.with_ymd_and_hms(2026, 5, 1, 0, 0, 0).unwrap();
        let tm = TimeMap::new(
            logical_start,
            real_start,
            Duration::try_minutes(30).unwrap(),
            Duration::try_days(14).unwrap(),
        )
        .unwrap();
        let exec_start = real_start + Duration::try_seconds(10).unwrap();
        let exec_end = exec_start + Duration::try_seconds(1).unwrap();
        let (anchors, _) = build_anchors(&[make_exec(exec_start, exec_end)], &tm).unwrap();

        let line_a = format!(
            r#"{{"time":"{}","rule":"a"}}"#,
            exec_start.format(NANOSEC_FMT)
        );
        let burst_b = exec_start + Duration::milliseconds(100);
        let line_b = format!(r#"{{"time":"{}","rule":"b"}}"#, burst_b.format(NANOSEC_FMT));

        let dir = tempfile::tempdir().unwrap();
        let p = write_lines(dir.path(), &[&line_a, &line_b]);
        let (max_ts, diag) = rewrite_timestamps(&p, &tm, &anchors).unwrap();
        assert!(diag.is_empty());

        // Both records' rewritten times must be parseable; their delta
        // is 100 ms; first record lands exactly at the anchor's
        // `logical_start` (no scaling inside the window).
        let content = std::fs::read_to_string(&p).unwrap();
        let lines: Vec<_> = content.lines().collect();
        let ts_a: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        let ts_b: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
        let a = DateTime::parse_from_str(ts_a["time"].as_str().unwrap(), NANOSEC_FMT).unwrap();
        let b = DateTime::parse_from_str(ts_b["time"].as_str().unwrap(), NANOSEC_FMT).unwrap();
        assert_eq!(a.with_timezone(&Utc), anchors[0].logical_start);
        assert_eq!(b - a, Duration::milliseconds(100));
        assert_eq!(max_ts.unwrap(), b.with_timezone(&Utc));
        // Sanity: the anchor's logical_start is the global-map image
        // of `exec_start`, *not* the bare `logical_start` constant we
        // chose for the run — under compression, `exec_start`'s
        // 10-second offset from `real_start` is scaled.
        assert_ne!(anchors[0].logical_start, logical_start);
    }

    // ── out-of-window fallback uses TimeMap ───────────────────────

    #[test]
    fn record_outside_anchor_uses_global_time_map() {
        // No anchors → every record goes through the global map.
        let real_start = Utc.with_ymd_and_hms(2026, 1, 15, 9, 0, 0).unwrap();
        let logical_start = Utc.with_ymd_and_hms(2026, 5, 1, 0, 0, 0).unwrap();
        let tm = TimeMap::new(
            logical_start,
            real_start,
            Duration::try_minutes(30).unwrap(),
            Duration::try_days(14).unwrap(),
        )
        .unwrap();
        let real_mid = real_start + Duration::try_minutes(15).unwrap();
        let line = format!(r#"{{"time":"{}"}}"#, real_mid.format(NANOSEC_FMT));

        let dir = tempfile::tempdir().unwrap();
        let p = write_lines(dir.path(), &[&line]);
        let (max_ts, diag) = rewrite_timestamps(&p, &tm, &[]).unwrap();
        assert!(diag.is_empty());
        // 15 real minutes through a 30 m → 14 d compression = 7 logical days.
        assert_eq!(
            max_ts.unwrap(),
            logical_start + Duration::try_days(7).unwrap(),
        );
    }

    // ── edge cases ────────────────────────────────────────────────

    #[test]
    fn missing_time_field_passes_through_and_counts() {
        let dir = tempfile::tempdir().unwrap();
        let line = r#"{"rule":"r","output":"no timestamp here"}"#;
        let p = write_lines(dir.path(), &[line]);
        let original = std::fs::read(&p).unwrap();
        let (max_ts, diag) = rewrite_timestamps(&p, &identity_map(), &[]).unwrap();
        assert_eq!(diag.missing_field, 1);
        assert_eq!(diag.malformed_lines, 0);
        assert_eq!(diag.unparseable_ts, 0);
        assert!(max_ts.is_none());
        assert_eq!(std::fs::read(&p).unwrap(), original);
    }

    #[test]
    fn malformed_json_line_passes_through_and_counts() {
        let dir = tempfile::tempdir().unwrap();
        let line = r#"{"time":"2026-01-15T09:01:00Z","rule":"#;
        let p = write_lines(dir.path(), &[line]);
        let original = std::fs::read(&p).unwrap();
        let (max_ts, diag) = rewrite_timestamps(&p, &identity_map(), &[]).unwrap();
        assert_eq!(diag.malformed_lines, 1);
        assert!(max_ts.is_none());
        assert_eq!(std::fs::read(&p).unwrap(), original);
    }

    #[test]
    fn unparseable_timestamp_passes_through_and_counts() {
        let dir = tempfile::tempdir().unwrap();
        let line = r#"{"time":"not a timestamp","rule":"r"}"#;
        let p = write_lines(dir.path(), &[line]);
        let original = std::fs::read(&p).unwrap();
        let (max_ts, diag) = rewrite_timestamps(&p, &identity_map(), &[]).unwrap();
        assert_eq!(diag.unparseable_ts, 1);
        assert!(max_ts.is_none());
        assert_eq!(std::fs::read(&p).unwrap(), original);
    }

    #[test]
    fn out_of_window_timestamp_keeps_record_and_counts() {
        // Logical window is `start_at + 5m`; emit a record whose real
        // timestamp lands 10 logical minutes past it under identity
        // scale. The rewritten record is kept; only the counter is
        // incremented.
        let line = r#"{"time":"2026-01-15T09:10:00Z","rule":"r"}"#;
        let dir = tempfile::tempdir().unwrap();
        let p = write_lines(dir.path(), &[line]);
        let (max_ts, diag) = rewrite_timestamps(&p, &identity_map(), &[]).unwrap();
        assert_eq!(diag.out_of_window, 1);
        assert!(max_ts.is_some());
        // Record retained: the file still contains one line.
        let content = std::fs::read_to_string(&p).unwrap();
        assert_eq!(content.lines().count(), 1);
    }

    // ── aggregator contract ───────────────────────────────────────

    #[test]
    fn empty_file_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("falco.jsonl");
        std::fs::write(&p, "").unwrap();
        let (max_ts, diag) = rewrite_timestamps(&p, &identity_map(), &[]).unwrap();
        assert!(max_ts.is_none());
        assert!(diag.is_empty());
    }

    #[test]
    fn all_passthrough_lines_return_none() {
        let dir = tempfile::tempdir().unwrap();
        let p = write_lines(
            dir.path(),
            &[r#"{"rule":"missing-ts"}"#, r"not json at all"],
        );
        let (max_ts, diag) = rewrite_timestamps(&p, &identity_map(), &[]).unwrap();
        assert!(max_ts.is_none());
        assert_eq!(diag.missing_field, 1);
        assert_eq!(diag.malformed_lines, 1);
    }

    #[test]
    fn multi_record_returns_max_rewritten_ts() {
        let dir = tempfile::tempdir().unwrap();
        let p = write_lines(
            dir.path(),
            &[
                r#"{"time":"2026-01-15T09:01:00Z"}"#,
                r#"{"time":"2026-01-15T09:02:30Z"}"#,
                r#"{"time":"2026-01-15T09:02:00Z"}"#,
            ],
        );
        let (max_ts, _) = rewrite_timestamps(&p, &identity_map(), &[]).unwrap();
        assert_eq!(
            max_ts.unwrap(),
            Utc.with_ymd_and_hms(2026, 1, 15, 9, 2, 30).unwrap(),
        );
    }

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
