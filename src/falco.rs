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
    let (lookup, walker_total) = locate_field(body, TIME_KEY);
    // Cross-check the structural walker's depth-1 key count against
    // `serde_json`'s parsed Map size. They diverge precisely when one
    // or more source keys collide after JSON-escape decoding (e.g. a
    // literal `time` plus an escaped `time`); `serde_json` collapses
    // them via last-write-wins while the byte-exact walker sees them as
    // distinct keys. In that case the walker may have matched only the
    // literal spelling, leaving any escaped duplicate untouched and the
    // rewrite consistent with undefined-order semantics. The safe
    // behavior is to refuse the rewrite and classify the line as
    // malformed, matching the duplicate-key contract from #72.
    let serde_total = parsed.as_object().expect("object check above").len();
    if walker_total != serde_total {
        diag.malformed_lines += 1;
        return Ok(None);
    }
    let raw_value = match lookup {
        FieldLookup::String { start, end } => body
            .get(start..end)
            .expect("walker returns an in-bounds range"),
        FieldLookup::Absent => {
            // serde may have seen the key under a JSON-escaped spelling
            // (e.g. `"time"`), which the structural walker does
            // not decode. Stricter handling of escaped key spellings is
            // left to a future issue; the safe behavior here is to
            // leave the line byte-identical and count as malformed.
            if parsed.get(TIME_KEY).is_some() {
                diag.malformed_lines += 1;
            } else {
                diag.missing_field += 1;
            }
            return Ok(None);
        }
        FieldLookup::Duplicate => {
            // Duplicate top-level `time` keys: `serde_json`'s
            // last-write-wins is not a stable contract to lean on.
            // Detection happens here, before any type check, so the
            // classification cannot flip depending on which duplicate
            // survives the parse.
            diag.malformed_lines += 1;
            return Ok(None);
        }
        FieldLookup::NonString => {
            diag.unparseable_ts += 1;
            return Ok(None);
        }
    };
    let Some((real_ts, style, offset)) = parse_falco_time(raw_value) else {
        diag.unparseable_ts += 1;
        return Ok(None);
    };

    let rewritten = rewrite_ts(real_ts, time_map, anchors)?;
    let new_value = format_falco_time(rewritten, style, offset);
    let Some(new_body) = substitute_field_value(body, TIME_KEY, &new_value) else {
        // The walker said `String` above; if substitution fails here
        // something has changed under us. Leave the line byte-identical.
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

/// Classification of a depth-1 object-key lookup. The structural walker
/// distinguishes these four outcomes so each rewriter can map them to
/// the right diagnostic counter without relying on `serde_json`'s
/// last-write-wins behavior for duplicate keys.
pub(super) enum FieldLookup {
    /// Field not present as a depth-1 key (as seen by byte-level key
    /// comparison — JSON-escaped key spellings are intentionally not
    /// decoded; see `locate_field`).
    Absent,
    /// Field appears more than once at depth 1.
    Duplicate,
    /// Field present exactly once at depth 1, but its value is not a
    /// JSON string.
    NonString,
    /// Field present exactly once at depth 1 with a string value. The
    /// range covers the bytes *between* the surrounding quotes —
    /// neither quote is included.
    String { start: usize, end: usize },
}

/// Replaces the string value of the depth-1 object key `field` in a
/// JSON line with `new_value`, byte-for-byte. Every other byte of the
/// input — including insignificant whitespace and any unrelated keys —
/// is preserved exactly.
///
/// Internally consults `locate_field`; substitution only happens when
/// the lookup result is `FieldLookup::String`. Any other outcome
/// (`Absent`, `Duplicate`, `NonString`) returns `None`.
pub(super) fn substitute_field_value(raw: &str, field: &str, new_value: &str) -> Option<String> {
    let (FieldLookup::String { start, end }, _) = locate_field(raw, field) else {
        return None;
    };
    let mut out = String::with_capacity(raw.len() + new_value.len());
    out.push_str(raw.get(..start)?);
    out.push_str(new_value);
    out.push_str(raw.get(end..)?);
    Some(out)
}

/// Classifies a depth-1 object-key lookup of `field` in `raw`, along
/// with the total number of depth-1 object members the walker
/// iterated over.
///
/// Uses a structural walker (not raw substring search) so:
///   - JSON-permitted whitespace around `:` or around the string value
///     (e.g. `"time" : "..."`) does not defeat the locator,
///   - a `"<field>":"..."` substring embedded inside *another* field's
///     string value is not mistaken for the real top-level key,
///   - backslash escapes are respected so wire-form `\/Date(...)\/`
///     survives intact in Sysmon,
///   - duplicate top-level occurrences of `field` are reported via
///     `FieldLookup::Duplicate` rather than silently picking one
///     occurrence the way `serde_json`'s last-write-wins would.
///
/// Key comparison is byte-exact: JSON-escaped key spellings (e.g.
/// `"time"` for `time`) are not decoded and therefore do not
/// match a literal `time` field. A stricter contract that decodes
/// escape sequences in key strings is left to a future issue.
///
/// The returned key count enables callers to detect escape-equivalent
/// duplicates that the byte-exact walker cannot see directly: comparing
/// against `serde_json::Map::len()` flags collisions that `serde_json`
/// merges via last-write-wins. The count is the number of completed
/// key-value iterations; if the walker bails out mid-iteration on a
/// structural error it is a partial count (the caller has already
/// validated the JSON via `serde_json::from_str`, so this is only a
/// soundness floor, not a contract).
pub(super) fn locate_field(raw: &str, field: &str) -> (FieldLookup, usize) {
    let bytes = raw.as_bytes();
    let field_bytes = field.as_bytes();
    let mut i = skip_ws(bytes, 0);
    if bytes.get(i).copied() != Some(b'{') {
        return (FieldLookup::Absent, 0);
    }
    i += 1;
    i = skip_ws(bytes, i);
    if bytes.get(i).copied() == Some(b'}') {
        return (FieldLookup::Absent, 0);
    }

    let mut result = FieldLookup::Absent;
    let mut total: usize = 0;

    loop {
        if bytes.get(i).copied() != Some(b'"') {
            return (FieldLookup::Absent, total);
        }
        let key_start = i + 1;
        let Some(key_end) = scan_string_end(bytes, key_start) else {
            return (FieldLookup::Absent, total);
        };
        let key_matches = bytes.get(key_start..key_end) == Some(field_bytes);
        i = key_end + 1;

        i = skip_ws(bytes, i);
        if bytes.get(i).copied() != Some(b':') {
            return (FieldLookup::Absent, total);
        }
        i += 1;
        i = skip_ws(bytes, i);

        let Some(value_byte) = bytes.get(i).copied() else {
            return (FieldLookup::Absent, total);
        };
        let (this_match, advance_to): (FieldLookup, usize) = if value_byte == b'"' {
            let val_start = i + 1;
            let Some(val_end) = scan_string_end(bytes, val_start) else {
                return (FieldLookup::Absent, total);
            };
            (
                FieldLookup::String {
                    start: val_start,
                    end: val_end,
                },
                val_end + 1,
            )
        } else {
            let Some(end) = skip_value(bytes, i) else {
                return (FieldLookup::Absent, total);
            };
            (FieldLookup::NonString, end)
        };

        total += 1;

        if key_matches {
            match result {
                FieldLookup::Absent => result = this_match,
                _ => return (FieldLookup::Duplicate, total),
            }
        }

        i = advance_to;
        i = skip_ws(bytes, i);
        match bytes.get(i).copied() {
            Some(b',') => {
                i += 1;
                i = skip_ws(bytes, i);
            }
            Some(b'}') => return (result, total),
            _ => return (FieldLookup::Absent, total),
        }
    }
}

/// Advances past JSON insignificant whitespace (space, tab, CR, LF).
/// Non-ASCII whitespace is intentionally not skipped — JSON does not
/// recognize it as insignificant.
fn skip_ws(bytes: &[u8], mut i: usize) -> usize {
    while let Some(&c) = bytes.get(i) {
        match c {
            b' ' | b'\t' | b'\r' | b'\n' => i += 1,
            _ => break,
        }
    }
    i
}

/// Scans from `start` to the position of the closing `"` of a JSON
/// string, respecting backslash escapes. Returns the index of the
/// closing quote (not past it). Returns `None` on premature end.
fn scan_string_end(bytes: &[u8], start: usize) -> Option<usize> {
    let mut i = start;
    while let Some(&c) = bytes.get(i) {
        match c {
            b'\\' => {
                bytes.get(i + 1)?;
                i += 2;
            }
            b'"' => return Some(i),
            _ => i += 1,
        }
    }
    None
}

/// Skips over a JSON value starting at `i`, returning the index of the
/// byte one past the value. Handles strings, objects, arrays, and
/// primitive tokens (number / `true` / `false` / `null`). Nested
/// brace/bracket depth is tracked uniformly: well-formed JSON (which
/// the caller has already validated via `serde_json::from_str`)
/// guarantees that the next `}` or `]` at depth 1 closes the outer
/// container.
fn skip_value(bytes: &[u8], start: usize) -> Option<usize> {
    let mut i = start;
    match bytes.get(i).copied()? {
        b'"' => Some(scan_string_end(bytes, i + 1)? + 1),
        b'{' | b'[' => {
            let mut depth: usize = 1;
            i += 1;
            while depth > 0 {
                match bytes.get(i).copied()? {
                    b'"' => {
                        i = scan_string_end(bytes, i + 1)? + 1;
                    }
                    b'{' | b'[' => {
                        depth += 1;
                        i += 1;
                    }
                    b'}' | b']' => {
                        depth -= 1;
                        i += 1;
                    }
                    _ => i += 1,
                }
            }
            Some(i)
        }
        _ => {
            while let Some(&c) = bytes.get(i) {
                match c {
                    b',' | b'}' | b']' | b' ' | b'\t' | b'\r' | b'\n' => break,
                    _ => i += 1,
                }
            }
            Some(i)
        }
    }
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

    // ── #72: robustness contract ──────────────────────────────────

    #[test]
    fn whitespace_around_colon_and_value_round_trips_byte_for_byte() {
        // Valid JSON with insignificant whitespace around `:` and the
        // string value must be rewritten correctly under identity and
        // pass through byte-for-byte (no whitespace normalization, no
        // diagnostic counter incremented).
        let dir = tempfile::tempdir().unwrap();
        let line = r#"{"time" : "2026-01-15T09:01:00Z" , "rule":"r"}"#;
        let p = write_lines(dir.path(), &[line]);
        let original = std::fs::read(&p).unwrap();
        let (max_ts, diag) = rewrite_timestamps(&p, &identity_map(), &[]).unwrap();
        assert!(diag.is_empty());
        assert!(max_ts.is_some());
        assert_eq!(std::fs::read(&p).unwrap(), original);
    }

    #[test]
    fn embedded_time_substring_is_not_mistaken_for_real_key() {
        // A prior field's string value literally contains `\"time\":`
        // (i.e. the bytes `"time":` after JSON-unescaping). The
        // structural walker must skip over it and only rewrite the
        // real top-level `time`. The embedded substring must remain
        // byte-for-byte unchanged.
        let real_start = Utc.with_ymd_and_hms(2026, 1, 15, 9, 0, 0).unwrap();
        let logical_start = Utc.with_ymd_and_hms(2026, 5, 1, 0, 0, 0).unwrap();
        let tm = TimeMap::new(
            logical_start,
            real_start,
            Duration::try_minutes(30).unwrap(),
            Duration::try_days(14).unwrap(),
        )
        .unwrap();
        let line = r#"{"output":"x \"time\":\"fake\" y","time":"2026-01-15T09:01:00Z"}"#;
        let dir = tempfile::tempdir().unwrap();
        let p = write_lines(dir.path(), &[line]);
        let (_, diag) = rewrite_timestamps(&p, &tm, &[]).unwrap();
        assert!(diag.is_empty());
        let s = std::fs::read_to_string(&p).unwrap();
        // The embedded substring survives literally.
        assert!(
            s.contains(r#"\"time\":\"fake\""#),
            "embedded substring must survive byte-for-byte: {s}",
        );
        // The real `time` key was rewritten — its original value is
        // gone, replaced by the logical-start anchor under compression.
        assert!(
            !s.contains("2026-01-15T09:01:00Z"),
            "real top-level `time` should have been rewritten: {s}",
        );
    }

    #[test]
    fn non_string_time_value_counts_as_unparseable_ts() {
        // `time` is present but its JSON value is a number, not a
        // string. The contract classifies this as `unparseable_ts`,
        // matching Sysmon's identical classification of the same shape.
        let dir = tempfile::tempdir().unwrap();
        let line = r#"{"time":12345,"rule":"r"}"#;
        let p = write_lines(dir.path(), &[line]);
        let original = std::fs::read(&p).unwrap();
        let (max_ts, diag) = rewrite_timestamps(&p, &identity_map(), &[]).unwrap();
        assert_eq!(diag.unparseable_ts, 1);
        assert_eq!(diag.missing_field, 0);
        assert_eq!(diag.malformed_lines, 0);
        assert!(max_ts.is_none());
        assert_eq!(std::fs::read(&p).unwrap(), original);
    }

    #[test]
    fn duplicate_time_keys_count_as_malformed_lines() {
        // Two `time` keys at depth 1, both strings. `serde_json`'s
        // last-write-wins masks the duplicate at the parsed-value
        // level, but the structural walker must detect it and the line
        // must be classified as `malformed_lines` per #72's safe
        // duplicate-key contract.
        let dir = tempfile::tempdir().unwrap();
        let line = r#"{"time":"2026-01-15T09:01:00Z","time":"2026-01-15T09:02:00Z"}"#;
        let p = write_lines(dir.path(), &[line]);
        let original = std::fs::read(&p).unwrap();
        let (max_ts, diag) = rewrite_timestamps(&p, &identity_map(), &[]).unwrap();
        assert_eq!(diag.malformed_lines, 1);
        assert_eq!(diag.unparseable_ts, 0);
        assert_eq!(diag.missing_field, 0);
        assert!(max_ts.is_none());
        assert_eq!(std::fs::read(&p).unwrap(), original);
    }

    #[test]
    fn duplicate_time_keys_string_then_non_string_count_as_malformed() {
        // First `time` is a string, second is a number. `serde_json`
        // last-write-wins surfaces the number, which without duplicate
        // detection would mis-classify as `unparseable_ts`. The walker
        // must catch the duplicate first.
        let dir = tempfile::tempdir().unwrap();
        let line = r#"{"time":"2026-01-15T09:01:00Z","time":12345}"#;
        let p = write_lines(dir.path(), &[line]);
        let original = std::fs::read(&p).unwrap();
        let (max_ts, diag) = rewrite_timestamps(&p, &identity_map(), &[]).unwrap();
        assert_eq!(diag.malformed_lines, 1);
        assert_eq!(diag.unparseable_ts, 0);
        assert_eq!(diag.missing_field, 0);
        assert!(max_ts.is_none());
        assert_eq!(std::fs::read(&p).unwrap(), original);
    }

    #[test]
    fn duplicate_time_keys_non_string_then_string_count_as_malformed() {
        // First `time` is a number, second is a string. `serde_json`
        // last-write-wins surfaces the string; the walker must still
        // detect the duplicate and classify as `malformed_lines`.
        let dir = tempfile::tempdir().unwrap();
        let line = r#"{"time":12345,"time":"2026-01-15T09:01:00Z"}"#;
        let p = write_lines(dir.path(), &[line]);
        let original = std::fs::read(&p).unwrap();
        let (max_ts, diag) = rewrite_timestamps(&p, &identity_map(), &[]).unwrap();
        assert_eq!(diag.malformed_lines, 1);
        assert_eq!(diag.unparseable_ts, 0);
        assert_eq!(diag.missing_field, 0);
        assert!(max_ts.is_none());
        assert_eq!(std::fs::read(&p).unwrap(), original);
    }

    #[test]
    fn duplicate_time_keys_both_non_string_count_as_malformed() {
        // Both `time` values are numbers. Without duplicate detection
        // before the type check, this would mis-classify as
        // `unparseable_ts`.
        let dir = tempfile::tempdir().unwrap();
        let line = r#"{"time":12345,"time":67890}"#;
        let p = write_lines(dir.path(), &[line]);
        let original = std::fs::read(&p).unwrap();
        let (max_ts, diag) = rewrite_timestamps(&p, &identity_map(), &[]).unwrap();
        assert_eq!(diag.malformed_lines, 1);
        assert_eq!(diag.unparseable_ts, 0);
        assert!(max_ts.is_none());
        assert_eq!(std::fs::read(&p).unwrap(), original);
    }

    #[test]
    fn literal_then_escaped_time_key_counts_as_malformed() {
        // A literal `time` followed by an escape-equivalent
        // `time` (which decodes to `time`). `serde_json` merges
        // both into a single `time` entry via last-write-wins; the
        // byte-exact walker sees only the literal as a match. Without
        // the walker/serde key-count cross-check, the walker would
        // rewrite the literal occurrence, leaving the escaped duplicate
        // byte-identical, and the rewrite would be consistent with
        // undefined-order semantics. The safe behavior is to refuse
        // the rewrite and classify the line as `malformed_lines`.
        let dir = tempfile::tempdir().unwrap();
        let line = "{\"time\":\"2026-01-15T09:01:00Z\",\"\\u0074ime\":\"2026-01-15T09:02:00Z\"}";
        let p = write_lines(dir.path(), &[line]);
        let original = std::fs::read(&p).unwrap();
        let (max_ts, diag) = rewrite_timestamps(&p, &identity_map(), &[]).unwrap();
        assert_eq!(diag.malformed_lines, 1);
        assert_eq!(diag.unparseable_ts, 0);
        assert_eq!(diag.missing_field, 0);
        assert!(max_ts.is_none());
        assert_eq!(std::fs::read(&p).unwrap(), original);
    }

    #[test]
    fn escaped_then_literal_time_key_counts_as_malformed() {
        // Reverse order of `literal_then_escaped_time_key_counts_as_malformed`:
        // the escaped spelling appears first, the literal `time`
        // second. `serde_json` still merges both into a single `time`
        // entry. The walker sees the literal as a match and would
        // otherwise rewrite it; the cross-check must catch the
        // collision and refuse.
        let dir = tempfile::tempdir().unwrap();
        let line = "{\"\\u0074ime\":\"2026-01-15T09:02:00Z\",\"time\":\"2026-01-15T09:01:00Z\"}";
        let p = write_lines(dir.path(), &[line]);
        let original = std::fs::read(&p).unwrap();
        let (max_ts, diag) = rewrite_timestamps(&p, &identity_map(), &[]).unwrap();
        assert_eq!(diag.malformed_lines, 1);
        assert_eq!(diag.unparseable_ts, 0);
        assert_eq!(diag.missing_field, 0);
        assert!(max_ts.is_none());
        assert_eq!(std::fs::read(&p).unwrap(), original);
    }

    #[test]
    fn escaped_key_spelling_is_out_of_scope_and_counts_as_malformed() {
        // `"time"` decodes to `time` per JSON's escape rules but
        // the structural walker compares key bytes literally and does
        // not decode them. The robustness contract leaves stricter
        // escape-aware key handling to a future issue; the safe
        // behavior here is to pass the line through byte-for-byte and
        // count it as `malformed_lines`, never as a false rewrite of
        // a different key.
        let dir = tempfile::tempdir().unwrap();
        // The key on the wire is literally `time` (the bytes
        // `\`, `u`, `0`, `0`, `7`, `4`, `i`, `m`, `e`). JSON decodes
        // this to the string `time`, so `serde_json` sees the field;
        // the walker compares key bytes literally, so it does not.
        let line = "{\"\\u0074ime\":\"2026-01-15T09:01:00Z\",\"rule\":\"r\"}";
        let p = write_lines(dir.path(), &[line]);
        let original = std::fs::read(&p).unwrap();
        let (max_ts, diag) = rewrite_timestamps(&p, &identity_map(), &[]).unwrap();
        assert_eq!(diag.malformed_lines, 1);
        assert_eq!(diag.missing_field, 0);
        assert!(max_ts.is_none());
        assert_eq!(std::fs::read(&p).unwrap(), original);
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
