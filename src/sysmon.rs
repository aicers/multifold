use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use chrono::{DateTime, FixedOffset, TimeZone, Utc};

use crate::falco::{FieldLookup, locate_field, substitute_field_value};
use crate::time::{ExecAnchor, RewriteDiagnostics, TimeMap, logical_window, rewrite_ts};
use crate::vm::{self, ProvisionedVm};

/// JSON key for the Sysmon event timestamp emitted by
/// `Get-WinEvent | ConvertTo-Json -Compress`.
const TIME_KEY: &str = "TimeCreated";

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

/// Rewrites the `TimeCreated` field of every record in a Sysmon
/// JSONL file onto the logical timeline. See `falco::rewrite_timestamps`
/// for the shared contract; the only Sysmon-specific behavior is the
/// dual wire format (`\/Date(<ms>)\/` for Windows PowerShell 5.1, ISO
/// 8601 for PowerShell 7+) and the requirement to preserve the input
/// offset and fractional precision on round-trip.
///
/// Sysmon JSONL is treated as having a single rewritten timestamp
/// field, `TimeCreated`. This is the only timestamp-bearing entry
/// emitted by the `Get-WinEvent | ConvertTo-Json -Compress` capture
/// path used in `collect_logs`, and matches the field consumed by the
/// validator's L4-002 process↔Sysmon overlap check in
/// `src/validator.rs`. If a future Sysmon schema or capture variant
/// introduces additional timestamp fields that downstream consumers
/// care about, extend this rewriter and revisit the validator
/// accordingly. See `falco::rewrite_timestamps` for the analogous
/// `time`-only scope statement on the Falco side.
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
        let (body, eol) = raw_line
            .strip_suffix('\n')
            .map_or((raw_line, ""), |b| (b, "\n"));
        if body.is_empty() {
            output.push_str(raw_line);
            continue;
        }
        let new_body =
            match rewrite_sysmon_line(body, time_map, anchors, &mut diag, &mut max_ts, start, end)?
            {
                Some(s) => s,
                None => body.to_owned(),
            };
        output.push_str(&new_body);
        output.push_str(eol);
    }

    std::fs::write(path, &output).with_context(|| format!("failed to write {}", path.display()))?;
    Ok((max_ts, diag))
}

fn rewrite_sysmon_line(
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
    // literal `TimeCreated` plus an escaped `TimeCreated`);
    // `serde_json` collapses them via last-write-wins while the
    // byte-exact walker sees them as distinct keys. In that case the
    // walker may have matched only the literal spelling, leaving any
    // escaped duplicate untouched and the rewrite consistent with
    // undefined-order semantics. The safe behavior is to refuse the
    // rewrite and classify the line as malformed, matching the
    // duplicate-key contract from #72.
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
            // (e.g. `"TimeCreated"`), which the structural walker
            // does not decode. Stricter handling of escaped key
            // spellings is left to a future issue; the safe behavior
            // here is to leave the line byte-identical and count as
            // malformed.
            if parsed.get(TIME_KEY).is_some() {
                diag.malformed_lines += 1;
            } else {
                diag.missing_field += 1;
            }
            return Ok(None);
        }
        FieldLookup::Duplicate => {
            // Duplicate top-level `TimeCreated`: `serde_json`'s
            // last-write-wins is not a stable contract to lean on.
            // Detection happens here, before any type check, so the
            // classification cannot flip depending on which duplicate
            // survives the parse.
            diag.malformed_lines += 1;
            return Ok(None);
        }
        FieldLookup::NonString => {
            // Field present but not a string (number, bool, null,
            // object, array). Matches Falco's classification of the
            // same shape.
            diag.unparseable_ts += 1;
            return Ok(None);
        }
    };
    let Some((real_ts, style)) = parse_sysmon_time(raw_value) else {
        diag.unparseable_ts += 1;
        return Ok(None);
    };

    let rewritten = rewrite_ts(real_ts, time_map, anchors)?;
    let new_value = format_sysmon_time(rewritten, &style);
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

enum SysmonStyle {
    /// `/Date(<ms>)/`. `escaped` records whether the on-wire slashes
    /// were backslash-escaped (`\/Date(<ms>)\/`, the Windows
    /// PowerShell 5.1 default) or bare (`/Date(<ms>)/`, what some
    /// serde re-encoders emit). The spelling is preserved on write.
    DateMs { escaped: bool },
    /// PowerShell 7+ ISO 8601 with `Z`. `frac_digits` is the number of
    /// digits after the decimal point in the original input.
    IsoZ { frac_digits: usize },
    /// PowerShell 7+ ISO 8601 with a numeric offset (e.g. `+09:00`).
    IsoOffset {
        offset: FixedOffset,
        frac_digits: usize,
    },
}

fn parse_sysmon_time(raw_value: &str) -> Option<(DateTime<Utc>, SysmonStyle)> {
    // `/Date(<ms>)/` with either escaped or bare slashes. The
    // escaped form is the PowerShell 5.1 wire default; the bare form
    // is what some serde re-encoders emit after a parse round-trip.
    // Both must round-trip in their original spelling.
    for (prefix, suffix, escaped) in [("\\/Date(", ")\\/", true), ("/Date(", ")/", false)] {
        if let Some(inner) = raw_value
            .strip_prefix(prefix)
            .and_then(|r| r.strip_suffix(suffix))
        {
            let ms: i64 = inner.parse().ok()?;
            let utc = Utc.timestamp_millis_opt(ms).single()?;
            return Some((utc, SysmonStyle::DateMs { escaped }));
        }
    }
    // ISO 8601. Chrono's RFC 3339 parser accepts both `Z` and `±HH:MM`.
    let dt = DateTime::parse_from_rfc3339(raw_value).ok()?;
    let frac_digits = count_frac_digits(raw_value);
    let style = if raw_value.ends_with('Z') {
        SysmonStyle::IsoZ { frac_digits }
    } else {
        SysmonStyle::IsoOffset {
            offset: *dt.offset(),
            frac_digits,
        }
    };
    Some((dt.with_timezone(&Utc), style))
}

fn count_frac_digits(s: &str) -> usize {
    let Some(dot_pos) = s.find('.') else {
        return 0;
    };
    s[dot_pos + 1..]
        .chars()
        .take_while(char::is_ascii_digit)
        .count()
}

fn format_sysmon_time(utc: DateTime<Utc>, style: &SysmonStyle) -> String {
    match style {
        SysmonStyle::DateMs { escaped: true } => {
            format!("\\/Date({})\\/", utc.timestamp_millis())
        }
        SysmonStyle::DateMs { escaped: false } => {
            format!("/Date({})/", utc.timestamp_millis())
        }
        SysmonStyle::IsoZ { frac_digits } => format_iso(utc, None, *frac_digits),
        SysmonStyle::IsoOffset {
            offset,
            frac_digits,
        } => format_iso(utc, Some(*offset), *frac_digits),
    }
}

/// Emits an ISO 8601 timestamp with arbitrary fractional precision
/// (`%.Nf` is only defined for N ∈ {3, 6, 9} in chrono). When `offset`
/// is `None`, the suffix is `Z`; otherwise the suffix is `±HH:MM`.
fn format_iso(utc: DateTime<Utc>, offset: Option<FixedOffset>, frac_digits: usize) -> String {
    let head = match offset {
        None => utc.format("%Y-%m-%dT%H:%M:%S").to_string(),
        Some(ofs) => utc
            .with_timezone(&ofs)
            .format("%Y-%m-%dT%H:%M:%S")
            .to_string(),
    };
    let frac = if frac_digits == 0 {
        String::new()
    } else {
        let nanos = utc.timestamp_subsec_nanos();
        let nanos_str = format!("{nanos:09}");
        let truncated = if frac_digits <= 9 {
            nanos_str[..frac_digits].to_string()
        } else {
            // Sub-nanosecond inputs (e.g. .NET's 7 digits is fine, but
            // we still handle padding for any future precision bump).
            format!("{}{}", nanos_str, "0".repeat(frac_digits - 9))
        };
        format!(".{truncated}")
    };
    let tail = match offset {
        None => "Z".to_string(),
        Some(ofs) => format_offset(ofs),
    };
    format!("{head}{frac}{tail}")
}

fn format_offset(offset: FixedOffset) -> String {
    let secs = offset.local_minus_utc();
    let sign = if secs < 0 { '-' } else { '+' };
    let abs = secs.unsigned_abs();
    let h = abs / 3600;
    let m = (abs % 3600) / 60;
    format!("{sign}{h:02}:{m:02}")
}

#[cfg(test)]
mod tests {
    use chrono::Duration;

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

    // ── rewrite_timestamps ────────────────────────────────────────

    fn identity_map() -> TimeMap {
        let t = Utc.with_ymd_and_hms(2026, 1, 15, 9, 0, 0).unwrap();
        let dur = Duration::try_minutes(5).unwrap();
        TimeMap::new(t, t, dur, dur).unwrap()
    }

    fn write_lines(dir: &Path, lines: &[&str]) -> PathBuf {
        let p = dir.join("sysmon.jsonl");
        let mut content = String::new();
        for l in lines {
            content.push_str(l);
            content.push('\n');
        }
        std::fs::write(&p, content).unwrap();
        p
    }

    /// `Date(<ms>)` payload for `2026-01-15T09:01:15Z` — `1768467675000`.
    const DATE_MS_LINE: &str = r#"{"TimeCreated":"\/Date(1768467675000)\/","Id":4688}"#;
    /// Bare `/Date(<ms>)/` — what some serde re-encoders produce.
    const DATE_MS_BARE_LINE: &str = r#"{"TimeCreated":"/Date(1768467675000)/","Id":4688}"#;
    const ISO_Z_LINE: &str = r#"{"TimeCreated":"2026-01-15T09:01:15Z","Id":4688}"#;
    const ISO_OFFSET_LINE: &str = r#"{"TimeCreated":"2026-01-15T18:01:15+09:00","Id":4688}"#;

    #[test]
    fn identity_preserves_date_ms_wire_form_byte_for_byte() {
        let dir = tempfile::tempdir().unwrap();
        let p = write_lines(dir.path(), &[DATE_MS_LINE]);
        let original = std::fs::read(&p).unwrap();
        let (max_ts, diag) = rewrite_timestamps(&p, &identity_map(), &[]).unwrap();
        assert!(diag.is_empty());
        assert!(max_ts.is_some());
        // Critically, the escaped slashes must survive: read the file
        // back as raw bytes and assert equality, then also verify the
        // backslash bytes are present.
        let written = std::fs::read(&p).unwrap();
        assert_eq!(written, original);
        assert!(
            std::str::from_utf8(&written).unwrap().contains(r"\/Date("),
            "escaped slashes must survive the round-trip",
        );
    }

    #[test]
    fn identity_preserves_bare_date_ms_byte_for_byte() {
        // Bare `/Date(<ms>)/` (no escaped slashes) must also round-trip
        // byte-for-byte and NOT be converted to the escaped spelling.
        let dir = tempfile::tempdir().unwrap();
        let p = write_lines(dir.path(), &[DATE_MS_BARE_LINE]);
        let original = std::fs::read(&p).unwrap();
        let (max_ts, diag) = rewrite_timestamps(&p, &identity_map(), &[]).unwrap();
        assert!(diag.is_empty());
        assert!(max_ts.is_some());
        let written = std::fs::read(&p).unwrap();
        assert_eq!(written, original);
        let s = std::str::from_utf8(&written).unwrap();
        assert!(
            s.contains("/Date(") && !s.contains(r"\/Date("),
            "bare slashes must NOT be promoted to escaped slashes: {s}",
        );
    }

    #[test]
    fn bare_date_ms_rewrites_under_compression_keeps_bare_slashes() {
        // Same scenario as `date_ms_rewrites_under_compression` but the
        // input is the bare-slash spelling. The rewritten line must
        // keep bare slashes, not switch to the escaped form.
        let real_start = Utc.with_ymd_and_hms(2026, 1, 15, 9, 0, 0).unwrap();
        let logical_start = Utc.with_ymd_and_hms(2026, 5, 1, 0, 0, 0).unwrap();
        let tm = TimeMap::new(
            logical_start,
            real_start,
            Duration::try_minutes(30).unwrap(),
            Duration::try_days(14).unwrap(),
        )
        .unwrap();
        let dir = tempfile::tempdir().unwrap();
        let p = write_lines(dir.path(), &[DATE_MS_BARE_LINE]);
        let (_, diag) = rewrite_timestamps(&p, &tm, &[]).unwrap();
        assert!(diag.is_empty());
        let s = std::fs::read_to_string(&p).unwrap();
        assert!(
            s.contains("/Date(") && !s.contains(r"\/Date("),
            "rewritten value must keep bare slashes: {s}",
        );
    }

    #[test]
    fn identity_preserves_iso_z_byte_for_byte() {
        let dir = tempfile::tempdir().unwrap();
        let p = write_lines(dir.path(), &[ISO_Z_LINE]);
        let original = std::fs::read(&p).unwrap();
        let (_, diag) = rewrite_timestamps(&p, &identity_map(), &[]).unwrap();
        assert!(diag.is_empty());
        assert_eq!(std::fs::read(&p).unwrap(), original);
    }

    #[test]
    fn identity_preserves_iso_offset_byte_for_byte() {
        let dir = tempfile::tempdir().unwrap();
        let p = write_lines(dir.path(), &[ISO_OFFSET_LINE]);
        let original = std::fs::read(&p).unwrap();
        let (_, diag) = rewrite_timestamps(&p, &identity_map(), &[]).unwrap();
        assert!(diag.is_empty());
        // The `+09:00` offset must NOT be normalized to `Z`.
        let s = std::fs::read_to_string(&p).unwrap();
        assert!(s.contains("+09:00"));
        assert_eq!(std::fs::read(&p).unwrap(), original);
    }

    #[test]
    fn iso_offset_input_keeps_offset_on_rewrite() {
        // Under a non-identity map, the rewritten value must still
        // emit `+09:00`, not `Z`. We use a compression map and check
        // the suffix.
        let real_start = Utc.with_ymd_and_hms(2026, 1, 15, 9, 0, 0).unwrap();
        let logical_start = Utc.with_ymd_and_hms(2026, 5, 1, 0, 0, 0).unwrap();
        let tm = TimeMap::new(
            logical_start,
            real_start,
            Duration::try_minutes(30).unwrap(),
            Duration::try_days(14).unwrap(),
        )
        .unwrap();
        // 2026-01-15T18:01:15+09:00 == 2026-01-15T09:01:15Z (75 s past
        // real_start). Within the 30-min real window.
        let dir = tempfile::tempdir().unwrap();
        let p = write_lines(dir.path(), &[ISO_OFFSET_LINE]);
        let (_, diag) = rewrite_timestamps(&p, &tm, &[]).unwrap();
        assert!(diag.is_empty());
        let s = std::fs::read_to_string(&p).unwrap();
        assert!(
            s.contains("+09:00") && !s.contains('Z'),
            "rewritten value must preserve the +09:00 offset: {s}",
        );
    }

    #[test]
    fn iso_with_microsecond_fractional_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let line = r#"{"TimeCreated":"2026-01-15T09:01:15.123456Z","Id":4688}"#;
        let p = write_lines(dir.path(), &[line]);
        let original = std::fs::read(&p).unwrap();
        let (_, diag) = rewrite_timestamps(&p, &identity_map(), &[]).unwrap();
        assert!(diag.is_empty());
        assert_eq!(std::fs::read(&p).unwrap(), original);
    }

    #[test]
    fn iso_with_seven_digit_dotnet_fractional_round_trips() {
        // PowerShell 7+ default `.ToString("o")` form carries 7
        // fractional digits (100 ns ticks). Identity must preserve
        // every digit, not truncate to microseconds.
        let dir = tempfile::tempdir().unwrap();
        let line = r#"{"TimeCreated":"2026-01-15T09:01:15.1234567Z","Id":4688}"#;
        let p = write_lines(dir.path(), &[line]);
        let original = std::fs::read(&p).unwrap();
        let (max_ts, diag) = rewrite_timestamps(&p, &identity_map(), &[]).unwrap();
        assert!(diag.is_empty());
        assert_eq!(
            max_ts.unwrap().timestamp_subsec_nanos(),
            123_456_700,
            "identity rewrite must preserve 100 ns ticks",
        );
        assert_eq!(std::fs::read(&p).unwrap(), original);
    }

    #[test]
    fn iso_with_nine_digit_nanosecond_fractional_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let line = r#"{"TimeCreated":"2026-01-15T09:01:15.123456789Z","Id":4688}"#;
        let p = write_lines(dir.path(), &[line]);
        let original = std::fs::read(&p).unwrap();
        let (max_ts, diag) = rewrite_timestamps(&p, &identity_map(), &[]).unwrap();
        assert!(diag.is_empty());
        assert_eq!(max_ts.unwrap().timestamp_subsec_nanos(), 123_456_789);
        assert_eq!(std::fs::read(&p).unwrap(), original);
    }

    // ── edge cases ────────────────────────────────────────────────

    #[test]
    fn missing_field_passes_through_and_counts() {
        let dir = tempfile::tempdir().unwrap();
        let line = r#"{"Id":4688,"Message":"no timestamp"}"#;
        let p = write_lines(dir.path(), &[line]);
        let original = std::fs::read(&p).unwrap();
        let (max_ts, diag) = rewrite_timestamps(&p, &identity_map(), &[]).unwrap();
        assert_eq!(diag.missing_field, 1);
        assert!(max_ts.is_none());
        assert_eq!(std::fs::read(&p).unwrap(), original);
    }

    #[test]
    fn malformed_line_passes_through_and_counts() {
        let dir = tempfile::tempdir().unwrap();
        let line = r#"{"TimeCreated":"2026-01-15T09:01:15Z""#;
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
        let line = r#"{"TimeCreated":"not a timestamp","Id":4688}"#;
        let p = write_lines(dir.path(), &[line]);
        let original = std::fs::read(&p).unwrap();
        let (max_ts, diag) = rewrite_timestamps(&p, &identity_map(), &[]).unwrap();
        assert_eq!(diag.unparseable_ts, 1);
        assert!(max_ts.is_none());
        assert_eq!(std::fs::read(&p).unwrap(), original);
    }

    #[test]
    fn out_of_window_keeps_record_and_counts() {
        let dir = tempfile::tempdir().unwrap();
        // 10 logical minutes past the 5-minute window under identity.
        let line = r#"{"TimeCreated":"2026-01-15T09:10:00Z","Id":4688}"#;
        let p = write_lines(dir.path(), &[line]);
        let (max_ts, diag) = rewrite_timestamps(&p, &identity_map(), &[]).unwrap();
        assert_eq!(diag.out_of_window, 1);
        assert!(max_ts.is_some());
        let content = std::fs::read_to_string(&p).unwrap();
        assert_eq!(content.lines().count(), 1);
    }

    // ── aggregator contract ───────────────────────────────────────

    #[test]
    fn empty_file_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("sysmon.jsonl");
        std::fs::write(&p, "").unwrap();
        let (max_ts, diag) = rewrite_timestamps(&p, &identity_map(), &[]).unwrap();
        assert!(max_ts.is_none());
        assert!(diag.is_empty());
    }

    #[test]
    fn multi_record_returns_max_rewritten_ts() {
        let dir = tempfile::tempdir().unwrap();
        let p = write_lines(
            dir.path(),
            &[
                r#"{"TimeCreated":"2026-01-15T09:01:00Z"}"#,
                r#"{"TimeCreated":"2026-01-15T09:02:30Z"}"#,
                r#"{"TimeCreated":"2026-01-15T09:02:00Z"}"#,
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
    fn whitespace_around_colon_with_date_ms_round_trips_byte_for_byte() {
        // Valid JSON with insignificant whitespace around `:`. The
        // `\/Date(<ms>)\/` escaped-slash form must survive intact and
        // the line must pass through byte-for-byte under identity with
        // no diagnostic incremented.
        let dir = tempfile::tempdir().unwrap();
        let line = r#"{"TimeCreated" : "\/Date(1768467675000)\/" , "Id":4688}"#;
        let p = write_lines(dir.path(), &[line]);
        let original = std::fs::read(&p).unwrap();
        let (max_ts, diag) = rewrite_timestamps(&p, &identity_map(), &[]).unwrap();
        assert!(diag.is_empty());
        assert!(max_ts.is_some());
        let written = std::fs::read(&p).unwrap();
        assert_eq!(written, original);
        assert!(
            std::str::from_utf8(&written).unwrap().contains(r"\/Date("),
            "escaped slashes must survive: {}",
            std::str::from_utf8(&written).unwrap(),
        );
    }

    #[test]
    fn embedded_time_created_substring_is_not_mistaken_for_real_key() {
        // A prior field's string value literally contains
        // `\"TimeCreated\":\"fake\"`. The structural walker must skip
        // it and rewrite only the real top-level `TimeCreated`. The
        // embedded substring must remain byte-for-byte unchanged.
        let real_start = Utc.with_ymd_and_hms(2026, 1, 15, 9, 0, 0).unwrap();
        let logical_start = Utc.with_ymd_and_hms(2026, 5, 1, 0, 0, 0).unwrap();
        let tm = TimeMap::new(
            logical_start,
            real_start,
            Duration::try_minutes(30).unwrap(),
            Duration::try_days(14).unwrap(),
        )
        .unwrap();
        let line = r#"{"Message":"x \"TimeCreated\":\"fake\" y","TimeCreated":"2026-01-15T09:01:15Z","Id":4688}"#;
        let dir = tempfile::tempdir().unwrap();
        let p = write_lines(dir.path(), &[line]);
        let (_, diag) = rewrite_timestamps(&p, &tm, &[]).unwrap();
        assert!(diag.is_empty());
        let s = std::fs::read_to_string(&p).unwrap();
        assert!(
            s.contains(r#"\"TimeCreated\":\"fake\""#),
            "embedded substring must survive byte-for-byte: {s}",
        );
        // The real top-level `TimeCreated` was rewritten — its
        // original ISO string is gone.
        assert!(
            !s.contains("\"TimeCreated\":\"2026-01-15T09:01:15Z\""),
            "real top-level TimeCreated should have been rewritten: {s}",
        );
    }

    #[test]
    fn non_string_time_value_counts_as_unparseable_ts() {
        // Per #72: a `TimeCreated` field present but with a non-string
        // value (here, a number) must be classified as
        // `unparseable_ts`, not `missing_field`. This matches Falco's
        // classification of the same shape.
        let dir = tempfile::tempdir().unwrap();
        let line = r#"{"TimeCreated":12345,"Id":4688}"#;
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
    fn duplicate_time_created_keys_count_as_malformed_lines() {
        // Two depth-1 `TimeCreated` keys, both strings. `serde_json`'s
        // last-write-wins masks the duplicate at the parsed-value
        // level, but the structural walker must detect it and the line
        // must be classified as `malformed_lines` per #72's safe
        // duplicate-key contract.
        let dir = tempfile::tempdir().unwrap();
        let line = r#"{"TimeCreated":"2026-01-15T09:01:15Z","TimeCreated":"2026-01-15T09:02:15Z","Id":4688}"#;
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
    fn duplicate_time_created_string_then_non_string_count_as_malformed() {
        // First `TimeCreated` is a string, second is a number.
        // `serde_json` last-write-wins surfaces the number, which
        // without duplicate detection would mis-classify as
        // `unparseable_ts`. The walker must catch the duplicate first.
        let dir = tempfile::tempdir().unwrap();
        let line = r#"{"TimeCreated":"2026-01-15T09:01:15Z","TimeCreated":12345,"Id":4688}"#;
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
    fn duplicate_time_created_non_string_then_string_count_as_malformed() {
        // First `TimeCreated` is a number, second is a string.
        // `serde_json` last-write-wins surfaces the string; the walker
        // must still detect the duplicate and classify as
        // `malformed_lines`.
        let dir = tempfile::tempdir().unwrap();
        let line = r#"{"TimeCreated":12345,"TimeCreated":"2026-01-15T09:01:15Z","Id":4688}"#;
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
    fn duplicate_time_created_both_non_string_count_as_malformed() {
        // Both `TimeCreated` values are numbers. Without duplicate
        // detection before the type check, this would mis-classify as
        // `unparseable_ts`.
        let dir = tempfile::tempdir().unwrap();
        let line = r#"{"TimeCreated":12345,"TimeCreated":67890,"Id":4688}"#;
        let p = write_lines(dir.path(), &[line]);
        let original = std::fs::read(&p).unwrap();
        let (max_ts, diag) = rewrite_timestamps(&p, &identity_map(), &[]).unwrap();
        assert_eq!(diag.malformed_lines, 1);
        assert_eq!(diag.unparseable_ts, 0);
        assert!(max_ts.is_none());
        assert_eq!(std::fs::read(&p).unwrap(), original);
    }

    #[test]
    fn literal_then_escaped_time_created_key_counts_as_malformed() {
        // A literal `TimeCreated` followed by an escape-equivalent
        // `TimeCreated` (which decodes to `TimeCreated`).
        // `serde_json` merges both into a single `TimeCreated` entry
        // via last-write-wins; the byte-exact walker sees only the
        // literal as a match. Without the walker/serde key-count
        // cross-check, the walker would rewrite the literal occurrence,
        // leaving the escaped duplicate byte-identical, and the
        // rewrite would be consistent with undefined-order semantics.
        // The safe behavior is to refuse the rewrite and classify the
        // line as `malformed_lines`.
        let dir = tempfile::tempdir().unwrap();
        let line = "{\"TimeCreated\":\"2026-01-15T09:01:15Z\",\"\\u0054imeCreated\":\"2026-01-15T09:02:15Z\",\"Id\":4688}";
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
    fn escaped_then_literal_time_created_key_counts_as_malformed() {
        // Reverse order: the escaped spelling appears first, the
        // literal `TimeCreated` second. `serde_json` still merges both
        // into a single `TimeCreated` entry. The walker sees the
        // literal as a match and would otherwise rewrite it; the
        // cross-check must catch the collision and refuse.
        let dir = tempfile::tempdir().unwrap();
        let line = "{\"\\u0054imeCreated\":\"2026-01-15T09:02:15Z\",\"TimeCreated\":\"2026-01-15T09:01:15Z\",\"Id\":4688}";
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
        // `"TimeCreated"` decodes to `TimeCreated` per JSON's
        // escape rules but the structural walker compares key bytes
        // literally and does not decode them. The robustness contract
        // leaves stricter escape-aware key handling to a future issue;
        // the safe behavior here is to pass the line through
        // byte-for-byte and count it as `malformed_lines`, never as a
        // false rewrite of a different key.
        let dir = tempfile::tempdir().unwrap();
        // The key on the wire is literally `TimeCreated` (the `T`
        // byte replaced by `T`). JSON decodes this to
        // `TimeCreated`, so `serde_json` sees the field; the walker
        // compares key bytes literally, so it does not.
        let line = "{\"\\u0054imeCreated\":\"2026-01-15T09:01:15Z\",\"Id\":4688}";
        let p = write_lines(dir.path(), &[line]);
        let original = std::fs::read(&p).unwrap();
        let (max_ts, diag) = rewrite_timestamps(&p, &identity_map(), &[]).unwrap();
        assert_eq!(diag.malformed_lines, 1);
        assert_eq!(diag.missing_field, 0);
        assert!(max_ts.is_none());
        assert_eq!(std::fs::read(&p).unwrap(), original);
    }

    #[test]
    fn date_ms_rewrites_under_compression() {
        // 30 real minutes → 14 logical days. The record's real ts is
        // 75 s past `real_start`. Under compression, the rewritten
        // value must land at `logical_start + 75 s * scale`.
        let real_start = Utc.with_ymd_and_hms(2026, 1, 15, 9, 0, 0).unwrap();
        let logical_start = Utc.with_ymd_and_hms(2026, 5, 1, 0, 0, 0).unwrap();
        let real_window = Duration::try_minutes(30).unwrap();
        let logical_window = Duration::try_days(14).unwrap();
        let tm = TimeMap::new(logical_start, real_start, real_window, logical_window).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let p = write_lines(dir.path(), &[DATE_MS_LINE]);
        let (max_ts, diag) = rewrite_timestamps(&p, &tm, &[]).unwrap();
        assert!(diag.is_empty());
        // Wire form must remain `\/Date(<new_ms>)\/`.
        let s = std::fs::read_to_string(&p).unwrap();
        assert!(s.contains(r"\/Date("), "DateMs wire form must survive: {s}");
        // The fixture records `2026-01-15T09:01:15Z`, 75 s past
        // `real_start`. Derive the scaled logical offset from the map's
        // window durations rather than a hard-coded ms literal so the
        // assertion fails on any arithmetic regression — millisecond
        // rounding, sign error, or off-by-one in the affine map.
        let real_offset = Duration::try_seconds(75).unwrap();
        let expected = logical_start
            + Duration::milliseconds(
                real_offset.num_milliseconds() * logical_window.num_milliseconds()
                    / real_window.num_milliseconds(),
            );
        assert_eq!(max_ts.unwrap(), expected);
    }

    // ── anchor preservation ───────────────────────────────────────

    #[test]
    fn anchor_burst_preserves_intra_session_spacing() {
        // 30 real minutes → 14 logical days. Two `\/Date(<ms>)\/`
        // records inside one execution window must keep their real
        // 100 ms spacing, the first record must land exactly at the
        // anchor's `logical_start`, and both lines must retain the
        // escaped-slash wire form (no normalization to bare slashes).
        use std::net::Ipv4Addr;

        use crate::activity::Execution;
        use crate::scenario::Protocol;
        use crate::time::build_anchors;

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
        let exec = Execution {
            start: exec_start,
            end: exec_end,
            source: "a".into(),
            target: "b".into(),
            protocol: Protocol::Tcp,
            src_ip: Ipv4Addr::new(10, 0, 0, 2),
            src_port: 0,
            dst_ip: Ipv4Addr::new(10, 0, 0, 3),
            dst_port: 80,
            attack: None,
            exit_code: 0,
            command: String::new(),
        };
        let (anchors, _) = build_anchors(&[exec], &tm).unwrap();

        let burst_b = exec_start + Duration::milliseconds(100);
        let line_a = format!(
            r#"{{"TimeCreated":"\/Date({})\/","Id":4688}}"#,
            exec_start.timestamp_millis(),
        );
        let line_b = format!(
            r#"{{"TimeCreated":"\/Date({})\/","Id":4689}}"#,
            burst_b.timestamp_millis(),
        );

        let dir = tempfile::tempdir().unwrap();
        let p = write_lines(dir.path(), &[&line_a, &line_b]);
        let (max_ts, diag) = rewrite_timestamps(&p, &tm, &anchors).unwrap();
        assert!(diag.is_empty());

        let content = std::fs::read_to_string(&p).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 2);

        // Parse the embedded ms integer back to a `DateTime<Utc>` so a
        // millisecond-rounding regression in the rewriter fails this
        // test — checking only the wire-form spelling would not.
        let parse_date_ms = |line: &str| -> DateTime<Utc> {
            let v: serde_json::Value = serde_json::from_str(line).expect("JSON parse");
            // `serde_json` decodes `\/` to `/`, so the surfaced value
            // is the bare-slash form regardless of the on-wire spelling.
            let raw = v["TimeCreated"].as_str().expect("TimeCreated string");
            let inner = raw
                .strip_prefix("/Date(")
                .and_then(|r| r.strip_suffix(")/"))
                .expect("/Date(<ms>)/ payload");
            let ms: i64 = inner.parse().expect("ms integer");
            Utc.timestamp_millis_opt(ms).single().expect("valid ms")
        };
        let a = parse_date_ms(lines[0]);
        let b = parse_date_ms(lines[1]);
        assert_eq!(a, anchors[0].logical_start);
        assert_eq!(b - a, Duration::milliseconds(100));
        assert_eq!(max_ts.unwrap(), b);

        // Wire form: both lines must retain the escaped `\/Date(`
        // spelling and must NOT have been promoted/demoted between
        // the two `DateMs` spellings.
        for line in &lines {
            assert!(
                line.contains(r"\/Date("),
                "escaped slashes must survive: {line}",
            );
            assert!(
                !line.contains("\"/Date("),
                "escaped form must not be normalized to bare slashes: {line}",
            );
        }

        // Sanity: the anchor's logical_start is the global-map image
        // of `exec_start`, not the bare `logical_start` constant — the
        // 10 s real offset is scaled before the anchor lands.
        assert_ne!(anchors[0].logical_start, logical_start);
    }
}
