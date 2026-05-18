//! Real-to-logical timestamp mapping and per-execution anchors.
//!
//! The affine mapping is:
//!
//! ```text
//! logical_ts = start_at + (real_ts - real_generation_start) * scale
//! scale      = logical_duration / scenario.duration
//! ```
//!
//! All arithmetic uses microsecond integers with an `i128` intermediate
//! product so realistic compression ratios (e.g., `2w → 30m`) cannot
//! overflow `i64` during the multiply. Final narrowing back to `i64` is
//! surfaced as an error via [`i64::try_from`].

use anyhow::{Context, Result, anyhow, ensure};
use chrono::{DateTime, Duration, Utc};

use crate::activity::{CAPTURE_DRAIN_SECS, Execution};

/// Affine mapping from real wall-clock time to the scenario's declared
/// logical timeline. Built once per run before activities execute.
pub(crate) struct TimeMap {
    start_at: DateTime<Utc>,
    real_generation_start: DateTime<Utc>,
    logical_us: i64,
    real_us: i64,
}

impl TimeMap {
    /// Builds a [`TimeMap`] from the effective `start_at`, the run's
    /// `real_generation_start`, and the scenario's real and logical
    /// durations.
    pub(crate) fn new(
        start_at: DateTime<Utc>,
        real_generation_start: DateTime<Utc>,
        scenario_duration: Duration,
        logical_duration: Duration,
    ) -> Result<Self> {
        let real_us = scenario_duration
            .num_microseconds()
            .context("scenario duration exceeds microsecond range")?;
        let logical_us = logical_duration
            .num_microseconds()
            .context("logical duration exceeds microsecond range")?;
        ensure!(real_us > 0, "scenario duration must be strictly positive");
        ensure!(logical_us > 0, "logical duration must be strictly positive");
        Ok(Self {
            start_at,
            real_generation_start,
            logical_us,
            real_us,
        })
    }

    pub(crate) fn start_at(&self) -> DateTime<Utc> {
        self.start_at
    }

    pub(crate) fn real_generation_start(&self) -> DateTime<Utc> {
        self.real_generation_start
    }

    /// Returns `true` when the map is a true pass-through: the logical
    /// timeline coincides with the real one and scale is 1:1. Used by
    /// the bundle assembler to preserve pre-#63 `actual_end` semantics
    /// when neither `start_at` nor `logical_duration` is set.
    pub(crate) fn is_identity(&self) -> bool {
        self.start_at == self.real_generation_start && self.logical_us == self.real_us
    }

    pub(crate) fn logical_us(&self) -> i64 {
        self.logical_us
    }

    pub(crate) fn real_us(&self) -> i64 {
        self.real_us
    }

    /// Maps a real wall-clock timestamp onto the logical timeline.
    pub(crate) fn to_logical(&self, real: DateTime<Utc>) -> Result<DateTime<Utc>> {
        let delta_us = (real - self.real_generation_start)
            .num_microseconds()
            .context("real-to-generation delta exceeds microsecond range")?;
        let scaled = i128::from(delta_us) * i128::from(self.logical_us) / i128::from(self.real_us);
        let scaled_us = i64::try_from(scaled)
            .map_err(|_| anyhow!("logical timestamp microseconds overflow i64"))?;
        self.start_at
            .checked_add_signed(Duration::microseconds(scaled_us))
            .ok_or_else(|| anyhow!("computed logical timestamp overflows DateTime range"))
    }
}

/// Per-execution anchor that preserves intra-session timing when the
/// rewriter maps a record whose real timestamp falls inside the
/// execution's window.
pub(crate) struct ExecAnchor {
    pub(crate) real_start: DateTime<Utc>,
    pub(crate) real_end: DateTime<Utc>,
    pub(crate) logical_start: DateTime<Utc>,
    pub(crate) source: String,
    pub(crate) target: String,
}

/// Pair of executions whose anchor windows intersect after drain
/// clamping. Reported as data; the call site is responsible for
/// printing the human-readable warning.
pub(crate) struct OverlapWarning {
    pub(crate) a_source: String,
    pub(crate) a_target: String,
    pub(crate) b_source: String,
    pub(crate) b_target: String,
}

/// Builds the per-execution anchor list sorted by real-start, padding
/// each `real_end` with [`CAPTURE_DRAIN_SECS`] and clamping it against
/// the next anchor whose `real_start` is strictly greater. Also
/// returns any overlap warnings the call site can surface.
pub(crate) fn build_anchors(
    executions: &[Execution],
    time_map: &TimeMap,
) -> Result<(Vec<ExecAnchor>, Vec<OverlapWarning>)> {
    let drain_secs =
        i64::try_from(CAPTURE_DRAIN_SECS).context("CAPTURE_DRAIN_SECS exceeds i64 range")?;
    let drain = Duration::try_seconds(drain_secs).context("drain duration out of range")?;

    let mut sorted: Vec<&Execution> = executions.iter().collect();
    sorted.sort_by_key(|e| e.start);

    let mut anchors = Vec::with_capacity(sorted.len());
    for (i, exec) in sorted.iter().enumerate() {
        let padded_end = exec.end.checked_add_signed(drain).ok_or_else(|| {
            anyhow!(
                "drain-padded end overflows for execution {}→{}",
                exec.source,
                exec.target,
            )
        })?;
        let next_start = sorted[i + 1..]
            .iter()
            .map(|e| e.start)
            .find(|s| *s > exec.start);
        let real_end = match next_start {
            Some(ns) => padded_end.min(ns),
            None => padded_end,
        };
        let logical_start = time_map.to_logical(exec.start)?;
        anchors.push(ExecAnchor {
            real_start: exec.start,
            real_end,
            logical_start,
            source: exec.source.clone(),
            target: exec.target.clone(),
        });
    }

    let warnings = detect_overlaps(&anchors);
    Ok((anchors, warnings))
}

/// Returns one [`OverlapWarning`] per pair of anchors whose
/// `[real_start, real_end]` windows intersect strictly. Touching at
/// the endpoint (`b.real_start == a.real_end`) is not an overlap.
pub(crate) fn detect_overlaps(anchors: &[ExecAnchor]) -> Vec<OverlapWarning> {
    let mut warnings = Vec::new();
    for i in 0..anchors.len() {
        for j in (i + 1)..anchors.len() {
            let a = &anchors[i];
            let b = &anchors[j];
            let (earlier, later) = if a.real_start <= b.real_start {
                (a, b)
            } else {
                (b, a)
            };
            if later.real_start < earlier.real_end {
                warnings.push(OverlapWarning {
                    a_source: earlier.source.clone(),
                    a_target: earlier.target.clone(),
                    b_source: later.source.clone(),
                    b_target: later.target.clone(),
                });
            }
        }
    }
    warnings
}

/// Rewrites a real timestamp onto the logical timeline. Records whose
/// real timestamp falls inside some anchor window are rewritten via
/// that anchor with no scaling (intra-session preservation); records
/// outside every window fall back to the global `TimeMap`.
//
// Ground Truth (#63) rewrites by execution identity to guarantee
// per-record provenance, not by window containment. This helper is
// the entry point PCAP (#64) and JSONL (#65) rewriters consume —
// they only have a raw timestamp, no execution identity. Locked-in
// here per #63's "TimeMap + anchor list" deliverable so the later
// sub-issues plug in without re-deriving the lookup rule.
#[allow(dead_code)]
pub(crate) fn rewrite_ts(
    real_ts: DateTime<Utc>,
    time_map: &TimeMap,
    anchors: &[ExecAnchor],
) -> Result<DateTime<Utc>> {
    if let Some(anchor) = find_anchor(anchors, real_ts) {
        anchor
            .logical_start
            .checked_add_signed(real_ts - anchor.real_start)
            .ok_or_else(|| anyhow!("anchor-based rewrite overflows DateTime range"))
    } else {
        time_map.to_logical(real_ts)
    }
}

/// Returns the anchor whose window contains `ts`. Under overlapping
/// windows, the deterministic pick is the one with the latest
/// `real_start` not exceeding `ts`.
//
// Kept private; reachable only via `rewrite_ts`. See its allow note
// for the #63 → #64/#65 hand-off rationale.
#[allow(dead_code)]
fn find_anchor(anchors: &[ExecAnchor], ts: DateTime<Utc>) -> Option<&ExecAnchor> {
    anchors
        .iter()
        .filter(|a| a.real_start <= ts && ts <= a.real_end)
        .max_by_key(|a| a.real_start)
}

/// Converts a logical-time offset to its real-time equivalent under
/// the current scale. Kept as a pure helper so the scheduler call site
/// can convert authored `start_offset`s without coupling to `TimeMap`
/// construction state.
pub(crate) fn logical_offset_to_real(
    offset: Duration,
    logical_us: i64,
    real_us: i64,
) -> Result<Duration> {
    ensure!(logical_us > 0, "logical duration must be strictly positive");
    ensure!(real_us > 0, "scenario duration must be strictly positive");
    let offset_us = offset
        .num_microseconds()
        .context("logical offset exceeds microsecond range")?;
    let scaled = i128::from(offset_us) * i128::from(real_us) / i128::from(logical_us);
    let scaled_us =
        i64::try_from(scaled).map_err(|_| anyhow!("scaled real offset overflows i64"))?;
    Ok(Duration::microseconds(scaled_us))
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use chrono::TimeZone;

    use super::*;
    use crate::activity::Execution;
    use crate::scenario::Protocol;

    fn fixed(ts: i64) -> DateTime<Utc> {
        Utc.timestamp_opt(ts, 0).unwrap()
    }

    fn identity_map(start: DateTime<Utc>) -> TimeMap {
        TimeMap::new(
            start,
            start,
            Duration::try_seconds(300).unwrap(),
            Duration::try_seconds(300).unwrap(),
        )
        .unwrap()
    }

    fn make_exec(start: DateTime<Utc>, end: DateTime<Utc>, src: &str, dst: &str) -> Execution {
        Execution {
            start,
            end,
            source: src.into(),
            target: dst.into(),
            protocol: Protocol::Tcp,
            src_ip: Ipv4Addr::new(10, 0, 0, 2),
            src_port: 0,
            dst_ip: Ipv4Addr::new(10, 0, 0, 3),
            dst_port: 80,
            attack: None,
            exit_code: 0,
            command: String::new(),
        }
    }

    // ── TimeMap ───────────────────────────────────────────────────

    #[test]
    fn identity_map_returns_real_unchanged() {
        let start = fixed(1_737_000_000);
        let tm = identity_map(start);
        let ts = fixed(1_737_000_120);
        assert_eq!(tm.to_logical(ts).unwrap(), ts);
    }

    #[test]
    fn compression_maps_real_to_logical() {
        // 30 real minutes → 14 logical days (factor 672).
        let real_start = fixed(1_000_000_000);
        let logical_start = fixed(2_000_000_000);
        let tm = TimeMap::new(
            logical_start,
            real_start,
            Duration::try_minutes(30).unwrap(),
            Duration::try_days(14).unwrap(),
        )
        .unwrap();
        // 15 real minutes in → halfway through 14 logical days.
        let real_mid = real_start + Duration::try_minutes(15).unwrap();
        let logical_mid = tm.to_logical(real_mid).unwrap();
        let expected = logical_start + Duration::try_days(7).unwrap();
        assert_eq!(logical_mid, expected);
    }

    #[test]
    fn compression_boundary_does_not_overflow_i128_intermediate() {
        // 30 real minutes → 14 logical days. Real delta near 30 min
        // makes the i64-intermediate product exceed ~9.2e18; this test
        // confirms the i128 intermediate keeps the math correct.
        let real_start = fixed(0);
        let tm = TimeMap::new(
            fixed(0),
            real_start,
            Duration::try_minutes(30).unwrap(),
            Duration::try_days(14).unwrap(),
        )
        .unwrap();
        // 30 real minutes = 1.8e9 µs; 14d = 1.21e12 µs.
        // Product = 1.8e9 * 1.21e12 = 2.18e21, well past i64 limit.
        let real_end = real_start + Duration::try_minutes(30).unwrap();
        let logical_end = tm.to_logical(real_end).unwrap();
        let expected = fixed(0) + Duration::try_days(14).unwrap();
        assert_eq!(logical_end, expected);
    }

    #[test]
    fn time_map_rejects_zero_durations() {
        let t = fixed(0);
        let zero = Duration::zero();
        let one_min = Duration::try_minutes(1).unwrap();
        assert!(TimeMap::new(t, t, zero, one_min).is_err());
        assert!(TimeMap::new(t, t, one_min, zero).is_err());
    }

    // ── logical_offset_to_real ────────────────────────────────────

    #[test]
    fn logical_offset_identity() {
        let offset = Duration::try_minutes(5).unwrap();
        let real = logical_offset_to_real(offset, 300_000_000, 300_000_000).unwrap();
        assert_eq!(real, offset);
    }

    #[test]
    fn logical_offset_compressed_shrinks() {
        // 14d logical / 30m real → 672× compression.
        // 1d logical offset → 30m/14 real offset ≈ 128.57s.
        let logical_us = Duration::try_days(14).unwrap().num_microseconds().unwrap();
        let real_us = Duration::try_minutes(30)
            .unwrap()
            .num_microseconds()
            .unwrap();
        let offset = Duration::try_days(1).unwrap();
        let real = logical_offset_to_real(offset, logical_us, real_us).unwrap();
        // Expected: 1d * 30m / 14d = 30m/14 = 128571428 µs ≈ 128.57 s
        let expected = Duration::microseconds(
            i64::try_from(
                i128::from(offset.num_microseconds().unwrap()) * i128::from(real_us)
                    / i128::from(logical_us),
            )
            .unwrap(),
        );
        assert_eq!(real, expected);
    }

    #[test]
    fn logical_offset_to_real_boundary_uses_i128() {
        // Same boundary as TimeMap: 14d offset under 14d/30m scale
        // produces real = 30m. The intermediate product overflows i64.
        let logical_us = Duration::try_days(14).unwrap().num_microseconds().unwrap();
        let real_us = Duration::try_minutes(30)
            .unwrap()
            .num_microseconds()
            .unwrap();
        let offset = Duration::try_days(14).unwrap();
        let real = logical_offset_to_real(offset, logical_us, real_us).unwrap();
        assert_eq!(real, Duration::try_minutes(30).unwrap());
    }

    #[test]
    fn logical_offset_rejects_zero_logical() {
        let offset = Duration::try_seconds(1).unwrap();
        assert!(logical_offset_to_real(offset, 0, 1).is_err());
    }

    // ── build_anchors ─────────────────────────────────────────────

    #[test]
    fn build_anchors_drain_clamp_no_overlap() {
        // Two back-to-back executions whose real spacing is less than
        // CAPTURE_DRAIN_SECS — the earlier anchor's real_end must be
        // clamped to the later anchor's real_start.
        let t0 = fixed(1_000_000_000);
        let a = make_exec(t0, t0, "a", "x");
        let b = make_exec(
            t0 + Duration::milliseconds(500),
            t0 + Duration::milliseconds(500),
            "b",
            "y",
        );
        let tm = identity_map(t0);
        let (anchors, warnings) = build_anchors(&[a, b], &tm).unwrap();
        assert_eq!(anchors.len(), 2);
        assert!(warnings.is_empty());
        assert_eq!(anchors[0].real_end, anchors[1].real_start);
    }

    #[test]
    fn build_anchors_tail_keeps_full_drain() {
        let t0 = fixed(1_000_000_000);
        let a = make_exec(t0, t0, "a", "x");
        let tm = identity_map(t0);
        let (anchors, _) = build_anchors(&[a], &tm).unwrap();
        let expected_end =
            t0 + Duration::try_seconds(i64::try_from(CAPTURE_DRAIN_SECS).unwrap()).unwrap();
        assert_eq!(anchors[0].real_end, expected_end);
    }

    #[test]
    fn build_anchors_same_start_produces_overlap_warning() {
        let t0 = fixed(1_000_000_000);
        let a = make_exec(t0, t0 + Duration::try_seconds(2).unwrap(), "a", "x");
        let b = make_exec(t0, t0 + Duration::try_seconds(2).unwrap(), "b", "y");
        let tm = identity_map(t0);
        let (_, warnings) = build_anchors(&[a, b], &tm).unwrap();
        assert_eq!(warnings.len(), 1);
    }

    #[test]
    fn detect_overlaps_empty_for_back_to_back_clamped_windows() {
        let t0 = fixed(1_000_000_000);
        let anchors = vec![
            ExecAnchor {
                real_start: t0,
                real_end: t0 + Duration::milliseconds(500),
                logical_start: t0,
                source: "a".into(),
                target: "x".into(),
            },
            ExecAnchor {
                real_start: t0 + Duration::milliseconds(500),
                real_end: t0 + Duration::milliseconds(1500),
                logical_start: t0 + Duration::milliseconds(500),
                source: "b".into(),
                target: "y".into(),
            },
        ];
        assert!(detect_overlaps(&anchors).is_empty());
    }

    #[test]
    fn detect_overlaps_flags_hand_rolled_overlapping_anchors() {
        let t0 = fixed(1_000_000_000);
        let anchors = vec![
            ExecAnchor {
                real_start: t0,
                real_end: t0 + Duration::try_seconds(5).unwrap(),
                logical_start: t0,
                source: "a".into(),
                target: "x".into(),
            },
            ExecAnchor {
                real_start: t0 + Duration::try_seconds(2).unwrap(),
                real_end: t0 + Duration::try_seconds(7).unwrap(),
                logical_start: t0 + Duration::try_seconds(2).unwrap(),
                source: "b".into(),
                target: "y".into(),
            },
        ];
        let warnings = detect_overlaps(&anchors);
        assert_eq!(warnings.len(), 1);
        assert_eq!(warnings[0].a_source, "a");
        assert_eq!(warnings[0].b_source, "b");
    }

    // ── rewrite_ts ────────────────────────────────────────────────

    #[test]
    fn rewrite_anchor_preserves_intra_session_duration() {
        // Under heavy compression, a record inside the anchor window
        // keeps its original real spacing — proving intra-session
        // timing is preserved.
        let real_start = fixed(0);
        let logical_start = fixed(1_000_000_000);
        let tm = TimeMap::new(
            logical_start,
            real_start,
            Duration::try_minutes(30).unwrap(),
            Duration::try_days(14).unwrap(),
        )
        .unwrap();
        let exec_start = real_start + Duration::try_seconds(10).unwrap();
        let exec_end = exec_start + Duration::milliseconds(100);
        let exec = make_exec(exec_start, exec_end, "a", "x");
        let (anchors, _) = build_anchors(&[exec], &tm).unwrap();

        let rewritten_start = rewrite_ts(exec_start, &tm, &anchors).unwrap();
        let rewritten_end = rewrite_ts(exec_end, &tm, &anchors).unwrap();
        // The intra-session gap of 100ms must be preserved exactly.
        assert_eq!(rewritten_end - rewritten_start, Duration::milliseconds(100));
    }

    #[test]
    fn rewrite_outside_anchor_uses_time_map() {
        let real_start = fixed(0);
        let logical_start = fixed(1_000_000_000);
        let tm = TimeMap::new(
            logical_start,
            real_start,
            Duration::try_minutes(30).unwrap(),
            Duration::try_days(14).unwrap(),
        )
        .unwrap();
        // No anchors → always falls back to TimeMap.
        let real_mid = real_start + Duration::try_minutes(15).unwrap();
        let logical = rewrite_ts(real_mid, &tm, &[]).unwrap();
        assert_eq!(logical, logical_start + Duration::try_days(7).unwrap());
    }

    #[test]
    fn rewrite_inter_session_gap_reflects_authored_offsets() {
        // Two executions with different real starts under compression:
        // the rewritten gap between their starts must follow the
        // logical scale, not the real spacing.
        let real_start = fixed(0);
        let logical_start = fixed(1_000_000_000);
        let tm = TimeMap::new(
            logical_start,
            real_start,
            Duration::try_minutes(30).unwrap(),
            Duration::try_days(14).unwrap(),
        )
        .unwrap();
        let first_start = real_start + Duration::try_minutes(10).unwrap();
        let second_start = real_start + Duration::try_minutes(20).unwrap();
        let a = make_exec(first_start, first_start, "a", "x");
        let b = make_exec(second_start, second_start, "b", "y");
        let (anchors, _) = build_anchors(&[a, b], &tm).unwrap();

        // Use the anchors' own logical_start values — these reflect
        // the global scale because they're computed at anchor
        // construction by TimeMap::to_logical.
        let gap = anchors[1].logical_start - anchors[0].logical_start;
        // 10 real minutes between starts scale to 10 * (14d / 30m) days
        // = 14d / 3. Verify by formula.
        let expected = Duration::microseconds(
            i64::try_from(
                i128::from(
                    Duration::try_minutes(10)
                        .unwrap()
                        .num_microseconds()
                        .unwrap(),
                ) * i128::from(tm.logical_us())
                    / i128::from(tm.real_us()),
            )
            .unwrap(),
        );
        assert_eq!(gap, expected);
    }

    #[test]
    fn find_anchor_picks_latest_real_start_under_overlap() {
        let t0 = fixed(1_000_000_000);
        let anchors = vec![
            ExecAnchor {
                real_start: t0,
                real_end: t0 + Duration::try_seconds(10).unwrap(),
                logical_start: t0,
                source: "a".into(),
                target: "x".into(),
            },
            ExecAnchor {
                real_start: t0 + Duration::try_seconds(3).unwrap(),
                real_end: t0 + Duration::try_seconds(8).unwrap(),
                logical_start: t0 + Duration::try_seconds(3).unwrap(),
                source: "b".into(),
                target: "y".into(),
            },
        ];
        let ts = t0 + Duration::try_seconds(5).unwrap();
        let picked = find_anchor(&anchors, ts).unwrap();
        assert_eq!(picked.source, "b");
    }
}
