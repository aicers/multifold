#!/usr/bin/env python3
"""Assert ground_truth/manifest.jsonl invariants for the compressed AC-0 bundle.

Checks (per issue #66, §3):

* Exactly two execution records exist (one normal + one attack).
* The two `start` timestamps land roughly `5d` and `10d` past `start_at`,
  allowing a few seconds of logical-time slack for command-execution
  overhead at the scheduler.
* The inter-session gap between the two starts is approximately `5d`.
"""

import json
import sys
from datetime import datetime, timedelta, timezone

START_AT = "2026-05-03T00:00:00Z"
OFFSET_NORMAL = timedelta(days=5)
OFFSET_ATTACK = timedelta(days=10)
EXPECTED_GAP = timedelta(days=5)

# Logical-time slack: a few seconds of intra-window command execution plus
# the scheduler's real-time jitter (mapped through scale_factor = 4032 it
# can amount to several minutes of logical time, but realistic runs stay
# within a few logical seconds because anchor windows preserve real
# spacing). 10 minutes is generous and keeps CI green on slow runners.
TOLERANCE = timedelta(minutes=10)


def parse_z(s: str) -> datetime:
    if not s.endswith("Z"):
        raise ValueError(f"timestamp '{s}' must end with 'Z'")
    return datetime.fromisoformat(s.replace("Z", "+00:00")).astimezone(timezone.utc)


def main(path: str) -> int:
    with open(path, "r", encoding="utf-8") as fh:
        records = [json.loads(line) for line in fh if line.strip()]

    if len(records) != 2:
        print(
            f"FAIL: expected 2 records in manifest.jsonl, found {len(records)}",
            file=sys.stderr,
        )
        return 1

    records.sort(key=lambda r: r["start"])
    start_at = parse_z(START_AT)
    first_start = parse_z(records[0]["start"])
    second_start = parse_z(records[1]["start"])

    first_offset = first_start - start_at
    second_offset = second_start - start_at
    if abs(first_offset - OFFSET_NORMAL) > TOLERANCE:
        print(
            f"FAIL: first record start offset = {first_offset} "
            f"(expected ~{OFFSET_NORMAL}, tolerance {TOLERANCE})",
            file=sys.stderr,
        )
        return 1
    if abs(second_offset - OFFSET_ATTACK) > TOLERANCE:
        print(
            f"FAIL: second record start offset = {second_offset} "
            f"(expected ~{OFFSET_ATTACK}, tolerance {TOLERANCE})",
            file=sys.stderr,
        )
        return 1

    gap = second_start - first_start
    if abs(gap - EXPECTED_GAP) > TOLERANCE:
        print(
            f"FAIL: inter-session gap = {gap} (expected ~{EXPECTED_GAP}, "
            f"tolerance {TOLERANCE})",
            file=sys.stderr,
        )
        return 1

    print("manifest.jsonl invariants OK")
    print(f"  first start  = {records[0]['start']} (offset {first_offset})")
    print(f"  second start = {records[1]['start']} (offset {second_offset})")
    print(f"  gap          = {gap}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
