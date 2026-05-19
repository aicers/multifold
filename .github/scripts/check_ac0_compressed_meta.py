#!/usr/bin/env python3
"""Assert meta.json invariants for the compressed AC-0 CI bundle.

Checks:
* `duration.actual_start == "2026-05-03T00:00:00Z"`
* `duration.total == "14d"`
* `actual_end > actual_start` and `actual_end <= start_at + 14d`
"""

import json
import sys
from datetime import datetime, timedelta, timezone

EXPECTED_START_AT = "2026-05-03T00:00:00Z"
EXPECTED_TOTAL = "14d"
LOGICAL_DURATION = timedelta(days=14)


def parse_z(s: str) -> datetime:
    if not s.endswith("Z"):
        raise ValueError(f"timestamp '{s}' must end with 'Z'")
    return datetime.fromisoformat(s.replace("Z", "+00:00")).astimezone(timezone.utc)


def main(path: str) -> int:
    with open(path, "r", encoding="utf-8") as fh:
        meta = json.load(fh)

    duration = meta["duration"]
    actual_start = duration["actual_start"]
    actual_end = duration["actual_end"]
    total = duration["total"]

    if actual_start != EXPECTED_START_AT:
        print(
            f"FAIL: duration.actual_start = {actual_start!r}, expected {EXPECTED_START_AT!r}",
            file=sys.stderr,
        )
        return 1

    if total != EXPECTED_TOTAL:
        print(
            f"FAIL: duration.total = {total!r}, expected {EXPECTED_TOTAL!r}",
            file=sys.stderr,
        )
        return 1

    start_dt = parse_z(actual_start)
    end_dt = parse_z(actual_end)
    upper = start_dt + LOGICAL_DURATION

    if not end_dt > start_dt:
        print(
            f"FAIL: actual_end ({actual_end}) is not strictly after "
            f"actual_start ({actual_start})",
            file=sys.stderr,
        )
        return 1

    if end_dt > upper:
        print(
            f"FAIL: actual_end ({actual_end}) exceeds start_at + 14d "
            f"({upper.strftime('%Y-%m-%dT%H:%M:%SZ')})",
            file=sys.stderr,
        )
        return 1

    print("meta.json invariants OK")
    print(f"  actual_start = {actual_start}")
    print(f"  total        = {total}")
    print(f"  actual_end   = {actual_end}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
