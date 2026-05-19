#!/usr/bin/env python3
"""Assert PCAP structural invariants for the compressed AC-0 bundle.

Checks (per issue #66, §3):

* Magic byte is a recognised microsecond-resolution PCAP magic.
* Packet count is strictly greater than zero.
* Every per-packet timestamp falls in `[start_at, +∞)` (no negative
  offsets relative to the scenario's logical start_at).
* Packet timestamps are monotonically non-decreasing.

Intra-packet interval preservation is *not* asserted here — that is
unit-test territory.
"""

import struct
import sys
from datetime import datetime, timedelta, timezone

START_AT = datetime.fromisoformat("2026-05-03T00:00:00+00:00").astimezone(timezone.utc)
PCAP_MAGIC_US_LE = b"\xd4\xc3\xb2\xa1"
PCAP_MAGIC_US_BE = b"\xa1\xb2\xc3\xd4"


def main(path: str) -> int:
    with open(path, "rb") as fh:
        data = fh.read()

    if len(data) < 24:
        print(f"FAIL: pcap '{path}' shorter than global header", file=sys.stderr)
        return 1

    magic = data[0:4]
    if magic == PCAP_MAGIC_US_LE:
        endian = "<"
    elif magic == PCAP_MAGIC_US_BE:
        endian = ">"
    else:
        print(
            f"FAIL: unrecognised pcap magic {magic.hex()} "
            f"(expected microsecond LE or BE)",
            file=sys.stderr,
        )
        return 1

    offset = 24
    count = 0
    last_ts: datetime | None = None
    while offset < len(data):
        if offset + 16 > len(data):
            print(
                f"FAIL: truncated packet record at offset {offset}",
                file=sys.stderr,
            )
            return 1
        ts_sec, ts_usec, incl_len, _orig_len = struct.unpack(
            f"{endian}IIII", data[offset : offset + 16]
        )
        if ts_usec >= 1_000_000:
            print(
                f"FAIL: packet {count} has out-of-range microseconds: {ts_usec}",
                file=sys.stderr,
            )
            return 1
        ts = datetime.fromtimestamp(0, tz=timezone.utc) + timedelta(
            seconds=ts_sec, microseconds=ts_usec
        )
        if ts < START_AT:
            print(
                f"FAIL: packet {count} timestamp {ts.isoformat()} is before "
                f"start_at {START_AT.isoformat()}",
                file=sys.stderr,
            )
            return 1
        if last_ts is not None and ts < last_ts:
            print(
                f"FAIL: packet {count} timestamp {ts.isoformat()} regresses "
                f"after previous {last_ts.isoformat()}",
                file=sys.stderr,
            )
            return 1
        last_ts = ts
        count += 1
        offset += 16 + incl_len

    if count == 0:
        print("FAIL: pcap has zero packets", file=sys.stderr)
        return 1

    print(f"pcap structural invariants OK ({count} packets)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
