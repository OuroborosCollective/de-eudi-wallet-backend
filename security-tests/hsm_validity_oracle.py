#!/usr/bin/env python3
"""Independent oracle for HSM date-only validity semantics."""
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

INSTANT = datetime(2026, 1, 1, 0, 30, tzinfo=timezone.utc)
START = datetime(2026, 1, 1, tzinfo=timezone.utc).date()
END = START

host_dates = {
    zone: INSTANT.astimezone(ZoneInfo(zone)).date()
    for zone in ("America/Los_Angeles", "Europe/Berlin", "UTC")
}

# Independent negative path: host-local projection is demonstrably non-deterministic.
assert len(set(host_dates.values())) > 1, host_dates

# Canonical UTC projection remains stable and enforces both interval boundaries.
utc_date = INSTANT.astimezone(timezone.utc).date()
assert START <= utc_date <= END
assert not (START <= datetime(2025, 12, 31, 23, 59, 59, tzinfo=timezone.utc).date() <= END)
assert not (START <= datetime(2026, 1, 2, 0, 0, tzinfo=timezone.utc).date() <= END)

print("HSM VALIDITY ORACLE: PASS")
print("host_local_dates=", host_dates)
print("canonical_utc_date=", utc_date.isoformat())
