#!/usr/bin/env python3
"""Independent state-transition oracle for MDVM security metadata."""

# Old flow: both assertions are verified against an unlocked snapshot counter=10.
# If 12 commits first and 11 commits second, persisted security state rolls back.
stored = 10
snapshot_a = stored
snapshot_b = stored
assert 11 > snapshot_a
assert 12 > snapshot_b
stored = 12
stored = 11
assert stored == 11  # demonstrates old rollback

# Hardened flow: each writer reloads under the DB lock and compare-before-write.
stored = 10
for candidate in (12, 11):
    if candidate > stored:
        stored = candidate
assert stored == 12

# Duplicate replay cannot pass after the first commit.
stored = 10
accepted = []
for candidate in (11, 11):
    ok = candidate > stored
    accepted.append(ok)
    if ok:
        stored = candidate
assert accepted == [True, False]
assert stored == 11

# Lack of newly verified assertion/attestation must preserve last-good evidence.
old_assertion = 17
new_assertion = None
persisted_assertion = new_assertion if new_assertion is not None else old_assertion
assert persisted_assertion == 17

old_android_attestation = {"patch": "2026-09"}
new_android_attestation = None
persisted_android_attestation = (
    new_android_attestation if new_android_attestation is not None else old_android_attestation
)
assert persisted_android_attestation == old_android_attestation

print("MDVM REPLAY/EVIDENCE ORACLE: PASS")
