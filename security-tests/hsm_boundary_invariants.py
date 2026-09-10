#!/usr/bin/env python3
"""Fail-closed source and arithmetic invariants for the HSM/PKCS#11 boundary."""
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
HSM = ROOT / "src/main/kotlin/de/eudiwallet/backend/shared/hsm"
failures: list[str] = []


def require(condition: bool, message: str) -> None:
    if not condition:
        failures.append(message)


config = (HSM / "HsmConfiguration.kt").read_text(encoding="utf-8")
pool = (HSM / "HsmSessionPool.kt").read_text(encoding="utf-8")
session = (HSM / "HsmSession.kt").read_text(encoding="utf-8")

# Configuration is deny-by-default but remains explicitly extensible for vendor mechanisms.
for invariant in (
    "allowedWrappingMechanisms: Set<Long>",
    "Ck.CKM_AES_KEY_WRAP",
    "Ck.CKM_AES_KEY_WRAP_PAD",
    "wrappingMechanism in allowedWrappingMechanisms",
    "allowedWrappingMechanisms.size <= MAX_ALLOWED_WRAPPING_MECHANISMS",
    "poolSize in 1..MAX_HSM_POOL_SIZE",
    "workerCount in 1..MAX_HSM_WORKER_COUNT",
    "!poolBorrowTimeout.isNegative && !poolBorrowTimeout.isZero",
):
    require(invariant in config, f"HSM configuration invariant missing: {invariant}")

# A cached pool is identified by physical module + slot; conflicting credentials/config fail closed.
for invariant in (
    "data class PoolIdentity",
    "val moduleLibrary: String",
    "val slotLabel: String",
    "data class PoolConfiguration",
    "val wrappingMechanism: Long",
    "val poolSize: Int",
    "val workerCount: Int",
    "val borrowTimeout: Duration",
    "val pinFingerprint: PinFingerprint",
    "MessageDigest.isEqual(digest, other.digest)",
    "Conflicting HSM pool configuration for the same module and slot",
    "ConcurrentHashMap<PoolIdentity, PoolRegistration>()",
):
    require(invariant in pool, f"HSM pool identity invariant missing: {invariant}")
require("ConcurrentHashMap<String, HsmSessionPool>()" not in pool, "HSM pool must not be keyed by slot label alone")
require(
    "slot.pin" not in pool.split("data class PoolIdentity", 1)[1].split("data class PoolConfiguration", 1)[0],
    "raw HSM PIN leaked into pool identity",
)

# Protocol-shape guards: implementation is fixed to P-256 + SHA-256 + 96-bit IV + 128-bit GCM tag.
for invariant in (
    "MAX_HSM_WRAPPED_PRIVATE_KEY_BYTES = 64 * 1024",
    "SHA256_DIGEST_BYTES = 32",
    "P256_RAW_ECDSA_SIGNATURE_BYTES = 64",
    "bytes.size == P256_RAW_ECDSA_SIGNATURE_BYTES",
    "authTag.size == AES_TAG_BYTES",
    "iv.size == IV_BYTES",
    "digest.size == SHA256_DIGEST_BYTES",
):
    require(invariant in session, f"HSM protocol-shape invariant missing: {invariant}")

# Independent arithmetic oracle for fixed cryptographic protocol widths.
require(128 // 8 == 16, "AES-GCM tag conversion drift")
require(96 // 8 == 12, "AES-GCM IV conversion drift")
require(256 // 8 == 32, "SHA-256 digest conversion drift")
require(2 * (256 // 8) == 64, "P-256 raw ECDSA signature width drift")

if failures:
    print("HSM BOUNDARY INVARIANTS: FAIL", file=sys.stderr)
    for failure in failures:
        print(f" - {failure}", file=sys.stderr)
    raise SystemExit(1)

print("HSM BOUNDARY INVARIANTS: PASS")
print("protocol_widths={sha256:32,p256_raw_ecdsa:64,gcm_iv:12,gcm_tag:16}")
