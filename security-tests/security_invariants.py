#!/usr/bin/env python3
"""Fail-closed source invariants runnable without the unpublished build system."""
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "src/main/kotlin/de/eudiwallet/backend"
failures = []


def require(condition: bool, message: str) -> None:
    if not condition:
        failures.append(message)


service = (BACKEND / "shared/ServiceBootstrap.kt").read_text(encoding="utf-8")
policy = (BACKEND / "shared/WalletBootstrapSecurity.kt").read_text(encoding="utf-8")
bc = (BACKEND / "shared/crypto/BouncyCastle.kt").read_text(encoding="utf-8")
hsm_key = (BACKEND / "shared/hsm/HsmKey.kt").read_text(encoding="utf-8")
hsm_session = (BACKEND / "shared/hsm/HsmSession.kt").read_text(encoding="utf-8")
symmetric_lineage = (BACKEND / "shared/keyrollover/SymmetricKeyLineage.kt").read_text(encoding="utf-8")
asymmetric_lineage = (BACKEND / "shared/keyrollover/AsymmetricSigningLineage.kt").read_text(encoding="utf-8")

# All product entry points converge on runWalletService; security is enforced there.
for path in BACKEND.glob("*Application.kt"):
    text = path.read_text(encoding="utf-8")
    if "fun main(" in text:
        require("runWalletService<" in text, f"{path.name}: bypasses shared service bootstrap")

require("WalletBootstrapSecurity.validateAndCopy(args, profile)" in service, "shared bootstrap validation missing")
require("validatePreparedEnvironment(" in service, "prepared-environment validation missing")
require("Security.removeProvider" not in bc, "provider list must not mutate while BouncyCastle.kt loads")
require("Security.insertProviderAt" not in bc, "provider order must not mutate while BouncyCastle.kt loads")

for invariant in (
    "requireEquivalentProvider(existing, bundled)",
    "existing.javaClass.classLoader === bundled.javaClass.classLoader",
    "existing.versionStr == bundled.versionStr",
    "existingSource == bundledSource",
    "Security.getProvider(EXPECTED_BC_PROVIDER_NAME) === bundled",
):
    require(invariant in service, f"provider provenance invariant missing: {invariant}")

for invariant in (
    'PinnedProperty("spring.main.allow-bean-definition-overriding", "false")',
    'PinnedProperty("spring.main.allow-circular-references", "false")',
    'PinnedProperty("spring.jmx.enabled", "false")',
    'PinnedProperty("management.endpoint.shutdown.enabled", "false")',
    'System.getenv("SPRING_APPLICATION_JSON").isNullOrBlank()',
    'forbiddenRuntimeProfiles = setOf("build-docs")',
    'normalized.startsWith("-agentlib:jdwp")',
    'normalized.startsWith("-xrunjdwp")',
):
    require(invariant in policy, f"bootstrap invariant missing: {invariant}")

# HSM/key-lineage validity must be host-timezone-independent and fail closed.
require("ZoneOffset.UTC" in hsm_key, "HSM validity is not explicitly canonicalized to UTC")
for path_name, text in (
    ("HsmKey.kt", hsm_key),
    ("HsmSession.kt", hsm_session),
    ("SymmetricKeyLineage.kt", symmetric_lineage),
    ("AsymmetricSigningLineage.kt", asymmetric_lineage),
):
    require("TimeZone.getDefault" not in text, f"{path_name}: host default timezone leaks into key validity")
    require("ZoneId.systemDefault" not in text, f"{path_name}: host default timezone leaks into key validity")

require("!startDate.isAfter(on) && !endDate.isBefore(on)" in hsm_key, "HSM active-key interval is incomplete")
require(".filter { it.isActiveAt(validityDate) }" in hsm_session, "HSM scan can return inactive/future keys")
require("limit = 2" in hsm_session, "HSM key lookup cannot detect duplicate key identities")
require(
    "Multiple HSM objects match the same key ID and class" in hsm_session,
    "ambiguous HSM key identity is not rejected",
)
require("check(primary.isActiveAt(Instant.now()))" in symmetric_lineage, "symmetric primary can outlive validity")
require("held.compareAndSet(heldSet, null)" in symmetric_lineage, "expired symmetric key is not disabled")
require(
    "signing key is outside its declared validity window" in asymmetric_lineage,
    "asymmetric signing key can outlive validity",
)
require("held.compareAndSet(heldKey, null)" in asymmetric_lineage, "expired signing key is not disabled")
require(
    "now signing with an expired key" not in symmetric_lineage + asymmetric_lineage,
    "key lineage still explicitly permits expired cryptographic use",
)

# Documentation stubs must remain unreachable as runtime profiles.
require(
    "stubCertifiedKeySource()" in (BACKEND / "mdvm/MdvmConfiguration.kt").read_text(encoding="utf-8"),
    "expected docs stub moved; review profile gate",
)
require('"build-docs"' in policy, "build-docs runtime rejection missing")

if failures:
    print("SECURITY INVARIANTS: FAIL", file=sys.stderr)
    for failure in failures:
        print(f" - {failure}", file=sys.stderr)
    raise SystemExit(1)

print("SECURITY INVARIANTS: PASS")
