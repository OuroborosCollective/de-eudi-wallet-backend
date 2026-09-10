#!/usr/bin/env python3
"""Fail-closed source invariants runnable without the unpublished build system."""
from pathlib import Path
import re
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

# Documentation stubs must remain unreachable as runtime profiles.
require('stubCertifiedKeySource()' in (BACKEND / "mdvm/MdvmConfiguration.kt").read_text(encoding="utf-8"), "expected docs stub moved; review profile gate")
require('"build-docs"' in policy, "build-docs runtime rejection missing")

if failures:
    print("SECURITY INVARIANTS: FAIL", file=sys.stderr)
    for failure in failures:
        print(f" - {failure}", file=sys.stderr)
    raise SystemExit(1)

print("SECURITY INVARIANTS: PASS")
