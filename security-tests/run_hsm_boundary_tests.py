#!/usr/bin/env python3
"""Real production Kotlin boundary tests; no stubs or full-wallet success claim."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
HSM = "src/main/kotlin/de/eudiwallet/backend/shared/hsm/"
SOURCES = [HSM + x for x in ("HsmException.kt", "SlotConfig.kt", "HsmOperationChecks.kt", "pkcs11/PinEncoding.kt")]
TEST = "security-tests/HsmBoundaryRegression.kt"
NATIVE = [HSM + "pkcs11/" + x for x in ("Ck.kt", "Mechanism.kt", "Pkcs11.kt", "Pkcs11Exception.kt", "Pkcs11Ffm.kt", "Template.kt")]
NATIVE_TEST = "security-tests/Pkcs11BoundaryIntegration.kt"
MAIN = "de.eudiwallet.backend.shared.hsm.HsmBoundaryRegressionKt"
NATIVE_MAIN = "de.eudiwallet.backend.shared.hsm.pkcs11.Pkcs11BoundaryIntegrationKt"


def run(command, timeout=120):
    return subprocess.run(command, cwd=ROOT, text=True, capture_output=True, timeout=timeout, check=False)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def wiring():
    session = (ROOT / HSM / "HsmSession.kt").read_text()
    pool = (ROOT / HSM / "HsmSessionPool.kt").read_text()
    native = (ROOT / HSM / "pkcs11/Pkcs11Ffm.kt").read_text()
    login = native.split("override fun login(", 1)[1].split("override fun logout", 1)[0]
    signing = session.split("fun signWithWrappedKey(", 1)[1].split("fun signEcdsaSha256", 1)[0]
    decrypt = session.split("fun decrypt(", 1)[1].split("fun <T : HsmKeyRef>", 1)[0]
    checks = {
        "pin_no_immutable_string_or_spread_copy": "String(pin)" not in login and "*pinBytes" not in login,
        "pin_encoder_and_native_wipe": "withUtf8Pin(pin)" in login and "pinSegment.fill(0)" in login,
        "pin_caller_chars_cleared": "pin.fill('\\u0000')" in pool,
        "digest_guard_before_lookup_and_unwrap": signing.index("requireSha256Digest") < signing.index("getKey(") < signing.index("unwrapWithMasterKey("),
        "ecdsa_result_shape_gate": "requireP256Signature(signature)" in session,
        "hmac_result_shape_gate": ".also(HsmOperationChecks::requireSha256Mac)" in session,
        "gcm_shape_before_native_decrypt": decrypt.index("requireGcmDecryptionShape") < decrypt.index("pkcs11.decrypt("),
        "single_slot_config_definition": sum(p.read_text().count("data class SlotConfig(") for p in (ROOT / "src/main/kotlin").rglob("*.kt")) == 1,
    }
    if not all(checks.values()):
        raise RuntimeError("Source wiring check failed: " + ",".join(k for k, v in checks.items() if not v))
    return checks


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--native-library", type=Path)
    parser.add_argument("--mutations", action="store_true")
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    report = {"scope": "production boundary helpers; optional real SoftHSM PKCS11 adapter", "fullWalletBuild": "NOT_RUN", "hardwareHsm": "NOT_RUN", "sonarQube": "NOT_RUN", "nativeIntegration": "NOT_REQUESTED", "status": "FAIL"}
    try:
        compiler, java = shutil.which("kotlinc"), shutil.which("java")
        if not compiler or not java:
            raise RuntimeError("Real kotlinc and java executables are required")
        report["compiler"] = run([compiler, "-version"]).stderr.strip()
        report["jvm"] = run([java, "-version"]).stderr.strip()
        report["sourceWiringStaticOnly"] = wiring()
        revision = run(["git", "rev-parse", "HEAD"])
        report["checkoutRevision"] = revision.stdout.strip() if revision.returncode == 0 else None
        report["githubHeadRevision"] = os.getenv("EXPECTED_HEAD_SHA")
        all_sources = SOURCES + [TEST]
        if args.native_library:
            if not args.native_library.is_file():
                raise RuntimeError("Requested SoftHSM library is missing")
            all_sources += NATIVE + [NATIVE_TEST]
            report["nativeLibrarySha256"] = sha(args.native_library)
        report["sourceSha256"] = {p: sha(ROOT / p) for p in all_sources}
        with tempfile.TemporaryDirectory(prefix="wallet-boundary-") as tmp:
            jar = str(Path(tmp) / "tests.jar")
            result = run([compiler, *[str(ROOT / p) for p in all_sources], "-opt-in=kotlin.ExperimentalStdlibApi", "-include-runtime", "-d", jar])
            (args.output / "compile.log").write_text(result.stdout + result.stderr)
            if result.returncode:
                raise RuntimeError("Production boundary compilation failed; see compile.log")
            result = run([java, "-Xmx256m", "-cp", jar, MAIN])
            (args.output / "runtime.log").write_text(result.stdout + result.stderr)
            if result.returncode:
                raise RuntimeError("Boundary runtime tests failed; see runtime.log")
            match = re.search(r"HSM_BOUNDARY_TESTS_PASS checks=(\d+)", result.stdout)
            if not match:
                raise RuntimeError("Boundary test receipt missing")
            report["checks"] = int(match.group(1))
            report["boundaryRuntime"] = "PASS"
            if args.native_library:
                result = run([java, "-Xmx256m", "--enable-native-access=ALL-UNNAMED", "-cp", jar, NATIVE_MAIN, str(args.native_library)])
                (args.output / "native.log").write_text(result.stdout + result.stderr)
                if result.returncode or "PKCS11_SOFTHSM_PASS" not in result.stdout:
                    raise RuntimeError("Real SoftHSM integration failed; see native.log")
                report["nativeIntegration"] = "PASS_SOFTWARE_PKCS11_NOT_HARDWARE"
            if args.mutations:
                mutants = [
                    ("pin_text_leak", "SlotConfig.kt", "pin=[REDACTED]", "pin=$pin"),
                    ("pin_bytes_not_cleared", "pkcs11/PinEncoding.kt", "bytes.fill(0)", "bytes.fill(1)"),
                    ("digest_guard_disabled", "HsmOperationChecks.kt", "digest.size != SHA256_BYTES", "false"),
                    ("zero_r_accepted", "HsmOperationChecks.kt", "r.signum() <= 0 || r >= p256Order", "r >= p256Order"),
                    ("mac_output_guard_disabled", "HsmOperationChecks.kt", "!isSha256Mac(mac)", "false"),
                    ("gcm_tag_guard_disabled", "HsmOperationChecks.kt", "tag.size != GCM_TAG_BYTES", "false"),
                ]
                report["mutationTests"] = {}
                for name, relative, old, new in mutants:
                    source_path = HSM + relative
                    text = (ROOT / source_path).read_text()
                    if text.count(old) != 1:
                        raise RuntimeError("Mutation target missing or ambiguous: " + name)
                    changed = Path(tmp) / relative
                    changed.parent.mkdir(parents=True, exist_ok=True)
                    changed.write_text(text.replace(old, new))
                    mutated_jar = str(Path(tmp) / (name + ".jar"))
                    result = run([compiler, str(changed), "-cp", jar, "-Xfriend-paths=" + jar, "-d", mutated_jar])
                    if result.returncode:
                        raise RuntimeError("Mutant did not compile; not counted as detected: " + name)
                    result = run([java, "-Xmx256m", "-cp", mutated_jar + os.pathsep + jar, MAIN])
                    (args.output / (name + ".log")).write_text(result.stdout + result.stderr)
                    if result.returncode == 0:
                        raise RuntimeError("Mutation survived: " + name)
                    report["mutationTests"][name] = "COMPILED_AND_REJECTED_BY_TESTS"
                    print("MUTATION_KILLED " + name, flush=True)
        report["status"] = "PASS_BOUNDED_SCOPE"
    except (RuntimeError, ValueError, OSError, subprocess.TimeoutExpired) as error:
        report["error"] = str(error)
    finally:
        (args.output / "receipt.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report, sort_keys=True))
    return 0 if report["status"] == "PASS_BOUNDED_SCOPE" else 1


if __name__ == "__main__":
    sys.exit(main())
