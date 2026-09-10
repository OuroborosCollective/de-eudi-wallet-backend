# HSM boundary hardening — run 3

## Scope and provenance

Baseline: `7a6f0443a16e449084605351361545406ded6d38` on `patch-1`.
The uploaded ZIP has SHA-256 `6a7dd2bf61b77720ca3aabd8f168dce4faa417be255131c99f5964e371cedfde`.
The modified existing HSM files were checked against exact GitHub blob identities; no older ZIP tree is being restored over GitHub.

## Findings and changes

1. `SlotConfig` previously generated a `toString` containing its PIN. The original declaration compiled and failed a non-disclosure regression. The class is now in its own dependency-free source file with a redacted `toString`; constructor, component and copy contracts are retained.
2. Native login previously constructed `String(pin)` and a Kotlin spread-copy. `withUtf8Pin` encodes without a String, rejects malformed UTF-16, and clears both temporary byte arrays in finally paths. `Pkcs11Ffm` copies into native memory without a spread-copy and clears that buffer. The pool clears its temporary CharArray and closes opened sessions on encoding failures as well as PKCS11 exceptions. The original configuration String and runtime/GC copies cannot be guaranteed erased.
3. SHA-256 digest length is checked before unwrap/sign; raw P-256 signatures are checked for 64-byte encoding and scalar range; HS256 output length and GCM IV/tag/output shapes are checked. These are boundary invariants, NOT proof of signature validity, authenticity, key provenance, or constant-time execution. The RWSCA HTTP endpoint already checked digest length: this is internal defense in depth, not a claimed remote bypass.

Valid high-S ECDSA signatures, empty GCM plaintext, Unicode PINs, and the wrapping flow remain supported. `CKA_EXTRACTABLE=true` on keys that need C_WrapKey was deliberately not disabled. No crypto algorithm was replaced, and no production token or deployment was contacted.

## Executed locally

`python3 security-tests/run_hsm_boundary_tests.py --output /tmp/hsm-evidence --mutations`

Kotlin 1.9.0 / JDK 21.0.11: 11,224 checks passed, including 10,000 finite public-input fuzz cases, 32 real JCA ECDSA signature cases (both S forms), and five real AES-GCM roundtrips with tamper rejection. All six deliberately weakened, separately compiled mutants were rejected by tests. This compiles the real boundary sources, not stubbed Spring/HSM types. The source-wiring checks are explicitly static-only.

The local receipt records hashes and the actual toolchain; a null checkoutRevision honestly means local ZIP-derived files, not a live Git checkout. The compiler and JDK are older than the production catalog: the CI uses the catalog's Kotlin 2.4.10 and JDK 25.

## Added CI, not pre-claimed

The new workflow checks out the exact PR/push head, verifies the Kotlin compiler archive against the digest in the official JetBrains release, and runs the production PKCS11 FFM adapter against a disposable SoftHSM token. Native cases cover wrong-PIN rejection, login, repeated login, real token ECDSA generation/sign/verify and changed-digest rejection. Only logs/receipts are uploaded, never token state. SoftHSM is a software PKCS11 implementation, not hardware assurance. An actual CI receipt is required before calling this native lane successful.

## Remaining evidence gaps

Full Spring wallet compile, DB migrations/transactions, hardware-HSM compatibility, production deployment/readback, protocol E2E, full-module fuzzing, memory-forensics and timing/side-channel analysis remain unproven. The source mirror lacks its complete build/deployment inputs. Do not infer a zero-vulnerability result from these tests or increment the four-full-clean-round counter.

SonarQube analysis was not executed: no SonarQube action was discoverable and no sonar CLI exists in the local environment. Wolfram Context/Language calls returned network_error; no formal Wolfram PASS is claimed. Elevate Invoices has no security-analysis action and no invoice data was accessed. Agent consent is task-scoped to this repository; no secrets, account setup, spending or production administration was performed.

## Primary references

- OASIS PKCS11 3.1: https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html
- OASIS ECDSA mechanisms: https://docs.oasis-open.org/pkcs11/pkcs11-curr/v3.0/pkcs11-curr-v3.0.html
- Kotlin data classes: https://kotlinlang.org/docs/data-classes.html
- Java Signature API: https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/security/Signature.html
- Official Kotlin release used by CI: https://github.com/JetBrains/kotlin/releases/tag/v2.4.10
