# Wallet key-material boundary: scope and evidence

## Change

The public functions remain in `shared/crypto/Key.kt` with their existing names and JVM file facade. They now delegate to `WalletKeyMaterial`, a small input boundary using the real bundled Bouncy Castle provider. This patch does not register providers or change HSM configuration.

Wallet public keys must match the complete P-256 domain (field/curve, generator, order, cofactor), be finite and on-curve, and have field-bounded coordinates. Domain and coordinate checks precede arithmetic. Public DER is bounded to 2 KiB before parsing. Private DER is bounded to 16 KiB; private PEM and certificate resources to 64 KiB before parsing. These are local parser budgets, not HTTP request-size or execution-time guarantees.

The private-key reader accepts unencrypted PKCS#8 `PrivateKeyInfo` and the already-supported SEC1 `PEMKeyPair` form. It rejects other or multiple PEM objects, owns/closes streams on success and failure, and clears temporary byte arrays on a best-effort basis. This does not guarantee removal of copies held by the parser, provider, JVM or operating system. Certificate reads use a per-call factory and close their streams; they do not replace certificate-chain or revocation verification.

## Reproduced findings, not allegations

The previous PKCS#8 reader cast every parsed object to `PEMKeyPair`; the real parser returns `PrivateKeyInfo` for PKCS#8. The old canonicalizer compared only the curve equation before replacing other domain parameters. Certificate resource streams were not explicitly closed by `readX509Cert`. These findings do not establish intentional backdoors or account takeover.

## Actual test scope

`run_wallet_key_regressions.sh` compiles the actual `WalletKeyMaterial.kt` and `BouncyCastle.kt`, with actual BC jars. It runs 25 groups including real signing/verification, 64 independent key roundtrips, 1,000 malformed DER inputs, 256 parallel operations, bounds and resource-close failures. Two independently compiled mutations (curve-only validation and missing stream closure) must fail runtime assertions. Malformed input fixtures do not replace cryptographic verification.

The six public wrapper connections in `Key.kt` are checked separately as SOURCE_WIRING_ONLY. This is not a full compile of the facade or backend. Local execution: Kotlin 1.9.0, OpenJDK 21.0.11, packaged BC 1.80. The dedicated CI uses checksum-pinned Kotlin 2.4.10/BC 1.85 and a JDK 25 Docker runtime, recording the exact source and resolved image identity. The Docker test has no network, runs non-root, uses a read-only root/source tree and bounded resources. Its image identity is test evidence, not a production attestation.

## Release boundary and remaining work

A component PASS is not a release approval or a claim of zero vulnerabilities. The published repository does not supply the complete original build, production configuration and customer-facing environment. Full facade/backend compilation, actual Postgres/HSM integration, authorized/revoked-account races, one-time action consent, recovery/admin permissions, attestation trust chains, client integrity, timing analysis and deployment provenance require separate tests with the corresponding real dependencies. Four complete clean architecture rounds have NOT been performed.

This is an identity-wallet backend; this change does not demonstrate custody or protection of customer bank funds. No universal access exception, hidden administrative account, new encryption scheme or obfuscation layer is added. Strong user authorization should bind the identity, operation, object, request digest, audience, expiry and replay state and be enforced again at the effect boundary. That is an acceptance requirement for subsequent integration, not a claim implemented by this parser patch.

The isolated change targets the owner's `patch-1` branch only. Merge must follow same-head CI review and an unchanged-base check; main and production deployment are outside this patch. No Docker cluster was locked down. Wolfram's current requests failed externally; no formal Wolfram PASS or SonarQube scan is claimed.

## Primary references

- Bouncy Castle PEMParser API: https://downloads.bouncycastle.org/java/docs/bcpkix-jdk18on-javadoc/org/bouncycastle/openssl/PEMParser.html
- Java ECParameterSpec API: https://docs.oracle.com/en/java/javase/25/docs/api/java.base/java/security/spec/ECParameterSpec.html
- Dependency hashes: Maven Central `org/bouncycastle/{bcprov,bcpkix,bcutil}-jdk18on/1.85/*.jar.sha256`; hardcoded in the CI workflow, not trusted from test output.
