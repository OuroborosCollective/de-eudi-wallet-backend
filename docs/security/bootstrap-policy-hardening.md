# Bootstrap policy: alias, index and rejection-state regression

## Scope and authority

This is a defensive change to the owner's `OuroborosCollective/de-eudi-wallet-backend`
fork, targeting `patch-1`. It does not authorize deployment, access to customer data,
account operations, third-party testing, production lockdown, billing or secret changes.
There is no automatic merge-to-main or unbounded agent loop in this change.

## Reproduced findings

The pre-change production policy (Git blob `98d15182568678b4ab46fc2c045a3872fe752806`)
accepted compact reserved-property aliases and indexed variants of blocked source,
profile and wildcard-exposure options. An invalid startup could also mutate JVM
properties before rejection, and duplicate-option errors included untrusted key names.
These are startup-policy failures, not evidence of a remote account compromise,
a malicious backdoor, or malicious developer intent.

## Changes

A conservative, locale-independent policy fingerprint makes separator/case variants
of reserved names comparable. Indexed option roots receive the same reserved-list
policy, scalar pins reject indexed variants, and indexed secret fields are rejected.
Accepted argument bytes are preserved; this is NOT a replacement for Spring binding.
All validation completes before the pinning stage, and all JVM pin conflicts are
checked under the Properties monitor before any pin is written. Oversized input is
rejected before UTF-8 allocation. Rejection messages no longer echo arbitrary key names.
The combined entrypoint delegates to the already-shared `runWalletService`, removing
the older duplicate policy rather than maintaining two divergent security paths.

## Evidence and limits

Run `bash security-tests/run_bootstrap_regressions.sh`. The suite compiles and executes
the real production Kotlin policy without stubs: safe cases, negative cases, all five
service-profile identifiers, 5,000 seeded policy aliases and 256 concurrent validations.
Two separately compiled mutations must fail the intended assertions. The combined
entrypoint check is a static wiring assertion, explicitly not a Spring runtime test.

The focused tests do not prove complete Spring 4.1.1 binding behavior, five running
applications, HSM integration, database isolation, live network policy or absence of
all vulnerabilities. Hostile code with control of the JVM can replace global properties;
this policy is not an in-process sandbox. Process isolation, user authorization,
anti-replay transactions, signing consent and deployment integrity need separate tests.
See `security-tests/evidence/bootstrap-policy-local-2026-09-10.json` for local results.
