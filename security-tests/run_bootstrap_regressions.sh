#!/usr/bin/env bash
set -euo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
compiler=${KOTLINC:-kotlinc}
target=${JVM_TARGET:-17}
source_file="$root/src/main/kotlin/de/eudiwallet/backend/shared/WalletBootstrapSecurity.kt"
test_file="$root/security-tests/WalletBootstrapSecurityRegression.kt"
"$compiler" -version
java -version
sha256sum "$source_file" "$test_file"
"$compiler" "$source_file" "$test_file" -jvm-target "$target" -include-runtime -d "$work/tests.jar"
timeout 90 java -Xms32m -Xmx256m -XX:MaxMetaspaceSize=128m \
    -cp "$work/tests.jar" securitytests.WalletBootstrapSecurityRegression

# These are source-wiring assertions, not a full Spring application boot.
entry="$root/src/main/kotlin/de/eudiwallet/backend/WalletBackendApplication.kt"
grep -Fq 'runWalletService<WalletBackendApplication>(args, SERVICE_MODE)' "$entry"
if grep -Eq 'object[[:space:]]+WalletBootstrapSecurity' "$entry"; then
    echo 'FAIL duplicate combined policy' >&2
    exit 1
fi
printf 'PASS combined-source-wiring (static)\n'

# Test sensitivity: compile real mutated validators and require the runtime
# assertions to fail for the intended reason. Never ship either mutation.
for mutation in wildcard side_effect; do
    mutated="$work/WalletBootstrapSecurity.kt"
    if [[ "$mutation" == wildcard ]]; then
        sed 's/securityCheck(!containsWildcard)/securityCheck(true)/' "$source_file" > "$mutated"
        expected='FAIL indexed-management-wildcards'
    else
        sed 's/        validateArguments(arguments)/        pinSpringSecurityProperties()\n        validateArguments(arguments)/' "$source_file" > "$mutated"
        expected='FAIL reject-before-any-property-write'
    fi
    if cmp -s "$source_file" "$mutated"; then
        echo 'FAIL mutation did not change source' >&2; exit 1
    fi
    "$compiler" "$mutated" "$test_file" -jvm-target "$target" -include-runtime -d "$work/mutant.jar"
    set +e
    timeout 90 java -Xms32m -Xmx256m -XX:MaxMetaspaceSize=128m \
        -cp "$work/mutant.jar" securitytests.WalletBootstrapSecurityRegression > "$work/mutant.log" 2>&1
    status=$?
    set -e
    if [[ "$status" != 1 ]] || ! grep -Fq "$expected" "$work/mutant.log"; then
        echo "FAIL mutation was not detected as expected: $mutation" >&2
        cat "$work/mutant.log" >&2
        exit 1
    fi
    printf 'PASS compiled-mutation-detected %s\n' "$mutation"
done
