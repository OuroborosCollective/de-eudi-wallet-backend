#!/usr/bin/env bash
set -euo pipefail
: "${BC_CLASSPATH:?Supply verified bcprov, bcpkix and bcutil jars in BC_CLASSPATH}"
kotlinc_bin="${KOTLINC:-kotlinc}"
jvm_target="${JVM_TARGET:-17}"
root=$(cd "$(dirname "$0")/.." && pwd)
crypto="$root/src/main/kotlin/de/eudiwallet/backend/shared/crypto"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# This harness needs only the JDK, Kotlin and standard shell tools, not Python.
# Wiring assertions are source evidence, separate from the actual JVM tests.
while IFS= read -r contract; do
  test "$(grep -F -c -- "$contract" "$crypto/Key.kt")" = 1 || {
    echo 'Missing or duplicated canonical key-material wiring' >&2; exit 1;
  }
done <<'CONTRACTS'
fun ByteArray.ecPublicKeyFromX509(): ECPublicKey = WalletKeyMaterial.decodePublicKey(this)
fun ByteArray.ecPrivateKeyFromPkcs8(): ECPrivateKey = WalletKeyMaterial.decodePrivateKey(this)
fun ECPublicKey.toCanonicalP256(): ECPublicKey = WalletKeyMaterial.canonicalP256(this)
ECKey.Builder(RECOMMENDED_EC_CURVE, toCanonicalP256()).build()
WalletKeyMaterial.readPrivateKey(pemPath.inputStream)
WalletKeyMaterial.readCertificate(certificateResource.inputStream)
CONTRACTS
printf '%s\n' 'PASS SOURCE_WIRING_ONLY: six original public key/resource functions'
sha256sum "$crypto/Key.kt" "$crypto/BouncyCastle.kt" "$crypto/WalletKeyMaterial.kt" \
  "$root/security-tests/WalletKeyMaterialRegression.kt"

compile() {
  "$kotlinc_bin" "$crypto/BouncyCastle.kt" "$1" \
    "$root/security-tests/WalletKeyMaterialRegression.kt" \
    -classpath "$BC_CLASSPATH" -jvm-target "$jvm_target" -include-runtime -d "$2"
}
run() {
  java -Xms32m -Xmx192m -cp "$1:$BC_CLASSPATH" \
    de.eudiwallet.backend.shared.crypto.WalletKeyMaterialRegressionKt
}
compile "$crypto/WalletKeyMaterial.kt" "$work/tests.jar"
run "$work/tests.jar"

# Mutation controls must compile successfully and then fail an assertion.
for mutation in domain stream; do
  if test "$mutation" = domain; then
    for target in \
      'parameters.curve == p256.curve &&' \
      'parameters.generator == p256.generator &&' \
      'parameters.order == p256.order &&' \
      'parameters.cofactor == p256.cofactor,'; do
      test "$(grep -F -c -- "$target" "$crypto/WalletKeyMaterial.kt")" = 1 || {
        echo 'Domain mutation target drifted' >&2; exit 1;
      }
    done
    sed \
      -e 's/parameters.curve == p256.curve \&\&/parameters.curve == p256.curve,/' \
      -e '/parameters.generator == p256.generator \&\&/d' \
      -e '/parameters.order == p256.order \&\&/d' \
      -e '/parameters.cofactor == p256.cofactor,/d' \
      "$crypto/WalletKeyMaterial.kt" > "$work/WalletKeyMaterial.kt"
  else
    test "$(grep -F -c 'input.use { stream ->' "$crypto/WalletKeyMaterial.kt")" = 2 || {
      echo 'Stream mutation target drifted' >&2; exit 1;
    }
    sed 's/input.use { stream ->/input.let { stream ->/g' \
      "$crypto/WalletKeyMaterial.kt" > "$work/WalletKeyMaterial.kt"
  fi
  compile "$work/WalletKeyMaterial.kt" "$work/mutated.jar"
  if run "$work/mutated.jar" > "$work/mutation.log" 2>&1; then
    echo "FAIL: security mutation survived: $mutation" >&2; exit 1
  fi
  grep -q 'IllegalStateException' "$work/mutation.log" || {
    cat "$work/mutation.log"; echo 'Mutation did not fail an assertion' >&2; exit 1;
  }
  echo "PASS MUTATION_KILLED: $mutation (compiled successfully, assertion failed at runtime)"
done
printf '%s\n' 'WALLET_KEY_BOUNDARY_GATE_PASS scope=selected_production_key_material_not_whole_backend'
