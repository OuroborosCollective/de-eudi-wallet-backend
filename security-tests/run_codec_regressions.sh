#!/usr/bin/env bash
# Focused JVM regression lane, not a replacement for the unpublished backend build.
set -euo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
KOTLINC=${KOTLINC:-kotlinc}
JAVA=${JAVA_HOME:+$JAVA_HOME/bin/}java
JVM_TARGET=${JVM_TARGET:-17}
BUILD_DIR=$(mktemp -d "${TMPDIR:-/tmp}/wallet-codec.XXXXXXXX")
trap 'rm -rf -- "$BUILD_DIR"' EXIT
cd "$ROOT"
KOTLIN_BIN=$(command -v "$KOTLINC")
KOTLIN_LIB=$(cd -- "$(dirname -- "$(readlink -f "$KOTLIN_BIN")")/../lib" && pwd)
"$KOTLINC" -version
"$JAVA" -version
sha256sum src/main/kotlin/de/eudiwallet/backend/statuslist/StatusListCodec.kt \
  security-tests/StatusListCodecRegression.kt security-tests/run_codec_regressions.sh \
  src/main/kotlin/de/eudiwallet/backend/mdvm/MdvmAccount.kt \
  security-tests/MdvmSourceIntegrityRegression.kt
"$KOTLINC" -jvm-target "$JVM_TARGET" \
  src/main/kotlin/de/eudiwallet/backend/statuslist/StatusListCodec.kt \
  security-tests/StatusListCodecRegression.kt \
  -include-runtime -d "$BUILD_DIR/codec-regressions.jar"
"$JAVA" -Xmx128m -cp "$BUILD_DIR/codec-regressions.jar" securitytests.StatusListCodecRegression
# Parse the real MDVM source. This is syntax/declaration integrity, NOT full type checking.
# Compiler API opt-ins apply ONLY to this isolated parser harness, never to production.
"$KOTLINC" -jvm-target "$JVM_TARGET" -cp "$KOTLIN_LIB/kotlin-compiler.jar" \
  -opt-in=org.jetbrains.kotlin.K1Deprecation \
  -opt-in=org.jetbrains.kotlin.config.CompilerConfiguration.Internals \
  security-tests/MdvmSourceIntegrityRegression.kt -d "$BUILD_DIR/mdvm-source-tests.jar"
"$JAVA" -Xmx256m -cp "$BUILD_DIR/mdvm-source-tests.jar:$KOTLIN_LIB/*" \
  securitytests.MdvmSourceIntegrityRegression src/main/kotlin/de/eudiwallet/backend/mdvm/MdvmAccount.kt
