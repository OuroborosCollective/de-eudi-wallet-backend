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
"$KOTLINC" -version
"$JAVA" -version
sha256sum src/main/kotlin/de/eudiwallet/backend/statuslist/StatusListCodec.kt \
  security-tests/StatusListCodecRegression.kt security-tests/run_codec_regressions.sh
"$KOTLINC" -jvm-target "$JVM_TARGET" \
  src/main/kotlin/de/eudiwallet/backend/statuslist/StatusListCodec.kt \
  security-tests/StatusListCodecRegression.kt \
  -include-runtime -d "$BUILD_DIR/codec-regressions.jar"
"$JAVA" -Xmx128m -cp "$BUILD_DIR/codec-regressions.jar" securitytests.StatusListCodecRegression
