#!/bin/bash
# Run AsyncSan demo through oss-fuzz infrastructure.
# Usage: bash tools/oss-fuzz/run_ossfuzz.sh
#
# Prerequisites: docker, ~/oss-fuzz cloned, ~/llvm-project built

set -eu

OSS_FUZZ_DIR=~/oss-fuzz
PROJECT=asyncsan-demo
PROJECT_DIR="$OSS_FUZZ_DIR/projects/$PROJECT"

echo "[1/4] Setting up oss-fuzz project..."
mkdir -p "$PROJECT_DIR"
cp ~/llvm-project/tools/oss-fuzz/asyncsan-demo/* "$PROJECT_DIR/"
chmod +x "$PROJECT_DIR/build.sh"

echo "[2/4] Building Docker image (this builds LLVM — may take 1-2 hours first time)..."
cd "$OSS_FUZZ_DIR"
python3 infra/helper.py build_image "$PROJECT"

echo "[3/4] Building fuzz targets..."
python3 infra/helper.py build_fuzzers --sanitizer address "$PROJECT"

echo "[4/4] Running fuzzer (30 seconds)..."
timeout 35 python3 infra/helper.py run_fuzzer "$PROJECT" fuzz_signal_handler \
    -- -max_total_time=30 -print_final_stats=1 2>&1 || true

echo ""
echo "=== Check output above for AsyncSan signal-safety violations ==="
echo "Build artifacts in: $OSS_FUZZ_DIR/build/out/$PROJECT/"
