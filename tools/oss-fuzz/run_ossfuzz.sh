#!/bin/bash
# Run AsyncSan fuzz target through oss-fuzz with host's pre-built clang.
# No LLVM build inside Docker — mounts ~/llvm-project/build instead.
#
# Usage: bash ~/llvm-project/tools/oss-fuzz/run_ossfuzz.sh

set -eu

OSS_FUZZ=~/oss-fuzz
PROJECT=asyncsan-demo
LLVM_BUILD=~/llvm-project/build

echo "[1/4] Copying project files..."
mkdir -p "$OSS_FUZZ/projects/$PROJECT"
cp ~/llvm-project/tools/oss-fuzz/asyncsan-demo/* "$OSS_FUZZ/projects/$PROJECT/"
chmod +x "$OSS_FUZZ/projects/$PROJECT/build.sh"

echo "[2/4] Building Docker image (lightweight — no LLVM build)..."
cd "$OSS_FUZZ"
python3 infra/helper.py build_image "$PROJECT"

echo "[3/4] Building fuzz targets (mounting host clang)..."
python3 infra/helper.py build_fuzzers --sanitizer address "$PROJECT" \
    -e "CC=/src/llvm-build/bin/clang" \
    -e "CXX=/src/llvm-build/bin/clang++" \
    -- --volume "$LLVM_BUILD:/src/llvm-build:ro"

echo "[4/4] Running fuzzer (30 seconds)..."
timeout 40 python3 infra/helper.py run_fuzzer "$PROJECT" fuzz_signal_handler \
    -- -max_total_time=30 -print_final_stats=1 2>&1 || true

echo ""
echo "=== Done. Check output above for AsyncSan violations ==="
