#!/bin/bash
# Run AsyncSan fuzz target through oss-fuzz with host's pre-built clang.
# Mounts ~/llvm-project/build as /src/llvm-build inside container.
set -eu

OSS_FUZZ=~/oss-fuzz
PROJECT=asyncsan-demo
LLVM_BUILD=~/llvm-project/build
OUT_DIR="$OSS_FUZZ/build/out/$PROJECT"
WORK_DIR="$OSS_FUZZ/build/work/$PROJECT"

mkdir -p "$OUT_DIR" "$WORK_DIR"

echo "[1/3] Copying project files + building image..."
mkdir -p "$OSS_FUZZ/projects/$PROJECT"
cp ~/llvm-project/tools/oss-fuzz/asyncsan-demo/* "$OSS_FUZZ/projects/$PROJECT/"
chmod +x "$OSS_FUZZ/projects/$PROJECT/build.sh"
cd "$OSS_FUZZ"
python3 infra/helper.py build_image "$PROJECT" --no-pull

echo "[2/3] Building fuzz targets (mounting host clang)..."
docker run --rm \
    -v "$LLVM_BUILD:/src/llvm-build:ro" \
    -v "$OUT_DIR:/out" \
    -v "$WORK_DIR:/work" \
    -e FUZZING_ENGINE=libfuzzer \
    -e SANITIZER=address \
    -e ARCHITECTURE=x86_64 \
    -e PROJECT_NAME="$PROJECT" \
    -e FUZZING_LANGUAGE=c++ \
    -e LIB_FUZZING_ENGINE=/usr/lib/libFuzzingEngine.a \
    -t gcr.io/oss-fuzz/"$PROJECT" \
    bash -c "compile_libfuzzer && bash /src/build.sh"

echo "[3/3] Running fuzzer (30 seconds)..."
docker run --rm \
    -v "$OUT_DIR:/out" \
    -v "$WORK_DIR:/work" \
    -e ASAN_OPTIONS=detect_signal_unsafe_writes=1 \
    -t gcr.io/oss-fuzz-base/base-runner \
    bash -c "timeout 30 /out/fuzz_signal_handler -max_total_time=25 -print_final_stats=1 2>&1 || true"

echo ""
echo "=== Done ==="
ls -la "$OUT_DIR/"
