#!/bin/bash
# Run AsyncSan on an oss-fuzz project.
#
# Prerequisites:
#   - Docker running
#   - oss-fuzz repo cloned
#   - AsyncSan base-builder image built (or will be built)
#
# Usage:
#   ./run-asyncsan-ossfuzz.sh <project-name> [fuzz-target] [duration]
#
# Examples:
#   ./run-asyncsan-ossfuzz.sh openssh          # build + qualify all targets
#   ./run-asyncsan-ossfuzz.sh openssh kex_fuzz 60   # fuzz kex_fuzz for 60s
#
# Environment:
#   OSS_FUZZ_DIR   — path to oss-fuzz checkout (default: /tmp/oss-fuzz)
#   ASYNCSAN_IMAGE — base-builder image name (default: asyncsan-base-builder)
#   LLVM_REPO      — LLVM fork URL for building custom clang

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT="${1:?Usage: $0 <project-name> [fuzz-target] [duration]}"
FUZZ_TARGET="${2:-}"
DURATION="${3:-30}"

: "${OSS_FUZZ_DIR:=/tmp/oss-fuzz}"
: "${ASYNCSAN_IMAGE:=asyncsan-base-builder}"
: "${LLVM_REPO:=https://github.com/SmitVaishanav/llvm-project.git}"

if [[ ! -d "$OSS_FUZZ_DIR/projects/$PROJECT" ]]; then
    echo "error: project '$PROJECT' not found in $OSS_FUZZ_DIR/projects/" >&2
    echo "Available projects with signal handlers:" >&2
    ls "$OSS_FUZZ_DIR/projects/" | grep -E 'openssh|redis|nginx|postgres|bash|screen|tmux' 2>/dev/null || true
    exit 1
fi

echo "==== AsyncSan oss-fuzz Pipeline ===="
echo "  Project:    $PROJECT"
echo "  oss-fuzz:   $OSS_FUZZ_DIR"
echo "  Base image: $ASYNCSAN_IMAGE"
echo

# --- Step 1: Build AsyncSan base-builder image (if needed) ---
if ! docker image inspect "$ASYNCSAN_IMAGE" &>/dev/null; then
    echo "==== Step 1: Building AsyncSan base-builder image ===="
    echo "  This builds LLVM/Clang from $LLVM_REPO — may take 30+ minutes"
    docker build \
        -t "$ASYNCSAN_IMAGE" \
        -f "$SCRIPT_DIR/asyncsan-base-builder.Dockerfile" \
        --build-arg LLVM_REPO="$LLVM_REPO" \
        "$SCRIPT_DIR"
    echo "  Base image built."
else
    echo "==== Step 1: Base image exists, skipping ===="
fi
echo

# --- Step 2: Build project with AsyncSan ---
echo "==== Step 2: Building $PROJECT with AsyncSan ===="

# Create modified Dockerfile that uses our base image
TEMP_DIR=$(mktemp -d)
trap "rm -rf $TEMP_DIR" EXIT

# Copy project files
cp -r "$OSS_FUZZ_DIR/projects/$PROJECT/." "$TEMP_DIR/"

# Replace base image in Dockerfile
sed -i.bak "s|FROM gcr.io/oss-fuzz-base/base-builder.*|FROM $ASYNCSAN_IMAGE|" "$TEMP_DIR/Dockerfile"

# Inject AsyncSan flags into build.sh
# Add flag injection at the top of build.sh (after shebang)
if [[ -f "$TEMP_DIR/build.sh" ]]; then
    INJECT='# AsyncSan: inject signal-safety instrumentation flags
if [[ "${SANITIZER:-address}" == "address" ]]; then
    ASYNCSAN_FLAGS="-mllvm -asan-detect-signal-unsafe-calls -mllvm -asan-detect-signal-unsafe-writes -mllvm -asan-detect-signal-unsafe-gep-writes"
    export CFLAGS="${CFLAGS:-} ${ASYNCSAN_FLAGS}"
    export CXXFLAGS="${CXXFLAGS:-} ${ASYNCSAN_FLAGS}"
    echo "[AsyncSan] Signal-safety instrumentation enabled"
fi'
    # Insert after first line (shebang)
    sed -i.bak "1 a\\
$(echo "$INJECT" | sed 's/$/\\/' | sed '$ s/\\$//')" "$TEMP_DIR/build.sh"
fi

# Build the project image
PROJECT_IMAGE="asyncsan-$PROJECT"
docker build -t "$PROJECT_IMAGE" "$TEMP_DIR"

# Build fuzzers
echo "  Building fuzzers..."
docker run --rm \
    -v "$TEMP_DIR/out:/out" \
    -e SANITIZER=address \
    -e FUZZING_ENGINE=libfuzzer \
    "$PROJECT_IMAGE" \
    bash -c "source /asyncsan-compile 2>/dev/null; compile"

echo "  Fuzzers built to $TEMP_DIR/out/"
ls "$TEMP_DIR/out/" 2>/dev/null | head -20
echo

# --- Step 3: Qualify binaries with angr ---
echo "==== Step 3: Qualifying fuzz targets ===="
FUZZ_TARGETS=()
for binary in "$TEMP_DIR/out/"*; do
    if file "$binary" | grep -q 'ELF.*executable'; then
        echo "  Qualifying: $(basename $binary)"
        python3 "$SCRIPT_DIR/../asyncsan-qualify.py" "$binary" 2>/dev/null || true
        FUZZ_TARGETS+=("$binary")
    fi
done

if [[ ${#FUZZ_TARGETS[@]} -eq 0 ]]; then
    echo "  No ELF binaries found in output."
    exit 1
fi
echo

# --- Step 4: Fuzz (if target specified) ---
if [[ -n "$FUZZ_TARGET" ]]; then
    echo "==== Step 4: Fuzzing $FUZZ_TARGET for ${DURATION}s ===="
    TARGET_BINARY="$TEMP_DIR/out/$FUZZ_TARGET"
    if [[ ! -f "$TARGET_BINARY" ]]; then
        echo "error: target '$FUZZ_TARGET' not found" >&2
        echo "Available targets:"
        ls "$TEMP_DIR/out/" | head -20
        exit 1
    fi

    docker run --rm \
        -v "$TEMP_DIR/out:/out" \
        -e ASAN_OPTIONS="detect_signal_unsafe_writes=1" \
        "$PROJECT_IMAGE" \
        timeout "$DURATION" "/out/$FUZZ_TARGET" "/out/${FUZZ_TARGET}_seed_corpus" 2>&1 || true

    echo
    echo "  Fuzzing complete. Check output above for signal-safety violations."
else
    echo "==== Step 4: Skipped (no fuzz target specified) ===="
    echo "  To fuzz, re-run with: $0 $PROJECT <target> [duration]"
    echo "  Available targets:"
    for t in "${FUZZ_TARGETS[@]}"; do
        echo "    $(basename $t)"
    done
fi

echo
echo "==== Pipeline Complete ===="
