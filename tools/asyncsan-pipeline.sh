#!/usr/bin/env bash
# AsyncSan Pipeline — build → qualify → run/fuzz
#
# Usage:
#   asyncsan-pipeline.sh <binary> [-- run-args...]
#   asyncsan-pipeline.sh --build "<build-cmd>" --binary <output-binary> [-- run-args...]
#
# Examples:
#   # Just qualify + run an already-built binary:
#   asyncsan-pipeline.sh ./my_server -- --port 8080
#
#   # Build, qualify, and run:
#   asyncsan-pipeline.sh --build "make CC=\$ASAN_CC CFLAGS=\$ASAN_CFLAGS" --binary ./my_server
#
# Environment:
#   ASYNCSAN_CLANG    — path to clang with AsyncSan (default: clang)
#   ASYNCSAN_CLANGXX  — path to clang++ (default: clang++)
#   ASYNCSAN_QUALIFY  — path to asyncsan-qualify.py (default: alongside this script)
#   ASYNCSAN_TIMEOUT  — max seconds for the run phase (default: 30)
#   ASYNCSAN_VENV     — python venv with angr (default: /tmp/angr-venv)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Defaults
: "${ASYNCSAN_CLANG:=clang}"
: "${ASYNCSAN_CLANGXX:=clang++}"
: "${ASYNCSAN_QUALIFY:=$SCRIPT_DIR/asyncsan-qualify.py}"
: "${ASYNCSAN_TIMEOUT:=30}"
: "${ASYNCSAN_VENV:=/tmp/angr-venv}"

# AsyncSan compiler flags
ASYNCSAN_CFLAGS="-fsanitize=address -mllvm -asan-detect-signal-unsafe-calls -mllvm -asan-detect-signal-unsafe-writes -mllvm -asan-detect-signal-unsafe-gep-writes"
ASYNCSAN_LDFLAGS="-fsanitize=address"

# Export for build commands
export ASAN_CC="$ASYNCSAN_CLANG"
export ASAN_CXX="$ASYNCSAN_CLANGXX"
export ASAN_CFLAGS="$ASYNCSAN_CFLAGS"
export ASAN_LDFLAGS="$ASYNCSAN_LDFLAGS"

# --- Parse args ---
BUILD_CMD=""
BINARY=""
RUN_ARGS=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        --build)  BUILD_CMD="$2"; shift 2 ;;
        --binary) BINARY="$2"; shift 2 ;;
        --)       shift; RUN_ARGS=("$@"); break ;;
        -h|--help)
            sed -n '2,/^$/s/^# //p' "$0"
            exit 0
            ;;
        *)
            # Positional: binary path
            if [[ -z "$BINARY" ]]; then
                BINARY="$1"; shift
            else
                RUN_ARGS+=("$1"); shift
            fi
            ;;
    esac
done

if [[ -z "$BINARY" ]]; then
    echo "error: no binary specified" >&2
    echo "usage: asyncsan-pipeline.sh [--build CMD] --binary <path> [-- args...]" >&2
    exit 1
fi

# --- Phase 1: Build ---
if [[ -n "$BUILD_CMD" ]]; then
    echo "==== Phase 1: BUILD ===="
    echo "  CC=$ASAN_CC"
    echo "  CFLAGS=$ASAN_CFLAGS"
    echo "  Command: $BUILD_CMD"
    echo
    eval "$BUILD_CMD"
    echo
    if [[ ! -f "$BINARY" ]]; then
        echo "error: build succeeded but binary '$BINARY' not found" >&2
        exit 1
    fi
    echo "  Build complete: $BINARY"
else
    echo "==== Phase 1: BUILD (skipped — using existing binary) ===="
    if [[ ! -f "$BINARY" ]]; then
        echo "error: binary '$BINARY' not found" >&2
        exit 1
    fi
fi
echo

# --- Phase 2: Qualify ---
echo "==== Phase 2: QUALIFY ===="

# Activate angr venv if available
if [[ -d "$ASYNCSAN_VENV" ]]; then
    source "$ASYNCSAN_VENV/bin/activate"
fi

QUALIFY_EXIT=0
python3 "$ASYNCSAN_QUALIFY" "$BINARY" || QUALIFY_EXIT=$?

echo

if [[ $QUALIFY_EXIT -ne 0 ]]; then
    echo "==== Phase 3: RUN (skipped — no non-trivial handlers) ===="
    echo
    echo "Pipeline complete. Binary is CLEAN — no async-signal-safety risk detected."
    exit 0
fi

# --- Phase 3: Run ---
echo "==== Phase 3: RUN ===="
echo "  Binary: $BINARY"
echo "  Timeout: ${ASYNCSAN_TIMEOUT}s"
echo "  ASAN_OPTIONS: detect_signal_unsafe_writes=1"
if [[ ${#RUN_ARGS[@]} -gt 0 ]]; then
    echo "  Args: ${RUN_ARGS[*]}"
fi
echo

export ASAN_OPTIONS="detect_signal_unsafe_writes=1"

set +e
if command -v timeout &>/dev/null; then
    timeout "$ASYNCSAN_TIMEOUT" "$BINARY" ${RUN_ARGS[@]+"${RUN_ARGS[@]}"} 2>&1
elif command -v gtimeout &>/dev/null; then
    gtimeout "$ASYNCSAN_TIMEOUT" "$BINARY" ${RUN_ARGS[@]+"${RUN_ARGS[@]}"} 2>&1
else
    "$BINARY" ${RUN_ARGS[@]+"${RUN_ARGS[@]}"} 2>&1
fi
RUN_EXIT=$?
set -e

echo
echo "==== PIPELINE SUMMARY ===="
echo "  Binary:    $BINARY"
echo "  Qualify:   FUZZ (non-trivial handlers found)"
echo "  Run exit:  $RUN_EXIT"
if [[ $RUN_EXIT -eq 0 ]]; then
    echo "  Result:    Completed — check output above for signal-safety report"
elif [[ $RUN_EXIT -eq 124 ]]; then
    echo "  Result:    Timed out after ${ASYNCSAN_TIMEOUT}s (may need longer run or signal trigger)"
else
    echo "  Result:    Exited with code $RUN_EXIT"
fi
