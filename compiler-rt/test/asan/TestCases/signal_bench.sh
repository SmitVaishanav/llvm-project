#!/bin/bash
# Microbenchmark runner for async-signal-safety instrumentation overhead.
# Compiles signal_bench.cpp in 4 configurations, runs each with/without
# handler registered, prints comparison table.
#
# Usage: ./signal_bench.sh [path-to-clang++]

set -e

CLANG="${1:-clang++}"
SDK=$(xcrun --show-sdk-path 2>/dev/null || echo "")
SYSROOT=""
if [ -n "$SDK" ]; then
  SYSROOT="-isysroot $SDK"
fi
SRC="$(dirname "$0")/signal_bench.cpp"
DIR=$(mktemp -d)
ITERS=20000000

echo "=== Signal Safety Instrumentation Microbenchmarks ==="
echo "Compiler: $CLANG"
echo "Iterations: $ITERS"
echo ""

# Build 4 configurations
echo "Building..."
$CLANG $SYSROOT -O2 "$SRC" -o "$DIR/baseline" -DITERATIONS=$ITERS
$CLANG $SYSROOT -O2 -fsanitize=address "$SRC" -o "$DIR/asan" -DITERATIONS=$ITERS
$CLANG $SYSROOT -O2 -fsanitize=address \
  -mllvm -asan-detect-signal-unsafe-writes \
  -mllvm -asan-detect-signal-unsafe-gep-writes \
  -mllvm -asan-detect-signal-unsafe-calls \
  "$SRC" -o "$DIR/asyncsan" -DITERATIONS=$ITERS
echo "Done."
echo ""

# Run each config: without handler (no overhead expected for asyncsan)
# and with handler (asyncsan overhead kicks in)
echo "=== No handler registered (instrumentation gated off) ==="
echo "--- baseline ---"
"$DIR/baseline"
echo "--- asan ---"
ASAN_OPTIONS=detect_signal_unsafe_writes=1 "$DIR/asan"
echo "--- asyncsan ---"
ASAN_OPTIONS=detect_signal_unsafe_writes=1 "$DIR/asyncsan"
echo ""

echo "=== Handler registered (instrumentation active) ==="
echo "--- baseline ---"
"$DIR/baseline" --handler
echo "--- asan ---"
ASAN_OPTIONS=detect_signal_unsafe_writes=1 "$DIR/asan" --handler
echo "--- asyncsan ---"
ASAN_OPTIONS=detect_signal_unsafe_writes=1 "$DIR/asyncsan" --handler
echo ""

rm -rf "$DIR"
echo "Done. Compare asyncsan vs asan (handler) for overhead from our instrumentation."
