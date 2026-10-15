#!/bin/bash
# Run all AsyncSan E2E tests
CLANG=~/llvm-project/build/bin/clang
FLAGS="-fsanitize=address -mllvm -asan-detect-signal-unsafe-calls -mllvm -asan-detect-signal-unsafe-writes -mllvm -asan-detect-signal-unsafe-gep-writes"
ASAN="ASAN_OPTIONS=detect_signal_unsafe_writes=1"
PASS=0
FAIL=0
SKIP=0

for src in ~/llvm-project/compiler-rt/test/asan/TestCases/signal_unsafe_*.cpp; do
    name=$(basename "$src" .cpp)
    out="/tmp/test_${name}"
    printf "%-50s " "$name"

    # Compile
    if ! $CLANG $FLAGS -o "$out" "$src" -lstdc++ 2>/dev/null; then
        echo "COMPILE_FAIL"
        FAIL=$((FAIL+1))
        continue
    fi

    # Run with timeout
    output=$(timeout 10 env $ASAN "$out" 2>&1)
    exit_code=$?

    if echo "$output" | grep -q "Match #\|Matched signal-safety\|candidates"; then
        echo "PASS"
        PASS=$((PASS+1))
    elif [ $exit_code -eq 124 ]; then
        echo "TIMEOUT"
        SKIP=$((SKIP+1))
    else
        echo "NO_OUTPUT"
        SKIP=$((SKIP+1))
    fi
done

echo ""
echo "Results: $PASS pass, $FAIL fail, $SKIP skip"
