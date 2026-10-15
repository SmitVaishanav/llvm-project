#!/bin/bash -eu

# AsyncSan flags on top of whatever SANITIZER_FLAGS oss-fuzz sets
ASYNCSAN_FLAGS="-mllvm -asan-detect-signal-unsafe-calls -mllvm -asan-detect-signal-unsafe-writes -mllvm -asan-detect-signal-unsafe-gep-writes"

# oss-fuzz passes -stdlib=libc++ but we didn't build it — use libstdc++
FIXED_CXXFLAGS=$(echo "$CXXFLAGS" | sed 's/-stdlib=libc++//g')

# Build each fuzz target
for src in $SRC/*.cpp; do
    name=$(basename "$src" .cpp)
    $CXX $FIXED_CXXFLAGS $ASYNCSAN_FLAGS "$src" -o "$OUT/$name" $LIB_FUZZING_ENGINE -lstdc++
done
