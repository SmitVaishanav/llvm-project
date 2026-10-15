#!/bin/bash -eu

# AsyncSan flags on top of whatever SANITIZER_FLAGS oss-fuzz sets
ASYNCSAN_FLAGS="-mllvm -asan-detect-signal-unsafe-calls -mllvm -asan-detect-signal-unsafe-writes -mllvm -asan-detect-signal-unsafe-gep-writes"

# oss-fuzz passes -stdlib=libc++ but we didn't build it — use libstdc++
FIXED_CXXFLAGS=$(echo "$CXXFLAGS" | sed 's/-stdlib=libc++//g')

# oss-fuzz sets LIB_FUZZING_ENGINE to -fsanitize=fuzzer, which makes our
# clang look for libclang_rt.fuzzer.a. Use pre-compiled lib instead.
FUZZER_LIB="/usr/lib/libFuzzingEngine.a"

# Build each fuzz target
for src in $SRC/*.cpp; do
    name=$(basename "$src" .cpp)
    $CXX $FIXED_CXXFLAGS $ASYNCSAN_FLAGS -c "$src" -o "${name}.o"
    $CXX $FIXED_CXXFLAGS "${name}.o" -o "$OUT/$name" "$FUZZER_LIB" -lstdc++ -lpthread -lrt -ldl
done
