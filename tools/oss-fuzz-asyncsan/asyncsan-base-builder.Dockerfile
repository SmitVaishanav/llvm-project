# AsyncSan-enabled base-builder for oss-fuzz.
#
# Extends the standard oss-fuzz base-builder with a custom LLVM/Clang
# that includes the AsyncSan signal-safety detection pass.
#
# Usage:
#   docker build -t asyncsan-base-builder -f asyncsan-base-builder.Dockerfile .
#   # Then use this as the base image for project Dockerfiles instead of
#   # gcr.io/oss-fuzz-base/base-builder

FROM gcr.io/oss-fuzz-base/base-builder

# Install LLVM build dependencies
RUN apt-get update && apt-get install -y \
    cmake ninja-build python3 git \
    && rm -rf /var/lib/apt/lists/*

# Clone and build AsyncSan-enabled LLVM/Clang
# Replace this URL with the actual fork URL
ARG LLVM_REPO=https://github.com/SmitVaishanav/llvm-project.git
ARG LLVM_BRANCH=main

RUN git clone --depth 1 -b $LLVM_BRANCH $LLVM_REPO /tmp/llvm-src

RUN cmake -G Ninja -S /tmp/llvm-src/llvm -B /tmp/llvm-build \
    -DCMAKE_BUILD_TYPE=Release \
    -DLLVM_ENABLE_PROJECTS="clang;compiler-rt;lld" \
    -DLLVM_TARGETS_TO_BUILD="X86" \
    -DCLANG_DEFAULT_LINKER=lld \
    -DCMAKE_INSTALL_PREFIX=/usr/local/asyncsan \
    && cmake --build /tmp/llvm-build --target install -j$(nproc) \
    && rm -rf /tmp/llvm-src /tmp/llvm-build

# Override CC/CXX to use AsyncSan clang
ENV CC=/usr/local/asyncsan/bin/clang
ENV CXX=/usr/local/asyncsan/bin/clang++

# Add AsyncSan instrumentation flags to default CFLAGS/CXXFLAGS
# These are appended to whatever oss-fuzz sets
ENV ASYNCSAN_FLAGS="-mllvm -asan-detect-signal-unsafe-calls -mllvm -asan-detect-signal-unsafe-writes -mllvm -asan-detect-signal-unsafe-gep-writes"
