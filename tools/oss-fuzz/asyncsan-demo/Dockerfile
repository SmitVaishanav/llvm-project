FROM gcr.io/oss-fuzz-base/base-builder

# Install LLVM build dependencies
RUN apt-get update && apt-get install -y \
    cmake ninja-build python3 git \
    && rm -rf /var/lib/apt/lists/*

# Clone and build AsyncSan-enabled LLVM clang + compiler-rt
RUN git clone --depth 1 https://github.com/SmitVaishanav/llvm-project.git /src/llvm-project && \
    cmake -G Ninja -S /src/llvm-project/llvm -B /src/llvm-build \
      -DCMAKE_BUILD_TYPE=Release \
      -DLLVM_ENABLE_PROJECTS="clang" \
      -DLLVM_ENABLE_RUNTIMES="compiler-rt" \
      -DLLVM_TARGETS_TO_BUILD="X86" \
      -DCOMPILER_RT_BUILD_SANITIZERS=ON \
      -DLLVM_ENABLE_PER_TARGET_RUNTIME_DIR=ON && \
    ninja -C /src/llvm-build clang compiler-rt -j$(nproc)

# Build ASan runtime (the 'compiler-rt' target only builds builtins)
RUN ninja -C /src/llvm-build/runtimes/runtimes-bins asan -j$(nproc)

# Link runtime libs into clang's resource dir so clang finds them
RUN CLANG_VER=$(/src/llvm-build/bin/clang --version | grep -oP 'clang version \K[0-9]+') && \
    DEST="/src/llvm-build/lib/clang/${CLANG_VER}/lib/x86_64-unknown-linux-gnu" && \
    mkdir -p "$DEST" && \
    find /src/llvm-build/runtimes -name "libclang_rt.*.a" -exec cp {} "$DEST/" \; 2>/dev/null; \
    find /src/llvm-build/lib -path "*/linux/libclang_rt.*.a" -exec cp {} "$DEST/" \; 2>/dev/null; \
    echo "Runtime libs installed:" && ls "$DEST/"

# Override oss-fuzz's default clang with our AsyncSan-enabled one
ENV CC=/src/llvm-build/bin/clang
ENV CXX=/src/llvm-build/bin/clang++

# Copy fuzz targets
COPY build.sh *.cpp $SRC/
WORKDIR $SRC
