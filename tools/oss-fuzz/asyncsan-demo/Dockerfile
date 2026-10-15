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
      -DCOMPILER_RT_BUILD_SANITIZERS=ON && \
    ninja -C /src/llvm-build clang compiler-rt -j$(nproc)

# Override oss-fuzz's default clang with our AsyncSan-enabled one
ENV CC=/src/llvm-build/bin/clang
ENV CXX=/src/llvm-build/bin/clang++

# Copy fuzz targets
COPY build.sh *.cpp $SRC/
WORKDIR $SRC
