FROM gcr.io/oss-fuzz-base/base-builder

# No LLVM build — we mount the host's pre-built clang via docker volume.
# This avoids 1-2 hour rebuilds on every Dockerfile change.

# Override oss-fuzz's default clang with our AsyncSan-enabled one
ENV CC=/src/llvm-build/bin/clang
ENV CXX=/src/llvm-build/bin/clang++

# Copy fuzz targets
COPY build.sh *.cpp $SRC/
WORKDIR $SRC
