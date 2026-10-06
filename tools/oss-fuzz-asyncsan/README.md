# AsyncSan + oss-fuzz Integration

Run AsyncSan signal-safety analysis on any oss-fuzz project.

## Architecture

```
oss-fuzz project ──→ Build with AsyncSan clang ──→ angr qualify ──→ Fuzz
                     (custom -mllvm flags)         (skip trivial)   (collect report)
```

## Requirements

- Docker (x86-64 recommended, ARM64 works with emulation)
- Python 3 + angr (`pip install angr`)
- oss-fuzz repo (`git clone https://github.com/google/oss-fuzz /tmp/oss-fuzz`)

## Quick Start

```bash
# 1. Build + qualify + fuzz openssh
./run-asyncsan-ossfuzz.sh openssh kex_fuzz 60

# 2. Just qualify (no fuzzing)
./run-asyncsan-ossfuzz.sh postgresql
```

## Manual Integration

To add AsyncSan to any project's `build.sh`, add these lines after the shebang:

```bash
# AsyncSan signal-safety instrumentation
ASYNCSAN_FLAGS="-mllvm -asan-detect-signal-unsafe-calls \
  -mllvm -asan-detect-signal-unsafe-writes \
  -mllvm -asan-detect-signal-unsafe-gep-writes"
export CFLAGS="$CFLAGS $ASYNCSAN_FLAGS"
export CXXFLAGS="$CXXFLAGS $ASYNCSAN_FLAGS"
```

And set at runtime:
```bash
export ASAN_OPTIONS="detect_signal_unsafe_writes=1"
```

## Files

- `asyncsan-base-builder.Dockerfile` — Docker image with AsyncSan-enabled clang
- `asyncsan-compile` — Compile wrapper that injects flags
- `run-asyncsan-ossfuzz.sh` — Full pipeline script

## Target Projects

Projects known to have signal handlers (good candidates):

| Project | Handler Pattern | Expected Findings |
|---------|----------------|-------------------|
| openssh | SIGALRM → syslog → malloc (CVE-2024-6387) | FUZZ |
| postgresql | pqsignal wrapper, reaper → free | FUZZ |
| redis | crash handler → serverLog → malloc | FUZZ |
| nginx | signal handlers for worker management | INVESTIGATE |

## Notes

- oss-fuzz infra runs on x86-64. ARM64 hosts need `--platform linux/amd64` Docker flag.
- First build takes ~30min (compiles LLVM from source).
- Subsequent builds use cached base image.
- The `asyncsan-qualify.py` binary qualifier runs locally (no Docker needed).
