# AsyncSan — Project Memory

Everything about this project in one place: what it is, what we built, what's done, what's left.

---

## Who

- **Student/RA**: Smit Vaishnav
- **Advisor**: Prof. Michael Greenberg
- **Research group**: binpash (async-safety subproject)
- **Collaborator context**: Ioannis works on dynamic analysis side (backtrace/Valgrind approach in `binpash/async-safety`)

## What

**AsyncSan** = extension to LLVM's AddressSanitizer that detects async-signal-safety violations.

The core problem: signal handlers in C programs can only safely call "async-signal-safe" functions (defined by POSIX). Calling malloc, printf, etc. from a signal handler is undefined behavior and causes real CVEs (e.g., CVE-2024-6387 regreSSHion in OpenSSH). There's no tool that catches this automatically. We're building one inside LLVM/ASan.

### Three detection modes

1. **Wide writes** — non-atomic stores wider than 8 bytes in signal handler context (can cause torn writes)
2. **Unsafe calls** — direct calls to functions not on the POSIX async-signal-safe list
3. **GEP writes** — writes through getelementptr (struct field / array element access), which indicate complex data structure manipulation unsafe in handlers

### Two-layer architecture

```
Compile time (LLVM pass)              Runtime (compiler-rt)
─────────────────────────             ─────────────────────
Instruments code with calls    →      Collects candidates in ring buffer
to __asan_signal_candidate_*         Dedup via hash table (PC+context)
Gates on global flag:                Tags context (main vs signal handler)
__asan_signal_handler_registered     At exit: matchmaking report + GDB script
```

The LLVM pass adds instrumentation calls. The runtime intercepts sigaction/signal/sigset, sets a global flag, wraps the handler in a trampoline that sets/clears TLS `__asan_in_signal_handler`, and collects candidate violations from both main code and handler code. At exit, it cross-references (matchmaking) to find overlapping writes and matching function calls between contexts, then generates a GDB script for reproduction.

---

## Repos

| Repo | Purpose |
|------|---------|
| `SmitVaishanav/llvm-project` | LLVM fork — all development happens here |
| `binpash/async-safety` | Dynamic analysis (Ioannis's backtrace/Valgrind work) |
| `binpash/async-safety-analysis` | Analysis repo (private) — AsyncSan PRs go here |

---

## Key Files in This Repo

### LLVM Instrumentation Pass
- `llvm/lib/Transforms/Instrumentation/AddressSanitizer.cpp` — the pass itself. Adds instrumentation for all three detection modes. Checks `__asan_signal_handler_registered` global before calling runtime functions.

### Compiler-RT Runtime
- `compiler-rt/lib/asan/asan_rtl.cpp` — candidate collection (lock-free ring buffer, 4096 entries), dedup hash table (2048 slots), matchmaking logic, aggregated report, GDB script generation
- `compiler-rt/lib/asan/asan_interceptors.cpp` — interceptors for sigaction, signal, sigset. Sets `__asan_signal_handler_registered` global. Installs trampoline wrappers.
- `compiler-rt/lib/asan/asan_interface_internal.h` — declarations for `__asan_signal_candidate_write`, `__asan_signal_candidate_call`, etc.
- `compiler-rt/lib/asan/asan_internal.h` — internal declarations
- `compiler-rt/lib/asan/asan_flags.inc` — runtime flag: `detect_signal_unsafe_writes`

### Tests
- IR tests (3): `llvm/test/Instrumentation/AddressSanitizer/signal-unsafe-{write,call,gep-write}.ll`
- E2E tests (11+): `compiler-rt/test/asan/TestCases/signal_unsafe_*.cpp` — cover wide writes, unsafe calls, GEP writes, nested handlers, struct writes, altstack, corruption scenarios, real-world patterns (postgres, redis, screen, tmux, bash, CVEs)

### Tools (our additions)
- `tools/asyncsan-qualify.py` — angr-based binary qualifier. Scans a compiled binary to find signal handlers and analyze them for potential violations BEFORE running with AsyncSan. Uses capstone linear disassembly (not CFGFast) for speed.
- `tools/asyncsan-pipeline.sh` — end-to-end workflow script: build with AsyncSan → angr qualify → run with detection
- `tools/oss-fuzz-asyncsan/` — oss-fuzz integration (Dockerfile, compile wrapper, pipeline script, README)
- `tools/study_todo.md` — self-study checklist for all underlying concepts

---

## Compiler Flags

```bash
# Compile-time (LLVM pass flags)
-mllvm -asan-detect-signal-unsafe-writes      # wide writes >8 bytes
-mllvm -asan-detect-signal-unsafe-calls        # calls to non-async-signal-safe functions
-mllvm -asan-detect-signal-unsafe-gep-writes   # writes through GEP

# Runtime
ASAN_OPTIONS=detect_signal_unsafe_writes=1
```

---

## Signal API Coverage

| API | How we intercept |
|-----|-----------------|
| `sigaction()` with SA_SIGINFO | `asan_signal_trampoline` (3-arg wrapper) |
| `sigaction()` with sa_handler | `asan_signal_trampoline_handler` (1-arg wrapper) |
| `signal()` | `SIGNAL_INTERCEPTOR_SIGNAL_IMPL` macro |
| `sigset()` (Linux only) | Custom `INTERCEPTOR(uptr, sigset, ...)` |

---

## angr Qualifier — What It Does and How

The qualifier (`tools/asyncsan-qualify.py`) takes a compiled binary and answers: "does this binary register signal handlers, and if so, are they trivial or potentially unsafe?"

### How it works
1. Load binary with angr's CLE loader
2. Build stub map (PLT entries → symbol names). For arm64e Mach-O, falls back to `otool -Iv` since angr doesn't parse `__auth_stubs`
3. Linear disassembly of text section using capstone directly (NOT angr's CFGFast — that was too slow, 120s on postgres)
4. Scan for `bl`/`call` instructions targeting sigaction/signal PLT entries
5. For each registration call, backward-scan preceding instructions to extract handler address from register (x2 for sigaction on arm64, rsi/rdx on x86-64)
6. Handle `adrp + add` pairs on arm64 (page-aligned address + offset)
7. For wrapper functions like PostgreSQL's `pqsignal()`, trace through all callers to find actual handler arguments
8. Analyze each handler: walk its instructions, check calls against async-signal-safe list
9. Output: list of handlers, trivial vs non-trivial, unsafe calls found

### Performance
- PostgreSQL (arm64, 26K functions): **31 seconds** (down from 3.5 minutes with CFGFast)
- Professor's threshold: <1.5 minutes — we're well under

### Results on real binaries
- **PostgreSQL (arm64)**: 82 handlers found, 5 non-trivial
- **sshd (macOS arm64e)**: 0 handlers (signal setup in linked dylibs, not main binary — correct behavior, but professor wants us to try resolving dylib references)

---

## Runtime Architecture Details

### Lock-free ring buffer
- 4096 entries, atomic index with relaxed ordering
- Each entry: PC, address, size, context (main/handler), function name
- No locks — safe to use from signal handler context

### Dedup hash table
- 2048 slots, keyed by PC + context
- Prevents duplicate reports for same instrumented site

### Matchmaking (at exit)
- Cross-references main-thread candidates with handler candidates
- Overlapping writes: main writes to address range that handler also writes to
- Same function calls: both contexts call same non-async-signal-safe function
- Generates GDB script with breakpoints at offending PCs

---

## What's Been Done (chronological)

1. Designed and implemented LLVM instrumentation pass (all 3 detection modes)
2. Implemented compiler-rt runtime (ring buffer, dedup, trampoline, interceptors)
3. Added signal/sigset interceptors (beyond just sigaction)
4. Built v2 architecture (candidate collection + matchmaking, replacing v1 direct detection)
5. Wrote 3 IR tests + 11+ E2E tests covering real-world patterns
6. Built angr qualifier tool
7. Optimized angr qualifier: CFGFast → capstone linear disassembly (3.5min → 31s on postgres)
8. Added Mach-O support: arm64e `__auth_stubs`, `otool` fallback, underscore-prefixed symbols
9. Added wrapper function resolution (pqsignal → sigaction tracing)
10. Created oss-fuzz integration scaffold
11. Created asyncsan-pipeline.sh workflow script
12. Docker setup (Ubuntu 22.04 aarch64 container for Linux testing)

---

## What's Left / Next Steps

1. **x86-64 support**: Professor confirmed arm64 is a nonstarter for oss-fuzz. Need x86-64 environment.
2. **oss-fuzz testing**: Files created but untested. Need x86-64 Docker.
3. **sshd dylib resolution**: Professor wants us to try statically resolving dylib signal handlers (sshd shows 0 handlers because setup is in linked .so/.dylib files).
4. **Push to binpash/async-safety-analysis**: Code needs to go up as PRs.
5. **Linux sshd testing**: Try qualifier on Linux x86-64 sshd where handlers may be in main binary.

---

## Known Limitations

- Struct assignment at -O0: lowered to per-field ≤8-byte stores, so wide-write detector misses them
- Indirect calls not checked (only direct calls with known symbol names)
- sigset() interceptor is Linux-only (not on macOS)
- angr qualifier doesn't follow indirect calls or jump tables
- macOS sshd: handlers registered in dylibs, not visible to static binary analysis of main executable

---

## Professor's Latest Feedback (Discord)

- "What is direct capstone disassembly? Not having CFG feels tough but maybe okay?"
- "sshd showing as 0 isn't great... it has vulns! Are the dylib/SOs mentioned in a way we could try to statically resolve?"
- "arm64 is a nonstarter, so I do think we need x86_64"
- Priorities: test on real binaries (sshd, postgres), get oss-fuzz working, maybe BINSEC after

---

## Real-World CVEs That Motivate This Work

| CVE | What happened |
|-----|--------------|
| CVE-2024-6387 (regreSSHion) | OpenSSH sshd: race condition in signal handler called non-async-signal-safe functions, led to RCE |
| PostgreSQL signal bugs | pqsignal handlers calling non-safe functions |
| Redis crash handler | serverLog called from signal handler (uses malloc internally) |
| GNU Screen | Signal handler vulnerabilities |

---

## Environment

- Dev machine: macOS, Apple Silicon (arm64)
- Docker container: Ubuntu 22.04 aarch64 (`llvm-linux`)
- Need: x86-64 Linux environment for oss-fuzz
- Python: 3.14 with angr in venv at `/tmp/angr-venv`
- LLVM build: Ninja, debug build
