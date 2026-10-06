// Proves signal-safety write race deterministically using LLDB.
// LLDB breakpoint in handler → examines shared memory → confirms both
// contexts write to same address. No timing dependency.
//
// RUN: %clangxx_asan -g -O0 -mllvm -asan-detect-signal-unsafe-writes %s -o %t
// RUN: lldb --batch \
// RUN:   -o "settings set target.env-vars ASAN_OPTIONS=detect_signal_unsafe_writes=1" \
// RUN:   -o "breakpoint set -n handler" \
// RUN:   -o "run" \
// RUN:   -o "frame variable sig" \
// RUN:   -o "expression *shared" \
// RUN:   -o "continue" \
// RUN:   -- %t 2>&1 | FileCheck %s --check-prefix=LLDB
//
// Also verify the report + LLDB script are generated:
// RUN: %env_asan_opts=detect_signal_unsafe_writes=1 %run %t 2>&1 \
// RUN:   | FileCheck %s --check-prefix=REPORT
//
// REQUIRES: system-darwin
// REQUIRES: asan-64-bits

#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

typedef long long Vec4 __attribute__((vector_size(32)));

Vec4 *shared;

void handler(int sig) {
  Vec4 poison = {0x2222222222222222LL, 0x2222222222222222LL,
                 0x2222222222222222LL, 0x2222222222222222LL};
  *shared = poison;
}

int main() {
  Vec4 state = {0x1111111111111111LL, 0x1111111111111111LL,
                0x1111111111111111LL, 0x1111111111111111LL};
  shared = &state;

  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = handler;
  sigemptyset(&sa.sa_mask);
  sigaction(SIGUSR1, &sa, NULL);

  // Main writes pattern
  *shared = state;

  // Trigger handler (deterministic)
  kill(getpid(), SIGUSR1);

  printf("done\n");
  return 0;
}

// LLDB proves: breakpoint fires in handler, shared has main's pattern (0x1111...)
// before handler overwrites it with 0x2222...
// LLDB: stop reason = breakpoint
// LLDB: handler
// LLDB: 0x1111111111111111
//
// REPORT: Signal Safety Analysis Report
// REPORT: Main-thread candidates
// REPORT: [W] write
// REPORT: Signal-handler candidates
// REPORT: [W] write
// REPORT: Matched signal-safety violations
// REPORT: Match {{.*}}: WRITE to overlapping address range
// REPORT: LLDB script written to
