// SOUND: atomic writes in signal handler should NOT be flagged.
// sig_atomic_t and _Atomic writes are async-signal-safe.
//
// RUN: %clangxx_asan -O0 -mllvm -asan-detect-signal-unsafe-writes %s -o %t
// RUN: %env_asan_opts=detect_signal_unsafe_writes=1 %run %t 2>&1 \
// RUN:   | FileCheck %s
//
// REQUIRES: asan-64-bits
// REQUIRES: x86_64-target-arch || aarch64-target-arch || arm64-target-arch

#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

volatile sig_atomic_t flag = 0;
_Atomic int atomic_counter = 0;

void handler(int sig) {
  // These are all async-signal-safe writes:
  flag = 1;                          // sig_atomic_t (4 or 8 bytes, atomic)
  atomic_store(&atomic_counter, 42); // _Atomic int
}

int main() {
  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = handler;
  sigemptyset(&sa.sa_mask);
  sigaction(SIGUSR1, &sa, NULL);

  flag = 0;
  atomic_store(&atomic_counter, 0);

  kill(getpid(), SIGUSR1);

  printf("flag=%d counter=%d\n", (int)flag, atomic_load(&atomic_counter));
  printf("done\n");
  return 0;
}

// These writes are <= 8 bytes so the wide-write detector shouldn't flag them.
// No matches expected.
// CHECK: done
// CHECK-NOT: Match
