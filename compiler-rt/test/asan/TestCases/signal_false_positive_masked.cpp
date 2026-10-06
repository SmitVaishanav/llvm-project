// FALSE POSITIVE: main and handler write to same address, but signals are
// masked during main's write (sigprocmask). Technically safe — handler can't
// interrupt the write. Our detector doesn't track signal masks, so it flags
// this as a match.
//
// This documents a known limitation.
//
// RUN: %clangxx_asan -O0 -mllvm -asan-detect-signal-unsafe-writes %s -o %t
// RUN: %env_asan_opts=detect_signal_unsafe_writes=1 %run %t 2>&1 \
// RUN:   | FileCheck %s
//
// REQUIRES: asan-64-bits
// REQUIRES: x86_64-target-arch || aarch64-target-arch || arm64-target-arch

#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

typedef long long Vec4 __attribute__((vector_size(32)));

Vec4 *shared;

void handler(int sig) {
  Vec4 val = {9, 9, 9, 9};
  *shared = val;
}

int main() {
  Vec4 state = {0, 0, 0, 0};
  shared = &state;

  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = handler;
  sigemptyset(&sa.sa_mask);
  sigaction(SIGUSR1, &sa, NULL);

  // Block SIGUSR1 during write — handler CAN'T interrupt us here.
  sigset_t block, old;
  sigemptyset(&block);
  sigaddset(&block, SIGUSR1);
  sigprocmask(SIG_BLOCK, &block, &old);

  Vec4 val = {1, 2, 3, 4};
  *shared = val;  // Safe: SIGUSR1 blocked.

  sigprocmask(SIG_SETMASK, &old, NULL);

  // Now deliver signal (handler runs here, after our write is done).
  kill(getpid(), SIGUSR1);

  printf("done\n");
  return 0;
}

// FALSE POSITIVE: detector doesn't know about sigprocmask, flags match anyway.
// This is a known limitation — documenting it.
// CHECK: Matched signal-safety violations
// CHECK: Match {{.*}}: WRITE to overlapping address range
