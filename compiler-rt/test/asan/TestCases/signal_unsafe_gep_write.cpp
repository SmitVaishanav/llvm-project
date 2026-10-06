// Test that ASan detects writes through GEP (struct field) inside signal
// handlers.
//
// RUN: %clangxx_asan -O0 -mllvm -asan-detect-signal-unsafe-gep-writes %s -o %t
// RUN: %env_asan_opts=detect_signal_unsafe_writes=1 %run %t 2>&1 \
// RUN:   | FileCheck %s
//
// Negative test: without the runtime flag, no error should be reported.
// RUN: %clangxx_asan -O0 -mllvm -asan-detect-signal-unsafe-gep-writes %s -o %t
// RUN: %env_asan_opts=detect_signal_unsafe_writes=0 %run %t 2>&1 \
// RUN:   | FileCheck %s --check-prefix=CLEAN
//
// REQUIRES: asan-64-bits
// REQUIRES: x86_64-target-arch || aarch64-target-arch || arm64-target-arch

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct Pair {
  int x;
  int y;
};

volatile struct Pair *g_pair;

void handler(int sig, siginfo_t *info, void *ctx) {
  // Writing to a struct field through a pointer — detected via GEP.
  g_pair->y = 42;
}

int main() {
  struct Pair p = {1, 2};
  g_pair = &p;

  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_sigaction = handler;
  sa.sa_flags = SA_SIGINFO;
  sigemptyset(&sa.sa_mask);

  if (sigaction(SIGUSR1, &sa, NULL) != 0) {
    perror("sigaction");
    return 1;
  }

  kill(getpid(), SIGUSR1);

  puts("no error detected");
  return 0;
}

// CHECK: Signal Safety Analysis Report
// CHECK: Signal-handler candidates
// CHECK: [W] write
//
// CLEAN: no error detected
