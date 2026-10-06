// Negative test: an 8-byte write inside a signal handler should NOT be flagged
// (architecturally atomic on x86_64/aarch64).
//
// RUN: %clangxx_asan -O0 -mllvm -asan-detect-signal-unsafe-writes %s -o %t
// RUN: %env_asan_opts=detect_signal_unsafe_writes=1 %run %t 2>&1 \
// RUN:   | FileCheck %s
//
// REQUIRES: asan-64-bits
// REQUIRES: x86_64-target-arch || aarch64-target-arch || arm64-target-arch

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

long *shared_ptr;

void handler(int sig, siginfo_t *info, void *ctx) {
  // 8-byte store — fits in a single instruction, architecturally atomic.
  *shared_ptr = 42;
}

int main() {
  long obj = 0;
  shared_ptr = &obj;

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

// CHECK: no error detected
// CHECK-NOT: ERROR: AddressSanitizer
