// Test: a 32-byte (4 x i64) vector write inside a signal handler triggers
// the detector. This exercises a different wide type than the 16-byte
// vector used in signal_unsafe_write.cpp.
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

typedef long long Vec4 __attribute__((vector_size(32)));

Vec4 *shared_ptr;

void handler(int sig, siginfo_t *info, void *ctx) {
  Vec4 val = {1, 2, 3, 4};
  *shared_ptr = val;  // 32-byte non-atomic store — should be flagged.
}

int main() {
  Vec4 obj;
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

// CHECK: Signal Safety Analysis Report
// CHECK: Signal-handler candidates
// CHECK: [W] write
