// Test that ASan collects signal safety candidates and matches writes
// to overlapping address ranges in main thread and signal handler.
//
// RUN: %clangxx_asan -O0 -mllvm -asan-detect-signal-unsafe-writes %s -o %t
// RUN: %env_asan_opts=detect_signal_unsafe_writes=1 %run %t 2>&1 \
// RUN:   | FileCheck %s
//
// Negative test: without the flag, no report should appear.
// RUN: %clangxx_asan -O0 -mllvm -asan-detect-signal-unsafe-writes %s -o %t
// RUN: %env_asan_opts=detect_signal_unsafe_writes=0 %run %t 2>&1 \
// RUN:   | FileCheck %s --check-prefix=CLEAN
//
// REQUIRES: asan-64-bits
// REQUIRES: x86_64-target-arch || aarch64-target-arch || arm64-target-arch

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

typedef long long Vec2 __attribute__((vector_size(16)));

Vec2 shared;
Vec2 *shared_ptr;

void handler(int sig, siginfo_t *info, void *ctx) {
  // Signal handler: 16-byte write to same address as main thread.
  Vec2 val = {42, 43};
  *shared_ptr = val;
}

int main() {
  shared_ptr = &shared;

  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_sigaction = handler;
  sa.sa_flags = SA_SIGINFO;
  sigemptyset(&sa.sa_mask);

  if (sigaction(SIGUSR1, &sa, NULL) != 0) {
    perror("sigaction");
    return 1;
  }

  // Main thread: 16-byte write to same address (after handler registered).
  Vec2 main_val = {1, 2};
  *shared_ptr = main_val;

  // Trigger the signal handler.
  kill(getpid(), SIGUSR1);

  puts("done");
  return 0;
}

// CHECK: Signal Safety Analysis Report
// CHECK: Main-thread candidates
// CHECK: [W] write
// CHECK: Signal-handler candidates
// CHECK: [W] write
// CHECK: Matched signal-safety violations
// CHECK: Match #1: WRITE to overlapping address range
// CHECK: Main:
// CHECK: Signal:
//
// CLEAN-NOT: Signal Safety Analysis Report
// CLEAN: done
