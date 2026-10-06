// Test that ASan collects signal safety candidates and matches calls
// to the same async-signal-unsafe function in both contexts.
//
// RUN: %clangxx_asan -O0 -mllvm -asan-detect-signal-unsafe-calls %s -o %t
// RUN: %env_asan_opts=detect_signal_unsafe_writes=1 %run %t 2>&1 \
// RUN:   | FileCheck %s
//
// Negative test: without the runtime flag, no report should appear.
// RUN: %clangxx_asan -O0 -mllvm -asan-detect-signal-unsafe-calls %s -o %t
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

void handler(int sig, siginfo_t *info, void *ctx) {
  // Signal handler: calls malloc (async-signal-unsafe).
  void *p = malloc(64);
  free(p);
}

int main() {
  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_sigaction = handler;
  sa.sa_flags = SA_SIGINFO;
  sigemptyset(&sa.sa_mask);

  if (sigaction(SIGUSR1, &sa, NULL) != 0) {
    perror("sigaction");
    return 1;
  }

  // Main thread: also calls malloc (after handler registered).
  void *p = malloc(128);
  free(p);

  // Trigger the signal handler.
  kill(getpid(), SIGUSR1);

  puts("done");
  return 0;
}

// CHECK: Signal Safety Analysis Report
// CHECK: Main-thread candidates
// CHECK: [C] call to 'malloc'
// CHECK: Signal-handler candidates
// CHECK: [C] call to 'malloc'
// CHECK: Matched signal-safety violations
// CHECK: Match {{.*}}: CALL to same function 'malloc'
// CHECK: LLDB script written to
//
// CLEAN-NOT: Signal Safety Analysis Report
// CLEAN: done
