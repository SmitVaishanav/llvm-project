// UNSOUND: both main and handler write to same struct field via GEP.
// Detector should match overlapping writes.
//
// RUN: %clangxx_asan -O0 -mllvm -asan-detect-signal-unsafe-gep-writes %s -o %t
// RUN: %env_asan_opts=detect_signal_unsafe_writes=1 %run %t 2>&1 \
// RUN:   | FileCheck %s
//
// REQUIRES: asan-64-bits
// REQUIRES: x86_64-target-arch || aarch64-target-arch || arm64-target-arch

#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

struct SharedState {
  int status;
  int error_code;
};

struct SharedState *shared;

void handler(int sig) {
  // GEP write to shared->status — same field main writes to.
  shared->status = 99;
  shared->error_code = -1;
}

int main() {
  struct SharedState state = {0, 0};
  shared = &state;

  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = handler;
  sigemptyset(&sa.sa_mask);
  sigaction(SIGUSR1, &sa, NULL);

  // Main writes to same struct fields.
  shared->status = 1;
  shared->error_code = 0;

  kill(getpid(), SIGUSR1);

  printf("status=%d error=%d\n", shared->status, shared->error_code);
  printf("done\n");
  return 0;
}

// Both contexts write to same struct fields → match.
// CHECK: Signal Safety Analysis Report
// CHECK: Main-thread candidates
// CHECK: Signal-handler candidates
// CHECK: Matched signal-safety violations
// CHECK: Match
// CHECK: LLDB script written to
