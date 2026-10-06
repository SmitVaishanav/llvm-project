// UNSOUND: handler has both wide writes AND unsafe calls that match main.
// Detector should report both write and call matches.
//
// RUN: %clangxx_asan -O0 -mllvm -asan-detect-signal-unsafe-writes \
// RUN:   -mllvm -asan-detect-signal-unsafe-calls %s -o %t
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

Vec4 *shared;

void handler(int sig) {
  // Wide write (same address as main).
  Vec4 val = {9, 9, 9, 9};
  *shared = val;
  // Unsafe call (same function as main).
  void *p = malloc(16);
  free(p);
}

int main() {
  Vec4 state = {1, 2, 3, 4};
  shared = &state;

  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = handler;
  sigemptyset(&sa.sa_mask);
  sigaction(SIGUSR1, &sa, NULL);

  // Wide write to same address.
  Vec4 val = {5, 6, 7, 8};
  *shared = val;

  // Unsafe call.
  void *p = malloc(32);
  free(p);

  kill(getpid(), SIGUSR1);

  printf("done\n");
  return 0;
}

// Both write AND call matches.
// CHECK: Signal Safety Analysis Report
// CHECK: Matched signal-safety violations
// CHECK: WRITE to overlapping address range
// CHECK: CALL to same function 'malloc'
// CHECK: LLDB script written to
