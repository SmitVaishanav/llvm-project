// UNSOUND: both main and handler call multiple async-signal-unsafe functions.
// Detector should match each shared function.
//
// RUN: %clangxx_asan -O0 -mllvm -asan-detect-signal-unsafe-calls %s -o %t
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

void handler(int sig) {
  // Multiple unsafe calls — all also called in main.
  void *p = malloc(32);
  free(p);
  fprintf(stderr, "handler ran\n");
}

int main() {
  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = handler;
  sigemptyset(&sa.sa_mask);
  sigaction(SIGUSR1, &sa, NULL);

  // Same unsafe calls in main context.
  void *p = malloc(64);
  free(p);
  fprintf(stderr, "main running\n");

  kill(getpid(), SIGUSR1);

  printf("done\n");
  return 0;
}

// Multiple functions called in both contexts → multiple matches.
// CHECK: Signal Safety Analysis Report
// CHECK: Matched signal-safety violations
// CHECK: CALL to same function 'malloc'
// CHECK: CALL to same function 'free'
// CHECK: LLDB script written to
