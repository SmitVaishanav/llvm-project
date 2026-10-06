// Test: nested signals — depth counter goes 1 -> 2 -> 1 -> 0.
// Both the inner (SIGUSR2) and outer (SIGUSR1) handlers do a large write;
// we expect the detector to fire on the FIRST one encountered (SIGUSR1's).
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

typedef long long Vec2 __attribute__((vector_size(16)));

Vec2 *shared_ptr;

void inner_handler(int sig, siginfo_t *info, void *ctx) {
  Vec2 val = {100, 200};
  *shared_ptr = val;  // 16-byte store in nested handler (depth 2).
}

void outer_handler(int sig, siginfo_t *info, void *ctx) {
  // Raise a nested signal from within this handler.
  kill(getpid(), SIGUSR2);

  Vec2 val = {42, 43};
  *shared_ptr = val;  // 16-byte store in outer handler (depth 1).
}

int main() {
  Vec2 obj;
  shared_ptr = &obj;

  // Install SIGUSR2 handler (inner).
  struct sigaction sa2;
  memset(&sa2, 0, sizeof(sa2));
  sa2.sa_sigaction = inner_handler;
  sa2.sa_flags = SA_SIGINFO;
  sigemptyset(&sa2.sa_mask);
  if (sigaction(SIGUSR2, &sa2, NULL) != 0) {
    perror("sigaction SIGUSR2");
    return 1;
  }

  // Install SIGUSR1 handler (outer).
  // Do NOT mask SIGUSR2 so nested delivery is possible.
  struct sigaction sa1;
  memset(&sa1, 0, sizeof(sa1));
  sa1.sa_sigaction = outer_handler;
  sa1.sa_flags = SA_SIGINFO;
  sigemptyset(&sa1.sa_mask);
  if (sigaction(SIGUSR1, &sa1, NULL) != 0) {
    perror("sigaction SIGUSR1");
    return 1;
  }

  kill(getpid(), SIGUSR1);

  puts("no error detected");
  return 0;
}

// CHECK: Signal Safety Analysis Report
// CHECK: Signal-handler candidates
// CHECK: [W] write
