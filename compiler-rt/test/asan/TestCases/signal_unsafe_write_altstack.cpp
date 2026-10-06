// Test: handler running on an alternate signal stack (sigaltstack) is still detected.
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

void handler(int sig, siginfo_t *info, void *ctx) {
  Vec2 val = {77, 88};
  *shared_ptr = val;  // 16-byte non-atomic store on alternate stack.
}

int main() {
  Vec2 obj;
  shared_ptr = &obj;

  // Set up an alternate signal stack.
  stack_t ss;
  ss.ss_sp = malloc(SIGSTKSZ);
  if (ss.ss_sp == NULL) {
    perror("malloc");
    return 1;
  }
  ss.ss_size = SIGSTKSZ;
  ss.ss_flags = 0;
  if (sigaltstack(&ss, NULL) != 0) {
    perror("sigaltstack");
    return 1;
  }

  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_sigaction = handler;
  sa.sa_flags = SA_SIGINFO | SA_ONSTACK;
  sigemptyset(&sa.sa_mask);

  if (sigaction(SIGUSR1, &sa, NULL) != 0) {
    perror("sigaction");
    return 1;
  }

  kill(getpid(), SIGUSR1);

  puts("no error detected");
  free(ss.ss_sp);
  return 0;
}

// CHECK: Signal Safety Analysis Report
// CHECK: Signal-handler candidates
// CHECK: [W] write
