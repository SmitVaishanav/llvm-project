// SOUND: handler only calls async-signal-safe functions.
// write(), _exit(), signal() are all on the POSIX safe list.
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
  // All async-signal-safe per POSIX:
  const char msg[] = "caught signal\n";
  write(STDERR_FILENO, msg, sizeof(msg) - 1);
  signal(sig, SIG_DFL);
}

int main() {
  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = handler;
  sigemptyset(&sa.sa_mask);
  sigaction(SIGUSR1, &sa, NULL);

  // Main calls unsafe functions, but handler doesn't — no match.
  void *p = malloc(64);
  free(p);
  printf("triggering signal\n");

  kill(getpid(), SIGUSR1);

  printf("done\n");
  return 0;
}

// Handler only calls safe functions → no signal-handler call candidates.
// Main has call candidates but nothing to match against.
// CHECK: done
// CHECK-NOT: Match
