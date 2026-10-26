// Test ASAN_SIGNAL_LOGDIR: on signal delivery, emit a file with ns timestamp.
//
// RUN: %clangxx_asan -O0 -mllvm -asan-detect-signal-unsafe-calls %s -o %t
// RUN: rm -rf %t.logdir && mkdir %t.logdir
// RUN: ASAN_SIGNAL_LOGDIR=%t.logdir %env_asan_opts=detect_signal_unsafe_writes=1 %run %t
// RUN: test $(ls %t.logdir | wc -l) -eq 1
// RUN: cat %t.logdir/* | grep -q "^10 "
//
// REQUIRES: asan-64-bits
// REQUIRES: x86_64-target-arch || aarch64-target-arch || arm64-target-arch

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

volatile int got_signal = 0;

void handler(int sig) {
  got_signal = 1;
}

int main() {
  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = handler;
  sa.sa_flags = 0;
  sigemptyset(&sa.sa_mask);

  if (sigaction(SIGUSR1, &sa, NULL) != 0) {
    perror("sigaction");
    return 1;
  }

  raise(SIGUSR1);

  printf("got_signal=%d\n", got_signal);
  return 0;
}
