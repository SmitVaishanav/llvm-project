// SOUND: handler only reads shared state, never writes.
// Reading is safe — only concurrent writes cause corruption.
//
// RUN: %clangxx_asan -O0 -mllvm -asan-detect-signal-unsafe-writes %s -o %t
// RUN: %env_asan_opts=detect_signal_unsafe_writes=1 %run %t 2>&1 \
// RUN:   | FileCheck %s
//
// REQUIRES: asan-64-bits
// REQUIRES: x86_64-target-arch || aarch64-target-arch || arm64-target-arch

#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

typedef long long Vec4 __attribute__((vector_size(32)));

Vec4 shared_data = {1, 2, 3, 4};
volatile long long sum = 0;

void handler(int sig) {
  // Only READS shared_data — no write candidate.
  sum = shared_data[0] + shared_data[1] + shared_data[2] + shared_data[3];
}

int main() {
  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = handler;
  sigemptyset(&sa.sa_mask);
  sigaction(SIGUSR1, &sa, NULL);

  // Main writes to shared_data (wide write, flagged as candidate).
  Vec4 pattern = {10, 20, 30, 40};
  shared_data = pattern;

  kill(getpid(), SIGUSR1);

  printf("sum=%lld\n", (long long)sum);
  printf("done\n");
  return 0;
}

// Main has write candidate, but handler has NO write candidate.
// No match → no violation reported.
// CHECK: done
// CHECK-NOT: Match
