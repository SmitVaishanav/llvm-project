// SOUND: main and handler both do wide writes, but to DIFFERENT addresses.
// No overlap → no match → no violation.
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

Vec4 main_data;
Vec4 handler_data;

void handler(int sig) {
  // Writes to handler_data — different address than main.
  Vec4 val = {5, 6, 7, 8};
  handler_data = val;
}

int main() {
  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = handler;
  sigemptyset(&sa.sa_mask);
  sigaction(SIGUSR1, &sa, NULL);

  // Writes to main_data — different address than handler.
  Vec4 val = {1, 2, 3, 4};
  main_data = val;

  kill(getpid(), SIGUSR1);

  printf("done\n");
  return 0;
}

// Both contexts write 32 bytes, but to different addresses.
// Candidates collected in both, but no overlapping range → no match.
// CHECK: Signal Safety Analysis Report
// CHECK: Main-thread candidates
// CHECK: [W] write
// CHECK: Signal-handler candidates
// CHECK: [W] write
// CHECK: No matches found
