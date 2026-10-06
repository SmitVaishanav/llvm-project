// SOUND: no signal handler registered → no candidates collected at all.
// The detector should be completely silent.
//
// RUN: %clangxx_asan -O0 -mllvm -asan-detect-signal-unsafe-writes \
// RUN:   -mllvm -asan-detect-signal-unsafe-calls %s -o %t
// RUN: %env_asan_opts=detect_signal_unsafe_writes=1 %run %t 2>&1 \
// RUN:   | FileCheck %s
//
// REQUIRES: asan-64-bits
// REQUIRES: x86_64-target-arch || aarch64-target-arch || arm64-target-arch

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct BigStruct {
  long long a, b, c, d;
};

int main() {
  // No sigaction/signal call → __asan_signal_handler_registered stays 0.
  // All instrumented writes and calls should be skipped.
  struct BigStruct s;
  memset(&s, 0, sizeof(s));
  s.a = 1; s.b = 2; s.c = 3; s.d = 4;

  void *p = malloc(128);
  free(p);

  printf("done\n");
  return 0;
}

// No handler registered → no report at all.
// CHECK: done
// CHECK-NOT: Signal Safety Analysis Report
