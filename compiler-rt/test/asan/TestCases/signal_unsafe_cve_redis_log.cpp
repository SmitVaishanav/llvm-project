// Minimal reproducer for Redis-style signal handler bug.
// Redis SIGSEGV/SIGBUS handler called serverLog() → snprintf/malloc/write.
// Also called rdbSave() for crash dump which does heavy I/O and allocation.
// Main code also uses malloc/snprintf → async-signal-unsafe overlap.
//
// RUN: %clangxx_asan -O2 \
// RUN:   -mllvm -asan-detect-signal-unsafe-calls \
// RUN:   -fsanitize=address %s -o %t
// RUN: %env_asan_opts=detect_signal_unsafe_writes=1 %run %t 2>&1 | FileCheck %s

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Simulate Redis serverLog() — calls snprintf + malloc
void serverLog(const char *fmt, int val) {
  char *buf = (char *)malloc(256);
  snprintf(buf, 256, fmt, val);
  free(buf);
}

void sigsegv_handler(int sig) {
  // Redis crash handler: log state + attempt RDB save
  serverLog("Signal %d received, saving state", sig);
}

int main() {
  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = sigsegv_handler;
  // Use SIGUSR1 instead of SIGSEGV to avoid ASan interference
  sigaction(SIGUSR1, &sa, NULL);

  // Main: Redis command processing loop
  for (int i = 0; i < 10; i++) {
    char *cmd = (char *)malloc(64);
    snprintf(cmd, 64, "SET key%d value%d", i, i);
    free(cmd);
  }

  // Trigger handler so it collects candidates
  raise(SIGUSR1);

  printf("done\n");
  return 0;
}

// CHECK: done
// CHECK: Signal Safety Analysis Report
// CHECK: Main-thread candidates
// CHECK: [C] call to 'malloc'
// CHECK: Signal-handler candidates
// CHECK: [C] call to 'malloc'
// CHECK: Matched signal-safety violations
// CHECK: Match {{.*}}: CALL to same function 'malloc'
// CHECK: Match {{.*}}: CALL to same function 'snprintf'
// CHECK: Match {{.*}}: CALL to same function 'free'
// CHECK: LLDB script written to
