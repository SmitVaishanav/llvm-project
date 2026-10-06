// Minimal reproducer for PostgreSQL-style signal handler bug.
// PostgreSQL background workers used to call exit() from signal handlers,
// which internally calls atexit handlers, malloc, stdio — all unsafe.
// Main code also calls malloc/printf → async-signal-unsafe overlap.
//
// RUN: %clangxx_asan -O2 \
// RUN:   -mllvm -asan-detect-signal-unsafe-calls \
// RUN:   -fsanitize=address %s -o %t
// RUN: %env_asan_opts=detect_signal_unsafe_writes=1 %run %t 2>&1 | FileCheck %s

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// Simulate what PostgreSQL's signal handler did:
// call cleanup functions that use malloc/printf
void pg_cleanup(int sig) {
  char *buf = (char *)malloc(128);
  snprintf(buf, 128, "cleaning up shared memory (signal %d)", sig);
  fprintf(stderr, "%s\n", buf);
  free(buf);
}

void sigterm_handler(int sig) {
  pg_cleanup(sig);
}

int main() {
  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = sigterm_handler;
  sigaction(SIGUSR2, &sa, NULL);

  // Main: normal database operations using malloc/fprintf/free
  for (int i = 0; i < 5; i++) {
    char *p = (char *)malloc(512);
    snprintf(p, 512, "query result %d", i);
    fprintf(stdout, "query %d: %s\n", i, p);
    free(p);
  }

  // Trigger handler so it collects candidates
  raise(SIGUSR2);

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
// CHECK: Match {{.*}}: CALL to same function 'fprintf'
// CHECK: Match {{.*}}: CALL to same function 'free'
// CHECK: LLDB script written to
