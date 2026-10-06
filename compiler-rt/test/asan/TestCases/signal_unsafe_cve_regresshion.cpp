// Minimal reproducer for regreSSHion (CVE-2024-6387) pattern.
// OpenSSH's SIGALRM handler called syslog(), which internally calls malloc().
// Main code also calls malloc() → async-signal-unsafe overlap.
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

// Simulate syslog() — internally calls malloc/snprintf/free
void fake_syslog(const char *msg) {
  char *buf = (char *)malloc(256);
  snprintf(buf, 256, "LOG: %s", msg);
  free(buf);
}

void sigalrm_handler(int sig) {
  // CVE-2024-6387: OpenSSH called syslog() in SIGALRM handler
  fake_syslog("login timeout expired");
}

int main() {
  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = sigalrm_handler;
  sigaction(SIGALRM, &sa, NULL);

  // Main code: authentication loop allocates memory
  for (int i = 0; i < 10; i++) {
    char *p = (char *)malloc(1024);
    snprintf(p, 1024, "auth attempt %d", i);
    printf("%s\n", p);
    free(p);
  }

  // Trigger handler so it collects candidates
  raise(SIGALRM);

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
