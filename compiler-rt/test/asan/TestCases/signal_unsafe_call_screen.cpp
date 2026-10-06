// Reproducer based on GNU Screen signal handling pattern.
// Screen's AttacherFinit() handler (SIGHUP) calls MakeClientSocket(),
// WriteMessage(), and then exit(0). AttacherFinitBye() calls Panic()
// which uses fprintf/vfprintf, then exit().
// All of these are async-signal-unsafe.
//
// Source: screen/src/attacher.c:315 — AttacherFinit()
//        screen/src/attacher.c:345 — AttacherFinitBye()
//
// RUN: %clangxx_asan -O2 \
// RUN:   -mllvm -asan-detect-signal-unsafe-calls \
// RUN:   -fsanitize=address %s -o %t
// RUN: %env_asan_opts=detect_signal_unsafe_writes=1 %run %t 2>&1 | FileCheck %s

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Simulates Screen's Panic() which does fprintf + exit
static void Panic(int err, const char *msg) {
  fprintf(stderr, "PANIC: %s (errno=%d)\n", msg, err);
  // Real Panic calls exit(), but we skip to avoid killing the test
}

// Simulates AttacherFinitBye — the SIGHUP/SIG_BYE handler
static void AttacherFinitBye(int sig) {
  // Screen handler does: setgid, setuid, Kill(ppid, SIGHUP), exit(0)
  // Panic is called if setgid/setuid fails
  char *buf = (char *)malloc(64);
  snprintf(buf, 64, "cleaning up signal %d", sig);
  Panic(0, buf);
  free(buf);
}

int main() {
  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = AttacherFinitBye;
  sigaction(SIGUSR1, &sa, NULL);

  // Main: screen event loop uses malloc/fprintf
  for (int i = 0; i < 5; i++) {
    char *msg = (char *)malloc(128);
    snprintf(msg, 128, "processing input %d", i);
    fprintf(stdout, "%s\n", msg);
    free(msg);
  }

  raise(SIGUSR1);
  printf("done\n");
  return 0;
}

// CHECK: done
// CHECK: Signal Safety Analysis Report
// CHECK: Signal-handler candidates
// CHECK: [C] call to 'malloc'
// CHECK: Matched signal-safety violations
// CHECK: Match {{.*}}: CALL to same function
