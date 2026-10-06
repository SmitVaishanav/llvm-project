// Reproducer for bash SIGALRM/TMOUT signal safety bug (bug-bash 2026-08).
// bash's alrm_catcher() handler runs bash_logout() which executes
// arbitrary shell commands — calls malloc/printf/fflush internally.
// Main shell loop also uses malloc/printf for command processing.
//
// Source: bash/eval.c:256 — alrm_catcher()
// Ref: https://lists.gnu.org/archive/html/bug-bash/2026-08/msg00104.html
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

// Simulates bash_logout() — sources ~/.bash_logout, runs commands
static void bash_logout() {
  char *buf = (char *)malloc(256);
  snprintf(buf, 256, "Running logout commands...");
  fprintf(stderr, "%s\n", buf);
  free(buf);
}

// bash eval.c:256 — alrm_catcher
static void alrm_catcher(int sig) {
  const char *msg = "timed out waiting for input: auto-logout\n";
  write(STDOUT_FILENO, msg, strlen(msg));  // this part is safe
  bash_logout();  // THIS IS THE BUG — runs arbitrary code in handler
  // real code also calls jump_to_top_level(EXITPROG) — longjmp, also unsafe
}

int main() {
  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = alrm_catcher;
  sigaction(SIGALRM, &sa, NULL);

  // Main: shell command processing loop
  for (int i = 0; i < 5; i++) {
    char *cmd = (char *)malloc(128);
    snprintf(cmd, 128, "echo command_%d", i);
    fprintf(stdout, "executing: %s\n", cmd);
    free(cmd);
  }

  raise(SIGALRM);
  printf("done\n");
  return 0;
}

// CHECK: done
// CHECK: Signal Safety Analysis Report
// CHECK: Signal-handler candidates
// CHECK: [C] call to 'malloc'
// CHECK: Matched signal-safety violations
// CHECK: Match {{.*}}: CALL to same function 'malloc'
