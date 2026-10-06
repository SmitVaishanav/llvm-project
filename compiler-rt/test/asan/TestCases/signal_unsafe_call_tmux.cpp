// Reproducer based on tmux signal handling pattern.
// tmux's client_signal() handler calls log_debug() which uses
// vsnprintf internally, and also calls strsignal/strerror
// (both async-signal-unsafe). Main code also uses snprintf/malloc.
//
// Source: tmux/client.c:513 — client_signal()
//
// RUN: %clangxx_asan -O2 \
// RUN:   -mllvm -asan-detect-signal-unsafe-calls \
// RUN:   -fsanitize=address %s -o %t
// RUN: %env_asan_opts=detect_signal_unsafe_writes=1 %run %t 2>&1 | FileCheck %s

#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Simulates tmux log_debug("%s: %s", __func__, strsignal(sig))
static void log_debug(const char *fmt, ...) {
  char buf[256];
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(buf, sizeof(buf), fmt, ap);
  va_end(ap);
  fprintf(stderr, "debug: %s\n", buf);
}

static void client_signal(int sig) {
  // tmux calls log_debug + strsignal in signal handler
  const char *signame = strsignal(sig);
  log_debug("client_signal: %s", signame);

  // tmux also calls proc_send which writes to a socket
  // (write() is safe, but strsignal/vsnprintf are not)
}

int main() {
  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = client_signal;
  sa.sa_flags = SA_RESTART;
  sigaction(SIGUSR1, &sa, NULL);

  // Main: tmux event loop uses malloc/snprintf
  for (int i = 0; i < 5; i++) {
    char *buf = (char *)malloc(128);
    snprintf(buf, 128, "event %d processed", i);
    fprintf(stdout, "%s\n", buf);
    free(buf);
  }

  raise(SIGUSR1);
  printf("done\n");
  return 0;
}

// CHECK: done
// CHECK: Signal Safety Analysis Report
// CHECK: Signal-handler candidates
// CHECK: [C] call to 'vsnprintf'
// CHECK: Matched signal-safety violations
// CHECK: Match {{.*}}: CALL to same function
