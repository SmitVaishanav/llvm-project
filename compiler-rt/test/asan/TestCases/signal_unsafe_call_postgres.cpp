// Test: Mimics PostgreSQL BUG #11095 — quickdie() calls syslog() inside a
// SIGQUIT signal handler, which can deadlock when syslog's internal malloc
// is interrupted.
//
// Modeled after: src/backend/tcop/postgres.c quickdie() in PostgreSQL <= 9.3
// See: https://www.postgresql.org/message-id/20140730233328.2696.87275@wrigleys.postgresql.org
//
// RUN: %clangxx_asan -O0 -mllvm -asan-detect-signal-unsafe-calls %s -o %t
// RUN: %env_asan_opts=detect_signal_unsafe_writes=1 %run %t 2>&1 \
// RUN:   | FileCheck %s
//
// REQUIRES: asan-64-bits
// REQUIRES: x86_64-target-arch || aarch64-target-arch || arm64-target-arch

#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

// Mimics PostgreSQL's ereport() -> syslog() path in quickdie().
static void pg_ereport(const char *fmt, ...) {
  char buf[256];
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(buf, sizeof(buf), fmt, ap);  // async-signal-unsafe
  va_end(ap);
  openlog("postgres", LOG_PID, LOG_LOCAL0);  // async-signal-unsafe
  syslog(LOG_ERR, "%s", buf);               // async-signal-unsafe
  closelog();                                // async-signal-unsafe
}

// Mimics PostgreSQL's quickdie() — SIGQUIT handler.
static void quickdie(int sig) {
  pg_ereport("terminating connection due to administrator command");
  _exit(0);
}

int main() {
  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = quickdie;
  sa.sa_flags = 0;
  sigemptyset(&sa.sa_mask);

  if (sigaction(SIGQUIT, &sa, NULL) != 0) {
    perror("sigaction");
    return 1;
  }

  kill(getpid(), SIGQUIT);

  puts("no error detected");
  return 0;
}

// CHECK: Signal Safety Analysis Report
// CHECK: Signal-handler candidates
// CHECK: [C] call to
