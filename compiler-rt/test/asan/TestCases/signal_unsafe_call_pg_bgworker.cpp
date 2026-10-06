// Test: Mimics PostgreSQL bgworker_die() — SIGTERM handler for background
// workers that calls ereport(FATAL), which internally calls malloc() via
// the error formatting and logging machinery.
//
// Modeled after: src/backend/postmaster/bgworker.c bgworker_die() (pre-fix)
// See: https://postgrespro.com/list/thread-id/2602283
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
#include <unistd.h>

// Mimics PostgreSQL's ereport(FATAL, ...) path:
//   ereport -> errstart -> errfinish -> EmitErrorReport -> syslog/fprintf
// The key issue is that ereport allocates memory via palloc (which wraps
// malloc) and calls formatting functions.
static void ereport_fatal(const char *fmt, ...) {
  // palloc -> malloc (async-signal-unsafe)
  char *buf = (char *)malloc(512);
  if (buf) {
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, 512, fmt, ap);  // async-signal-unsafe
    va_end(ap);
    fprintf(stderr, "FATAL: %s\n", buf);  // async-signal-unsafe
    free(buf);
  }
}

// Mimics PostgreSQL's bgworker_die() — default SIGTERM handler for
// background workers (removed in recent PostgreSQL versions).
static void bgworker_die(int sig) {
  ereport_fatal("terminating background worker \"%s\" due to administrator "
                "command", "test_worker");
  _exit(0);
}

int main() {
  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = bgworker_die;
  sa.sa_flags = 0;
  sigemptyset(&sa.sa_mask);

  if (sigaction(SIGTERM, &sa, NULL) != 0) {
    perror("sigaction");
    return 1;
  }

  kill(getpid(), SIGTERM);

  puts("no error detected");
  return 0;
}

// CHECK: Signal Safety Analysis Report
// CHECK: Signal-handler candidates
// CHECK: [C] call to
