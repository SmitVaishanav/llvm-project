// Test: Mimics Redis signal handler bug — sigtermHandler calls redisLog()
// which internally uses snprintf/fprintf, both async-signal-unsafe.
//
// Modeled after: src/server.c sigtermHandler() in Redis <= 7.x
// See: https://github.com/redis/redis/issues/213
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

// Mimics Redis's redisLog() — formats and writes a log message.
static void redisLog(int level, const char *fmt, ...) {
  char msg[256];
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(msg, sizeof(msg), fmt, ap);  // async-signal-unsafe
  va_end(ap);
  fprintf(stderr, "[%d] %s\n", getpid(), msg);  // async-signal-unsafe
}

// Mimics Redis's sigtermHandler().
static void sigtermHandler(int sig) {
  redisLog(0, "Received SIGTERM scheduling shutdown...");
  // In real Redis, this sets server.shutdown_asap = 1
  _exit(0);
}

int main() {
  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = sigtermHandler;
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
