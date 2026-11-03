// Fuzz target with periodic signal delivery every 250ms.
// Stacks the deck: setitimer fires SIGALRM into unsafe handler while
// main thread does malloc/snprintf/free — maximizes chance of catching
// async-signal-safety violations.
//
// Usage: compile with -fsanitize=address,fuzzer -mllvm -asan-detect-signal-unsafe-calls
// Run with: ASAN_OPTIONS=detect_signal_unsafe_writes=1

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/time.h>

static volatile int handler_called = 0;

static void unsafe_handler(int sig) {
  // async-signal-unsafe: malloc + snprintf + free in signal context
  char *buf = (char *)malloc(128);
  if (buf) {
    snprintf(buf, 128, "caught signal %d", sig);
    free(buf);
  }
  handler_called = 1;
}

static int timer_armed = 0;

static void arm_timer() {
  if (timer_armed) return;
  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = unsafe_handler;
  sigemptyset(&sa.sa_mask);
  sigaction(SIGALRM, &sa, NULL);

  // Fire SIGALRM every 250ms
  struct itimerval itv;
  itv.it_interval.tv_sec = 0;
  itv.it_interval.tv_usec = 250000;
  itv.it_value.tv_sec = 0;
  itv.it_value.tv_usec = 250000;
  setitimer(ITIMER_REAL, &itv, NULL);
  timer_armed = 1;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  arm_timer();

  // Main-thread work: malloc/snprintf/free that races with SIGALRM handler
  for (size_t i = 0; i < size && i < 128; i++) {
    char *p = (char *)malloc(data[i] + 1);
    if (p) {
      snprintf(p, data[i] + 1, "work-%zu", i);
      free(p);
    }
  }

  return 0;
}
