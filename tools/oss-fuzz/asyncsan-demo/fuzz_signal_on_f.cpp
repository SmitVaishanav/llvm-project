// Fuzz target: sends itself SIGALRM when input contains 'f'.
// Unsafe handler calls malloc/snprintf — AsyncSan should detect the violation.
//
// Models CVE-2024-6387: SIGALRM fires while main code holds malloc lock.

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

static volatile int handler_called = 0;

static void unsafe_handler(int sig) {
  // async-signal-unsafe: malloc + snprintf inside signal handler
  char *buf = (char *)malloc(128);
  if (buf) {
    snprintf(buf, 128, "caught signal %d", sig);
    free(buf);
  }
  handler_called = 1;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  // Install unsafe handler for SIGALRM
  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = unsafe_handler;
  sigemptyset(&sa.sa_mask);
  sigaction(SIGALRM, &sa, NULL);

  // Main-thread work: malloc/free that races with handler
  for (size_t i = 0; i < size && i < 64; i++) {
    char *p = (char *)malloc(data[i] + 1);
    if (p) {
      snprintf(p, data[i] + 1, "main-%zu", i);
      // When we see 'f', fire the signal mid-malloc-region
      if (data[i] == 'f')
        raise(SIGALRM);
      free(p);
    }
  }

  signal(SIGALRM, SIG_DFL);
  return 0;
}
