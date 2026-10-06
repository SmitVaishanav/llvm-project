// Test: Demonstrates that a non-atomic write in a signal handler can corrupt
// data that the main program is actively using. This is a proof-of-concept
// showing the real-world impact of async-signal-unsafe writes.
//
// Scenario:
//   1. Main thread repeatedly writes a known pattern to a shared struct
//   2. A timer signal (SIGALRM) fires and the handler overwrites the struct
//      with a different pattern
//   3. Main thread detects torn/corrupted data (mix of both patterns)
//
// This mimics real bugs like regreSSHion where a signal handler writes to
// shared state that the main program is also using.
//
// RUN: %clangxx_asan -O0 -mllvm -asan-detect-signal-unsafe-writes %s -o %t
// RUN: %env_asan_opts=detect_signal_unsafe_writes=1 %run %t 2>&1 \
// RUN:   | FileCheck %s
//
// REQUIRES: asan-64-bits
// REQUIRES: x86_64-target-arch || aarch64-target-arch || arm64-target-arch

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>

// A 32-byte vector — too large to write atomically on any architecture.
typedef long long Vec4 __attribute__((vector_size(32)));

Vec4 *shared;
volatile int handler_ran = 0;

// Signal handler overwrites shared state with pattern 0x2222...
// This is a non-atomic 32-byte write — async-signal-unsafe.
void handler(int sig) {
  Vec4 poison = {0x2222222222222222LL, 0x2222222222222222LL,
                 0x2222222222222222LL, 0x2222222222222222LL};
  // Non-atomic write to shared memory — ASan should flag this.
  *shared = poison;
  handler_ran = 1;
}

int main() {
  Vec4 state;
  shared = &state;

  // Install SIGALRM handler.
  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = handler;
  sa.sa_flags = 0;
  sigemptyset(&sa.sa_mask);
  if (sigaction(SIGALRM, &sa, NULL) != 0) {
    perror("sigaction");
    return 1;
  }

  // Set up a fast timer to fire SIGALRM frequently.
  struct itimerval timer;
  timer.it_value.tv_sec = 0;
  timer.it_value.tv_usec = 1000;   // 1ms initial
  timer.it_interval.tv_sec = 0;
  timer.it_interval.tv_usec = 500; // 0.5ms interval
  setitimer(ITIMER_REAL, &timer, NULL);

  int corruption_detected = 0;
  Vec4 pattern1 = {0x1111111111111111LL, 0x1111111111111111LL,
                   0x1111111111111111LL, 0x1111111111111111LL};

  // Repeatedly write pattern1 and check for torn reads.
  // A signal interrupting mid-write can leave a mix of patterns.
  for (int i = 0; i < 1000000 && !corruption_detected; i++) {
    // Write our pattern.
    *shared = pattern1;

    // Read back individual elements and check for torn state.
    long long v0 = shared[0][0];
    long long v1 = shared[0][1];
    long long v2 = shared[0][2];
    long long v3 = shared[0][3];

    int has_1 = (v0 == 0x1111111111111111LL) || (v1 == 0x1111111111111111LL) ||
                (v2 == 0x1111111111111111LL) || (v3 == 0x1111111111111111LL);
    int has_2 = (v0 == 0x2222222222222222LL) || (v1 == 0x2222222222222222LL) ||
                (v2 == 0x2222222222222222LL) || (v3 == 0x2222222222222222LL);

    if (has_1 && has_2) {
      printf("DATA CORRUPTION DETECTED at iteration %d!\n", i);
      printf("  [0] = 0x%llx\n", v0);
      printf("  [1] = 0x%llx\n", v1);
      printf("  [2] = 0x%llx\n", v2);
      printf("  [3] = 0x%llx\n", v3);
      corruption_detected = 1;
    }
  }

  // Disable timer.
  memset(&timer, 0, sizeof(timer));
  setitimer(ITIMER_REAL, &timer, NULL);

  if (!corruption_detected && handler_ran) {
    printf("Signal handler ran but no torn write observed in this run "
           "(timing-dependent — the bug is still real).\n");
  }

  // ASan flags the non-atomic write in the handler regardless of whether
  // we observed corruption — that's the point of the detector.
  printf("done\n");
  return 0;
}

// The detector fires on the signal handler's 32-byte struct write.
// CHECK: done
// CHECK: Signal Safety Analysis Report
// CHECK: Main-thread candidates
// CHECK: [W] write
// CHECK: Signal-handler candidates
// CHECK: [W] write
// CHECK: Matched signal-safety violations
// CHECK: Match {{.*}}: WRITE to overlapping address range
// CHECK: LLDB script written to
