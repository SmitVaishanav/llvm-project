// Benchmark: measures overhead of asyncsan instrumentation.
// Runs a tight loop performing writes and function calls, with and without
// signal handler context. Not a lit test — run manually for benchmarking.
//
// Build 3 ways:
//   1. clang++ -O2 bench.cpp -o bench_baseline
//   2. clang++ -O2 -fsanitize=address bench.cpp -o bench_asan
//   3. clang++ -O2 -fsanitize=address -mllvm -asan-detect-signal-unsafe-writes
//      -mllvm -asan-detect-signal-unsafe-calls bench.cpp -o bench_asyncsan

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define ITERATIONS 10000000

// Simulate a workload with writes and function calls.
volatile long long sink;
char buf[4096];

void do_work() {
  for (int i = 0; i < ITERATIONS; i++) {
    // 16-byte write (would be checked by wide-write detector)
    memcpy(buf, buf + 16, 16);
    // Function calls (would be checked by unsafe-call detector)
    snprintf(buf, sizeof(buf), "iteration %d value %lld", i, sink);
    sink = buf[0] + buf[1];
  }
}

int main() {
  struct timespec start, end;

  clock_gettime(CLOCK_MONOTONIC, &start);
  do_work();
  clock_gettime(CLOCK_MONOTONIC, &end);

  double elapsed = (end.tv_sec - start.tv_sec) +
                   (end.tv_nsec - start.tv_nsec) / 1e9;
  printf("elapsed: %.3f seconds (%d iterations)\n", elapsed, ITERATIONS);
  return 0;
}
