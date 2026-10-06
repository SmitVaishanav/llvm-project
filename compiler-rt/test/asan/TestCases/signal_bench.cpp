// Microbenchmark for async-signal-safety instrumentation overhead.
// Not a lit test — run via signal_bench.sh for full comparison.
//
// Measures 4 operation types independently:
//   1. Wide writes (>8 bytes, non-atomic) — -asan-detect-signal-unsafe-writes
//   2. GEP writes (struct field stores) — -asan-detect-signal-unsafe-gep-writes
//   3. Unsafe calls (malloc/free) — -asan-detect-signal-unsafe-calls
//   4. Libc calls (snprintf/fprintf, no allocator) — -asan-detect-signal-unsafe-calls
//   5. Small writes (<=8 bytes) — control, should have zero extra overhead

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifndef ITERATIONS
#define ITERATIONS 5000000
#endif

typedef long long Vec4 __attribute__((vector_size(32)));

// Globals to prevent optimization
volatile long long sink;
Vec4 wide_buf;
struct Pair { long long x, y; } pair_buf;

// Dummy handler — just needs to be registered to activate instrumentation.
void dummy_handler(int sig) { (void)sig; }

static double now() {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return ts.tv_sec + ts.tv_nsec / 1e9;
}

void bench_wide_writes(int n) {
  Vec4 val = {1, 2, 3, 4};
  for (int i = 0; i < n; i++) {
    wide_buf = val;
    __asm__ volatile("" ::: "memory");
    val[0] = i;
  }
  sink = wide_buf[0];
}

void bench_gep_writes(int n) {
  for (int i = 0; i < n; i++) {
    pair_buf.x = i;
    pair_buf.y = i + 1;
    __asm__ volatile("" ::: "memory");
  }
  sink = pair_buf.x;
}

void bench_unsafe_calls(int n) {
  for (int i = 0; i < n; i++) {
    void *p = malloc(64);
    __asm__ volatile("" :: "r"(p) : "memory");
    free(p);
  }
}

void bench_libc_calls(int n) {
  char buf[128];
  FILE *f = fopen("/dev/null", "w");
  for (int i = 0; i < n; i++) {
    snprintf(buf, sizeof(buf), "item %d", i);
    fprintf(f, "%s", buf);
    __asm__ volatile("" ::: "memory");
  }
  fclose(f);
}

void bench_small_writes(int n) {
  volatile long long v = 0;
  for (int i = 0; i < n; i++) {
    v = i;
    __asm__ volatile("" ::: "memory");
  }
  sink = v;
}

int main(int argc, char **argv) {
  int register_handler = 0;
  if (argc > 1 && strcmp(argv[1], "--handler") == 0)
    register_handler = 1;

  if (register_handler) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = dummy_handler;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGUSR1, &sa, NULL);
  }

  int n = ITERATIONS;
  double t;

  t = now(); bench_wide_writes(n); t = now() - t;
  printf("wide_writes:  %.4f s  (%d iters, handler=%d)\n", t, n, register_handler);

  t = now(); bench_gep_writes(n); t = now() - t;
  printf("gep_writes:   %.4f s  (%d iters, handler=%d)\n", t, n, register_handler);

  t = now(); bench_unsafe_calls(n); t = now() - t;
  printf("unsafe_calls: %.4f s  (%d iters, handler=%d)\n", t, n, register_handler);

  t = now(); bench_libc_calls(n); t = now() - t;
  printf("libc_calls:   %.4f s  (%d iters, handler=%d)\n", t, n, register_handler);

  t = now(); bench_small_writes(n); t = now() - t;
  printf("small_writes: %.4f s  (%d iters, handler=%d)\n", t, n, register_handler);

  return 0;
}
