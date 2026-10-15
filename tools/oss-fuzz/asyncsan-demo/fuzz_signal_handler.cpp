// Fuzz target: exercises signal handler patterns with fuzzer-driven input.
// Detects async-signal-safety violations via AsyncSan instrumentation.
//
// Models real CVEs:
//   CVE-2024-6387 (OpenSSH): SIGALRM handler calls malloc/syslog
//   BUG #11095 (PostgreSQL): SIGQUIT handler calls syslog/malloc

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>

// Simulates async-signal-unsafe work in a signal handler
// (like OpenSSH's grace_alarm_handler calling syslog → malloc)
static volatile int handler_called = 0;

static void unsafe_handler(int sig) {
    // These are all async-signal-unsafe — AsyncSan should flag them
    char *buf = (char *)malloc(256);
    if (buf) {
        snprintf(buf, 256, "signal %d received", sig);
        free(buf);
    }
    handler_called = 1;
}

static void trivial_handler(int sig) {
    // This is safe — just sets a flag
    handler_called = 1;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 2) return 0;

    // Fuzzer controls which signal and handler type
    int signum_choice = data[0] % 3;
    int handler_type = data[1] % 2;

    int signum;
    switch (signum_choice) {
        case 0: signum = SIGALRM; break;  // CVE-2024-6387 signal
        case 1: signum = SIGUSR1; break;
        default: signum = SIGUSR2; break;
    }

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handler_type ? unsafe_handler : trivial_handler;
    sigemptyset(&sa.sa_mask);
    sigaction(signum, &sa, NULL);

    // Main-thread work: allocations that overlap with handler
    for (size_t i = 2; i < size && i < 64; i++) {
        char *p = (char *)malloc(data[i] + 1);
        if (p) {
            snprintf(p, data[i] + 1, "work-%zu", i);
            free(p);
        }
    }

    // Trigger signal handler
    raise(signum);

    // Reset handler
    signal(signum, SIG_DFL);
    return 0;
}
