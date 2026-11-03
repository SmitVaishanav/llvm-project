// Fuzz target modeling CVE-2024-6387 (regreSSHion).
//
// OpenSSH's grace_alarm_handler fires SIGALRM after LoginGraceTime (30s)
// if client hasn't authenticated. The handler calls syslog → malloc
// (async-signal-unsafe) while the main pre-auth code also does malloc.
//
// This harness:
//   1. Installs an unsafe SIGALRM handler (models grace_alarm_handler)
//   2. Sets alarm(30) (models LoginGraceTime=30)
//   3. Processes fuzzed "pre-auth packets" doing malloc/free
//   4. Also fires SIGALRM via setitimer every 250ms to stack the deck
//
// AsyncSan detects: malloc/syslog/free called in both main + handler context.

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <syslog.h>
#include <sys/time.h>
#include <unistd.h>

// Models OpenSSH grace_alarm_handler (sshd.c)
// Real code: cleanup_exit → syslog → malloc (async-signal-unsafe)
static void grace_alarm_handler(int sig) {
  // syslog calls malloc internally — this is the CVE
  syslog(LOG_WARNING, "Timeout before authentication for connection");
  // Real handler also calls exit/cleanup, but syslog alone is enough
  char *buf = (char *)malloc(256);
  if (buf) {
    snprintf(buf, 256, "grace timeout signal %d", sig);
    free(buf);
  }
}

static int timer_armed = 0;

static void arm_timer() {
  if (timer_armed) return;

  openlog("sshd-fuzz", LOG_PID, LOG_AUTH);

  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = grace_alarm_handler;
  sa.sa_flags = SA_RESTART;
  sigemptyset(&sa.sa_mask);
  sigaction(SIGALRM, &sa, NULL);

  // Stack the deck: fire SIGALRM every 250ms
  struct itimerval itv;
  itv.it_interval.tv_sec = 0;
  itv.it_interval.tv_usec = 250000;
  itv.it_value.tv_sec = 0;
  itv.it_value.tv_usec = 250000;
  setitimer(ITIMER_REAL, &itv, NULL);

  timer_armed = 1;
}

// Models sshd pre-auth packet processing:
// ssh_packet_read → sshbuf_get → malloc/realloc
static void process_preauth_packet(const uint8_t *data, size_t len) {
  if (len < 4) return;

  // Packet length — clamp to reasonable size
  size_t pkt_len = data[0] + 1;  // 1–256 bytes

  // Allocate packet buffer (like sshbuf)
  char *pkt = (char *)malloc(pkt_len);
  if (!pkt) return;

  // Copy available data
  size_t copy_len = (len - 4 < pkt_len) ? len - 4 : pkt_len;
  if (copy_len > 0)
    memcpy(pkt, data + 4, copy_len);

  // "Process" packet — models key exchange / auth parsing
  // These mallocs race with SIGALRM handler's malloc
  for (size_t i = 0; i < copy_len && i < 64; i++) {
    size_t fsz = ((uint8_t)pkt[i % copy_len]) + 16;
    char *field = (char *)malloc(fsz);
    if (field) {
      snprintf(field, fsz, "field-%zu", i);
      free(field);
    }
  }

  free(pkt);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  arm_timer();
  process_preauth_packet(data, size);
  return 0;
}
