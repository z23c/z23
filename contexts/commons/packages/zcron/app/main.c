/* zcron CLI: validate a cron expression and print upcoming fires. */

#include "zcron/zcron.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <limits.h>

static int parse_epoch(const char *text, long long *epoch) {
  errno = 0;
  char *end;
  long long value = strtoll(text, &end, 10);
  if (end == text || *end || errno == ERANGE) {
    fprintf(stderr, "zcron: bad epoch\n");
    return 2;
  }
  *epoch = value;
  return 0;
}

static int parse_count(const char *text, int *count) {
  errno = 0;
  char *end;
  long value = strtol(text, &end, 10);
  if (end == text || *end || errno == ERANGE || value < INT_MIN || value > INT_MAX) {
    fprintf(stderr, "zcron: bad count\n");
    return 2;
  }
  *count = (int)value;
  return 0;
}

static int clock_epoch(long long *epoch) {
  time_t now = time(NULL);
  long long value = (long long)now;
  if (now == (time_t)-1 || (time_t)value != now || (now > 0 && value < 0)) {
    fprintf(stderr, "zcron: clock unavailable or out of range\n");
    return 1;
  }
  *epoch = value;
  return 0;
}

struct output_state { int attempted, failed; };

static void record_output(struct output_state *out, int written) {
  out->attempted = 1;
  if (written < 0) out->failed = 1;
}

static int finish_output(const struct output_state *out, int result) {
  if (out->attempted && (out->failed || fflush(stdout) != 0 || ferror(stdout))) {
    fprintf(stderr, "zcron: output write failed\n");
    return 1;
  }
  return result;
}

static int render_fire(long long epoch, struct output_state *out) {
  time_t tt = (time_t)epoch;
  struct tm tmv;
  char buf[32];
  if ((long long)tt != epoch || !gmtime_r(&tt, &tmv) ||
      strftime(buf, sizeof buf, "%Y-%m-%d %H:%M UTC", &tmv) == 0) {
    fprintf(stderr, "zcron: calendar conversion failed\n");
    return 1;
  }
  record_output(out, printf("%lld  %s\n", epoch, buf));
  return out->failed ? 1 : 0;
}

static int run_schedule(const zcron *c, long long after, int count,
                         struct output_state *out) {
  for (int i = 0; i < count; i++) {
    long long next = zcron_next(c, after);
    if (next < 0) {
      record_output(out, puts("never (within 8 years)"));
      break;
    }
    if (render_fire(next, out) != 0) return 1;
    after = next;
  }
  return 0;
}

int main(int argc, char **argv) {
  zcron c;
  char err[128];
  long long after;
  int count = 5;

  if (argc < 2) {
    fprintf(stderr, "usage: zcron EXPR [AFTER_EPOCH] [COUNT]\n");
    return 2;
  }
  if (!zcron_parse(argv[1], strlen(argv[1]), &c, err, sizeof err)) {
    fprintf(stderr, "invalid: %s\n", err);
    return 1;
  }
  int result = argc > 2 ? parse_epoch(argv[2], &after) : clock_epoch(&after);
  if (result) return result;
  if (argc > 3 && parse_count(argv[3], &count) != 0) return 2;
  struct output_state out = {0};
  result = run_schedule(&c, after, count, &out);
  return finish_output(&out, result);
}
