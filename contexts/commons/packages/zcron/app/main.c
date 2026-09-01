/* zcron CLI: validate a cron expression and print upcoming fires. */

#include "zcron/zcron.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

int main(int argc, char **argv) {
  zcron c;
  char err[128];
  long long after;
  int count = 5;
  int i;

  if (argc < 2) {
    fprintf(stderr, "usage: zcron EXPR [AFTER_EPOCH] [COUNT]\n");
    return 2;
  }
  if (!zcron_parse(argv[1], strlen(argv[1]), &c, err, sizeof err)) {
    fprintf(stderr, "invalid: %s\n", err);
    return 1;
  }
  after = argc > 2 ? strtoll(argv[2], NULL, 10) : (long long)time(NULL);
  if (argc > 3) count = atoi(argv[3]);
  for (i = 0; i < count; i++) {
    long long n = zcron_next(&c, after);
    if (n < 0) {
      puts("never (within 8 years)");
      break;
    }
    {
      time_t tt = (time_t)n;
      char buf[32];
      struct tm tmv;
      gmtime_r(&tt, &tmv);
      strftime(buf, sizeof buf, "%Y-%m-%d %H:%M UTC", &tmv);
      printf("%lld  %s\n", n, buf);
    }
    after = n;
  }
  return 0;
}
