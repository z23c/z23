/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: ztime - RFC 3339 timestamp conversion CLI.
 *
 * Usage:
 *   ztime parse  TIMESTAMP...   print Unix seconds[.nanos] per argument
 *   ztime format UNIX_SECS...   print canonical UTC RFC 3339 per argument
 *
 * Exit 0 when every argument converted, 1 when any failed (failures on
 * stderr), 2 on misuse.
 */
#include "ztime/ztime.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int finish_output(int bad, bool wrote, bool failed) {
  if (wrote && (failed || fflush(stdout) != 0 || ferror(stdout))) {
    fprintf(stderr, "ztime: output write failed\n");
    return 1;
  }
  return bad;
}

static int do_parse(int argc, char **argv) {
  int bad = 0;
  bool wrote = false, failed = false;
  for (int i = 2; i < argc; i++) {
    ztime_instant it;
    if (!ztime_parse(argv[i], &it)) {
      fprintf(stderr, "ztime: invalid timestamp '%s'\n", argv[i]);
      bad = 1;
      continue;
    }
    int written = it.nanos
        ? printf("%lld.%09u\n", (long long)it.unix_secs, it.nanos)
        : printf("%lld\n", (long long)it.unix_secs);
    wrote = true;
    failed |= written < 0;
  }
  return finish_output(bad, wrote, failed);
}

static int do_format(int argc, char **argv) {
  int bad = 0;
  bool wrote = false, failed = false;
  for (int i = 2; i < argc; i++) {
    char *end = NULL;
    long long secs = strtoll(argv[i], &end, 10);
    if (!end || *end || end == argv[i]) {
      fprintf(stderr, "ztime: invalid unix seconds '%s'\n", argv[i]);
      bad = 1;
      continue;
    }
    ztime_instant it = {secs, 0};
    char buf[32];
    if (!ztime_format(&it, buf, sizeof(buf))) {
      fprintf(stderr, "ztime: out of range '%s'\n", argv[i]);
      bad = 1;
      continue;
    }
    wrote = true;
    failed |= puts(buf) == EOF;
  }
  return finish_output(bad, wrote, failed);
}

int main(int argc, char **argv) {
  if (argc < 3) {
    fprintf(stderr, "usage: ztime parse TIMESTAMP... | ztime format "
                    "UNIX_SECS...\n");
    return 2;
  }
  if (!strcmp(argv[1], "parse"))
    return do_parse(argc, argv);
  if (!strcmp(argv[1], "format"))
    return do_format(argc, argv);
  fprintf(stderr, "ztime: unknown mode '%s'\n", argv[1]);
  return 2;
}
