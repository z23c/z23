/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: inidump - parse INI from stdin and print a flattened,
 *          deterministic "section.key = value" dump.
 *
 * Usage: inidump < config.ini
 *
 * Input is bounded at 16 MiB.  Entries print in sorted (section, key)
 * order; global-section keys print with an empty section prefix.
 */
#include "zini/zini.h"

#include <stdio.h>
#include <stdlib.h>

#define MAX_INPUT (16u * 1024u * 1024u)

static void print_entry(void *ctx, const char *section, const char *key,
                        const char *value) {
  (void)ctx;
  if (section[0] != '\0')
    printf("[%s] ", section);
  printf("%s = %s\n", key, value);
}

int main(void) {
  static char input[MAX_INPUT];
  size_t len = fread(input, 1, sizeof(input), stdin);
  if (ferror(stdin) || !feof(stdin)) {
    fprintf(stderr, "inidump: read error or input over 16 MiB bound\n");
    return 2;
  }

  zini_error err = {0, nullptr};
  zini *ini = zini_parse(input, len, &err);
  if (!ini) {
    fprintf(stderr, "inidump: line %zu: %s\n", err.line, err.message);
    return 1;
  }

  zini_foreach(ini, print_entry, nullptr);
  fprintf(stderr, "%zu entries\n", zini_count(ini));
  zini_destroy(ini);
  return 0;
}
