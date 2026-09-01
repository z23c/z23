/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: utf8check - validate stdin as well-formed UTF-8.
 *
 * Usage: zutf8 < data
 *
 * Exit 0 when the whole input is well-formed UTF-8, 1 when it is not
 * (byte offset and reason on stderr), 2 on read error or input over
 * the 64 MiB bound. With --count, print the code-point count instead
 * of validating silently.
 */
#include "zutf8/zutf8.h"

#include <stdio.h>
#include <string.h>

#define MAX_INPUT (64u * 1024u * 1024u)

static char input[MAX_INPUT];

int main(int argc, char **argv) {
  int count_mode = 0;
  if (argc > 2 || (argc == 2 && strcmp(argv[1], "--count"))) {
    fprintf(stderr, "usage: zutf8 [--count] < data\n");
    return 2;
  }
  count_mode = argc == 2;

  size_t len = fread(input, 1, sizeof(input), stdin);
  if (ferror(stdin) || !feof(stdin)) {
    fprintf(stderr, "zutf8: read error or input over 64 MiB bound\n");
    return 2;
  }

  size_t pos = 0, count = 0;
  while (pos < len) {
    uint32_t cp;
    size_t used;
    zutf8_status st = zutf8_decode_n(input + pos, len - pos, &cp, &used);
    if (st != ZUTF8_OK) {
      fprintf(stderr, "zutf8: %s at byte %zu\n",
              st == ZUTF8_TRUNCATED ? "truncated sequence"
                                    : "invalid byte sequence",
              pos);
      return 1;
    }
    pos += used;
    count++;
  }
  if (count_mode)
    printf("%zu\n", count);
  return 0;
}
