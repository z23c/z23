/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: rangecheck - print stdin version lines satisfying a semver range.
 *
 * Usage: zrange RANGE < versions
 *
 * Exit 0 when at least one version satisfied the range, 1 when none did,
 * 2 on misuse, an invalid range, or input over the 16 MiB bound. Lines
 * that are not strict SemVer are skipped (reported on stderr). Lines are
 * bounded at 4096 bytes.
 */
#include "zrange/zrange.h"

#include <stdio.h>
#include <string.h>

#define MAX_INPUT (16u * 1024u * 1024u)
#define MAX_LINE 4096u

static char input[MAX_INPUT];

int main(int argc, char **argv) {
  if (argc != 2) {
    fprintf(stderr, "usage: zrange RANGE < versions\n");
    return 2;
  }
  zrange range;
  if (!zrange_parse(argv[1], &range)) {
    fprintf(stderr, "zrange: invalid range '%s'\n", argv[1]);
    return 2;
  }

  size_t len = fread(input, 1, sizeof(input), stdin);
  if (ferror(stdin) || !feof(stdin)) {
    fprintf(stderr, "zrange: read error or input over 16 MiB bound\n");
    return 2;
  }

  int matched = 0;
  int skipped = 0;
  size_t pos = 0;
  while (pos < len) {
    size_t start = pos;
    while (pos < len && input[pos] != '\n')
      pos++;
    size_t end = pos;
    if (end > start && input[end - 1] == '\r')
      end--;
    pos++; /* consume the newline (or step past EOF) */
    size_t line_len = end - start;
    if (!line_len)
      continue;
    if (line_len > MAX_LINE) {
      fprintf(stderr, "zrange: line over %u bytes; skipped\n", MAX_LINE);
      skipped = 1;
      continue;
    }
    zsemver v;
    if (!zsemver_parse_n(input + start, line_len, &v)) {
      fprintf(stderr, "zrange: not strict semver: '%.*s'\n", (int)line_len,
              input + start);
      skipped = 1;
      continue;
    }
    if (zrange_satisfies(&range, &v)) {
      printf("%.*s\n", (int)line_len, input + start);
      matched = 1;
    }
  }
  (void)skipped;
  return matched ? 0 : 1;
}
