/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: zgrep-lite - print stdin lines matching a glob pattern.
 *
 * Usage: zglob PATTERN < lines
 *
 * Exit 0 when at least one line matched, 1 when none did, 2 on misuse or
 * input over the 16 MiB bound. Lines are bounded at 4096 bytes (longer
 * lines are truncated for matching, which is reported on stderr).
 */
#include "zglob/zglob.h"

#include <stdio.h>
#include <string.h>

#define MAX_INPUT (16u * 1024u * 1024u)
#define MAX_LINE 4096u

static char input[MAX_INPUT];

int main(int argc, char **argv) {
  if (argc != 2) {
    fprintf(stderr, "usage: zglob PATTERN < lines\n");
    return 2;
  }
  const char *pat = argv[1];
  size_t plen = strlen(pat);

  size_t len = fread(input, 1, sizeof(input), stdin);
  if (ferror(stdin) || !feof(stdin)) {
    fprintf(stderr, "zglob: read error or input over 16 MiB bound\n");
    return 2;
  }

  int matched = 0;
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
    if (line_len > MAX_LINE) {
      fprintf(stderr, "zglob: line over %u bytes; matching truncated\n",
              MAX_LINE);
      line_len = MAX_LINE;
    }
    if (zglob_match_n(pat, plen, input + start, line_len)) {
      printf("%.*s\n", (int)(end - start), input + start);
      matched = 1;
    }
  }
  return matched ? 0 : 1;
}
