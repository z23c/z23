/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: grep over zre - print lines matching a regular expression.
 *
 * Usage: zre PATTERN [FILE]   (reads stdin when FILE is omitted or "-")
 *
 * Exit 0 when at least one line matched, 1 when none did, 2 on misuse,
 * pattern compile error, or input over the 16 MiB bound. Lines are
 * bounded at 4096 bytes for matching (longer lines are matched truncated,
 * reported once on stderr); '^'/'$' anchor to the line, matching grep.
 */
#include "zre/zre.h"

#include <stdio.h>
#include <string.h>

#define MAX_INPUT (16u * 1024u * 1024u)
#define MAX_LINE 4096u

static char input[MAX_INPUT];

int main(int argc, char **argv) {
  if (argc < 2 || argc > 3) {
    fprintf(stderr, "usage: zre PATTERN [FILE]\n");
    return 2;
  }
  char err[128];
  zre_prog *prog = NULL;
  zre_status st =
      zre_compile(argv[1], strlen(argv[1]), &prog, err, sizeof(err));
  if (st != ZRE_OK) {
    fprintf(stderr, "%s\n", err[0] ? err : zre_strerror(st));
    return 2;
  }

  FILE *in = stdin;
  if (argc == 3 && strcmp(argv[2], "-") != 0) {
    in = fopen(argv[2], "rb");
    if (!in) {
      fprintf(stderr, "zre: cannot open %s\n", argv[2]);
      zre_free(prog);
      return 2;
    }
  }
  size_t len = fread(input, 1, sizeof(input), in);
  if (ferror(in) || !feof(in)) {
    fprintf(stderr, "zre: read error or input over 16 MiB bound\n");
    if (in != stdin)
      fclose(in);
    zre_free(prog);
    return 2;
  }
  if (in != stdin)
    fclose(in);

  int matched = 0, truncated_note = 0;
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
      if (!truncated_note) {
        fprintf(stderr, "zre: line over %u bytes; matching truncated\n",
                MAX_LINE);
        truncated_note = 1;
      }
      line_len = MAX_LINE;
    }
    if (zre_match(prog, input + start, line_len, NULL, 0)) {
      printf("%.*s\n", (int)(end - start), input + start);
      matched = 1;
    }
  }
  zre_free(prog);
  return matched ? 0 : 1;
}
