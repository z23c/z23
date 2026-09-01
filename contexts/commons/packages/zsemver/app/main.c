/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: semversort - read one version per line from stdin, reject
 *          anything that is not strict SemVer 2.0.0, and print the valid
 *          versions in precedence order (stable for equal precedence).
 *
 * Usage: semversort < versions.txt
 *
 * Input is bounded at 1 MiB and 65536 lines. Invalid lines are reported
 * on stderr with their line number and abort the sort (exit 2): a version
 * sorter that silently drops input is worse than no sorter.
 */
#include "zsemver/zsemver.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_INPUT (1024u * 1024u)
#define MAX_LINES 65536u

typedef struct {
  const char *text; /* into the input buffer */
  size_t len;
  zsemver version;
  size_t line_no;
} row;

static int row_cmp(const void *va, const void *vb) {
  const row *a = va;
  const row *b = vb;
  int c = zsemver_compare(&a->version, &b->version);
  if (c != 0)
    return c;
  return a->line_no < b->line_no ? -1 : a->line_no > b->line_no ? 1 : 0;
}

static char input[MAX_INPUT];
static row rows[MAX_LINES];

int main(void) {
  size_t len = fread(input, 1, sizeof(input), stdin);
  if (ferror(stdin) || !feof(stdin)) {
    fprintf(stderr, "semversort: read error or input over 1 MiB bound\n");
    return 2;
  }

  size_t n = 0, pos = 0, line_no = 0;
  while (pos < len) {
    line_no++;
    size_t start = pos;
    while (pos < len && input[pos] != '\n')
      pos++;
    size_t end = pos;
    if (end > start && input[end - 1] == '\r')
      end--;
    pos++; /* consume the newline (or step past EOF) */
    if (end == start)
      continue; /* blank lines carry no version */
    if (n == MAX_LINES) {
      fprintf(stderr, "semversort: over %u lines\n", MAX_LINES);
      return 2;
    }
    rows[n].text = input + start;
    rows[n].len = end - start;
    rows[n].line_no = line_no;
    if (!zsemver_parse_n(rows[n].text, rows[n].len, &rows[n].version)) {
      fprintf(stderr, "semversort: line %zu is not strict SemVer: %.*s\n",
              line_no, (int)rows[n].len, rows[n].text);
      return 2;
    }
    n++;
  }

  qsort(rows, n, sizeof(rows[0]), row_cmp);
  for (size_t i = 0; i < n; i++)
    printf("%.*s\n", (int)rows[i].len, rows[i].text);
  return 0;
}
