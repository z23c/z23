/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: zdiff CLI — print the line edit script between two files
 *          as ' ', '-', '+' prefixed lines. Exit 0 when identical,
 *          1 when different, 2 on error. Bounded: files up to 4 MiB,
 *          ZDIFF_MAX_LINES lines each. */
#include "zdiff/zdiff.h"

#include <stdbool.h>
#include <stdio.h>

enum { MAX_FILE = 4 << 20 };

static char old_text[MAX_FILE], new_text[MAX_FILE];
static zdiff_line old_lines[ZDIFF_MAX_LINES + 1],
    new_lines[ZDIFF_MAX_LINES + 1];
static uint32_t dp[ZDIFF_MAX_CELLS];
static zdiff_op ops[2 * ZDIFF_MAX_LINES + 2];

static bool read_file(const char *path, char *buf, size_t cap,
                      size_t *len_out) {
  FILE *f = fopen(path, "rb");
  if (!f)
    return false;
  size_t n = fread(buf, 1, cap, f);
  bool ok = !ferror(f) && feof(f); /* !feof: longer than cap */
  fclose(f);
  if (ok)
    *len_out = n;
  return ok;
}

int main(int argc, char **argv) {
  if (argc != 3) {
    fprintf(stderr, "usage: zdiff OLD NEW\n");
    return 2;
  }
  size_t old_len = 0, new_len = 0;
  if (!read_file(argv[1], old_text, sizeof old_text, &old_len)) {
    fprintf(stderr, "zdiff: cannot read %s (missing or > %d bytes)\n",
            argv[1], MAX_FILE);
    return 2;
  }
  if (!read_file(argv[2], new_text, sizeof new_text, &new_len)) {
    fprintf(stderr, "zdiff: cannot read %s (missing or > %d bytes)\n",
            argv[2], MAX_FILE);
    return 2;
  }
  size_t n = 0;
  zdiff_status st = zdiff_texts(
      old_text, old_len, old_lines, ZDIFF_MAX_LINES + 1, new_text, new_len,
      new_lines, ZDIFF_MAX_LINES + 1, dp, ZDIFF_MAX_CELLS, ops,
      2 * ZDIFF_MAX_LINES + 2, &n);
  if (st != ZDIFF_OK) {
    fprintf(stderr, "zdiff: %s\n", zdiff_status_name(st));
    return 2;
  }
  bool different = false;
  for (size_t i = 0; i < n; i++) {
    const zdiff_op *op = &ops[i];
    const char *text = op->kind == ZDIFF_INS ? new_text : old_text;
    const zdiff_line *lines =
        op->kind == ZDIFF_INS ? new_lines : old_lines;
    uint32_t idx = op->kind == ZDIFF_INS ? op->new_line : op->old_line;
    char prefix = op->kind == ZDIFF_KEEP  ? ' '
                  : op->kind == ZDIFF_DEL ? '-'
                                          : '+';
    if (op->kind != ZDIFF_KEEP)
      different = true;
    if (printf("%c %.*s\n", prefix, (int)lines[idx].len,
               text + lines[idx].off) < 0) {
      fprintf(stderr, "zdiff: write failed\n");
      return 2;
    }
  }
  return different ? 1 : 0;
}
