/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: csvtab - render CSV from stdin as an aligned table, or print
 *          simple statistics with --stats.
 *
 * Usage: csvtab [--stats] < data.csv
 *
 * Input is bounded at 16 MiB and per-row scratch at 64 KiB / 1024 fields;
 * oversized input fails closed with a diagnostic rather than truncating.
 */
#include "zcsv/zcsv.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_INPUT (16u * 1024u * 1024u)
#define ROW_DATA_CAP (64u * 1024u)
#define ROW_FIELD_CAP 1024u
#define COL_WIDTH_MAX 40u

typedef struct {
  size_t rows;
  size_t max_fields;
  size_t *widths; /* per-column max display width, heap-owned */
  size_t widths_cap;
} stats;

static void observe(void *vctx, const zcsv_field *fields, size_t n) {
  stats *s = vctx;
  if (n > s->widths_cap) {
    size_t cap = s->widths_cap ? s->widths_cap : 16;
    while (cap < n)
      cap *= 2;
    size_t *w = realloc(s->widths, cap * sizeof(*w));
    if (!w) {
      fprintf(stderr, "csvtab: out of memory\n");
      exit(2);
    }
    for (size_t i = s->widths_cap; i < cap; i++)
      w[i] = 0;
    s->widths = w;
    s->widths_cap = cap;
  }
  for (size_t i = 0; i < n; i++) {
    size_t len = fields[i].len;
    if (len > COL_WIDTH_MAX)
      len = COL_WIDTH_MAX;
    if (len > s->widths[i])
      s->widths[i] = len;
  }
  if (n > s->max_fields)
    s->max_fields = n;
  s->rows++;
}

static void print_row(const zcsv_field *fields, size_t n, const stats *s) {
  for (size_t i = 0; i < s->max_fields; i++) {
    putchar(i == 0 ? '|' : ' ');
    putchar(' ');
    if (i < n) {
      size_t len = fields[i].len;
      bool trunc = len > COL_WIDTH_MAX;
      if (trunc)
        len = COL_WIDTH_MAX;
      fwrite(fields[i].ptr, 1, len, stdout);
      for (size_t pad = len; pad < s->widths[i]; pad++)
        putchar(' ');
      if (trunc)
        putchar('+');
    } else {
      for (size_t pad = 0; pad < s->widths[i]; pad++)
        putchar(' ');
    }
    fputs(" |", stdout);
  }
  putchar('\n');
}

typedef struct {
  const stats *s;
  size_t row_index;
} printer;

static void emit_row(void *vctx, const zcsv_field *fields, size_t n) {
  printer *p = vctx;
  print_row(fields, n, p->s);
  if (p->row_index == 0 && p->s->rows > 1) {
    /* Header separator. */
    for (size_t i = 0; i < p->s->max_fields; i++) {
      putchar(i == 0 ? '|' : '-');
      putchar('-');
      for (size_t k = 0; k < p->s->widths[i]; k++)
        putchar('-');
      fputs("-|", stdout);
    }
    putchar('\n');
  }
  p->row_index++;
}

int main(int argc, char **argv) {
  bool stats_only = argc > 1 && strcmp(argv[1], "--stats") == 0;
  if (argc > 1 && !stats_only) {
    fprintf(stderr, "usage: csvtab [--stats] < data.csv\n");
    return 2;
  }

  static char input[MAX_INPUT];
  size_t len = fread(input, 1, sizeof(input), stdin);
  if (ferror(stdin)) {
    fprintf(stderr, "csvtab: read error\n");
    return 2;
  }
  if (!feof(stdin)) {
    fprintf(stderr, "csvtab: input exceeds 16 MiB bound\n");
    return 2;
  }

  static char row_data[ROW_DATA_CAP];
  static zcsv_field row_fields[ROW_FIELD_CAP];

  /* Pass 1: gather widths and counts. */
  stats s = {0};
  zcsv_parser p;
  zcsv_init(&p, row_data, sizeof(row_data), row_fields, ROW_FIELD_CAP,
            observe, &s);
  zcsv_status st = zcsv_feed(&p, input, len);
  if (st == ZCSV_OK)
    st = zcsv_finish(&p);
  if (st != ZCSV_OK) {
    fprintf(stderr, "csvtab: %s\n", zcsv_status_str(st));
    free(s.widths);
    return 1;
  }

  if (stats_only) {
    printf("rows: %zu\nfields(max): %zu\nbytes: %zu\n", s.rows, s.max_fields,
           len);
    free(s.widths);
    return 0;
  }

  /* Pass 2: render. */
  printer pr = {.s = &s, .row_index = 0};
  zcsv_init(&p, row_data, sizeof(row_data), row_fields, ROW_FIELD_CAP,
            emit_row, &pr);
  st = zcsv_feed(&p, input, len);
  if (st == ZCSV_OK)
    st = zcsv_finish(&p);
  if (st != ZCSV_OK) {
    fprintf(stderr, "csvtab: %s\n", zcsv_status_str(st));
    free(s.widths);
    return 1;
  }
  free(s.widths);
  return 0;
}
