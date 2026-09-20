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

static int finish_output(FILE *out) {
  if (fflush(out) == EOF || ferror(out)) {
    fprintf(stderr, "csvtab: write error\n");
    return 2;
  }
  return 0;
}

static int read_input(FILE *in, char *input, size_t cap, size_t *len) {
  *len = fread(input, 1, cap, in);
  /* A full buffer does not set EOF. Probe one byte to distinguish the
   * inclusive bound from overflow, then also check errors from the probe. */
  int extra = *len == cap ? fgetc(in) : EOF;
  if (ferror(in)) {
    fprintf(stderr, "csvtab: read error\n");
    return 2;
  }
  if (extra != EOF) {
    fprintf(stderr, "csvtab: input exceeds 16 MiB bound\n");
    return 2;
  }
  return 0;
}

/* Lay out one bounded cell; never split a visible CR/LF marker. */
static size_t layout_field(const zcsv_field *field, char out[COL_WIDTH_MAX]) {
  size_t used = 0, last = 0;
  for (size_t i = 0; i < field->len; i++) {
    char c = field->ptr[i];
    size_t width = (c == '\r' || c == '\n') ? 2u : 1u;
    if (width > COL_WIDTH_MAX - used) {
      if (used == COL_WIDTH_MAX)
        used = last;
      out[used++] = '+';
      break;
    }
    last = used;
    if (width == 2u) {
      out[used++] = '\\';
      out[used++] = c == '\r' ? 'r' : 'n';
    } else {
      out[used++] = c;
    }
  }
  return used;
}

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
    char cell[COL_WIDTH_MAX];
    size_t len = layout_field(&fields[i], cell);
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
      char cell[COL_WIDTH_MAX];
      size_t len = layout_field(&fields[i], cell);
      fwrite(cell, 1, len, stdout);
      for (size_t pad = len; pad < s->widths[i]; pad++)
        putchar(' ');
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
  size_t len = 0;
  if (read_input(stdin, input, sizeof(input), &len) != 0)
    return 2;

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
    return finish_output(stdout);
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
  return finish_output(stdout);
}
