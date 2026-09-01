/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: zjson CLI — turn key<TAB>value lines on stdin into a JSON
 *          object on stdout. Deterministic, bounded, allocation-free. */
#include "zjson/zjson.h"

#include <stdio.h>
#include <string.h>

enum { MAX_LINE = 4096, OUT_CAP = 1 << 20 };

static char out[OUT_CAP];
static char line[MAX_LINE];

int main(void) {
  zjson w;
  zjson_init(&w, out, sizeof out);
  zjson_obj_open(&w);

  unsigned long members = 0;
  while (fgets(line, sizeof line, stdin)) {
    size_t n = strlen(line);
    if (n == sizeof line - 1 && line[n - 1] != '\n' && !feof(stdin)) {
      fprintf(stderr, "zjson: line exceeds %d bytes\n", MAX_LINE - 1);
      return 1;
    }
    if (n && line[n - 1] == '\n')
      line[--n] = '\0';
    char *tab = strchr(line, '\t');
    if (!tab || tab == line) {
      fprintf(stderr, "zjson: expected non-empty key<TAB>value line\n");
      return 1;
    }
    zjson_key_n(&w, line, (size_t)(tab - line));
    zjson_str(&w, tab + 1);
    members++;
  }

  zjson_obj_close(&w);
  size_t len = 0;
  zjson_status st = zjson_finish(&w, &len);
  if (st != ZJSON_OK) {
    fprintf(stderr, "zjson: %s\n", zjson_status_name(st));
    return 1;
  }
  if (fwrite(out, 1, len, stdout) != len || fputc('\n', stdout) == EOF) {
    fprintf(stderr, "zjson: write failed\n");
    return 1;
  }
  (void)members;
  return 0;
}
