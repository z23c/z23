/* ztoml CLI: validate and dump a TOML-subset document from stdin.
 *
 * Usage: ztoml [--events]
 *   default:   parse stdin; print "ok: N events" or the error with
 *              byte offset; exit 1 on parse failure
 *   --events:  also print each event, one per line
 *
 * This is the package's real consumer. */
#include "ztoml/ztoml.h"

#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#if defined(_WIN32)
#include <fcntl.h>
#include <io.h>
#endif

static bool cli_read(FILE *source, char *doc, size_t *len) {
#if defined(_WIN32)
  if (_setmode(_fileno(source), _O_BINARY) == -1) {
    fputs("ztoml: cannot select binary input mode\n", stderr);
    return false;
  }
#endif
  *len = fread(doc, 1, ZTOML_MAX, source);
  int extra = EOF;
  if (*len == ZTOML_MAX && !ferror(source)) extra = fgetc(source);
  if (ferror(source)) {
    fputs("ztoml: error reading stdin\n", stderr);
    return false;
  }
  if (extra != EOF) {
    fprintf(stderr, "ztoml: input exceeds %u bytes\n", (unsigned)ZTOML_MAX);
    return false;
  }
  doc[*len] = '\0';
  return true;
}

static void show_value(FILE *output, const ztoml_ev *ev) {
  static char strbuf[ZTOML_MAX + 1];
  switch (ev->vtype) {
  case ZTOML_V_STR_BASIC: {
    size_t dn = ztoml_str_decode(ev->ptr, ev->len, strbuf, sizeof strbuf);
    if (dn == SIZE_MAX || dn >= sizeof strbuf)
      fprintf(output, "str (bad escapes)\n");
    else
      fprintf(output, "str \"%s\"\n", strbuf);
    break;
  }
  case ZTOML_V_STR_LIT: fprintf(output, "str '%.*s'\n", (int)ev->len, ev->ptr); break;
  case ZTOML_V_INT: fprintf(output, "int %lld\n", (long long)ev->i64); break;
  case ZTOML_V_FLOAT: fprintf(output, "float %.17g\n", ev->f64); break;
  case ZTOML_V_BOOL: fprintf(output, "bool %s\n", ev->boolean ? "true" : "false"); break;
  default: fprintf(output, "value?\n"); break;
  }
}

static void show_event(FILE *output, const ztoml_ev *ev) {
  switch (ev->kind) {
  case ZTOML_EV_SECTION: fprintf(output, "section [%.*s]\n", (int)ev->len, ev->ptr); break;
  case ZTOML_EV_KEY: fprintf(output, "key %.*s\n", (int)ev->len, ev->ptr); break;
  case ZTOML_EV_ARR_OPEN: fprintf(output, "array [\n"); break;
  case ZTOML_EV_ARR_CLOSE: fprintf(output, "array ]\n"); break;
  case ZTOML_EV_VALUE: show_value(output, ev); break;
  default: break;
  }
}

static int cli_run(int argc, char **argv, FILE *source, FILE *output) {
  static char doc[ZTOML_MAX + 1];
  size_t len = 0;
  int show = argc > 1 && strcmp(argv[1], "--events") == 0;
  ztoml t;
  ztoml_err e;
  size_t count = 0;

  if (!cli_read(source, doc, &len)) return 1;
  e = ztoml_init(&t, doc, len);
  if (e != ZTOML_OK) {
    fprintf(stderr, "ztoml: %s\n", ztoml_err_str(e));
    return 1;
  }
  for (;;) {
    ztoml_ev ev;
    e = ztoml_next(&t, &ev);
    if (e != ZTOML_OK) {
      fprintf(stderr, "ztoml: %s at offset %zu (line %zu)\n",
              ztoml_err_str(e), t.err_off, t.line);
      return 1;
    }
    count++;
    if (show) show_event(output, &ev);
    if (ev.kind == ZTOML_EV_DONE) break;
  }
  fprintf(output, "ok: %zu events\n", count - 1);
  if (fflush(output) != 0 || ferror(output)) {
    fputs("ztoml: output write failed\n", stderr);
    return 1;
  }
  return 0;
}

int main(int argc, char **argv) {
  return cli_run(argc, argv, stdin, stdout);
}
