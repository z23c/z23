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
#include <string.h>

int main(int argc, char **argv) {
  static char doc[ZTOML_MAX + 1];
  static char strbuf[ZTOML_MAX + 1];
  size_t len = 0, n;
  int show = argc > 1 && strcmp(argv[1], "--events") == 0;
  ztoml t;
  ztoml_err e;
  size_t count = 0;

  while ((n = fread(doc + len, 1, sizeof(doc) - 1 - len, stdin)) > 0)
    len += n;
  if (ferror(stdin)) {
    fprintf(stderr, "ztoml: error reading stdin\n");
    return 1;
  }
  doc[len] = '\0';

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
    if (show) {
      switch (ev.kind) {
      case ZTOML_EV_SECTION: printf("section [%.*s]\n", (int)ev.len, ev.ptr); break;
      case ZTOML_EV_KEY: printf("key %.*s\n", (int)ev.len, ev.ptr); break;
      case ZTOML_EV_ARR_OPEN: printf("array [\n"); break;
      case ZTOML_EV_ARR_CLOSE: printf("array ]\n"); break;
      case ZTOML_EV_VALUE:
        switch (ev.vtype) {
        case ZTOML_V_STR_BASIC: {
          size_t dn = ztoml_str_decode(ev.ptr, ev.len, strbuf,
                                       sizeof(strbuf));
          if (dn == SIZE_MAX || dn >= sizeof(strbuf))
            printf("str (bad escapes)\n");
          else
            printf("str \"%s\"\n", strbuf);
          break;
        }
        case ZTOML_V_STR_LIT: printf("str '%.*s'\n", (int)ev.len, ev.ptr); break;
        case ZTOML_V_INT: printf("int %lld\n", (long long)ev.i64); break;
        case ZTOML_V_FLOAT: printf("float %.17g\n", ev.f64); break;
        case ZTOML_V_BOOL: printf("bool %s\n", ev.boolean ? "true" : "false"); break;
        default: printf("value?\n"); break;
        }
        break;
      default: break;
      }
    }
    if (ev.kind == ZTOML_EV_DONE) break;
  }
  printf("ok: %zu events\n", count - 1);
  return 0;
}
