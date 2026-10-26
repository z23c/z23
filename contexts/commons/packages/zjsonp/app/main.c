/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: zjsonp CLI — validate JSON on stdin and dump the event
 *          stream as indented lines. Exit 0 on a valid document,
 *          1 on a syntax/depth error (offset reported), 2 on I/O or
 *          size errors. Input bounded to 16 MiB. */
#include "zjsonp/zjsonp.h"

#include <stdio.h>
#if defined(_WIN32)
#include <fcntl.h>
#include <io.h>
#endif

enum { MAX_INPUT = 16 << 20 };

static char input[MAX_INPUT];

static const char *kind_name(zjsonp_event_kind k) {
  switch (k) {
  case ZJRP_OBJ_OPEN: return "obj-open";
  case ZJRP_OBJ_CLOSE: return "obj-close";
  case ZJRP_ARR_OPEN: return "arr-open";
  case ZJRP_ARR_CLOSE: return "arr-close";
  case ZJRP_KEY: return "key";
  case ZJRP_STR: return "str";
  case ZJRP_NUM: return "num";
  case ZJRP_BOOL: return "bool";
  case ZJRP_NULL: return "null";
  }
  return "?";
}

static bool cli_read(FILE *source, size_t *len) {
#if defined(_WIN32)
  if (_setmode(_fileno(source), _O_BINARY) == -1) {
    fputs("zjsonp: cannot select binary input mode\n", stderr);
    return false;
  }
#endif
  *len = fread(input, 1, sizeof input, source);
  if (*len == sizeof input && !ferror(source))
    (void)fgetc(source); /* Distinguish exact capacity from one extra byte. */
  if (ferror(source) || !feof(source)) {
    fprintf(stderr, "zjsonp: read error or input over %d bytes\n",
            MAX_INPUT);
    return false;
  }
  return true;
}

static int cli_run(FILE *source, FILE *output) {
  size_t len;
  if (!cli_read(source, &len)) return 2;
  zjsonp p;
  zjsonp_init(&p, input, len);
  unsigned depth = 0;
  for (;;) {
    zjsonp_event ev;
    zjsonp_status st = zjsonp_next(&p, &ev);
    if (st == ZJRP_DONE) {
      if (fflush(output) != 0 || ferror(output)) {
        fputs("zjsonp: stdout write failed\n", stderr);
        return 2;
      }
      return 0;
    }
    if (st != ZJRP_OK) {
      fprintf(stderr, "zjsonp: %s at byte %zu\n",
              zjsonp_status_name(st), zjsonp_pos(&p));
      return 1;
    }
    if (ev.kind == ZJRP_OBJ_CLOSE || ev.kind == ZJRP_ARR_CLOSE)
      depth--;
    for (unsigned i = 0; i < depth; i++)
      fputs("  ", output);
    if (ev.len)
      fprintf(output, "%s %.*s\n", kind_name(ev.kind), (int)ev.len,
             input + ev.off);
    else
      fprintf(output, "%s\n", kind_name(ev.kind));
    if (ev.kind == ZJRP_OBJ_OPEN || ev.kind == ZJRP_ARR_OPEN)
      depth++;
  }
}

int main(void) {
  return cli_run(stdin, stdout);
}
