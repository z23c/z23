/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: zjsonp CLI — validate JSON on stdin and dump the event
 *          stream as indented lines. Exit 0 on a valid document,
 *          1 on a syntax/depth error (offset reported), 2 on I/O or
 *          size errors. Input bounded to 16 MiB. */
#include "zjsonp/zjsonp.h"

#include <stdio.h>

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

int main(void) {
  size_t len = fread(input, 1, sizeof input, stdin);
  if (ferror(stdin) || !feof(stdin)) {
    fprintf(stderr, "zjsonp: read error or input over %d bytes\n",
            MAX_INPUT);
    return 2;
  }
  zjsonp p;
  zjsonp_init(&p, input, len);
  unsigned depth = 0;
  for (;;) {
    zjsonp_event ev;
    zjsonp_status st = zjsonp_next(&p, &ev);
    if (st == ZJRP_DONE)
      return 0;
    if (st != ZJRP_OK) {
      fprintf(stderr, "zjsonp: %s at byte %zu\n",
              zjsonp_status_name(st), zjsonp_pos(&p));
      return 1;
    }
    if (ev.kind == ZJRP_OBJ_CLOSE || ev.kind == ZJRP_ARR_CLOSE)
      depth--;
    for (unsigned i = 0; i < depth; i++)
      fputs("  ", stdout);
    if (ev.len)
      printf("%s %.*s\n", kind_name(ev.kind), (int)ev.len,
             input + ev.off);
    else
      printf("%s\n", kind_name(ev.kind));
    if (ev.kind == ZJRP_OBJ_OPEN || ev.kind == ZJRP_ARR_OPEN)
      depth++;
  }
}
