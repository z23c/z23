/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: zurl CLI — parse each URI argument and print its
 *          components. Exit 0 when all are valid, 1 otherwise. */
#include "zurl/zurl.h"

#include <stdio.h>

static void show(FILE *output, const char *name, const char *text, zurl_span s,
                 bool present) {
  if (present)
    fprintf(output, "  %s: %.*s\n", name, (int)s.len, text + s.off);
}

static int cli_run(int argc, char **argv, FILE *output) {
  if (argc < 2) {
    fprintf(stderr, "usage: zurl URI [URI ...]\n");
    return 2;
  }
  int rc = 0;
  for (int a = 1; a < argc; a++) {
    const char *t = argv[a];
    zurl u;
    if (!zurl_parse(t, &u)) {
      fprintf(output, "%s: INVALID\n", t);
      rc = 1;
      continue;
    }
    fprintf(output, "%s:\n", t);
    show(output, "scheme", t, u.scheme, true);
    show(output, "userinfo", t, u.userinfo, u.has_userinfo);
    show(output, "host", t, u.host, u.has_authority);
    if (u.host_is_ipv4)
      fprintf(output, "  host-kind: ipv4\n");
    else if (u.host_is_ip_literal)
      fprintf(output, "  host-kind: ip-literal\n");
    if (u.has_port)
      fprintf(output, "  port: %u\n", u.port);
    show(output, "path", t, u.path, true);
    show(output, "query", t, u.query, u.has_query);
    show(output, "fragment", t, u.fragment, u.has_fragment);
  }
  if (fflush(output) != 0 || ferror(output)) {
    fputs("zurl: output write failed\n", stderr);
    return 1;
  }
  return rc;
}

int main(int argc, char **argv) {
  return cli_run(argc, argv, stdout);
}
