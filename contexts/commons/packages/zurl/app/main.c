/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: zurl CLI — parse each URI argument and print its
 *          components. Exit 0 when all are valid, 1 otherwise. */
#include "zurl/zurl.h"

#include <stdio.h>

static void show(const char *name, const char *text, zurl_span s,
                 bool present) {
  if (present)
    printf("  %s: %.*s\n", name, (int)s.len, text + s.off);
}

int main(int argc, char **argv) {
  if (argc < 2) {
    fprintf(stderr, "usage: zurl URI [URI ...]\n");
    return 2;
  }
  int rc = 0;
  for (int a = 1; a < argc; a++) {
    const char *t = argv[a];
    zurl u;
    if (!zurl_parse(t, &u)) {
      printf("%s: INVALID\n", t);
      rc = 1;
      continue;
    }
    printf("%s:\n", t);
    show("scheme", t, u.scheme, true);
    show("userinfo", t, u.userinfo, u.has_userinfo);
    show("host", t, u.host, u.has_authority);
    if (u.host_is_ipv4)
      printf("  host-kind: ipv4\n");
    else if (u.host_is_ip_literal)
      printf("  host-kind: ip-literal\n");
    if (u.has_port)
      printf("  port: %u\n", u.port);
    show("path", t, u.path, true);
    show("query", t, u.query, u.has_query);
    show("fragment", t, u.fragment, u.has_fragment);
  }
  return rc;
}
