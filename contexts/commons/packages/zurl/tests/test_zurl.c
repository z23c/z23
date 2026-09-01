/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: KAT, bounds, and fuzz tests for zurl. */
#include "zurl/zurl.h"

#include <stdio.h>
#include <string.h>

#define CHECK(cond)                                                          \
  do {                                                                       \
    if (!(cond)) {                                                           \
      fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);        \
      return 1;                                                              \
    }                                                                        \
  } while (0)

static bool span_eq(const char *text, zurl_span s, const char *want) {
  return s.len == strlen(want) &&
         memcmp(text + s.off, want, s.len) == 0;
}

static int test_kat_valid(void) {
  zurl u;
  {
    const char *t = "https://user@example.com:8443/path/to?q=1#frag";
    CHECK(zurl_parse(t, &u));
    CHECK(span_eq(t, u.scheme, "https"));
    CHECK(u.has_userinfo && span_eq(t, u.userinfo, "user"));
    CHECK(span_eq(t, u.host, "example.com"));
    CHECK(u.has_port && u.port == 8443);
    CHECK(span_eq(t, u.path, "/path/to"));
    CHECK(u.has_query && span_eq(t, u.query, "q=1"));
    CHECK(u.has_fragment && span_eq(t, u.fragment, "frag"));
    CHECK(zurl_scheme_is(&u, t, "https"));
    CHECK(!zurl_scheme_is(&u, t, "http"));
  }
  {
    const char *t = "https://example.com";
    CHECK(zurl_parse(t, &u));
    CHECK(!u.has_userinfo && !u.has_port && !u.has_query &&
          !u.has_fragment);
    CHECK(u.port == 0);
    CHECK(u.path.len == 0);
  }
  {
    const char *t = "http://127.0.0.1:8080/";
    CHECK(zurl_parse(t, &u));
    CHECK(u.host_is_ipv4 && span_eq(t, u.host, "127.0.0.1"));
    CHECK(u.port == 8080);
    CHECK(span_eq(t, u.path, "/"));
  }
  {
    const char *t = "http://[2001:db8::1]:8333/x";
    CHECK(zurl_parse(t, &u));
    CHECK(u.host_is_ip_literal &&
          span_eq(t, u.host, "[2001:db8::1]"));
    CHECK(u.port == 8333);
  }
  {
    const char *t = "ssh://git@host.xz/repo.git";
    CHECK(zurl_parse(t, &u));
    CHECK(span_eq(t, u.userinfo, "git"));
    CHECK(span_eq(t, u.path, "/repo.git"));
  }
  {
    /* no authority: rootless and empty paths */
    const char *t = "mailto:user@example.com";
    CHECK(zurl_parse(t, &u));
    CHECK(!u.has_authority && span_eq(t, u.path, "user@example.com"));
    const char *t2 = "tel:+1-555-0100";
    CHECK(zurl_parse(t2, &u) && span_eq(t2, u.path, "+1-555-0100"));
    const char *t3 = "urn:isbn:9780132350884";
    CHECK(zurl_parse(t3, &u) &&
          span_eq(t3, u.path, "isbn:9780132350884"));
  }
  {
    /* empty authority is grammar-legal (file:) */
    const char *t = "file:///etc/passwd";
    CHECK(zurl_parse(t, &u));
    CHECK(u.has_authority && u.host.len == 0);
    CHECK(span_eq(t, u.path, "/etc/passwd"));
  }
  {
    /* explicit :0 port is present-and-zero, not absent */
    const char *t = "http://h:0/";
    CHECK(zurl_parse(t, &u));
    CHECK(u.has_port && u.port == 0);
  }
  {
    /* percent encodings validate and pass through */
    const char *t = "https://h/%41%2f%2F?a=%20";
    CHECK(zurl_parse(t, &u));
    CHECK(span_eq(t, u.path, "/%41%2f%2F"));
  }
  {
    /* scheme case is preserved in the slice, compared fold-case */
    const char *t = "HTTPS://EXAMPLE.COM/";
    CHECK(zurl_parse(t, &u));
    CHECK(span_eq(t, u.scheme, "HTTPS"));
    CHECK(zurl_scheme_is(&u, t, "https"));
  }
  {
    /* query and fragment may contain ? / : @ / */
    const char *t = "https://h/p?x=1?y:@/z#f/?";
    CHECK(zurl_parse(t, &u));
    CHECK(span_eq(t, u.query, "x=1?y:@/z"));
    CHECK(span_eq(t, u.fragment, "f/?"));
  }
  return 0;
}

static int test_invalid(void) {
  static const char *bad[] = {
      "",
      "x",
      "1http://x",            /* scheme starts with a digit */
      "+http://x",            /* scheme must start alpha */
      "http//x",              /* missing ':' */
      "//host/path",          /* no scheme */
      "http://",              /* "//" then nothing... (see note) */
      "http://ho st/",        /* raw space in host */
      "http://host:99999/",   /* port too big */
      "http://host:abc/",     /* non-numeric port */
      "http://host:1:2/",     /* second colon */
      "http://host:/",        /* empty port digits? (see note) */
      "http://256.1.1.1/",    /* octet > 255 */
      "http://1.2.3/",        /* too few octets */
      "http://1.2.3.4.5/",    /* too many octets */
      "http://1..2.3/",       /* empty octet */
      "http://[::1",          /* unterminated literal */
      "http://[::1]x/",       /* garbage after literal */
      "http://[::g]/",        /* bad literal char */
      "http://host/pa th",    /* raw space in path */
      "http://host/%zz",      /* bad pct hex */
      "http://host/%",        /* truncated pct */
      "http://host/%4",       /* truncated pct */
      "http://a@b@c/",        /* raw @ in userinfo */
      "scheme:////x",         /* empty authority, then ok path — see
                                 note below */
      "ht tp://x",            /* space in scheme */
  };
  /* Notes: "http://" parses (empty authority); "http://host:/" parses
   * (empty port means 0 digits -> port 0, has_port); "scheme:////x"
   * parses (empty authority + path "//x"). They are listed to pin the
   * behavior; remove them from the bad table. */
  static const char *ok[] = {"http://", "http://host:/",
                             "scheme:////x"};
  zurl u;
  for (size_t i = 0; i < sizeof ok / sizeof ok[0]; i++) {
    if (!zurl_parse(ok[i], &u)) {
      fprintf(stderr, "FAIL valid pinned case: %s\n", ok[i]);
      return 1;
    }
  }
  for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
    bool skip = false;
    for (size_t k = 0; k < sizeof ok / sizeof ok[0]; k++)
      if (strcmp(bad[i], ok[k]) == 0)
        skip = true;
    if (skip)
      continue;
    if (zurl_parse(bad[i], &u)) {
      fprintf(stderr, "FAIL invalid accepted: %s\n", bad[i]);
      return 1;
    }
  }
  return 0;
}

static int test_copy_and_null(void) {
  zurl u;
  const char *t = "https://example.com/path";
  CHECK(zurl_parse(t, &u));
  char buf[8];
  CHECK(zurl_copy(t, &u.host, buf, sizeof buf) == 11);
  CHECK(memcmp(buf, "example.", 8) == 0); /* truncated copy bounded */
  CHECK(zurl_copy(t, &u.host, NULL, 0) == 11); /* measure */
  CHECK(zurl_copy(NULL, &u.host, buf, 8) == SIZE_MAX);
  CHECK(zurl_copy(t, NULL, buf, 8) == SIZE_MAX);
  CHECK(!zurl_parse(NULL, &u));
  CHECK(!zurl_parse_n(NULL, 3, &u));
  CHECK(!zurl_parse_n(t, 5, NULL));
  CHECK(!zurl_scheme_is(NULL, t, "https"));
  CHECK(!zurl_scheme_is(&u, NULL, "https"));
  CHECK(!zurl_scheme_is(&u, t, NULL));
  /* failure zeroes the result */
  CHECK(!zurl_parse("!!!", &u));
  CHECK(u.scheme.len == 0 && !u.has_authority && u.port == 0);
  return 0;
}

static uint64_t rng_state = 0x0123456789abcdefull;
static uint64_t rnd(void) {
  rng_state ^= rng_state << 13;
  rng_state ^= rng_state >> 7;
  rng_state ^= rng_state << 17;
  return rng_state;
}

static int test_fuzz(void) {
  static const char *parts[] = {"https", "http",  "ssh",   "ftp",
                                "://",   "user@", "host",  ".com",
                                ":8080", "/",     "path",  "?q=1",
                                "#frag", "%41",   ":",     "@",
                                "1.2.3.4", "[::1]", " "};
  static char doc[256];
  zurl u;
  for (unsigned trial = 0; trial < 20000; trial++) {
    size_t n = 0;
    unsigned segs = 1 + rnd() % 8;
    for (unsigned s = 0; s < segs && n < sizeof doc - 8; s++) {
      const char *p = parts[rnd() % (sizeof parts / sizeof parts[0])];
      size_t pl = strlen(p);
      memcpy(doc + n, p, pl);
      n += pl;
    }
    doc[n] = '\0';
    /* any outcome is fine; it must be total and non-crashing */
    bool ok = zurl_parse_n(doc, n, &u);
    (void)ok;
    /* mutate a byte and parse again */
    if (n > 0)
      doc[rnd() % n] = (char)(rnd() & 0xff);
    ok = zurl_parse_n(doc, n, &u);
    (void)ok;
  }
  return 0;
}

int main(void) {
  struct {
    const char *name;
    int (*fn)(void);
  } tests[] = {
      {"kat_valid", test_kat_valid},
      {"invalid", test_invalid},
      {"copy_and_null", test_copy_and_null},
      {"fuzz", test_fuzz},
  };
  for (size_t i = 0; i < sizeof tests / sizeof tests[0]; i++) {
    if (tests[i].fn() != 0) {
      fprintf(stderr, "test %s FAILED\n", tests[i].name);
      return 1;
    }
  }
  printf("all %zu zurl tests passed\n", sizeof tests / sizeof tests[0]);
  return 0;
}
