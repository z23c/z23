/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: zini test suite.  Exits nonzero on the first failure. */
#include "zini/zini.h"

#include <stdio.h>
#include <string.h>

static bool cli_omit_entries;
static void cli_test_foreach(const zini *ini, zini_entry_fn fn, void *ctx) {
  if (!cli_omit_entries) zini_foreach(ini, fn, ctx);
}

#define zini_foreach cli_test_foreach
#define main zini_cli_main
#include "../app/main.c"
#undef main
#undef zini_foreach

static int failures = 0;

#define CHECK(cond)                                                          \
  do {                                                                       \
    if (!(cond)) {                                                           \
      fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);        \
      failures++;                                                            \
    }                                                                        \
  } while (0)

static zini *must_parse(const char *text) {
  zini_error err = {0, nullptr};
  zini *ini = zini_parse(text, strlen(text), &err);
  if (!ini)
    fprintf(stderr, "  parse failed at line %zu: %s\n", err.line,
            err.message);
  return ini;
}

static void test_sections_and_keys(void) {
  zini *ini = must_parse("[server]\nhost = example.com\nport = 8332\n"
                         "[wallet]\nautoload=1\n");
  CHECK(ini != nullptr);
  CHECK(zini_count(ini) == 3);
  const char *v = zini_get(ini, "server", "host");
  CHECK(v && strcmp(v, "example.com") == 0);
  v = zini_get(ini, "server", "port");
  CHECK(v && strcmp(v, "8332") == 0);
  v = zini_get(ini, "wallet", "autoload");
  CHECK(v && strcmp(v, "1") == 0);
  CHECK(zini_get(ini, "server", "missing") == nullptr);
  CHECK(zini_get(ini, "missing", "host") == nullptr);
  zini_destroy(ini);
}

static void test_global_section(void) {
  zini *ini = must_parse("top = 1\n[s]\nk = v\n");
  CHECK(ini != nullptr);
  const char *v = zini_get(ini, nullptr, "top");
  CHECK(v && strcmp(v, "1") == 0);
  v = zini_get(ini, "", "top");
  CHECK(v && strcmp(v, "1") == 0);
  zini_destroy(ini);
}

static void test_comments(void) {
  /* Junk between ']' and end-of-line makes the header malformed, even if
   * the junk looks like a comment. */
  zini_error err = {0, nullptr};
  const char *bad = "[s] ; trailing junk\n";
  CHECK(zini_parse(bad, strlen(bad), &err) == nullptr);

  zini *ini = must_parse("# leading comment\n"
                         "; another comment\n"
                         "   # indented comment\n"
                         "[s]\nk = v # inline comment\n"
                         "j = v ; inline comment\n"
                         "h = a#b ; hash without leading space stays\n");
  CHECK(ini != nullptr);
  const char *v = zini_get(ini, "s", "k");
  CHECK(v && strcmp(v, "v") == 0);
  v = zini_get(ini, "s", "j");
  CHECK(v && strcmp(v, "v") == 0);
  v = zini_get(ini, "s", "h");
  CHECK(v && strcmp(v, "a#b") == 0);
  zini_destroy(ini);
}

static void test_duplicate_keys_last_wins(void) {
  zini *ini = must_parse("[s]\nk = first\nk = second\n"
                         "[s]\nk = third\n"); /* repeated section merges */
  CHECK(ini != nullptr);
  CHECK(zini_count(ini) == 1);
  const char *v = zini_get(ini, "s", "k");
  CHECK(v && strcmp(v, "third") == 0);
  zini_destroy(ini);
}

static void test_empty_values_and_whitespace(void) {
  zini *ini = must_parse("[s]\nempty =\nblank=   \nspaced   =   value  \n");
  CHECK(ini != nullptr);
  const char *v = zini_get(ini, "s", "empty");
  CHECK(v && strcmp(v, "") == 0);
  v = zini_get(ini, "s", "blank");
  CHECK(v && strcmp(v, "") == 0);
  v = zini_get(ini, "s", "spaced");
  CHECK(v && strcmp(v, "value") == 0);
  zini_destroy(ini);
}

static void test_crlf(void) {
  zini *ini = must_parse("[s]\r\nk = v\r\n");
  CHECK(ini != nullptr);
  const char *v = zini_get(ini, "s", "k");
  CHECK(v && strcmp(v, "v") == 0);
  zini_destroy(ini);
}

static void test_malformed_lines(void) {
  zini_error err = {0, nullptr};
  const char *bad[] = {
      "not a key value line\n", /* no '=' */
      "= novaluekey\n",         /* empty key */
      "[unterminated\n",        /* no closing bracket */
      "[s] extra\n",            /* junk after ']' */
  };
  for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
    zini *ini = zini_parse(bad[i], strlen(bad[i]), &err);
    CHECK(ini == nullptr);
    CHECK(err.line == 1);
    CHECK(err.message != nullptr);
  }
  /* Error line number advances. */
  zini *ini = zini_parse("[s]\nk=v\nbad line\n", 16, &err);
  CHECK(ini == nullptr && err.line == 3);
}

static void test_empty_section_name_and_header_whitespace(void) {
  zini *ini = must_parse("[  padded  ]\nk = v\n[]\ng = 1\n");
  CHECK(ini != nullptr);
  const char *v = zini_get(ini, "padded", "k");
  CHECK(v && strcmp(v, "v") == 0);
  /* An empty section name aliases the global section. */
  v = zini_get(ini, "", "g");
  CHECK(v && strcmp(v, "1") == 0);
  zini_destroy(ini);
}

static void test_empty_input(void) {
  zini *ini = must_parse("");
  CHECK(ini != nullptr);
  CHECK(zini_count(ini) == 0);
  zini_destroy(ini);
}

/* --- iteration determinism: sorted by (section, key) --- */

typedef struct {
  char dump[2048];
  size_t len;
} dump_ctx;

static void dump_entry(void *vctx, const char *section, const char *key,
                       const char *value) {
  dump_ctx *d = vctx;
  int n = snprintf(d->dump + d->len, sizeof(d->dump) - d->len, "%s.%s=%s\n",
                   section, key, value);
  d->len += (size_t)n;
}

static void test_iteration_sorted_deterministic(void) {
  /* Same content, different file order, must dump identically. */
  const char *a = "root=g\n[zeta]\nb=2\na=1\n[alpha]\ny=9\n";
  const char *b = "root=g\n[alpha]\ny=9\n[zeta]\na=1\nb=2\n";
  zini *ia = must_parse(a);
  zini *ib = must_parse(b);
  CHECK(ia && ib);
  dump_ctx da = {.len = 0}, db = {.len = 0};
  zini_foreach(ia, dump_entry, &da);
  zini_foreach(ib, dump_entry, &db);
  const char *want = ".root=g\nalpha.y=9\nzeta.a=1\nzeta.b=2\n";
  CHECK(strcmp(da.dump, want) == 0);
  CHECK(strcmp(db.dump, want) == 0);
  zini_destroy(ia);
  zini_destroy(ib);
}

static void test_embedded_nul(void) {
  /* Explicit spans: strlen would hide the byte and cannot qualify this test. */
  static const char key[] = "a\0b=1\na=2\n";
  static const char section[] = "[s\0x]\nk=v\n";
  static const char value[] = "k=v\0x\n";
  static const char partial[] = "ok=1\nbad=v\0x\n";
  static const char nested[] = "[s]\nok=1\nbad\0key=2\r\n";
  static const char inline_comment[] = "k=v # ignored\0bytes\n";
  static const char blank_nul[] = " \t\0 \t\n";
  const struct {
    const char *text;
    size_t len;
    size_t line;
  } cases[] = {
      {key, sizeof key - 1, 1},
      {section, sizeof section - 1, 1},
      {value, sizeof value - 1, 1},
      {partial, sizeof partial - 1, 2},
      {nested, sizeof nested - 1, 3},
      {inline_comment, sizeof inline_comment - 1, 1},
      {blank_nul, sizeof blank_nul - 1, 1},
  };
  for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
    zini_error err = {0, nullptr};
    zini *ini = zini_parse(cases[i].text, cases[i].len, &err);
    CHECK(ini == nullptr);
    CHECK(err.line == cases[i].line);
    CHECK(err.message && strcmp(err.message, "embedded NUL byte") == 0);
    zini_destroy(ini); /* clean up the unexpected base result on RED */
  }
  zini *ini = zini_parse(nested, sizeof nested - 1, nullptr);
  CHECK(ini == nullptr); /* cleanup must not depend on a diagnostic pointer */
  zini_destroy(ini);

  /* Ignored full-line comments retain their byte-span behavior. */
  static const char comments[] = " # ignored\0bytes\n; ignored\0bytes\nk=v\n";
  ini = zini_parse(comments, sizeof comments - 1, nullptr);
  CHECK(ini != nullptr);
  if (ini) {
    CHECK(zini_count(ini) == 1);
    const char *v = zini_get(ini, "", "k");
    CHECK(v && strcmp(v, "v") == 0);
  }
  zini_destroy(ini);
}

static int cli_case(const char *text, bool omit, int status, const char *expected) {
  FILE *source = tmpfile(), *output = tmpfile();
  int failed = 1;
  if (!source || !output) goto cleanup;
  if (fputs(text, source) < 0 || fflush(source) != 0) goto cleanup;
  rewind(source);
  cli_omit_entries = omit;
  int rc = cli_run(source, output);
  cli_omit_entries = false;
  if (rc != status) goto cleanup;
  rewind(output);
  char bytes[1024];
  size_t n = fread(bytes, 1, sizeof bytes, output);
  if (ferror(output) || n != strlen(expected)) goto cleanup;
  if (memcmp(bytes, expected, n) != 0) goto cleanup;
  failed = 0;
cleanup:
  if (source && fclose(source) != 0) failed = 1;
  if (output && fclose(output) != 0) failed = 1;
  return failed;
}

static int cli_output_error(const char *path, const char *access) {
  FILE *source = tmpfile(), *output = fopen(path, access);
  char buffer[4096];
  int failed = 1;
  if (!source || !output) goto cleanup;
  if (setvbuf(output, buffer, _IOFBF, sizeof buffer) != 0) goto cleanup;
  if (fputs("k=v\n", source) < 0 || fflush(source) != 0) goto cleanup;
  rewind(source);
  if (cli_run(source, output) != 2 || !ferror(output)) goto cleanup;
  failed = 0;
cleanup:
  if (source && fclose(source) != 0) failed = 1;
  if (output) (void)fclose(output);
  return failed;
}

static void test_cli_output(void) {
  CHECK(cli_case("", false, 0, "") == 0);
  CHECK(cli_case("k=v\n", true, 2, "") == 0);
  CHECK(cli_case("k=v\n", false, 0, "k = v\n") == 0);
  CHECK(cli_case("[z]\nb=2\na=1\n[]\ng=0\n[a]\nk=v\n", false, 0,
      "g = 0\n[a] k = v\n[z] a = 1\n[z] b = 2\n") == 0);
#if defined(_WIN32)
  CHECK(cli_output_error("NUL", "r") == 0);
#else
  CHECK(cli_output_error("/dev/null", "r") == 0);
#endif
#if defined(__linux__)
  CHECK(cli_output_error("/dev/full", "w") == 0);
#endif
}

int main(void) {
  test_cli_output();
  test_sections_and_keys();
  test_global_section();
  test_comments();
  test_duplicate_keys_last_wins();
  test_empty_values_and_whitespace();
  test_crlf();
  test_malformed_lines();
  test_embedded_nul();
  test_empty_section_name_and_header_whitespace();
  test_empty_input();
  test_iteration_sorted_deterministic();
  if (failures) {
    fprintf(stderr, "zini: %d failure(s)\n", failures);
    return 1;
  }
  puts("zini: all tests passed");
  return 0;
}
