/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: zxml test suite.  Exits nonzero on the first failure. */
#include "zxml/zxml.h"

#include <stdio.h>
#include <string.h>

/* Only the embedded CLI's standard output is redirected; the library's
 * existing sink tests and this test program retain their real streams. */
static FILE *cli_output;
static FILE *cli_stream(FILE *stream) {
  return stream == stdout && cli_output ? cli_output : stream;
}
static size_t cli_fwrite(const void *data, size_t size, size_t n, FILE *stream) {
  return fwrite(data, size, n, cli_stream(stream));
}
static int cli_fputc(int ch, FILE *stream) {
  return fputc(ch, cli_stream(stream));
}
static int cli_fflush(FILE *stream) {
  return fflush(cli_stream(stream));
}
static int cli_ferror(FILE *stream) {
  return ferror(cli_stream(stream));
}

#define fwrite cli_fwrite
#define fputc cli_fputc
#define fflush cli_fflush
#define ferror cli_ferror
#define main zxml_cli_main
#include "../app/main.c"
#undef main
#undef ferror
#undef fflush
#undef fputc
#undef fwrite

static int failures = 0;

#define CHECK(cond)                                                          \
  do {                                                                       \
    if (!(cond)) {                                                           \
      fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);        \
      failures++;                                                            \
    }                                                                        \
  } while (0)

/* Growing-buffer sink; can be told to fail after a byte budget. */
typedef struct {
  char buf[16384];
  size_t len;
  size_t budget; /* fail once writes would exceed this */
} sink;

static bool sink_write(void *ctx, const char *data, size_t len) {
  sink *s = ctx;
  if (s->len + len > s->budget)
    return false;
  memcpy(s->buf + s->len, data, len);
  s->len += len;
  return true;
}

#define SINK(name)                                                           \
  sink name;                                                                 \
  name.len = 0;                                                              \
  name.budget = sizeof(name.buf)

/* Run body with a fresh writer over a fresh sink, then compare bytes. */
#define GOLDEN(flags, body, want)                                            \
  do {                                                                       \
    SINK(s_);                                                                \
    zxml x_;                                                                 \
    zxml_open(&x_, sink_write, &s_, (flags));                                \
    do {                                                                     \
      body                                                                   \
    } while (0);                                                             \
    CHECK(zxml_close(&x_) == ZXML_OK);                                       \
    CHECK(s_.len == strlen(want));                                           \
    CHECK(memcmp(s_.buf, (want), s_.len) == 0);                              \
    if (s_.len != strlen(want) || memcmp(s_.buf, (want), s_.len) != 0)       \
      fprintf(stderr, "  got: %.*s\n", (int)s_.len, s_.buf);                 \
  } while (0)

#define OK(call) CHECK((call) == ZXML_OK)
#define ERR(call, want) CHECK((call) == (want))

static void test_nesting(void) {
  GOLDEN(ZXML_COMPACT, OK(zxml_elem_open(&x_, "a"));
         OK(zxml_elem_open(&x_, "b")); OK(zxml_text(&x_, "hi"));
         OK(zxml_elem_close(&x_)); OK(zxml_elem_close(&x_));,
         "<a><b>hi</b></a>");
  /* Empty element self-closes. */
  GOLDEN(ZXML_COMPACT, OK(zxml_elem_open(&x_, "a"));
         OK(zxml_elem_close(&x_));,
         "<a/>");
  /* zxml_elem convenience, with and without text. */
  GOLDEN(ZXML_COMPACT, OK(zxml_elem_open(&x_, "r"));
         OK(zxml_elem(&x_, "k", "v")); OK(zxml_elem(&x_, "e", NULL));
         OK(zxml_elem_close(&x_));,
         "<r><k>v</k><e/></r>");
}

static void test_attributes(void) {
  GOLDEN(ZXML_COMPACT, OK(zxml_elem_open(&x_, "a"));
         OK(zxml_attr(&x_, "x", "1")); OK(zxml_attr(&x_, "y", NULL));
         OK(zxml_elem_close(&x_));,
         "<a x=\"1\" y=\"\"/>");
  /* Attribute escaping: all five predefined entities. */
  GOLDEN(ZXML_COMPACT, OK(zxml_elem_open(&x_, "a"));
         OK(zxml_attr(&x_, "v", "\"&<>'")); OK(zxml_elem_close(&x_));,
         "<a v=\"&quot;&amp;&lt;&gt;&apos;\"/>");
}

static void test_text_escaping(void) {
  /* In text, only & < > are escaped; quotes pass through. */
  GOLDEN(ZXML_COMPACT, OK(zxml_elem_open(&x_, "t"));
         OK(zxml_text(&x_, "5 < 6 & \"q\" 'x' > 4"));
         OK(zxml_elem_close(&x_));,
         "<t>5 &lt; 6 &amp; \"q\" 'x' &gt; 4</t>");
  /* Tab/newline/return are legal and pass through. */
  GOLDEN(ZXML_COMPACT, OK(zxml_elem_open(&x_, "t"));
         OK(zxml_text(&x_, "a\tb\nc\rd")); OK(zxml_elem_close(&x_));,
         "<t>a\tb\nc\rd</t>");
  /* Valid multibyte UTF-8 passes through unescaped. */
  GOLDEN(ZXML_COMPACT, OK(zxml_elem_open(&x_, "t"));
         OK(zxml_text(&x_, "caf\xC3\xA9 \xE2\x80\x94 ok"));
         OK(zxml_elem_close(&x_));,
         "<t>caf\xC3\xA9 \xE2\x80\x94 ok</t>");
}

static void test_rejection(void) {
  /* Invalid UTF-8 is rejected, never emitted. */
  SINK(s);
  zxml x;
  zxml_open(&x, sink_write, &s, ZXML_COMPACT);
  OK(zxml_elem_open(&x, "t"));
  ERR(zxml_text(&x, "bad \xFF byte"), ZXML_ERR_UTF8);
  ERR(zxml_text(&x, "\xC3"), ZXML_ERR_UTF8);        /* truncated */
  ERR(zxml_text(&x, "\xED\xA0\x80"), ZXML_ERR_UTF8); /* surrogate */
  ERR(zxml_text(&x, "overlong \xC0\xAF"), ZXML_ERR_UTF8);
  ERR(zxml_text(&x, "still utf8 error"), ZXML_ERR_UTF8); /* sticky */
  /* Nothing of the rejected text reached the sink. */
  CHECK(s.len == 2 && memcmp(s.buf, "<t", 2) == 0);

  /* Control bytes. */
  zxml_open(&x, sink_write, &s, ZXML_COMPACT);
  OK(zxml_elem_open(&x, "t"));
  ERR(zxml_text(&x, "a\x01" "b"), ZXML_ERR_TEXT);
  ERR(zxml_text(&x, "a\x0B"
                    "b"),
      ZXML_ERR_TEXT);

  /* Same checks for attribute values. */
  zxml_open(&x, sink_write, &s, ZXML_COMPACT);
  OK(zxml_elem_open(&x, "t"));
  ERR(zxml_attr(&x, "k", "\xFF"), ZXML_ERR_UTF8);

  zxml_open(&x, sink_write, &s, ZXML_COMPACT);
  OK(zxml_elem_open(&x, "t"));
  ERR(zxml_attr(&x, "k", "a\x7F"
                         "\x02"),
      ZXML_ERR_TEXT);
}

static void test_state_errors(void) {
  SINK(s);
  zxml x;

  /* Close with nothing open. */
  zxml_open(&x, sink_write, &s, ZXML_COMPACT);
  ERR(zxml_elem_close(&x), ZXML_ERR_STATE);

  /* zxml_close with an open element. */
  zxml_open(&x, sink_write, &s, ZXML_COMPACT);
  OK(zxml_elem_open(&x, "a"));
  ERR(zxml_close(&x), ZXML_ERR_STATE);
  ERR(zxml_elem_close(&x), ZXML_ERR_STATE); /* sticky */

  /* zxml_close with no root at all. */
  zxml_open(&x, sink_write, &s, ZXML_COMPACT);
  ERR(zxml_close(&x), ZXML_ERR_STATE);

  /* Double close. */
  zxml_open(&x, sink_write, &s, ZXML_COMPACT);
  OK(zxml_elem(&x, "a", "x"));
  OK(zxml_close(&x));
  ERR(zxml_close(&x), ZXML_ERR_STATE);
  ERR(zxml_elem(&x, "b", "y"), ZXML_ERR_STATE); /* use after close */

  /* Attribute outside a start tag (after text). */
  zxml_open(&x, sink_write, &s, ZXML_COMPACT);
  OK(zxml_elem_open(&x, "a"));
  OK(zxml_text(&x, "t"));
  ERR(zxml_attr(&x, "k", "v"), ZXML_ERR_STATE);

  /* Text outside the root element. */
  zxml_open(&x, sink_write, &s, ZXML_COMPACT);
  ERR(zxml_text(&x, "hello"), ZXML_ERR_STATE);

  /* A second root element. */
  zxml_open(&x, sink_write, &s, ZXML_COMPACT);
  OK(zxml_elem(&x, "a", NULL));
  ERR(zxml_elem_open(&x, "b"), ZXML_ERR_STATE);

  /* Comment after the root closed. */
  zxml_open(&x, sink_write, &s, ZXML_COMPACT);
  OK(zxml_elem(&x, "a", NULL));
  ERR(zxml_comment(&x, "late"), ZXML_ERR_STATE);

  /* Decl must come first. */
  zxml_open(&x, sink_write, &s, ZXML_COMPACT);
  OK(zxml_elem_open(&x, "a"));
  ERR(zxml_decl(&x), ZXML_ERR_STATE);
}

static void test_names(void) {
  SINK(s);
  zxml x;
  zxml_open(&x, sink_write, &s, ZXML_COMPACT);
  ERR(zxml_elem_open(&x, "1a"), ZXML_ERR_NAME);
  zxml_open(&x, sink_write, &s, ZXML_COMPACT);
  ERR(zxml_elem_open(&x, "a b"), ZXML_ERR_NAME);
  zxml_open(&x, sink_write, &s, ZXML_COMPACT);
  ERR(zxml_elem_open(&x, ""), ZXML_ERR_NAME);
  zxml_open(&x, sink_write, &s, ZXML_COMPACT);
  ERR(zxml_elem_open(&x, NULL), ZXML_ERR_NAME);
  zxml_open(&x, sink_write, &s, ZXML_COMPACT);
  {
    char longname[ZXML_MAX_NAME + 2];
    memset(longname, 'a', sizeof(longname) - 1);
    longname[sizeof(longname) - 1] = '\0';
    ERR(zxml_elem_open(&x, longname), ZXML_ERR_NAME);
  }
  zxml_open(&x, sink_write, &s, ZXML_COMPACT);
  OK(zxml_elem_open(&x, "a"));
  ERR(zxml_attr(&x, "1k", "v"), ZXML_ERR_NAME);
  /* Names with . - _ : are fine (XML namespaces). */
  s.len = 0;
  zxml_open(&x, sink_write, &s, ZXML_COMPACT);
  OK(zxml_elem_open(&x, "dc:creator"));
  OK(zxml_attr(&x, "xml:lang", "en"));
  OK(zxml_elem_close(&x));
  OK(zxml_close(&x));
  CHECK(s.len == strlen("<dc:creator xml:lang=\"en\"/>"));
}

static void test_depth(void) {
  SINK(s);
  zxml x;
  zxml_open(&x, sink_write, &s, ZXML_COMPACT);
  for (size_t i = 0; i < ZXML_MAX_DEPTH; i++)
    OK(zxml_elem_open(&x, "d"));
  ERR(zxml_elem_open(&x, "d"), ZXML_ERR_DEPTH);
  for (size_t i = 0; i < ZXML_MAX_DEPTH; i++)
    ERR(zxml_elem_close(&x), ZXML_ERR_DEPTH); /* sticky */
}

static void test_pretty_vs_compact(void) {
  static const char *want_pretty = "<?xml version=\"1.0\" "
                                   "encoding=\"UTF-8\"?>\n"
                                   "<rss version=\"2.0\">\n"
                                   "  <channel>\n"
                                   "    <title>T</title>\n"
                                   "    <link>https://example.com/</link>\n"
                                   "  </channel>\n"
                                   "</rss>";
  static const char *want_compact =
      "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
      "<rss version=\"2.0\"><channel><title>T</title>"
      "<link>https://example.com/</link></channel></rss>";
#define FEED_BODY                                                          \
  OK(zxml_decl(&x_));                                                      \
  OK(zxml_elem_open(&x_, "rss"));                                          \
  OK(zxml_attr(&x_, "version", "2.0"));                                    \
  OK(zxml_elem_open(&x_, "channel"));                                      \
  OK(zxml_elem(&x_, "title", "T"));                                        \
  OK(zxml_elem(&x_, "link", "https://example.com/"));                      \
  OK(zxml_elem_close(&x_));                                                \
  OK(zxml_elem_close(&x_));
  GOLDEN(ZXML_PRETTY, FEED_BODY, want_pretty);
  GOLDEN(ZXML_COMPACT, FEED_BODY, want_compact);
#undef FEED_BODY
  /* Mixed content: no newline is inserted around text, output stays
   * well-formed. */
  GOLDEN(ZXML_PRETTY, OK(zxml_elem_open(&x_, "a"));
         OK(zxml_text(&x_, "pre")); OK(zxml_elem(&x_, "b", "x"));
         OK(zxml_elem_close(&x_));,
         "<a>pre\n  <b>x</b>\n</a>");
}

static void test_comments(void) {
  GOLDEN(ZXML_COMPACT, OK(zxml_elem_open(&x_, "a"));
         OK(zxml_comment(&x_, "note")); OK(zxml_elem_close(&x_));,
         "<a><!--note--></a>");
  /* Comment before the root is allowed. */
  GOLDEN(ZXML_COMPACT, OK(zxml_comment(&x_, "head"));
         OK(zxml_elem(&x_, "a", NULL));,
         "<!--head--><a/>");
  /* "--" inside a comment is illegal. */
  SINK(s);
  zxml x;
  zxml_open(&x, sink_write, &s, ZXML_COMPACT);
  OK(zxml_elem_open(&x, "a"));
  ERR(zxml_comment(&x, "bad -- comment"), ZXML_ERR_TEXT);
}

static void test_sink_failure(void) {
  SINK(s);
  s.budget = 8; /* fail after 8 bytes */
  zxml x;
  zxml_open(&x, sink_write, &s, ZXML_COMPACT);
  OK(zxml_elem_open(&x, "aa"));
  ERR(zxml_elem_open(&x, "bbbbbbbb"), ZXML_ERR_SINK);
  ERR(zxml_elem_close(&x), ZXML_ERR_SINK); /* sticky */
  CHECK(s.len == 5); /* "<aa>" and '<' of the failing element */
}

static void test_sitemap_golden(void) {
  static const char *want =
      "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
      "<urlset xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\">"
      "<url><loc>https://example.com/</loc><lastmod>2026-08-16</lastmod>"
      "<priority>1.0</priority></url>"
      "<url><loc>https://example.com/about?a=1&amp;b=2</loc>"
      "<lastmod>2026-08-01</lastmod><priority>0.5</priority></url>"
      "</urlset>";
  GOLDEN(ZXML_COMPACT, OK(zxml_decl(&x_));
         OK(zxml_elem_open(&x_, "urlset"));
         OK(zxml_attr(&x_, "xmlns",
                      "http://www.sitemaps.org/schemas/sitemap/0.9"));
         OK(zxml_elem_open(&x_, "url"));
         OK(zxml_elem(&x_, "loc", "https://example.com/"));
         OK(zxml_elem(&x_, "lastmod", "2026-08-16"));
         OK(zxml_elem(&x_, "priority", "1.0"));
         OK(zxml_elem_close(&x_));
         OK(zxml_elem_open(&x_, "url"));
         OK(zxml_elem(&x_, "loc", "https://example.com/about?a=1&b=2"));
         OK(zxml_elem(&x_, "lastmod", "2026-08-01"));
         OK(zxml_elem(&x_, "priority", "0.5"));
         OK(zxml_elem_close(&x_));
         OK(zxml_elem_close(&x_));,
         want);
}

static void test_rss_item_golden(void) {
  static const char *want =
      "<rss version=\"2.0\">\n"
      "  <channel>\n"
      "    <title>Example &amp; Sons</title>\n"
      "    <item>\n"
      "      <title>caf\xC3\xA9 \xE2\x80\x94 bytes &lt;ok&gt;</title>\n"
      "      <link>https://example.com/item/1</link>\n"
      "      <guid isPermaLink=\"true\">https://example.com/item/1</guid>\n"
      "      <pubDate>Sun, 16 Aug 2026 00:00:00 +0000</pubDate>\n"
      "    </item>\n"
      "  </channel>\n"
      "</rss>";
  GOLDEN(ZXML_PRETTY, OK(zxml_elem_open(&x_, "rss"));
         OK(zxml_attr(&x_, "version", "2.0"));
         OK(zxml_elem_open(&x_, "channel"));
         OK(zxml_elem(&x_, "title", "Example & Sons"));
         OK(zxml_elem_open(&x_, "item"));
         OK(zxml_elem(&x_, "title", "caf\xC3\xA9 \xE2\x80\x94 bytes <ok>"));
         OK(zxml_elem(&x_, "link", "https://example.com/item/1"));
         OK(zxml_elem_open(&x_, "guid"));
         OK(zxml_attr(&x_, "isPermaLink", "true"));
         OK(zxml_text(&x_, "https://example.com/item/1"));
         OK(zxml_elem_close(&x_));
         OK(zxml_elem(&x_, "pubDate", "Sun, 16 Aug 2026 00:00:00 +0000"));
         OK(zxml_elem_close(&x_));
         OK(zxml_elem_close(&x_));
         OK(zxml_elem_close(&x_));,
         want);
}

/* A comment's last byte cannot join its closing '-->' delimiter. */
static void test_comment_tail_controls(void) {
  static const char *const rows[] = {"", "-note", "note-here"};
  static const char *const expected[] = {
      "<r><!----></r>", "<r><!---note--></r>", "<r><!--note-here--></r>"};
  for (size_t i = 0; i < sizeof rows / sizeof rows[0]; i++) {
    SINK(s);
    zxml x;
    zxml_open(&x, sink_write, &s, ZXML_COMPACT);
    OK(zxml_elem_open(&x, "r"));
    OK(zxml_comment(&x, rows[i]));
    OK(zxml_elem_close(&x));
    OK(zxml_close(&x));
    CHECK(s.len == strlen(expected[i]));
    CHECK(s.len <= strlen(expected[i]) &&
          memcmp(s.buf, expected[i], s.len) == 0);
  }
}

static void test_comment_tail(void) {
  static const char *const rows[] = {"-", "note-"};
  for (size_t i = 0; i < sizeof rows / sizeof rows[0]; i++) {
    SINK(s);
    zxml x;
    zxml_open(&x, sink_write, &s, ZXML_COMPACT);
    zxml_status opened = zxml_elem_open(&x, "r");
    zxml_status result = zxml_comment(&x, rows[i]);
    CHECK(opened == ZXML_OK && result == ZXML_ERR_TEXT &&
          zxml_elem_close(&x) == ZXML_ERR_TEXT &&
          s.len == 2 && memcmp(s.buf, "<r", 2) == 0);
  }
}

/* These scalars are valid UTF-8 but outside XML 1.0's Char production. */
static void test_xml_scalar_edges(void) {
  static const char *const rows[] = {"\xEF\xBF\xBE", "\xEF\xBF\xBF",
      "a\xEF\xBF\xBE", "a\xEF\xBF\xBF",
      "\xC3\xA9\xEF\xBF\xBE", "\xC3\xA9\xEF\xBF\xBF"};
  for (size_t i = 0; i < sizeof rows / sizeof rows[0]; i++) {
    for (unsigned operation = 0; operation < 3; operation++) {
      SINK(s);
      zxml x;
      zxml_open(&x, sink_write, &s, ZXML_COMPACT);
      zxml_status opened = zxml_elem_open(&x, "r");
      zxml_status result = operation == 0 ? zxml_text(&x, rows[i]) :
                           operation == 1 ? zxml_attr(&x, "v", rows[i]) :
                                            zxml_comment(&x, rows[i]);
      CHECK(opened == ZXML_OK && result == ZXML_ERR_TEXT &&
            zxml_elem_close(&x) == ZXML_ERR_TEXT &&
            s.len == 2 && memcmp(s.buf, "<r", 2) == 0);
    }
  }
}

/* Adjacent permitted scalar values remain valid in all XML text contexts. */
static void test_xml_scalar_controls(void) {
  static const char *const rows[] = {"\xEF\xBF\xBD", "\xF0\x90\x80\x80"};
  for (size_t i = 0; i < sizeof rows / sizeof rows[0]; i++) {
    for (unsigned operation = 0; operation < 3; operation++) {
      SINK(s);
      zxml x;
      zxml_open(&x, sink_write, &s, ZXML_COMPACT);
      OK(zxml_elem_open(&x, "r"));
      zxml_status result = operation == 0 ? zxml_text(&x, rows[i]) :
                           operation == 1 ? zxml_attr(&x, "v", rows[i]) :
                                            zxml_comment(&x, rows[i]);
      CHECK(result == ZXML_OK);
      OK(zxml_elem_close(&x));
      OK(zxml_close(&x));
      const char *prefix = operation == 0 ? "<r>" :
                           operation == 1 ? "<r v=\"" : "<r><!--";
      const char *suffix = operation == 0 ? "</r>" :
                           operation == 1 ? "\"/>" : "--></r>";
      CHECK(s.len == strlen(prefix) + strlen(rows[i]) + strlen(suffix));
      CHECK(memcmp(s.buf, prefix, strlen(prefix)) == 0);
      CHECK(memcmp(s.buf + strlen(prefix), rows[i], strlen(rows[i])) == 0);
      CHECK(memcmp(s.buf + strlen(prefix) + strlen(rows[i]), suffix,
                   strlen(suffix)) == 0);
    }
  }
}

static bool cli_feed_contents(const char *bytes, bool compact) {
  if (strstr(bytes, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>") != bytes ||
      !strstr(bytes, "<rss version=\"2.0\">") || !strstr(bytes, "</rss>") ||
      !strstr(bytes, "Escaping &amp; &lt;friends&gt;")) return false;
  size_t items = 0;
  for (const char *p = bytes; (p = strstr(p, "<item>")) != NULL; p++) items++;
  return items == 3 && ((strchr(bytes, '\n') == NULL) == compact);
}

static int cli_normal(bool compact) {
  FILE *output = tmpfile();
  if (!output) return 1;
  cli_output = output;
  char *argv[] = {"zxml", compact ? "--compact" : NULL, NULL};
  bool ok = zxml_cli_main(compact ? 2 : 1, argv) == 0;
  rewind(output);
  char bytes[4096] = {0};
  size_t n = fread(bytes, 1, sizeof bytes - 1, output);
  ok = ok && !ferror(output) && n > 0 && n < sizeof bytes - 1;
  ok = ok && cli_feed_contents(bytes, compact);
  if (fclose(output) != 0) ok = false;
  cli_output = NULL;
  return ok ? 0 : 1;
}

static int cli_usage(void) {
  FILE *output = tmpfile();
  if (!output) return 1;
  cli_output = output;
  char *argv[] = {"zxml", "--bad", NULL, NULL};
  bool ok = zxml_cli_main(2, argv) == 2 && ftell(output) == 0;
  argv[1] = "--compact";
  argv[2] = "extra";
  ok = ok && zxml_cli_main(3, argv) == 2 && ftell(output) == 0;
  if (fclose(output) != 0) ok = false;
  cli_output = NULL;
  return ok ? 0 : 1;
}

static int cli_output_error(const char *path, const char *access, bool compact) {
  FILE *output = fopen(path, access);
  if (!output) return 1;
  char buffer[4096];
  bool ok = setvbuf(output, buffer, _IOFBF, sizeof buffer) == 0;
  cli_output = output;
  char *argv[] = {"zxml", compact ? "--compact" : NULL, NULL};
  if (ok) ok = zxml_cli_main(compact ? 2 : 1, argv) == 1 && cli_ferror(stdout);
  (void)cli_fflush(stdout);
  (void)fclose(output);
  cli_output = NULL;
  return ok ? 0 : 1;
}

static void test_cli_output(void) {
  CHECK(cli_normal(false) == 0);
  CHECK(cli_normal(true) == 0);
  CHECK(cli_usage() == 0);
#if defined(_WIN32)
  const char *null_path = "NUL";
#else
  const char *null_path = "/dev/null";
#endif
  for (int compact = 0; compact < 2; compact++) {
    CHECK(cli_output_error(null_path, "r", compact != 0) == 0);
#if defined(__linux__)
    CHECK(cli_output_error("/dev/full", "w", compact != 0) == 0);
#endif
  }
}

int main(void) {
  test_cli_output();
  test_xml_scalar_controls();
  test_comment_tail_controls();
  test_xml_scalar_edges();
  test_comment_tail();
  test_nesting();
  test_attributes();
  test_text_escaping();
  test_rejection();
  test_state_errors();
  test_names();
  test_depth();
  test_pretty_vs_compact();
  test_comments();
  test_sink_failure();
  test_sitemap_golden();
  test_rss_item_golden();
  if (failures) {
    fprintf(stderr, "zxml: %d failure(s)\n", failures);
    return 1;
  }
  printf("zxml: all tests passed\n");
  return 0;
}
