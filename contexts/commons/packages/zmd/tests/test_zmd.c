/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: zmd test suite.  Exits nonzero on any failure. */
#include "zmd/zmd.h"

#include <stdio.h>
#include <string.h>

static int failures = 0;

#define CHECK(cond)                                                          \
  do {                                                                       \
    if (!(cond)) {                                                           \
      fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);        \
      failures++;                                                            \
    }                                                                        \
  } while (0)

/* Capturing write callback: the whole render lands in one buffer. */
static char cap[1u << 20];
static size_t cap_len;
static bool cap_break; /* simulate a failing sink */

static bool cap_write(void *ctx, const char *data, size_t len) {
  (void)ctx;
  if (cap_break)
    return false;
  if (cap_len + len > sizeof(cap))
    return false;
  memcpy(cap + cap_len, data, len);
  cap_len += len;
  return true;
}

/* Render md (NUL-terminated) and NUL-terminate the capture. */
static const char *render(const char *md) {
  cap_len = 0;
  cap_break = false;
  bool ok = zmd_render_html(md, strlen(md), cap_write, NULL);
  cap[cap_len] = '\0';
  return ok ? cap : NULL;
}

/* Golden check: md must render successfully to exactly want. */
#define EXPECT(md, want)                                                     \
  do {                                                                       \
    const char *got_ = render(md);                                           \
    if (!got_ || strcmp(got_, want) != 0) {                                  \
      fprintf(stderr, "FAIL %s:%d\n  md:   %s\n  want: %s\n  got:  %s\n",   \
              __FILE__, __LINE__, md, want, got_ ? got_ : "(render error)"); \
      failures++;                                                            \
    }                                                                        \
  } while (0)

/* The render must fail closed. */
#define REJECT(md)                                                           \
  do {                                                                       \
    cap_len = 0;                                                             \
    cap_break = false;                                                       \
    if (zmd_render_html(md, strlen(md), cap_write, NULL)) {                  \
      fprintf(stderr, "FAIL %s:%d: render accepted %s\n", __FILE__,          \
              __LINE__, md);                                                 \
      failures++;                                                            \
    }                                                                        \
  } while (0)

static void test_headings(void) {
  EXPECT("# Hello", "<h1>Hello</h1>\n");
  EXPECT("###### Six", "<h6>Six</h6>\n");
  EXPECT("####### seven is a paragraph", "<p>####### seven is a paragraph</p>\n");
  EXPECT("#NoSpace", "<p>#NoSpace</p>\n");
  EXPECT("## Title ##", "<h2>Title</h2>\n"); /* closing sequence stripped */
  EXPECT("## C# rules", "<h2>C# rules</h2>\n"); /* '#' after text kept */
  EXPECT("# **Hi** `x`", "<h1><strong>Hi</strong> <code>x</code></h1>\n");
  EXPECT("##   \n", "<h2></h2>\n"); /* empty heading */
}

static void test_paragraphs(void) {
  EXPECT("hello world", "<p>hello world</p>\n");
  EXPECT("a\nb", "<p>a\nb</p>\n"); /* soft break keeps the newline */
  EXPECT("a  \nb", "<p>a<br>\nb</p>\n"); /* two trailing spaces: hard break */
  EXPECT("a\n\nb", "<p>a</p>\n<p>b</p>\n");
  EXPECT("", "");                 /* empty document */
  EXPECT("\n\n  \n\n", "");       /* blank lines only */
  EXPECT("a\r\nb\r\n", "<p>a\nb</p>\n"); /* CRLF accepted */
  /* paragraphs stop at the next block construct */
  EXPECT("text\n# head", "<p>text</p>\n<h1>head</h1>\n");
  EXPECT("text\n- item", "<p>text</p>\n<ul>\n<li>item</li>\n</ul>\n");
  /* no setext headings in the subset */
  EXPECT("Title\n===", "<p>Title\n===</p>\n");
}

static void test_inline(void) {
  EXPECT("**bold**", "<p><strong>bold</strong></p>\n");
  EXPECT("*em*", "<p><em>em</em></p>\n");
  EXPECT("`code`", "<p><code>code</code></p>\n");
  EXPECT("a **b** c *d* e `f` g",
         "<p>a <strong>b</strong> c <em>d</em> e <code>f</code> g</p>\n");
  /* different markers nest */
  EXPECT("**bold *em* end**",
         "<p><strong>bold <em>em</em> end</strong></p>\n");
  EXPECT("**bold `code`**",
         "<p><strong>bold <code>code</code></strong></p>\n");
  /* code spans are literal inside */
  EXPECT("`**not bold**`", "<p><code>**not bold**</code></p>\n");
}

static void test_inline_unclosed(void) {
  EXPECT("**oops", "<p>**oops</p>\n");
  EXPECT("*oops", "<p>*oops</p>\n");
  EXPECT("`oops", "<p>`oops</p>\n");
  EXPECT("***", "<hr>\n"); /* three stars alone are a rule, not emphasis */
  EXPECT("**a *b**", "<p><strong>a *b</strong></p>\n");
  EXPECT("[a](https://x", "<p>[a](https://x</p>\n");
  EXPECT("[a]", "<p>[a]</p>\n");
  EXPECT("[a] (b)", "<p>[a] (b)</p>\n"); /* space between ] and ( */
  EXPECT("![alt](", "<p>![alt](</p>\n");
  EXPECT("lone ! bang", "<p>lone ! bang</p>\n");
}

static void test_escaping(void) {
  /* no raw HTML passthrough: everything is escaped */
  EXPECT("<script>alert(\"x\")&'</script>",
         "<p>&lt;script&gt;alert(&quot;x&quot;)&amp;&#39;&lt;/script&gt;"
         "</p>\n");
  EXPECT("# <b>x</b>", "<h1>&lt;b&gt;x&lt;/b&gt;</h1>\n");
  EXPECT("`<b>`", "<p><code>&lt;b&gt;</code></p>\n");
  EXPECT("```\n<b>&amp;\n```", "<pre><code>&lt;b&gt;&amp;amp;\n</code></pre>\n");
  /* attribute context: quotes in a URL are escaped */
  EXPECT("[a](https://x/?q=\"1\")",
         "<p><a href=\"https://x/?q=&quot;1&quot;\">a</a></p>\n");
  EXPECT("![<x>](pic.png)",
         "<p><img src=\"pic.png\" alt=\"&lt;x&gt;\"></p>\n");
}

static void test_links_images(void) {
  EXPECT("[site](https://example.com)",
         "<p><a href=\"https://example.com\">site</a></p>\n");
  EXPECT("[h](http://x)", "<p><a href=\"http://x\">h</a></p>\n");
  EXPECT("[m](mailto:a@b.c)", "<p><a href=\"mailto:a@b.c\">m</a></p>\n");
  EXPECT("[r](/a/b)", "<p><a href=\"/a/b\">r</a></p>\n");
  EXPECT("[r](page.html#frag)", "<p><a href=\"page.html#frag\">r</a></p>\n");
  EXPECT("[a](HTTPS://x)", "<p><a href=\"HTTPS://x\">a</a></p>\n");
  EXPECT("[**b**](https://x)",
         "<p><a href=\"https://x\"><strong>b</strong></a></p>\n");
  EXPECT("![pic](https://x/i.png)",
         "<p><img src=\"https://x/i.png\" alt=\"pic\"></p>\n");
}

static void test_url_policy(void) {
  /* disallowed schemes degrade the construct to escaped literal text */
  EXPECT("[a](javascript:alert(1))", "<p>[a](javascript:alert(1))</p>\n");
  EXPECT("[a](JaVaScRiPt:alert(1))", "<p>[a](JaVaScRiPt:alert(1))</p>\n");
  EXPECT("[a](data:text/html,x)", "<p>[a](data:text/html,x)</p>\n");
  EXPECT("[a](vbscript:x)", "<p>[a](vbscript:x)</p>\n");
  EXPECT("[a](file:///etc/passwd)", "<p>[a](file:///etc/passwd)</p>\n");
  EXPECT("![p](javascript:x)", "<p>![p](javascript:x)</p>\n");
  /* control bytes and whitespace in the URL are rejected the same way */
  EXPECT("[a](https://x/ |)", "<p>[a](https://x/ |)</p>\n");
  EXPECT("[a](https://x/\x01y)", "<p>[a](https://x/\x01y)</p>\n");
}

static void test_fences(void) {
  EXPECT("```\nint x;\n```", "<pre><code>int x;\n</code></pre>\n");
  EXPECT("```c\nint x;\n```", "<pre><code>int x;\n</code></pre>\n");
  EXPECT("```\n```", "<pre><code></code></pre>\n");
  /* unclosed fence runs to end of input */
  EXPECT("```\ncode\nmore", "<pre><code>code\nmore\n</code></pre>\n");
  EXPECT("before\n```\nx < y\n```\nafter",
         "<p>before</p>\n<pre><code>x &lt; y\n</code></pre>\n<p>after</p>\n");
}

static void test_rules(void) {
  EXPECT("---", "<hr>\n");
  EXPECT("***", "<hr>\n");
  EXPECT("___", "<hr>\n");
  EXPECT("- - -", "<hr>\n");
  EXPECT("--", "<p>--</p>\n");   /* two is not enough */
  EXPECT("-*-", "<p>-*-</p>\n"); /* mixed marks are not a rule */
  EXPECT("a\n---\nb", "<p>a</p>\n<hr>\n<p>b</p>\n");
}

static void test_lists(void) {
  EXPECT("- a\n- b", "<ul>\n<li>a</li>\n<li>b</li>\n</ul>\n");
  EXPECT("* a", "<ul>\n<li>a</li>\n</ul>\n");
  EXPECT("1. a\n2. b\n10. c",
         "<ol>\n<li>a</li>\n<li>b</li>\n<li>c</li>\n</ol>\n");
  EXPECT("1.a", "<p>1.a</p>\n"); /* no space after the dot: paragraph */
  EXPECT("- **x** and `y`",
         "<ul>\n<li><strong>x</strong> and <code>y</code></li>\n</ul>\n");
  /* a blank line or a marker-type change starts a new list */
  EXPECT("- a\n\n- b", "<ul>\n<li>a</li>\n</ul>\n<ul>\n<li>b</li>\n</ul>\n");
  EXPECT("- a\n1. b",
         "<ul>\n<li>a</li>\n</ul>\n<ol>\n<li>b</li>\n</ol>\n");
  EXPECT("- <b>", "<ul>\n<li>&lt;b&gt;</li>\n</ul>\n");
}

static void test_blockquotes(void) {
  EXPECT("> hi", "<blockquote>\n<p>hi</p>\n</blockquote>\n");
  EXPECT(">hi", "<blockquote>\n<p>hi</p>\n</blockquote>\n");
  EXPECT("> a\n> b", "<blockquote>\n<p>a\nb</p>\n</blockquote>\n");
  EXPECT("> **bold**", "<blockquote>\n<p><strong>bold</strong></p>\n</blockquote>\n");
  EXPECT("> <x>", "<blockquote>\n<p>&lt;x&gt;</p>\n</blockquote>\n");
  EXPECT("q\n> b", "<p>q</p>\n<blockquote>\n<p>b</p>\n</blockquote>\n");
  /* separated by a blank line: two quotes */
  EXPECT("> a\n\n> b",
         "<blockquote>\n<p>a</p>\n</blockquote>\n"
         "<blockquote>\n<p>b</p>\n</blockquote>\n");
}

static void test_utf8(void) {
  EXPECT("héllo — wörld", "<p>héllo — wörld</p>\n"); /* multibyte passes */
  REJECT("bad \xC0\x80");       /* overlong */
  REJECT("bad \xE2\x82");       /* truncated 3-byte */
  REJECT("bad \xED\xA0\x80");   /* UTF-16 surrogate */
  REJECT("bad \xF4\x90\x80\x80"); /* above U+10FFFF */
  REJECT("\x80");               /* lone continuation */
}

static void test_fail_closed(void) {
  /* NULL arguments */
  CHECK(!zmd_render_html(NULL, 5, cap_write, NULL));
  CHECK(!zmd_render_html("x", 1, NULL, NULL));
  /* NULL with zero length is a valid empty document */
  cap_len = 0;
  CHECK(zmd_render_html(NULL, 0, cap_write, NULL));
  CHECK(cap_len == 0);
  /* over the input bound: rejected before the pointer is dereferenced */
  CHECK(!zmd_render_html("x", (size_t)ZMD_MAX_INPUT + 1, cap_write, NULL));
  /* a failing sink aborts the render */
  cap_len = 0;
  cap_break = true;
  CHECK(!zmd_render_html("hello", 5, cap_write, NULL));
  cap_break = false;
}

static void test_long_document(void) {
  /* a mixed document end to end */
  const char *md =
      "# Doc\n"
      "\n"
      "Intro **bold** text.\n"
      "\n"
      "- one\n"
      "- two\n"
      "\n"
      "> quoted\n"
      "\n"
      "```\n"
      "code & <>\n"
      "```\n"
      "\n"
      "---\n"
      "\n"
      "[link](https://x) and ![img](i.png)\n";
  const char *want =
      "<h1>Doc</h1>\n"
      "<p>Intro <strong>bold</strong> text.</p>\n"
      "<ul>\n<li>one</li>\n<li>two</li>\n</ul>\n"
      "<blockquote>\n<p>quoted</p>\n</blockquote>\n"
      "<pre><code>code &amp; &lt;&gt;\n</code></pre>\n"
      "<hr>\n"
      "<p><a href=\"https://x\">link</a> and "
      "<img src=\"i.png\" alt=\"img\"></p>\n";
  EXPECT(md, want);
}

int main(void) {
  test_headings();
  test_paragraphs();
  test_inline();
  test_inline_unclosed();
  test_escaping();
  test_links_images();
  test_url_policy();
  test_fences();
  test_rules();
  test_lists();
  test_blockquotes();
  test_utf8();
  test_fail_closed();
  test_long_document();
  if (failures) {
    fprintf(stderr, "zmd: %d failure(s)\n", failures);
    return 1;
  }
  printf("zmd: all tests passed\n");
  return 0;
}
