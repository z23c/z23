/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Markdown-subset to HTML rendering (see the header for the
 *          exact subset contract). */
#include "zmd/zmd.h"

#include "zhtml/zhtml.h"
#include "zutf8/zutf8.h"

#include <stdint.h>
#include <string.h>

/* Recursion guard for nested inline constructs; deeper nesting renders
 * as literal escaped text instead of markup. */
#define ZMD_MAX_INLINE_DEPTH 16

typedef struct {
  zmd_write_fn write;
  void *ctx;
} zmd_out;

static bool out_raw(zmd_out *o, const char *s, size_t n) {
  if (n == 0)
    return true;
  return o->write(o->ctx, s, n);
}

static bool out_lit(zmd_out *o, const char *s) {
  return out_raw(o, s, strlen(s));
}

/* Escape s[0..n) through zhtml in bounded chunks: 128 source bytes
 * escape to at most 6 * 128 = 768 bytes, under the 1024-byte scratch
 * buffer, so a well-formed call can never truncate. */
static bool out_escaped(zmd_out *o, const char *s, size_t n) {
  char buf[1024];
  while (n > 0) {
    size_t chunk = n < 128 ? n : 128;
    size_t need = zhtml_escape(buf, sizeof(buf), s, chunk);
    if (need == SIZE_MAX || need >= sizeof(buf))
      return false;
    if (!out_raw(o, buf, need))
      return false;
    s += chunk;
    n -= chunk;
  }
  return true;
}

/* ---------- inline constructs ---------- */

/* Index of c in s[from..n), or n. */
static size_t find_ch(const char *s, size_t n, size_t from, char c) {
  for (size_t i = from; i < n; i++)
    if (s[i] == c)
      return i;
  return n;
}

/* Index of the next "**" in s[from..n), or n. */
static size_t find_dstar(const char *s, size_t n, size_t from) {
  for (size_t i = from; i + 1 < n; i++)
    if (s[i] == '*' && s[i + 1] == '*')
      return i;
  return n;
}

/* Case-insensitive comparison against a lowercase literal. */
static bool scheme_is(const char *u, size_t n, const char *want) {
  size_t w = strlen(want);
  if (n != w)
    return false;
  for (size_t i = 0; i < n; i++) {
    char c = u[i];
    if (c >= 'A' && c <= 'Z')
      c = (char)(c + ('a' - 'A'));
    if (c != want[i])
      return false;
  }
  return true;
}

/* URL policy (see the header): no whitespace or control bytes; a scheme
 * must be http, https, or mailto (case-insensitive); schemeless URLs
 * pass. Anything malformed fails closed. */
static bool url_ok(const char *u, size_t n) {
  for (size_t i = 0; i < n; i++) {
    unsigned char c = (unsigned char)u[i];
    if (c <= 0x20 || c == 0x7f)
      return false; /* whitespace and control bytes are never allowed */
  }
  size_t colon = n;
  for (size_t i = 0; i < n; i++) {
    char c = u[i];
    if (c == ':') {
      colon = i;
      break;
    }
    if (c == '/' || c == '?' || c == '#')
      break; /* a scheme must come first */
  }
  if (colon == n)
    return true; /* no scheme: relative URL */
  if (colon == 0)
    return false;
  for (size_t i = 0; i < colon; i++) {
    char c = u[i];
    bool alpha = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
    bool rest = (c >= '0' && c <= '9') || c == '+' || c == '-' || c == '.';
    if (!alpha && !(i > 0 && rest))
      return false; /* invalid scheme name: fail closed */
  }
  return scheme_is(u, colon, "http") || scheme_is(u, colon, "https") ||
         scheme_is(u, colon, "mailto");
}

/* Parse "[text](url)" with s[i] == '['. On success fills the text and
 * url spans and returns the index just past ')'; returns SIZE_MAX when
 * the construct is incomplete (n itself is a valid end position). */
static size_t parse_bracket(const char *s, size_t n, size_t i, size_t *ts,
                            size_t *te, size_t *us, size_t *ue) {
  size_t close = find_ch(s, n, i + 1, ']');
  if (close == n || close + 1 >= n || s[close + 1] != '(')
    return SIZE_MAX;
  size_t pclose = find_ch(s, n, close + 2, ')');
  if (pclose == n)
    return SIZE_MAX;
  *ts = i + 1;
  *te = close;
  *us = close + 2;
  *ue = pclose;
  return pclose + 1;
}

static bool render_inline(zmd_out *o, const char *s, size_t n, int depth) {
  if (depth > ZMD_MAX_INLINE_DEPTH)
    return out_escaped(o, s, n); /* pathological nesting: literal text */
  size_t i = 0;
  while (i < n) {
    char c = s[i];
    if (c == '`') {
      size_t j = find_ch(s, n, i + 1, '`');
      if (j == n) {
        if (!out_escaped(o, s + i, 1)) /* unclosed: literal backtick */
          return false;
        i++;
        continue;
      }
      if (!out_lit(o, "<code>") || !out_escaped(o, s + i + 1, j - i - 1) ||
          !out_lit(o, "</code>"))
        return false;
      i = j + 1;
      continue;
    }
    if (c == '*') {
      if (i + 1 < n && s[i + 1] == '*') {
        size_t j = find_dstar(s, n, i + 2);
        if (j != n) {
          if (!out_lit(o, "<strong>") ||
              !render_inline(o, s + i + 2, j - i - 2, depth + 1) ||
              !out_lit(o, "</strong>"))
            return false;
          i = j + 2;
          continue;
        }
        /* unclosed "**": one literal star, rescan the second */
        if (!out_escaped(o, s + i, 1))
          return false;
        i++;
        continue;
      }
      size_t j = find_ch(s, n, i + 1, '*');
      if (j == n) {
        if (!out_escaped(o, s + i, 1)) /* unclosed: literal star */
          return false;
        i++;
        continue;
      }
      if (!out_lit(o, "<em>") ||
          !render_inline(o, s + i + 1, j - i - 1, depth + 1) ||
          !out_lit(o, "</em>"))
        return false;
      i = j + 1;
      continue;
    }
    if (c == '!' && i + 1 < n && s[i + 1] == '[') {
      size_t ts, te, us, ue;
      size_t end = parse_bracket(s, n, i + 1, &ts, &te, &us, &ue);
      if (end == SIZE_MAX) {
        if (!out_escaped(o, s + i, 1)) /* not an image: literal '!' */
          return false;
        i++;
        continue;
      }
      if (!url_ok(s + us, ue - us)) {
        /* rejected URL: the whole construct degrades to literal text */
        if (!out_escaped(o, s + i, end - i))
          return false;
        i = end;
        continue;
      }
      if (!out_lit(o, "<img src=\"") || !out_escaped(o, s + us, ue - us) ||
          !out_lit(o, "\" alt=\"") || !out_escaped(o, s + ts, te - ts) ||
          !out_lit(o, "\">"))
        return false;
      i = end;
      continue;
    }
    if (c == '[') {
      size_t ts, te, us, ue;
      size_t end = parse_bracket(s, n, i, &ts, &te, &us, &ue);
      if (end == SIZE_MAX) {
        if (!out_escaped(o, s + i, 1)) /* not a link: literal '[' */
          return false;
        i++;
        continue;
      }
      if (!url_ok(s + us, ue - us)) {
        if (!out_escaped(o, s + i, end - i))
          return false;
        i = end;
        continue;
      }
      if (!out_lit(o, "<a href=\"") || !out_escaped(o, s + us, ue - us) ||
          !out_lit(o, "\">") ||
          !render_inline(o, s + ts, te - ts, depth + 1) ||
          !out_lit(o, "</a>"))
        return false;
      i = end;
      continue;
    }
    /* plain run up to the next candidate marker */
    size_t j = i + 1;
    while (j < n && s[j] != '`' && s[j] != '*' && s[j] != '[' &&
           s[j] != '!')
      j++;
    if (!out_escaped(o, s + i, j - i))
      return false;
    i = j;
  }
  return true;
}

/* ---------- block constructs ---------- */

/* Line helpers operate on s[0..n), one line without its '\n' (a trailing
 * '\r' was already stripped by the scanner). */

static bool is_blank(const char *s, size_t n) {
  for (size_t i = 0; i < n; i++)
    if (s[i] != ' ' && s[i] != '\t')
      return false;
  return true;
}

/* ATX heading level 1..6, or 0: column-0 '#'s followed by a space, tab,
 * or end of line. */
static int atx_level(const char *s, size_t n) {
  size_t i = 0;
  while (i < n && s[i] == '#')
    i++;
  if (i == 0 || i > 6)
    return 0;
  if (i < n && s[i] != ' ' && s[i] != '\t')
    return 0;
  return (int)i;
}

static bool is_fence(const char *s, size_t n) {
  return n >= 3 && s[0] == '`' && s[1] == '`' && s[2] == '`';
}

/* Thematic break: spaces/tabs plus at least three identical -, *, _. */
static bool is_hr(const char *s, size_t n) {
  char mark = 0;
  int count = 0;
  for (size_t i = 0; i < n; i++) {
    char c = s[i];
    if (c == ' ' || c == '\t')
      continue;
    if (c != '-' && c != '*' && c != '_')
      return false;
    if (mark == 0)
      mark = c;
    else if (c != mark)
      return false;
    count++;
  }
  return count >= 3;
}

/* Unordered item: content offset after "- " / "* ", or 0. */
static size_t ulist_off(const char *s, size_t n) {
  if (n >= 2 && (s[0] == '-' || s[0] == '*') &&
      (s[1] == ' ' || s[1] == '\t'))
    return 2;
  return 0;
}

/* Ordered item: content offset after "N. ", or 0. */
static size_t olist_off(const char *s, size_t n) {
  size_t i = 0;
  while (i < n && s[i] >= '0' && s[i] <= '9')
    i++;
  if (i == 0 || i >= n || s[i] != '.')
    return 0;
  if (i + 1 >= n || (s[i + 1] != ' ' && s[i + 1] != '\t'))
    return 0;
  return i + 2;
}

/* True when the line starts any block construct (paragraphs stop here). */
static bool starts_block(const char *s, size_t n) {
  return atx_level(s, n) > 0 || is_fence(s, n) || is_hr(s, n) ||
         (n > 0 && s[0] == '>') || ulist_off(s, n) > 0 ||
         olist_off(s, n) > 0;
}

static size_t rtrim(const char *s, size_t n) {
  while (n > 0 && (s[n - 1] == ' ' || s[n - 1] == '\t'))
    n--;
  return n;
}

typedef struct {
  const char *md;
  size_t len;
  size_t pos;
} zmd_scan;

/* Consume the next line; returns its length (no '\n', no trailing '\r')
 * and sets *off to its start. */
static size_t next_line(zmd_scan *sc, size_t *off) {
  *off = sc->pos;
  while (sc->pos < sc->len && sc->md[sc->pos] != '\n')
    sc->pos++;
  size_t end = sc->pos;
  if (sc->pos < sc->len)
    sc->pos++; /* consume the '\n' */
  if (end > *off && sc->md[end - 1] == '\r')
    end--;
  return end - *off;
}

static size_t peek_line(const zmd_scan *sc, size_t *off) {
  zmd_scan copy = *sc;
  return next_line(&copy, off);
}

/* Emit the run of '>' lines as one paragraph inside a blockquote. */
static bool render_quote(zmd_out *o, zmd_scan *sc) {
  if (!out_lit(o, "<blockquote>\n<p>"))
    return false;
  bool first = true;
  bool br = false; /* previous line ended in two spaces: hard break */
  while (sc->pos < sc->len) {
    size_t off, n = peek_line(sc, &off);
    if (n == 0 || sc->md[off] != '>')
      break;
    next_line(sc, &off);
    size_t cs = 1; /* strip '>' and one optional space */
    if (cs < n && sc->md[off + cs] == ' ')
      cs++;
    size_t ce = rtrim(sc->md + off, n);
    if (ce < cs)
      ce = cs;
    if (!first && !(br ? out_lit(o, "<br>\n") : out_lit(o, "\n")))
      return false;
    br = n - ce >= 2;
    if (!render_inline(o, sc->md + off + cs, ce - cs, 0))
      return false;
    first = false;
  }
  return out_lit(o, "</p>\n</blockquote>\n");
}

/* Emit the run of same-type list items as <ul> or <ol>. */
static bool render_list(zmd_out *o, zmd_scan *sc, bool ordered) {
  if (!out_lit(o, ordered ? "<ol>\n" : "<ul>\n"))
    return false;
  while (sc->pos < sc->len) {
    size_t off, n = peek_line(sc, &off);
    size_t cs = ordered ? olist_off(sc->md + off, n)
                        : ulist_off(sc->md + off, n);
    if (cs == 0)
      break;
    next_line(sc, &off);
    while (cs < n && (sc->md[off + cs] == ' ' || sc->md[off + cs] == '\t'))
      cs++;
    size_t ce = rtrim(sc->md + off, n);
    if (ce < cs)
      ce = cs;
    if (!out_lit(o, "<li>") ||
        !render_inline(o, sc->md + off + cs, ce - cs, 0) ||
        !out_lit(o, "</li>\n"))
      return false;
  }
  return out_lit(o, ordered ? "</ol>\n" : "</ul>\n");
}

static bool render_blocks(zmd_out *o, const char *md, size_t len) {
  zmd_scan sc = { md, len, 0 };
  while (sc.pos < sc.len) {
    size_t off, n = peek_line(&sc, &off);
    const char *s = md + off;

    if (is_blank(s, n)) {
      next_line(&sc, &off);
      continue;
    }

    /* fenced code: literal escaped lines until a closing fence or EOF
     * (an unclosed fence runs to end of input, fail-visible) */
    if (is_fence(s, n)) {
      next_line(&sc, &off); /* opening fence; info string ignored */
      if (!out_lit(o, "<pre><code>"))
        return false;
      while (sc.pos < sc.len) {
        n = peek_line(&sc, &off);
        if (is_fence(md + off, n)) {
          next_line(&sc, &off);
          break;
        }
        next_line(&sc, &off);
        if (!out_escaped(o, md + off, n) || !out_lit(o, "\n"))
          return false;
      }
      if (!out_lit(o, "</code></pre>\n"))
        return false;
      continue;
    }

    int lvl = atx_level(s, n);
    if (lvl > 0) {
      next_line(&sc, &off);
      size_t cs = (size_t)lvl, ce = rtrim(s, n);
      while (cs < ce && (s[cs] == ' ' || s[cs] == '\t'))
        cs++;
      /* optional closing sequence: trailing '#'s after whitespace */
      if (ce > cs && s[ce - 1] == '#') {
        size_t k = ce;
        while (k > cs && s[k - 1] == '#')
          k--;
        if (k == cs || s[k - 1] == ' ' || s[k - 1] == '\t')
          ce = rtrim(s, k);
      }
      const char open[4] = { '<', 'h', (char)('0' + lvl), '>' };
      const char close[6] = { '<', '/', 'h', (char)('0' + lvl), '>', '\n' };
      if (!out_raw(o, open, 4) || !render_inline(o, s + cs, ce - cs, 0) ||
          !out_raw(o, close, 6))
        return false;
      continue;
    }

    if (is_hr(s, n)) {
      next_line(&sc, &off);
      if (!out_lit(o, "<hr>\n"))
        return false;
      continue;
    }

    if (s[0] == '>') {
      if (!render_quote(o, &sc))
        return false;
      continue;
    }

    if (ulist_off(s, n) > 0) {
      if (!render_list(o, &sc, false))
        return false;
      continue;
    }

    if (olist_off(s, n) > 0) {
      if (!render_list(o, &sc, true))
        return false;
      continue;
    }

    /* paragraph: consecutive lines that start no block construct */
    if (!out_lit(o, "<p>"))
      return false;
    bool first = true;
    bool br = false;
    while (sc.pos < sc.len) {
      n = peek_line(&sc, &off);
      if (is_blank(md + off, n) || starts_block(md + off, n))
        break;
      next_line(&sc, &off);
      size_t ce = rtrim(md + off, n);
      if (!first && !(br ? out_lit(o, "<br>\n") : out_lit(o, "\n")))
        return false;
      br = n - ce >= 2;
      if (!render_inline(o, md + off, ce, 0))
        return false;
      first = false;
    }
    if (!out_lit(o, "</p>\n"))
      return false;
  }
  return true;
}

bool zmd_render_html(const char *md, size_t md_len, zmd_write_fn write,
                     void *ctx) {
  if (!write || (!md && md_len > 0))
    return false;
  if (md_len > ZMD_MAX_INPUT)
    return false; /* checked before md is dereferenced */
  if (md_len > 0 && !zutf8_validate_n(md, md_len))
    return false;
  zmd_out o = { write, ctx };
  return render_blocks(&o, md, md_len);
}
