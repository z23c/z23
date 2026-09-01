/* ztoml — bounded TOML-subset pull parser. See include/ztoml/ztoml.h. */
#include "ztoml/ztoml.h"

#include <errno.h>
#include <limits.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>

const char *ztoml_err_str(ztoml_err e) {
  switch (e) {
  case ZTOML_OK: return "ok";
  case ZTOML_ERR_ARG: return "invalid argument";
  case ZTOML_ERR_RANGE: return "bound exceeded";
  case ZTOML_ERR_SYNTAX: return "syntax error";
  case ZTOML_ERR_BADVALUE: return "invalid value";
  }
  return "unknown error";
}

static ztoml_err ztoml__fail(ztoml *t, ztoml_err e, size_t off) {
  t->err = e;
  t->err_off = off;
  return e;
}

ztoml_err ztoml_init(ztoml *t, const char *doc, size_t len) {
  if (t == NULL || (doc == NULL && len != 0)) return ZTOML_ERR_ARG;
  if (len > ZTOML_MAX) return ZTOML_ERR_RANGE;
  memset(t, 0, sizeof(*t));
  t->doc = doc;
  t->len = len;
  t->line = 1;
  t->at_line_start = 1;
  return ZTOML_OK;
}

static int ztoml__ws(char c) { return c == ' ' || c == '\t'; }

/* Skip spaces/tabs and comments. Never crosses a newline. */
static void ztoml__skip_inline(ztoml *t) {
  while (t->pos < t->len) {
    char c = t->doc[t->pos];
    if (ztoml__ws(c)) {
      t->pos++;
    } else if (c == '#') {
      while (t->pos < t->len && t->doc[t->pos] != '\n') t->pos++;
    } else {
      break;
    }
  }
}

static int ztoml__bare_key_char(char c) {
  return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
         (c >= '0' && c <= '9') || c == '_' || c == '-';
}

/* Scan a (possibly dotted) bare key or section path starting at
 * t->pos. Returns length, 0 when the first char is invalid. Advances
 * t->pos past the path. Errors on over-long paths. */
static size_t ztoml__scan_path(ztoml *t, ztoml_err *err) {
  size_t start = t->pos, n = 0;
  int need_key = 1;
  *err = ZTOML_OK;
  while (t->pos < t->len) {
    char c = t->doc[t->pos];
    if (need_key) {
      if (!ztoml__bare_key_char(c)) break;
      need_key = 0;
    } else if (c == '.') {
      need_key = 1;
    } else if (ztoml__bare_key_char(c)) {
      /* continue */
    } else {
      break;
    }
    t->pos++;
    n++;
    if (n > ZTOML_MAX_KEY) {
      *err = ztoml__fail(t, ZTOML_ERR_RANGE, start);
      return 0;
    }
  }
  if (need_key && n > 0) { /* trailing dot */
    *err = ztoml__fail(t, ZTOML_ERR_SYNTAX, t->pos - 1);
    return 0;
  }
  return n;
}

static ztoml_err ztoml__section(ztoml *t, ztoml_ev *ev) {
  size_t off = t->pos;
  size_t path_off, path_len;
  ztoml_err e;
  t->pos++; /* '[' */
  if (t->pos < t->len && t->doc[t->pos] == '[')
    return ztoml__fail(t, ZTOML_ERR_SYNTAX, off); /* [[...]] unsupported */
  ztoml__skip_inline(t);
  path_off = t->pos;
  path_len = ztoml__scan_path(t, &e);
  if (e != ZTOML_OK) return e;
  if (path_len == 0) return ztoml__fail(t, ZTOML_ERR_SYNTAX, path_off);
  ztoml__skip_inline(t);
  if (t->pos >= t->len || t->doc[t->pos] != ']')
    return ztoml__fail(t, ZTOML_ERR_SYNTAX, t->pos);
  t->pos++;
  ev->kind = ZTOML_EV_SECTION;
  ev->ptr = t->doc + path_off;
  ev->len = path_len;
  return ZTOML_OK;
}

static ztoml_err ztoml__basic_string(ztoml *t, ztoml_ev *ev) {
  size_t start = t->pos;
  size_t content = start + 1, i;
  (void)start;
  for (i = content; i < t->len; i++) {
    char c = t->doc[i];
    if (c == '\n') return ztoml__fail(t, ZTOML_ERR_SYNTAX, i);
    if (c == '\\') {
      i++;
      if (i >= t->len) break;
      continue;
    }
    if (c == '"') {
      ev->kind = ZTOML_EV_VALUE;
      ev->vtype = ZTOML_V_STR_BASIC;
      ev->ptr = t->doc + content;
      ev->len = i - content;
      t->pos = i + 1;
      return ZTOML_OK;
    }
  }
  return ztoml__fail(t, ZTOML_ERR_SYNTAX, start); /* unterminated */
}

static ztoml_err ztoml__lit_string(ztoml *t, ztoml_ev *ev) {
  size_t start = t->pos;
  size_t content = start + 1, i;
  for (i = content; i < t->len; i++) {
    char c = t->doc[i];
    if (c == '\n') return ztoml__fail(t, ZTOML_ERR_SYNTAX, i);
    if (c == '\'') {
      ev->kind = ZTOML_EV_VALUE;
      ev->vtype = ZTOML_V_STR_LIT;
      ev->ptr = t->doc + content;
      ev->len = i - content;
      t->pos = i + 1;
      return ZTOML_OK;
    }
  }
  return ztoml__fail(t, ZTOML_ERR_SYNTAX, start);
}

/* Copy a numeric token minus underscores into buf (cap bounded).
 * Returns length, SIZE_MAX when over cap. */
static size_t ztoml__strip_us(const char *p, size_t n, char *buf,
                              size_t cap) {
  size_t i, o = 0;
  for (i = 0; i < n; i++) {
    if (p[i] == '_') continue;
    if (o + 1 >= cap) return SIZE_MAX;
    buf[o++] = p[i];
  }
  buf[o] = '\0';
  return o;
}

/* Validate underscore placement: no leading/trailing/double, and a
 * digit on each side. */
static int ztoml__us_ok(const char *p, size_t n) {
  size_t i;
  for (i = 0; i < n; i++)
    if (p[i] == '_') {
      if (i == 0 || i + 1 == n) return 0;
      if (p[i - 1] == '_' || p[i + 1] == '_') return 0;
    }
  return 1;
}

static ztoml_err ztoml__number(ztoml *t, ztoml_ev *ev, const char *p,
                               size_t n) {
  char buf[80];
  size_t m;
  int neg = 0, is_float = 0, base = 10;
  size_t i = 0;
  if (!ztoml__us_ok(p, n))
    return ztoml__fail(t, ZTOML_ERR_SYNTAX, t->pos - n);
  if (i < n && (p[i] == '+' || p[i] == '-')) {
    neg = p[i] == '-';
    i++;
  }
  /* inf / nan */
  if (n - i == 3 && (memcmp(p + i, "inf", 3) == 0 ||
                     memcmp(p + i, "nan", 3) == 0)) {
    ev->kind = ZTOML_EV_VALUE;
    ev->vtype = ZTOML_V_FLOAT;
    if (p[i] == 'i') ev->f64 = neg ? -INFINITY : INFINITY;
    else ev->f64 = neg ? -NAN : NAN;
    return ZTOML_OK;
  }
  if (i + 1 < n && p[i] == '0' &&
      (p[i + 1] == 'x' || p[i + 1] == 'o' || p[i + 1] == 'b')) {
    char c = p[i + 1];
    base = c == 'x' ? 16 : c == 'o' ? 8 : 2;
    if (neg) return ztoml__fail(t, ZTOML_ERR_SYNTAX, t->pos - n);
    if (n - (i + 2) == 0)
      return ztoml__fail(t, ZTOML_ERR_SYNTAX, t->pos - n);
  }
  if (base == 10) {
    size_t j;
    for (j = i; j < n; j++) {
      char c = p[j];
      if (c == '.' || c == 'e' || c == 'E') is_float = 1;
    }
    /* TOML: no leading zeros ("01", "01.5", "0_0" are invalid), and a
     * float needs digits on both sides of '.' ("5." / ".5" invalid). */
    if (i + 1 < n && p[i] == '0' &&
        ((p[i + 1] >= '0' && p[i + 1] <= '9') || p[i + 1] == '_'))
      return ztoml__fail(t, ZTOML_ERR_SYNTAX, t->pos - n + i);
    if (i < n && p[i] == '.')
      return ztoml__fail(t, ZTOML_ERR_SYNTAX, t->pos - n + i);
  }
  m = ztoml__strip_us(p, n, buf, sizeof(buf));
  if (m == SIZE_MAX)
    return ztoml__fail(t, ZTOML_ERR_RANGE, t->pos - n);
  if (is_float) {
    char *end = NULL;
    double v;
    errno = 0;
    v = strtod(buf, &end);
    if (end == buf || *end != '\0')
      return ztoml__fail(t, ZTOML_ERR_SYNTAX, t->pos - n);
    if (errno == ERANGE && (v == HUGE_VAL || v == -HUGE_VAL))
      return ztoml__fail(t, ZTOML_ERR_BADVALUE, t->pos - n);
    /* TOML requires digits around '.' and after e; enforce basic
     * shape: ".5" and "5." and "1e" are rejected by strtod's end
     * pointer only partially — check the original token. */
    {
      size_t j;
      for (j = 0; j + 1 < n; j++) {
        if (p[j] == '.' &&
            !(p[j + 1] >= '0' && p[j + 1] <= '9'))
          return ztoml__fail(t, ZTOML_ERR_SYNTAX, t->pos - n + j);
      }
      if (n > 0 && p[n - 1] == '.')
        return ztoml__fail(t, ZTOML_ERR_SYNTAX, t->pos - 1);
    }
    ev->kind = ZTOML_EV_VALUE;
    ev->vtype = ZTOML_V_FLOAT;
    ev->f64 = v;
    return ZTOML_OK;
  }
  /* Integer. */
  {
    const char *digits = buf;
    char *end = NULL;
    unsigned long long u;
    if (base != 10) digits += 2;
    if (*digits == '\0')
      return ztoml__fail(t, ZTOML_ERR_SYNTAX, t->pos - n);
    if (base == 10 && *digits == '+') digits++;
    errno = 0;
    if (neg) {
      long long v = strtoll(buf, &end, base);
      if (errno == ERANGE || end == buf || *end != '\0')
        return ztoml__fail(t, errno == ERANGE ? ZTOML_ERR_BADVALUE
                                              : ZTOML_ERR_SYNTAX,
                           t->pos - n);
      ev->i64 = (int64_t)v;
    } else {
      u = strtoull(digits, &end, base);
      if (errno == ERANGE || end == digits || *end != '\0' ||
          u > (unsigned long long)INT64_MAX)
        return ztoml__fail(t, errno == ERANGE ||
                                  u > (unsigned long long)INT64_MAX
                              ? ZTOML_ERR_BADVALUE
                              : ZTOML_ERR_SYNTAX,
                           t->pos - n);
      ev->i64 = (int64_t)u;
    }
    ev->kind = ZTOML_EV_VALUE;
    ev->vtype = ZTOML_V_INT;
    return ZTOML_OK;
  }
}

static int ztoml__value_char(char c) {
  /* Characters that may appear inside an unquoted scalar token. */
  return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
         (c >= '0' && c <= '9') || c == '+' || c == '-' || c == '.' ||
         c == '_' || c == ':';
}

static ztoml_err ztoml__value(ztoml *t, ztoml_ev *ev) {
  char c;
  ztoml__skip_inline(t);
  if (t->pos >= t->len)
    return ztoml__fail(t, ZTOML_ERR_SYNTAX, t->pos);
  c = t->doc[t->pos];
  if (c == '"') return ztoml__basic_string(t, ev);
  if (c == '\'') return ztoml__lit_string(t, ev);
  if (c == '[') {
    if (t->arr_depth >= ZTOML_MAX_DEPTH)
      return ztoml__fail(t, ZTOML_ERR_RANGE, t->pos);
    t->pos++;
    t->arr_first[t->arr_depth] = 1;
    t->arr_after_value[t->arr_depth] = 0;
    t->arr_depth++;
    ev->kind = ZTOML_EV_ARR_OPEN;
    return ZTOML_OK;
  }
  /* bare token */
  {
    size_t start = t->pos, n;
    while (t->pos < t->len && ztoml__value_char(t->doc[t->pos])) t->pos++;
    n = t->pos - start;
    if (n == 0) return ztoml__fail(t, ZTOML_ERR_SYNTAX, start);
    if (n == 4 && memcmp(t->doc + start, "true", 4) == 0) {
      ev->kind = ZTOML_EV_VALUE;
      ev->vtype = ZTOML_V_BOOL;
      ev->boolean = 1;
      return ZTOML_OK;
    }
    if (n == 5 && memcmp(t->doc + start, "false", 5) == 0) {
      ev->kind = ZTOML_EV_VALUE;
      ev->vtype = ZTOML_V_BOOL;
      ev->boolean = 0;
      return ZTOML_OK;
    }
    /* A date-shaped token (contains ':') is unsupported subset. */
    if (memchr(t->doc + start, ':', n) != NULL)
      return ztoml__fail(t, ZTOML_ERR_SYNTAX, start);
    return ztoml__number(t, ev, t->doc + start, n);
  }
}

static ztoml_err ztoml__pair(ztoml *t, ztoml_ev *ev) {
  /* At a bare key: emit KEY, expect '=' on the following call. */
  ztoml_err e;
  size_t key_off = t->pos, key_len;
  key_len = ztoml__scan_path(t, &e);
  if (e != ZTOML_OK) return e;
  if (key_len == 0) return ztoml__fail(t, ZTOML_ERR_SYNTAX, key_off);
  ztoml__skip_inline(t);
  if (t->pos >= t->len || t->doc[t->pos] != '=')
    return ztoml__fail(t, ZTOML_ERR_SYNTAX, t->pos);
  t->pos++;
  t->pair_pending = 1;
  ev->kind = ZTOML_EV_KEY;
  ev->ptr = t->doc + key_off;
  ev->len = key_len;
  return ZTOML_OK;
}

ztoml_err ztoml_next(ztoml *t, ztoml_ev *ev) {
  if (t == NULL || ev == NULL) return ZTOML_ERR_ARG;
  memset(ev, 0, sizeof(*ev));
  if (t->err != ZTOML_OK) return t->err;

  /* Continuation of a pair: the value follows the '='. */
  if (t->pair_pending) {
    ztoml_err e;
    t->pair_pending = 0;
    e = ztoml__value(t, ev);
    if (e == ZTOML_OK && t->arr_depth > 0 && ev->kind == ZTOML_EV_VALUE)
      t->arr_after_value[t->arr_depth - 1] = 1;
    return e;
  }

  /* Inside an array: separators, elements, close. Newlines allowed. */
  if (t->arr_depth > 0) {
    for (;;) {
      char c;
      if (t->pos >= t->len)
        return ztoml__fail(t, ZTOML_ERR_SYNTAX, t->len); /* unclosed [ */
      c = t->doc[t->pos];
      if (c == '\n') {
        t->pos++;
        t->line++;
        continue;
      }
      if (c == ',') {
        if (!t->arr_after_value[t->arr_depth - 1])
          return ztoml__fail(t, ZTOML_ERR_SYNTAX, t->pos);
        t->pos++;
        t->arr_after_value[t->arr_depth - 1] = 0;
        t->arr_first[t->arr_depth - 1] = 0;
        continue;
      }
      if (c == ']') {
        t->pos++;
        t->arr_depth--;
        if (t->arr_depth > 0)
          t->arr_after_value[t->arr_depth - 1] = 1; /* nested done */
        ev->kind = ZTOML_EV_ARR_CLOSE;
        return ZTOML_OK;
      }
      if (ztoml__ws(c) || c == '#') {
        ztoml__skip_inline(t);
        continue;
      }
      if (t->arr_after_value[t->arr_depth - 1])
        return ztoml__fail(t, ZTOML_ERR_SYNTAX, t->pos); /* missing , */
      {
        ztoml_err e = ztoml__value(t, ev);
        if (e == ZTOML_OK && ev->kind == ZTOML_EV_VALUE)
          t->arr_after_value[t->arr_depth - 1] = 1;
        return e;
      }
    }
  }

  /* Top level. */
  for (;;) {
    char c;
    if (t->pos >= t->len) {
      ev->kind = ZTOML_EV_DONE;
      return ZTOML_OK;
    }
    c = t->doc[t->pos];
    if (c == '\n') {
      t->pos++;
      t->line++;
      continue;
    }
    if (ztoml__ws(c) || c == '#') {
      ztoml__skip_inline(t);
      continue;
    }
    if (c == '[') return ztoml__section(t, ev);
    /* After a pair value, the next token must start a new line. */
    if (ztoml__bare_key_char(c)) {
      /* Bare keys only at line start: TOML pair per line. We accept
       * leniently: a pair may follow ws after a newline only. Enforce
       * by checking previous non-ws char was newline or doc start. */
      size_t scan = t->pos;
      int line_start = 1;
      while (scan > 0) {
        char pc = t->doc[scan - 1];
        if (pc == '\n') break;
        if (ztoml__ws(pc)) {
          scan--;
          continue;
        }
        line_start = 0;
        break;
      }
      if (!line_start)
        return ztoml__fail(t, ZTOML_ERR_SYNTAX, t->pos);
      return ztoml__pair(t, ev);
    }
    return ztoml__fail(t, ZTOML_ERR_SYNTAX, t->pos);
  }
}

/* ---- string decoding ------------------------------------------------------ */

static int ztoml__hexval(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  return -1;
}

/* Emit one codepoint as UTF-8 into the measuring writer. */
static size_t ztoml__emit_cp(uint32_t cp, char *dst, size_t cap,
                             size_t len) {
  unsigned char tmp[4];
  size_t n, i;
  if (cp < 0x80) {
    tmp[0] = (unsigned char)cp;
    n = 1;
  } else if (cp < 0x800) {
    tmp[0] = (unsigned char)(0xC0 | (cp >> 6));
    tmp[1] = (unsigned char)(0x80 | (cp & 0x3F));
    n = 2;
  } else if (cp < 0x10000) {
    tmp[0] = (unsigned char)(0xE0 | (cp >> 12));
    tmp[1] = (unsigned char)(0x80 | ((cp >> 6) & 0x3F));
    tmp[2] = (unsigned char)(0x80 | (cp & 0x3F));
    n = 3;
  } else {
    tmp[0] = (unsigned char)(0xF0 | (cp >> 18));
    tmp[1] = (unsigned char)(0x80 | ((cp >> 12) & 0x3F));
    tmp[2] = (unsigned char)(0x80 | ((cp >> 6) & 0x3F));
    tmp[3] = (unsigned char)(0x80 | (cp & 0x3F));
    n = 4;
  }
  for (i = 0; i < n; i++) {
    if (dst != NULL && len + 1 < cap) dst[len] = (char)tmp[i];
    len++;
  }
  return len;
}

size_t ztoml_str_decode(const char *ptr, size_t len, char *dst,
                        size_t cap) {
  size_t i = 0, out = 0;
  if (ptr == NULL && len != 0) return SIZE_MAX;
  while (i < len) {
    char c = ptr[i];
    if (c != '\\') {
      if (dst != NULL && out + 1 < cap) dst[out] = c;
      out++;
      i++;
      continue;
    }
    i++;
    if (i >= len) return SIZE_MAX;
    c = ptr[i++];
    switch (c) {
    case '"': case '\\': {
      if (dst != NULL && out + 1 < cap) dst[out] = c;
      out++;
      break;
    }
    case 'b': if (dst != NULL && out + 1 < cap) dst[out] = '\b'; out++; break;
    case 't': if (dst != NULL && out + 1 < cap) dst[out] = '\t'; out++; break;
    case 'n': if (dst != NULL && out + 1 < cap) dst[out] = '\n'; out++; break;
    case 'f': if (dst != NULL && out + 1 < cap) dst[out] = '\f'; out++; break;
    case 'r': if (dst != NULL && out + 1 < cap) dst[out] = '\r'; out++; break;
    case 'u': case 'U': {
      int ndigits = c == 'u' ? 4 : 8;
      uint32_t cp = 0;
      int k;
      if (i + (size_t)ndigits > len) return SIZE_MAX;
      for (k = 0; k < ndigits; k++) {
        int v = ztoml__hexval(ptr[i + (size_t)k]);
        if (v < 0) return SIZE_MAX;
        cp = (cp << 4) | (uint32_t)v;
      }
      i += (size_t)ndigits;
      if (cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF))
        return SIZE_MAX; /* lone surrogate / out of range */
      out = ztoml__emit_cp(cp, dst, cap, out);
      break;
    }
    default:
      return SIZE_MAX; /* unknown escape */
    }
  }
  if (dst != NULL && cap > 0) dst[out < cap ? out : cap - 1] = '\0';
  return out;
}
