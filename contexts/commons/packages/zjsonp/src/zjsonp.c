/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: bounded RFC 8259 pull parser (see the header). */
#include "zjsonp/zjsonp.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "zutf8/zutf8.h"

void zjsonp_init(zjsonp *p, const char *text, size_t len) {
  if (!p)
    return;
  memset(p, 0, sizeof(*p));
  p->text = text;
  p->len = text ? len : 0;
}

size_t zjsonp_pos(const zjsonp *p) { return p ? p->pos : 0; }

const char *zjsonp_status_name(zjsonp_status st) {
  switch (st) {
  case ZJRP_OK: return "ok";
  case ZJRP_DONE: return "done";
  case ZJRP_SYNTAX: return "syntax";
  case ZJRP_DEPTH: return "depth";
  }
  return "unknown";
}

static bool is_ws(char c) {
  return c == ' ' || c == '\t' || c == '\n' || c == '\r';
}

static void skip_ws(zjsonp *p) {
  while (p->pos < p->len && is_ws(p->text[p->pos]))
    p->pos++;
}

/* Scan a string whose opening quote is at pos. On success returns
 * true, sets off/len to the raw payload between the quotes, and
 * leaves pos past the closing quote. Raw payload bytes must be
 * well-formed UTF-8 with no raw control bytes; escapes must be
 * well-formed (\uXXXX needs four hex digits; the escaped set is
 * exactly "\"\\/bfnrtu"). */
static bool scan_string(zjsonp *p, size_t *off, size_t *len) {
  size_t i = p->pos + 1;
  size_t start = i;
  while (i < p->len) {
    unsigned char c = (unsigned char)p->text[i];
    if (c == '"') {
      *off = start;
      *len = i - start;
      p->pos = i + 1;
      return zutf8_validate_n(p->text + start, i - start);
    }
    if (c == '\\') {
      if (i + 1 >= p->len)
        return false;
      char e = p->text[i + 1];
      if (e == 'u') {
        if (i + 5 >= p->len)
          return false;
        for (int k = 2; k <= 5; k++) {
          char h = p->text[i + k];
          bool hex = (h >= '0' && h <= '9') || (h >= 'a' && h <= 'f') ||
                     (h >= 'A' && h <= 'F');
          if (!hex)
            return false;
        }
        i += 6;
        continue;
      }
      if (e != '"' && e != '\\' && e != '/' && e != 'b' && e != 'f' &&
          e != 'n' && e != 'r' && e != 't')
        return false;
      i += 2;
      continue;
    }
    if (c < 0x20)
      return false; /* raw control byte */
    i++;
  }
  return false; /* unterminated */
}

/* Scan a number per the strict grammar starting at pos. On success
 * advances pos past the number and returns its length, else 0 and
 * pos is unchanged. */
static size_t scan_number(zjsonp *p) {
  size_t i = p->pos;
  if (i < p->len && p->text[i] == '-')
    i++;
  if (i >= p->len)
    return 0;
  if (p->text[i] == '0') {
    i++;
  } else if (p->text[i] >= '1' && p->text[i] <= '9') {
    while (i < p->len && p->text[i] >= '0' && p->text[i] <= '9')
      i++;
  } else {
    return 0;
  }
  if (i < p->len && p->text[i] == '.') {
    i++;
    if (i >= p->len || p->text[i] < '0' || p->text[i] > '9')
      return 0;
    while (i < p->len && p->text[i] >= '0' && p->text[i] <= '9')
      i++;
  }
  if (i < p->len && (p->text[i] == 'e' || p->text[i] == 'E')) {
    i++;
    if (i < p->len && (p->text[i] == '+' || p->text[i] == '-'))
      i++;
    if (i >= p->len || p->text[i] < '0' || p->text[i] > '9')
      return 0;
    while (i < p->len && p->text[i] >= '0' && p->text[i] <= '9')
      i++;
  }
  size_t n = i - p->pos;
  p->pos = i;
  return n;
}

static bool match_literal(zjsonp *p, const char *lit, size_t n) {
  if (p->len - p->pos < n || memcmp(p->text + p->pos, lit, n) != 0)
    return false;
  p->pos += n;
  return true;
}

/* Separator handling before a value: at the top level a single value
 * is allowed; in an array a ',' separates elements; in an object the
 * value follows its key's ':'. */
static bool value_preamble(zjsonp *p) {
  if (p->depth == 0)
    return !p->top_done;
  uint32_t lvl = p->depth - 1;
  if ((p->is_array >> lvl) & 1u) {
    if (!((p->first >> lvl) & 1u)) {
      if (p->pos >= p->len || p->text[p->pos] != ',')
        return false;
      p->pos++;
      p->after_comma |= 1u << lvl;
      skip_ws(p);
    }
    return true;
  }
  if ((p->expect_key >> lvl) & 1u)
    return false; /* object key expected, not a value */
  if (p->pos >= p->len || p->text[p->pos] != ':')
    return false;
  p->pos++;
  skip_ws(p);
  return true;
}

static void value_done(zjsonp *p) {
  if (p->depth == 0) {
    p->top_done = true;
    return;
  }
  uint32_t lvl = p->depth - 1;
  p->first &= ~(1u << lvl);
  p->after_comma &= ~(1u << lvl);
  p->expect_key |= 1u << lvl; /* object: back to expecting a key */
}

zjsonp_status zjsonp_next(zjsonp *p, zjsonp_event *ev) {
  if (!p || !ev)
    return ZJRP_SYNTAX;

  skip_ws(p);

  /* Complete document: only trailing whitespace may follow. */
  if (p->top_done && p->depth == 0)
    return p->pos == p->len ? ZJRP_DONE : ZJRP_SYNTAX;

  /* Container close? */
  if (p->depth > 0 && p->pos < p->len &&
      (p->text[p->pos] == '}' || p->text[p->pos] == ']')) {
    uint32_t lvl = p->depth - 1;
    bool is_arr = (p->is_array >> lvl) & 1u;
    char c = p->text[p->pos];
    if (is_arr != (c == ']'))
      return ZJRP_SYNTAX; /* mismatched bracket */
    if ((p->after_comma >> lvl) & 1u)
      return ZJRP_SYNTAX; /* trailing comma */
    if (!is_arr && !((p->expect_key >> lvl) & 1u))
      return ZJRP_SYNTAX; /* key with no value */
    p->pos++;
    p->depth--;
    ev->kind = is_arr ? ZJRP_ARR_CLOSE : ZJRP_OBJ_CLOSE;
    ev->off = p->pos - 1;
    ev->len = 0;
    value_done(p);
    return ZJRP_OK;
  }

  /* Object key? */
  if (p->depth > 0) {
    uint32_t lvl = p->depth - 1;
    if (!((p->is_array >> lvl) & 1u) && ((p->expect_key >> lvl) & 1u)) {
      if (!((p->first >> lvl) & 1u)) {
        if (p->pos >= p->len || p->text[p->pos] != ',')
          return ZJRP_SYNTAX;
        p->pos++;
        p->after_comma |= 1u << lvl;
        skip_ws(p);
      }
      if (p->pos >= p->len || p->text[p->pos] != '"')
        return ZJRP_SYNTAX;
      size_t off = 0, len = 0;
      if (!scan_string(p, &off, &len))
        return ZJRP_SYNTAX;
      p->expect_key &= ~(1u << lvl);
      ev->kind = ZJRP_KEY;
      ev->off = off;
      ev->len = len;
      return ZJRP_OK;
    }
  }

  if (!value_preamble(p))
    return ZJRP_SYNTAX;
  if (p->pos >= p->len)
    return ZJRP_SYNTAX; /* truncated input */

  char c = p->text[p->pos];
  ev->off = p->pos;
  switch (c) {
  case '{':
  case '[': {
    if (p->depth == ZJRP_MAX_DEPTH)
      return ZJRP_DEPTH;
    uint32_t lvl = p->depth;
    p->depth++;
    if (c == '[') {
      p->is_array |= 1u << lvl;
      p->expect_key &= ~(1u << lvl);
    } else {
      p->is_array &= ~(1u << lvl);
      p->expect_key |= 1u << lvl;
    }
    p->first |= 1u << lvl;
    p->after_comma &= ~(1u << lvl);
    p->pos++;
    ev->kind = c == '[' ? ZJRP_ARR_OPEN : ZJRP_OBJ_OPEN;
    ev->len = 0;
    return ZJRP_OK;
  }
  case '"': {
    size_t off = 0, len = 0;
    if (!scan_string(p, &off, &len))
      return ZJRP_SYNTAX;
    ev->kind = ZJRP_STR;
    ev->off = off;
    ev->len = len;
    value_done(p);
    return ZJRP_OK;
  }
  case 't':
    if (!match_literal(p, "true", 4))
      return ZJRP_SYNTAX;
    ev->kind = ZJRP_BOOL;
    ev->len = 4;
    value_done(p);
    return ZJRP_OK;
  case 'f':
    if (!match_literal(p, "false", 5))
      return ZJRP_SYNTAX;
    ev->kind = ZJRP_BOOL;
    ev->len = 5;
    value_done(p);
    return ZJRP_OK;
  case 'n':
    if (!match_literal(p, "null", 4))
      return ZJRP_SYNTAX;
    ev->kind = ZJRP_NULL;
    ev->len = 4;
    value_done(p);
    return ZJRP_OK;
  default: {
    size_t n = scan_number(p);
    if (n == 0)
      return ZJRP_SYNTAX;
    ev->kind = ZJRP_NUM;
    ev->len = n;
    value_done(p);
    return ZJRP_OK;
  }
  }
}

size_t zjsonp_str_decode(const char *text, const zjsonp_event *ev,
                         char *out, size_t cap) {
  if (!text || !ev || (ev->kind != ZJRP_KEY && ev->kind != ZJRP_STR))
    return SIZE_MAX;
  size_t n = 0;
  size_t i = ev->off, end = ev->off + ev->len;
  while (i < end) {
    unsigned char c = (unsigned char)text[i];
    uint32_t cp = c;
    size_t adv = 1;
    if (c == '\\') {
      if (i + 1 >= end)
        return SIZE_MAX;
      char e = text[i + 1];
      switch (e) {
      case '"': cp = '"'; adv = 2; break;
      case '\\': cp = '\\'; adv = 2; break;
      case '/': cp = '/'; adv = 2; break;
      case 'b': cp = 0x08; adv = 2; break;
      case 'f': cp = 0x0c; adv = 2; break;
      case 'n': cp = 0x0a; adv = 2; break;
      case 'r': cp = 0x0d; adv = 2; break;
      case 't': cp = 0x09; adv = 2; break;
      case 'u': {
        if (i + 5 >= end)
          return SIZE_MAX;
        uint32_t v = 0;
        for (int k = 2; k <= 5; k++) {
          char h = text[i + k];
          v <<= 4;
          if (h >= '0' && h <= '9') v |= (uint32_t)(h - '0');
          else if (h >= 'a' && h <= 'f') v |= (uint32_t)(h - 'a' + 10);
          else if (h >= 'A' && h <= 'F') v |= (uint32_t)(h - 'A' + 10);
          else return SIZE_MAX;
        }
        adv = 6;
        if (v >= 0xd800 && v <= 0xdbff) { /* high surrogate */
          if (i + 11 >= end || text[i + 6] != '\\' ||
              text[i + 7] != 'u')
            return SIZE_MAX;
          uint32_t lo = 0;
          for (int k = 8; k <= 11; k++) {
            char h = text[i + k];
            lo <<= 4;
            if (h >= '0' && h <= '9') lo |= (uint32_t)(h - '0');
            else if (h >= 'a' && h <= 'f') lo |= (uint32_t)(h - 'a' + 10);
            else if (h >= 'A' && h <= 'F') lo |= (uint32_t)(h - 'A' + 10);
            else return SIZE_MAX;
          }
          if (lo < 0xdc00 || lo > 0xdfff)
            return SIZE_MAX;
          cp = 0x10000 + ((v - 0xd800) << 10) + (lo - 0xdc00);
          adv = 12;
        } else if (v >= 0xdc00 && v <= 0xdfff) {
          return SIZE_MAX; /* lone low surrogate */
        } else {
          cp = v;
        }
        break;
      }
      default:
        return SIZE_MAX;
      }
    }
    char enc[4];
    size_t en = zutf8_encode(cp, enc);
    if (en == 0)
      return SIZE_MAX;
    for (size_t k = 0; k < en; k++) {
      if (n < cap && out)
        out[n] = enc[k];
      n++;
    }
    i += adv;
  }
  return n;
}

bool zjsonp_num_i64(const char *text, const zjsonp_event *ev,
                    int64_t *out) {
  if (!text || !ev || ev->kind != ZJRP_NUM || !out)
    return false;
  if (ev->len == 0 || ev->len >= 24)
    return false;
  char tmp[24];
  memcpy(tmp, text + ev->off, ev->len);
  tmp[ev->len] = '\0';
  if (strchr(tmp, '.') || strchr(tmp, 'e') || strchr(tmp, 'E'))
    return false; /* integer form only */
  char *end = NULL;
  long long v = strtoll(tmp, &end, 10);
  if (!end || *end != '\0')
    return false;
  if ((long long)(int64_t)v != v)
    return false;
  /* range check: strtoll clamps on overflow; reformat to detect it */
  char back[24];
  snprintf(back, sizeof back, "%lld", v);
  if (strcmp(back, tmp) != 0)
    return false;
  *out = (int64_t)v;
  return true;
}

bool zjsonp_num_f64(const char *text, const zjsonp_event *ev,
                    double *out) {
  if (!text || !ev || ev->kind != ZJRP_NUM || !out)
    return false;
  if (ev->len == 0 || ev->len >= 64)
    return false;
  char tmp[64];
  memcpy(tmp, text + ev->off, ev->len);
  tmp[ev->len] = '\0';
  char *end = NULL;
  double v = strtod(tmp, &end);
  if (!end || *end != '\0')
    return false;
  *out = v;
  return true;
}
