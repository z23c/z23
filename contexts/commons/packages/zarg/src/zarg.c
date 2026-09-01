/* zarg — bounded argv parser. See include/zarg/zarg.h. */
#include "zarg/zarg.h"

#include <errno.h>
#include <limits.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>

static size_t zarg__nlen(const char *s, size_t cap) {
  size_t n = 0;
  while (n < cap && s[n] != '\0') n++;
  return n;
}

const char *zarg_err_str(zarg_err e) {
  switch (e) {
  case ZARG_OK: return "ok";
  case ZARG_ERR_ARG: return "invalid argument";
  case ZARG_ERR_RANGE: return "bound exceeded";
  case ZARG_ERR_UNKNOWN: return "unknown option";
  case ZARG_ERR_MISSING: return "missing option value";
  case ZARG_ERR_BADVALUE: return "invalid option value";
  case ZARG_ERR_USAGE: return "invalid spec table";
  }
  return "unknown error";
}

static int zarg__long_name_ok(const char *s) {
  size_t n, i;
  if (s == NULL) return 0;
  n = zarg__nlen(s, ZARG_MAX_NAME + 1);
  if (n == 0 || n > ZARG_MAX_NAME) return 0;
  for (i = 0; i < n; i++) {
    char c = s[i];
    int alnum = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                (c >= '0' && c <= '9');
    if (!alnum && c != '-' && c != '_') return 0;
    if (i == 0 && !alnum) return 0;
  }
  return 1;
}

static int zarg__short_name_ok(char c) {
  if (c == 0) return 1; /* absent */
  if (c == '-') return 0;
  return c >= 33 && c <= 126;
}

static zarg_err zarg__spec_validate(const zarg_opt *spec, size_t n) {
  size_t i, j;
  if (spec == NULL && n != 0) return ZARG_ERR_ARG;
  if (n > ZARG_MAX_SPEC) return ZARG_ERR_RANGE;
  for (i = 0; i < n; i++) {
    const zarg_opt *o = &spec[i];
    if (o->short_name == 0 && o->long_name == NULL) return ZARG_ERR_USAGE;
    if (!zarg__short_name_ok(o->short_name)) return ZARG_ERR_USAGE;
    if (o->long_name != NULL && !zarg__long_name_ok(o->long_name))
      return ZARG_ERR_USAGE;
    if (o->type < ZARG_BOOL || o->type > ZARG_F64) return ZARG_ERR_USAGE;
    for (j = i + 1; j < n; j++) {
      if (o->long_name != NULL && spec[j].long_name != NULL &&
          strcmp(o->long_name, spec[j].long_name) == 0)
        return ZARG_ERR_USAGE;
    }
  }
  return ZARG_OK;
}

zarg_err zarg_init(zarg_parser *p, const zarg_opt *spec, size_t spec_count,
                   int argc, char **argv) {
  zarg_err e;
  if (p == NULL || argv == NULL || argc < 0) return ZARG_ERR_ARG;
  if ((uint64_t)(unsigned)argc > ZARG_MAX_ARGS) return ZARG_ERR_RANGE;
  e = zarg__spec_validate(spec, spec_count);
  if (e != ZARG_OK) return e;
  memset(p, 0, sizeof(*p));
  p->spec = spec;
  p->spec_count = spec_count;
  p->argc = argc;
  p->argv = argv;
  p->next = 1; /* skip program name */
  return ZARG_OK;
}

zarg_err zarg_conv_i64(const char *s, int64_t *out) {
  char *end = NULL;
  long long v;
  if (s == NULL || out == NULL) return ZARG_ERR_ARG;
  /* Reject leading whitespace (strtoll would skip it) and empty. */
  if (*s != '+' && *s != '-' && (*s < '0' || *s > '9'))
    return ZARG_ERR_BADVALUE;
  errno = 0;
  v = strtoll(s, &end, 10);
  if (errno == ERANGE || end == s || *end != '\0') return ZARG_ERR_BADVALUE;
  *out = (int64_t)v;
  return ZARG_OK;
}

zarg_err zarg_conv_u64(const char *s, uint64_t *out) {
  char *end = NULL;
  unsigned long long v;
  if (s == NULL || out == NULL) return ZARG_ERR_ARG;
  if (*s != '+' && (*s < '0' || *s > '9')) return ZARG_ERR_BADVALUE;
  errno = 0;
  v = strtoull(s, &end, 10);
  if (errno == ERANGE || end == s || *end != '\0') return ZARG_ERR_BADVALUE;
  *out = (uint64_t)v;
  return ZARG_OK;
}

zarg_err zarg_conv_f64(const char *s, double *out) {
  char *end = NULL;
  double v;
  if (s == NULL || out == NULL) return ZARG_ERR_ARG;
  /* Reject leading whitespace (strtod would skip it) and empty. */
  if (*s == '\0' || *s == ' ' || *s == '\t' || *s == '\n' || *s == '\r' ||
      *s == '\f' || *s == '\v')
    return ZARG_ERR_BADVALUE;
  errno = 0;
  v = strtod(s, &end);
  if (end == s || *end != '\0') return ZARG_ERR_BADVALUE;
  if (errno == ERANGE && (v == HUGE_VAL || v == -HUGE_VAL))
    return ZARG_ERR_BADVALUE; /* overflow; underflow to 0/denormal is fine */
  *out = v;
  return ZARG_OK;
}

/* Find spec index for a short name; SIZE_MAX if absent. */
static size_t zarg__find_short(const zarg_parser *p, char c) {
  size_t i;
  for (i = 0; i < p->spec_count; i++)
    if (p->spec[i].short_name == c && c != 0) return i;
  return SIZE_MAX;
}

/* Find spec index for a long name of length n; SIZE_MAX if absent. */
static size_t zarg__find_long(const zarg_parser *p, const char *s, size_t n) {
  size_t i;
  if (n == 0 || n > ZARG_MAX_NAME) return SIZE_MAX;
  for (i = 0; i < p->spec_count; i++) {
    const char *ln = p->spec[i].long_name;
    if (ln != NULL && strlen(ln) == n && memcmp(ln, s, n) == 0) return i;
  }
  return SIZE_MAX;
}

/* Fill converted fields for a value-taking option. */
static zarg_err zarg__convert(const zarg_opt *o, const char *value,
                              zarg_item *it) {
  switch (o->type) {
  case ZARG_BOOL: it->value = NULL; return ZARG_OK;
  case ZARG_STR: it->value = value; return ZARG_OK;
  case ZARG_I64:
    it->value = value;
    return zarg_conv_i64(value, &it->i64);
  case ZARG_U64:
    it->value = value;
    return zarg_conv_u64(value, &it->u64);
  case ZARG_F64:
    it->value = value;
    return zarg_conv_f64(value, &it->f64);
  }
  return ZARG_ERR_USAGE;
}

static zarg_err zarg__fail(zarg_parser *p, zarg_err e, size_t index) {
  p->err = e;
  p->err_index = index;
  return e;
}

/* Consume a value for spec entry `si`. `inline_value` is non-NULL when
 * the value was glued to the token (-ofile, --out=file); otherwise the
 * next argv entry is taken. */
static zarg_err zarg__take_value(zarg_parser *p, size_t si,
                                 const char *inline_value, zarg_item *it) {
  const zarg_opt *o = &p->spec[si];
  const char *value = inline_value;
  if (o->type == ZARG_BOOL) {
    it->kind = ZARG_ITEM_OPT;
    it->spec_index = si;
    it->value = NULL;
    return ZARG_OK;
  }
  if (value == NULL) {
    if (p->next >= (size_t)p->argc)
      return zarg__fail(p, ZARG_ERR_MISSING, p->next - 1);
    value = p->argv[p->next++];
    if (value == NULL)
      return zarg__fail(p, ZARG_ERR_ARG, p->next - 1);
  }
  it->kind = ZARG_ITEM_OPT;
  it->spec_index = si;
  {
    zarg_err e = zarg__convert(o, value, it);
    if (e != ZARG_OK)
      return zarg__fail(p, e, value == inline_value ? p->next : p->next - 1);
  }
  return ZARG_OK;
}

static zarg_err zarg__long(zarg_parser *p, const char *tok, size_t tok_index,
                           zarg_item *it) {
  const char *eq = strchr(tok, '=');
  size_t nlen = eq != NULL ? (size_t)(eq - tok) : strlen(tok);
  size_t si = zarg__find_long(p, tok, nlen);
  if (nlen > ZARG_MAX_NAME) return zarg__fail(p, ZARG_ERR_RANGE, tok_index);
  if (si == SIZE_MAX) return zarg__fail(p, ZARG_ERR_UNKNOWN, tok_index);
  if (p->spec[si].type == ZARG_BOOL && eq != NULL)
    return zarg__fail(p, ZARG_ERR_BADVALUE, tok_index);
  return zarg__take_value(p, si, eq != NULL ? eq + 1 : NULL, it);
}

/* Parse a short bundle starting at p->tail (points past '-'). Emits one
 * option per call; keeps the remainder in p->tail. */
static zarg_err zarg__short(zarg_parser *p, size_t tok_index, zarg_item *it) {
  char c = *p->tail;
  size_t si = zarg__find_short(p, c);
  if (si == SIZE_MAX) return zarg__fail(p, ZARG_ERR_UNKNOWN, tok_index);
  p->tail++;
  if (p->spec[si].type == ZARG_BOOL) {
    zarg_err e = zarg__take_value(p, si, NULL, it);
    if (*p->tail == '\0') p->tail = NULL;
    return e;
  }
  /* Value-taking: glued remainder wins, else next argv. */
  {
    const char *inline_value = *p->tail != '\0' ? p->tail : NULL;
    p->tail = NULL;
    return zarg__take_value(p, si, inline_value, it);
  }
}

zarg_err zarg_next(zarg_parser *p, zarg_item *it) {
  if (p == NULL || it == NULL) return ZARG_ERR_ARG;
  memset(it, 0, sizeof(*it));
  it->spec_index = SIZE_MAX;
  if (p->err != ZARG_OK) return p->err;

  /* Pending bundle tail? */
  if (p->tail != NULL) return zarg__short(p, p->next - 1, it);

  while (p->next < (size_t)p->argc) {
    const char *tok = p->argv[p->next];
    size_t tok_index = p->next;
    if (tok == NULL) return zarg__fail(p, ZARG_ERR_ARG, tok_index);
    p->next++;
    if (!p->opts_done && tok[0] == '-' && tok[1] != '\0') {
      if (tok[1] == '-') {
        if (tok[2] == '\0') {
          p->opts_done = 1;
          continue; /* "--": skip, end options */
        }
        return zarg__long(p, tok + 2, tok_index, it);
      }
      p->tail = tok + 1;
      {
        zarg_err e = zarg__short(p, tok_index, it);
        return e;
      }
    }
    /* Positional (also "-" and everything after "--"). */
    it->kind = ZARG_ITEM_POS;
    it->text = tok;
    it->pos_index = p->pos_count++;
    return ZARG_OK;
  }
  it->kind = ZARG_ITEM_END;
  return ZARG_OK;
}

size_t zarg_usage(const zarg_opt *spec, size_t spec_count, const char *prog,
                  char *buf, size_t cap) {
  /* Append-with-measure writer; never writes past cap, always NULs. */
  size_t len = 0;
  size_t i;
  if (zarg__spec_validate(spec, spec_count) != ZARG_OK) {
    if (buf != NULL && cap > 0) buf[0] = '\0';
    return 0;
  }
#define ZARG__PUT(s)                                                    \
  do {                                                                  \
    const char *zarg__s = (s);                                          \
    while (*zarg__s != '\0') {                                          \
      if (buf != NULL && len + 1 < cap) buf[len] = *zarg__s;            \
      len++;                                                            \
      zarg__s++;                                                        \
    }                                                                   \
  } while (0)
#define ZARG__PUTC(c)                                                   \
  do {                                                                  \
    if (buf != NULL && len + 1 < cap) buf[len] = (c);                   \
    len++;                                                              \
  } while (0)
  if (prog != NULL) {
    ZARG__PUT("usage: ");
    ZARG__PUT(prog);
    ZARG__PUT(" [options]\n");
  }
  for (i = 0; i < spec_count; i++) {
    const zarg_opt *o = &spec[i];
    ZARG__PUT("  ");
    if (o->short_name != 0) {
      ZARG__PUTC('-');
      ZARG__PUTC(o->short_name);
      if (o->long_name != NULL) ZARG__PUT(", ");
    } else {
      ZARG__PUT("    ");
    }
    if (o->long_name != NULL) {
      ZARG__PUT("--");
      ZARG__PUT(o->long_name);
    }
    switch (o->type) {
    case ZARG_STR: ZARG__PUT(" <str>"); break;
    case ZARG_I64: ZARG__PUT(" <int>"); break;
    case ZARG_U64: ZARG__PUT(" <uint>"); break;
    case ZARG_F64: ZARG__PUT(" <float>"); break;
    case ZARG_BOOL: break;
    }
    if (o->help != NULL) {
      ZARG__PUT("\t");
      ZARG__PUT(o->help);
    }
    ZARG__PUTC('\n');
  }
  if (buf != NULL && cap > 0) buf[len < cap ? len : cap - 1] = '\0';
#undef ZARG__PUT
#undef ZARG__PUTC
  return len;
}
