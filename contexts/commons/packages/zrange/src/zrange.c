/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: semver range matching (see the header for the grammar). */
#include "zrange/zrange.h"

#include <string.h>

static bool is_ws(char c) { return c == ' ' || c == '\t'; }

static void zero(zrange *out) { memset(out, 0, sizeof(*out)); }

/* Push one comparator; false on the total bound. */
static bool push_comp(zrange *out, zrange_op op, const zsemver *v) {
  if (out->comp_count == ZRANGE_MAX_COMPARATORS)
    return false;
  zrange_comparator *c = &out->comps[out->comp_count++];
  c->op = op;
  c->version = *v;
  out->sets[out->set_count - 1].count++;
  return true;
}

/* Parse one comparator token over tok[0..tlen) and push the one or two
 * comparators it expands to (^ and ~ each add a lower AND an upper
 * bound). */
static bool push_token(zrange *out, const char *tok, size_t tlen) {
  if (!tlen)
    return false;
  zrange_op op = ZRANGE_EQ;
  size_t pos = 0;
  bool caret = false, tilde = false;
  if (tok[0] == '^') {
    caret = true;
    pos = 1;
  } else if (tok[0] == '~') {
    tilde = true;
    pos = 1;
  } else if (tok[0] == '<' || tok[0] == '>' || tok[0] == '=') {
    bool eq = tlen > 1 && tok[1] == '=';
    if (tok[0] == '<')
      op = eq ? ZRANGE_LE : ZRANGE_LT;
    else if (tok[0] == '>')
      op = eq ? ZRANGE_GE : ZRANGE_GT;
    pos = eq ? 2 : 1;
  }
  if (pos >= tlen)
    return false;
  zsemver v;
  if (!zsemver_parse_n(tok + pos, tlen - pos, &v))
    return false;
  if (!caret && !tilde)
    return push_comp(out, op, &v);

  /* Caret / tilde: lower bound >= v, upper bound per the npm tables. */
  if (!push_comp(out, ZRANGE_GE, &v))
    return false;
  zsemver up;
  memset(&up, 0, sizeof(up));
  if (caret) {
    if (v.major > 0) {
      if (v.major == UINT64_MAX)
        return false; /* overflow past the version ceiling */
      up.major = v.major + 1;
    } else if (v.minor > 0) {
      if (v.minor == UINT64_MAX)
        return false;
      up.minor = v.minor + 1;
    } else {
      if (v.patch == UINT64_MAX)
        return false;
      up.patch = v.patch + 1;
    }
  } else {
    if (v.minor == UINT64_MAX)
      return false; /* overflow */
    up.major = v.major;
    up.minor = v.minor + 1;
  }
  return push_comp(out, ZRANGE_LT, &up);
}

/* Parse into *out; false leaves *out untouched. */
static bool parse_into(const char *str, size_t len, zrange *out) {
  size_t pos = 0;
  for (;;) {
    if (out->set_count == ZRANGE_MAX_SETS)
      return false;
    zrange_set *set = &out->sets[out->set_count];
    set->start = out->comp_count;
    set->count = 0;
    out->set_count++;

    bool any = false;
    bool union_seen = false;
    while (pos < len) {
      while (pos < len && is_ws(str[pos]))
        pos++;
      if (pos == len)
        break;
      if (str[pos] == '|') {
        if (pos + 1 >= len || str[pos + 1] != '|')
          return false; /* single '|' is not the union operator */
        pos += 2;
        union_seen = true;
        break;
      }
      size_t start = pos;
      while (pos < len && !is_ws(str[pos]) && str[pos] != '|')
        pos++;
      if (!push_token(out, str + start, pos - start))
        return false;
      any = true;
    }
    if (!any)
      return false; /* empty set (leading/trailing/doubled "||") */
    if (!union_seen)
      return true; /* reached the end of input */
    /* A consumed "||" must be followed by another set; loop on. */
  }
}

bool zrange_parse_n(const char *str, size_t len, zrange *out) {
  if (!out)
    return false;
  zero(out);
  if (!str || !len)
    return false;
  if (!parse_into(str, len, out)) {
    zero(out);
    return false;
  }
  return true;
}

bool zrange_parse(const char *str, zrange *out) {
  return str && zrange_parse_n(str, strlen(str), out);
}

static bool comp_pass(const zrange_comparator *c, const zsemver *v) {
  int cmp = zsemver_compare(v, &c->version);
  switch (c->op) {
  case ZRANGE_LT: return cmp < 0;
  case ZRANGE_LE: return cmp <= 0;
  case ZRANGE_GT: return cmp > 0;
  case ZRANGE_GE: return cmp >= 0;
  case ZRANGE_EQ: return cmp == 0;
  }
  return false;
}

bool zrange_satisfies(const zrange *range, const zsemver *version) {
  if (!range || !version || !range->set_count)
    return false;
  for (size_t s = 0; s < range->set_count; s++) {
    const zrange_set *set = &range->sets[s];
    bool pass = true;
    bool prerelease_admitted = !version->prerelease;
    for (size_t i = set->start; pass && i < set->start + set->count; i++) {
      const zrange_comparator *c = &range->comps[i];
      pass = comp_pass(c, version);
      if (version->prerelease && c->version.prerelease &&
          c->version.major == version->major &&
          c->version.minor == version->minor &&
          c->version.patch == version->patch)
        prerelease_admitted = true;
    }
    if (pass && prerelease_admitted)
      return true;
  }
  return false;
}

bool zrange_test(const char *range, const char *version) {
  zrange r;
  zsemver v;
  return range && version && zrange_parse(range, &r) &&
         zsemver_parse(version, &v) && zrange_satisfies(&r, &v);
}
