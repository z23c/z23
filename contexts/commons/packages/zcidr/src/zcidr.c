/* zcidr — IP/CIDR parse, format, contain.  See zcidr.h. */

#include "zcidr/zcidr.h"

#include <string.h>

/* ---------- IPv4 --------------------------------------------------- */

static int parse_v4_impl(const char *s, size_t len, zcidr_v4 *out,
                         size_t *consumed) {
  size_t i = 0;
  int part;
  zcidr_v4 r;
  for (part = 0; part < 4; part++) {
    unsigned v = 0;
    size_t digits = 0;
    while (i < len && s[i] >= '0' && s[i] <= '9') {
      v = v * 10 + (unsigned)(s[i] - '0');
      if (v > 255) return 0;
      i++;
      digits++;
    }
    if (digits == 0 || digits > 3) return 0;
    if (digits > 1 && s[i - digits] == '0') return 0; /* leading zero */
    r.b[part] = (uint8_t)v;
    if (part < 3) {
      if (i >= len || s[i] != '.') return 0;
      i++;
    }
  }
  *out = r;
  if (consumed) *consumed = i;
  return i == len;
}

int zcidr_parse_v4(const char *s, size_t len, zcidr_v4 *out) {
  if (!s || !out) return 0;
  return parse_v4_impl(s, len, out, NULL);
}

/* ---------- IPv6 --------------------------------------------------- */

static int hexval(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

int zcidr_parse_v6(const char *s, size_t len, zcidr_v6 *out) {
  uint16_t groups[8];
  int ngroups = 0;
  int dbl_colon_at = -1; /* group index where "::" occurred */
  size_t i = 0;
  if (!s || !out || len == 0) return 0;
  memset(groups, 0, sizeof groups);

  if (len >= 2 && s[0] == ':' && s[1] == ':') {
    dbl_colon_at = 0;
    i = 2;
    if (i == len) goto finish; /* "::" alone */
  } else if (s[0] == ':') {
    return 0;
  }

  while (i < len) {
    unsigned v = 0;
    int digits = 0;
    /* possible IPv4 tail: must start at a group boundary */
    if (ngroups < 8) {
      zcidr_v4 tail;
      size_t consumed = 0;
      if (parse_v4_impl(s + i, len - i, &tail, &consumed)) {
        if (ngroups > 7 - 1) return 0; /* need room for 2 groups */
        groups[ngroups++] = (uint16_t)((tail.b[0] << 8) | tail.b[1]);
        groups[ngroups++] = (uint16_t)((tail.b[2] << 8) | tail.b[3]);
        i += consumed;
        if (i != len) return 0;
        goto finish;
      }
    }
    while (i < len && hexval(s[i]) >= 0) {
      int h = hexval(s[i]);
      if (digits == 4) return 0;
      v = v * 16 + (unsigned)h;
      digits++;
      i++;
    }
    if (digits == 0) return 0;
    if (ngroups >= 8) return 0;
    groups[ngroups++] = (uint16_t)v;
    if (i == len) break;
    if (s[i] != ':') return 0;
    /* ":" or "::" */
    if (i + 1 < len && s[i + 1] == ':') {
      if (dbl_colon_at >= 0) return 0; /* only one "::" allowed */
      dbl_colon_at = ngroups;
      i += 2;
      if (i == len) goto finish; /* trailing "::" */
    } else {
      i++;
      if (i == len) return 0; /* trailing single ":" */
    }
  }

finish:
  if (dbl_colon_at < 0) {
    if (ngroups != 8) return 0;
  } else {
    int insert = 8 - ngroups;
    int g;
    if (insert < 1) return 0; /* "::" must compress at least one group */
    for (g = ngroups - 1; g >= dbl_colon_at; g--)
      groups[g + insert] = groups[g];
    for (g = dbl_colon_at; g < dbl_colon_at + insert; g++) groups[g] = 0;
  }
  for (i = 0; i < 8; i++) {
    out->b[i * 2] = (uint8_t)(groups[i] >> 8);
    out->b[i * 2 + 1] = (uint8_t)(groups[i] & 0xFF);
  }
  return 1;
}

/* ---------- prefix ------------------------------------------------- */

static int parse_prefix(const char *s, size_t len, unsigned max,
                        unsigned *out) {
  unsigned v = 0;
  size_t i = 0;
  if (len == 0 || len > 3) return 0;
  if (len > 1 && s[0] == '0') return 0; /* leading zero */
  for (; i < len; i++) {
    if (s[i] < '0' || s[i] > '9') return 0;
    v = v * 10 + (unsigned)(s[i] - '0');
  }
  if (v > max) return 0;
  *out = v;
  return 1;
}

int zcidr_parse(const char *s, size_t len, zcidr *out) {
  const char *slash = NULL;
  size_t i;
  zcidr r;
  if (!s || !out || len == 0) return 0;
  for (i = 0; i < len; i++) {
    if (s[i] == '/') {
      if (slash) return 0;
      slash = s + i;
    }
  }
  memset(&r, 0, sizeof r);
  {
    size_t alen = slash ? (size_t)(slash - s) : len;
    if (alen == 0) return 0;
    if (parse_v4_impl(s, alen, &r.v4, NULL)) {
      r.is_v6 = 0;
    } else if (zcidr_parse_v6(s, alen, &r.v6)) {
      r.is_v6 = 1;
    } else {
      return 0;
    }
  }
  if (slash) {
    unsigned max = r.is_v6 ? 128u : 32u;
    if (!parse_prefix(slash + 1, len - (size_t)(slash - s) - 1, max,
                      &r.prefix))
      return 0;
    r.has_prefix = 1;
  }
  *out = r;
  return 1;
}

/* ---------- containment -------------------------------------------- */

static int bytes_contain(const uint8_t *net, const uint8_t *addr,
                         unsigned prefix, unsigned nbytes) {
  unsigned full = prefix / 8;
  unsigned rem = prefix % 8;
  unsigned i;
  if (full > nbytes) return 0;
  for (i = 0; i < full; i++)
    if (net[i] != addr[i]) return 0;
  if (rem) {
    uint8_t mask = (uint8_t)(0xFFu << (8 - rem));
    if ((net[full] & mask) != (addr[full] & mask)) return 0;
  }
  return 1;
}

int zcidr_contains(const zcidr *net, const zcidr *addr) {
  if (!net || !addr) return 0;
  if (net->is_v6 != addr->is_v6) return 0;
  if (!net->has_prefix) {
    /* bare address contains only itself */
    return zcidr_cmp(net, addr) == 0;
  }
  if (net->is_v6)
    return bytes_contain(net->v6.b, addr->v6.b, net->prefix, 16);
  return bytes_contain(net->v4.b, addr->v4.b, net->prefix, 4);
}

int zcidr_cmp(const zcidr *a, const zcidr *b) {
  int c;
  if (a->is_v6 != b->is_v6) return a->is_v6 ? 1 : -1;
  if (a->is_v6) {
    c = memcmp(a->v6.b, b->v6.b, 16);
  } else {
    c = memcmp(a->v4.b, b->v4.b, 4);
  }
  return c < 0 ? -1 : c > 0 ? 1 : 0;
}

/* ---------- format ------------------------------------------------- */

typedef struct {
  char *out;
  size_t cap;
  size_t len;
} fmtr;

static void emit(fmtr *f, const char *s) {
  while (*s) {
    if (f->out && f->len + 1 < f->cap) f->out[f->len] = *s;
    f->len++;
    s++;
  }
}

static void emit_uint(fmtr *f, unsigned v) {
  char tmp[10];
  int i = 0;
  if (v == 0) {
    emit(f, "0");
    return;
  }
  while (v) {
    tmp[i++] = (char)('0' + v % 10);
    v /= 10;
  }
  while (i > 0) {
    char c[2] = {tmp[--i], 0};
    emit(f, c);
  }
}

static void emit_hex(fmtr *f, unsigned v) {
  char tmp[4];
  int i = 0;
  if (v == 0) {
    emit(f, "0");
    return;
  }
  while (v) {
    unsigned d = v & 0xF;
    tmp[i++] = (char)(d < 10 ? '0' + d : 'a' + d - 10);
    v >>= 4;
  }
  while (i > 0) {
    char c[2] = {tmp[--i], 0};
    emit(f, c);
  }
}

static size_t fmt_done(fmtr *f) {
  if (f->out && f->cap > 0) f->out[f->len < f->cap ? f->len : f->cap - 1] = '\0';
  return f->len;
}

size_t zcidr_format_v4(const zcidr_v4 *a, char *out, size_t cap) {
  fmtr f = {out, cap, 0};
  int i;
  if (!a) {
    if (out && cap) out[0] = '\0';
    return 0;
  }
  for (i = 0; i < 4; i++) {
    if (i) emit(&f, ".");
    emit_uint(&f, a->b[i]);
  }
  return fmt_done(&f);
}

size_t zcidr_format_v6(const zcidr_v6 *a, char *out, size_t cap) {
  uint16_t g[8];
  int i;
  int best_start = -1, best_len = 0;
  fmtr f = {out, cap, 0};
  if (!a) {
    if (out && cap) out[0] = '\0';
    return 0;
  }
  for (i = 0; i < 8; i++) g[i] = (uint16_t)((a->b[i * 2] << 8) | a->b[i * 2 + 1]);
  /* find the left-most longest run of zero groups (length >= 2) */
  for (i = 0; i < 8;) {
    if (g[i] == 0) {
      int j = i;
      while (j < 8 && g[j] == 0) j++;
      if (j - i > best_len) {
        best_start = i;
        best_len = j - i;
      }
      i = j;
    } else {
      i++;
    }
  }
  if (best_len < 2) best_start = -1;
  for (i = 0; i < 8; i++) {
    if (i == best_start) {
      emit(&f, "::");
      i += best_len - 1;
      continue;
    }
    if (i > 0 && i != best_start + best_len) emit(&f, ":");
    emit_hex(&f, g[i]);
  }
  return fmt_done(&f);
}

size_t zcidr_format(const zcidr *c, char *out, size_t cap) {
  fmtr f = {out, cap, 0};
  size_t n;
  if (!c) {
    if (out && cap) out[0] = '\0';
    return 0;
  }
  if (c->is_v6)
    n = zcidr_format_v6(&c->v6, out, cap);
  else
    n = zcidr_format_v4(&c->v4, out, cap);
  f.len = n;
  if (c->has_prefix) {
    emit(&f, "/");
    emit_uint(&f, c->prefix);
  }
  return fmt_done(&f);
}

void zcidr_network(zcidr *c) {
  uint8_t *b;
  unsigned nbytes, full, rem, i;
  if (!c || !c->has_prefix) return;
  b = c->is_v6 ? c->v6.b : c->v4.b;
  nbytes = c->is_v6 ? 16u : 4u;
  full = c->prefix / 8;
  rem = c->prefix % 8;
  if (full >= nbytes) return;
  if (rem) b[full] &= (uint8_t)(0xFFu << (8 - rem));
  for (i = full + (rem ? 1u : 0u); i < nbytes; i++) b[i] = 0;
}
