/* zcron — cron parsing and next-fire computation.  See zcron.h. */

#include "zcron/zcron.h"

#include <string.h>

/* ---------- civil calendar (UTC), Howard Hinnant's algorithms ------ */

static void civil_from_days(long long z, int *y, unsigned *m, unsigned *d) {
  long long era;
  unsigned doe, yoe, doy, mp;
  z += 719468;
  era = (z >= 0 ? z : z - 146096) / 146097;
  doe = (unsigned)(z - era * 146097);
  yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
  *y = (int)yoe + (int)era * 400;
  doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
  mp = (5 * doy + 2) / 153;
  *d = doy - (153 * mp + 2) / 5 + 1;
  *m = mp + (mp < 10 ? 3 : (unsigned)-9);
  *y += *m <= 2; /* Jan/Feb belong to the following civil year */
}

static int is_leap(int y) {
  return (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
}

static unsigned days_in_month(int y, unsigned m) {
  static const unsigned dim[12] = {31, 28, 31, 30, 31, 30,
                                   31, 31, 30, 31, 30, 31};
  if (m == 2 && is_leap(y)) return 29;
  return dim[m - 1];
}

/* weekday of epoch day z: 1970-01-01 was Thursday (4); 0 = Sunday */
static unsigned weekday_from_days(long long z) {
  long long w = (z + 4) % 7;
  if (w < 0) w += 7;
  return (unsigned)w;
}

/* ---------- parsing ------------------------------------------------ */

typedef struct {
  const char *p;
  const char *end;
  char *err;
  size_t err_cap;
} parser;

static void perr(parser *ps, const char *msg) {
  if (ps->err && ps->err_cap > 0) {
    size_t n = strlen(msg);
    if (n >= ps->err_cap) n = ps->err_cap - 1;
    memcpy(ps->err, msg, n);
    ps->err[n] = '\0';
  }
}

static void skip_ws(parser *ps) {
  while (ps->p < ps->end && (*ps->p == ' ' || *ps->p == '\t')) ps->p++;
}

static int parse_uint(parser *ps, int *out) {
  int v = 0;
  int any = 0;
  while (ps->p < ps->end && *ps->p >= '0' && *ps->p <= '9') {
    if (v > 100000) return 0; /* absurd value guard */
    v = v * 10 + (*ps->p - '0');
    ps->p++;
    any = 1;
  }
  if (!any) return 0;
  *out = v;
  return 1;
}

static int name3(parser *ps, const char *const names[], int nnames,
                 int base, int *out) {
  int i;
  if (ps->end - ps->p < 3) return 0;
  for (i = 0; i < nnames; i++) {
    const char *nm = names[i];
    int j;
    int match = 1;
    for (j = 0; j < 3; j++) {
      char a = ps->p[j];
      char b = nm[j];
      if (a >= 'A' && a <= 'Z') a = (char)(a + 32);
      if (a != b) {
        match = 0;
        break;
      }
    }
    if (match) {
      ps->p += 3;
      *out = base + i;
      return 1;
    }
  }
  return 0;
}

/*
 * Parse one field into a bitmask.  lo..hi is the value domain
 * (inclusive); value v sets bit (bit_base + v).
 */
static int parse_field(parser *ps, int lo, int hi, unsigned bit_base,
                       const char *const names[], int nnames,
                       uint64_t *bits, int *is_star, const char *fname,
                       int fold_7_to_0) {
  int first = 1;
  *bits = 0;
  *is_star = 0;
  for (;;) {
    int a, b, step = 1;
    int star = 0;
    int have_a;
    skip_ws(ps);
    if (ps->p < ps->end && *ps->p == '*') {
      ps->p++;
      star = 1;
      a = lo;
      b = hi;
      have_a = 1;
    } else {
      have_a = parse_uint(ps, &a) ||
               (names && name3(ps, names, nnames, lo, &a));
      if (!have_a) {
        perr(ps, fname);
        return 0;
      }
      if (fold_7_to_0 && a == 7) a = 0;
      b = a;
    }
    if (!star && ps->p < ps->end && *ps->p == '-') {
      ps->p++;
      if (!parse_uint(ps, &b) &&
          !(names && name3(ps, names, nnames, lo, &b))) {
        perr(ps, "bad range end");
        return 0;
      }
      if (fold_7_to_0 && b == 7) b = 0;
    }
    if (ps->p < ps->end && *ps->p == '/') {
      ps->p++;
      if (!parse_uint(ps, &step) || step < 1) {
        perr(ps, "bad step");
        return 0;
      }
      if (star) {
        a = lo;
        b = hi;
      }
    }
    if (a < lo || a > hi || b < lo || b > hi || a > b) {
      perr(ps, "value out of range");
      return 0;
    }
    {
      int v;
      for (v = a; v <= b; v += step) {
        int vv = (fold_7_to_0 && v == 7) ? 0 : v;
        *bits |= 1ull << (bit_base + vv);
      }
    }
    if (star && first && step == 1 &&
        (ps->p >= ps->end || *ps->p != ','))
      *is_star = 1;
    skip_ws(ps);
    if (ps->p < ps->end && *ps->p == ',') {
      ps->p++;
      first = 0;
      continue;
    }
    break;
  }
  return 1;
}

int zcron_parse(const char *s, size_t len, zcron *out, char *err,
                size_t err_cap) {
  static const char *const month_names[12] = {"jan", "feb", "mar", "apr",
                                              "may", "jun", "jul", "aug",
                                              "sep", "oct", "nov", "dec"};
  static const char *const dow_names[7] = {"sun", "mon", "tue", "wed",
                                           "thu", "fri", "sat"};
  parser ps;
  uint64_t minute, hour, dom, month, dow;
  int mstar, hstar, domstar, mostar, dowstar;
  if (err && err_cap > 0) err[0] = '\0';
  if (!s || !out) {
    if (err && err_cap > 0) perr(&(parser){0, 0, err, err_cap}, "null arg");
    return 0;
  }
  ps.p = s;
  ps.end = s + len;
  ps.err = err;
  ps.err_cap = err_cap;

  if (!parse_field(&ps, 0, 59, 0, NULL, 0, &minute, &mstar, "bad minute", 0))
    return 0;
  if (!parse_field(&ps, 0, 23, 0, NULL, 0, &hour, &hstar, "bad hour", 0))
    return 0;
  if (!parse_field(&ps, 1, 31, 0, NULL, 0, &dom, &domstar, "bad dom", 0))
    return 0;
  if (!parse_field(&ps, 1, 12, 0, month_names, 12, &month, &mostar,
                   "bad month", 0))
    return 0;
  if (!parse_field(&ps, 0, 7, 0, dow_names, 7, &dow, &dowstar, "bad dow", 1))
    return 0;
  skip_ws(&ps);
  if (ps.p != ps.end) {
    perr(&ps, "trailing garbage");
    return 0;
  }
  (void)mstar;
  (void)hstar;
  (void)mostar;
  out->minute = minute;
  out->hour = (uint32_t)hour;
  out->dom = (uint32_t)dom;
  out->month = (uint16_t)month;
  out->dow = (uint16_t)dow;
  out->dom_star = domstar;
  out->dow_star = dowstar;
  return 1;
}

/* ---------- next fire ---------------------------------------------- */

static int matches(const zcron *c, unsigned mo, unsigned d, unsigned h,
                   unsigned mi, unsigned wd) {
  int dom_ok = (c->dom >> d) & 1u;
  int dow_ok = (c->dow >> wd) & 1u;
  int day_ok;
  if (!c->dom_star && !c->dow_star)
    day_ok = dom_ok || dow_ok; /* Vixie OR semantics */
  else
    day_ok = dom_ok && dow_ok;
  return ((c->month >> mo) & 1u) && day_ok && ((c->hour >> h) & 1u) &&
         ((c->minute >> mi) & 1ull);
}

long long zcron_next(const zcron *c, long long after) {
  long long minute0;
  long long limit;
  long long t;
  if (!c || after < 0) return -1;
  minute0 = after / 60 + 1; /* first minute strictly after `after` */
  /* search at most 8 years of minutes (covers two Feb-29 cycles) */
  limit = minute0 + 8LL * 366 * 24 * 60;
  for (t = minute0; t < limit; t++) {
    long long days = t / (24 * 60);
    long long rem = t % (24 * 60);
    int y;
    unsigned mo, d;
    unsigned h = (unsigned)(rem / 60);
    unsigned mi = (unsigned)(rem % 60);
    unsigned wd;
    if (rem < 0) {
      days -= 1;
      rem += 24 * 60;
      h = (unsigned)(rem / 60);
      mi = (unsigned)(rem % 60);
    }
    /* cheap rejects before the calendar conversion */
    if (!((c->minute >> mi) & 1ull)) continue;
    if (!((c->hour >> h) & 1u)) continue;
    civil_from_days(days, &y, &mo, &d);
    if (!((c->month >> mo) & 1u)) continue;
    if (d > days_in_month(y, mo)) continue; /* unreachable, defensive */
    wd = weekday_from_days(days);
    if (matches(c, mo, d, h, mi, wd)) return t * 60;
  }
  return -1;
}

/* ---------- canonical format --------------------------------------- */

typedef struct {
  char *out;
  size_t cap;
  size_t len;
} fmtr;

static void femit(fmtr *f, const char *s) {
  while (*s) {
    if (f->out && f->len + 1 < f->cap) f->out[f->len] = *s;
    f->len++;
    s++;
  }
}

static void femit_uint(fmtr *f, unsigned v) {
  char tmp[12];
  int i = 0;
  if (v == 0) {
    femit(f, "0");
    return;
  }
  while (v > 0) {
    tmp[i++] = (char)('0' + v % 10);
    v /= 10;
  }
  while (i > 0) {
    char c[2] = {tmp[--i], 0};
    femit(f, c);
  }
}

/* Render one field's bitmask over [lo,hi] as runs "a-b", comma lists. */
static void fmt_field(fmtr *f, uint64_t bits, int lo, int hi) {
  int v = lo;
  int first = 1;
  if (bits == 0) {
    femit(f, "!");
    return;
  }
  while (v <= hi) {
    if ((bits >> v) & 1ull) {
      int run_end = v;
      while (run_end < hi && ((bits >> (run_end + 1)) & 1ull)) run_end++;
      if (!first) femit(f, ",");
      first = 0;
      femit_uint(f, (unsigned)v);
      if (run_end > v) {
        femit(f, "-");
        femit_uint(f, (unsigned)run_end);
      }
      v = run_end + 1;
    } else {
      v++;
    }
  }
}

size_t zcron_format(const zcron *c, char *out, size_t cap) {
  fmtr f;
  if (!c) {
    if (out && cap > 0) out[0] = '\0';
    return 0;
  }
  f.out = out;
  f.cap = cap;
  f.len = 0;
  fmt_field(&f, c->minute, 0, 59);
  femit(&f, " ");
  fmt_field(&f, c->hour, 0, 23);
  femit(&f, " ");
  fmt_field(&f, c->dom, 1, 31);
  femit(&f, " ");
  fmt_field(&f, c->month, 1, 12);
  femit(&f, " ");
  fmt_field(&f, c->dow, 0, 6);
  if (out && cap > 0) out[f.len < cap ? f.len : cap - 1] = '\0';
  return f.len;
}
