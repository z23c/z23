/* ztoml — bounded TOML-subset pull parser
 *
 * Apache-2.0 licensed. C23, freestanding-friendly, no allocation.
 *
 * Supported subset:
 *   - key/value pairs: bare keys (A-Za-z0-9_-), dotted keys kept raw
 *   - sections [name] and [dotted.name]; [[array-of-tables]] NOT
 *     supported
 *   - values: basic strings "..." (escapes incl. \uXXXX), literal
 *     strings '...', integers (dec/0x/0o/0b, underscores), floats
 *     (., e, inf, nan, underscores), booleans, arrays of values
 *     (nestable to ZTOML_MAX_DEPTH)
 *   - comments (# ...) anywhere whitespace is allowed
 *
 * Not supported (clean ZTOML_ERR_SYNTAX): multiline strings, inline
 * tables, datetimes, quoted keys, array-of-tables headers.
 *
 * Events are zero-copy slices into the document. Typed conversions
 * are done inline for INT/FLOAT/BOOL; string payload slices retain
 * their quotes-stripped raw form — use ztoml_str_decode() to resolve
 * escapes of a basic string.
 */
#ifndef ZTOML_H
#define ZTOML_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef ZTOML_MAX
#define ZTOML_MAX 65535u
#endif
#ifndef ZTOML_MAX_DEPTH
#define ZTOML_MAX_DEPTH 8u
#endif
#ifndef ZTOML_MAX_KEY
#define ZTOML_MAX_KEY 256u
#endif

typedef enum {
  ZTOML_OK = 0,
  ZTOML_ERR_ARG = 1,     /* NULL argument */
  ZTOML_ERR_RANGE = 2,   /* a bound exceeded (doc size, depth, key len) */
  ZTOML_ERR_SYNTAX = 3,  /* malformed input; err_off names the offset */
  ZTOML_ERR_BADVALUE = 4 /* numeric conversion overflow etc. */
} ztoml_err;

typedef enum {
  ZTOML_EV_DONE = 0,
  ZTOML_EV_SECTION = 1,  /* [path] — slice is the raw dotted path */
  ZTOML_EV_KEY = 2,      /* key of a pair — slice is the raw key */
  ZTOML_EV_VALUE = 3,    /* scalar value; vtype selects payload */
  ZTOML_EV_ARR_OPEN = 4,
  ZTOML_EV_ARR_CLOSE = 5
} ztoml_ev_kind;

typedef enum {
  ZTOML_V_NONE = 0,
  ZTOML_V_STR_BASIC = 1, /* "..." — slice raw (escapes unresolved) */
  ZTOML_V_STR_LIT = 2,   /* '...' — slice is literal content */
  ZTOML_V_INT = 3,       /* i64 valid */
  ZTOML_V_FLOAT = 4,     /* f64 valid */
  ZTOML_V_BOOL = 5       /* boolean valid */
} ztoml_vtype;

typedef struct {
  ztoml_ev_kind kind;
  const char *ptr; /* SECTION/KEY/STR: slice start (into doc) */
  size_t len;      /* slice length */
  ztoml_vtype vtype;
  int64_t i64;
  double f64;
  int boolean;
} ztoml_ev;

typedef struct {
  const char *doc;
  size_t len;
  size_t pos;
  size_t line; /* 1-based, for diagnostics */
  int at_line_start;
  int pair_pending;   /* next token continues a key = ... pair */
  size_t arr_depth;   /* open arrays */
  int arr_first[ZTOML_MAX_DEPTH];   /* per-depth: no element seen yet */
  int arr_after_value[ZTOML_MAX_DEPTH]; /* per-depth: expect , or ] */
  ztoml_err err;
  size_t err_off;
} ztoml;

ztoml_err ztoml_init(ztoml *t, const char *doc, size_t len);

/* Advance one event. ZTOML_OK with kind == ZTOML_EV_DONE at end of
 * input (arrays must be balanced first — trailing '[' is SYNTAX).
 * Errors are sticky; err_off is the byte offset. */
ztoml_err ztoml_next(ztoml *t, ztoml_ev *ev);

/* Decode a basic-string slice (escapes resolved, UTF-8 validated
 * structurally for \u sequences). Returns needed length, SIZE_MAX on
 * malformed escape. Literal slices need no decoding. */
size_t ztoml_str_decode(const char *ptr, size_t len, char *dst,
                        size_t cap);

const char *ztoml_err_str(ztoml_err e);

#ifdef __cplusplus
}
#endif

#endif /* ZTOML_H */
