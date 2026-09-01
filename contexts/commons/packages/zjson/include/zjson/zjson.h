/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: bounded JSON (RFC 8259) serialization for C23.
 *          Allocation-free, depth-bounded, and total: the writer emits
 *          into caller storage, every call returns a status, and the
 *          state machine rejects structurally impossible sequences
 *          (a value where a key belongs, a second top-level value, a
 *          close that does not match the open) instead of producing
 *          invalid JSON.
 *
 * Rules enforced:
 *  - one top-level value; containers nest at most ZJSON_MAX_DEPTH deep;
 *  - object members are key/value pairs: a string key, then a value;
 *  - strings must be well-formed UTF-8 (validated via zutf8); control
 *    characters U+0000..U+001F, '"', and '\\' are escaped exactly as
 *    RFC 8259 section 7 requires; other bytes pass through unchanged;
 *  - doubles must be finite (JSON cannot represent NaN/Inf) and print
 *    with %.17g, which round-trips every IEEE 754 binary64 value;
 *  - on buffer overflow the writer keeps measuring: zjson_len() then
 *    reports the exact capacity that would have been needed.
 *
 * The first error is sticky: once any call fails, later calls are
 * no-ops that return the recorded status. zjson_finish() requires a
 * complete document and NUL-terminates it when there is room.
 */
#ifndef ZJSON_H
#define ZJSON_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define ZJSON_MAX_DEPTH 32

typedef enum {
  ZJSON_OK = 0,   /* call succeeded */
  ZJSON_OVERFLOW, /* output buffer too small; zjson_len() still measures */
  ZJSON_STATE,    /* call not valid in the current structural state */
  ZJSON_DEPTH,    /* nesting would exceed ZJSON_MAX_DEPTH */
  ZJSON_ENCODING  /* malformed UTF-8 string or non-finite double */
} zjson_status;

typedef struct {
  char *buf;         /* caller-owned output storage (may be NULL) */
  size_t cap;        /* size of buf in bytes */
  size_t len;        /* content bytes produced; exceeds cap on overflow */
  zjson_status status; /* sticky first error */
  uint32_t depth;    /* open containers, 0..ZJSON_MAX_DEPTH */
  uint32_t is_array; /* bit i: container at level i is an array */
  uint32_t pending;  /* bit i: object at level i awaits a member value */
  bool top_done;     /* the single top-level value has completed */
  uint32_t count[ZJSON_MAX_DEPTH]; /* completed entries per level */
} zjson;

/* Initialize a writer over buf[0..cap). buf may be NULL (cap is then
 * treated as 0; every byte overflows but is still measured). NULL w
 * is a no-op. */
void zjson_init(zjson *w, char *buf, size_t cap);

/* Sticky status, and the content length produced so far. */
zjson_status zjson_status_of(const zjson *w);
size_t zjson_len(const zjson *w);

/* Static name for a status ("ok", "overflow", ...); never NULL. */
const char *zjson_status_name(zjson_status st);

/* Containers. open pushes a level (value position rules apply);
 * close requires the matching kind and, for objects, no dangling key. */
zjson_status zjson_obj_open(zjson *w);
zjson_status zjson_obj_close(zjson *w);
zjson_status zjson_arr_open(zjson *w);
zjson_status zjson_arr_close(zjson *w);

/* Object member key. Valid only directly inside an object, in key
 * position. The key must be well-formed UTF-8; it is escaped on emit. */
zjson_status zjson_key_n(zjson *w, const char *str, size_t len);
zjson_status zjson_key(zjson *w, const char *str);

/* Scalar values. Valid at the top level (once), as an array element,
 * or as the value after an object key. */
zjson_status zjson_str_n(zjson *w, const char *str, size_t len);
zjson_status zjson_str(zjson *w, const char *str);
zjson_status zjson_i64(zjson *w, int64_t v);
zjson_status zjson_u64(zjson *w, uint64_t v);
zjson_status zjson_f64(zjson *w, double v);
zjson_status zjson_bool(zjson *w, bool v);
zjson_status zjson_null(zjson *w);

/* Finish the document: requires exactly one complete top-level value.
 * On success writes a NUL terminator when len < cap (the terminator is
 * not counted in the length) and stores the content length in
 * *len_out when non-NULL. */
zjson_status zjson_finish(zjson *w, size_t *len_out);

#endif /* ZJSON_H */
