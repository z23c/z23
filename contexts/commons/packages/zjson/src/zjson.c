/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: bounded RFC 8259 JSON writer (see the header for the rules). */
#include "zjson/zjson.h"

#include <inttypes.h>
#include <math.h>
#include <stdio.h>
#include <string.h>

#include "zutf8/zutf8.h"

void zjson_init(zjson *w, char *buf, size_t cap) {
  if (!w)
    return;
  memset(w, 0, sizeof(*w));
  w->buf = buf;
  w->cap = buf ? cap : 0;
  w->status = ZJSON_OK;
}

zjson_status zjson_status_of(const zjson *w) { return w ? w->status : ZJSON_STATE; }

size_t zjson_len(const zjson *w) { return w ? w->len : 0; }

const char *zjson_status_name(zjson_status st) {
  switch (st) {
  case ZJSON_OK: return "ok";
  case ZJSON_OVERFLOW: return "overflow";
  case ZJSON_STATE: return "state";
  case ZJSON_DEPTH: return "depth";
  case ZJSON_ENCODING: return "encoding";
  }
  return "unknown";
}

static zjson_status fail(zjson *w, zjson_status st) {
  if (w->status == ZJSON_OK)
    w->status = st;
  return w->status;
}

/* Append s[0..n); measure even when there is no room. */
static void emit(zjson *w, const char *s, size_t n) {
  if (w->len > SIZE_MAX - n) {
    w->len = SIZE_MAX;
    fail(w, ZJSON_OVERFLOW);
    return;
  }
  if (w->len <= w->cap && n <= w->cap - w->len)
    memcpy(w->buf + w->len, s, n);
  else
    fail(w, ZJSON_OVERFLOW);
  w->len += n;
}

static void emit_ch(zjson *w, char c) { emit(w, &c, 1); }

/* Separator and position check before any value (scalar or container
 * open). On success the caller emits the value, then value_end(). */
static zjson_status value_begin(zjson *w) {
  if (w->depth == 0) {
    if (w->top_done)
      return fail(w, ZJSON_STATE);
    return ZJSON_OK;
  }
  uint32_t lvl = w->depth - 1;
  if ((w->is_array >> lvl) & 1u) {
    if (w->count[lvl] > 0)
      emit_ch(w, ',');
    return ZJSON_OK;
  }
  if (!((w->pending >> lvl) & 1u))
    return fail(w, ZJSON_STATE); /* object value without a key */
  return ZJSON_OK;
}

static void value_end(zjson *w) {
  if (w->depth == 0) {
    w->top_done = true;
    return;
  }
  uint32_t lvl = w->depth - 1;
  w->pending &= ~(1u << lvl);
  w->count[lvl]++;
}

static zjson_status open_container(zjson *w, bool array) {
  if (!w)
    return ZJSON_STATE;
  if (w->status != ZJSON_OK)
    return w->status;
  zjson_status st = value_begin(w);
  if (st != ZJSON_OK)
    return st;
  if (w->depth == ZJSON_MAX_DEPTH)
    return fail(w, ZJSON_DEPTH);
  uint32_t lvl = w->depth;
  w->depth++;
  if (array)
    w->is_array |= 1u << lvl;
  else
    w->is_array &= ~(1u << lvl);
  w->pending &= ~(1u << lvl);
  w->count[lvl] = 0;
  emit_ch(w, array ? '[' : '{');
  return w->status;
}

static zjson_status close_container(zjson *w, bool array) {
  if (!w)
    return ZJSON_STATE;
  if (w->status != ZJSON_OK)
    return w->status;
  if (w->depth == 0)
    return fail(w, ZJSON_STATE);
  uint32_t lvl = w->depth - 1;
  if (((w->is_array >> lvl) & 1u) != (uint32_t)array)
    return fail(w, ZJSON_STATE);
  if (!array && ((w->pending >> lvl) & 1u))
    return fail(w, ZJSON_STATE); /* key with no value */
  w->depth--;
  emit_ch(w, array ? ']' : '}');
  value_end(w);
  return w->status;
}

zjson_status zjson_obj_open(zjson *w) { return open_container(w, false); }
zjson_status zjson_obj_close(zjson *w) { return close_container(w, false); }
zjson_status zjson_arr_open(zjson *w) { return open_container(w, true); }
zjson_status zjson_arr_close(zjson *w) { return close_container(w, true); }

/* Emit s[0..len) as a quoted, escaped JSON string. Caller must have
 * validated UTF-8; only the mandatory escapes are applied. */
static void emit_escaped(zjson *w, const char *s, size_t len) {
  static const char hexd[] = "0123456789abcdef";
  emit_ch(w, '"');
  for (size_t i = 0; i < len; i++) {
    unsigned char c = (unsigned char)s[i];
    switch (c) {
    case '"': emit(w, "\\\"", 2); break;
    case '\\': emit(w, "\\\\", 2); break;
    case '\b': emit(w, "\\b", 2); break;
    case '\t': emit(w, "\\t", 2); break;
    case '\n': emit(w, "\\n", 2); break;
    case '\f': emit(w, "\\f", 2); break;
    case '\r': emit(w, "\\r", 2); break;
    default:
      if (c < 0x20) {
        char esc[6] = {'\\', 'u', '0', '0', hexd[c >> 4], hexd[c & 15]};
        emit(w, esc, sizeof esc);
      } else {
        emit_ch(w, (char)c);
      }
    }
  }
  emit_ch(w, '"');
}

zjson_status zjson_key_n(zjson *w, const char *str, size_t len) {
  if (!w)
    return ZJSON_STATE;
  if (w->status != ZJSON_OK)
    return w->status;
  if (w->depth == 0)
    return fail(w, ZJSON_STATE);
  uint32_t lvl = w->depth - 1;
  if ((w->is_array >> lvl) & 1u)
    return fail(w, ZJSON_STATE); /* key inside an array */
  if ((w->pending >> lvl) & 1u)
    return fail(w, ZJSON_STATE); /* key where a value belongs */
  if (!str || !zutf8_validate_n(str, len))
    return fail(w, ZJSON_ENCODING);
  if (w->count[lvl] > 0)
    emit_ch(w, ',');
  emit_escaped(w, str, len);
  emit_ch(w, ':');
  w->pending |= 1u << lvl;
  return w->status;
}

zjson_status zjson_key(zjson *w, const char *str) {
  if (!str)
    return w ? fail(w, ZJSON_ENCODING) : ZJSON_STATE;
  return zjson_key_n(w, str, strlen(str));
}

zjson_status zjson_str_n(zjson *w, const char *str, size_t len) {
  if (!w)
    return ZJSON_STATE;
  if (w->status != ZJSON_OK)
    return w->status;
  zjson_status st = value_begin(w);
  if (st != ZJSON_OK)
    return st;
  if (!str || !zutf8_validate_n(str, len))
    return fail(w, ZJSON_ENCODING);
  emit_escaped(w, str, len);
  value_end(w);
  return w->status;
}

zjson_status zjson_str(zjson *w, const char *str) {
  if (!str)
    return w ? fail(w, ZJSON_ENCODING) : ZJSON_STATE;
  return zjson_str_n(w, str, strlen(str));
}

/* Emit a formatted scalar produced by snprintf into tmp. */
static zjson_status emit_scalar(zjson *w, const char *tmp, size_t n) {
  zjson_status st = value_begin(w);
  if (st != ZJSON_OK)
    return st;
  emit(w, tmp, n);
  value_end(w);
  return w->status;
}

zjson_status zjson_i64(zjson *w, int64_t v) {
  if (!w)
    return ZJSON_STATE;
  if (w->status != ZJSON_OK)
    return w->status;
  char tmp[24];
  int n = snprintf(tmp, sizeof tmp, "%" PRId64, v);
  return emit_scalar(w, tmp, (size_t)n);
}

zjson_status zjson_u64(zjson *w, uint64_t v) {
  if (!w)
    return ZJSON_STATE;
  if (w->status != ZJSON_OK)
    return w->status;
  char tmp[24];
  int n = snprintf(tmp, sizeof tmp, "%" PRIu64, v);
  return emit_scalar(w, tmp, (size_t)n);
}

zjson_status zjson_f64(zjson *w, double v) {
  if (!w)
    return ZJSON_STATE;
  if (w->status != ZJSON_OK)
    return w->status;
  if (!isfinite(v))
    return fail(w, ZJSON_ENCODING); /* JSON has no NaN/Inf */
  char tmp[32];
  int n = snprintf(tmp, sizeof tmp, "%.17g", v);
  return emit_scalar(w, tmp, (size_t)n);
}

zjson_status zjson_bool(zjson *w, bool v) {
  if (!w)
    return ZJSON_STATE;
  if (w->status != ZJSON_OK)
    return w->status;
  return emit_scalar(w, v ? "true" : "false", v ? 4 : 5);
}

zjson_status zjson_null(zjson *w) {
  if (!w)
    return ZJSON_STATE;
  if (w->status != ZJSON_OK)
    return w->status;
  return emit_scalar(w, "null", 4);
}

zjson_status zjson_finish(zjson *w, size_t *len_out) {
  if (!w)
    return ZJSON_STATE;
  if (w->status == ZJSON_OK && (w->depth != 0 || !w->top_done))
    fail(w, ZJSON_STATE);
  if (w->status == ZJSON_OK && w->len < w->cap)
    w->buf[w->len] = '\0';
  if (len_out)
    *len_out = w->len;
  return w->status;
}
