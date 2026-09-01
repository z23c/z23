/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: bounded, allocation-free RFC 4180 CSV parser and writer. */
#include "zcsv/zcsv.h"

#include <string.h>

void zcsv_init(zcsv_parser *p, char *row_data_scratch, size_t row_data_cap,
               zcsv_field *field_scratch, size_t field_cap, zcsv_row_fn on_row,
               void *ctx) {
  p->on_row = on_row;
  p->ctx = ctx;
  p->data = row_data_scratch;
  p->data_cap = row_data_cap;
  p->fields = field_scratch;
  p->field_cap = field_cap;
  p->data_len = 0;
  p->field_start = 0;
  p->nfields = 0;
  p->state = ZCSV_ST_FIELD_START;
  p->after_cr = false;
  p->seen_any = false;
}

/* Append one byte to the current field. */
static zcsv_status zcsv_push(zcsv_parser *p, char c) {
  if (p->data_len >= p->data_cap)
    return ZCSV_ERR_FIELD_TOO_LONG;
  p->data[p->data_len++] = c;
  return ZCSV_OK;
}

/* Close the current field and record its view. */
static zcsv_status zcsv_end_field(zcsv_parser *p) {
  if (p->nfields >= p->field_cap)
    return ZCSV_ERR_TOO_MANY_FIELDS;
  p->fields[p->nfields].ptr = p->data + p->field_start;
  p->fields[p->nfields].len = p->data_len - p->field_start;
  p->nfields++;
  p->field_start = p->data_len;
  p->state = ZCSV_ST_FIELD_START;
  return ZCSV_OK;
}

/* Close the current record and deliver it. */
static zcsv_status zcsv_end_row(zcsv_parser *p) {
  zcsv_status st = zcsv_end_field(p);
  if (st != ZCSV_OK)
    return st;
  p->on_row(p->ctx, p->fields, p->nfields);
  p->data_len = 0;
  p->field_start = 0;
  p->nfields = 0;
  p->seen_any = false;
  return ZCSV_OK;
}

zcsv_status zcsv_feed(zcsv_parser *p, const char *data, size_t len) {
  for (size_t i = 0; i < len; i++) {
    char c = data[i];

    if (p->after_cr) {
      /* Swallow the LF half of a CRLF pair already terminated by the CR. */
      p->after_cr = false;
      if (c == '\n')
        continue;
    }

    zcsv_status st = ZCSV_OK;
    switch (p->state) {
    case ZCSV_ST_FIELD_START:
      p->seen_any = true;
      if (c == '"') {
        p->state = ZCSV_ST_IN_QUOTED;
      } else if (c == ',') {
        st = zcsv_end_field(p);
      } else if (c == '\n') {
        st = zcsv_end_row(p);
      } else if (c == '\r') {
        st = zcsv_end_row(p);
        p->after_cr = true;
      } else {
        st = zcsv_push(p, c);
        p->state = ZCSV_ST_IN_PLAIN;
      }
      break;

    case ZCSV_ST_IN_PLAIN:
      p->seen_any = true;
      if (c == ',') {
        st = zcsv_end_field(p);
      } else if (c == '\n') {
        st = zcsv_end_row(p);
      } else if (c == '\r') {
        st = zcsv_end_row(p);
        p->after_cr = true;
      } else if (c == '"') {
        return ZCSV_ERR_STRAY_QUOTE;
      } else {
        st = zcsv_push(p, c);
      }
      break;

    case ZCSV_ST_IN_QUOTED:
      p->seen_any = true;
      if (c == '"') {
        p->state = ZCSV_ST_AFTER_QUOTE;
      } else {
        st = zcsv_push(p, c); /* commas, CR, LF are data here */
      }
      break;

    case ZCSV_ST_AFTER_QUOTE:
      if (c == '"') {
        st = zcsv_push(p, '"'); /* escaped quote */
        p->state = ZCSV_ST_IN_QUOTED;
      } else if (c == ',') {
        st = zcsv_end_field(p);
      } else if (c == '\n') {
        st = zcsv_end_row(p);
      } else if (c == '\r') {
        st = zcsv_end_row(p);
        p->after_cr = true;
      } else {
        return ZCSV_ERR_STRAY_QUOTE; /* e.g. "abc"x */
      }
      break;
    }
    if (st != ZCSV_OK)
      return st;
  }
  return ZCSV_OK;
}

zcsv_status zcsv_finish(zcsv_parser *p) {
  if (p->state == ZCSV_ST_IN_QUOTED)
    return ZCSV_ERR_UNTERMINATED;
  p->after_cr = false;
  /* Emit a final record only when bytes were seen since the last row end;
   * a trailing terminator must not create a phantom row. */
  if (p->seen_any || p->nfields > 0)
    return zcsv_end_row(p);
  return ZCSV_OK;
}

const char *zcsv_status_str(zcsv_status st) {
  switch (st) {
  case ZCSV_OK:
    return "ok";
  case ZCSV_ERR_FIELD_TOO_LONG:
    return "row exceeded row-data scratch bound";
  case ZCSV_ERR_TOO_MANY_FIELDS:
    return "row exceeded field-count scratch bound";
  case ZCSV_ERR_STRAY_QUOTE:
    return "stray quote outside a quoted field";
  case ZCSV_ERR_UNTERMINATED:
    return "unterminated quoted field";
  }
  return "unknown";
}

size_t zcsv_header_index(const zcsv_field *header, size_t nfields,
                         const char *name) {
  size_t name_len = strlen(name);
  for (size_t i = 0; i < nfields; i++) {
    if (header[i].len == name_len &&
        memcmp(header[i].ptr, name, name_len) == 0)
      return i;
  }
  return SIZE_MAX;
}

bool zcsv_field_equals(const zcsv_field *f, const char *cstr) {
  size_t n = strlen(cstr);
  return f->len == n && memcmp(f->ptr, cstr, n) == 0;
}

bool zcsv_field_needs_quotes(const char *f, size_t len) {
  for (size_t i = 0; i < len; i++) {
    char c = f[i];
    if (c == ',' || c == '"' || c == '\r' || c == '\n')
      return true;
  }
  return false;
}

static size_t emit(char *out, size_t cap, size_t at, char c) {
  if (at < cap)
    out[at] = c;
  return at + 1;
}

size_t zcsv_write_field(char *out, size_t cap, const char *f, size_t len) {
  size_t at = 0;
  bool quoted = zcsv_field_needs_quotes(f, len);
  if (quoted)
    at = emit(out, cap, at, '"');
  for (size_t i = 0; i < len; i++) {
    if (f[i] == '"')
      at = emit(out, cap, at, '"'); /* double it */
    at = emit(out, cap, at, f[i]);
  }
  if (quoted)
    at = emit(out, cap, at, '"');
  return at;
}

size_t zcsv_write_row(char *out, size_t cap, const char *const *fields,
                      const size_t *lens, size_t nfields) {
  size_t at = 0;
  for (size_t i = 0; i < nfields; i++) {
    if (i > 0)
      at = emit(out, cap, at, ',');
    /* Render each field into the remaining space. */
    size_t need = zcsv_write_field(out + (at < cap ? at : cap),
                                   cap - (at < cap ? at : cap), fields[i],
                                   lens ? lens[i] : strlen(fields[i]));
    at += need;
  }
  at = emit(out, cap, at, '\r');
  at = emit(out, cap, at, '\n');
  return at;
}
