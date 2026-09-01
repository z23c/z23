/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: bounded, allocation-free RFC 4180 CSV parser and writer.
 *
 * The parser never allocates: the caller supplies one scratch buffer that
 * holds the bytes of every field in the row currently being parsed, plus a
 * scratch array of zcsv_field views.  Both bounds are hard limits; exceeding
 * either one fails the feed with an explicit status instead of growing.
 *
 * Ownership/lifetimes:
 *  - zcsv_init() borrows the two caller scratch regions; they must outlive
 *    every zcsv_feed()/zcsv_finish() call on that parser.
 *  - Field pointers handed to the row callback point into the row scratch
 *    and are valid only for the duration of that callback.  Copy them if
 *    they must survive.
 *  - zcsv_write_field()/zcsv_write_row() never allocate; they return the
 *    number of bytes the full output requires so a short caller buffer can
 *    be detected (required > capacity) instead of silently truncated.
 *
 * Grammar notes (RFC 4180, strict):
 *  - Records are separated by CRLF or LF.  A bare CR also ends a record and
 *    a following LF is swallowed, so lone-CR input parses too.
 *  - Quoted fields may contain commas, quotes (escaped as ""), CR and LF.
 *  - A '"' is only legal at the start of a field or as "" inside a quoted
 *    field; anywhere else it is ZCSV_ERR_STRAY_QUOTE.
 *  - Every record line produces a row, including empty lines (one empty
 *    field).  A trailing line terminator does not produce a phantom row.
 */
#ifndef ZCSV_H
#define ZCSV_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h> /* SIZE_MAX */

/* View of one parsed field.  ptr/len only; not NUL-terminated. */
typedef struct {
  const char *ptr;
  size_t len;
} zcsv_field;

/* Invoked once per completed record.  fields is valid only during the call. */
typedef void (*zcsv_row_fn)(void *ctx, const zcsv_field *fields,
                            size_t nfields);

typedef enum {
  ZCSV_OK = 0,
  ZCSV_ERR_FIELD_TOO_LONG,  /* row bytes exceeded the row-data scratch cap */
  ZCSV_ERR_TOO_MANY_FIELDS, /* field count exceeded the field-view cap */
  ZCSV_ERR_STRAY_QUOTE,     /* '"' where RFC 4180 forbids it */
  ZCSV_ERR_UNTERMINATED,    /* input ended inside a quoted field */
} zcsv_status;

typedef struct {
  zcsv_row_fn on_row;
  void *ctx;
  /* Caller-owned scratch: bytes of the row currently being parsed. */
  char *data;
  size_t data_cap;
  /* Caller-owned scratch: one view per field of the current row. */
  zcsv_field *fields;
  size_t field_cap;
  /* Internal state; do not touch. */
  size_t data_len;
  size_t field_start;
  size_t nfields;
  unsigned state;
  bool after_cr;
  bool seen_any;
} zcsv_parser;

/* Parser state machine states (internal). */
enum {
  ZCSV_ST_FIELD_START = 0,
  ZCSV_ST_IN_PLAIN,
  ZCSV_ST_IN_QUOTED,
  ZCSV_ST_AFTER_QUOTE,
};

/* Bind a parser to caller scratch.  All pointers must be non-null and both
 * capacities at least 1. */
void zcsv_init(zcsv_parser *p, char *row_data_scratch, size_t row_data_cap,
               zcsv_field *field_scratch, size_t field_cap, zcsv_row_fn on_row,
               void *ctx);

/* Feed one chunk of CSV text.  Rows are delivered to on_row as they
 * complete.  Returns ZCSV_OK or the first error encountered; after an error
 * the parser state is unspecified and must not be fed again. */
[[nodiscard]] zcsv_status zcsv_feed(zcsv_parser *p, const char *data,
                                    size_t len);

/* Flush a final record that has no trailing terminator.  Detects an
 * unterminated quoted field.  Always call after the last zcsv_feed(). */
[[nodiscard]] zcsv_status zcsv_finish(zcsv_parser *p);

const char *zcsv_status_str(zcsv_status st);

/* --- header row helper --- */

/* Case-sensitive lookup of a column name in a header row.  Returns the
 * column index or SIZE_MAX when absent. */
size_t zcsv_header_index(const zcsv_field *header, size_t nfields,
                         const char *name);

/* Compare a field view with a NUL-terminated string. */
bool zcsv_field_equals(const zcsv_field *f, const char *cstr);

/* --- writer --- */

/* True when the field must be quoted (contains ',', '"', CR, LF) or is
 * empty-leading/trailing-space sensitive?  RFC 4180 quotes only on the
 * three special characters; zcsv follows exactly that. */
bool zcsv_field_needs_quotes(const char *f, size_t len);

/* Write one field, quoting and doubling '"' as needed.  Returns the number
 * of bytes the full rendering requires; if the return value exceeds cap the
 * output was truncated and must be discarded.  Never NUL-terminates. */
size_t zcsv_write_field(char *out, size_t cap, const char *f, size_t len);

/* Write one full record: comma-joined fields followed by CRLF.  Same
 * required-length contract as zcsv_write_field(). */
size_t zcsv_write_row(char *out, size_t cap, const char *const *fields,
                      const size_t *lens, size_t nfields);

#endif /* ZCSV_H */
