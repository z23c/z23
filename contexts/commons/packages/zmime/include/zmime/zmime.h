/*
 * zmime — MIME media type lookup and Content-Type header parsing in
 * freestanding C23.
 *
 * Two jobs:
 *   1. A small built-in registry mapping the common file extensions to
 *      media types and back (text/html, engine/application/json, image/png,
 *      ...).  Unknown inputs return "engine/application/octet-stream" on the
 *      extension lookup and 0 on the reverse lookup.
 *   2. A strict parser for Content-Type header values:
 *      "type/subtype; param=value; charset=utf-8".  Type and subtype
 *      must be RFC 9110 tokens; parameters are token or quoted-string
 *      values (with backslash escapes).  Whitespace around separators
 *      is optional.  The parser is total: every input is either
 *      accepted or rejected with a clean 0 return.
 *
 * All matching is case-insensitive per RFC 2045.  No allocation, no
 * globals, no locale (ASCII case folding only).
 */
#ifndef ZMIME_H
#define ZMIME_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Case-insensitive extension lookup.  ext may start with '.' or not
 * ("html" or ".html").  Returns the media type string, or
 * "engine/application/octet-stream" for NULL/unknown/oversized input. */
const char *zmime_from_extension(const char *ext, size_t len);

/* Reverse lookup: first registered extension (no dot) for an exact
 * media type, or NULL. */
const char *zmime_to_extension(const char *mime, size_t len);

typedef struct {
  char type[64];       /* lowercased, e.g. "text" */
  char subtype[64];    /* lowercased, e.g. "html" */
  char charset[64];    /* lowercased charset parameter value, or "" */
  size_t nparams;      /* number of parameters (charset included) */
  struct {
    char name[32];     /* lowercased */
    char value[64];    /* unquoted, escapes decoded */
  } params[8];         /* at most 8 parameters are retained */
} zmime_content_type;

/*
 * Parse a Content-Type value.  Returns 1 on success, 0 on malformed
 * input.  On success *out is fully initialised; when more than 8
 * parameters are present the extras are skipped but the parse still
 * succeeds (nparams reports the true count).
 */
int zmime_parse_content_type(const char *s, size_t len,
                             zmime_content_type *out);

/* Rebuild a canonical header value from a parsed structure.
 * snprintf-style: returns would-be length, NUL-terminates if cap>0. */
size_t zmime_format_content_type(const zmime_content_type *ct, char *out,
                                 size_t cap);

#ifdef __cplusplus
}
#endif

#endif /* ZMIME_H */
