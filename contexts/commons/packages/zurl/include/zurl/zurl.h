/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: bounded URI parser (RFC 3986 absolute URIs) for C23.
 *          Allocation-free and total: components are byte slices of
 *          the input, every malformed input is a clean false, and no
 *          byte outside the input is ever read.
 *
 * Accepted grammar:
 *
 *   uri       := scheme ":" hier [ "?" query ] [ "#" fragment ]
 *   hier      := "//" authority path-abempty   (authority form)
 *              | path-absolute | path-rootless | path-empty
 *   authority := [ userinfo "@" ] host [ ":" port ]
 *   host      := reg-name | "[" (IPv6-ish literal) "]" | IPv4
 *   scheme    := ALPHA *( ALPHA | DIGIT | "+" | "-" | "." )
 *   port      := *DIGIT                      (value must fit 0..65535)
 *
 * Percent-encodings (%XX, uppercase or lowercase hex) are validated
 * everywhere they are allowed. Characters outside the RFC's
 * unreserved / sub-delims / pct-encoded sets are rejected per
 * component. Relative references are not accepted; this parser is
 * for absolute URIs only.
 *
 * The result struct is caller-owned plain data; slices point into the
 * input, which must outlive them.
 */
#ifndef ZURL_H
#define ZURL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
  size_t off;
  size_t len;
} zurl_span;

typedef struct {
  zurl_span scheme;   /* always present */
  zurl_span userinfo; /* len 0 when absent */
  zurl_span host;     /* authority form only */
  zurl_span path;     /* always present (may be len 0) */
  zurl_span query;    /* after '?', len 0 when absent */
  zurl_span fragment; /* after '#', len 0 when absent */
  uint16_t port;      /* 0 when absent; a literal ":0" parses to 0 too */
  bool has_authority;
  bool has_userinfo;
  bool has_port;      /* distinguishes absent port from ":0" */
  bool has_query;
  bool has_fragment;
  bool host_is_ip_literal; /* "[...]" form */
  bool host_is_ipv4;       /* dotted-quad form */
} zurl;

/* Parse text[0..len) as an absolute URI. True on success; *out is
 * fully overwritten either way (zeroed on failure). NULL out is
 * false; NULL text with nonzero len is false. */
bool zurl_parse_n(const char *text, size_t len, zurl *out);

/* NUL-terminated convenience wrapper. */
bool zurl_parse(const char *text, zurl *out);

/* Copy a component into out[0..cap); returns the component length
 * (even when it exceeds cap) or SIZE_MAX for a NULL span/text. */
size_t zurl_copy(const char *text, const zurl_span *span, char *out,
                 size_t cap);

/* True when the scheme compares equal (case-insensitive, per RFC) to
 * the given lowercase literal, e.g. "https". */
bool zurl_scheme_is(const zurl *u, const char *text, const char *lower);

#endif /* ZURL_H */
