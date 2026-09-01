/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: RFC 3986 absolute-URI parser (see the header). */
#include "zurl/zurl.h"

#include <string.h>

static bool is_alpha(unsigned char c) {
  return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}
static bool is_digit(unsigned char c) { return c >= '0' && c <= '9'; }
static bool is_hex(unsigned char c) {
  return is_digit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}
static bool is_unreserved(unsigned char c) {
  return is_alpha(c) || is_digit(c) || c == '-' || c == '.' ||
         c == '_' || c == '~';
}
static bool is_sub_delim(unsigned char c) {
  return c == '!' || c == '$' || c == '&' || c == '\'' || c == '(' ||
         c == ')' || c == '*' || c == '+' || c == ',' || c == ';' ||
         c == '=';
}

/* A percent-encoding run at text[i] (must start with '%'). */
static bool pct_ok(const char *text, size_t len, size_t i) {
  return i + 2 < len && is_hex((unsigned char)text[i + 1]) &&
         is_hex((unsigned char)text[i + 2]);
}

/* Validate a run of pchar-ish characters over [i, end): unreserved,
 * pct-encoded, sub-delims, plus the caller's extra allowed set.
 * Returns the advanced index, or SIZE_MAX on a bad byte. */
static size_t scan_chars(const char *text, size_t i, size_t end,
                         const char *extra) {
  while (i < end) {
    unsigned char c = (unsigned char)text[i];
    if (c == '%') {
      if (!pct_ok(text, end, i))
        return SIZE_MAX;
      i += 3;
      continue;
    }
    if (is_unreserved(c) || is_sub_delim(c) ||
        (extra && strchr(extra, c))) {
      i++;
      continue;
    }
    return SIZE_MAX;
  }
  return i;
}

static void zero(zurl *out) { memset(out, 0, sizeof(*out)); }

bool zurl_parse_n(const char *text, size_t len, zurl *out) {
  if (!out)
    return false;
  zero(out);
  if (!text || len == 0)
    return false;

  /* scheme */
  size_t i = 0;
  if (!is_alpha((unsigned char)text[0]))
    return false;
  i = 1;
  while (i < len &&
         (is_alpha((unsigned char)text[i]) ||
          is_digit((unsigned char)text[i]) || text[i] == '+' ||
          text[i] == '-' || text[i] == '.'))
    i++;
  if (i >= len || text[i] != ':')
    return false;
  out->scheme = (zurl_span){0, i};
  i++; /* past ':' */

  /* hier part: authority form or a bare path */
  size_t path_start;
  if (len - i >= 2 && text[i] == '/' && text[i + 1] == '/') {
    out->has_authority = true;
    i += 2;
    size_t auth_start = i;
    /* authority ends at '/', '?', '#', or end */
    while (i < len && text[i] != '/' && text[i] != '?' && text[i] != '#')
      i++;
    size_t auth_end = i;

    /* userinfo: everything before the last '@' (an '@' in userinfo
     * would need pct-encoding; take the last so hosts may not hide).
     * An empty authority (e.g. "file:///path") is grammar-legal and
     * yields an empty host span with no userinfo or port. */
    size_t host_start = auth_start;
    for (size_t k = auth_start; k < auth_end; k++)
      if (text[k] == '@')
        host_start = k + 1;
    if (host_start != auth_start) {
      out->has_userinfo = true;
      out->userinfo =
          (zurl_span){auth_start, host_start - auth_start - 1};
      if (scan_chars(text, auth_start, host_start - 1, ":") ==
          SIZE_MAX)
        return false;
    }

    /* host [":" port] */
    size_t host_end = auth_end;
    bool has_port = false;
    zurl_span port_span = {0, 0};
    if (host_start == auth_end) {
      /* empty authority: nothing more to parse */
    } else if (text[host_start] == '[') {
      const char *close = memchr(text + host_start, ']', auth_end - host_start);
      if (!close)
        return false;
      host_end = (size_t)(close - text) + 1;
      out->host_is_ip_literal = true;
      /* literal body: hex digits, ':', '.', and zone id "%..." */
      for (size_t k = host_start + 1; k + 1 < host_end; k++) {
        unsigned char c = (unsigned char)text[k];
        if (!(is_hex(c) || c == ':' || c == '.'))
          return false;
      }
      if (host_end < auth_end && text[host_end] == ':') {
        has_port = true;
        port_span = (zurl_span){host_end + 1, auth_end - host_end - 1};
      } else if (host_end != auth_end) {
        return false;
      }
    } else {
      /* port is after the last ':' if that ':' is single (reg-names
       * contain no ':'; any ':' here starts the port) */
      for (size_t k = host_start; k < auth_end; k++)
        if (text[k] == ':') {
          if (has_port)
            return false; /* second colon */
          has_port = true;
          port_span = (zurl_span){k + 1, auth_end - k - 1};
          host_end = k;
        }
      if (host_end == host_start)
        return false; /* empty host */
      /* IPv4? digits and dots only, 4 octets 0..255 */
      bool maybe4 = true;
      for (size_t k = host_start; k < host_end; k++)
        if (!is_digit((unsigned char)text[k]) && text[k] != '.')
          maybe4 = false;
      if (maybe4) {
        unsigned octets = 0;
        size_t k = host_start;
        while (k < host_end) {
          size_t d0 = k;
          unsigned v = 0;
          while (k < host_end && is_digit((unsigned char)text[k])) {
            v = v * 10 + (unsigned)(text[k] - '0');
            if (v > 255 || k - d0 >= 3)
              return false;
            k++;
          }
          if (k == d0)
            return false; /* empty octet */
          octets++;
          if (k < host_end && text[k] == '.')
            k++;
        }
        if (octets != 4)
          return false;
        out->host_is_ipv4 = true;
      } else {
        /* reg-name */
        if (scan_chars(text, host_start, host_end, NULL) ==
            SIZE_MAX)
          return false;
      }
    }
    out->host = (zurl_span){host_start, host_end - host_start};

    if (has_port) {
      out->has_port = true;
      unsigned v = 0;
      for (size_t k = port_span.off; k < port_span.off + port_span.len;
           k++) {
        if (!is_digit((unsigned char)text[k]))
          return false;
        v = v * 10 + (unsigned)(text[k] - '0');
        if (v > 65535)
          return false;
      }
      out->port = (uint16_t)v;
    }
    path_start = i;
    /* path-abempty: empty or begins with '/' */
  } else {
    path_start = i;
  }

  /* path: up to '?', '#', or end */
  size_t path_end = path_start;
  while (path_end < len && text[path_end] != '?' && text[path_end] != '#')
    path_end++;
  out->path = (zurl_span){path_start, path_end - path_start};
  /* path characters: pchar + '/' */
  if (scan_chars(text, path_start, path_end, ":@/") == SIZE_MAX)
    return false;
  /* without an authority the path cannot begin with "//" */
  if (!out->has_authority && out->path.len >= 2 &&
      text[path_start] == '/' && text[path_start + 1] == '/')
    return false;

  i = path_end;
  if (i < len && text[i] == '?') {
    out->has_query = true;
    size_t qs = ++i;
    while (i < len && text[i] != '#')
      i++;
    out->query = (zurl_span){qs, i - qs};
    if (scan_chars(text, qs, i, ":@/?") == SIZE_MAX)
      return false;
  }
  if (i < len && text[i] == '#') {
    out->has_fragment = true;
    size_t fs = ++i;
    out->fragment = (zurl_span){fs, len - fs};
    if (scan_chars(text, fs, len, ":@/?") == SIZE_MAX)
      return false;
    i = len; /* fragment runs to end of input */
  }
  return i == len;
}

bool zurl_parse(const char *text, zurl *out) {
  if (!text) {
    if (out)
      zero(out);
    return false;
  }
  return zurl_parse_n(text, strlen(text), out);
}

size_t zurl_copy(const char *text, const zurl_span *span, char *out,
                 size_t cap) {
  if (!text || !span)
    return SIZE_MAX;
  for (size_t k = 0; k < span->len; k++) {
    if (out && k < cap)
      out[k] = text[span->off + k];
  }
  return span->len;
}

bool zurl_scheme_is(const zurl *u, const char *text,
                    const char *lower) {
  if (!u || !text || !lower)
    return false;
  size_t n = strlen(lower);
  if (u->scheme.len != n)
    return false;
  for (size_t k = 0; k < n; k++) {
    char c = text[u->scheme.off + k];
    if (c >= 'A' && c <= 'Z')
      c = (char)(c - 'A' + 'a');
    if (c != lower[k])
      return false;
  }
  return true;
}
