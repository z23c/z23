/* znetstring — netstring framing codec (DJB netstrings)
 *
 * Apache-2.0 licensed. C23, freestanding-friendly, no allocation.
 *
 * A netstring frames a byte payload as ASCII:
 *
 *     <decimal length> ":" <payload bytes> ","
 *
 * Example: the payload "hello" is the 8-byte wire form "5:hello,".
 * The empty payload is "0:,". Length is written without leading
 * zeros; "03:abc," is invalid. This library encodes and strictly
 * parses single netstrings over caller-provided buffers. Parsing
 * reports the exact bytes consumed so callers can frame streams by
 * advancing over consecutive netstrings.
 */
#ifndef ZNETSTRING_H
#define ZNETSTRING_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef ZNETSTRING_MAX
#define ZNETSTRING_MAX 16777216u /* payload bytes (16 MiB) */
#endif

#define ZNETSTRING_MAX_DIGITS 10u /* decimal digits in a length field */

typedef enum {
  ZNETSTRING_OK = 0,
  ZNETSTRING_ERR_ARG = 1,   /* NULL argument */
  ZNETSTRING_ERR_RANGE = 2, /* payload length > ZNETSTRING_MAX or size overflow */
  ZNETSTRING_ERR_CAP = 3,   /* output buffer too small */
  ZNETSTRING_ERR_FORMAT = 4 /* bad digits, leading zero, missing ':' or ',' */
} znetstring_err;

typedef struct {
  const uint8_t *payload; /* points into the parsed buffer */
  size_t payload_len;     /* payload bytes */
  size_t consumed;        /* total wire bytes of this netstring */
} znetstring;

/* Exact wire size for a payload of n bytes, or 0 on ERR_RANGE. */
size_t znetstring_encoded_len(size_t n);

/* Encode payload into out (capacity cap). On success writes the wire
 * bytes and stores their count in *out_len. Output is not
 * NUL-terminated. */
znetstring_err znetstring_encode(const uint8_t *payload, size_t n,
                                 char *out, size_t cap, size_t *out_len);

/* Strictly parse one netstring at the start of buf[0..n). On success
 * *out describes the payload and the consumed wire bytes. A buffer
 * that ends before the netstring completes also reports
 * ZNETSTRING_ERR_FORMAT; use znetstring_prefix() to distinguish
 * truncation from malformed input when framing streams. */
znetstring_err znetstring_parse(const char *buf, size_t n, znetstring *out);

/* Returns 1 when buf holds a strict prefix of a valid netstring
 * (more bytes could complete it), 0 otherwise. Useful for stream
 * readers deciding whether to read more or fail. */
int znetstring_prefix(const char *buf, size_t n);

const char *znetstring_err_str(znetstring_err e);

#ifdef __cplusplus
}
#endif

#endif /* ZNETSTRING_H */
