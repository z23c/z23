/* zpem — PEM armor (RFC 7468) over DER bytes
 *
 * Apache-2.0 licensed. C23, freestanding-friendly, no allocation.
 *
 * PEM frames binary data as:
 *
 *     -----BEGIN LABEL-----
 *     <base64, 64 chars per line>
 *     -----END LABEL-----
 *
 * Labels are 1..32 chars from [A-Z0-9 -], never starting or ending
 * with a space or hyphen ("CERTIFICATE", "PRIVATE KEY", "EC
 * PARAMETERS"). The parser is strict: markers must match exactly,
 * labels must agree, and the base64 body is validated by zbase64's
 * strict decoder after line-ending removal. Only CR and LF are
 * tolerated inside the body; any other whitespace or character is
 * rejected.
 *
 * Parsing reports the exact bytes consumed so callers can walk
 * multi-block PEM files by advancing over consecutive blocks.
 * Decoding uses a caller-provided scratch buffer for the stripped
 * base64 text; no heap.
 */
#ifndef ZPEM_H
#define ZPEM_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ZPEM_MAX_LABEL 32u

typedef enum {
  ZPEM_OK = 0,
  ZPEM_ERR_ARG = 1,     /* NULL argument */
  ZPEM_ERR_RANGE = 2,   /* label over ZPEM_MAX_LABEL or size overflow */
  ZPEM_ERR_CAP = 3,     /* output or scratch buffer too small */
  ZPEM_ERR_FORMAT = 4,  /* bad markers, label mismatch, truncation */
  ZPEM_ERR_LABEL = 5,   /* illegal label characters */
  ZPEM_ERR_BASE64 = 6   /* body failed strict base64 validation */
} zpem_err;

typedef struct {
  const char *label;  /* points into the parsed input */
  size_t label_len;
  const char *b64;    /* body region, line endings included */
  size_t b64_len;
  size_t consumed;    /* total bytes of this block, incl. final EOL */
} zpem_block;

/* Exact encoded size for der_len bytes under a label of label_len,
 * or 0 on ZPEM_ERR_RANGE. */
size_t zpem_encoded_len(size_t der_len, size_t label_len);

/* Encode der into out (capacity cap) with 64-column lines and a
 * trailing newline. On success stores the byte count in *out_len. */
zpem_err zpem_encode(const char *label, size_t label_len,
                     const uint8_t *der, size_t der_len,
                     char *out, size_t cap, size_t *out_len);

/* Strictly parse the block at the start of pem[0..n) into *blk.
 * Truncation and malformed input both report ZPEM_ERR_FORMAT. */
zpem_err zpem_parse(const char *pem, size_t n, zpem_block *blk);

/* Decode a parsed block. scratch (capacity scratch_cap) must hold
 * blk->b64_len bytes; der_out (capacity der_cap) receives the DER
 * bytes and *der_len their count. */
zpem_err zpem_decode(const zpem_block *blk, char *scratch, size_t scratch_cap,
                     uint8_t *der_out, size_t der_cap, size_t *der_len);

/* One-shot convenience: parse the block at pem[0..n) and decode it.
 * On success *consumed (if non-NULL) reports the block's wire bytes. */
zpem_err zpem_read(const char *pem, size_t n, char *scratch, size_t scratch_cap,
                   uint8_t *der_out, size_t der_cap, size_t *der_len,
                   zpem_block *blk);

const char *zpem_err_str(zpem_err e);

#ifdef __cplusplus
}
#endif

#endif /* ZPEM_H */
