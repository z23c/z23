/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * base64url, RFC 4648 §5, unpadded — the encoding every ACME field uses.
 *
 * This lives in the node's own lib/net, apart from the rest of the ACME
 * machinery, because the node genuinely needs it: the TLS-ALPN-01 responder
 * (net/acme_challenge.h) builds a key authorization, and that is a base64url
 * string. It is a pure byte codec — no keys, no sockets, no CA — so it is
 * the one piece of the ACME vocabulary that belongs on both sides of the
 * node / certificate-worker boundary.
 *
 * Written out rather than driven through OpenSSL's EVP base64 BIO: the EVP
 * encoder emits the standard alphabet with padding and line breaks, so every
 * call would need three fixups, and its decoder is lenient about characters
 * an ACME field must reject.
 */

#ifndef ZCL_NET_ACME_B64URL_H
#define ZCL_NET_ACME_B64URL_H

#include <stdbool.h>
#include <stddef.h>

/* Encoded length of `len` input bytes, excluding the NUL terminator. */
size_t acme_b64url_encoded_len(size_t len);

/* Encode into `out`. Returns the encoded length (excluding NUL), or 0 when
 * the output buffer cannot hold the result plus its NUL. Encoding zero bytes
 * succeeds and yields the empty string, which is also a length of 0 — check
 * the output buffer, not the return, when len may be 0. */
size_t acme_b64url_encode(const void *data, size_t len, char *out, size_t out_len);

/* Decode NUL-terminated unpadded base64url. Rejects '+', '/', '=' and any
 * other byte outside the RFC 4648 §5 alphabet, and rejects a length ≡ 1
 * (mod 4), which encodes no whole byte. */
bool acme_b64url_decode(const char *text, void *out, size_t out_len,
                        size_t *decoded);

#endif /* ZCL_NET_ACME_B64URL_H */
