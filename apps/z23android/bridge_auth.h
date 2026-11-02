/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZAPP_BRIDGE_AUTH_H
#define ZAPP_BRIDGE_AUTH_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
/* Bridge protocol 2: mutual authentication keyed by the pairing secret, which never crosses the wire.
 *   host  -> app   {"v":2,"nonce":NS}                    NS: 32 fresh random bytes as 64 hex digits
 *   app   -> host  {"v":2,"nonce":NC}                    NC: 32 fresh random bytes
 *   host  -> app   TAG {"v":2}                           TAG over "server", NS, NC; the app checks it first
 *   app   -> host  TAG REQUEST                           TAG over "client", NS, NC, SHA3-256(REQUEST)
 *   host  -> app   TAG LINE, one per line, the last is the final reply
 *                                                        TAG over "line", NS, NC, SHA3-256(REQUEST), index, LINE
 * TAG is 64 lowercase hex digits and a space precedes the line. HMAC-SHA3-256 keyed by the secret. */
#define ZAPP_AUTH_VERSION 2
#define ZAPP_AUTH_HEX 64
struct zapp_auth {
    unsigned char key[32], ns[32], nc[32], rd[32];
    uint64_t seq;
};
bool zapp_auth_random(unsigned char *out, size_t size);
/* Takes the 64-digit lowercase hex pairing secret; clears nonces, request digest and index. */
bool zapp_auth_start(struct zapp_auth *auth, const char *secret_hex);
void zapp_auth_wipe(struct zapp_auth *auth);
void zapp_auth_hex(const unsigned char *in, size_t size, char *out); /* out holds 2 * size + 1 */
bool zapp_auth_unhex(const char *hex, size_t size, unsigned char *out); /* lowercase, exactly 2 * size digits */
void zapp_auth_bind(struct zapp_auth *auth, const void *request, size_t size);
/* Writes "TAG LINE" without a terminator; out holds ZAPP_AUTH_HEX + 2 + size bytes. */
size_t zapp_auth_seal(const struct zapp_auth *auth, const char *label, uint64_t index,
                      const char *line, size_t size, char *out);
/* The line of a frame whose tag verifies, or NULL. Constant-time comparison. */
const char *zapp_auth_open(const struct zapp_auth *auth, const char *label, uint64_t index, const char *frame);

/* The request frame: binds the digest of the request, then seals or opens it under "client". */
size_t zapp_auth_seal_request(struct zapp_auth *auth, const char *request, size_t size, char *out);
const char *zapp_auth_open_request(struct zapp_auth *auth, const char *frame);
#endif
