/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: RFC 4648 Base64 encode/decode for C23 — strict, allocation-free,
 *          with caller-provided buffers and exact size arithmetic.
 *
 * Design notes:
 *  - Two alphabets, kept strictly separate: the standard alphabet (with
 *    canonical '=' padding, required) and the URL-safe alphabet (padding
 *    optional on decode). A mixed-alphabet input is rejected; whitespace
 *    is never skipped — this is a data format, not a text filter.
 *  - Decode validates before writing past the current position, so a
 *    rejected input never leaves partial output bytes beyond *out_len.
 *  - No allocation, no global state, constant-time is NOT a goal (this is
 *    an encoding, not a secret-handling codec).
 */
#ifndef ZBASE64_H
#define ZBASE64_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Exact encoded length (with padding) for len input bytes. */
size_t zbase64_encode_len(size_t len);

/* Worst-case decoded size for an encoded input of len characters
 * (callers may pass a larger cap; decode reports the true length). */
size_t zbase64_decode_cap(size_t len);

/* Encode in[0..len) into out (capacity cap). out is NUL-terminated on
 * success. Returns false only when cap < zbase64_encode_len(len) + 1. */
bool zbase64_encode(const uint8_t *in, size_t len, char *out, size_t cap);
bool zbase64url_encode(const uint8_t *in, size_t len, char *out,
                       size_t cap);

/* Strictly decode in[0..len) into out (capacity cap), storing the decoded
 * length at *out_len. zbase64_decode requires canonical standard-alphabet
 * input with exact padding; zbase64url_decode requires the URL-safe
 * alphabet and accepts omitted padding. Both reject whitespace, foreign
 * characters, mixed alphabets, non-canonical padding, and leftover bits
 * that are not zero (no silent truncation of malformed data). */
bool zbase64_decode(const char *in, size_t len, uint8_t *out, size_t cap,
                    size_t *out_len);
bool zbase64url_decode(const char *in, size_t len, uint8_t *out, size_t cap,
                       size_t *out_len);

#endif /* ZBASE64_H */
