/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Shared formatting utilities for controllers and views.
 * Centralizes html_escape, time formatting, ZCL amount formatting,
 * and string validation to eliminate duplication across controllers. */

#ifndef ZCL_VIEWS_FORMAT_HELPERS_H
#define ZCL_VIEWS_FORMAT_HELPERS_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <inttypes.h>

#define ZATOSHI_PER_ZCL 100000000LL

/* Format UTC timestamp as "YYYY-MM-DD HH:MM:SS UTC". */
void zcl_format_time(char *buf, size_t max, int64_t timestamp);

/* Format zatoshi amount as "X.YYYYYYYY" ZCL string (8 decimals). */
void zcl_format_zcl(char *buf, size_t max, int64_t zatoshi);

/* Format zatoshi as "X.Y…" ZCL, dropping trailing zeros but never below
 * min_decimals places. Exact integer arithmetic (no double rounding).
 * Backs zcl_format_zcl_short (min 4) and the store price display (min 2). */
void zcl_format_zcl_trimmed(char *buf, size_t max, int64_t zatoshi,
                            int min_decimals);

/* Format zatoshi as short "X.YYYY" (4 decimals, trailing zeros trimmed).
 * Use for dashboard/history display. Full precision on detail pages. */
void zcl_format_zcl_short(char *buf, size_t max, int64_t zatoshi);

/* Check if string is all hex digits of given length. */
bool zcl_is_all_hex(const char *s, size_t len);

/* Combined check: s is non-NULL, strlen(s) == expected_len, and every
 * byte is [0-9a-fA-F]. Use for txid / blockhash / sha3-256 controller
 * inputs where the canonical hash is exactly `expected_len` hex chars. */
bool zcl_is_hex_string(const char *s, size_t expected_len);

/* Check if non-empty string contains only decimal digits. */
bool zcl_is_all_digits(const char *s);

/* Naive JSON string extraction: find "key":"value" and copy value to out.
 * Validates closing quote. Returns false if key not found or malformed. */
bool zcl_json_extract_str(const char *json, const char *key,
                          char *out, size_t outmax);

/* Naive JSON integer extraction. Returns false if key not found. */
bool zcl_json_extract_int(const char *json, const char *key, int64_t *out);

/* Naive JSON real extraction. Returns false if key not found. */
bool zcl_json_extract_real(const char *json, const char *key, double *out);

/* Return-value convenience wrappers over the out-param zcl_json_extract_*
 * helpers, for call sites that prefer a default on a missing key.
 * int wrapper returns -1 on miss; real wrapper returns 0.0 on miss. */
static inline int64_t zcl_json_int(const char *json, const char *key)
{
    int64_t v = -1;
    zcl_json_extract_int(json, key, &v);
    return v;
}

static inline double zcl_json_real(const char *json, const char *key)
{
    double v = 0.0;
    zcl_json_extract_real(json, key, &v);
    return v;
}

/* Integer power of ten (10^n) for token-decimal scaling. n must be >= 0. */
static inline int64_t zcl_pow10(int n)
{
    int64_t p = 1;
    for (int i = 0; i < n; i++) p *= 10;
    return p;
}

#endif
