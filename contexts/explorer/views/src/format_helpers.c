/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "views/format_helpers.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <time.h>

void zcl_format_time(char *buf, size_t max, int64_t timestamp)
{
    if (!buf || max == 0) return;
    buf[0] = '\0';
    if (timestamp <= 0) return;
    time_t t = (time_t)timestamp;
    struct tm tm;
    if (!gmtime_r(&t, &tm)) return;
    strftime(buf, max, "%Y-%m-%d %H:%M:%S UTC", &tm);
}

void zcl_format_zcl(char *buf, size_t max, int64_t zatoshi)
{
    int64_t whole, frac;
    if (zatoshi < 0) {
        whole = (-zatoshi) / ZATOSHI_PER_ZCL;
        frac = (-zatoshi) % ZATOSHI_PER_ZCL;
        snprintf(buf, max, "-%" PRId64 ".%08" PRId64, whole, frac);
    } else {
        whole = zatoshi / ZATOSHI_PER_ZCL;
        frac = zatoshi % ZATOSHI_PER_ZCL;
        snprintf(buf, max, "%" PRId64 ".%08" PRId64, whole, frac);
    }
}

void zcl_format_zcl_trimmed(char *buf, size_t max, int64_t zatoshi,
                            int min_decimals)
{
    char full[32];
    zcl_format_zcl(full, sizeof(full), zatoshi);
    char *dot = strchr(full, '.');
    if (dot && strlen(dot) > (size_t)(min_decimals + 1)) {
        /* Drop trailing zeros, but never below min_decimals places. */
        int last_nonzero = min_decimals;
        for (int i = 8; i > min_decimals; i--)
            if (dot[i] != '0') { last_nonzero = i; break; }
        dot[last_nonzero + 1] = '\0';
    }
    snprintf(buf, max, "%s", full);
}

void zcl_format_zcl_short(char *buf, size_t max, int64_t zatoshi)
{
    zcl_format_zcl_trimmed(buf, max, zatoshi, 4);
}

bool zcl_is_all_hex(const char *s, size_t len)
{
    for (size_t i = 0; i < len; i++)
        if (!isxdigit((unsigned char)s[i])) return false;
    return true;
}

bool zcl_is_hex_string(const char *s, size_t expected_len)
{
    return s && strlen(s) == expected_len && zcl_is_all_hex(s, expected_len);
}

bool zcl_is_all_digits(const char *s)
{
    if (!s || !*s) return false;
    for (const char *p = s; *p; p++)
        if (!isdigit((unsigned char)*p)) return false;
    return true;
}

bool zcl_json_extract_str(const char *json, const char *key,
                          char *out, size_t outmax)
{
    if (!json || !key || !out || outmax == 0) return false;
    char search[128];
    snprintf(search, sizeof(search), "\"%s\":", key);
    const char *p = strstr(json, search);
    if (!p) return false;
    p += strlen(search);
    while (*p == ' ') p++;
    if (*p != '"') return false;
    p++;
    size_t i = 0;
    while (p[i] && p[i] != '"' && i < outmax - 1) {
        out[i] = p[i]; i++;
    }
    out[i] = '\0';
    if (p[i] != '"') return false;
    return i > 0;
}

bool zcl_json_extract_int(const char *json, const char *key, int64_t *out)
{
    if (!json || !key || !out) return false;
    char search[128];
    snprintf(search, sizeof(search), "\"%s\":", key);
    const char *p = strstr(json, search);
    if (!p) return false;
    p += strlen(search);
    while (*p == ' ') p++;
    char *end = NULL;
    *out = strtoll(p, &end, 10);
    return end != p;
}

bool zcl_json_extract_real(const char *json, const char *key, double *out)
{
    if (!json || !key || !out) return false;
    char search[128];
    snprintf(search, sizeof(search), "\"%s\":", key);
    const char *p = strstr(json, search);
    if (!p) return false;
    p += strlen(search);
    while (*p == ' ') p++;
    char *end = NULL;
    *out = strtod(p, &end);
    return end != p;
}
