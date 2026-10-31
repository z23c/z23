/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: UTF-8 well-formedness and tag character checks for Clips text fields. */

#include "clips_internal.h"

static bool clips_text_ascii_ok(uint8_t c)
{
    return (c >= 0x20u || c == 0x0au) && c != 0x7fu;
}

static bool clips_text_lead(uint8_t c, size_t *extra, uint32_t *min)
{
    if (c >= 0xc2u && c <= 0xdfu) {
        *extra = 1;
        *min = 0x80u;
        return true;
    }
    if (c >= 0xe0u && c <= 0xefu) {
        *extra = 2;
        *min = 0x800u;
        return true;
    }
    if (c >= 0xf0u && c <= 0xf4u) {
        *extra = 3;
        *min = 0x10000u;
        return true;
    }
    return false;
}

static bool clips_text_continuations(const uint8_t *s, size_t n, size_t i, size_t extra)
{
    if (extra > n - i - 1)
        return false;
    for (size_t k = 1; k <= extra; k++) {
        if ((s[i + k] & 0xc0u) != 0x80u)
            return false;
    }
    return true;
}

static uint32_t clips_text_code_point(const uint8_t *s, size_t i, size_t extra)
{
    uint32_t cp = s[i] & (0x3fu >> extra);

    for (size_t k = 1; k <= extra; k++)
        cp = (cp << 6) | (s[i + k] & 0x3fu);
    return cp;
}

static bool clips_text_multibyte(const uint8_t *s, size_t n, size_t i, size_t *step)
{
    size_t extra = 0;
    uint32_t min = 0;
    uint32_t cp = 0;

    if (!clips_text_lead(s[i], &extra, &min))
        return false;
    if (!clips_text_continuations(s, n, i, extra))
        return false;
    cp = clips_text_code_point(s, i, extra);
    if (cp < min || cp > 0x10ffffu || (cp >= 0xd800u && cp <= 0xdfffu))
        return false;
    if (cp >= 0x80u && cp <= 0x9fu)
        return false;
    *step = extra + 1;
    return true;
}

static bool clips_text_char(const uint8_t *s, size_t n, size_t i, size_t *step)
{
    if (s[i] < 0x80u) {
        *step = 1;
        return clips_text_ascii_ok(s[i]);
    }
    return clips_text_multibyte(s, n, i, step);
}

/* Well-formed UTF-8 with no control characters except LF. Normalization to
 * NFC is not checked here: no normalization table is in-tree. */
bool clips_text_wellformed(const uint8_t *s, size_t n)
{
    size_t i = 0;

    while (i < n) {
        size_t step = 0;
        if (!clips_text_char(s, n, i, &step))
            return false;
        i += step;
    }
    return true;
}

static bool clips_tag_char(uint8_t c)
{
    return (c >= 0x61u && c <= 0x7au) || (c >= 0x30u && c <= 0x39u) || c == 0x5fu;
}

bool clips_tag_valid(const uint8_t *t, size_t n)
{
    if (n == 0)
        return false;
    for (size_t i = 0; i < n; i++) {
        if (!clips_tag_char(t[i]))
            return false;
    }
    return true;
}
