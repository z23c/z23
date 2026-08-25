/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * evidence_ledger_row — see services/evidence_ledger_row.h for the contract
 * and for why the bounded tail read lives in exactly one place. Pure reader:
 * no allocation, no clock, no globals, no threads. */

// one-result-type-ok:evidence-ledger-row-pure-reader
//
// A pure parsing/IO-read helper, not a fallible service executor. Every
// "false" returned here means the CALLER passed bad arguments or the field is
// absent; a missing or unreadable ledger is data (no rows scanned), never an
// error a caller branches on.

#include "services/evidence_ledger_row.h"

#include "util/log_macros.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void evidence_copy_bounded(char *dst, size_t cap, const char *src, size_t len)
{
    if (!dst || cap == 0)
        return;
    if (!src)
        len = 0;
    if (len >= cap)
        len = cap - 1;
    if (len)
        memcpy(dst, src, len);
    dst[len] = '\0';
}

const char *evidence_find_sub(const char *hay, size_t len, const char *needle)
{
    if (!hay || !needle)
        return NULL;
    size_t nlen = strlen(needle);
    if (nlen == 0 || nlen > len)
        return NULL;
    for (size_t i = 0; i + nlen <= len; i++) {
        if (memcmp(hay + i, needle, nlen) == 0)
            return hay + i;
    }
    return NULL;
}

enum {
    EVIDENCE_FLAT_KEY_CAP = 64,
    EVIDENCE_ARRAY_OBJECT_KEY_CAP = 16
};

struct key_span {
    const char *at;
    size_t len;
};

static const char *row_ws(const char *p, const char *end)
{
    while (p < end && (*p == ' ' || *p == '\t' || *p == '\r'))
        p++;
    return p;
}

static bool row_hex(char c)
{
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
           (c >= 'A' && c <= 'F');
}

/* Skip one valid JSON string. Keys set reject_escape because ledger field
 * names are fixed ASCII tokens; accepting an escaped spelling would make
 * duplicate-key comparison ambiguous. */
static bool row_skip_string(const char **pp, const char *end,
                            const char **content, size_t *content_len,
                            bool reject_escape)
{
    const char *p = *pp;
    if (p >= end || *p != '"')
        return false; // raw-return-ok:pure-flat-row-predicate
    p++;
    const char *start = p;
    while (p < end && *p != '"') {
        unsigned char c = (unsigned char)*p;
        if (c < 0x20)
            return false; // raw-return-ok:pure-flat-row-predicate
        if (*p == '\\') {
            if (reject_escape)
                return false; // raw-return-ok:pure-flat-row-predicate
            p++;
            if (p >= end)
                return false; // raw-return-ok:pure-flat-row-predicate
            if (*p == 'u') {
                for (unsigned i = 0; i < 4; i++) {
                    p++;
                    if (p >= end || !row_hex(*p))
                        return false; // raw-return-ok:pure-flat-row-predicate
                }
            } else if (!strchr("\"\\/bfnrt", *p)) {
                return false; // raw-return-ok:pure-flat-row-predicate
            }
        }
        p++;
    }
    if (p >= end)
        return false; // raw-return-ok:pure-flat-row-predicate
    if (content)
        *content = start;
    if (content_len)
        *content_len = (size_t)(p - start);
    *pp = p + 1;
    return true;
}

static bool row_skip_scalar(const char **pp, const char *end)
{
    const char *p = *pp;
    if (p >= end)
        return false; // raw-return-ok:pure-flat-row-predicate
    if (*p == '"') {
        if (!row_skip_string(&p, end, NULL, NULL, false))
            return false; // raw-return-ok:pure-flat-row-predicate
    } else if ((size_t)(end - p) >= 4 && memcmp(p, "true", 4) == 0) {
        p += 4;
    } else if ((size_t)(end - p) >= 5 && memcmp(p, "false", 5) == 0) {
        p += 5;
    } else if ((size_t)(end - p) >= 4 && memcmp(p, "null", 4) == 0) {
        p += 4;
    } else {
        if (*p == '-')
            p++;
        if (p >= end || *p < '0' || *p > '9')
            return false; // raw-return-ok:pure-flat-row-predicate
        if (*p == '0') {
            p++;
        } else {
            while (p < end && *p >= '0' && *p <= '9')
                p++;
        }
    }
    *pp = p;
    return true;
}

/* The tip-agreement recorder's disagreeing_hashes field is an array of
 * {height,hash,peers} objects. Accept exactly that bounded structural class:
 * flat objects with unique ASCII keys and scalar values. No object may nest
 * another container, and the fixed key cap bounds stack and comparison work. */
static bool row_skip_array_object(const char **pp, const char *end)
{
    const char *p = *pp;
    if (p >= end || *p != '{')
        return false; // raw-return-ok:pure-flat-row-predicate
    p = row_ws(p + 1, end);
    if (p < end && *p == '}') {
        *pp = p + 1;
        return true;
    }

    struct key_span keys[EVIDENCE_ARRAY_OBJECT_KEY_CAP];
    size_t key_count = 0;
    for (;;) {
        const char *key_at = NULL;
        size_t key_len = 0;
        if (!row_skip_string(&p, end, &key_at, &key_len, true) ||
            key_len == 0 || key_count >= EVIDENCE_ARRAY_OBJECT_KEY_CAP)
            return false; // raw-return-ok:pure-flat-row-predicate
        for (size_t i = 0; i < key_count; i++) {
            if (keys[i].len == key_len &&
                memcmp(keys[i].at, key_at, key_len) == 0)
                return false; // raw-return-ok:pure-flat-row-predicate
        }
        keys[key_count++] = (struct key_span){ key_at, key_len };
        p = row_ws(p, end);
        if (p >= end || *p != ':')
            return false; // raw-return-ok:pure-flat-row-predicate
        p = row_ws(p + 1, end);
        if (!row_skip_scalar(&p, end))
            return false; // raw-return-ok:pure-flat-row-predicate
        p = row_ws(p, end);
        if (p < end && *p == ',') {
            p = row_ws(p + 1, end);
            continue;
        }
        if (p >= end || *p != '}')
            return false; // raw-return-ok:pure-flat-row-predicate
        *pp = p + 1;
        return true;
    }
}

static bool row_skip_value(const char **pp, const char *end)
{
    const char *p = *pp;
    if (p >= end)
        return false; // raw-return-ok:pure-flat-row-predicate
    if (*p != '[')
        return row_skip_scalar(pp, end);

    p = row_ws(p + 1, end);
    if (p < end && *p == ']') {
        *pp = p + 1;
        return true;
    }
    for (;;) {
        if (p < end && *p == '{') {
            if (!row_skip_array_object(&p, end))
                return false; // raw-return-ok:pure-flat-row-predicate
        } else if (!row_skip_scalar(&p, end)) {
            return false; // raw-return-ok:pure-flat-row-predicate
        }
        p = row_ws(p, end);
        if (p < end && *p == ',') {
            p = row_ws(p + 1, end);
            continue;
        }
        if (p >= end || *p != ']')
            return false; // raw-return-ok:pure-flat-row-predicate
        *pp = p + 1;
        return true;
    }
}

/* Validate the WHOLE object while finding an exact top-level key. This is
 * intentionally not substring search: a string value containing `"ts":1`
 * must never masquerade as the real timestamp field. */
static bool row_scan_object(const char *row, size_t len, const char *want,
                            const char **value, bool *found)
{
    if (value)
        *value = NULL;
    if (found)
        *found = false;
    if (!row)
        return false; // raw-return-ok:pure-flat-row-predicate
    const char *p = row_ws(row, row + len);
    const char *end = row + len;
    if (p >= end || *p != '{')
        return false; // raw-return-ok:pure-flat-row-predicate
    p = row_ws(p + 1, end);
    if (p < end && *p == '}')
        return row_ws(p + 1, end) == end;

    struct key_span keys[EVIDENCE_FLAT_KEY_CAP];
    size_t key_count = 0;
    for (;;) {
        const char *key_at = NULL;
        size_t key_len = 0;
        if (!row_skip_string(&p, end, &key_at, &key_len, true) ||
            key_len == 0 || key_count >= EVIDENCE_FLAT_KEY_CAP)
            return false; // raw-return-ok:pure-flat-row-predicate
        for (size_t i = 0; i < key_count; i++) {
            if (keys[i].len == key_len &&
                memcmp(keys[i].at, key_at, key_len) == 0)
                return false; // raw-return-ok:pure-flat-row-predicate
        }
        keys[key_count++] = (struct key_span){ key_at, key_len };
        p = row_ws(p, end);
        if (p >= end || *p != ':')
            return false; // raw-return-ok:pure-flat-row-predicate
        p = row_ws(p + 1, end);
        const char *value_at = p;
        if (!row_skip_value(&p, end))
            return false; // raw-return-ok:pure-flat-row-predicate
        if (want && strlen(want) == key_len &&
            memcmp(want, key_at, key_len) == 0) {
            if (value)
                *value = value_at;
            if (found)
                *found = true;
        }
        p = row_ws(p, end);
        if (p < end && *p == ',') {
            p = row_ws(p + 1, end);
            continue;
        }
        if (p >= end || *p != '}')
            return false; // raw-return-ok:pure-flat-row-predicate
        return row_ws(p + 1, end) == end;
    }
}

bool evidence_row_flat_object_valid(const char *row, size_t len)
{
    return row_scan_object(row, len, NULL, NULL, NULL);
}

static const char *row_value(const char *row, size_t len, const char *key)
{
    const char *value = NULL;
    bool found = false;
    if (!key || !row_scan_object(row, len, key, &value, &found))
        return NULL;
    return found ? value : NULL;
}

/* A primitive is evidence only when its whole token ended.  Without this
 * check `100x` becomes timestamp 100 and `truex` becomes true, which lets a
 * torn or foreign row manufacture a plausible sample. */
static bool row_token_ended(const char *at, const char *end)
{
    while (at < end && (*at == ' ' || *at == '\t' || *at == '\r'))
        at++;
    return at == end || *at == ',' || *at == '}';
}

bool evidence_row_str(const char *row, size_t len, const char *key,
                      char *dst, size_t cap)
{
    if (dst && cap)
        dst[0] = '\0';
    const char *at = row_value(row, len, key);
    if (!at || *at != '"')
        return false;
    at++;
    const char *end = row + len;
    size_t n = 0;
    while (at < end && *at != '"') {
        char c = *at;
        if (c == '\\' && at + 1 < end) {
            at++;
            c = *at;
            if (c == 'n' || c == 't' || c == 'r')
                c = ' ';
        }
        if (dst && cap && n + 1 < cap)
            dst[n++] = c;
        at++;
    }
    if (dst && cap)
        dst[n < cap ? n : cap - 1] = '\0';
    return at < end && row_token_ended(at + 1, end);
}

bool evidence_row_int(const char *row, size_t len, const char *key,
                      int64_t *out)
{
    const char *at = row_value(row, len, key);
    if (!at)
        return false;
    const char *end = row + len;
    bool neg = false;
    if (*at == '-') {
        neg = true;
        at++;
    }
    if (at >= end || *at < '0' || *at > '9')
        return false;
    int64_t v = 0;
    while (at < end && *at >= '0' && *at <= '9') {
        if (v > (INT64_MAX - (*at - '0')) / 10)
            return false;
        v = v * 10 + (*at - '0');
        at++;
    }
    if (!row_token_ended(at, end))
        return false; // raw-return-ok:pure-token-boundary-predicate
    if (out)
        *out = neg ? -v : v;
    return true;
}

bool evidence_row_bool(const char *row, size_t len, const char *key,
                       bool *out)
{
    const char *at = row_value(row, len, key);
    if (!at)
        return false; // raw-return-ok:field-absence-predicate
    const char *end = row + len;
    bool value;
    size_t width;
    if ((size_t)(end - at) >= 4 && memcmp(at, "true", 4) == 0) {
        value = true;
        width = 4;
    } else if ((size_t)(end - at) >= 5 && memcmp(at, "false", 5) == 0) {
        value = false;
        width = 5;
    } else {
        return false; // raw-return-ok:field-type-predicate
    }
    if (!row_token_ended(at + width, end))
        return false; // raw-return-ok:pure-token-boundary-predicate
    if (out)
        *out = value;
    return true;
}

bool evidence_row_is_null(const char *row, size_t len, const char *key)
{
    const char *at = row_value(row, len, key);
    if (!at)
        return false; // raw-return-ok:field-absence-predicate
    const char *end = row + len;
    return (size_t)(end - at) >= 4 && memcmp(at, "null", 4) == 0 &&
           row_token_ended(at + 4, end);
}

bool evidence_ledger_scan_text(const char *text, size_t len,
                              evidence_row_fn fn, void *ctx)
{
    if (!fn)
        LOG_FAIL("evidence_ledger", "row callback is NULL");
    if (!text && len)
        LOG_FAIL("evidence_ledger", "ledger text is NULL with len=%zu", len);

    size_t i = 0;
    while (i < len) {
        size_t j = i;
        while (j < len && text[j] != '\n')
            j++;
        if (j > i)
            fn(text + i, j - i, ctx);
        i = (j < len) ? j + 1 : len;
    }
    return true;
}

bool evidence_ledger_scan_tail(const char *path, size_t tail_bytes,
                              evidence_row_fn fn, void *ctx,
                              unsigned *out_overlong, unsigned *out_incomplete)
{
    if (!fn)
        LOG_FAIL("evidence_ledger", "row callback is NULL");
    if (!path || !path[0])
        LOG_FAIL("evidence_ledger", "ledger path is NULL/empty");
    if (tail_bytes == 0)
        LOG_FAIL("evidence_ledger", "tail_bytes is 0 for '%s'", path);

    FILE *f = fopen(path, "rb");
    if (!f)
        return true;            /* absent ledger: no rows, not an error */

    /* Seek to the last tail_bytes so a rotated or very long ledger stays a
     * cheap read, then stream a row at a time. */
    bool partial_head = false;
    if (fseek(f, 0, SEEK_END) == 0) {
        long size = ftell(f);
        if (size > (long)tail_bytes) {
            if (fseek(f, size - (long)tail_bytes, SEEK_SET) == 0)
                partial_head = true;
            else
                rewind(f);
        } else {
            rewind(f);
        }
    }

    /* BYTE-COUNTED, NOT NUL-TERMINATED, and that is the whole point.
     *
     * This loop used to be fgets() + strlen(). strlen() stops at the first NUL
     * byte, and a NUL is exactly what a torn append leaves behind — the
     * filesystem allocated the block and the data never landed, so the row
     * reads back with a run of zeroes in the middle of otherwise perfect JSON.
     * fgets() had already consumed that whole physical line INCLUDING its
     * newline, but strlen() reported only the bytes before the NUL, so the
     * line looked unterminated: it was counted incomplete (right) and the
     * reader armed its consume-the-rest-of-the-line state (wrong — there was
     * no rest). The next fgets() returned the FOLLOWING line, a complete and
     * perfectly valid row, and it was swallowed as that phantom tail. One NUL
     * cost two rows, and the second loss was counted nowhere at all
     * (reproduced: valid / NUL / valid scanned 1 row, incomplete=1, and the
     * third row vanished silently).
     *
     * So row boundaries are decided by counting bytes to the next '\n' and
     * nothing else. A NUL is just a byte inside one row's content; it
     * disqualifies THAT row and cannot reach past its own newline. No
     * consume-the-tail state is needed either: the scan already stops at the
     * physical newline, so an overlong row or a post-seek fragment simply has
     * its surplus bytes dropped on the floor as they stream by, never folded
     * in as a second phantom row.
     *
     * The row buffer holds DATA bytes only — no newline, no NUL — because
     * nothing here needs a terminator: `fn` is handed (pointer, length). */
    char chunk[8192];
    char row[EVIDENCE_ROW_MAX];
    size_t rlen = 0;            /* data bytes of the current line, buffered */
    bool overlong = false;      /* this line has more than EVIDENCE_ROW_MAX */
    bool has_nul = false;       /* this line carries an embedded NUL byte */
    /* The first line after a mid-file seek is a fragment; dropping it is the
     * difference between describing evidence and inventing a sample. It is not
     * counted overlong: its true length is unknown, so calling it a malformed
     * row would invent a defect. It must also not cost the line after it. */
    bool fragment = partial_head;
    size_t got;

    while ((got = fread(chunk, 1, sizeof(chunk), f)) > 0) {
        size_t i = 0;
        while (i < got) {
            const char *nl = memchr(chunk + i, '\n', got - i);
            size_t seg = nl ? (size_t)(nl - (chunk + i)) : got - i;

            if (memchr(chunk + i, '\0', seg) != NULL)
                has_nul = true;
            if (rlen + seg > EVIDENCE_ROW_MAX) {
                overlong = true;
                if (rlen < EVIDENCE_ROW_MAX)
                    memcpy(row + rlen, chunk + i, EVIDENCE_ROW_MAX - rlen);
                rlen = EVIDENCE_ROW_MAX;
            } else if (seg) {
                memcpy(row + rlen, chunk + i, seg);
                rlen += seg;
            }
            i += seg;
            if (!nl)
                break;          /* the line continues into the next chunk */
            i++;                /* consume the newline itself */

            if (fragment) {
                fragment = false;
            } else if (overlong) {
                /* Longer than a row is allowed to be: corrupt or foreign
                 * content, counted malformed. */
                if (out_overlong)
                    (*out_overlong)++;
            } else if (has_nul) {
                /* Newline-terminated, so its length is known, but a NUL byte
                 * inside a flat JSON row means the bytes on disk are not what
                 * the recorder wrote. Counted with the torn appends rather
                 * than the malformed rows for the same reason: this is a write
                 * that did not all land, not a foreign row shape. It must
                 * never reach `fn` — every reader here treats the last row it
                 * was handed as authoritative for the per-sample fields. */
                if (out_incomplete)
                    (*out_incomplete)++;
            } else if (rlen > 0) {
                fn(row, rlen, ctx);
            }
            rlen = 0;
            overlong = false;
            has_nul = false;
        }
    }

    /* Whatever is left never met a newline: end of file mid-line. */
    if (rlen > 0 || overlong) {
        if (fragment) {
            /* a seek fragment that was also the whole tail: still not a row */
        } else if (overlong) {
            if (out_overlong)
                (*out_overlong)++;
        } else if (out_incomplete) {
            /* A torn append caught mid-write, or a truncated file. Not
             * malformed — the bytes may be a perfectly good row that is not
             * all there yet — and not a sample. */
            (*out_incomplete)++;
        }
    }
    fclose(f);
    return true;
}

bool evidence_ledger_resolve_path(const char *dir_env, const char *home_rel_dir,
                                 const char *file, char *out, size_t cap)
{
    if (!out || cap == 0)
        LOG_FAIL("evidence_ledger", "path output buffer is NULL/empty");
    out[0] = '\0';
    if (!dir_env || !dir_env[0])
        LOG_FAIL("evidence_ledger", "dir env var name is NULL/empty");
    if (!home_rel_dir || !home_rel_dir[0])
        LOG_FAIL("evidence_ledger", "home-relative dir is NULL/empty");
    if (!file || !file[0])
        LOG_FAIL("evidence_ledger", "ledger file name is NULL/empty");

    const char *dir = getenv(dir_env);
    if (dir && dir[0]) {
        if (snprintf(out, cap, "%s/%s", dir, file) >= (int)cap) {
            out[0] = '\0';
            LOG_FAIL("evidence_ledger", "%s path too long for buffer",
                     dir_env);
        }
        return true;
    }

    const char *home = getenv("HOME");
    if (!home || !home[0])
        LOG_FAIL("evidence_ledger",
                 "no %s and no HOME to resolve the %s ledger path from",
                 dir_env, file);
    if (snprintf(out, cap, "%s/%s/%s", home, home_rel_dir, file) >= (int)cap) {
        out[0] = '\0';
        LOG_FAIL("evidence_ledger", "default %s path too long for buffer",
                 file);
    }
    return true;
}
