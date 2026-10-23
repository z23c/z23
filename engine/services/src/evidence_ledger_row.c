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

/* The keys already seen in one object, bounded by its cap. */
struct key_set {
    struct key_span *span;
    size_t count;
    size_t cap;
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

/* Skip the escape that starts at the backslash *pp points to. On success *pp
 * is left on the escape's last byte, so the caller steps past it. */
static bool row_skip_escape(const char **pp, const char *end)
{
    const char *p = *pp;
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
    *pp = p;
    return true;
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
            if (!row_skip_escape(&p, end))
                return false; // raw-return-ok:pure-flat-row-predicate
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

/* Skip one of the JSON literals true, false or null. Leaves *pp unchanged on
 * a miss, so the caller can try the next token class from the same byte. */
static bool row_skip_literal(const char **pp, const char *end)
{
    static const char *const words[] = { "true", "false", "null", NULL };
    for (size_t i = 0; words[i]; i++) {
        size_t n = strlen(words[i]);
        if ((size_t)(end - *pp) >= n && memcmp(*pp, words[i], n) == 0) {
            *pp += n;
            return true;
        }
    }
    return false; // raw-return-ok:pure-flat-row-predicate
}

/* Skip one JSON number: an optional '-', then 0 or a digit run. The caller
 * guarantees *pp < end. */
static bool row_skip_number(const char **pp, const char *end)
{
    const char *p = *pp;
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
    *pp = p;
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
    } else if (!row_skip_literal(&p, end) && !row_skip_number(&p, end)) {
        return false; // raw-return-ok:pure-flat-row-predicate
    }
    *pp = p;
    return true;
}

/* Consume the punctuation byte c between blanks. *pp always ends past the
 * blanks that precede c, and past c and the blanks after it on a match. */
static bool row_take_punct(const char **pp, const char *end, char c)
{
    const char *p = row_ws(*pp, end);
    *pp = p;
    if (p >= end || *p != c)
        return false; // raw-return-ok:pure-flat-row-predicate
    *pp = row_ws(p + 1, end);
    return true;
}

/* Consume the closing byte of a container. *pp moves only on a match. */
static bool row_close(const char **pp, const char *end, char closer)
{
    const char *p = *pp;
    if (p >= end || *p != closer)
        return false; // raw-return-ok:pure-flat-row-predicate
    *pp = p + 1;
    return true;
}

/* Read one member name into *key. A name must be non-empty, unescaped,
 * unique within its object and fit the set's cap. */
static bool row_take_key(const char **pp, const char *end,
                         struct key_set *set, struct key_span *key)
{
    const char *p = *pp;
    *key = (struct key_span){ NULL, 0 };
    if (!row_skip_string(&p, end, &key->at, &key->len, true) ||
        key->len == 0 || set->count >= set->cap)
        return false; // raw-return-ok:pure-flat-row-predicate
    for (size_t i = 0; i < set->count; i++) {
        if (set->span[i].len == key->len &&
            memcmp(set->span[i].at, key->at, key->len) == 0)
            return false; // raw-return-ok:pure-flat-row-predicate
    }
    set->span[set->count++] = *key;
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
    if (row_close(&p, end, '}')) {
        *pp = p;
        return true;
    }

    struct key_span keys[EVIDENCE_ARRAY_OBJECT_KEY_CAP];
    struct key_set set = { keys, 0, EVIDENCE_ARRAY_OBJECT_KEY_CAP };
    for (;;) {
        struct key_span key;
        if (!row_take_key(&p, end, &set, &key))
            return false; // raw-return-ok:pure-flat-row-predicate
        if (!row_take_punct(&p, end, ':'))
            return false; // raw-return-ok:pure-flat-row-predicate
        if (!row_skip_scalar(&p, end))
            return false; // raw-return-ok:pure-flat-row-predicate
        if (row_take_punct(&p, end, ','))
            continue;
        if (!row_close(&p, end, '}'))
            return false; // raw-return-ok:pure-flat-row-predicate
        *pp = p;
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

/* Report a match through the caller's out-params; NULL resets them. */
static void row_set_found(const char **value, bool *found, const char *at)
{
    if (value)
        *value = at;
    if (found)
        *found = at != NULL;
}

static bool row_key_is(const char *want, const struct key_span *key)
{
    return want && strlen(want) == key->len &&
           memcmp(want, key->at, key->len) == 0;
}

/* Validate the WHOLE object while finding an exact top-level key. This is
 * intentionally not substring search: a string value containing `"ts":1`
 * must never masquerade as the real timestamp field. */
static bool row_scan_object(const char *row, size_t len, const char *want,
                            const char **value, bool *found)
{
    row_set_found(value, found, NULL);
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
    struct key_set set = { keys, 0, EVIDENCE_FLAT_KEY_CAP };
    for (;;) {
        struct key_span key;
        if (!row_take_key(&p, end, &set, &key))
            return false; // raw-return-ok:pure-flat-row-predicate
        if (!row_take_punct(&p, end, ':'))
            return false; // raw-return-ok:pure-flat-row-predicate
        const char *value_at = p;
        if (!row_skip_value(&p, end))
            return false; // raw-return-ok:pure-flat-row-predicate
        if (row_key_is(want, &key))
            row_set_found(value, found, value_at);
        if (row_take_punct(&p, end, ','))
            continue;
        if (!row_close(&p, end, '}'))
            return false; // raw-return-ok:pure-flat-row-predicate
        return row_ws(p, end) == end;
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

/* NUL-terminate dst after n copied bytes, never past cap. */
static void row_str_terminate(char *dst, size_t cap, size_t n)
{
    if (dst && cap)
        dst[n < cap ? n : cap - 1] = '\0';
}

/* Store one decoded byte, keeping room for the terminator. */
static void row_str_put(char *dst, size_t cap, size_t *n, char c)
{
    if (dst && cap && *n + 1 < cap)
        dst[(*n)++] = c;
}

/* Decode the byte at *at inside a string value. An escape yields its
 * character, with \n \t \r flattened to a space; *at ends on that byte. */
static char row_str_decode(const char **at, const char *end)
{
    const char *p = *at;
    char c = *p;
    if (c == '\\' && p + 1 < end) {
        p++;
        c = *p;
        if (c == 'n' || c == 't' || c == 'r')
            c = ' ';
    }
    *at = p;
    return c;
}

bool evidence_row_str(const char *row, size_t len, const char *key,
                      char *dst, size_t cap)
{
    row_str_terminate(dst, cap, 0);
    const char *at = row_value(row, len, key);
    if (!at || *at != '"')
        return false;
    at++;
    const char *end = row + len;
    size_t n = 0;
    while (at < end && *at != '"') {
        row_str_put(dst, cap, &n, row_str_decode(&at, end));
        at++;
    }
    row_str_terminate(dst, cap, n);
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

/* Seek to the last tail_bytes of f so a rotated or very long ledger stays a
 * cheap read. Returns true when that seek landed mid-file, which makes the
 * first line a fragment. */
static bool row_seek_tail(FILE *f, size_t tail_bytes)
{
    bool partial_head = false;
    if (fseek(f, 0, SEEK_END) == 0) {
        long size = ftell(f);
        if (size > (long)tail_bytes &&
            fseek(f, size - (long)tail_bytes, SEEK_SET) == 0)
            partial_head = true;
        else
            rewind(f);
    }
    return partial_head;
}

/* Line assembly state for evidence_ledger_scan_tail. The row buffer holds
 * DATA bytes only — no newline, no NUL: `fn` is handed (pointer, length). */
struct row_tail {
    evidence_row_fn fn;
    void *ctx;
    unsigned *out_overlong;
    unsigned *out_incomplete;
    char row[EVIDENCE_ROW_MAX];
    size_t rlen;                /* data bytes of the current line, buffered */
    bool overlong;              /* this line has more than EVIDENCE_ROW_MAX */
    bool has_nul;               /* this line carries an embedded NUL byte */
    bool fragment;              /* the current line is a post-seek fragment */
};

/* Append one newline-free segment of the current line. An overlong row keeps
 * only its first EVIDENCE_ROW_MAX bytes; the surplus streams by as dropped. */
static void row_tail_take(struct row_tail *t, const char *at, size_t seg)
{
    if (memchr(at, '\0', seg) != NULL)
        t->has_nul = true;
    if (t->rlen + seg > EVIDENCE_ROW_MAX) {
        t->overlong = true;
        if (t->rlen < EVIDENCE_ROW_MAX)
            memcpy(t->row + t->rlen, at, EVIDENCE_ROW_MAX - t->rlen);
        t->rlen = EVIDENCE_ROW_MAX;
    } else if (seg) {
        memcpy(t->row + t->rlen, at, seg);
        t->rlen += seg;
    }
}

/* A newline ended the current line: count it or hand it to fn, then reset the
 * line state for the next one. */
static void row_tail_line_done(struct row_tail *t)
{
    if (t->fragment) {
        t->fragment = false;
    } else if (t->overlong) {
        /* Longer than a row is allowed to be: corrupt or foreign
         * content, counted malformed. */
        if (t->out_overlong)
            (*t->out_overlong)++;
    } else if (t->has_nul) {
        /* Newline-terminated, so its length is known, but a NUL byte
         * inside a flat JSON row means the bytes on disk are not what
         * the recorder wrote. Counted with the torn appends rather
         * than the malformed rows for the same reason: this is a write
         * that did not all land, not a foreign row shape. It must
         * never reach `fn` — every reader here treats the last row it
         * was handed as authoritative for the per-sample fields. */
        if (t->out_incomplete)
            (*t->out_incomplete)++;
    } else if (t->rlen > 0) {
        t->fn(t->row, t->rlen, t->ctx);
    }
    t->rlen = 0;
    t->overlong = false;
    t->has_nul = false;
}

/* Split one chunk at its newlines and feed each piece to the line state. */
static void row_tail_chunk(struct row_tail *t, const char *chunk, size_t got)
{
    size_t i = 0;
    while (i < got) {
        const char *nl = memchr(chunk + i, '\n', got - i);
        size_t seg = nl ? (size_t)(nl - (chunk + i)) : got - i;

        row_tail_take(t, chunk + i, seg);
        i += seg;
        if (!nl)
            break;          /* the line continues into the next chunk */
        i++;                /* consume the newline itself */
        row_tail_line_done(t);
    }
}

/* Whatever is left never met a newline: end of file mid-line. */
static void row_tail_eof(struct row_tail *t)
{
    if (t->rlen == 0 && !t->overlong)
        return;
    if (t->fragment) {
        /* a seek fragment that was also the whole tail: still not a row */
    } else if (t->overlong) {
        if (t->out_overlong)
            (*t->out_overlong)++;
    } else if (t->out_incomplete) {
        /* A torn append caught mid-write, or a truncated file. Not
         * malformed — the bytes may be a perfectly good row that is not
         * all there yet — and not a sample. */
        (*t->out_incomplete)++;
    }
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

    bool partial_head = row_seek_tail(f, tail_bytes);

    /* BYTE-COUNTED, NOT NUL-TERMINATED. A torn append leaves NUL bytes in the
     * middle of otherwise valid JSON, and strlen() would stop at the first
     * one, misreading a terminated line as unterminated and swallowing the
     * following valid row as a phantom tail.
     *
     * Row boundaries are decided by counting bytes to the next '\n' and
     * nothing else. A NUL is just a byte inside one row's content; it
     * disqualifies THAT row and cannot reach past its own newline. An
     * overlong row or a post-seek fragment has its surplus bytes dropped as
     * they stream by, never folded in as a second phantom row. */
    char chunk[8192];
    /* The first line after a mid-file seek is a fragment; dropping it is the
     * difference between describing evidence and inventing a sample. It is not
     * counted overlong: its true length is unknown, so calling it a malformed
     * row would invent a defect. It must also not cost the line after it. */
    struct row_tail t = {
        .fn = fn,
        .ctx = ctx,
        .out_overlong = out_overlong,
        .out_incomplete = out_incomplete,
        .fragment = partial_head,
    };
    size_t got;
    while ((got = fread(chunk, 1, sizeof(chunk), f)) > 0)
        row_tail_chunk(&t, chunk, got);
    row_tail_eof(&t);
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

bool evidence_ledger_home_rel_dir(const char *home_rel_dir, char *out,
                                 size_t cap)
{
    if (!out || cap == 0)
        LOG_FAIL("evidence_ledger", "path output buffer is NULL/empty");
    out[0] = '\0';
    if (!home_rel_dir || !home_rel_dir[0])
        LOG_FAIL("evidence_ledger", "home-relative dir is NULL/empty");
    const char *home = getenv("HOME");
    if (!home || !home[0])
        LOG_FAIL("evidence_ledger", "no HOME to resolve %s from",
                 home_rel_dir);
    if (snprintf(out, cap, "%s/%s", home, home_rel_dir) >= (int)cap) {
        out[0] = '\0';
        LOG_FAIL("evidence_ledger", "%s path too long for buffer",
                 home_rel_dir);
    }
    return true;
}
