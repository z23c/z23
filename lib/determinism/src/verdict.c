/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Purpose: derive a group's verdict vector from the harness transcript and
 * fold it into one order-, outcome- and membership-sensitive digest.
 *
 * The framing below is length-prefixed at every variable field, so no two
 * distinct vectors can produce the same byte stream by concatenation: a check
 * named "ab" followed by "c" and a check named "a" followed by "bc" differ in
 * their length prefixes even though their name bytes concatenate the same. The
 * running index is folded in as well, so a pure reordering — an order
 * dependence between checks, one of the three failures this exists to find —
 * moves the digest even when the multiset of pairs is unchanged. */

#include "determinism/verdict.h"

#include "base/log_macros.h"
#include "base/serialize_le.h"

#include <string.h>

/* Domain separation: this digest must never collide with any other SHA3-256
 * in the tree that happens to hash the same bytes for another purpose. */
static const char k_domain[] = "zcl.determinism.verdict_vector.v1";

const char *zcl_det_outcome_name(enum zcl_det_outcome outcome)
{
    switch (outcome) {
    case ZCL_DET_OUTCOME_NONE: return "none";
    case ZCL_DET_OUTCOME_PASS: return "PASS";
    case ZCL_DET_OUTCOME_FAIL: return "FAIL";
    case ZCL_DET_OUTCOME_SKIP: return "SKIP";
    case ZCL_DET_OUTCOME_UNOBSERVED: return "UNOBSERVED";
    }
    return "unknown";
}

static void write_u32(struct sha3_256_ctx *ctx, uint32_t v)
{
    unsigned char buf[4];
    zcl_write_u32_le(buf, v);
    sha3_256_write(ctx, buf, sizeof(buf));
}

static void write_u16(struct sha3_256_ctx *ctx, uint16_t v)
{
    unsigned char buf[2];
    zcl_write_u16_le(buf, v);
    sha3_256_write(ctx, buf, sizeof(buf));
}

static void write_field(struct sha3_256_ctx *ctx, const char *s, size_t len)
{
    /* len is bounded by the caller's fixed-size buffers, so the u16 prefix
     * cannot truncate; assert it rather than assume it. */
    if (len > 0xFFFFu) len = 0xFFFFu;
    write_u16(ctx, (uint16_t)len);
    if (len) sha3_256_write(ctx, (const unsigned char *)s, len);
}

void zcl_det_vector_begin(struct zcl_det_vector *v)
{
    if (!v) return;
    memset(v, 0, sizeof(*v));
    sha3_256_init(&v->ctx);
    sha3_256_write(&v->ctx, (const unsigned char *)k_domain,
                   sizeof(k_domain)); /* NUL included: a terminator, not text */
    v->started = true;
}

bool zcl_det_vector_add(struct zcl_det_vector *v,
                        const struct zcl_det_check *check)
{
    if (!v || !check) LOG_FAIL("determinism", "null vector or check");
    if (!v->started) LOG_FAIL("determinism", "vector_add before vector_begin");
    if (v->count == UINT32_MAX)
        LOG_FAIL("determinism", "verdict vector exceeds %u checks", UINT32_MAX);

    write_u32(&v->ctx, v->count);
    /* The ORIGINAL name length, then the (possibly truncated) bytes. */
    write_u32(&v->ctx, (uint32_t)(check->name_len > UINT32_MAX
                                      ? UINT32_MAX
                                      : check->name_len));
    write_field(&v->ctx, check->name, strnlen(check->name, ZCL_DET_NAME_MAX));
    write_u16(&v->ctx, (uint16_t)check->outcome);
    write_field(&v->ctx, check->locator,
                strnlen(check->locator, ZCL_DET_LOCATOR_MAX));
    v->count++;
    return true;
}

bool zcl_det_vector_finish(struct zcl_det_vector *v,
                           uint8_t out[ZCL_DET_DIGEST_LEN],
                           uint32_t *out_count)
{
    if (!v || !out) LOG_FAIL("determinism", "null vector or output");
    if (!v->started) LOG_FAIL("determinism", "vector_finish before begin");
    write_u32(&v->ctx, v->count); /* the count is part of the preimage */
    sha3_256_finalize(&v->ctx, out);
    if (out_count) *out_count = v->count;
    v->started = false;
    return true;
}

/* ── line parsing ─────────────────────────────────────────────────────────*/

static const char *skip_space(const char *s)
{
    while (*s == ' ' || *s == '\t') s++;
    return s;
}

/* Copy at most cap-1 bytes and NUL-terminate. */
static void copy_bounded(char *dst, size_t cap, const char *src, size_t len)
{
    if (cap == 0) return;
    if (len >= cap) len = cap - 1;
    memcpy(dst, src, len);
    dst[len] = '\0';
}

/* "FAIL at lib/test/src/test_foo.c:412 (got != want): 7 != 9"
 *   -> locator "lib/test/src/test_foo.c:412", everything after it discarded.
 * The discarded tail is where a pointer value or a temp path would live. */
static void extract_locator(const char *after_fail, char *out, size_t cap)
{
    out[0] = '\0';
    const char *p = skip_space(after_fail);
    if (strncmp(p, "at ", 3) != 0) return;
    p = skip_space(p + 3);
    const char *end = p;
    while (*end && *end != ' ' && *end != '\t' && *end != '\r' && *end != '\n')
        end++;
    copy_bounded(out, cap, p, (size_t)(end - p));
}

bool zcl_det_parse_check_line(const char *line, struct zcl_det_check *out)
{
    if (!line || !out) return false;
    memset(out, 0, sizeof(*out));

    const char *start = skip_space(line);

    /* The separator the harness prints between a name and its outcome. Take
     * the LAST occurrence so a name that itself contains "... " keeps its
     * whole text and the suffix is always the outcome word. */
    const char *sep = NULL;
    for (const char *p = start; (p = strstr(p, "... ")) != NULL; p += 1)
        sep = p;
    if (!sep || sep == start) return false;

    const char *suffix = sep + 4;
    enum zcl_det_outcome outcome = ZCL_DET_OUTCOME_NONE;
    char locator[ZCL_DET_LOCATOR_MAX];
    locator[0] = '\0';

    if (strncmp(suffix, "OK", 2) == 0) {
        /* Only a bare OK counts. "OKAY, moving on" is chatter, not a verdict. */
        const char *tail = skip_space(suffix + 2);
        if (*tail != '\0' && *tail != '\r' && *tail != '\n') return false;
        outcome = ZCL_DET_OUTCOME_PASS;
    } else if (strncmp(suffix, "FAIL", 4) == 0) {
        outcome = ZCL_DET_OUTCOME_FAIL;
        extract_locator(suffix + 4, locator, sizeof(locator));
    } else if (strncmp(suffix, "SKIP (", 6) == 0) {
        outcome = ZCL_DET_OUTCOME_SKIP;
    } else if (strncmp(suffix, "UNOBSERVED (", 12) == 0) {
        outcome = ZCL_DET_OUTCOME_UNOBSERVED;
    } else {
        return false;
    }

    size_t name_len = (size_t)(sep - start);
    /* A control character inside a "name" means the line is not a verdict
     * line at all (a raw dump that happened to contain "... OK"). */
    for (size_t i = 0; i < name_len; i++) {
        unsigned char c = (unsigned char)start[i];
        if (c < 0x20 || c == 0x7F) return false;
    }

    out->name_len = name_len;
    copy_bounded(out->name, sizeof(out->name), start, name_len);
    out->outcome = outcome;
    copy_bounded(out->locator, sizeof(out->locator), locator,
                 strlen(locator));
    return true;
}

/* ── the stream machine ───────────────────────────────────────────────────*/

/* True when the line is NOTHING but an outcome word, which is how a check
 * that logged while it ran reports its result. "OK: done" and "FAILURES: 0"
 * are prose and must not close anything. */
static bool line_is_bare_outcome(const char *line, enum zcl_det_outcome *out,
                                 char *locator, size_t locator_cap)
{
    const char *p = skip_space(line);
    locator[0] = '\0';
    if (strncmp(p, "OK", 2) == 0) {
        const char *tail = skip_space(p + 2);
        if (*tail != '\0' && *tail != '\r' && *tail != '\n') return false;
        *out = ZCL_DET_OUTCOME_PASS;
        return true;
    }
    if (strncmp(p, "FAIL", 4) == 0) {
        *out = ZCL_DET_OUTCOME_FAIL;
        extract_locator(p + 4, locator, locator_cap);
        return true;
    }
    if (strncmp(p, "SKIP (", 6) == 0) {
        *out = ZCL_DET_OUTCOME_SKIP;
        return true;
    }
    if (strncmp(p, "UNOBSERVED (", 12) == 0) {
        *out = ZCL_DET_OUTCOME_UNOBSERVED;
        return true;
    }
    return false;
}

/* The name a line OPENS, or false. The harness prints the name first, so the
 * FIRST separator on the line is its boundary; anything after it is whatever
 * the test logged next. A line that is already a complete check is not an
 * opener and is never offered here. */
static bool line_opens_check(const char *line, const char **name,
                             size_t *name_len)
{
    const char *start = skip_space(line);
    const char *sep = strstr(start, "... ");
    if (!sep || sep == start) return false;
    size_t len = (size_t)(sep - start);
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)start[i];
        if (c < 0x20 || c == 0x7F) return false;
    }
    *name = start;
    *name_len = len;
    return true;
}

void zcl_det_stream_begin(struct zcl_det_stream *s)
{
    if (!s) return;
    memset(s, 0, sizeof(*s));
    zcl_det_vector_begin(&s->vec);
}

static bool stream_emit(struct zcl_det_stream *s, const char *name,
                        size_t name_len, enum zcl_det_outcome outcome,
                        const char *locator)
{
    struct zcl_det_check c;
    memset(&c, 0, sizeof(c));
    c.name_len = name_len;
    copy_bounded(c.name, sizeof(c.name), name, name_len);
    c.outcome = outcome;
    copy_bounded(c.locator, sizeof(c.locator), locator, strlen(locator));
    return zcl_det_vector_add(&s->vec, &c);
}

bool zcl_det_stream_line(struct zcl_det_stream *s, const char *line)
{
    if (!s || !line) LOG_FAIL("determinism", "null stream or line");

    /* 1. A complete "<name>... <outcome>" line. If a check was still open it
     *    never produced an outcome: drop it and count it rather than pair it
     *    with the wrong result. */
    struct zcl_det_check complete;
    if (zcl_det_parse_check_line(line, &complete)) {
        if (s->has_pending) { s->dangling++; s->has_pending = false; }
        return zcl_det_vector_add(&s->vec, &complete);
    }

    /* 2. A bare outcome closes the check that is open. With none open it is
     *    a summary line or stray prose and is ignored. */
    enum zcl_det_outcome outcome = ZCL_DET_OUTCOME_NONE;
    char locator[ZCL_DET_LOCATOR_MAX];
    if (line_is_bare_outcome(line, &outcome, locator, sizeof(locator))) {
        if (!s->has_pending) return true;
        s->has_pending = false;
        return stream_emit(s, s->pending, s->pending_len, outcome, locator);
    }

    /* 3. Otherwise the line may OPEN a check, but only when none is open. */
    if (s->has_pending) return true;
    const char *name = NULL;
    size_t name_len = 0;
    if (!line_opens_check(line, &name, &name_len)) return true;
    s->pending_len = name_len;
    copy_bounded(s->pending, sizeof(s->pending), name, name_len);
    s->has_pending = true;
    return true;
}

bool zcl_det_stream_finish(struct zcl_det_stream *s,
                           uint8_t out[ZCL_DET_DIGEST_LEN],
                           uint32_t *out_count, uint64_t *out_dangling)
{
    if (!s) LOG_FAIL("determinism", "null stream");
    if (s->has_pending) { s->dangling++; s->has_pending = false; }
    if (out_dangling) *out_dangling = s->dangling;
    return zcl_det_vector_finish(&s->vec, out, out_count);
}

/* ── group header parsing ─────────────────────────────────────────────────*/

static const char k_rule[] = "====================";

bool zcl_det_parse_group_header(const char *line, char *out_group,
                                size_t out_cap,
                                enum zcl_det_group_status *out_status)
{
    if (!line || !out_group || out_cap == 0) return false;
    const size_t rule_len = sizeof(k_rule) - 1;
    if (strncmp(line, k_rule, rule_len) != 0) return false;
    const char *p = skip_space(line + rule_len);

    const char *open = strstr(p, " (");
    if (!open) return false;
    size_t group_len = (size_t)(open - p);
    if (group_len == 0 || group_len >= out_cap) return false;
    copy_bounded(out_group, out_cap, p, group_len);

    if (out_status) {
        const char *st = open + 2;
        if (strncmp(st, "PASS", 4) == 0)            *out_status = ZCL_DET_GROUP_PASS;
        else if (strncmp(st, "FAIL", 4) == 0)       *out_status = ZCL_DET_GROUP_FAIL;
        else if (strncmp(st, "SIGNALED", 8) == 0)   *out_status = ZCL_DET_GROUP_SIGNALED;
        else if (strncmp(st, "WEDGED", 6) == 0)     *out_status = ZCL_DET_GROUP_WEDGED;
        else                                        *out_status = ZCL_DET_GROUP_UNKNOWN;
    }
    return true;
}

/* ── transcript scan ──────────────────────────────────────────────────────*/

/* A single group's captured output can carry very long lines (a hex dump).
 * Read in fixed chunks and treat an over-long line as its own line: a
 * deterministic split, so it cannot manufacture a digest difference. */
#define ZCL_DET_LINE_MAX 8192

bool zcl_det_transcript_scan(FILE *in, zcl_det_group_sink sink, void *ctx,
                             struct zcl_det_scan_stats *stats)
{
    if (!in || !sink) LOG_FAIL("determinism", "null transcript or sink");

    struct zcl_det_scan_stats local = {0};
    struct zcl_det_group_digest current;
    struct zcl_det_stream stream;
    uint64_t dangling = 0;
    bool in_group = false;
    char line[ZCL_DET_LINE_MAX];

    memset(&current, 0, sizeof(current));

    while (fgets(line, (int)sizeof(line), in) != NULL) {
        local.lines++;

        char group[ZCL_DET_GROUP_MAX];
        enum zcl_det_group_status status = ZCL_DET_GROUP_UNKNOWN;
        if (zcl_det_parse_group_header(line, group, sizeof(group), &status)) {
            if (in_group) {
                if (!zcl_det_stream_finish(&stream, current.digest,
                                           &current.check_count, &dangling))
                    return false;
                local.checks += current.check_count;
                local.dangling += dangling;
                if (current.check_count == 0) local.groups_without_vector++;
                if (!sink(ctx, &current)) return false;
            }
            memset(&current, 0, sizeof(current));
            copy_bounded(current.group, sizeof(current.group), group,
                         strlen(group));
            current.status = status;
            zcl_det_stream_begin(&stream);
            in_group = true;
            local.groups++;
            continue;
        }

        if (!in_group) continue;
        if (!zcl_det_stream_line(&stream, line)) return false;
    }

    if (ferror(in)) LOG_FAIL("determinism", "transcript read error");

    if (in_group) {
        if (!zcl_det_stream_finish(&stream, current.digest,
                                   &current.check_count, &dangling))
            return false;
        local.checks += current.check_count;
        local.dangling += dangling;
        if (current.check_count == 0) local.groups_without_vector++;
        if (!sink(ctx, &current)) return false;
    }

    if (stats) *stats = local;
    return true;
}

