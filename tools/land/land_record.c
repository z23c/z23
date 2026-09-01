/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The canonical encoding described in land_record.h.
 *
 * Every encoder starts by zeroing the whole frame buffer it is about to
 * fill. That is not defensive habit: a reserved byte left at whatever the
 * stack held would make the same submission hash differently on two runs,
 * and the chain that hashes it would then disagree about identical content.
 * The test group checks exactly that property.
 *
 * There is no private integer packer and no private hex codec here. Both
 * live in platform/modules/base (serialize_le.h, hex.h), both are `static inline` so they
 * cost this tool nothing at link time, and using them buys the one thing a
 * canonical format actually needs: exactly one implementation of "what do
 * these bytes mean", shared with everything else in this tree that writes
 * bytes to disk. Every fixed-width field below is therefore u32 or u64
 * big-endian — there is no u16 in the layout, because reaching for one would
 * have meant hand-rolling a packer for it.
 */

#include "land_record.h"

#include "base/hex.h"
#include "base/serialize_le.h"
#include "sha3/sha3.h"

#include <string.h>

/* ── labels ───────────────────────────────────────────────────────────── */

const char *land_state_label(enum land_state s)
{
    switch (s) {
    case LAND_STATE_QUEUED:  return "QUEUED";
    case LAND_STATE_GATING:  return "GATING";
    case LAND_STATE_LANDED:  return "LANDED";
    case LAND_STATE_REFUSED: return "REFUSED";
    case LAND_STATE_TIMEOUT: return "TIMEOUT";
    }
    return "UNKNOWN";
}

bool land_state_parse(const char *text, enum land_state *out)
{
    if (!text || !out)
        return false;
    static const struct { const char *name; enum land_state s; } k[] = {
        { "queued", LAND_STATE_QUEUED },   { "gating", LAND_STATE_GATING },
        { "landed", LAND_STATE_LANDED },   { "refused", LAND_STATE_REFUSED },
        { "timeout", LAND_STATE_TIMEOUT },
    };
    for (size_t i = 0; i < sizeof k / sizeof k[0]; i++) {
        if (strcmp(text, k[i].name) == 0) {
            *out = k[i].s;
            return true;
        }
    }
    return false;
}

const char *land_gate_outcome_label(enum land_gate_outcome o)
{
    switch (o) {
    case LAND_GATE_GREEN:   return "green";
    case LAND_GATE_RED:     return "red";
    case LAND_GATE_TIMEOUT: return "timeout";
    }
    return "unknown";
}

bool land_gate_outcome_parse(const char *text, enum land_gate_outcome *out)
{
    if (!text || !out)
        return false;
    if (strcmp(text, "green") == 0)   { *out = LAND_GATE_GREEN;   return true; }
    if (strcmp(text, "red") == 0)     { *out = LAND_GATE_RED;     return true; }
    if (strcmp(text, "timeout") == 0) { *out = LAND_GATE_TIMEOUT; return true; }
    return false;
}

/* ── hex ──────────────────────────────────────────────────────────────
 * Named wrappers, not a second codec. A sha has ONE spelling here — exactly
 * 40 lowercase hex digits — so a short or uppercase argument is a refusal
 * rather than a silently different commit, and platform/modules/base's canonical decoder
 * is what enforces it. */

bool land_sha_parse(const char *hex, uint8_t out[LAND_SHA_BYTES])
{
    if (!out)
        return false;
    return zcl_hex_decode_lower(hex, out, LAND_SHA_BYTES);
}

void land_sha_format(const uint8_t in[LAND_SHA_BYTES],
                     char out[LAND_SHA_HEX + 1])
{
    zcl_hex_encode(in, LAND_SHA_BYTES, out);
}

bool land_id32_parse(const char *hex, uint8_t out[32])
{
    if (!out)
        return false;
    return zcl_hex_decode_lower(hex, out, 32);
}

void land_id32_format(const uint8_t in[32], char out[65])
{
    zcl_hex_encode(in, 32, out);
}

/* ── the content address of a verdict ─────────────────────────────────
 * A fixed 100-byte preimage, laid out in land_record.h. Fixed-size on
 * purpose: with no variable-length field there is no length prefix to get
 * wrong and no way for two different inputs to produce the same byte string,
 * so the digest is a function of the four facts and nothing else. */

#define LAND_DIGEST_DOMAIN "z23.land.verdict.v1"
#define LAND_DIGEST_PREIMAGE 100u

void land_verdict_digest(const uint8_t head[LAND_SHA_BYTES],
                         const uint8_t integration[LAND_SHA_BYTES],
                         const uint8_t gate_id[LAND_GATE_ID_BYTES],
                         enum land_state state, bool stress,
                         uint8_t out[LAND_DIGEST_BYTES])
{
    if (!out)
        return;
    uint8_t pre[LAND_DIGEST_PREIMAGE];
    memset(pre, 0, sizeof pre);
    /* 20 bytes of domain, NUL-padded: the string is 19 characters, so the
     * final byte is the terminator and the field is exactly full. */
    memcpy(pre, LAND_DIGEST_DOMAIN, sizeof LAND_DIGEST_DOMAIN);
    if (head)
        memcpy(pre + 20, head, LAND_SHA_BYTES);
    if (integration)
        memcpy(pre + 40, integration, LAND_SHA_BYTES);
    if (gate_id)
        memcpy(pre + 60, gate_id, LAND_GATE_ID_BYTES);
    zcl_write_u32_be(pre + 92, (uint32_t)state);
    zcl_write_u32_be(pre + 96, stress ? 1u : 0u);
    zcl_sha3_256(pre, sizeof pre, out);
}

void land_stream_id(uint8_t out[32])
{
    /* Derived from a name rather than a magic constant so the binding is
     * legible: anyone can recompute it from the string. */
    static const char name[] = "z23.land.queue.v1";
    zcl_sha3_256((const unsigned char *)name, sizeof name - 1, out);
}

/* ── shared field helpers ─────────────────────────────────────────────── */

/* Copy a bounded, NUL-terminated field out of a frame. Refuses an embedded
 * NUL: a branch name holding one would render as a short string while
 * hashing as a long one, which is precisely the "two things, one hash"
 * shape a canonical encoding exists to forbid. */
static bool take_text(const uint8_t *src, size_t len, char *dst, size_t cap)
{
    if (len >= cap)
        return false;
    for (size_t i = 0; i < len; i++) {
        if (src[i] == 0)
            return false;
        dst[i] = (char)src[i];
    }
    dst[len] = '\0';
    return true;
}

static bool text_len(const char *s, size_t max, size_t *out)
{
    size_t n = s ? strlen(s) : 0;
    if (n > max)
        return false;
    for (size_t i = 0; i < n; i++) {
        /* A newline or a tab in a branch name would split a status line in
         * two. Refuse at the encoder so no such record ever reaches disk. */
        unsigned char c = (unsigned char)s[i];
        if (c < 0x20 || c == 0x7F)
            return false;
    }
    *out = n;
    return true;
}

/* ── SUBMIT ───────────────────────────────────────────────────────────── */

#define SUBMIT_FIXED 40u
/*  0 u32 version
 *  4 u32 branch_len
 *  8 u32 submitter_len
 * 12 u32 note_len
 * 16 u8[20] head
 * 36 u32 reserved (must be zero)
 * 40 branch || submitter || note
 */

size_t land_submit_encode(const struct land_submit *in, uint8_t *buf,
                          size_t cap)
{
    size_t bl, sl, nl;
    if (!in || !buf)
        return 0;
    if (!text_len(in->branch, LAND_BRANCH_MAX, &bl) || bl == 0)
        return 0;
    if (!text_len(in->submitter, LAND_SUBMITTER_MAX, &sl) || sl == 0)
        return 0;
    if (!text_len(in->note, LAND_NOTE_MAX, &nl))
        return 0;
    size_t total = SUBMIT_FIXED + bl + sl + nl;
    if (total > cap)
        return 0;
    memset(buf, 0, total);
    zcl_write_u32_be(buf + 0, LAND_RECORD_VERSION);
    zcl_write_u32_be(buf + 4, (uint32_t)bl);
    zcl_write_u32_be(buf + 8, (uint32_t)sl);
    zcl_write_u32_be(buf + 12, (uint32_t)nl);
    memcpy(buf + 16, in->head, LAND_SHA_BYTES);
    /* bytes 36..39 stay zero */
    memcpy(buf + SUBMIT_FIXED, in->branch, bl);
    memcpy(buf + SUBMIT_FIXED + bl, in->submitter, sl);
    memcpy(buf + SUBMIT_FIXED + bl + sl, in->note, nl);
    return total;
}

bool land_submit_decode(const uint8_t *buf, size_t len,
                        struct land_submit *out)
{
    if (!buf || !out || len < SUBMIT_FIXED)
        return false;
    if (zcl_read_u32_be(buf) != LAND_RECORD_VERSION)
        return false;
    if (zcl_read_u32_be(buf + 36) != 0)
        return false;
    uint32_t bl = zcl_read_u32_be(buf + 4);
    uint32_t sl = zcl_read_u32_be(buf + 8);
    uint32_t nl = zcl_read_u32_be(buf + 12);
    if (bl == 0 || sl == 0)
        return false;
    if (bl > LAND_BRANCH_MAX || sl > LAND_SUBMITTER_MAX || nl > LAND_NOTE_MAX)
        return false;
    if (len != SUBMIT_FIXED + bl + sl + nl) /* no trailing bytes */
        return false;
    memset(out, 0, sizeof *out);
    memcpy(out->head, buf + 16, LAND_SHA_BYTES);
    const uint8_t *p = buf + SUBMIT_FIXED;
    return take_text(p, bl, out->branch, sizeof out->branch) &&
           take_text(p + bl, sl, out->submitter, sizeof out->submitter) &&
           take_text(p + bl + sl, nl, out->note, sizeof out->note);
}

/* ── GATE_RUN ─────────────────────────────────────────────────────────── */

#define GATE_FIXED 72u
/*  0 u32 version
 *  4 u32 outcome
 *  8 u32 stress (0 or 1)
 * 12 u32 member_count
 * 16 u8[20] integration head
 * 36 u32 reserved (must be zero)
 * 40 u8[32] gate_id — the source identity of the tree the gate ran over
 * 72 u64 member_seq[member_count]
 */

size_t land_gate_run_encode(const struct land_gate_run *in, uint8_t *buf,
                            size_t cap)
{
    if (!in || !buf)
        return 0;
    if (in->outcome != LAND_GATE_GREEN && in->outcome != LAND_GATE_RED &&
        in->outcome != LAND_GATE_TIMEOUT)
        return 0;
    if (in->member_count == 0 || in->member_count > LAND_MEMBERS_MAX)
        return 0;
    for (uint32_t i = 0; i < in->member_count; i++)
        if (in->member_seq[i] == 0) /* seq is 1-based; 0 names nothing */
            return 0;
    size_t total = GATE_FIXED + (size_t)in->member_count * 8u;
    if (total > cap)
        return 0;
    memset(buf, 0, total);
    zcl_write_u32_be(buf + 0, LAND_RECORD_VERSION);
    zcl_write_u32_be(buf + 4, (uint32_t)in->outcome);
    zcl_write_u32_be(buf + 8, in->stress ? 1u : 0u);
    zcl_write_u32_be(buf + 12, in->member_count);
    memcpy(buf + 16, in->integration, LAND_SHA_BYTES);
    memcpy(buf + 40, in->gate_id, LAND_GATE_ID_BYTES);
    for (uint32_t i = 0; i < in->member_count; i++)
        zcl_write_u64_be(buf + GATE_FIXED + (size_t)i * 8u, in->member_seq[i]);
    return total;
}

bool land_gate_run_decode(const uint8_t *buf, size_t len,
                          struct land_gate_run *out)
{
    if (!buf || !out || len < GATE_FIXED)
        return false;
    if (zcl_read_u32_be(buf) != LAND_RECORD_VERSION)
        return false;
    if (zcl_read_u32_be(buf + 36) != 0)
        return false;
    uint32_t stress = zcl_read_u32_be(buf + 8);
    if (stress > 1)
        return false;
    uint32_t outcome = zcl_read_u32_be(buf + 4);
    if (outcome != LAND_GATE_GREEN && outcome != LAND_GATE_RED &&
        outcome != LAND_GATE_TIMEOUT)
        return false;
    uint32_t n = zcl_read_u32_be(buf + 12);
    if (n == 0 || n > LAND_MEMBERS_MAX)
        return false;
    if (len != GATE_FIXED + (size_t)n * 8u)
        return false;
    memset(out, 0, sizeof *out);
    out->outcome = (enum land_gate_outcome)outcome;
    out->stress = stress == 1u;
    out->member_count = n;
    memcpy(out->integration, buf + 16, LAND_SHA_BYTES);
    memcpy(out->gate_id, buf + 40, LAND_GATE_ID_BYTES);
    for (uint32_t i = 0; i < n; i++) {
        out->member_seq[i] =
            zcl_read_u64_be(buf + GATE_FIXED + (size_t)i * 8u);
        if (out->member_seq[i] == 0)
            return false;
    }
    return true;
}

/* ── VERDICT ──────────────────────────────────────────────────────────── */

#define VERDICT_FIXED 72u
/*  0 u32 version
 *  4 u32 state
 *  8 u64 submit_seq
 * 16 u64 gate_run_seq
 * 24 u8[20] head
 * 44 u8[20] integration
 * 64 u32 branch_len
 * 68 u32 reason_len
 * 72 branch || reason
 */

size_t land_verdict_encode(const struct land_verdict *in, uint8_t *buf,
                           size_t cap)
{
    size_t bl, rl;
    if (!in || !buf)
        return 0;
    if (in->state != LAND_STATE_LANDED && in->state != LAND_STATE_REFUSED &&
        in->state != LAND_STATE_TIMEOUT)
        return 0; /* QUEUED and GATING are derived, never asserted */
    if (in->submit_seq == 0)
        return 0;
    if (!text_len(in->branch, LAND_BRANCH_MAX, &bl) || bl == 0)
        return 0;
    if (!text_len(in->reason, LAND_REASON_MAX, &rl))
        return 0;
    size_t total = VERDICT_FIXED + bl + rl;
    if (total > cap)
        return 0;
    memset(buf, 0, total);
    zcl_write_u32_be(buf + 0, LAND_RECORD_VERSION);
    zcl_write_u32_be(buf + 4, (uint32_t)in->state);
    zcl_write_u64_be(buf + 8, in->submit_seq);
    zcl_write_u64_be(buf + 16, in->gate_run_seq);
    memcpy(buf + 24, in->head, LAND_SHA_BYTES);
    memcpy(buf + 44, in->integration, LAND_SHA_BYTES);
    zcl_write_u32_be(buf + 64, (uint32_t)bl);
    zcl_write_u32_be(buf + 68, (uint32_t)rl);
    memcpy(buf + VERDICT_FIXED, in->branch, bl);
    memcpy(buf + VERDICT_FIXED + bl, in->reason, rl);
    return total;
}

bool land_verdict_decode(const uint8_t *buf, size_t len,
                         struct land_verdict *out)
{
    if (!buf || !out || len < VERDICT_FIXED)
        return false;
    if (zcl_read_u32_be(buf) != LAND_RECORD_VERSION)
        return false;
    uint32_t state = zcl_read_u32_be(buf + 4);
    if (state != LAND_STATE_LANDED && state != LAND_STATE_REFUSED &&
        state != LAND_STATE_TIMEOUT)
        return false;
    uint64_t submit_seq = zcl_read_u64_be(buf + 8);
    if (submit_seq == 0)
        return false;
    uint32_t bl = zcl_read_u32_be(buf + 64);
    uint32_t rl = zcl_read_u32_be(buf + 68);
    if (bl == 0 || bl > LAND_BRANCH_MAX || rl > LAND_REASON_MAX)
        return false;
    if (len != VERDICT_FIXED + bl + rl)
        return false;
    memset(out, 0, sizeof *out);
    out->state = (enum land_state)state;
    out->submit_seq = submit_seq;
    out->gate_run_seq = zcl_read_u64_be(buf + 16);
    memcpy(out->head, buf + 24, LAND_SHA_BYTES);
    memcpy(out->integration, buf + 44, LAND_SHA_BYTES);
    const uint8_t *p = buf + VERDICT_FIXED;
    return take_text(p, bl, out->branch, sizeof out->branch) &&
           take_text(p + bl, rl, out->reason, sizeof out->reason);
}
