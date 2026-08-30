/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * receipt.c — the canonical form, its id, and the belief rule.
 *
 * Every function here treats its input as network input, because that is what
 * it is. See receipt.h for the design; the notes below are only about the
 * things this file does that a reader might otherwise take for slips.
 *
 * The encoder writes field by field into a zeroed buffer rather than casting
 * a struct: struct layout is a compiler's business, and the whole value of
 * this form is that two machines agree on it byte for byte. Character fields
 * are copied through a bounded helper that NUL-pads the tail, so a receipt
 * built on a stack that happened to hold old bytes cannot produce a second id
 * for the same claim.
 */

#include "receipt/receipt.h"

#include "base/serialize_le.h"
#include "sha3/sha3.h"

#include <stdio.h>
#include <string.h>

/* ── labels ──────────────────────────────────────────────────────────── */

const char *zcl_receipt_kind_label(enum zcl_receipt_kind k)
{
    switch (k) {
    case ZCL_RECEIPT_KIND_PASS:      return "PASS_RECEIPT";
    case ZCL_RECEIPT_KIND_RED_DELTA: return "RED_DELTA_RECEIPT";
    }
    return "UNKNOWN_KIND";
}

const char *zcl_receipt_verdict_label(enum zcl_receipt_verdict v)
{
    switch (v) {
    case ZCL_RECEIPT_VERDICT_PASS:       return "PASS";
    case ZCL_RECEIPT_VERDICT_FAIL:       return "FAIL";
    case ZCL_RECEIPT_VERDICT_HOLLOW:     return "HOLLOW";
    case ZCL_RECEIPT_VERDICT_NO_CHANGE:  return "NO_CHANGE";
    case ZCL_RECEIPT_VERDICT_TIMEOUT:    return "TIMEOUT";
    case ZCL_RECEIPT_VERDICT_REFUSED:    return "REFUSED";
    case ZCL_RECEIPT_VERDICT_UNVERIFIED: return "UNVERIFIED";
    }
    return "UNKNOWN_VERDICT";
}

const char *zcl_receipt_belief_label(enum zcl_receipt_belief b)
{
    switch (b) {
    case ZCL_RECEIPT_UNVERIFIED:   return "UNVERIFIED";
    case ZCL_RECEIPT_CORROBORATED: return "CORROBORATED";
    case ZCL_RECEIPT_REFUTED:      return "REFUTED";
    }
    return "UNKNOWN_BELIEF";
}

const char *zcl_receipt_eligibility_label(enum zcl_receipt_eligibility e)
{
    switch (e) {
    case ZCL_RECEIPT_ELIGIBILITY_UNKNOWN:
        return "UNKNOWN";
    case ZCL_RECEIPT_ELIGIBLE:
        return "ELIGIBLE";
    case ZCL_RECEIPT_INELIGIBLE_NONDETERMINISTIC:
        return "INELIGIBLE_NONDETERMINISTIC";
    case ZCL_RECEIPT_INELIGIBLE_TIMING_SENSITIVE:
        return "INELIGIBLE_TIMING_SENSITIVE";
    case ZCL_RECEIPT_INELIGIBLE_NO_VECTOR:
        return "INELIGIBLE_NO_VECTOR";
    }
    return "UNKNOWN";
}

/* ── small helpers ───────────────────────────────────────────────────── */

/* True when every byte is zero. Used for "no vector was measured" and for
 * "this is not a red-delta, so there is no base tree". SHA3-256 of the empty
 * input is not zero, so all-zero is a sentinel no real digest can collide
 * with. */
static bool all_zero(const uint8_t *p, size_t n)
{
    uint8_t acc = 0;
    for (size_t i = 0; i < n; i++)
        acc |= p[i];
    return acc == 0;
}

/* Constant-time 32-byte compare. A receipt digest is not a secret, but a
 * corroboration decision is exactly the shape of thing that acquires a timing
 * side channel the moment somebody signs one, and memcmp's early exit costs
 * nothing to avoid. */
static bool ct_eq32(const uint8_t a[32], const uint8_t b[32])
{
    uint8_t acc = 0;
    for (size_t i = 0; i < 32; i++)
        acc |= (uint8_t)(a[i] ^ b[i]);
    return acc == 0;
}

/* A character field is valid when it is NUL-terminated inside its width and
 * holds only printable ASCII before that NUL. Control bytes are refused
 * rather than sanitised: a group name with an embedded escape is not a group
 * name this tree has, and quietly stripping it would let two different
 * receipts render identically to a person. */
static bool field_is_clean(const char *s, size_t width)
{
    size_t i = 0;
    for (; i < width; i++) {
        if (s[i] == '\0')
            break;
        if ((unsigned char)s[i] < 0x20 || (unsigned char)s[i] > 0x7e)
            return false;
    }
    if (i == width)
        return false;            /* no NUL inside the field */
    for (; i < width; i++)
        if (s[i] != '\0')
            return false;        /* tail must be zero, or ids would differ */
    return true;
}

/* Copy `src` into a fixed-width field, NUL-padding the tail. Returns false
 * when src does not fit — a truncated group name is a different group. */
static bool field_set(char *dst, size_t width, const char *src)
{
    if (!src)
        return false;
    size_t n = strnlen(src, width);
    if (n >= width)
        return false;
    memset(dst, 0, width);
    memcpy(dst, src, n);
    return true;
}

static bool kind_in_range(uint8_t k)
{
    return k == ZCL_RECEIPT_KIND_PASS || k == ZCL_RECEIPT_KIND_RED_DELTA;
}

static bool verdict_in_range(uint8_t v)
{
    return v >= ZCL_RECEIPT_VERDICT_PASS && v <= ZCL_RECEIPT_VERDICT_UNVERIFIED;
}

/* ── validity ────────────────────────────────────────────────────────── */

bool zcl_receipt_is_valid(const struct zcl_proof_receipt *r)
{
    if (!r)
        return false;
    if (r->version != ZCL_RECEIPT_VERSION)
        return false;
    if (!kind_in_range(r->kind) || !verdict_in_range(r->verdict))
        return false;
    if (!field_is_clean(r->group, ZCL_RECEIPT_GROUP_MAX))
        return false;
    if (!field_is_clean(r->toolchain, ZCL_RECEIPT_TOOLCHAIN_MAX))
        return false;
    if (!field_is_clean(r->env_class, ZCL_RECEIPT_ENV_MAX))
        return false;
    if (r->group[0] == '\0')
        return false;
    /* A red-delta claims a tree that was red; a plain pass has no such tree
     * and must not carry a stale one, or the id would depend on a field that
     * means nothing. */
    if (r->kind == ZCL_RECEIPT_KIND_RED_DELTA) {
        if (all_zero(r->base_root, 32))
            return false;
        if (ct_eq32(r->base_root, r->source_root))
            return false;   /* base and post identical proves no delta */
    } else if (!all_zero(r->base_root, 32)) {
        return false;
    }
    return true;
}

bool zcl_receipt_is_publishable_pass(const struct zcl_proof_receipt *r)
{
    if (!zcl_receipt_is_valid(r))
        return false;
    if (r->verdict != ZCL_RECEIPT_VERDICT_PASS)
        return false;
    if (all_zero(r->verdict_vector, 32))
        return false;
    return r->checks_total > 0;
}

/* ── canonical bytes ─────────────────────────────────────────────────── */

/* The wire size is the sum of the field widths, and saying so here means a
 * field that grows without ZCL_RECEIPT_WIRE_BYTES growing with it fails to
 * COMPILE. A runtime check would only fail after somebody had already hashed
 * a short buffer, and the encoder's return type is size_t, so there is no
 * honest error value to hand back from one anyway. */
static_assert(1 + 1 + 1 + 32 + 32 + ZCL_RECEIPT_GROUP_MAX + 32 + 4 +
                  ZCL_RECEIPT_TOOLCHAIN_MAX + ZCL_RECEIPT_ENV_MAX + 32 ==
                  ZCL_RECEIPT_WIRE_BYTES,
              "ZCL_RECEIPT_WIRE_BYTES must equal the sum of the field widths");

size_t zcl_receipt_encode(uint8_t *out, size_t cap,
                          const struct zcl_proof_receipt *r)
{
    if (!out || cap < ZCL_RECEIPT_WIRE_BYTES || !zcl_receipt_is_valid(r))
        return 0;
    uint8_t *p = out;
    memset(out, 0, ZCL_RECEIPT_WIRE_BYTES);
    *p++ = r->version;
    *p++ = r->kind;
    *p++ = r->verdict;
    memcpy(p, r->source_root, 32);              p += 32;
    memcpy(p, r->base_root, 32);                p += 32;
    memcpy(p, r->group, ZCL_RECEIPT_GROUP_MAX); p += ZCL_RECEIPT_GROUP_MAX;
    memcpy(p, r->verdict_vector, 32);           p += 32;
    zcl_write_u32_be(p, r->checks_total);       p += 4;
    memcpy(p, r->toolchain, ZCL_RECEIPT_TOOLCHAIN_MAX);
    p += ZCL_RECEIPT_TOOLCHAIN_MAX;
    memcpy(p, r->env_class, ZCL_RECEIPT_ENV_MAX);
    p += ZCL_RECEIPT_ENV_MAX;
    memcpy(p, r->producer, 32);                 p += 32;
    (void)p;
    return ZCL_RECEIPT_WIRE_BYTES;
}

bool zcl_receipt_decode(struct zcl_proof_receipt *r,
                        const uint8_t *buf, size_t len)
{
    if (!r)
        return false;
    memset(r, 0, sizeof(*r));
    if (!buf || len != ZCL_RECEIPT_WIRE_BYTES)
        return false;
    const uint8_t *p = buf;
    r->version = *p++;
    r->kind    = *p++;
    r->verdict = *p++;
    memcpy(r->source_root, p, 32);              p += 32;
    memcpy(r->base_root, p, 32);                p += 32;
    memcpy(r->group, p, ZCL_RECEIPT_GROUP_MAX); p += ZCL_RECEIPT_GROUP_MAX;
    memcpy(r->verdict_vector, p, 32);           p += 32;
    r->checks_total = zcl_read_u32_be(p);       p += 4;
    memcpy(r->toolchain, p, ZCL_RECEIPT_TOOLCHAIN_MAX);
    p += ZCL_RECEIPT_TOOLCHAIN_MAX;
    memcpy(r->env_class, p, ZCL_RECEIPT_ENV_MAX);
    p += ZCL_RECEIPT_ENV_MAX;
    memcpy(r->producer, p, 32);
    if (!zcl_receipt_is_valid(r)) {
        memset(r, 0, sizeof(*r));   /* a refusal leaves nothing half-filled */
        return false;
    }
    return true;
}

bool zcl_receipt_id(uint8_t out[32], const struct zcl_proof_receipt *r)
{
    if (!out)
        return false;
    uint8_t wire[ZCL_RECEIPT_WIRE_BYTES];
    if (zcl_receipt_encode(wire, sizeof(wire), r) != ZCL_RECEIPT_WIRE_BYTES) {
        memset(out, 0, 32);
        return false;
    }
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    sha3_256_write(&ctx, (const unsigned char *)wire, sizeof(wire));
    sha3_256_finalize(&ctx, out);
    return true;
}

/* ── belief ──────────────────────────────────────────────────────────── */

enum zcl_receipt_belief zcl_receipt_corroborate(
    const struct zcl_proof_receipt *claim,
    const uint8_t observed_vector[32], uint32_t observed_checks)
{
    /* No claim worth checking, or nothing to check it with. Both answer
     * UNVERIFIED, which is the honest default and not a soft "no". */
    if (!claim || !observed_vector)
        return ZCL_RECEIPT_UNVERIFIED;
    if (!zcl_receipt_is_publishable_pass(claim))
        return ZCL_RECEIPT_UNVERIFIED;
    if (all_zero(observed_vector, 32) || observed_checks == 0)
        return ZCL_RECEIPT_UNVERIFIED;

    /* Running a different NUMBER of checks is a real difference, not a
     * rounding error: the two nodes did not run the same set. Reporting that
     * as corroboration because two digests happened to match would be the
     * worst possible outcome, so it is checked first and separately. */
    if (observed_checks != claim->checks_total)
        return ZCL_RECEIPT_REFUTED;

    return ct_eq32(claim->verdict_vector, observed_vector)
               ? ZCL_RECEIPT_CORROBORATED
               : ZCL_RECEIPT_REFUTED;
}

bool zcl_receipt_refutation_is_material(const struct zcl_proof_receipt *claim,
                                        const uint8_t observed_source_root[32],
                                        const char *observed_toolchain,
                                        const char *observed_env_class)
{
    if (!claim || !observed_source_root || !observed_toolchain ||
        !observed_env_class)
        return false;
    if (!ct_eq32(claim->source_root, observed_source_root))
        return false;
    if (strncmp(claim->toolchain, observed_toolchain,
                ZCL_RECEIPT_TOOLCHAIN_MAX) != 0)
        return false;
    if (strncmp(claim->env_class, observed_env_class,
                ZCL_RECEIPT_ENV_MAX) != 0)
        return false;
    return true;
}

/* ── eligibility ─────────────────────────────────────────────────────── */

enum zcl_receipt_eligibility zcl_receipt_group_eligibility(
    const struct zcl_receipt_ledger *ledger, const char *group)
{
    if (!ledger || !ledger->lookup || !group || !group[0])
        return ZCL_RECEIPT_ELIGIBILITY_UNKNOWN;
    enum zcl_receipt_eligibility e = ledger->lookup(group, ledger->user);
    switch (e) {
    case ZCL_RECEIPT_ELIGIBLE:
    case ZCL_RECEIPT_INELIGIBLE_NONDETERMINISTIC:
    case ZCL_RECEIPT_INELIGIBLE_TIMING_SENSITIVE:
    case ZCL_RECEIPT_INELIGIBLE_NO_VECTOR:
    case ZCL_RECEIPT_ELIGIBILITY_UNKNOWN:
        return e;
    }
    /* A ledger that answers off the enum is a ledger this code does not
     * understand, and the safe reading of "I do not understand you" is not
     * "yes". */
    return ZCL_RECEIPT_ELIGIBILITY_UNKNOWN;
}

bool zcl_receipt_build(struct zcl_proof_receipt *out,
                       const struct zcl_receipt_ledger *ledger,
                       enum zcl_receipt_kind kind,
                       enum zcl_receipt_verdict verdict,
                       const uint8_t source_root[32],
                       const uint8_t base_root[32],
                       const char *group,
                       const uint8_t verdict_vector[32],
                       uint32_t checks_total,
                       const char *toolchain,
                       const char *env_class,
                       const uint8_t producer[32],
                       char *why, size_t why_cap)
{
    if (why && why_cap)
        why[0] = '\0';
    if (!out)
        return false;
    memset(out, 0, sizeof(*out));

    if (!group || !group[0]) {
        if (why && why_cap)
            (void)snprintf(why, why_cap, "a receipt needs a group name");
        return false;
    }

    enum zcl_receipt_eligibility e =
        zcl_receipt_group_eligibility(ledger, group);
    if (e != ZCL_RECEIPT_ELIGIBLE) {
        if (why && why_cap)
            (void)snprintf(why, why_cap,
                "%s cannot produce a receipt: %s (ledger: %s)", group,
                zcl_receipt_eligibility_label(e),
                (ledger && ledger->source && ledger->source[0])
                    ? ledger->source
                    : "none wired");
        return false;
    }

    out->version = ZCL_RECEIPT_VERSION;
    out->kind    = (uint8_t)kind;
    out->verdict = (uint8_t)verdict;
    if (source_root) memcpy(out->source_root, source_root, 32);
    if (base_root && kind == ZCL_RECEIPT_KIND_RED_DELTA)
        memcpy(out->base_root, base_root, 32);
    if (verdict_vector) memcpy(out->verdict_vector, verdict_vector, 32);
    if (producer) memcpy(out->producer, producer, 32);
    out->checks_total = checks_total;

    if (!field_set(out->group, ZCL_RECEIPT_GROUP_MAX, group) ||
        !field_set(out->toolchain, ZCL_RECEIPT_TOOLCHAIN_MAX,
                   toolchain ? toolchain : "") ||
        !field_set(out->env_class, ZCL_RECEIPT_ENV_MAX,
                   env_class ? env_class : "")) {
        memset(out, 0, sizeof(*out));
        if (why && why_cap)
            (void)snprintf(why, why_cap,
                "a field does not fit its fixed width; a truncated name is a "
                "different name");
        return false;
    }

    if (!zcl_receipt_is_valid(out)) {
        memset(out, 0, sizeof(*out));
        if (why && why_cap)
            (void)snprintf(why, why_cap,
                "%s: the assembled receipt is not structurally valid", group);
        return false;
    }
    return true;
}
