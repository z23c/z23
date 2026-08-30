/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Purpose: encode, decode and adjudicate a determinism receipt, field at a
 * time, so the bytes are the same at -O0 and -O2 and on every platform.
 *
 * A receipt is evidence, never permission. See determinism/receipt.h. */

#include "determinism/receipt.h"

#include "base/log_macros.h"
#include "codec/cursor.h"
#include "sha3/sha3.h"

#include <stdio.h>
#include <string.h>

static const uint8_t k_magic[4] = { 'Z', 'D', 'R', '1' };

const char *zcl_det_corroboration_name(enum zcl_det_corroboration c)
{
    switch (c) {
    case ZCL_DET_INDETERMINATE: return "UNKNOWN";
    case ZCL_DET_CORROBORATED: return "CORROBORATED";
    case ZCL_DET_REFUTED: return "REFUTED";
    }
    return "INVALID";
}

void zcl_det_receipt_label_digest(const char *label,
                                  uint8_t out[ZCL_DET_DIGEST_LEN])
{
    if (!out) return;
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    static const char domain[] = "zcl.determinism.label.v1";
    sha3_256_write(&ctx, (const unsigned char *)domain, sizeof(domain));
    if (label)
        sha3_256_write(&ctx, (const unsigned char *)label, strlen(label));
    sha3_256_finalize(&ctx, out);
}

bool zcl_det_receipt_set_commit(struct zcl_det_receipt *r, const char *hex)
{
    if (!r || !hex) LOG_FAIL("determinism", "null receipt or commit hex");
    size_t n = strnlen(hex, 65);
    if (n != 40 && n != 64)
        LOG_FAIL("determinism",
                 "commit id must be 40 or 64 hex characters, got %zu", n);
    memset(r->commit, 0, sizeof(r->commit));
    return zcl_det_unhex(hex, r->commit, n / 2);
}

/* A fixed-width text field: exactly `width` bytes, the string then NUL fill.
 * Reading it back requires the fill to be all-NUL, so the mapping between a
 * name and its bytes is one-to-one and a decoder cannot be handed two
 * different encodings of the same receipt. */
static bool write_fixed_text(struct zcl_codec_writer *w, const char *s,
                             size_t width)
{
    uint8_t field[ZCL_DET_GROUP_MAX];
    if (width > sizeof(field)) return false;
    size_t n = strnlen(s, width);
    if (n == width) return false; /* no room for the terminator: refuse */
    memset(field, 0, width);
    memcpy(field, s, n);
    return zcl_codec_write_bytes(w, field, width);
}

static bool read_fixed_text(struct zcl_codec_reader *rd, char *out,
                            size_t width)
{
    uint8_t field[ZCL_DET_GROUP_MAX];
    if (width > sizeof(field)) return false;
    if (!zcl_codec_read_bytes(rd, field, width)) return false;
    size_t n = 0;
    while (n < width && field[n] != 0) n++;
    if (n == 0) return false;            /* empty group id is not a record */
    if (n == width) return false;        /* unterminated */
    for (size_t i = n; i < width; i++)
        if (field[i] != 0) return false; /* non-canonical padding */
    for (size_t i = 0; i < n; i++)
        if (field[i] < 0x20 || field[i] >= 0x7F) return false;
    memcpy(out, field, n);
    out[n] = '\0';
    return true;
}

bool zcl_det_receipt_encode(const struct zcl_det_receipt *r, uint8_t *out,
                            size_t out_cap, size_t *out_len)
{
    if (!r || !out) LOG_FAIL("determinism", "null receipt or output buffer");
    if (out_cap < ZCL_DET_RECEIPT_SIZE)
        LOG_FAIL("determinism", "receipt buffer %zu < %u bytes", out_cap,
                 ZCL_DET_RECEIPT_SIZE);

    struct zcl_codec_writer w;
    zcl_codec_writer_init(&w, out, ZCL_DET_RECEIPT_SIZE);

    bool ok = zcl_codec_write_bytes(&w, k_magic, sizeof(k_magic));
    ok = ok && zcl_codec_write_u16le(&w, r->version);
    ok = ok && zcl_codec_write_bytes(&w, r->commit, sizeof(r->commit));
    ok = ok && write_fixed_text(&w, r->group, ZCL_DET_GROUP_MAX);
    ok = ok && zcl_codec_write_bytes(&w, r->toolchain, sizeof(r->toolchain));
    ok = ok && zcl_codec_write_bytes(&w, r->env_class, sizeof(r->env_class));
    ok = ok && zcl_codec_write_u8(&w, r->verdict);
    ok = ok && zcl_codec_write_u8(&w, r->reason);
    ok = ok && zcl_codec_write_u16le(&w, r->perturbations);
    ok = ok && zcl_codec_write_u32le(&w, r->split_mask);
    ok = ok && zcl_codec_write_u32le(&w, r->check_count);
    ok = ok && zcl_codec_write_bytes(&w, r->vector, sizeof(r->vector));
    ok = ok && zcl_codec_write_bytes(&w, r->producer, sizeof(r->producer));
    if (!ok) LOG_FAIL("determinism", "receipt encode: %s",
                      zcl_codec_error_string(w.error));

    size_t written = 0;
    if (!zcl_codec_writer_finish(&w, &written))
        LOG_FAIL("determinism", "receipt encode did not finish cleanly");
    if (written != ZCL_DET_RECEIPT_SIZE)
        LOG_FAIL("determinism",
                 "receipt encoded %zu bytes, the pinned layout is %u", written,
                 ZCL_DET_RECEIPT_SIZE);
    if (out_len) *out_len = written;
    return true;
}

bool zcl_det_receipt_decode(const uint8_t *bytes, size_t len,
                            struct zcl_det_receipt *out)
{
    if (!bytes || !out) LOG_FAIL("determinism", "null receipt bytes or output");
    if (len != ZCL_DET_RECEIPT_SIZE)
        LOG_FAIL("determinism", "receipt is %zu bytes, the layout is %u", len,
                 ZCL_DET_RECEIPT_SIZE);

    struct zcl_codec_reader rd;
    zcl_codec_reader_init(&rd, bytes, len);

    uint8_t magic[4];
    if (!zcl_codec_read_bytes(&rd, magic, sizeof(magic)))
        LOG_FAIL("determinism", "receipt too short for its magic");
    if (memcmp(magic, k_magic, sizeof(k_magic)) != 0)
        LOG_FAIL("determinism", "receipt magic mismatch");

    struct zcl_det_receipt r;
    memset(&r, 0, sizeof(r));

    bool ok = zcl_codec_read_u16le(&rd, &r.version);
    if (!ok) LOG_FAIL("determinism", "receipt version unreadable");
    if (r.version != ZCL_DET_RECEIPT_VERSION)
        LOG_FAIL("determinism", "receipt version %u, this build speaks %u",
                 (unsigned)r.version, ZCL_DET_RECEIPT_VERSION);

    ok = zcl_codec_read_bytes(&rd, r.commit, sizeof(r.commit));
    ok = ok && read_fixed_text(&rd, r.group, ZCL_DET_GROUP_MAX);
    ok = ok && zcl_codec_read_bytes(&rd, r.toolchain, sizeof(r.toolchain));
    ok = ok && zcl_codec_read_bytes(&rd, r.env_class, sizeof(r.env_class));
    ok = ok && zcl_codec_read_u8(&rd, &r.verdict);
    ok = ok && zcl_codec_read_u8(&rd, &r.reason);
    ok = ok && zcl_codec_read_u16le(&rd, &r.perturbations);
    ok = ok && zcl_codec_read_u32le(&rd, &r.split_mask);
    ok = ok && zcl_codec_read_u32le(&rd, &r.check_count);
    ok = ok && zcl_codec_read_bytes(&rd, r.vector, sizeof(r.vector));
    ok = ok && zcl_codec_read_bytes(&rd, r.producer, sizeof(r.producer));
    if (!ok) LOG_FAIL("determinism", "receipt decode: %s",
                      zcl_codec_error_string(rd.error));

    if (r.verdict < ZCL_DET_CLASS_DETERMINISTIC ||
        r.verdict > ZCL_DET_CLASS_UNKNOWN)
        LOG_FAIL("determinism", "receipt verdict %u out of range",
                 (unsigned)r.verdict);
    if (r.reason > ZCL_DET_UNKNOWN_PARTIAL)
        LOG_FAIL("determinism", "receipt reason %u out of range",
                 (unsigned)r.reason);
    /* A measured verdict may not carry an unknown-reason, and an UNKNOWN
     * verdict must carry one. Otherwise the record could say two things. */
    if (r.verdict == ZCL_DET_CLASS_UNKNOWN) {
        if (r.reason == ZCL_DET_UNKNOWN_NONE)
            LOG_FAIL("determinism", "UNKNOWN receipt with no reason");
    } else if (r.reason != ZCL_DET_UNKNOWN_NONE) {
        LOG_FAIL("determinism", "measured receipt carries an unknown-reason");
    }
    /* Only a NONDETERMINISTIC verdict may name a splitting perturbation. */
    if (r.verdict != ZCL_DET_CLASS_NONDETERMINISTIC && r.split_mask != 0)
        LOG_FAIL("determinism", "non-empty split mask on a %s receipt",
                 zcl_det_class_name((enum zcl_det_class)r.verdict));
    if (r.verdict == ZCL_DET_CLASS_NONDETERMINISTIC && r.split_mask == 0)
        LOG_FAIL("determinism",
                 "NONDETERMINISTIC receipt names no perturbation; "
                 "\"it varies\" is not a finding");

    if (!zcl_codec_reader_finish(&rd))
        LOG_FAIL("determinism", "trailing bytes after the receipt");

    *out = r;
    return true;
}

static void say(char *why, size_t cap, const char *msg)
{
    if (!why || cap == 0) return;
    snprintf(why, cap, "%s", msg);
}

enum zcl_det_corroboration zcl_det_receipt_check(
    const struct zcl_det_receipt *claim, const struct zcl_det_receipt *fresh,
    char *why, size_t why_cap)
{
    /* Everything below returns INDETERMINATE by default. The only paths to
     * CORROBORATED or REFUTED are the two explicit ones at the end. */
    say(why, why_cap, "no comparison was made");
    if (!claim || !fresh) {
        say(why, why_cap, "a receipt was absent");
        return ZCL_DET_INDETERMINATE;
    }
    if (claim->version != fresh->version) {
        say(why, why_cap, "receipt versions differ");
        return ZCL_DET_INDETERMINATE;
    }
    if (strncmp(claim->group, fresh->group, ZCL_DET_GROUP_MAX) != 0) {
        say(why, why_cap, "the receipts are about different groups");
        return ZCL_DET_INDETERMINATE;
    }
    if (memcmp(claim->commit, fresh->commit, sizeof(claim->commit)) != 0) {
        say(why, why_cap,
            "the commit the claim names is not the commit that was run");
        return ZCL_DET_INDETERMINATE;
    }
    if (memcmp(claim->toolchain, fresh->toolchain,
               sizeof(claim->toolchain)) != 0) {
        say(why, why_cap,
            "the toolchain the claim names is not available here");
        return ZCL_DET_INDETERMINATE;
    }
    if (memcmp(claim->env_class, fresh->env_class,
               sizeof(claim->env_class)) != 0) {
        say(why, why_cap, "the environment classes differ");
        return ZCL_DET_INDETERMINATE;
    }
    if (claim->verdict == ZCL_DET_CLASS_UNKNOWN ||
        fresh->verdict == ZCL_DET_CLASS_UNKNOWN) {
        say(why, why_cap,
            "one side could not be measured; an unmeasured run neither "
            "confirms nor refutes");
        return ZCL_DET_INDETERMINATE;
    }
    if (claim->verdict == fresh->verdict &&
        claim->check_count == fresh->check_count &&
        claim->split_mask == fresh->split_mask &&
        memcmp(claim->vector, fresh->vector, sizeof(claim->vector)) == 0) {
        say(why, why_cap, "same commit, same toolchain, same verdict vector");
        return ZCL_DET_CORROBORATED;
    }
    say(why, why_cap,
        "same commit and toolchain, different verdict vector or verdict");
    return ZCL_DET_REFUTED;
}
