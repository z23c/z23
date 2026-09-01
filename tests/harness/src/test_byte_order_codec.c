/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Hermetic coverage for the one fixed-width byte-order codec,
 * platform/modules/base/include/base/serialize_le.h.
 *
 * Two things are proved here, and they are different things.
 *
 * 1. THE BYTES ARE WHAT WE SAY THEY ARE. Every expected byte array in the
 *    first half of this file is hand-written. Nothing is derived from the
 *    function under test, and nothing is checked by round-tripping a value
 *    through write-then-read — a pair that swapped byte order in both
 *    directions would round-trip perfectly and still put the wrong bytes on
 *    the wire. Round-trips are tested too, but only AFTER the absolute byte
 *    layout is pinned.
 *
 * 2. NOTHING MOVED. The canonical functions replaced twenty-two file-private
 *    helpers, every one of which was serializing something that is now on
 *    disk, in a database column, or on the P2P wire. The second half of this
 *    file carries a verbatim copy of each replaced helper's ORIGINAL body,
 *    taken from the source files as they stood before the migration, and
 *    asserts that the canonical function agrees with it on a corpus that
 *    includes 0, 1, max, max-1, every single-bit value of the width, and
 *    every single-byte-position value. If a migration changed a byte, one of
 *    these comparisons fails.
 *
 *    The originals are reproduced here rather than being deleted outright so
 *    that the equivalence is CHECKED BY THE BUILD on every run, not asserted
 *    once in a commit message. They are the only copies of the shift ladder
 *    left in the tree, and lib/test is excluded from the
 *    check-byte-order-codec-single scan for exactly this reason.
 *
 * Unaligned access is covered explicitly: the canonical functions go through
 * memcpy so that a 64-bit store at an odd address is defined, and several of
 * the real call sites do exactly that (zendp.c writes a u64 at body+5, a u32
 * at body+13 and a u64 at body+17 inside one packed record).
 *
 * Pure and deterministic: no clock, no RNG, no I/O, no live DB. */

#include "test/test_core.h"

#include "base/serialize_le.h"
#include "crypto/common.h"

#include <stdint.h>
#include <string.h>

/* ─────────────────── the twenty-two originals, verbatim ─────────────────
 *
 * Bodies copied unchanged from the pre-migration sources. Renamed only by
 * an `orig_<file>_` prefix, because several of them shared a name across
 * files — which is the duplication this test exists to close out.
 *
 * cognition/controllers/src/agent_anchor_status_controller.c */
static uint32_t orig_anchor_ale32_read(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint64_t orig_anchor_ale64_read(const uint8_t *p)
{
    uint64_t v = 0;
    for (int i = 0; i < 8; i++)
        v |= ((uint64_t)p[i]) << (8 * i);
    return v;
}

/* engine/models/src/op_return_index.c */
static void orig_opreturn_put_le64(uint8_t out[8], int64_t v)
{
    uint64_t u = (uint64_t)v;
    for (int i = 0; i < 8; i++) out[i] = (uint8_t)(u >> (8 * i));
}

static int64_t orig_opreturn_get_le64(const uint8_t in[8])
{
    uint64_t u = 0;
    for (int i = 7; i >= 0; i--) u = (u << 8) | in[i];
    return (int64_t)u;
}

/* engine/composition/src/consensus_state_replay_receipt.c */
static void orig_replay_put_le64(uint8_t *p, uint64_t v)
{
    for (size_t i = 0; i < 8; i++)
        p[i] = (uint8_t)(v >> (8u * i));
}

static uint64_t orig_replay_get_le64(const uint8_t *p)
{
    uint64_t v = 0;
    for (size_t i = 0; i < 8; i++)
        v |= (uint64_t)p[i] << (8u * i);
    return v;
}

/* engine/composition/src/consensus_state_snapshot_candidate.c — the ENCODER of the
 * split pair. Its matching decoder lived in a different file. */
static void orig_candidate_le64_encode(uint8_t out[8], int64_t value)
{
    uint64_t encoded = (uint64_t)value;
    for (size_t i = 0; i < 8; i++)
        out[i] = (uint8_t)(encoded >> (8u * i));
}

/* engine/composition/src/consensus_state_snapshot_candidate_validate.c — the DECODER
 * of the split pair, for the same persisted progress_meta blob. */
static int64_t orig_candidate_le64_decode(const uint8_t value[8])
{
    uint64_t decoded = 0;
    for (size_t i = 0; i < 8; i++)
        decoded |= (uint64_t)value[i] << (8u * i);
    return (int64_t)decoded;
}

/* engine/modules/storage/src/snapshot_shielded.c */
static void orig_shielded_put_le32(uint8_t b[4], uint32_t v)
{
    b[0] = (uint8_t)v;         b[1] = (uint8_t)(v >> 8);
    b[2] = (uint8_t)(v >> 16); b[3] = (uint8_t)(v >> 24);
}

static void orig_shielded_put_le64(uint8_t b[8], uint64_t v)
{
    for (int i = 0; i < 8; i++) b[i] = (uint8_t)(v >> (8 * i));
}

/* platform/modules/util/src/png_writer.c — the one BIG-endian pair in the migration. */
static void orig_png_put_be32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)(v);
}

static void orig_png_put_le16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v);
    p[1] = (uint8_t)(v >> 8);
}

/* contexts/wallet/modules/zid/src/zdesc.c — copy one of three inside contexts/wallet/modules/zid. */
static void orig_zdesc_put_le64(uint8_t *p, uint64_t v)
{
    for (int i = 0; i < 8; i++)
        p[i] = (uint8_t)(v >> (8 * i));
}

static uint64_t orig_zdesc_get_le64(const uint8_t *p)
{
    uint64_t v = 0;
    for (int i = 7; i >= 0; i--)
        v = (v << 8) | p[i];
    return v;
}

/* contexts/wallet/modules/zid/src/zendp.c — copy two of three inside contexts/wallet/modules/zid, and the only one
 * that carried all three widths. */
static void orig_zendp_put_le16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v & 0xffu);
    p[1] = (uint8_t)((v >> 8) & 0xffu);
}

static uint16_t orig_zendp_get_le16(const uint8_t *p)
{
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

static void orig_zendp_put_le32(uint8_t *p, uint32_t v)
{
    for (int i = 0; i < 4; i++)
        p[i] = (uint8_t)(v >> (8 * i));
}

static uint32_t orig_zendp_get_le32(const uint8_t *p)
{
    uint32_t v = 0;
    for (int i = 3; i >= 0; i--)
        v = (v << 8) | p[i];
    return v;
}

static void orig_zendp_put_le64(uint8_t *p, uint64_t v)
{
    for (int i = 0; i < 8; i++)
        p[i] = (uint8_t)(v >> (8 * i));
}

static uint64_t orig_zendp_get_le64(const uint8_t *p)
{
    uint64_t v = 0;
    for (int i = 7; i >= 0; i--)
        v = (v << 8) | p[i];
    return v;
}

/* contexts/wallet/modules/zid/src/zid.c — copy three of three inside contexts/wallet/modules/zid. */
static void orig_zid_put_le64(uint8_t *p, uint64_t v)
{
    for (int i = 0; i < 8; i++)
        p[i] = (uint8_t)(v >> (8 * i));
}

static uint64_t orig_zid_get_le64(const uint8_t *p)
{
    uint64_t v = 0;
    for (int i = 7; i >= 0; i--)
        v = (v << 8) | p[i];
    return v;
}

/* ────────────────────────── value corpora ──────────────────────────── */
/* Boundaries, then every single-bit value, then every value that isolates
 * one byte position — the patterns that catch a swapped or dropped byte. */

#define U16_CORPUS_N (6 + 16 + 2)
static void u16_corpus(uint16_t out[U16_CORPUS_N])
{
    size_t n = 0;
    out[n++] = 0;
    out[n++] = 1;
    out[n++] = 0xFFFFu;
    out[n++] = 0xFFFEu;
    out[n++] = 0x8000u;
    out[n++] = 0x1234u;
    for (unsigned b = 0; b < 16; b++)
        out[n++] = (uint16_t)(1u << b);
    out[n++] = 0x00FFu;
    out[n++] = 0xFF00u;
}

#define U32_CORPUS_N (6 + 32 + 4)
static void u32_corpus(uint32_t out[U32_CORPUS_N])
{
    size_t n = 0;
    out[n++] = 0;
    out[n++] = 1;
    out[n++] = 0xFFFFFFFFu;
    out[n++] = 0xFFFFFFFEu;
    out[n++] = 0x80000000u;
    out[n++] = 0x12345678u;
    for (unsigned b = 0; b < 32; b++)
        out[n++] = 1u << b;
    for (unsigned k = 0; k < 4; k++)
        out[n++] = 0xFFu << (8 * k);
}

#define U64_CORPUS_N (6 + 64 + 8)
static void u64_corpus(uint64_t out[U64_CORPUS_N])
{
    size_t n = 0;
    out[n++] = 0;
    out[n++] = 1;
    out[n++] = 0xFFFFFFFFFFFFFFFFull;
    out[n++] = 0xFFFFFFFFFFFFFFFEull;
    out[n++] = 0x8000000000000000ull;
    out[n++] = 0x0123456789ABCDEFull;
    for (unsigned b = 0; b < 64; b++)
        out[n++] = 1ull << b;
    for (unsigned k = 0; k < 8; k++)
        out[n++] = 0xFFull << (8 * k);
}

int test_byte_order_codec(void);
int test_byte_order_codec(void)
{
    int failures = 0;

    /* ═══════════ 1. absolute byte layout, hand-written ═══════════════ */

    TEST("zcl_write_u16_le: least-significant byte lands at p[0]") {
        uint8_t got[2];
        const uint8_t want[2] = { 0x34, 0x12 };
        zcl_write_u16_le(got, 0x1234u);
        ASSERT_EQ(memcmp(got, want, 2), 0);
        PASS();
    }

    TEST("zcl_write_u32_le: hand-written 0x12345678 layout") {
        uint8_t got[4];
        const uint8_t want[4] = { 0x78, 0x56, 0x34, 0x12 };
        zcl_write_u32_le(got, 0x12345678u);
        ASSERT_EQ(memcmp(got, want, 4), 0);
        PASS();
    }

    TEST("zcl_write_u64_le: hand-written 0x0123456789ABCDEF layout") {
        uint8_t got[8];
        const uint8_t want[8] = {
            0xEF, 0xCD, 0xAB, 0x89, 0x67, 0x45, 0x23, 0x01
        };
        zcl_write_u64_le(got, 0x0123456789ABCDEFull);
        ASSERT_EQ(memcmp(got, want, 8), 0);
        PASS();
    }

    TEST("zcl_write_u32_be: hand-written 0x12345678 layout, reversed") {
        uint8_t got[4];
        const uint8_t want[4] = { 0x12, 0x34, 0x56, 0x78 };
        zcl_write_u32_be(got, 0x12345678u);
        ASSERT_EQ(memcmp(got, want, 4), 0);
        PASS();
    }

    TEST("zcl_write_u64_be: hand-written 0x0123456789ABCDEF layout") {
        uint8_t got[8];
        const uint8_t want[8] = {
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF
        };
        zcl_write_u64_be(got, 0x0123456789ABCDEFull);
        ASSERT_EQ(memcmp(got, want, 8), 0);
        PASS();
    }

    TEST("readers decode hand-written byte arrays, not their own output") {
        const uint8_t le16[2] = { 0x34, 0x12 };
        const uint8_t le32[4] = { 0x78, 0x56, 0x34, 0x12 };
        const uint8_t le64[8] = {
            0xEF, 0xCD, 0xAB, 0x89, 0x67, 0x45, 0x23, 0x01
        };
        const uint8_t be32[4] = { 0x12, 0x34, 0x56, 0x78 };
        const uint8_t be64[8] = {
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF
        };
        ASSERT_EQ(zcl_read_u16_le(le16), 0x1234u);
        ASSERT_EQ(zcl_read_u32_le(le32), 0x12345678u);
        ASSERT(zcl_read_u64_le(le64) == 0x0123456789ABCDEFull);
        ASSERT_EQ(zcl_read_u32_be(be32), 0x12345678u);
        ASSERT(zcl_read_u64_be(be64) == 0x0123456789ABCDEFull);
        PASS();
    }

    TEST("boundary values: 0, 1, max and max-1 at every width") {
        uint8_t b[8];

        zcl_write_u16_le(b, 0);
        ASSERT_EQ(b[0], 0x00); ASSERT_EQ(b[1], 0x00);
        zcl_write_u16_le(b, 1);
        ASSERT_EQ(b[0], 0x01); ASSERT_EQ(b[1], 0x00);
        zcl_write_u16_le(b, 0xFFFFu);
        ASSERT_EQ(b[0], 0xFF); ASSERT_EQ(b[1], 0xFF);
        zcl_write_u16_le(b, 0xFFFEu);
        ASSERT_EQ(b[0], 0xFE); ASSERT_EQ(b[1], 0xFF);

        zcl_write_u32_le(b, 0xFFFFFFFEu);
        ASSERT_EQ(b[0], 0xFE); ASSERT_EQ(b[1], 0xFF);
        ASSERT_EQ(b[2], 0xFF); ASSERT_EQ(b[3], 0xFF);

        zcl_write_u64_le(b, 0xFFFFFFFFFFFFFFFEull);
        ASSERT_EQ(b[0], 0xFE);
        for (int i = 1; i < 8; i++)
            ASSERT_EQ(b[i], 0xFF);

        zcl_write_u64_le(b, 1);
        ASSERT_EQ(b[0], 0x01);
        for (int i = 1; i < 8; i++)
            ASSERT_EQ(b[i], 0x00);
        PASS();
    }

    TEST("signed forms are the two's-complement bits, nothing more") {
        uint8_t b[8];
        const uint8_t minus_one[8] = {
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
        };
        const uint8_t i64_min[8] = {
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80
        };
        const uint8_t i64_max[8] = {
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F
        };

        zcl_write_i64_le(b, -1);
        ASSERT_EQ(memcmp(b, minus_one, 8), 0);
        ASSERT(zcl_read_i64_le(minus_one) == -1);

        zcl_write_i64_le(b, INT64_MIN);
        ASSERT_EQ(memcmp(b, i64_min, 8), 0);
        ASSERT(zcl_read_i64_le(i64_min) == INT64_MIN);

        zcl_write_i64_le(b, INT64_MAX);
        ASSERT_EQ(memcmp(b, i64_max, 8), 0);
        ASSERT(zcl_read_i64_le(i64_max) == INT64_MAX);

        zcl_write_i32_le(b, -1);
        ASSERT_EQ(b[0], 0xFF); ASSERT_EQ(b[1], 0xFF);
        ASSERT_EQ(b[2], 0xFF); ASSERT_EQ(b[3], 0xFF);
        ASSERT(zcl_read_i32_le(b) == -1);

        zcl_write_i32_le(b, INT32_MIN);
        ASSERT_EQ(b[0], 0x00); ASSERT_EQ(b[1], 0x00);
        ASSERT_EQ(b[2], 0x00); ASSERT_EQ(b[3], 0x80);
        ASSERT(zcl_read_i32_le(b) == INT32_MIN);
        PASS();
    }

    /* ═══════════ 2. unaligned buffers ═══════════════════════════════ */

    TEST("every width writes and reads correctly at every odd offset") {
        /* +8 slack so a 64-bit store at offset 7 stays inside the array. */
        uint8_t buf[24];
        for (size_t off = 0; off < 8; off++) {
            memset(buf, 0xA5, sizeof(buf));

            zcl_write_u16_le(buf + off, 0xBEEFu);
            ASSERT_EQ(zcl_read_u16_le(buf + off), 0xBEEFu);
            ASSERT_EQ(buf[off], 0xEF);
            ASSERT_EQ(buf[off + 1], 0xBE);
            /* the byte just past the field is untouched */
            ASSERT_EQ(buf[off + 2], 0xA5);

            zcl_write_u32_le(buf + off, 0xDEADBEEFu);
            ASSERT_EQ(zcl_read_u32_le(buf + off), 0xDEADBEEFu);
            ASSERT_EQ(buf[off], 0xEF);
            ASSERT_EQ(buf[off + 3], 0xDE);
            ASSERT_EQ(buf[off + 4], 0xA5);

            zcl_write_u64_le(buf + off, 0x0123456789ABCDEFull);
            ASSERT(zcl_read_u64_le(buf + off) == 0x0123456789ABCDEFull);
            ASSERT_EQ(buf[off], 0xEF);
            ASSERT_EQ(buf[off + 7], 0x01);
            ASSERT_EQ(buf[off + 8], 0xA5);

            zcl_write_u32_be(buf + off, 0xDEADBEEFu);
            ASSERT_EQ(zcl_read_u32_be(buf + off), 0xDEADBEEFu);
            ASSERT_EQ(buf[off], 0xDE);
            ASSERT_EQ(buf[off + 3], 0xEF);

            zcl_write_u64_be(buf + off, 0x0123456789ABCDEFull);
            ASSERT(zcl_read_u64_be(buf + off) == 0x0123456789ABCDEFull);
            ASSERT_EQ(buf[off], 0x01);
            ASSERT_EQ(buf[off + 7], 0xEF);
        }
        PASS();
    }

    /* ═══════════ 3. round-trip, after the layout is pinned ══════════ */

    TEST("round-trip: every corpus value survives write then read") {
        uint8_t b[8];

        uint16_t c16[U16_CORPUS_N];
        u16_corpus(c16);
        for (size_t i = 0; i < U16_CORPUS_N; i++) {
            zcl_write_u16_le(b, c16[i]);
            ASSERT_EQ(zcl_read_u16_le(b), c16[i]);
        }

        uint32_t c32[U32_CORPUS_N];
        u32_corpus(c32);
        for (size_t i = 0; i < U32_CORPUS_N; i++) {
            zcl_write_u32_le(b, c32[i]);
            ASSERT_EQ(zcl_read_u32_le(b), c32[i]);
            zcl_write_u32_be(b, c32[i]);
            ASSERT_EQ(zcl_read_u32_be(b), c32[i]);
            zcl_write_i32_le(b, (int32_t)c32[i]);
            ASSERT(zcl_read_i32_le(b) == (int32_t)c32[i]);
        }

        uint64_t c64[U64_CORPUS_N];
        u64_corpus(c64);
        for (size_t i = 0; i < U64_CORPUS_N; i++) {
            zcl_write_u64_le(b, c64[i]);
            ASSERT(zcl_read_u64_le(b) == c64[i]);
            zcl_write_u64_be(b, c64[i]);
            ASSERT(zcl_read_u64_be(b) == c64[i]);
            zcl_write_i64_le(b, (int64_t)c64[i]);
            ASSERT(zcl_read_i64_le(b) == (int64_t)c64[i]);
        }
        PASS();
    }

    TEST("little-endian and big-endian are byte-reverses of each other") {
        uint64_t c64[U64_CORPUS_N];
        u64_corpus(c64);
        for (size_t i = 0; i < U64_CORPUS_N; i++) {
            uint8_t le[8], be[8];
            zcl_write_u64_le(le, c64[i]);
            zcl_write_u64_be(be, c64[i]);
            for (int k = 0; k < 8; k++)
                ASSERT_EQ(le[k], be[7 - k]);
        }
        PASS();
    }

    /* ═══════════ 4. byte-identity vs the replaced originals ═════════ */
    /* One assertion per migrated call site's helper. A failure here means a
     * persisted or on-wire format moved. */

    TEST("agent_anchor_status_controller.c: ale32_read/ale64_read") {
        uint32_t c32[U32_CORPUS_N];
        u32_corpus(c32);
        for (size_t i = 0; i < U32_CORPUS_N; i++) {
            uint8_t b[4];
            zcl_write_u32_le(b, c32[i]);
            ASSERT_EQ(zcl_read_u32_le(b), orig_anchor_ale32_read(b));
        }
        uint64_t c64[U64_CORPUS_N];
        u64_corpus(c64);
        for (size_t i = 0; i < U64_CORPUS_N; i++) {
            uint8_t b[8];
            zcl_write_u64_le(b, c64[i]);
            ASSERT(zcl_read_u64_le(b) == orig_anchor_ale64_read(b));
        }
        PASS();
    }

    TEST("op_return_index.c: put_le64/get_le64 (the op_return record)") {
        uint64_t c64[U64_CORPUS_N];
        u64_corpus(c64);
        for (size_t i = 0; i < U64_CORPUS_N; i++) {
            int64_t v = (int64_t)c64[i];
            uint8_t mine[8], theirs[8];
            zcl_write_i64_le(mine, v);
            orig_opreturn_put_le64(theirs, v);
            ASSERT_EQ(memcmp(mine, theirs, 8), 0);
            ASSERT(zcl_read_i64_le(mine) == orig_opreturn_get_le64(mine));
        }
        PASS();
    }

    TEST("consensus_state_replay_receipt.c: put_le64/get_le64 (the frozen "
         "344-byte replay payload)") {
        uint64_t c64[U64_CORPUS_N];
        u64_corpus(c64);
        for (size_t i = 0; i < U64_CORPUS_N; i++) {
            uint8_t mine[8], theirs[8];
            zcl_write_u64_le(mine, c64[i]);
            orig_replay_put_le64(theirs, c64[i]);
            ASSERT_EQ(memcmp(mine, theirs, 8), 0);
            ASSERT(zcl_read_u64_le(mine) == orig_replay_get_le64(mine));
        }
        PASS();
    }

    TEST("snapshot candidate: the split encode/decode pair still agree "
         "with each other AND with both originals") {
        uint64_t c64[U64_CORPUS_N];
        u64_corpus(c64);
        for (size_t i = 0; i < U64_CORPUS_N; i++) {
            int64_t v = (int64_t)c64[i];
            uint8_t mine[8], theirs[8];

            /* the writer, in consensus_state_snapshot_candidate.c */
            zcl_write_i64_le(mine, v);
            orig_candidate_le64_encode(theirs, v);
            ASSERT_EQ(memcmp(mine, theirs, 8), 0);

            /* the reader, in ..._candidate_validate.c — a different file,
             * a different name, the same progress_meta blob */
            ASSERT(zcl_read_i64_le(theirs) == orig_candidate_le64_decode(theirs));
            ASSERT(zcl_read_i64_le(mine) == v);
        }
        PASS();
    }

    TEST("snapshot_shielded.c: put_le32/put_le64 (the shielded snapshot "
         "file, whose bytes are also the SHA3 input)") {
        uint32_t c32[U32_CORPUS_N];
        u32_corpus(c32);
        for (size_t i = 0; i < U32_CORPUS_N; i++) {
            uint8_t mine[4], theirs[4];
            zcl_write_u32_le(mine, c32[i]);
            orig_shielded_put_le32(theirs, c32[i]);
            ASSERT_EQ(memcmp(mine, theirs, 4), 0);
        }
        uint64_t c64[U64_CORPUS_N];
        u64_corpus(c64);
        for (size_t i = 0; i < U64_CORPUS_N; i++) {
            uint8_t mine[8], theirs[8];
            zcl_write_u64_le(mine, c64[i]);
            orig_shielded_put_le64(theirs, c64[i]);
            ASSERT_EQ(memcmp(mine, theirs, 8), 0);
        }
        PASS();
    }

    TEST("png_writer.c: put_be32/put_le16 (PNG chunk framing and the "
         "stored-deflate block header)") {
        uint32_t c32[U32_CORPUS_N];
        u32_corpus(c32);
        for (size_t i = 0; i < U32_CORPUS_N; i++) {
            uint8_t mine[4], theirs[4];
            zcl_write_u32_be(mine, c32[i]);
            orig_png_put_be32(theirs, c32[i]);
            ASSERT_EQ(memcmp(mine, theirs, 4), 0);
        }
        uint16_t c16[U16_CORPUS_N];
        u16_corpus(c16);
        for (size_t i = 0; i < U16_CORPUS_N; i++) {
            uint8_t mine[2], theirs[2];
            zcl_write_u16_le(mine, c16[i]);
            orig_png_put_le16(theirs, c16[i]);
            ASSERT_EQ(memcmp(mine, theirs, 2), 0);
        }
        PASS();
    }

    TEST("contexts/wallet/modules/zid: all three private copies agreed with each other and "
         "with the canonical one") {
        uint16_t c16[U16_CORPUS_N];
        u16_corpus(c16);
        for (size_t i = 0; i < U16_CORPUS_N; i++) {
            uint8_t mine[2], theirs[2];
            zcl_write_u16_le(mine, c16[i]);
            orig_zendp_put_le16(theirs, c16[i]);
            ASSERT_EQ(memcmp(mine, theirs, 2), 0);
            ASSERT_EQ(zcl_read_u16_le(mine), orig_zendp_get_le16(mine));
        }

        uint32_t c32[U32_CORPUS_N];
        u32_corpus(c32);
        for (size_t i = 0; i < U32_CORPUS_N; i++) {
            uint8_t mine[4], theirs[4];
            zcl_write_u32_le(mine, c32[i]);
            orig_zendp_put_le32(theirs, c32[i]);
            ASSERT_EQ(memcmp(mine, theirs, 4), 0);
            ASSERT_EQ(zcl_read_u32_le(mine), orig_zendp_get_le32(mine));
        }

        uint64_t c64[U64_CORPUS_N];
        u64_corpus(c64);
        for (size_t i = 0; i < U64_CORPUS_N; i++) {
            uint8_t mine[8], zdesc[8], zendp[8], zid[8];
            zcl_write_u64_le(mine, c64[i]);
            orig_zdesc_put_le64(zdesc, c64[i]);
            orig_zendp_put_le64(zendp, c64[i]);
            orig_zid_put_le64(zid, c64[i]);
            ASSERT_EQ(memcmp(mine, zdesc, 8), 0);
            ASSERT_EQ(memcmp(mine, zendp, 8), 0);
            ASSERT_EQ(memcmp(mine, zid, 8), 0);
            ASSERT(zcl_read_u64_le(mine) == orig_zdesc_get_le64(mine));
            ASSERT(zcl_read_u64_le(mine) == orig_zendp_get_le64(mine));
            ASSERT(zcl_read_u64_le(mine) == orig_zid_get_le64(mine));
        }
        PASS();
    }

    /* ═══════════ 5. crypto/common.h still speaks for its callers ════ */
    /* Two of ReadLE32's twelve includers are under the byte-sealed core/
     * (core/math/src/hash.c and arith_uint256.c). The forwarding must be
     * transparent, so the Bitcoin Core spelling is pinned here too. */

    TEST("crypto/common.h forwards without changing a byte") {
        uint8_t b[8];
        const uint8_t le32[4] = { 0x78, 0x56, 0x34, 0x12 };
        const uint8_t be32[4] = { 0x12, 0x34, 0x56, 0x78 };

        ASSERT_EQ(ReadLE16((const unsigned char *)le32), 0x5678u);
        ASSERT_EQ(ReadLE32((const unsigned char *)le32), 0x12345678u);
        ASSERT_EQ(ReadBE32((const unsigned char *)be32), 0x12345678u);

        WriteLE32((unsigned char *)b, 0x12345678u);
        ASSERT_EQ(memcmp(b, le32, 4), 0);
        WriteBE32((unsigned char *)b, 0x12345678u);
        ASSERT_EQ(memcmp(b, be32, 4), 0);

        WriteLE64((unsigned char *)b, 0x0123456789ABCDEFull);
        ASSERT(ReadLE64((const unsigned char *)b) == 0x0123456789ABCDEFull);
        ASSERT_EQ(b[0], 0xEF);
        ASSERT_EQ(b[7], 0x01);

        WriteBE64((unsigned char *)b, 0x0123456789ABCDEFull);
        ASSERT(ReadBE64((const unsigned char *)b) == 0x0123456789ABCDEFull);
        ASSERT_EQ(b[0], 0x01);
        ASSERT_EQ(b[7], 0xEF);

        WriteLE16((unsigned char *)b, 0x1234u);
        ASSERT_EQ(b[0], 0x34);
        ASSERT_EQ(b[1], 0x12);
        PASS();
    }

_test_next:;
    if (failures == 0)
        printf("test_byte_order_codec: all passed\n");
    else
        printf("test_byte_order_codec: %d FAILED\n", failures);
    return failures;
}
