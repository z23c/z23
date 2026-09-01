/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Hermetic engine tests for the pure PNG encoder helpers in
 * platform/modules/util/src/png_writer.c: CRC32 (crc32_init / crc32_update), Adler32,
 * the big-endian/little-endian byte writers it now calls from the one
 * codec in platform/modules/base (zcl_write_u32_be / zcl_write_u16_le), the
 * PNG chunk framer (write_chunk), the stored-DEFLATE-in-zlib IDAT builder
 * (build_idat), and the public entry point png_write_rgb.
 *
 * Most helpers under test are `static` inside png_writer.c, so this file
 * gets white-box access the same way test_chaos_harness.c and
 * test_postmortem_to_scenario.c do: by #include-ing the .c file directly
 * instead of linking against it.
 *
 * Deterministic only:
 *   - CRC32/Adler32 known-answer vectors were cross-checked against a
 *     from-scratch reference implementation (not png_writer.c's own
 *     tables) computed offline; the constants below are the result.
 *   - build_idat / png_write_rgb round trips are verified with a
 *     from-scratch stored-DEFLATE-in-zlib decoder written in this file
 *     (pngw_inflate_stored) rather than by re-deriving expectations from
 *     the same production code path.
 *   - The two OOM branches inside build_idat are driven with the real
 *     checked-allocation fault-injection hook (zcl_alloc_fault_fail_next),
 *     the same mechanism test_coins.c / test_wallet.c / test_fees_oom.c
 *     already use — not a synthetic stub.
 * No node.db, no live node, no clock, no network. */

#include "test/test_core.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* png_write_rgb has external linkage and platform/modules/util/src/png_writer.c is
 * already compiled + linked into test_zcl as part of the production
 * library (it's the source hodl_controller.c calls to render charts).
 * #include-ing the .c file verbatim to reach its `static` helpers would
 * therefore redefine that externally-linked symbol and fail the link
 * with a duplicate-definition error. Rename it around the include so
 * this translation unit gets its own privately-linked (internal to this
 * TU only, still externally-linked by name but never referenced outside
 * it) copy under a name that can't collide, then call that copy below —
 * it is line-for-line the same production code, just textually renamed
 * by the preprocessor before either the declaration (in png_writer.h) or
 * the definition (in png_writer.c) is compiled. */
#define png_write_rgb pngw_under_test_write_rgb
#include "../../util/src/png_writer.c"
#undef png_write_rgb

#define PNGW_CHECK(name, expr) do {                                  \
    printf("test_png_writer: %s... ", (name));                      \
    if (expr) printf("OK\n");                                        \
    else { printf("FAIL\n"); failures++; }                           \
} while (0)

/* ── Independent (non-production) byte readers ─────────────────────
 * Deliberately NOT calling zcl_write_u32_be/zcl_write_u16_le in reverse,
 * so the chunk/IDAT structural checks below aren't tautological with the
 * writers under test. */
static uint32_t pngw_rd_be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static uint16_t pngw_rd_le16(const uint8_t *p)
{
    return (uint16_t)((uint16_t)p[0] | (uint16_t)(p[1] << 8));
}

/* From-scratch stored-DEFLATE-in-zlib decoder matching the wire format
 * build_idat produces: 2-byte zlib header, one-or-more BTYPE=00 stored
 * blocks, big-endian Adler32 trailer. Returns the decoded length, or
 * SIZE_MAX on any structural violation (including an Adler32 mismatch,
 * checked via the SAME adler32() helper under test — legitimate here
 * because adler32() already has its own known-answer coverage below;
 * this decoder is testing build_idat's *framing*, not re-deriving
 * Adler32 itself). */
static size_t pngw_inflate_stored(const uint8_t *idat, size_t idat_len,
                                   uint8_t *out, size_t out_cap)
{
    if (idat_len < 2 + 4) return SIZE_MAX;
    if (idat[0] != 0x78 || idat[1] != 0x01) return SIZE_MAX;
    size_t pos = 2;
    size_t out_len = 0;
    bool final_seen = false;
    while (!final_seen) {
        if (pos + 5 > idat_len - 4) return SIZE_MAX;
        uint8_t bfinal_btype = idat[pos++];
        if ((bfinal_btype & 0x06) != 0) return SIZE_MAX; /* only BTYPE=00 */
        bool is_final = (bfinal_btype & 0x01) != 0;
        uint16_t len = pngw_rd_le16(&idat[pos]);
        uint16_t nlen = pngw_rd_le16(&idat[pos + 2]);
        pos += 4;
        if ((uint16_t)(~len & 0xFFFFu) != nlen) return SIZE_MAX;
        if (pos + len > idat_len - 4) return SIZE_MAX;
        if (out_len + len > out_cap) return SIZE_MAX;
        memcpy(out + out_len, idat + pos, len);
        out_len += len;
        pos += len;
        final_seen = is_final;
    }
    if (pos != idat_len - 4) return SIZE_MAX; /* must land exactly on trailer */
    uint32_t stored_adler = pngw_rd_be32(&idat[pos]);
    if (stored_adler != adler32(out, out_len)) return SIZE_MAX;
    return out_len;
}

/* Build the PNG-spec-mandated filtered scanline layout (1 filter byte
 * "None" + row bytes, per row) independently of build_idat's own
 * internal loop, as the expected value for content comparisons. */
static void pngw_build_expected_filtered(const uint8_t *pixels, uint32_t w,
                                          uint32_t h, uint8_t *out)
{
    size_t row_bytes = (size_t)w * 3;
    for (uint32_t y = 0; y < h; y++) {
        out[y * (1 + row_bytes)] = 0x00;
        memcpy(&out[y * (1 + row_bytes) + 1], &pixels[y * row_bytes], row_bytes);
    }
}

/* Read one PNG chunk (length/type/data/crc), verifying the CRC via the
 * production crc32_update as an integration check of write_chunk's
 * wiring. Caller frees *data_out (zcl_malloc'd) when len>0. */
static bool pngw_read_chunk(FILE *f, char type_out[5], uint8_t **data_out,
                             uint32_t *len_out)
{
    uint8_t hdr[4];
    if (fread(hdr, 1, 4, f) != 4) return false;
    uint32_t len = pngw_rd_be32(hdr);
    char type[4];
    if (fread(type, 1, 4, f) != 4) return false;
    uint8_t *data = NULL;
    if (len > 0) {
        data = zcl_malloc(len, "pngw_test_chunk");
        if (!data) return false;
        if (fread(data, 1, len, f) != len) { free(data); return false; }
    }
    uint8_t crcbuf[4];
    if (fread(crcbuf, 1, 4, f) != 4) { free(data); return false; }
    uint32_t stored_crc = pngw_rd_be32(crcbuf);
    uint32_t computed = crc32_update(0, (const uint8_t *)type, 4);
    if (len > 0) computed = crc32_update(computed, data, len);
    if (computed != stored_crc) { free(data); return false; }
    memcpy(type_out, type, 4);
    type_out[4] = 0;
    *data_out = data;
    *len_out = len;
    return true;
}

int test_test_png_writer(void);
int test_test_png_writer(void)
{
    int failures = 0;

    /* ───────────────────────── crc32_init / crc32_update ───────────────────────── */
    {
        PNGW_CHECK("crc32: empty input is the XOR identity (0)",
                   crc32_update(0, (const uint8_t *)"", 0) == 0);

        PNGW_CHECK("crc32: known-answer \"123456789\" == 0xCBF43926",
                   crc32_update(0, (const uint8_t *)"123456789", 9) ==
                       0xCBF43926u);

        /* Chaining: two calls (crc-over-part1 fed as the seed for
         * crc-over-part2) must equal a single call over the whole
         * buffer — this is exactly the pattern write_chunk relies on
         * (crc over type, then chained crc over data). */
        const char *whole = "1234567890abcdef";
        uint32_t whole_crc =
            crc32_update(0, (const uint8_t *)whole, strlen(whole));
        uint32_t part_crc = crc32_update(0, (const uint8_t *)whole, 7);
        part_crc = crc32_update(part_crc, (const uint8_t *)whole + 7,
                                 strlen(whole) - 7);
        PNGW_CHECK("crc32: incremental chaining matches single-call CRC",
                   part_crc == whole_crc);
        PNGW_CHECK("crc32: known-answer 16-byte chained result == 0x5CA32739",
                   whole_crc == 0x5CA32739u);

        /* crc32_init() is idempotent behind the lazy-init guard inside
         * crc32_update; calling it directly a second time must not
         * perturb already-computed table entries. */
        crc32_init();
        crc32_init();
        PNGW_CHECK("crc32: table[0] == 0 (n=0 stays 0 through 8 shift rounds)",
                   crc32_table[0] == 0);
        PNGW_CHECK("crc32: table[1] == 0x77073096 (CRC-32/ISO-HDLC entry)",
                   crc32_table[1] == 0x77073096u);
    }

    /* ───────────────────────────────── adler32 ───────────────────────────────── */
    {
        PNGW_CHECK("adler32: empty input == 1 (a=1,b=0)",
                   adler32((const uint8_t *)"", 0) == 1);
        PNGW_CHECK("adler32: known-answer \"a\" == 0x00620062",
                   adler32((const uint8_t *)"a", 1) == 0x00620062u);
        PNGW_CHECK("adler32: known-answer \"Wikipedia\" == 0x11E60398",
                   adler32((const uint8_t *)"Wikipedia", 9) == 0x11E60398u);

        /* Modulo-65521 wraparound: 6000 bytes of 0xFF pushes both running
         * sums well past 65521 many times over. */
        uint8_t big[6000];
        memset(big, 0xFF, sizeof(big));
        PNGW_CHECK("adler32: known-answer 6000x0xFF wraparound == 0xA49759EA",
                   adler32(big, sizeof(big)) == 0xA49759EAu);
    }

    /* ─────────────────── zcl_write_u32_be / zcl_write_u16_le ─────────────────── */
    {
        uint8_t b4[4];
        zcl_write_u32_be(b4, 0x11223344u);
        PNGW_CHECK("put_be32: 0x11223344 -> {11,22,33,44}",
                   b4[0] == 0x11 && b4[1] == 0x22 && b4[2] == 0x33 &&
                       b4[3] == 0x44);

        zcl_write_u32_be(b4, 0);
        PNGW_CHECK("put_be32: 0 -> all-zero bytes",
                   b4[0] == 0 && b4[1] == 0 && b4[2] == 0 && b4[3] == 0);

        zcl_write_u32_be(b4, 0xFFFFFFFFu);
        PNGW_CHECK("put_be32: UINT32_MAX -> all-0xFF bytes",
                   b4[0] == 0xFF && b4[1] == 0xFF && b4[2] == 0xFF &&
                       b4[3] == 0xFF);

        uint8_t b2[2];
        zcl_write_u16_le(b2, 0x1234u);
        PNGW_CHECK("put_le16: 0x1234 -> {34,12} (low byte first)",
                   b2[0] == 0x34 && b2[1] == 0x12);

        zcl_write_u16_le(b2, 0);
        PNGW_CHECK("put_le16: 0 -> all-zero bytes", b2[0] == 0 && b2[1] == 0);

        zcl_write_u16_le(b2, 0xFFFFu);
        PNGW_CHECK("put_le16: UINT16_MAX -> all-0xFF bytes",
                   b2[0] == 0xFF && b2[1] == 0xFF);
    }

    /* ───────────────────────────────── write_chunk ───────────────────────────────── */
    {
        char path[128];
        strcpy(path, "/tmp/zcl_png_writer_chunk_XXXXXX");
        int fd = mkstemp(path);
        PNGW_CHECK("write_chunk: fixture mkstemp ok", fd >= 0);
        static const uint8_t data[4] = {0xDE, 0xAD, 0xBE, 0xEF};
        if (fd >= 0) {
            FILE *f = fdopen(fd, "wb");
            PNGW_CHECK("write_chunk: fixture fdopen ok", f != NULL);
            if (f) {
                PNGW_CHECK("write_chunk: data chunk write returns true",
                           write_chunk(f, "TEST", data, 4));
                PNGW_CHECK("write_chunk: zero-length chunk write returns true",
                           write_chunk(f, "IEND", NULL, 0));
                fclose(f);
            }

            FILE *rf = fopen(path, "rb");
            PNGW_CHECK("write_chunk: readback fopen ok", rf != NULL);
            if (rf) {
                char type[5];
                uint8_t *cdata = NULL;
                uint32_t clen = 0;
                bool ok1 = pngw_read_chunk(rf, type, &cdata, &clen);
                PNGW_CHECK("write_chunk: readback of data chunk parses + CRC verifies",
                           ok1);
                PNGW_CHECK("write_chunk: readback length == 4",
                           ok1 && clen == 4);
                PNGW_CHECK("write_chunk: readback type == \"TEST\"",
                           ok1 && memcmp(type, "TEST", 4) == 0);
                PNGW_CHECK("write_chunk: readback data bytes match",
                           ok1 && clen == 4 && memcmp(cdata, data, 4) == 0);
                if (cdata) free(cdata);

                char type2[5];
                uint8_t *cdata2 = NULL;
                uint32_t clen2 = 0;
                bool ok2 = pngw_read_chunk(rf, type2, &cdata2, &clen2);
                PNGW_CHECK("write_chunk: readback of zero-length chunk parses + CRC verifies",
                           ok2);
                PNGW_CHECK("write_chunk: readback zero-length chunk has len 0",
                           ok2 && clen2 == 0);
                PNGW_CHECK("write_chunk: readback zero-length chunk type == \"IEND\"",
                           ok2 && memcmp(type2, "IEND", 4) == 0);
                if (cdata2) free(cdata2);

                fclose(rf);
            }
            unlink(path);
        }

        /* Failure path: fwrite onto a read-only stream must make
         * write_chunk report false (no silent partial-write success). */
        char rpath[128];
        strcpy(rpath, "/tmp/zcl_png_writer_ro_XXXXXX");
        int rfd = mkstemp(rpath);
        PNGW_CHECK("write_chunk failure fixture: mkstemp ok", rfd >= 0);
        if (rfd >= 0) {
            close(rfd);
            FILE *rof = fopen(rpath, "rb");
            PNGW_CHECK("write_chunk failure fixture: read-only fopen ok",
                       rof != NULL);
            if (rof) {
                static const uint8_t data[4] = {1, 2, 3, 4};
                PNGW_CHECK("write_chunk: write onto a read-only stream returns false",
                           !write_chunk(rof, "FAIL", data, 4));
                fclose(rof);
            }
            unlink(rpath);
        }
    }

    /* ───────────────────────────────── build_idat ───────────────────────────────── */
    {
        /* (A) Single-block image: filtered_len (39) well under the
         * 65535-byte stored-block cap -> exactly one final block. */
        const uint32_t w = 4, h = 3;
        size_t row_bytes = (size_t)w * 3;
        size_t filtered_len = (size_t)h * (1 + row_bytes);
        uint8_t pixels[36];
        for (size_t i = 0; i < sizeof(pixels); i++)
            pixels[i] = (uint8_t)(i * 7 + 3);
        uint8_t expected[39];
        pngw_build_expected_filtered(pixels, w, h, expected);

        size_t idat_len = 0;
        uint8_t *idat = build_idat(pixels, w, h, &idat_len);
        PNGW_CHECK("build_idat: single-block returns non-NULL", idat != NULL);
        if (idat) {
            PNGW_CHECK("build_idat: single-block idat_len == 2+5+39+4 == 50",
                       idat_len == 50);
            PNGW_CHECK("build_idat: zlib header == {0x78,0x01}",
                       idat[0] == 0x78 && idat[1] == 0x01);
            PNGW_CHECK("build_idat: single block is BFINAL|BTYPE=00 (0x01)",
                       idat_len >= 3 && idat[2] == 0x01);
            PNGW_CHECK("build_idat: single block LEN == filtered_len (39)",
                       idat_len >= 5 && pngw_rd_le16(&idat[3]) == 39);
            PNGW_CHECK("build_idat: single block NLEN == ~LEN",
                       idat_len >= 7 &&
                           pngw_rd_le16(&idat[5]) == (uint16_t)(~39u & 0xFFFFu));
            PNGW_CHECK("build_idat: single block payload matches expected filtered bytes",
                       idat_len >= 46 && memcmp(&idat[7], expected, filtered_len) == 0);
            PNGW_CHECK("build_idat: trailing Adler32 matches adler32(expected)",
                       idat_len == 50 &&
                           pngw_rd_be32(&idat[46]) == adler32(expected, filtered_len));

            uint8_t decoded[64];
            size_t dec_len = pngw_inflate_stored(idat, idat_len, decoded, sizeof(decoded));
            PNGW_CHECK("build_idat: from-scratch decoder round-trips single-block content",
                       dec_len == filtered_len &&
                           memcmp(decoded, expected, filtered_len) == 0);
            free(idat);
        }

        /* (B) Multi-block image: filtered_len (270300) forces 5 stored
         * blocks (4 x 65535 + 1 x 8160), exercising the 65535-byte cap,
         * per-block NLEN, and BFINAL placement only on the LAST block. */
        const uint32_t bw = 300, bh = 300;
        size_t brow_bytes = (size_t)bw * 3;
        size_t bfiltered_len = (size_t)bh * (1 + brow_bytes);
        PNGW_CHECK("build_idat: multi-block fixture filtered_len == 270300",
                   bfiltered_len == 270300);

        uint8_t *bpixels = zcl_malloc((size_t)bw * bh * 3, "pngw_test_bpixels");
        uint8_t *bexpected = zcl_malloc(bfiltered_len, "pngw_test_bexpected");
        PNGW_CHECK("build_idat: multi-block fixture allocations ok",
                   bpixels != NULL && bexpected != NULL);
        if (bpixels && bexpected) {
            for (size_t i = 0; i < (size_t)bw * bh * 3; i++)
                bpixels[i] = (uint8_t)(i * 131 + 17);
            pngw_build_expected_filtered(bpixels, bw, bh, bexpected);

            size_t bidat_len = 0;
            uint8_t *bidat = build_idat(bpixels, bw, bh, &bidat_len);
            PNGW_CHECK("build_idat: multi-block returns non-NULL", bidat != NULL);
            if (bidat) {
                size_t expect_idat_len = 2 + 5 * 5 + bfiltered_len + 4;
                PNGW_CHECK("build_idat: multi-block idat_len == 2+5*5+270300+4",
                           bidat_len == expect_idat_len);

                bool blocks_ok = true;
                size_t pos = 2, consumed = 0;
                for (int blk = 0; blk < 5 && blocks_ok; blk++) {
                    if (pos + 5 > bidat_len) { blocks_ok = false; break; }
                    uint8_t bt = bidat[pos++];
                    bool is_final = (bt & 0x01) != 0;
                    bool expect_final = (blk == 4);
                    uint16_t len = pngw_rd_le16(&bidat[pos]);
                    uint16_t nlen = pngw_rd_le16(&bidat[pos + 2]);
                    pos += 4;
                    uint16_t expect_len = expect_final ? 8160 : 65535;
                    if (is_final != expect_final) blocks_ok = false;
                    if (len != expect_len) blocks_ok = false;
                    if (nlen != (uint16_t)(~len & 0xFFFFu)) blocks_ok = false;
                    if (pos + len > bidat_len) { blocks_ok = false; break; }
                    if (memcmp(&bidat[pos], bexpected + consumed, len) != 0)
                        blocks_ok = false;
                    pos += len;
                    consumed += len;
                }
                PNGW_CHECK("build_idat: multi-block framing (BFINAL only on block 5, "
                           "65535-byte cap, NLEN, payload) all correct",
                           blocks_ok);
                PNGW_CHECK("build_idat: multi-block consumed all filtered bytes",
                           consumed == bfiltered_len);
                PNGW_CHECK("build_idat: multi-block trailer position == idat_len-4",
                           pos == bidat_len - 4);
                PNGW_CHECK("build_idat: multi-block trailing Adler32 matches adler32(expected)",
                           pos + 4 == bidat_len &&
                               pngw_rd_be32(&bidat[pos]) == adler32(bexpected, bfiltered_len));

                uint8_t *bdecoded = zcl_malloc(bfiltered_len, "pngw_test_bdecoded");
                PNGW_CHECK("build_idat: multi-block decode-buffer alloc ok",
                           bdecoded != NULL);
                if (bdecoded) {
                    size_t bdec_len = pngw_inflate_stored(bidat, bidat_len, bdecoded,
                                                           bfiltered_len);
                    PNGW_CHECK("build_idat: from-scratch decoder round-trips multi-block content",
                               bdec_len == bfiltered_len &&
                                   memcmp(bdecoded, bexpected, bfiltered_len) == 0);
                    free(bdecoded);
                }
                free(bidat);
            }
        }
        if (bpixels) free(bpixels);
        if (bexpected) free(bexpected);

        /* (C) Degenerate 0x0 image: filtered_len == 0 forces the
         * "num_blocks == 0 -> forced to 1" fallback in build_idat. */
        size_t zlen = 0;
        uint8_t *zidat = build_idat(NULL, 0, 0, &zlen);
        PNGW_CHECK("build_idat: 0x0 image still returns non-NULL", zidat != NULL);
        if (zidat) {
            PNGW_CHECK("build_idat: 0x0 image idat_len == 2+5+0+4 == 11", zlen == 11);
            PNGW_CHECK("build_idat: 0x0 image zlib header == {0x78,0x01}",
                       zidat[0] == 0x78 && zidat[1] == 0x01);
            PNGW_CHECK("build_idat: 0x0 image single forced-final empty block",
                       zlen >= 7 && zidat[2] == 0x01 &&
                           pngw_rd_le16(&zidat[3]) == 0 &&
                           pngw_rd_le16(&zidat[5]) == 0xFFFF);
            PNGW_CHECK("build_idat: 0x0 image trailer == adler32 of empty input (1)",
                       zlen == 11 && pngw_rd_be32(&zidat[7]) == 1);
            free(zidat);
        }

        /* (D) OOM path 1: the filtered-scanline allocation fails. */
        zcl_alloc_fault_fail_next("png_filtered");
        size_t oom1_len = 0xdeadbeef; /* poisoned: must stay untouched on NULL */
        uint8_t *oom1 = build_idat(pixels, w, h, &oom1_len);
        PNGW_CHECK("build_idat: png_filtered alloc failure returns NULL",
                   oom1 == NULL);
        PNGW_CHECK("build_idat: png_filtered alloc failure leaves *out_len untouched",
                   oom1_len == 0xdeadbeef);
        zcl_alloc_fault_clear();
        if (oom1) free(oom1);

        /* (E) OOM path 2: the filtered allocation succeeds but the IDAT
         * buffer allocation fails (must not leak `filtered` — covered
         * functionally by returning NULL cleanly under the injected
         * fault rather than crashing/asserting). */
        zcl_alloc_fault_fail_next("png_idat");
        size_t oom2_len = 0xdeadbeef; /* poisoned: must stay untouched on NULL */
        uint8_t *oom2 = build_idat(pixels, w, h, &oom2_len);
        PNGW_CHECK("build_idat: png_idat alloc failure returns NULL", oom2 == NULL);
        PNGW_CHECK("build_idat: png_idat alloc failure leaves *out_len untouched",
                   oom2_len == 0xdeadbeef);
        zcl_alloc_fault_clear();
        if (oom2) free(oom2);
    }

    /* ───────────────────────────────── png_write_rgb ───────────────────────────────── */
    {
        /* Edge / defensive-argument cases. */
        PNGW_CHECK("png_write_rgb: NULL path returns false",
                   !pngw_under_test_write_rgb(NULL, (const uint8_t *)"", 1, 1));
        static const uint8_t one_px[3] = {1, 2, 3};
        PNGW_CHECK("png_write_rgb: NULL pixels returns false",
                   !pngw_under_test_write_rgb("/tmp/zcl_png_writer_unused.png", NULL, 1, 1));
        PNGW_CHECK("png_write_rgb: width==0 returns false",
                   !pngw_under_test_write_rgb("/tmp/zcl_png_writer_unused.png", one_px, 0, 1));
        PNGW_CHECK("png_write_rgb: height==0 returns false",
                   !pngw_under_test_write_rgb("/tmp/zcl_png_writer_unused.png", one_px, 1, 0));
        PNGW_CHECK("png_write_rgb: unopenable path (missing directory) returns false",
                   !pngw_under_test_write_rgb("/nonexistent_dir_zzz_png_writer_test/out.png",
                                  one_px, 1, 1));

        /* Full round trip: small (single-block IDAT) image. */
        {
            const uint32_t w = 4, h = 3;
            size_t row_bytes = (size_t)w * 3;
            size_t filtered_len = (size_t)h * (1 + row_bytes);
            uint8_t pixels[36];
            for (size_t i = 0; i < sizeof(pixels); i++)
                pixels[i] = (uint8_t)(i * 5 + 11);
            uint8_t expected[39];
            pngw_build_expected_filtered(pixels, w, h, expected);

            char path[128];
            strcpy(path, "/tmp/zcl_png_writer_rt_XXXXXX");
            int fd = mkstemp(path);
            PNGW_CHECK("png_write_rgb small round-trip: fixture mkstemp ok", fd >= 0);
            if (fd >= 0) {
                close(fd);
                PNGW_CHECK("png_write_rgb small round-trip: write succeeds",
                           pngw_under_test_write_rgb(path, pixels, w, h));

                FILE *f = fopen(path, "rb");
                PNGW_CHECK("png_write_rgb small round-trip: file reopens for readback",
                           f != NULL);
                if (f) {
                    static const uint8_t want_sig[8] = {137, 80, 78, 71,
                                                         13, 10, 26, 10};
                    uint8_t sig[8];
                    bool sig_ok = fread(sig, 1, 8, f) == 8 &&
                                  memcmp(sig, want_sig, 8) == 0;
                    PNGW_CHECK("png_write_rgb small round-trip: PNG signature matches",
                               sig_ok);

                    char ihdr_type[5];
                    uint8_t *ihdr_data = NULL;
                    uint32_t ihdr_len = 0;
                    bool ihdr_ok = pngw_read_chunk(f, ihdr_type, &ihdr_data, &ihdr_len);
                    PNGW_CHECK("png_write_rgb small round-trip: IHDR parses + CRC verifies",
                               ihdr_ok);
                    PNGW_CHECK("png_write_rgb small round-trip: IHDR type/len correct",
                               ihdr_ok && memcmp(ihdr_type, "IHDR", 4) == 0 &&
                                   ihdr_len == 13);
                    PNGW_CHECK("png_write_rgb small round-trip: IHDR width/height/depth/"
                               "colortype/compression/filter/interlace all correct",
                               ihdr_ok && ihdr_len == 13 &&
                                   pngw_rd_be32(&ihdr_data[0]) == w &&
                                   pngw_rd_be32(&ihdr_data[4]) == h &&
                                   ihdr_data[8] == 8 && ihdr_data[9] == 2 &&
                                   ihdr_data[10] == 0 && ihdr_data[11] == 0 &&
                                   ihdr_data[12] == 0);
                    if (ihdr_data) free(ihdr_data);

                    char idat_type[5];
                    uint8_t *idat_data = NULL;
                    uint32_t idat_len = 0;
                    bool idat_ok = pngw_read_chunk(f, idat_type, &idat_data, &idat_len);
                    PNGW_CHECK("png_write_rgb small round-trip: IDAT parses + CRC verifies",
                               idat_ok && memcmp(idat_type, "IDAT", 4) == 0);
                    if (idat_ok && idat_data) {
                        uint8_t decoded[64];
                        size_t dec_len = pngw_inflate_stored(idat_data, idat_len,
                                                              decoded, sizeof(decoded));
                        PNGW_CHECK("png_write_rgb small round-trip: IDAT decodes back to "
                                   "the exact original pixel bytes",
                                   dec_len == filtered_len &&
                                       memcmp(decoded, expected, filtered_len) == 0);
                    }
                    if (idat_data) free(idat_data);

                    char iend_type[5];
                    uint8_t *iend_data = NULL;
                    uint32_t iend_len = 0;
                    bool iend_ok = pngw_read_chunk(f, iend_type, &iend_data, &iend_len);
                    PNGW_CHECK("png_write_rgb small round-trip: IEND parses (len 0) + CRC verifies",
                               iend_ok && iend_len == 0 &&
                                   memcmp(iend_type, "IEND", 4) == 0);
                    if (iend_data) free(iend_data);

                    uint8_t trailing;
                    PNGW_CHECK("png_write_rgb small round-trip: nothing follows IEND",
                               fread(&trailing, 1, 1, f) == 0 && feof(f));

                    fclose(f);
                }
                unlink(path);
            }
        }
    }

    printf("\n=== test_png_writer: %d failure(s) ===\n", failures);
    return failures;
}
