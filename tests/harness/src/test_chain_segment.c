/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Unit tests for chain_segment — the sealed ROM segment store. Load-bearing
 * properties: a sealed range reads back byte-identical; any tampered byte is
 * caught (whole-segment digest on open, per-block digest on read); the manifest
 * root is stable for identical content; a missing body fails the whole seal
 * closed; an empty range is refused. The store is body-source-agnostic, so
 * these tests drive it with a deterministic synthetic body source rather than
 * real blocks (real-block wiring lives in chain_segment_controller.c).
 */

#include "test/test_core.h"

#include "storage/chain_segment.h"
#include "crypto/sha3.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define CS_CHECK(name, expr) do {                                       \
    if (expr) { printf("  chain_segment: %s... OK\n", (name)); }        \
    else { printf("  chain_segment: %s... FAIL\n", (name)); failures++; } \
} while (0)

/* Deterministic body: bytes and length are a pure function of height, so the
 * expected content is reproducible for the round-trip comparison. */
static size_t fix_len(uint32_t h) { return 16 + (h % 40); }
static void fix_fill(uint32_t h, uint8_t *b, size_t n)
{
    for (size_t i = 0; i < n; i++) b[i] = (uint8_t)(h * 31u + i * 7u + 3u);
}

struct fix_src { uint32_t missing_height; };

static bool fix_body(void *user, uint32_t h, uint8_t **bytes, size_t *len)
{
    struct fix_src *f = user;
    if (h == f->missing_height) return false;
    size_t n = fix_len(h);
    uint8_t *b = malloc(n);
    if (!b) return false;
    fix_fill(h, b, n);
    *bytes = b; *len = n;
    return true;
}

static bool file_exists(const char *dir, const char *name)
{
    char p[512];
    snprintf(p, sizeof(p), "%s/%s", dir, name);
    struct stat sb;
    return stat(p, &sb) == 0;
}

int test_chain_segment(void);
int test_chain_segment(void)
{
    printf("\n=== chain_segment tests ===\n");
    int failures = 0;
    char err[256];

    /* ── Round-trip: seal [1000,1032) then read every block back ──────── */
    {
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "chain_segment", "roundtrip");
        struct fix_src src = { .missing_height = UINT32_MAX };

        enum cseg_status st = chain_segment_seal_range(dir, fix_body, &src,
                                                       1000, 32, err, sizeof(err));
        CS_CHECK("seal_range ok", st == CSEG_OK);
        CS_CHECK("segment file present",
                 file_exists(dir, "seg-1000-32.dat"));
        CS_CHECK("manifest present", file_exists(dir, "manifest.dat"));

        char path[512];
        snprintf(path, sizeof(path), "%s/seg-1000-32.dat", dir);
        struct chain_segment *seg = NULL;
        st = chain_segment_open(path, &seg, err, sizeof(err));
        CS_CHECK("open verifies digest", st == CSEG_OK && seg != NULL);
        CS_CHECK("first_height", chain_segment_first_height(seg) == 1000);
        CS_CHECK("count", chain_segment_count(seg) == 32);

        bool all_ok = seg != NULL;
        for (uint32_t h = 1000; seg && h < 1032; h++) {
            uint8_t *got = NULL; size_t glen = 0;
            enum cseg_status gs = chain_segment_get_block(seg, h, &got, &glen,
                                                          err, sizeof(err));
            size_t elen = fix_len(h);
            uint8_t exp[64]; fix_fill(h, exp, elen);
            if (gs != CSEG_OK || glen != elen || memcmp(got, exp, elen) != 0)
                all_ok = false;
            free(got);
        }
        CS_CHECK("every block byte-identical", all_ok);

        /* out-of-range height */
        uint8_t *nb = NULL; size_t nl = 0;
        enum cseg_status oob = seg ? chain_segment_get_block(seg, 2000, &nb, &nl,
                                                             err, sizeof(err))
                                   : CSEG_ERR_NOT_FOUND;
        CS_CHECK("out-of-range height -> not_found", oob == CSEG_ERR_NOT_FOUND);
        free(nb);

        chain_segment_close(seg);
        test_rm_rf_recursive(dir);
    }

    /* ── Manifest root stability: identical content -> identical root ── */
    uint8_t root_a[32] = {0};
    {
        char da[256], db[256];
        test_make_tmpdir(da, sizeof(da), "chain_segment", "stable_a");
        test_make_tmpdir(db, sizeof(db), "chain_segment", "stable_b");
        struct fix_src src = { .missing_height = UINT32_MAX };

        chain_segment_seal_range(da, fix_body, &src, 5, 10, err, sizeof(err));
        chain_segment_seal_range(db, fix_body, &src, 5, 10, err, sizeof(err));

        struct chain_segment_stat sa, sb;
        enum cseg_status ra = chain_segment_store_stat(da, true, &sa, err, sizeof(err));
        enum cseg_status rb = chain_segment_store_stat(db, true, &sb, err, sizeof(err));
        CS_CHECK("store_stat a ok", ra == CSEG_OK);
        CS_CHECK("store_stat b ok", rb == CSEG_OK);
        CS_CHECK("segment_count 1", sa.segment_count == 1 && sb.segment_count == 1);
        CS_CHECK("covered range", sa.have_range && sa.min_height == 5 &&
                                  sa.max_height == 14);
        CS_CHECK("full verify all", sa.verified_count == 1 && sb.verified_count == 1);
        CS_CHECK("manifest root stable",
                 memcmp(sa.manifest_root, sb.manifest_root, 32) == 0);
        memcpy(root_a, sa.manifest_root, 32);

        test_rm_rf_recursive(da);
        test_rm_rf_recursive(db);
    }

    /* ── Tamper A: flip one byte in the segment -> open fails ────────── */
    {
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "chain_segment", "tamperA");
        struct fix_src src = { .missing_height = UINT32_MAX };
        chain_segment_seal_range(dir, fix_body, &src, 0, 8, err, sizeof(err));

        char path[512];
        snprintf(path, sizeof(path), "%s/seg-0-8.dat", dir);
        chmod(path, 0644);
        /* Flip a byte in the block-data region (after the 32-byte header +
         * 8*48-byte index) so the geometry stays valid and the whole-segment
         * digest is what catches it. */
        long tamper_off = 32 + 8 * 48 + 4;
        FILE *f = fopen(path, "r+b");
        bool wrote = false;
        if (f) {
            fseek(f, tamper_off, SEEK_SET);
            int c = fgetc(f);
            fseek(f, tamper_off, SEEK_SET);
            fputc(c ^ 0xff, f);
            fclose(f);
            wrote = true;
        }
        CS_CHECK("tamper write", wrote);

        struct chain_segment *seg = NULL;
        enum cseg_status st = chain_segment_open(path, &seg, err, sizeof(err));
        CS_CHECK("tampered open -> segment_digest",
                 st == CSEG_ERR_SEGMENT_DIGEST && seg == NULL);
        CS_CHECK("error names the segment", strstr(err, "seg-0-8.dat") != NULL);
        chain_segment_close(seg);
        test_rm_rf_recursive(dir);
    }

    /* ── Tamper B: corrupt a block body but re-fix the segment trailer so
     * open passes; the per-block digest must still catch it on read. ── */
    {
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "chain_segment", "tamperB");
        struct fix_src src = { .missing_height = UINT32_MAX };
        chain_segment_seal_range(dir, fix_body, &src, 100, 4, err, sizeof(err));

        char path[512];
        snprintf(path, sizeof(path), "%s/seg-100-4.dat", dir);
        chmod(path, 0644);

        /* Read whole file, flip a data byte, recompute trailer digest. */
        FILE *f = fopen(path, "rb");
        long sz = 0;
        uint8_t *buf = NULL;
        if (f) {
            fseek(f, 0, SEEK_END); sz = ftell(f); fseek(f, 0, SEEK_SET);
            buf = malloc((size_t)sz);
            if (buf && fread(buf, 1, (size_t)sz, f) != (size_t)sz) { free(buf); buf = NULL; }
            fclose(f);
        }
        bool patched = false;
        if (buf && sz > 0) {
            uint32_t count = 100; /* header offset 16 holds block_count */
            (void)count;
            size_t data_off = 32 + 4u * 48u; /* header + index for count=4 */
            buf[data_off] ^= 0xff;            /* corrupt the first block's bytes */
            size_t trailer_off = (size_t)sz - 32;
            sha3_256(buf, trailer_off, buf + trailer_off);
            FILE *w = fopen(path, "wb");
            if (w) {
                patched = fwrite(buf, 1, (size_t)sz, w) == (size_t)sz;
                fclose(w);
            }
        }
        free(buf);
        CS_CHECK("tamperB patch", patched);

        struct chain_segment *seg = NULL;
        enum cseg_status st = chain_segment_open(path, &seg, err, sizeof(err));
        CS_CHECK("open still passes (trailer re-fixed)", st == CSEG_OK && seg);

        uint8_t *got = NULL; size_t glen = 0;
        enum cseg_status gs = seg ? chain_segment_get_block(seg, 100, &got, &glen,
                                                           err, sizeof(err))
                                  : CSEG_ERR_BLOCK_DIGEST;
        CS_CHECK("corrupt block -> block_digest", gs == CSEG_ERR_BLOCK_DIGEST);
        CS_CHECK("block error names height 100", strstr(err, "100") != NULL);
        free(got);

        /* An untampered sibling block still reads fine. */
        uint8_t *ok2 = NULL; size_t l2 = 0;
        enum cseg_status gs2 = seg ? chain_segment_get_block(seg, 101, &ok2, &l2,
                                                            err, sizeof(err))
                                   : CSEG_ERR_BLOCK_DIGEST;
        CS_CHECK("sibling block still ok", gs2 == CSEG_OK);
        free(ok2);

        chain_segment_close(seg);
        test_rm_rf_recursive(dir);
    }

    /* ── Missing body -> whole seal fails closed, no file left ────────── */
    {
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "chain_segment", "missing");
        struct fix_src src = { .missing_height = 205 };
        enum cseg_status st = chain_segment_seal_range(dir, fix_body, &src,
                                                       200, 10, err, sizeof(err));
        CS_CHECK("missing body -> body_missing", st == CSEG_ERR_BODY_MISSING);
        CS_CHECK("error names the height", strstr(err, "205") != NULL);
        CS_CHECK("no segment file written",
                 !file_exists(dir, "seg-200-10.dat"));
        test_rm_rf_recursive(dir);
    }

    /* ── Empty range refused ──────────────────────────────────────────── */
    {
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "chain_segment", "empty");
        struct fix_src src = { .missing_height = UINT32_MAX };
        enum cseg_status st = chain_segment_seal_range(dir, fix_body, &src,
                                                       0, 0, err, sizeof(err));
        CS_CHECK("empty range -> empty_range", st == CSEG_ERR_EMPTY_RANGE);
        test_rm_rf_recursive(dir);
    }

    /* ── Two disjoint segments in one store; full verify catches a later
     * tamper vs the manifest. ── */
    {
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "chain_segment", "twoseg");
        struct fix_src src = { .missing_height = UINT32_MAX };
        chain_segment_seal_range(dir, fix_body, &src, 0, 5, err, sizeof(err));
        chain_segment_seal_range(dir, fix_body, &src, 500, 7, err, sizeof(err));

        struct chain_segment_stat stt;
        enum cseg_status st = chain_segment_store_stat(dir, true, &stt, err, sizeof(err));
        CS_CHECK("two-segment verify ok", st == CSEG_OK);
        CS_CHECK("segment_count 2", stt.segment_count == 2);
        CS_CHECK("covered 0..506", stt.min_height == 0 && stt.max_height == 506);

        /* Corrupt one segment file (leave manifest intact) -> open fails, so
         * full store verify surfaces a typed error naming that segment. */
        char path[512];
        snprintf(path, sizeof(path), "%s/seg-500-7.dat", dir);
        chmod(path, 0644);
        FILE *f = fopen(path, "r+b");
        if (f) { fseek(f, 33, SEEK_SET); fputc(0x00, f); fclose(f); }

        st = chain_segment_store_stat(dir, true, &stt, err, sizeof(err));
        CS_CHECK("store verify catches tamper",
                 st == CSEG_ERR_SEGMENT_DIGEST || st == CSEG_ERR_MANIFEST);
        CS_CHECK("verify error names segment", strstr(err, "seg-500-7") != NULL);

        test_rm_rf_recursive(dir);
    }

    /* ── Empty store: no manifest is not an error ─────────────────────── */
    {
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "chain_segment", "emptystore");
        struct chain_segment_stat stt;
        enum cseg_status st = chain_segment_store_stat(dir, false, &stt, err, sizeof(err));
        CS_CHECK("empty store ok", st == CSEG_OK && stt.segment_count == 0 &&
                                   !stt.have_range);
        test_rm_rf_recursive(dir);
    }

    /* ── Resident store reader (the fold substrate) ─────────────────────
     * covers()/sealed_max/get_block byte-identity, plus verify_index catching
     * a per-segment tamper. This is the API block_parse_cache reads through. */
    {
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "chain_segment", "store");
        struct fix_src src = { .missing_height = UINT32_MAX };
        chain_segment_seal_range(dir, fix_body, &src, 1000, 10, err, sizeof(err));
        chain_segment_seal_range(dir, fix_body, &src, 2000, 10, err, sizeof(err));

        struct chain_segment_store *store = NULL;
        enum cseg_status st = chain_segment_store_open(dir, &store, err, sizeof(err));
        CS_CHECK("store open ok", st == CSEG_OK && store != NULL);
        CS_CHECK("store have", chain_segment_store_have(store));
        CS_CHECK("segment_count 2", chain_segment_store_segment_count(store) == 2);
        CS_CHECK("sealed_max 2009", chain_segment_store_sealed_max(store) == 2009);
        CS_CHECK("covers sealed heights",
                 chain_segment_store_covers(store, 1000) &&
                 chain_segment_store_covers(store, 2009));
        CS_CHECK("does not cover gap/above",
                 !chain_segment_store_covers(store, 1500) &&
                 !chain_segment_store_covers(store, 3000));

        /* Byte-identity through the store for every covered height. */
        bool all_ok = store != NULL;
        for (uint32_t h = 1000; store && h < 1010; h++) {
            uint8_t *got = NULL; size_t glen = 0;
            enum cseg_status gs = chain_segment_store_get_block(store, h, &got,
                                                               &glen, err, sizeof(err));
            size_t elen = fix_len(h);
            uint8_t exp[64]; fix_fill(h, exp, elen);
            if (gs != CSEG_OK || glen != elen || memcmp(got, exp, elen) != 0)
                all_ok = false;
            free(got);
        }
        CS_CHECK("store get_block byte-identical", all_ok);

        /* Uncovered height -> not_found (the read-path falls back to blk*.dat). */
        uint8_t *nb = NULL; size_t nl = 0;
        enum cseg_status oob = store
            ? chain_segment_store_get_block(store, 1500, &nb, &nl, err, sizeof(err))
            : CSEG_ERR_NOT_FOUND;
        CS_CHECK("uncovered height -> not_found", oob == CSEG_ERR_NOT_FOUND);
        free(nb);

        /* verify_index passes clean on both, then a byte tamper on segment 1's
         * file makes its verify_index fail with a named typed error. */
        CS_CHECK("verify_index clean seg0",
                 store && chain_segment_store_verify_index(store, 0, err, sizeof(err)) == CSEG_OK);

        char tp[512];
        snprintf(tp, sizeof(tp), "%s/seg-2000-10.dat", dir);
        chmod(tp, 0644);
        FILE *tf = fopen(tp, "r+b");
        if (tf) { fseek(tf, 32 + 10 * 48 + 2, SEEK_SET); int c = fgetc(tf);
                  fseek(tf, 32 + 10 * 48 + 2, SEEK_SET); fputc(c ^ 0xff, tf);
                  fclose(tf); }
        enum cseg_status vst = store
            ? chain_segment_store_verify_index(store, 1, err, sizeof(err))
            : CSEG_OK;
        CS_CHECK("verify_index catches tamper",
                 vst == CSEG_ERR_SEGMENT_DIGEST || vst == CSEG_ERR_FORMAT ||
                 vst == CSEG_ERR_BLOCK_DIGEST);

        chain_segment_store_close(store);
        test_rm_rf_recursive(dir);
    }

    /* ── Store over an absent dir: empty, covers nothing (default node) ─── */
    {
        struct chain_segment_store *store = NULL;
        enum cseg_status st = chain_segment_store_open(
            "/tmp/zcl-nonexistent-seg-dir-xyz", &store, err, sizeof(err));
        CS_CHECK("absent-dir store ok + empty",
                 st == CSEG_OK && store != NULL &&
                 !chain_segment_store_have(store) &&
                 !chain_segment_store_covers(store, 0));
        chain_segment_store_close(store);
    }

    printf("chain_segment: %d failures\n", failures);
    return failures;
}
