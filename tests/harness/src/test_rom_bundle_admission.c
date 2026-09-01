/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Receipt-gated ROM catalog admission (config/rom_bundle_admission.h):
 *
 *   1. a synthetic bundle + a matching synthetic replay receipt admits into
 *      the shared rom_seed catalog exactly like a direct rom_seed_register;
 *   2. no receipt at all refuses admission, catalog untouched;
 *   3. a receipt bound to a DIFFERENT bundle's digest refuses admission;
 *   4. rom_bundle_admission_scan() admits only the receipt-bound bundle out
 *      of a directory holding both a valid and an unreceipted candidate.
 *
 * All fixtures live under a mkdtemp() dir in /tmp — never a real datadir,
 * never the network, never a live progress-store fold. */

#include "test/test_core.h"
#include "config/rom_bundle_admission.h"
#include "config/consensus_state_replay_receipt.h"
#include "net/rom_seed.h"
#include "crypto/sha3.h"

#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Deterministic content: SQLite magic in the first 16 bytes (or 0xEE garbage
 * when !magic_ok), then a fixed byte pattern — mirrors test_rom_seed.c's
 * gen_content so a synthetic "bundle" passes rom_seed's own structural gate
 * once the receipt gate has already admitted it. */
static void gen_content(uint8_t *buf, size_t size, bool magic_ok)
{
    static const uint8_t magic[16] = "SQLite format 3";
    for (size_t i = 0; i < size; i++)
        buf[i] = (uint8_t)((i * 197u + 11u) & 0xffu);
    if (size >= 16) {
        if (magic_ok) memcpy(buf, magic, 16);
        else memset(buf, 0xEE, 16);
    }
}

static bool write_file(const char *dir, const char *name,
                       const uint8_t *buf, size_t size)
{
    char path[1024];
    snprintf(path, sizeof(path), "%s/%s", dir, name);
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) return false;
    size_t off = 0;
    while (off < size) {
        ssize_t w = write(fd, buf + off, size - off);
        if (w <= 0) { close(fd); return false; }
        off += (size_t)w;
    }
    close(fd);
    return true;
}

/* ── (a) Valid bundle + matching receipt admits ─────────────────────── */

static int test_admit_with_valid_receipt(void)
{
    int failures = 0;
    TEST("rom_bundle_admission: matching receipt admits into rom_seed catalog") {
        rom_seed_reset();
        char root[] = "/tmp/zcl_rba_ok_XXXXXX";
        char *dir = mkdtemp(root);
        ASSERT(dir != NULL);

        size_t size = 64 * 1024;
        uint8_t *content = malloc(size);
        ASSERT(content != NULL);
        gen_content(content, size, true);
        const char *fname = "consensus-state-bundle-500.sqlite";
        ASSERT(write_file(dir, fname, content, size));

        uint8_t digest[32];
        sha3_256(content, size, digest);

        char receipt_path[256];
        ASSERT(consensus_state_replay_receipt_write_for_test(
            dir, digest, 500, 7, 2, 3, receipt_path, sizeof(receipt_path)));

        struct rom_artifact art;
        memset(&art, 0, sizeof(art));
        enum rom_bundle_admission_result rc =
            rom_bundle_admission_register(dir, fname, &art);
        ASSERT(rc == ROM_BUNDLE_ADMIT_OK);
        ASSERT(art.kind == ROM_ARTIFACT_CONSENSUS_BUNDLE);
        ASSERT(memcmp(art.whole_sha3, digest, 32) == 0);
        ASSERT(rom_seed_count() == 1);

        struct rom_artifact found;
        ASSERT(rom_seed_find_by_root(art.chunk_root, &found));
        ASSERT(memcmp(found.whole_sha3, digest, 32) == 0);

        free(content);
        char p[1100];
        snprintf(p, sizeof(p), "%s/%s", dir, fname); unlink(p);
        unlink(receipt_path);
        rmdir(dir);
        rom_seed_reset();
        PASS();
    } _test_next:;
    return failures;
}

/* ── (b) Absent receipt refuses, catalog untouched ──────────────────── */

static int test_refuse_without_receipt(void)
{
    int failures = 0;
    TEST("rom_bundle_admission: no receipt refuses (fail-closed)") {
        rom_seed_reset();
        char root[] = "/tmp/zcl_rba_norcpt_XXXXXX";
        char *dir = mkdtemp(root);
        ASSERT(dir != NULL);

        size_t size = 64 * 1024;
        uint8_t *content = malloc(size);
        ASSERT(content != NULL);
        gen_content(content, size, true);
        const char *fname = "consensus-state-bundle-501.sqlite";
        ASSERT(write_file(dir, fname, content, size));

        /* No consensus_state_replay_receipt.v1 written in `dir` at all. */
        struct rom_artifact art;
        memset(&art, 0, sizeof(art));
        enum rom_bundle_admission_result rc =
            rom_bundle_admission_register(dir, fname, &art);
        ASSERT(rc == ROM_BUNDLE_ADMIT_ERR_NO_RECEIPT);
        ASSERT(rom_seed_count() == 0);
        ASSERT(!rom_seed_offer_is_free(art.chunk_root));

        free(content);
        char p[1100];
        snprintf(p, sizeof(p), "%s/%s", dir, fname); unlink(p);
        rmdir(dir);
        rom_seed_reset();
        PASS();
    } _test_next:;
    return failures;
}

/* ── (c) Receipt bound to a DIFFERENT bundle digest refuses ─────────── */

static int test_refuse_mismatched_receipt(void)
{
    int failures = 0;
    TEST("rom_bundle_admission: receipt bound to a different bundle refuses") {
        rom_seed_reset();
        char root[] = "/tmp/zcl_rba_mismatch_XXXXXX";
        char *dir = mkdtemp(root);
        ASSERT(dir != NULL);

        size_t size = 64 * 1024;
        uint8_t *content = malloc(size);
        ASSERT(content != NULL);
        gen_content(content, size, true);
        const char *fname = "consensus-state-bundle-502.sqlite";
        ASSERT(write_file(dir, fname, content, size));

        /* Receipt binds a digest that is NOT this bundle's whole-file SHA3 —
         * e.g. a receipt copied alongside a byte-different bundle. */
        uint8_t wrong_digest[32];
        memset(wrong_digest, 0x42, sizeof(wrong_digest));
        char receipt_path[256];
        ASSERT(consensus_state_replay_receipt_write_for_test(
            dir, wrong_digest, 502, 1, 1, 1, receipt_path,
            sizeof(receipt_path)));

        struct rom_artifact art;
        memset(&art, 0, sizeof(art));
        enum rom_bundle_admission_result rc =
            rom_bundle_admission_register(dir, fname, &art);
        ASSERT(rc == ROM_BUNDLE_ADMIT_ERR_NO_RECEIPT);
        ASSERT(rom_seed_count() == 0);

        free(content);
        char p[1100];
        snprintf(p, sizeof(p), "%s/%s", dir, fname); unlink(p);
        unlink(receipt_path);
        rmdir(dir);
        rom_seed_reset();
        PASS();
    } _test_next:;
    return failures;
}

/* ── (d) Directory scan admits only the receipt-bound bundle ────────── */

static int test_scan_admits_only_receipt_bound(void)
{
    int failures = 0;
    TEST("rom_bundle_admission: scan admits only the bundle its receipt binds") {
        rom_seed_reset();
        char root[] = "/tmp/zcl_rba_scan_XXXXXX";
        char *dir = mkdtemp(root);
        ASSERT(dir != NULL);

        size_t size = 64 * 1024;
        uint8_t *good = malloc(size);
        uint8_t *other = malloc(size);
        ASSERT(good != NULL && other != NULL);
        gen_content(good, size, true);
        /* Distinct content from `good` so its digest genuinely differs (still
         * SQLite-magic-valid — the receipt gate, not the structural gate, is
         * what must refuse it: the datadir's one receipt can bind only one
         * bundle's digest). */
        gen_content(other, size, true);
        other[20] ^= 0xFF;

        const char *good_name = "consensus-state-bundle-503.sqlite";
        const char *other_name = "consensus-state-bundle-504.sqlite";
        ASSERT(write_file(dir, good_name, good, size));
        ASSERT(write_file(dir, other_name, other, size));

        uint8_t good_digest[32];
        sha3_256(good, size, good_digest);
        char receipt_path[256];
        ASSERT(consensus_state_replay_receipt_write_for_test(
            dir, good_digest, 503, 4, 2, 1, receipt_path,
            sizeof(receipt_path)));

        int admitted = rom_bundle_admission_scan(dir);
        ASSERT(admitted == 1);
        ASSERT(rom_seed_count() == 1);

        uint8_t found_whole[32];
        sha3_256(good, size, found_whole);
        struct rom_artifact arts[ROM_SEED_MAX_ARTIFACTS];
        int n = rom_seed_list(arts, ROM_SEED_MAX_ARTIFACTS);
        ASSERT(n == 1);
        ASSERT(memcmp(arts[0].whole_sha3, found_whole, 32) == 0);
        ASSERT(strcmp(arts[0].filename, good_name) == 0);

        free(good);
        free(other);
        char p[1100];
        snprintf(p, sizeof(p), "%s/%s", dir, good_name); unlink(p);
        snprintf(p, sizeof(p), "%s/%s", dir, other_name); unlink(p);
        unlink(receipt_path);
        rmdir(dir);
        rom_seed_reset();
        PASS();
    } _test_next:;
    return failures;
}

int test_rom_bundle_admission(void)
{
    int failures = 0;
    failures += test_admit_with_valid_receipt();
    failures += test_refuse_without_receipt();
    failures += test_refuse_mismatched_receipt();
    failures += test_scan_admits_only_receipt_bound();
    return failures;
}
