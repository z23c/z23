/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ROM artifact seeding: registry + free-tier serve policy + caps.
 *
 * Proves the free, fast, capped delivery tier for the network's bootstrap ROM:
 *   1. registration re-derives whole-file + per-chunk + chunk-root digests from
 *      the bytes on disk, matching an independent computation, across chunks;
 *   2. a free ROM chunk is served WITHOUT payment while an unknown root falls to
 *      the payment path;
 *   3. per-peer concurrency + per-peer/global byte-rate caps trip cleanly;
 *   4. a corrupt/truncated/mis-named on-disk artifact is refused at registration
 *      and never offered.
 *
 * All fixtures live under a mkdtemp() dir in /tmp — never a real datadir, never
 * the network. None of this touches a consensus predicate. */

#include "test/test_core.h"
#include "net/rom_seed.h"
#include "net/file_market.h"
#include "crypto/sha3.h"

#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* Deterministic content: SQLite magic in the first 16 bytes (or 0xEE garbage
 * when !magic_ok), then a fixed byte pattern. */
static void gen_content(uint8_t *buf, size_t size, bool magic_ok)
{
    static const uint8_t magic[16] = "SQLite format 3"; /* 15 chars + NUL = 16 */
    for (size_t i = 0; i < size; i++)
        buf[i] = (uint8_t)((i * 131u + 7u) & 0xffu);
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

/* ── (a0) Deregister: the inverse of register (GAP-2) ───────────────── */

static int test_deregister(void)
{
    int failures = 0;
    TEST("rom_seed: deregister drops the artifact from count + serve_lookup") {
        rom_seed_reset();
        char root[] = "/tmp/zcl_romseed_dereg_XXXXXX";
        char *dir = mkdtemp(root);
        ASSERT(dir != NULL);

        size_t size = 64 * 1024;
        uint8_t *content = malloc(size);
        ASSERT(content != NULL);
        gen_content(content, size, true);
        ASSERT(write_file(dir, "consensus-state-bundle-500.sqlite", content,
                          size));

        struct rom_artifact art;
        ASSERT(rom_seed_register(dir, "consensus-state-bundle-500.sqlite", NULL,
                                 &art) == ROM_REG_OK);
        ASSERT(rom_seed_count() == 1);
        struct rom_artifact hit;
        ASSERT(rom_seed_serve_lookup(art.chunk_root, 0, &hit)
               == ROM_SERVE_FREE_OK);

        /* The served directory listing carries the parsed height (GAP-4). */
        char json[1024];
        size_t jn = rom_seed_directory_json(json, sizeof(json));
        ASSERT(jn > 0);
        ASSERT(strstr(json, "\"height\":500") != NULL);

        /* Bad args are refused (mirrors register). */
        ASSERT(rom_seed_deregister(NULL, "consensus-state-bundle-500.sqlite")
               == ROM_REG_ERR_ARGS);
        ASSERT(rom_seed_deregister(dir, NULL) == ROM_REG_ERR_ARGS);
        ASSERT(rom_seed_deregister(dir, "../evil") == ROM_REG_ERR_ARGS);
        ASSERT(rom_seed_count() == 1); /* still registered after bad calls */

        /* Cross-shape match: registered bare, deregistered via the
         * "bundles/<name>" reseed shape — matched on basename. */
        ASSERT(rom_seed_deregister(dir,
               "bundles/consensus-state-bundle-500.sqlite") == ROM_REG_OK);
        ASSERT(rom_seed_count() == 0);
        ASSERT(rom_seed_serve_lookup(art.chunk_root, 0, NULL)
               == ROM_SERVE_NOT_ARTIFACT);

        /* Idempotent: deregistering an absent entry is OK, not an error. */
        ASSERT(rom_seed_deregister(dir, "consensus-state-bundle-500.sqlite")
               == ROM_REG_OK);
        ASSERT(rom_seed_count() == 0);

        free(content);
        char p[1100];
        snprintf(p, sizeof(p), "%s/consensus-state-bundle-500.sqlite", dir);
        unlink(p);
        rmdir(dir);
        rom_seed_reset();
        PASS();
    } _test_next:;
    return failures;
}

/* ── (a) Registration digests, including multi-chunk ────────────────── */

static int test_register_digests(void)
{
    int failures = 0;
    TEST("rom_seed: registration re-derives correct multi-chunk digests") {
        rom_seed_reset();
        char root[] = "/tmp/zcl_romseed_dig_XXXXXX";
        char *dir = mkdtemp(root);
        ASSERT(dir != NULL);

        /* Two chunks: one full 4 MB chunk + a short 4 KB tail. */
        size_t size = (size_t)ROM_SEED_CHUNK_SIZE + 4096;
        uint8_t *content = malloc(size);
        ASSERT(content != NULL);
        gen_content(content, size, true);
        ASSERT(write_file(dir, "consensus-state-bundle-100.sqlite",
                          content, size));

        struct rom_artifact art;
        enum rom_register_result rr =
            rom_seed_register(dir, "consensus-state-bundle-100.sqlite",
                              NULL, &art);
        ASSERT(rr == ROM_REG_OK);
        ASSERT(art.kind == ROM_ARTIFACT_CONSENSUS_BUNDLE);
        ASSERT(art.size_bytes == size);
        ASSERT(art.chunk_size == ROM_SEED_CHUNK_SIZE);
        ASSERT(art.num_chunks == 2);

        /* Independent whole-file digest. */
        uint8_t expect_whole[32];
        sha3_256(content, size, expect_whole);
        ASSERT(memcmp(art.whole_sha3, expect_whole, 32) == 0);

        /* Independent per-chunk digests. */
        uint8_t c0[32], c1[32];
        sha3_256(content, ROM_SEED_CHUNK_SIZE, c0);
        sha3_256(content + ROM_SEED_CHUNK_SIZE, 4096, c1);
        ASSERT(memcmp(art.chunk_sha3[0], c0, 32) == 0);
        ASSERT(memcmp(art.chunk_sha3[1], c1, 32) == 0);

        /* Independent chunk-root = SHA3(c0 || c1). */
        struct sha3_256_ctx rctx;
        sha3_256_init(&rctx);
        sha3_256_write(&rctx, c0, 32);
        sha3_256_write(&rctx, c1, 32);
        uint8_t expect_root[32];
        sha3_256_finalize(&rctx, expect_root);
        ASSERT(memcmp(art.chunk_root, expect_root, 32) == 0);

        /* Registry sees exactly this one artifact, findable by its root. */
        ASSERT(rom_seed_count() == 1);
        struct rom_artifact found;
        ASSERT(rom_seed_find_by_root(art.chunk_root, &found));
        ASSERT(memcmp(found.whole_sha3, art.whole_sha3, 32) == 0);

        /* read_chunk returns bytes matching the disk + verifies the digest. */
        uint8_t *rbuf = malloc(ROM_SEED_CHUNK_SIZE);
        ASSERT(rbuf != NULL);
        uint32_t rsz = 0;
        ASSERT(rom_seed_read_chunk(&art, dir, 0, rbuf, ROM_SEED_CHUNK_SIZE, &rsz));
        ASSERT(rsz == ROM_SEED_CHUNK_SIZE);
        ASSERT(memcmp(rbuf, content, ROM_SEED_CHUNK_SIZE) == 0);
        ASSERT(rom_seed_read_chunk(&art, dir, 1, rbuf, ROM_SEED_CHUNK_SIZE, &rsz));
        ASSERT(rsz == 4096);
        ASSERT(memcmp(rbuf, content + ROM_SEED_CHUNK_SIZE, 4096) == 0);
        /* Out-of-range chunk index refuses. */
        ASSERT(!rom_seed_read_chunk(&art, dir, 2, rbuf, ROM_SEED_CHUNK_SIZE, &rsz));

        free(rbuf);
        free(content);

        /* Fixture cleanup. */
        char p[1100];
        snprintf(p, sizeof(p), "%s/consensus-state-bundle-100.sqlite", dir);
        unlink(p);
        rmdir(dir);
        PASS();
    } _test_next:;
    return failures;
}

/* ── (b) Free chunk served without payment; unknown root needs payment ─ */

static int test_free_vs_priced(void)
{
    int failures = 0;
    TEST("rom_seed: free artifact serves without payment, unknown root does not") {
        rom_seed_reset();
        char root[] = "/tmp/zcl_romseed_free_XXXXXX";
        char *dir = mkdtemp(root);
        ASSERT(dir != NULL);

        size_t size = 64 * 1024; /* single chunk */
        uint8_t *content = malloc(size);
        ASSERT(content != NULL);
        gen_content(content, size, true);
        ASSERT(write_file(dir, "consensus-state-bundle-200.sqlite",
                          content, size));

        struct rom_artifact art;
        ASSERT(rom_seed_register(dir, "consensus-state-bundle-200.sqlite",
                                 NULL, &art) == ROM_REG_OK);

        /* The registered ROM artifact is FREE: serve without any payment. */
        struct rom_artifact out;
        ASSERT(rom_seed_serve_lookup(art.chunk_root, 0, &out) == ROM_SERVE_FREE_OK);
        ASSERT(rom_seed_offer_is_free(art.chunk_root));

        /* An unknown root (a priced market file) is NOT free — the payment path
         * owns it. */
        uint8_t bogus[32];
        memset(bogus, 0xAB, 32);
        ASSERT(rom_seed_serve_lookup(bogus, 0, &out) == ROM_SERVE_NOT_ARTIFACT);
        ASSERT(!rom_seed_offer_is_free(bogus));

        /* Out-of-range chunk on a real artifact. */
        ASSERT(rom_seed_serve_lookup(art.chunk_root, art.num_chunks, &out)
               == ROM_SERVE_OUT_OF_RANGE);

        /* Disabling the tier withholds even a registered free artifact. */
        rom_seed_set_enabled(false);
        ASSERT(rom_seed_serve_lookup(art.chunk_root, 0, &out) == ROM_SERVE_DISABLED);
        rom_seed_set_enabled(true);
        ASSERT(rom_seed_serve_lookup(art.chunk_root, 0, &out) == ROM_SERVE_FREE_OK);

        /* The gossip offer built for this artifact carries price 0. */
        struct file_offer offer;
        uint8_t self_ip[16] = {0};
        self_ip[15] = 9;
        ASSERT(rom_seed_build_offer(&art, self_ip, 18034, &offer));
        ASSERT(offer.price_per_mb == 0);
        ASSERT(memcmp(offer.root_hash, art.chunk_root, 32) == 0);
        ASSERT(offer.num_chunks == art.num_chunks);
        ASSERT(offer.size_bytes == art.size_bytes);
        ASSERT(offer.peer_port == 18034);
        ASSERT(offer.ttl == FILE_MARKET_MAX_TTL);

        free(content);
        char p[1100];
        snprintf(p, sizeof(p), "%s/consensus-state-bundle-200.sqlite", dir);
        unlink(p);
        rmdir(dir);
        PASS();
    } _test_next:;
    return failures;
}

/* ── (c) Concurrency + rate caps ────────────────────────────────────── */

static int test_caps(void)
{
    int failures = 0;
    TEST("rom_seed: per-peer concurrency + per-peer/global rate caps trip") {
        rom_seed_reset();
        rom_seed_set_max_inflight_per_peer(2);

        uint8_t ip[16]; memset(ip, 0, 16); ip[15] = 1;

        /* Two concurrent serves fit; the third is refused (deferred). */
        ASSERT(rom_seed_peer_acquire(ip));
        ASSERT(rom_seed_peer_acquire(ip));
        ASSERT(!rom_seed_peer_acquire(ip));
        /* Releasing one frees a slot. */
        rom_seed_peer_release(ip);
        ASSERT(rom_seed_peer_acquire(ip));
        /* A different peer has its own independent concurrency budget. */
        uint8_t ip2[16]; memset(ip2, 0, 16); ip2[15] = 2;
        ASSERT(rom_seed_peer_acquire(ip2));

        /* Per-peer byte-rate cap: within a 1 s window, crossing the cap trips. */
        rom_seed_reset();
        rom_seed_set_peer_bps_cap(1000);
        rom_seed_set_global_bps_cap(1000000); /* not the limiting factor here */
        int64_t now = 5000;
        ASSERT(rom_seed_rate_charge(ip, 600, now));       /* 600 <= 1000 */
        ASSERT(!rom_seed_rate_charge(ip, 600, now));       /* 1200 > 1000 → trip */
        /* Next second resets the window. */
        ASSERT(rom_seed_rate_charge(ip, 600, now + 1));

        /* Global byte-rate cap: two distinct peers share one global window. */
        rom_seed_reset();
        rom_seed_set_peer_bps_cap(1000000); /* not the limiting factor here */
        rom_seed_set_global_bps_cap(1000);
        ASSERT(rom_seed_rate_charge(ip, 600, now));        /* global 600 */
        ASSERT(!rom_seed_rate_charge(ip2, 600, now));       /* global 1200 > 1000 */

        rom_seed_reset();
        PASS();
    } _test_next:;
    return failures;
}

/* ── (d) Corrupt / invalid on-disk artifact refused at registration ─── */

static int test_corrupt_refused(void)
{
    int failures = 0;
    TEST("rom_seed: corrupt / invalid artifact refused and never offered") {
        rom_seed_reset();
        char root[] = "/tmp/zcl_romseed_bad_XXXXXX";
        char *dir = mkdtemp(root);
        ASSERT(dir != NULL);

        size_t size = 64 * 1024;
        uint8_t *content = malloc(size);
        ASSERT(content != NULL);

        /* Garbage header (no SQLite magic) → corrupt, not registered. */
        gen_content(content, size, false);
        ASSERT(write_file(dir, "consensus-state-bundle-300.sqlite",
                          content, size));
        ASSERT(rom_seed_register(dir, "consensus-state-bundle-300.sqlite",
                                 NULL, NULL) == ROM_REG_ERR_CORRUPT);
        ASSERT(rom_seed_count() == 0); /* never entered the registry */

        /* Valid content but a mismatched expected digest → corrupt. */
        gen_content(content, size, true);
        ASSERT(write_file(dir, "consensus-state-bundle-301.sqlite",
                          content, size));
        uint8_t wrong[32]; memset(wrong, 0x11, 32);
        ASSERT(rom_seed_register(dir, "consensus-state-bundle-301.sqlite",
                                 wrong, NULL) == ROM_REG_ERR_CORRUPT);
        ASSERT(rom_seed_count() == 0);

        /* The SAME file with the correct expected digest registers cleanly. */
        uint8_t good[32];
        sha3_256(content, size, good);
        ASSERT(rom_seed_register(dir, "consensus-state-bundle-301.sqlite",
                                 good, NULL) == ROM_REG_OK);
        ASSERT(rom_seed_count() == 1);

        /* Path-traversal / non-basename filename refused up front. */
        ASSERT(rom_seed_register(dir, "../etc/passwd", NULL, NULL)
               == ROM_REG_ERR_ARGS);
        /* A name that matches no known kind is refused. */
        ASSERT(rom_seed_register(dir, "random-file.txt", NULL, NULL)
               == ROM_REG_ERR_UNKNOWN_KIND);
        /* A too-small file (below one SQLite page) is refused. */
        gen_content(content, 512, true);
        ASSERT(write_file(dir, "consensus-state-bundle-302.sqlite",
                          content, 512));
        ASSERT(rom_seed_register(dir, "consensus-state-bundle-302.sqlite",
                                 NULL, NULL) == ROM_REG_ERR_TOO_SMALL);

        /* classify() maps names to kinds. */
        ASSERT(rom_seed_classify("consensus-state-bundle-9.sqlite")
               == ROM_ARTIFACT_CONSENSUS_BUNDLE);
        ASSERT(rom_seed_classify("block_index.bin") == ROM_ARTIFACT_HEADER_SEED);
        ASSERT(rom_seed_classify("hello.txt") == ROM_ARTIFACT_UNKNOWN);

        free(content);
        char p[1100];
        snprintf(p, sizeof(p), "%s/consensus-state-bundle-300.sqlite", dir); unlink(p);
        snprintf(p, sizeof(p), "%s/consensus-state-bundle-301.sqlite", dir); unlink(p);
        snprintf(p, sizeof(p), "%s/consensus-state-bundle-302.sqlite", dir); unlink(p);
        rmdir(dir);
        rom_seed_reset();
        PASS();
    } _test_next:;
    return failures;
}

/* ── Datadir scan + directory.json ──────────────────────────────────── */

static int test_scan_and_directory(void)
{
    int failures = 0;
    TEST("rom_seed: bounded datadir scan registers bundles + directory json") {
        rom_seed_reset();
        char root[] = "/tmp/zcl_romseed_scan_XXXXXX";
        char *dir = mkdtemp(root);
        ASSERT(dir != NULL);

        size_t size = 64 * 1024;
        uint8_t *content = malloc(size);
        ASSERT(content != NULL);
        gen_content(content, size, true);
        ASSERT(write_file(dir, "consensus-state-bundle-400.sqlite", content, size));
        /* A garbage bundle-named file must be skipped by the scan. */
        uint8_t *bad = malloc(size);
        ASSERT(bad != NULL);
        gen_content(bad, size, false);
        ASSERT(write_file(dir, "consensus-state-bundle-401.sqlite", bad, size));
        /* A non-artifact file must be ignored. */
        ASSERT(write_file(dir, "unrelated.dat", content, size));

        int reg = rom_seed_scan_datadir(dir);
        ASSERT(reg == 1);              /* only the valid bundle */
        ASSERT(rom_seed_count() == 1);

        char json[1024];
        size_t jn = rom_seed_directory_json(json, sizeof(json));
        ASSERT(jn > 0);
        ASSERT(json[0] == '[' && json[jn - 1] == ']');
        ASSERT(strstr(json, "consensus_bundle") != NULL);
        ASSERT(strstr(json, "\"chunks\":1") != NULL);

        free(content);
        free(bad);
        char p[1100];
        snprintf(p, sizeof(p), "%s/consensus-state-bundle-400.sqlite", dir); unlink(p);
        snprintf(p, sizeof(p), "%s/consensus-state-bundle-401.sqlite", dir); unlink(p);
        snprintf(p, sizeof(p), "%s/unrelated.dat", dir); unlink(p);
        rmdir(dir);
        rom_seed_reset();
        PASS();
    } _test_next:;
    return failures;
}

/* ── (e) bundles/ subdir scan — swarm-widening reseed (Lane A2) ────────
 *
 * boot_bundle_fetch.c lands verified downloads under <datadir>/bundles/, and
 * the installer deliberately RETAINS the source .sqlite there after install.
 * rom_seed_scan_datadir must find it (registering it as "bundles/<name>" so
 * rom_seed_read_chunk resolves it), while still ignoring a non-artifact file
 * placed alongside it and serving byte-identical chunks with the same
 * chunk_root a direct rom_seed_register of the same bytes would produce. */

static int test_bundles_subdir_scan(void)
{
    int failures = 0;
    TEST("rom_seed: bundles/ subdir scan registers a fetched bundle, "
         "ignores non-artifacts, same chunk_root as direct register") {
        rom_seed_reset();
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "romseed_bundlesdir", "ok");

        char bundles[320];
        snprintf(bundles, sizeof(bundles), "%s/bundles", dir);
        ASSERT(mkdir(bundles, 0700) == 0);

        size_t size = (size_t)ROM_SEED_CHUNK_SIZE + 4096; /* 2 chunks */
        uint8_t *content = malloc(size);
        ASSERT(content != NULL);
        gen_content(content, size, true);
        ASSERT(write_file(bundles, "consensus-state-bundle-500.sqlite",
                          content, size));
        /* A non-artifact file placed alongside it must be ignored. */
        ASSERT(write_file(bundles, "directory.json",
                          (const uint8_t *)"{}", 2));

        int reg = rom_seed_scan_datadir(dir);
        ASSERT(reg == 1); /* only the bundle, not directory.json */
        ASSERT(rom_seed_count() == 1);

        struct rom_artifact all[ROM_SEED_MAX_ARTIFACTS];
        int n = rom_seed_list(all, ROM_SEED_MAX_ARTIFACTS);
        ASSERT(n == 1);
        struct rom_artifact scanned = all[0];
        ASSERT(scanned.kind == ROM_ARTIFACT_CONSENSUS_BUNDLE);
        ASSERT(strcmp(scanned.filename, "bundles/consensus-state-bundle-500.sqlite")
               == 0);
        ASSERT(scanned.size_bytes == size);
        ASSERT(scanned.num_chunks == 2);

        /* Serving via the registry-recorded filename resolves to the SAME
         * bytes on disk (rom_seed_read_chunk builds "<datadir>/<filename>",
         * which must land on <dir>/bundles/consensus-state-bundle-500.sqlite,
         * not <dir>/consensus-state-bundle-500.sqlite). */
        uint8_t *rbuf = malloc(ROM_SEED_CHUNK_SIZE);
        ASSERT(rbuf != NULL);
        uint32_t rsz = 0;
        ASSERT(rom_seed_read_chunk(&scanned, dir, 0, rbuf, ROM_SEED_CHUNK_SIZE,
                                   &rsz));
        ASSERT(rsz == ROM_SEED_CHUNK_SIZE);
        ASSERT(memcmp(rbuf, content, ROM_SEED_CHUNK_SIZE) == 0);
        free(rbuf);

        /* Byte-identical to a direct register() of the same bytes: registering
         * the exact same content straight (no bundles/ prefix) under a fresh
         * registry entry must derive the SAME chunk_root — the swarm-served
         * artifact is not distinguishable-by-content from any other seeder's
         * copy of the identical bundle. */
        rom_seed_reset();
        struct rom_artifact direct;
        ASSERT(rom_seed_register(bundles, "consensus-state-bundle-500.sqlite",
                                 NULL, &direct) == ROM_REG_OK);
        ASSERT(memcmp(direct.chunk_root, scanned.chunk_root, 32) == 0);
        ASSERT(memcmp(direct.whole_sha3, scanned.whole_sha3, 32) == 0);

        free(content);
        rom_seed_reset();
        test_rm_rf_recursive(dir);
        PASS();
    } _test_next:;
    return failures;
}

/* A bundles/-shaped filename with anything other than the exact
 * ROM_SEED_BUNDLES_SUBDIR prefix, a second '/', or a leading '/' is refused —
 * rom_seed never reaches more than one level into exactly "bundles/". */
static int test_bundles_path_shape_refused(void)
{
    int failures = 0;
    TEST("rom_seed: only a one-level 'bundles/<name>' path is accepted") {
        rom_seed_reset();
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "romseed_pathshape", "ok");

        size_t size = 64 * 1024;
        uint8_t *content = malloc(size);
        ASSERT(content != NULL);
        gen_content(content, size, true);

        char sub[320];
        snprintf(sub, sizeof(sub), "%s/other", dir);
        ASSERT(mkdir(sub, 0700) == 0);
        ASSERT(write_file(sub, "consensus-state-bundle-501.sqlite",
                          content, size));
        /* Wrong subdir name. */
        ASSERT(rom_seed_register(dir, "other/consensus-state-bundle-501.sqlite",
                                 NULL, NULL) == ROM_REG_ERR_ARGS);

        /* Two levels deep under bundles/ — still refused. */
        ASSERT(rom_seed_register(dir,
                                 "bundles/deeper/consensus-state-bundle-501.sqlite",
                                 NULL, NULL) == ROM_REG_ERR_ARGS);

        /* A leading '/' (absolute-shaped) is refused. */
        ASSERT(rom_seed_register(dir, "/consensus-state-bundle-501.sqlite",
                                 NULL, NULL) == ROM_REG_ERR_ARGS);

        ASSERT(rom_seed_count() == 0);

        free(content);
        rom_seed_reset();
        test_rm_rf_recursive(dir);
        PASS();
    } _test_next:;
    return failures;
}

static int test_background_scan_worker_stack(void)
{
    int failures = 0;
    TEST("rom_seed: background scan fits the platform worker stack") {
        rom_seed_reset();
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "romseed_worker_stack", "ok");

        rom_seed_start_scan(dir, 0);
        rom_seed_stop_scan();

        ASSERT(rom_seed_count() == 0);
        test_rm_rf_recursive(dir);
        rom_seed_reset();
        PASS();
    } _test_next:;
    return failures;
}

int test_rom_seed(void)
{
    int failures = 0;
    failures += test_deregister();
    failures += test_register_digests();
    failures += test_free_vs_priced();
    failures += test_caps();
    failures += test_corrupt_refused();
    failures += test_scan_and_directory();
    failures += test_bundles_subdir_scan();
    failures += test_bundles_path_shape_refused();
    failures += test_background_scan_worker_stack();
    return failures;
}
