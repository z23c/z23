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

#include <dirent.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
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
        char root[512];
        char *dir = test_mkdtemp(root, sizeof(root), "zcl_rba_ok");
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
        char root[512];
        char *dir = test_mkdtemp(root, sizeof(root), "zcl_rba_norcpt");
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
        char root[512];
        char *dir = test_mkdtemp(root, sizeof(root), "zcl_rba_mismatch");
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
        char root[512];
        char *dir = test_mkdtemp(root, sizeof(root), "zcl_rba_scan");
        ASSERT(dir != NULL);

        size_t size = 64 * 1024;
        uint8_t *good = malloc(size);
        uint8_t *other = malloc(size);
        ASSERT(good != NULL && other != NULL);
        gen_content(good, size, true);
        /* Distinct content from `good` (still SQLite-magic-valid): the receipt
         * gate must refuse it, since the datadir's one receipt binds one digest. */
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

/* ── Mutation-gap tests: every refusal, the path bound, fd hygiene ──── */

#define RBA_BUNDLE "consensus-state-bundle-502.sqlite"

struct rba_fx {
    char dir[512];
    char name[160];
    char receipt[256];
    uint8_t digest[32];
};

/* A mkdtemp dir holding one bundle (content salted by `salt`) and, when
 * `receipt`, a replay receipt bound to that bundle's digest. */
static bool fx_setup(struct rba_fx *fx, const char *prefix, const char *name,
                     size_t size, bool magic, bool receipt, uint8_t salt)
{
    memset(fx, 0, sizeof(*fx));
    if (!test_mkdtemp(fx->dir, sizeof(fx->dir), prefix))
        return false;
    snprintf(fx->name, sizeof(fx->name), "%s", name);
    uint8_t *buf = malloc(size);
    if (!buf)
        return false;
    gen_content(buf, size, magic);
    buf[size - 1] ^= salt;
    bool ok = write_file(fx->dir, name, buf, size);
    sha3_256(buf, size, fx->digest);
    free(buf);
    if (ok && receipt)
        ok = consensus_state_replay_receipt_write_for_test(
            fx->dir, fx->digest, 700, 7, 2, 3, fx->receipt,
            sizeof(fx->receipt));
    return ok;
}

static void fx_teardown(struct rba_fx *fx)
{
    char p[1100];
    chmod(fx->dir, 0700);
    snprintf(p, sizeof(p), "%s/%s", fx->dir, fx->name);
    if (unlink(p) != 0)
        rmdir(p);
    if (fx->receipt[0])
        unlink(fx->receipt);
    rmdir(fx->dir);
}

static bool catalog_holds(const uint8_t digest[32])
{
    struct rom_artifact arts[ROM_SEED_MAX_ARTIFACTS];
    int n = rom_seed_list(arts, ROM_SEED_MAX_ARTIFACTS);
    for (int i = 0; i < n; i++)
        if (memcmp(arts[i].whole_sha3, digest, 32) == 0)
            return true;
    return false;
}

/* Register must refuse with `want`, leave *out untouched and the catalog
 * empty. */
static bool refused_with(const char *dir, const char *name,
                         enum rom_bundle_admission_result want)
{
    struct rom_artifact art;
    memset(&art, 0xA5, sizeof(art));
    struct rom_artifact before = art;
    enum rom_bundle_admission_result rc =
        rom_bundle_admission_register(dir, name, &art);
    if (rc != want || memcmp(&art, &before, sizeof(art)) != 0 ||
        rom_seed_count() != 0) {
        fprintf(stderr, "refused_with: rc=%d want=%d count=%d\n", (int)rc,
                (int)want, rom_seed_count());
        return false;
    }
    return true;
}

struct arg_row {
    int dir_kind; /* 0 NULL, 1 "", 2 "x" (absent), 3 the fixture dir */
    const char *name;
    enum rom_bundle_admission_result want;
};

static const struct arg_row arg_rows[] = {
    { 0, RBA_BUNDLE, ROM_BUNDLE_ADMIT_ERR_ARGS },
    { 1, RBA_BUNDLE, ROM_BUNDLE_ADMIT_ERR_ARGS },
    { 2, RBA_BUNDLE, ROM_BUNDLE_ADMIT_ERR_HASH },
    { 3, NULL, ROM_BUNDLE_ADMIT_ERR_ARGS },
    { 3, "", ROM_BUNDLE_ADMIT_ERR_ARGS },
    { 3, "a", ROM_BUNDLE_ADMIT_ERR_NOT_BUNDLE },
    { 3, ".", ROM_BUNDLE_ADMIT_ERR_ARGS },
    { 3, "..", ROM_BUNDLE_ADMIT_ERR_ARGS },
    { 3, "x..y", ROM_BUNDLE_ADMIT_ERR_ARGS },
    { 3, "consensus-state-bundle-1..sqlite", ROM_BUNDLE_ADMIT_ERR_ARGS },
    { 3, "sub/" RBA_BUNDLE, ROM_BUNDLE_ADMIT_ERR_ARGS },
    { 3, "/" RBA_BUNDLE, ROM_BUNDLE_ADMIT_ERR_ARGS },
    { 3, "block_index.bin", ROM_BUNDLE_ADMIT_ERR_NOT_BUNDLE },
    { 3, RBA_BUNDLE ".bak", ROM_BUNDLE_ADMIT_ERR_NOT_BUNDLE },
    { 3, "bundle-502.sqlite", ROM_BUNDLE_ADMIT_ERR_NOT_BUNDLE },
    { 3, "consensus-state-bundle-9.sqlite", ROM_BUNDLE_ADMIT_ERR_HASH },
};

static bool arg_rows_refused(const struct rba_fx *fx)
{
    static const char *const dirs[] = { NULL, "", "x" };
    for (size_t i = 0; i < sizeof(arg_rows) / sizeof(arg_rows[0]); i++) {
        const struct arg_row *r = &arg_rows[i];
        const char *dir = r->dir_kind == 3 ? fx->dir : dirs[r->dir_kind];
        if (!refused_with(dir, r->name, r->want)) {
            fprintf(stderr, "arg row %zu\n", i);
            return false;
        }
    }
    return true;
}

static int test_refuse_malformed_args(void)
{
    int failures = 0;
    TEST("rom_bundle_admission: malformed dir/filename draw exact refusals") {
        rom_seed_reset();
        struct rba_fx fx;
        ASSERT(fx_setup(&fx, "zcl_rba_args", RBA_BUNDLE, 8192, true, true, 0));
        bool ok = arg_rows_refused(&fx);
        fx_teardown(&fx);
        rom_seed_reset();
        ASSERT(ok);
        PASS();
    } _test_next:;
    return failures;
}

/* dir + "/" + name is bounded by a 1024-byte buffer: 1023 bytes fit, 1024
 * truncate and refuse. A directory that does not exist reaches ERR_HASH. */
static bool path_bound_rows(void)
{
    static const char name[] = "consensus-state-bundle-1.sqlite";
    static const struct {
        size_t total;
        enum rom_bundle_admission_result want;
    } rows[] = {
        { 1022, ROM_BUNDLE_ADMIT_ERR_HASH },
        { 1023, ROM_BUNDLE_ADMIT_ERR_HASH },
        { 1024, ROM_BUNDLE_ADMIT_ERR_ARGS },
        { 1025, ROM_BUNDLE_ADMIT_ERR_ARGS },
    };
    char dir[1100];
    for (size_t i = 0; i < sizeof(rows) / sizeof(rows[0]); i++) {
        size_t dlen = rows[i].total - strlen(name) - 1;
        for (size_t k = 0; k < dlen; k++)
            dir[k] = (k % 64 == 0) ? '/' : 'a';
        if (dlen > 1 && (dlen - 1) % 64 == 0)
            dir[dlen - 1] = 'a';
        dir[dlen] = '\0';
        if (!refused_with(dir, name, rows[i].want)) {
            fprintf(stderr, "path bound row %zu\n", i);
            return false;
        }
    }
    return true;
}

static int test_path_overflow_bound(void)
{
    int failures = 0;
    TEST("rom_bundle_admission: path buffer bound is exact (1023 ok, 1024 refused)") {
        rom_seed_reset();
        ASSERT(path_bound_rows());
        PASS();
    } _test_next:;
    return failures;
}

/* A candidate that cannot be hashed or registered refuses with the exact
 * stage, leaving the catalog empty and *out untouched. */
static bool unhashable_and_unregisterable(void)
{
    struct rba_fx dirfx, magic, small;
    bool ok = fx_setup(&dirfx, "zcl_rba_isdir", RBA_BUNDLE, 8192, true, true, 0);
    char p[1100];
    snprintf(p, sizeof(p), "%s/%s", dirfx.dir, RBA_BUNDLE);
    /* A directory named like a bundle opens but cannot be read. */
    ok = ok && unlink(p) == 0 && mkdir(p, 0700) == 0 &&
         refused_with(dirfx.dir, RBA_BUNDLE, ROM_BUNDLE_ADMIT_ERR_HASH);
    fx_teardown(&dirfx);
    /* Receipt binds the bytes, but rom_seed's own structural gate refuses. */
    ok = ok && fx_setup(&magic, "zcl_rba_magic", RBA_BUNDLE, 8192, false,
                        true, 0) &&
         refused_with(magic.dir, RBA_BUNDLE, ROM_BUNDLE_ADMIT_ERR_REGISTER);
    fx_teardown(&magic);
    ok = ok && fx_setup(&small, "zcl_rba_small", RBA_BUNDLE, 4095, true,
                        true, 0) &&
         refused_with(small.dir, RBA_BUNDLE, ROM_BUNDLE_ADMIT_ERR_REGISTER);
    fx_teardown(&small);
    return ok;
}

static int test_refuse_unhashable_unregisterable(void)
{
    int failures = 0;
    TEST("rom_bundle_admission: unreadable or structurally bad bundle refuses") {
        rom_seed_reset();
        bool ok = unhashable_and_unregisterable();
        rom_seed_reset();
        ASSERT(ok);
        PASS();
    } _test_next:;
    return failures;
}

/* The whole file is hashed: a size one byte past a read chunk (65536 + 1)
 * still admits with the receipt bound to its full digest. */
static int test_admit_past_one_chunk(void)
{
    int failures = 0;
    TEST("rom_bundle_admission: bundle one byte past a hash chunk admits") {
        rom_seed_reset();
        struct rba_fx fx;
        ASSERT(fx_setup(&fx, "zcl_rba_chunk", RBA_BUNDLE, 65536 + 1, true,
                        true, 0x5a));
        struct rom_artifact art;
        memset(&art, 0, sizeof(art));
        enum rom_bundle_admission_result rc =
            rom_bundle_admission_register(fx.dir, RBA_BUNDLE, &art);
        bool ok = rc == ROM_BUNDLE_ADMIT_OK &&
                  memcmp(art.whole_sha3, fx.digest, 32) == 0 &&
                  rom_seed_count() == 1 && catalog_holds(fx.digest);
        fx_teardown(&fx);
        rom_seed_reset();
        ASSERT(ok);
        PASS();
    } _test_next:;
    return failures;
}

/* A second admission hashes with a fresh context, not the leftover state of
 * the previous one. */
static int test_back_to_back_admissions_hash_fresh(void)
{
    int failures = 0;
    TEST("rom_bundle_admission: consecutive admissions each hash fresh") {
        rom_seed_reset();
        struct rba_fx a, b;
        ASSERT(fx_setup(&a, "zcl_rba_ba", "consensus-state-bundle-601.sqlite",
                        20000, true, true, 0x11));
        ASSERT(fx_setup(&b, "zcl_rba_bb", "consensus-state-bundle-602.sqlite",
                        30000, true, true, 0x22));
        bool ok = rom_bundle_admission_register(a.dir, a.name, NULL) ==
                  ROM_BUNDLE_ADMIT_OK;
        ok = ok && rom_bundle_admission_register(b.dir, b.name, NULL) ==
                       ROM_BUNDLE_ADMIT_OK;
        ok = ok && rom_seed_count() == 2 && catalog_holds(a.digest) &&
             catalog_holds(b.digest);
        fx_teardown(&a);
        fx_teardown(&b);
        rom_seed_reset();
        ASSERT(ok);
        PASS();
    } _test_next:;
    return failures;
}

/* Owner can traverse the dir (so the bundle hashes) but cannot open it for
 * reading: the receipt lookup cannot run, which must refuse, not admit. */
static int test_refuse_unreadable_receipt_dir(void)
{
    int failures = 0;
    TEST("rom_bundle_admission: unopenable receipt dir refuses (fail-closed)") {
        rom_seed_reset();
        struct rba_fx fx;
        ASSERT(fx_setup(&fx, "zcl_rba_noread", RBA_BUNDLE, 8192, true, true,
                        0));
        bool ok = true;
        if (geteuid() != 0) {
            ok = chmod(fx.dir, 0100) == 0 &&
                 refused_with(fx.dir, RBA_BUNDLE,
                              ROM_BUNDLE_ADMIT_ERR_NO_RECEIPT);
        }
        fx_teardown(&fx);
        rom_seed_reset();
        ASSERT(ok);
        PASS();
    } _test_next:;
    return failures;
}

/* ── No descriptor survives any admission outcome ───────────────────── */

static int count_open_fds(void)
{
    DIR *d = opendir("/proc/self/fd");
    if (!d)
        return -1;
    int n = 0;
    struct dirent *e;
    while ((e = readdir(d)) != NULL)
        if (e->d_name[0] != '.')
            n++;
    closedir(d);
    return n;
}

static void fd_workload(const struct rba_fx *good, const struct rba_fx *norcpt,
                        const struct rba_fx *magic)
{
    rom_seed_reset();
    (void)rom_bundle_admission_register(good->dir, good->name, NULL);
    (void)rom_bundle_admission_register(norcpt->dir, norcpt->name, NULL);
    (void)rom_bundle_admission_register(magic->dir, magic->name, NULL);
    (void)rom_bundle_admission_register(good->dir, "consensus-state-bundle-9.sqlite",
                                        NULL);
    (void)rom_bundle_admission_scan(good->dir);
    rom_seed_reset();
}

static int test_admission_leaks_no_descriptors(void)
{
    int failures = 0;
    TEST("rom_bundle_admission: admit/refuse/scan leave no descriptor open") {
        struct rba_fx good, norcpt, magic;
        ASSERT(fx_setup(&good, "zcl_rba_fg", "consensus-state-bundle-611.sqlite",
                        8192, true, true, 1));
        ASSERT(fx_setup(&norcpt, "zcl_rba_fn", "consensus-state-bundle-612.sqlite",
                        8192, true, false, 2));
        ASSERT(fx_setup(&magic, "zcl_rba_fm", "consensus-state-bundle-613.sqlite",
                        8192, false, true, 3));
        fd_workload(&good, &norcpt, &magic); /* warm lazy one-time opens */
        int before = count_open_fds();
        fd_workload(&good, &norcpt, &magic);
        int after = count_open_fds();
        fx_teardown(&good);
        fx_teardown(&norcpt);
        fx_teardown(&magic);
        ASSERT(before > 0);
        ASSERT(after == before);
        PASS();
    } _test_next:;
    return failures;
}

/* ── Scan: counts only real admissions; "." and degenerate dirs ─────── */
/* Scan: nothing admitted means 0 (a failed attempt is not an admission),
 * and degenerate directories draw 0. */
static bool scan_returns_zero_cases(void)
{
    struct rba_fx norcpt;
    if (!fx_setup(&norcpt, "zcl_rba_sn", "consensus-state-bundle-621.sqlite",
                  8192, true, false, 0))
        return false;
    bool ok = rom_bundle_admission_scan(norcpt.dir) == 0 &&
              rom_seed_count() == 0;
    fx_teardown(&norcpt);
    return ok && rom_bundle_admission_scan(NULL) == 0 &&
           rom_bundle_admission_scan("") == 0 &&
           rom_bundle_admission_scan("zcl_rba_no_such_dir_x") == 0;
}

static bool scan_admits_one_cases(void)
{
    struct rba_fx good;
    if (!fx_setup(&good, "zcl_rba_sg", "consensus-state-bundle-622.sqlite",
                  8192, true, true, 0))
        return false;
    bool ok = write_file(good.dir, "notes.txt", (const uint8_t *)"x", 1);
    ok = ok && rom_bundle_admission_scan(good.dir) == 1 &&
         rom_seed_count() == 1 && catalog_holds(good.digest);
    char p[1100];
    snprintf(p, sizeof(p), "%s/notes.txt", good.dir);
    unlink(p);
    fx_teardown(&good);
    return ok;
}

static int test_scan_counts_only_admissions(void)
{
    int failures = 0;
    TEST("rom_bundle_admission: scan counts admissions, not attempts") {
        rom_seed_reset();
        bool zero = scan_returns_zero_cases();
        rom_seed_reset();
        bool one = scan_admits_one_cases();
        rom_seed_reset();
        ASSERT(zero);
        ASSERT(one);
        PASS();
    } _test_next:;
    return failures;
}

static bool dot_dir_cases(const struct rba_fx *fx)
{
    struct rom_artifact art;
    memset(&art, 0, sizeof(art));
    bool ok = rom_bundle_admission_register(".", fx->name, &art) ==
                  ROM_BUNDLE_ADMIT_OK &&
              memcmp(art.whole_sha3, fx->digest, 32) == 0;
    rom_seed_reset();
    ok = ok && rom_bundle_admission_scan(".") == 1;
    rom_seed_reset();
    rom_bundle_admission_start_scan(".");
    rom_bundle_admission_stop_scan();
    ok = ok && rom_seed_count() == 1 && catalog_holds(fx->digest);
    rom_seed_reset();
    return ok;
}

static int test_dot_directory_admits(void)
{
    int failures = 0;
    TEST("rom_bundle_admission: a one-character dir name (.) is a real dir") {
        rom_seed_reset();
        struct rba_fx fx;
        ASSERT(fx_setup(&fx, "zcl_rba_dot", "consensus-state-bundle-631.sqlite",
                        8192, true, true, 0));
        char cwd[1024];
        ASSERT(getcwd(cwd, sizeof(cwd)) != NULL);
        ASSERT(chdir(fx.dir) == 0);
        bool ok = dot_dir_cases(&fx);
        bool back = chdir(cwd) == 0;
        fx_teardown(&fx);
        ASSERT(back);
        ASSERT(ok);
        PASS();
    } _test_next:;
    return failures;
}

/* ── Background scan lifecycle ──────────────────────────────────────── */

static bool lifecycle_holds(const struct rba_fx *a, const struct rba_fx *b)
{
    /* Nothing started: stop is a no-op, twice; empty starts are no-ops. */
    rom_bundle_admission_stop_scan();
    rom_bundle_admission_stop_scan();
    rom_bundle_admission_start_scan(NULL);
    rom_bundle_admission_start_scan("");
    rom_bundle_admission_stop_scan();
    if (rom_seed_count() != 0)
        return false;
    rom_bundle_admission_start_scan(a->dir);
    rom_bundle_admission_start_scan(b->dir); /* idempotent while started */
    rom_bundle_admission_stop_scan();        /* joins: scan ran to the end */
    if (rom_seed_count() != 1 || !catalog_holds(a->digest) ||
        catalog_holds(b->digest))
        return false;
    rom_bundle_admission_stop_scan();        /* already stopped: no-op */
    rom_bundle_admission_start_scan(b->dir); /* restartable after stop */
    rom_bundle_admission_stop_scan();
    return rom_seed_count() == 2 && catalog_holds(b->digest);
}

static int test_scan_thread_lifecycle(void)
{
    int failures = 0;
    TEST("rom_bundle_admission: start/stop scan thread is idempotent and joins") {
        rom_seed_reset();
        struct rba_fx a, b;
        ASSERT(fx_setup(&a, "zcl_rba_la", "consensus-state-bundle-641.sqlite",
                        8192, true, true, 0x31));
        ASSERT(fx_setup(&b, "zcl_rba_lb", "consensus-state-bundle-642.sqlite",
                        9000, true, true, 0x32));
        bool ok = lifecycle_holds(&a, &b);
        fx_teardown(&a);
        fx_teardown(&b);
        rom_seed_reset();
        ASSERT(ok);
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
    failures += test_refuse_malformed_args();
    failures += test_path_overflow_bound();
    failures += test_refuse_unhashable_unregisterable();
    failures += test_admit_past_one_chunk();
    failures += test_back_to_back_admissions_hash_fresh();
    failures += test_refuse_unreadable_receipt_dir();
    failures += test_admission_leaks_no_descriptors();
    failures += test_scan_counts_only_admissions();
    failures += test_dot_directory_admits();
    failures += test_scan_thread_lifecycle();
    return failures;
}
