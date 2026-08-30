/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Unit test for the compiled-checkpoint content re-check (W4-3b):
 *   - coins_kv_verify_against_checkpoint (storage/coins_kv.h): re-derive the
 *     canonical coins_kv commitment + count (the ONE coins_kv_commitment fold)
 *     and compare to a SHA3 UTXO checkpoint. A fixture set that matches passes;
 *     a single-row mutation fails closed with a typed reason.
 *   - boot_verify_rom (config/boot.h): the -verify-rom terminal verb dispatch —
 *     smoke-tested by forking a child that installs a test checkpoint override,
 *     opens the fixture progress store, and calls the verb; the child _exit()s
 *     PASS(0) on a matching set and FAIL(1) on a corrupted checkpoint.
 *
 * The fixture derives the checkpoint FROM the durable coins_kv set (so the
 * matching case is exact by construction), the same shape the real ceremony and
 * the -ratify-mint-anchor test use. */

#include "test/test_core.h"

#include "chain/checkpoints.h"
#include "config/boot.h"
#include "core/uint256.h"
#include "storage/coins_kv.h"
#include "storage/progress_store.h"

#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if !defined(_WIN32)
#include <sys/wait.h>
#endif
#include <unistd.h>
#if !defined(_WIN32)

#define CKR_CHECK(name, expr) do {                                          \
    if (expr) { printf("  ckpt_recheck: %s... OK\n", (name)); }             \
    else { printf("  ckpt_recheck: %s... FAIL\n", (name)); failures++; }    \
} while (0)

/* Build a fixture datadir with a small durable coins_kv, applied_height set to
 * `applied`, and a checkpoint `cp` derived from that durable set at `height`.
 * Returns the live db handle (progress store left OPEN), or NULL on failure. */
static sqlite3 *ckr_open_fixture(const char *tag, char *dir, size_t dir_cap,
                                 struct sha3_utxo_checkpoint *cp,
                                 int32_t height, int32_t applied)
{
    test_make_tmpdir(dir, dir_cap, tag, "main");
    if (!progress_store_open(dir))
        return NULL;
    sqlite3 *db = progress_store_db();
    if (!db || !coins_kv_ensure_schema(db) || !progress_meta_table_ensure(db))
        return NULL;

    struct uint256 t; uint256_set_null(&t);
    t.data[0] = 0xC0; t.data[1] = 0xDE; t.data[31] = 0x11;
    const unsigned char sc[5] = {0x76, 0xA9, 0x14, 0x00, 0x88};
    if (!coins_kv_add(db, t.data, 0, 5000, height, true, sc, sizeof(sc)) ||
        !coins_kv_add(db, t.data, 1, 7000, height, false, sc, sizeof(sc)) ||
        !coins_kv_add(db, t.data, 2, 9000, height, false, NULL, 0))
        return NULL;

    memset(cp, 0, sizeof(*cp));
    cp->height = height;
    if (coins_kv_commitment(db, cp->sha3_hash) != 0)
        return NULL;
    int64_t n = coins_kv_count(db);
    if (n < 0)
        return NULL;
    cp->utxo_count = (uint64_t)n;
    cp->total_supply = 21000;
    for (int i = 0; i < 32; i++)
        cp->block_hash[i] = (uint8_t)(0x40 + i);

    char *err = NULL;
    bool ok = sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, &err) == SQLITE_OK
              && coins_kv_set_applied_height_in_tx(db, applied)
              && sqlite3_exec(db, "COMMIT", NULL, NULL, &err) == SQLITE_OK;
    if (err) sqlite3_free(err);
    return ok ? db : NULL;
}

/* Fork a child that installs `override_cp` as the compiled checkpoint, opens the
 * fixture at `dir`, and dispatches -verify-rom. Returns the child's exit code
 * (0 PASS / 1 FAIL), or -1 on a fork/wait error. The child's stdout+stderr are
 * silenced so the expected-FAIL banner never pollutes the group log. */
static int ckr_run_verify_rom_child(const char *dir,
                                    const struct sha3_utxo_checkpoint *override_cp)
{
    pid_t pid = fork();
    if (pid < 0)
        return -1;
    if (pid == 0) {
        (void)freopen("/dev/null", "w", stdout);
        (void)freopen("/dev/null", "w", stderr);
        checkpoints_set_sha3_override_for_test(override_cp);
        if (!progress_store_open(dir))
            _exit(2);
        boot_verify_rom(dir);   /* TERMINAL: _exit(0) PASS / _exit(1) FAIL */
        _exit(3);               /* unreachable */
    }
    int st = 0;
    if (waitpid(pid, &st, 0) < 0 || !WIFEXITED(st))
        return -1;
    return WEXITSTATUS(st);
}

int test_ckpt_recheck(void);
int test_ckpt_recheck(void)
{
    printf("\n=== checkpoint content re-check (verify-rom) tests ===\n");
    int failures = 0;
    const int32_t H = 250;

    /* NULL hardening — no fixture needed. */
    {
        struct sha3_utxo_checkpoint cp; memset(&cp, 0, sizeof(cp));
        char reason[256] = {0};
        CKR_CHECK("null db -> false",
                  !coins_kv_verify_against_checkpoint(NULL, &cp, NULL, NULL,
                                                      reason, sizeof reason));
        CKR_CHECK("null db reason set", reason[0] != '\0');
    }

    /* Case (a): a fixture set matching a derived checkpoint passes. */
    {
        char dir[256];
        struct sha3_utxo_checkpoint cp;
        sqlite3 *db = ckr_open_fixture("ckr_match", dir, sizeof(dir), &cp,
                                       H, /*applied=*/H + 1);
        CKR_CHECK("match: fixture built", db != NULL);
        if (db) {
            uint8_t got[32] = {0};
            int64_t got_count = -1;
            char reason[256] = {0};
            CKR_CHECK("match: verify PASS",
                      coins_kv_verify_against_checkpoint(db, &cp, got, &got_count,
                                                         reason, sizeof reason));
            CKR_CHECK("match: got count == baked",
                      got_count == (int64_t)cp.utxo_count);
            CKR_CHECK("match: got root == baked",
                      memcmp(got, cp.sha3_hash, 32) == 0);
            CKR_CHECK("match: reason says reproduces",
                      strstr(reason, "reproduces") != NULL);
        }
        progress_store_close();
        test_cleanup_tmpdir(dir);
    }

    /* Case (b): a single-row value mutation fails closed (same count, different
     * sha3) with a typed reason naming "sha3". */
    {
        char dir[256];
        struct sha3_utxo_checkpoint cp;
        sqlite3 *db = ckr_open_fixture("ckr_mutate", dir, sizeof(dir), &cp,
                                       H, /*applied=*/H + 1);
        CKR_CHECK("mutate: fixture built", db != NULL);
        if (db) {
            /* Overwrite vout 1's value in place (INSERT OR REPLACE): the row
             * count is unchanged so ONLY the SHA3 commitment diverges. */
            struct uint256 t; uint256_set_null(&t);
            t.data[0] = 0xC0; t.data[1] = 0xDE; t.data[31] = 0x11;
            const unsigned char sc[5] = {0x76, 0xA9, 0x14, 0x00, 0x88};
            CKR_CHECK("mutate: row overwritten",
                      coins_kv_add(db, t.data, 1, 6999, H, false, sc, sizeof(sc)));
            uint8_t got[32] = {0};
            int64_t got_count = -1;
            char reason[256] = {0};
            CKR_CHECK("mutate: verify FAIL (closed)",
                      !coins_kv_verify_against_checkpoint(db, &cp, got, &got_count,
                                                          reason, sizeof reason));
            CKR_CHECK("mutate: count preserved (same cardinality)",
                      got_count == (int64_t)cp.utxo_count);
            CKR_CHECK("mutate: root diverged",
                      memcmp(got, cp.sha3_hash, 32) != 0);
            CKR_CHECK("mutate: reason names sha3",
                      strstr(reason, "sha3") != NULL);
        }
        progress_store_close();
        test_cleanup_tmpdir(dir);
    }

    /* Case (c): an added row (different cardinality) fails with a "count" reason. */
    {
        char dir[256];
        struct sha3_utxo_checkpoint cp;
        sqlite3 *db = ckr_open_fixture("ckr_count", dir, sizeof(dir), &cp,
                                       H, /*applied=*/H + 1);
        CKR_CHECK("count: fixture built", db != NULL);
        if (db) {
            struct uint256 t2; uint256_set_null(&t2);
            t2.data[0] = 0xAB; t2.data[31] = 0xCD;
            CKR_CHECK("count: extra row added",
                      coins_kv_add(db, t2.data, 0, 1, H, false, NULL, 0));
            char reason[256] = {0};
            CKR_CHECK("count: verify FAIL (closed)",
                      !coins_kv_verify_against_checkpoint(db, &cp, NULL, NULL,
                                                          reason, sizeof reason));
            CKR_CHECK("count: reason names count",
                      strstr(reason, "count") != NULL);
        }
        progress_store_close();
        test_cleanup_tmpdir(dir);
    }

    /* Case (d): -verify-rom verb dispatch — PASS(0) on a match, FAIL(1) on a
     * corrupted checkpoint. Each runs in a forked child (the verb _exit()s). */
    {
        char dir[256];
        struct sha3_utxo_checkpoint cp;
        sqlite3 *db = ckr_open_fixture("ckr_verb", dir, sizeof(dir), &cp,
                                       H, /*applied=*/H + 1);
        CKR_CHECK("verb: fixture built", db != NULL);
        progress_store_close();  /* close before fork: no shared sqlite fd */
        if (db) {
            int rc_pass = ckr_run_verify_rom_child(dir, &cp);
            CKR_CHECK("verb: PASS dispatch exits 0", rc_pass == 0);

            struct sha3_utxo_checkpoint bad = cp;
            bad.sha3_hash[0] ^= 0xFF;  /* corrupt the baked root */
            int rc_fail = ckr_run_verify_rom_child(dir, &bad);
            CKR_CHECK("verb: FAIL dispatch exits 1", rc_fail == 1);
        }
        test_cleanup_tmpdir(dir);
    }

    return failures;
}
#else  /* _WIN32 */
/* Windows has no fork()/waitpid process model; this group's forked verify-rom child dispatch lane
 * cannot run here. Skipped loudly rather than faked. */
int test_ckpt_recheck(void)
{
    printf("ckpt_recheck: SKIP (Windows): forked verify-rom child dispatch lane\n");
    return 0;
}
#endif
