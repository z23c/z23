/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Pins the production snapshot -> coins_kv apply transaction. uss_open owns the
 * SHA3 trust gate; boot_snapshot_apply_to_coins_kv owns exact-count insertion,
 * migration stamping, and rollback-on-any-mismatch.
 */

#include "test/test_core.h"

#include "chain/utxo_snapshot_loader.h"
#include "config/boot.h"
#include "storage/coins_kv.h"
#include "storage/progress_store.h"

#include <stdbool.h>
#include <stdint.h>
#include <sqlite3.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define SA_CHECK(name, expr) do {                                      \
    printf("snapshot_apply_coins_kv: %s... ", (name));                 \
    if (expr) printf("OK\n");                                         \
    else { printf("FAIL\n"); failures++; }                            \
} while (0)

static void sa_txid(uint8_t out[32], uint8_t seed)
{
    for (int i = 0; i < 32; i++)
        out[i] = (uint8_t)(seed + i * 3);
}

static bool sa_seed_source(sqlite3 *db)
{
    if (!coins_kv_ensure_schema(db))
        return false;

    uint8_t txid[32];
    uint8_t script_a[] = {0x76, 0xa9, 0x14, 0x01, 0x02};
    uint8_t script_b[] = {0x6a};
    uint8_t script_c[] = {0x21, 0x02, 0x03, 0x04, 0x05, 0xac};

    sa_txid(txid, 0x10);
    if (!coins_kv_add(db, txid, 0, 11111, 10, true,
                      script_a, sizeof(script_a)))
        return false;
    sa_txid(txid, 0x20);
    if (!coins_kv_add(db, txid, 2, 22222, 20, false,
                      script_b, sizeof(script_b)))
        return false;
    sa_txid(txid, 0x30);
    return coins_kv_add(db, txid, 7, 33333, 30, false,
                        script_c, sizeof(script_c));
}

static bool sa_write_snapshot(const char *path, uint8_t root[32],
                              uint64_t *count_out)
{
    sqlite3 *src = NULL;
    if (sqlite3_open(":memory:", &src) != SQLITE_OK)
        return false;

    bool ok = sa_seed_source(src) && coins_kv_commitment(src, root) == 0;
    uint8_t anchor_hash[32];
    for (int i = 0; i < 32; i++)
        anchor_hash[i] = (uint8_t)(0xa0 + i);
    uint8_t written_root[32] = {0};
    uint64_t written_count = 0;
    int64_t written_supply = 0;
    ok = ok && coins_kv_snapshot_write(src, path, 30, anchor_hash,
                                       /*shielded=*/NULL,
                                       written_root, &written_count,
                                       &written_supply);
    ok = ok && memcmp(root, written_root, 32) == 0;
    ok = ok && written_count == 3 && written_supply == 66666;
    if (count_out)
        *count_out = written_count;
    sqlite3_close(src);
    return ok;
}

static bool sa_migration_stamp_present(sqlite3 *db)
{
    uint8_t v = 0;
    size_t n = 0;
    bool found = false;
    return progress_meta_get(db, COINS_KV_MIGRATION_COMPLETE_KEY,
                             &v, sizeof(v), &n, &found) &&
           found && n == 1 && v == 1;
}

static bool sa_flip_body_byte(const char *path)
{
    FILE *f = fopen(path, "rb+");
    if (!f)
        return false;
    if (fseek(f, 128, SEEK_SET) != 0) {
        fclose(f);
        return false;
    }
    int c = fgetc(f);
    if (c == EOF) {
        fclose(f);
        return false;
    }
    if (fseek(f, 128, SEEK_SET) != 0) {
        fclose(f);
        return false;
    }
    fputc(c ^ 0xff, f);
    bool ok = fclose(f) == 0;
    return ok;
}

int test_snapshot_apply_coins_kv(void)
{
    printf("\n=== snapshot_apply_coins_kv ===\n");
    int failures = 0;

    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "snapshot_apply_coins_kv", "main");
    char snap_path[320];
    snprintf(snap_path, sizeof(snap_path), "%s/utxo-anchor.snapshot", dir);

    uint8_t expected_root[32] = {0};
    uint64_t expected_count = 0;
    SA_CHECK("source snapshot written",
             sa_write_snapshot(snap_path, expected_root, &expected_count));

    progress_store_close();
    bool opened = progress_store_open(dir);
    SA_CHECK("progress store opens", opened);
    sqlite3 *pdb = opened ? progress_store_db() : NULL;
    SA_CHECK("coins_kv schema", pdb && coins_kv_ensure_schema(pdb));
    SA_CHECK("destination starts empty", pdb && coins_kv_count(pdb) == 0);

    struct uss_header hdr;
    char err[128] = {0};
    struct uss_handle *h = uss_open(snap_path, true, expected_root,
                                    &hdr, err, sizeof(err));
    SA_CHECK("uss_open verifies body SHA3 and expected root",
             h != NULL && hdr.count == expected_count);
    if (h && pdb) {
        struct boot_snapshot_apply_result ar = {0};
        SA_CHECK("production helper applies exact count",
                 boot_snapshot_apply_to_coins_kv(pdb, h, hdr.count, &ar) &&
                 ar.inserted == expected_count &&
                 ar.emitted == (int64_t)expected_count);
        uint8_t got_root[32] = {0};
        SA_CHECK("destination count matches snapshot",
                 coins_kv_count(pdb) == (int64_t)expected_count);
        SA_CHECK("destination commitment matches snapshot root",
                 coins_kv_commitment(pdb, got_root) == 0 &&
                 memcmp(got_root, expected_root, 32) == 0);
        SA_CHECK("migration stamp committed with coins",
                 sa_migration_stamp_present(pdb));
        uss_close(h);
    } else if (h) {
        uss_close(h);
    }

    SA_CHECK("reset destination before mismatch test",
             pdb && coins_kv_reset_for_reseed(pdb) &&
             coins_kv_count(pdb) == 0);
    h = uss_open(snap_path, true, expected_root, &hdr, err, sizeof(err));
    SA_CHECK("uss_open still verifies clean snapshot", h != NULL);
    if (h && pdb) {
        struct boot_snapshot_apply_result ar = {0};
        SA_CHECK("wrong expected count rolls back",
                 !boot_snapshot_apply_to_coins_kv(pdb, h, hdr.count + 1, &ar) &&
                 ar.inserted == expected_count &&
                 ar.emitted == (int64_t)expected_count &&
                 coins_kv_count(pdb) == 0 &&
                 !sa_migration_stamp_present(pdb));
        uss_close(h);
    } else if (h) {
        uss_close(h);
    }

    SA_CHECK("reset destination before tamper test",
             pdb && coins_kv_reset_for_reseed(pdb) &&
             coins_kv_count(pdb) == 0);
    SA_CHECK("snapshot body tampered", sa_flip_body_byte(snap_path));
    err[0] = '\0';
    h = uss_open(snap_path, true, expected_root, &hdr, err, sizeof(err));
    SA_CHECK("tampered snapshot refused before apply",
             h == NULL && strcmp(err, "body sha3 mismatch") == 0);
    if (h)
        uss_close(h);
    SA_CHECK("tampered refusal leaves coins_kv empty",
             pdb && coins_kv_count(pdb) == 0 &&
             !sa_migration_stamp_present(pdb));

    progress_store_close();
    test_cleanup_tmpdir(dir);

    printf("snapshot_apply_coins_kv: %s (%d failures)\n",
           failures == 0 ? "OK" : "FAIL", failures);
    return failures;
}
