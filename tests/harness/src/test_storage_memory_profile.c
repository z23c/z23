/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_storage_memory_profile — the steady (tip-following) SQLite memory
 * profile on the consensus.db and projection connections.  On temp-dir
 * fixture stores: PRAGMA mmap_size / cache_size read back the folding values
 * at open, the steady 64 MiB / 128 MiB caps after the switch, the folding
 * values again after switching back, and a write/read round trip returns the
 * same rows in every profile (PRAGMA-only: no byte read or written changes). */

#include "test/test_core.h"

#include "storage/memory_profile.h"
#include "storage/progress_store.h"
#include "storage/projection_store.h"

#include <sqlite3.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define MP_CHECK(name, expr) do {                                      \
    if (expr) { printf("  memory_profile: %s... OK\n", (name)); }       \
    else { printf("  memory_profile: %s... FAIL\n", (name)); failures++; } \
} while (0)

static int64_t mp_pragma(sqlite3 *db, const char *sql)
{
    sqlite3_stmt *st = NULL;
    int64_t v = INT64_MIN;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK) return v;
    if (sqlite3_step(st) == SQLITE_ROW) v = sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);
    return v;
}

/* Fresh value per profile so a stale read cannot satisfy the check. */
static bool mp_roundtrip(sqlite3 *pdb, sqlite3 *jdb, int gen)
{
    char key[32], val[32], got[32];
    snprintf(key, sizeof(key), "mp_key_%d", gen);
    snprintf(val, sizeof(val), "mp_val_%d", gen);
    size_t len = 0;
    bool found = false;
    if (!progress_meta_set(pdb, key, val, strlen(val))) return false;
    if (!progress_meta_get(pdb, key, got, sizeof(got), &len, &found) ||
        !found || len != strlen(val) || memcmp(got, val, len) != 0)
        return false;
    projection_store_tx_lock();
    char sql[128];
    snprintf(sql, sizeof(sql), "INSERT INTO mp_rt(g) VALUES(%d)", gen);
    bool ok = sqlite3_exec(jdb, sql, NULL, NULL, NULL) == SQLITE_OK;
    snprintf(sql, sizeof(sql), "SELECT count(*) FROM mp_rt WHERE g=%d", gen);
    ok = ok && mp_pragma(jdb, sql) == 1;
    ok = ok && mp_pragma(jdb, "SELECT count(*) FROM mp_rt") == gen + 1;
    projection_store_tx_unlock();
    return ok;
}

int test_storage_memory_profile(void);
int test_storage_memory_profile(void)
{
    printf("\n=== storage memory profile tests ===\n");
    int failures = 0;
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "storage_memory_profile", "main");

    MP_CHECK("stores open", progress_store_open(dir) &&
                            projection_store_open(dir));
    sqlite3 *pdb = progress_store_db();
    sqlite3 *jdb = projection_store_db();
    if (!pdb || !jdb) {
        MP_CHECK("handles present", false);
        return failures;
    }
    projection_store_tx_lock();
    MP_CHECK("fixture table", sqlite3_exec(jdb,
             "CREATE TABLE IF NOT EXISTS mp_rt(g INTEGER)", NULL, NULL,
             NULL) == SQLITE_OK);
    projection_store_tx_unlock();

    int64_t p_mmap0 = mp_pragma(pdb, "PRAGMA mmap_size");
    int64_t p_cache0 = mp_pragma(pdb, "PRAGMA cache_size");
    int64_t j_mmap0 = mp_pragma(jdb, "PRAGMA mmap_size");
    int64_t j_cache0 = mp_pragma(jdb, "PRAGMA cache_size");
    MP_CHECK("open is folding-sized (kernel mmap > steady cap)",
             p_mmap0 > STORAGE_STEADY_MMAP_BYTES && p_cache0 < 0);
    MP_CHECK("open is folding-sized (projection 256 MiB / 64 MiB)",
             j_mmap0 == 256LL * 1024 * 1024 &&
             j_cache0 == -(64LL * 1024));
    MP_CHECK("starts folding", !storage_memory_profile_is_steady());
    MP_CHECK("round trip at open", mp_roundtrip(pdb, jdb, 0));

    MP_CHECK("switch to steady", storage_memory_profile_set(true));
    MP_CHECK("is steady", storage_memory_profile_is_steady());
    MP_CHECK("kernel steady mmap == 64 MiB",
             mp_pragma(pdb, "PRAGMA mmap_size") == STORAGE_STEADY_MMAP_BYTES);
    MP_CHECK("kernel steady cache == min(open, 128 MiB)",
             mp_pragma(pdb, "PRAGMA cache_size") ==
             -storage_memory_profile_steady_cache_kib(-p_cache0));
    MP_CHECK("kernel steady cache <= 128 MiB",
             -mp_pragma(pdb, "PRAGMA cache_size") <= STORAGE_STEADY_CACHE_KIB);
    MP_CHECK("projection steady mmap == 64 MiB",
             mp_pragma(jdb, "PRAGMA mmap_size") == STORAGE_STEADY_MMAP_BYTES);
    MP_CHECK("projection steady cache never above folding",
             mp_pragma(jdb, "PRAGMA cache_size") == j_cache0);
    MP_CHECK("round trip steady", mp_roundtrip(pdb, jdb, 1));

    MP_CHECK("switch back to folding", storage_memory_profile_set(false));
    MP_CHECK("is folding", !storage_memory_profile_is_steady());
    MP_CHECK("kernel folding restored",
             mp_pragma(pdb, "PRAGMA mmap_size") == p_mmap0 &&
             mp_pragma(pdb, "PRAGMA cache_size") == p_cache0);
    MP_CHECK("projection folding restored",
             mp_pragma(jdb, "PRAGMA mmap_size") == j_mmap0 &&
             mp_pragma(jdb, "PRAGMA cache_size") == j_cache0);
    MP_CHECK("round trip folding again", mp_roundtrip(pdb, jdb, 2));

    projection_store_close();
    progress_store_close();
    MP_CHECK("set with stores closed is a no-op success",
             storage_memory_profile_set(true));
    storage_memory_profile_set(false);
    test_cleanup_tmpdir(dir);
    return failures;
}
