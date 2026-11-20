/* Copyright 2026 Rhett Creighton - Apache License 2.0 */
#include "wallet_recovery_coverage.h"
#include "wallet_recovery_internal.h"
#include "wallet/wallet.h"
#include "wallet/keystore.h"
#include "util/safe_alloc.h"
#include "util/ar_step_readonly.h"
#include <sqlite3.h>
#include <stdlib.h>
#include <string.h>

static bool coverage_counts(sqlite3 *db, int64_t counts[4])
{
    const char *sql = "SELECT (SELECT count(*) FROM wallet_keys),"
        "(SELECT count(*) FROM wallet_sapling_keys),"
        "(SELECT count(*) FROM wallet_scripts),"
        "(SELECT count(*) FROM wallet_watch_only)";
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &s, NULL) != SQLITE_OK || !s) {
        sqlite3_finalize(s);
        return false;
    }
    bool ok = ar_step_checked(s, "coverage counts", NULL) == ZCL_STEP_ROW;
    if (ok) for (int i = 0; i < 4; i++) {
        counts[i] = sqlite3_column_int64(s, i);
        if (sqlite3_column_type(s, i) != SQLITE_INTEGER || counts[i] < 0) ok = false;
    }
    if (ok) ok = ar_step_checked(s, "coverage counts", NULL) == ZCL_STEP_DONE;
    if (sqlite3_finalize(s) != SQLITE_OK) ok = false;
    return ok;
}

static bool coverage_transparent_rows(sqlite3 *db, const struct wallet *old)
{
    sqlite3_stmt *s = NULL;
    const char *sql = "SELECT pubkey_hash,pubkey,compressed FROM wallet_keys";
    if (sqlite3_prepare_v2(db, sql, -1, &s, NULL) != SQLITE_OK || !s) {
        sqlite3_finalize(s);
        return false;
    }
    bool ok = true;
    enum zcl_step step;
    while ((step = ar_step_checked(s, "coverage transparent", NULL)) == ZCL_STEP_ROW) {
        int len = sqlite3_column_bytes(s, 1);
        const unsigned char *hash = sqlite3_column_blob(s, 0);
        const unsigned char *stored = sqlite3_column_blob(s, 1);
        int64_t compressed = sqlite3_column_int64(s, 2);
        if (sqlite3_column_type(s, 0) != SQLITE_BLOB || sqlite3_column_bytes(s, 0) != 20 ||
            sqlite3_column_type(s, 1) != SQLITE_BLOB || !hash || !stored ||
            sqlite3_column_type(s, 2) != SQLITE_INTEGER ||
            !((len == 33 && compressed == 1) || (len == 65 && compressed == 0))) {
            ok = false;
            break;
        }
        struct pubkey pk = {0}, actual = {0};
        pubkey_set(&pk, stored, (unsigned int)len);
        struct key_id id = pubkey_get_id(&pk);
        if (memcmp(hash, id.id.data, 20) ||
            !keystore_get_pubkey(&old->keystore, &id, &actual) ||
            actual.size != pk.size || memcmp(actual.vch, pk.vch, pk.size)) {
            ok = false;
            break;
        }
    }
    if (step != ZCL_STEP_DONE) ok = false;
    if (sqlite3_finalize(s) != SQLITE_OK) ok = false;
    return ok;
}


struct coverage_public {
    struct key_id transparent[MAX_KEYSTORE_KEYS];
    struct zip32_xfvk shielded[MAX_SAPLING_KEYS];
    size_t transparent_count, shielded_count;
};

static void coverage_collect(struct coverage_public *pub, const struct wallet *w)
{
    for (size_t i = 0; i < MAX_KEYSTORE_KEYS; i++)
        if (w->keystore.keys[i].used)
            pub->transparent[pub->transparent_count++] = w->keystore.keys[i].keyid;
    for (size_t i = 0; i < MAX_SAPLING_KEYS; i++)
        if (w->sapling_keys.keys[i].used)
            pub->shielded[pub->shielded_count++] = w->sapling_keys.keys[i].xfvk;
}

static bool coverage_xfvk_equal(const struct zip32_xfvk *a,
                                const struct zip32_xfvk *b)
{
    return a->depth == b->depth && a->parent_fvk_tag == b->parent_fvk_tag &&
        a->child_index == b->child_index &&
        memcmp(a->chain_code, b->chain_code, sizeof(a->chain_code)) == 0 &&
        memcmp(&a->fvk, &b->fvk, sizeof(a->fvk)) == 0 &&
        memcmp(a->dk, b->dk, sizeof(a->dk)) == 0;
}

static bool coverage_contains_keys(const struct coverage_public *pub,
                                   const struct wallet *rebuilt)
{
    for (size_t i = 0; i < pub->transparent_count; i++)
        if (!keystore_have_key(&rebuilt->keystore, &pub->transparent[i]))
            return false;
    for (size_t i = 0; i < pub->shielded_count; i++) {
        bool found = false;
        for (size_t j = 0; j < MAX_SAPLING_KEYS; j++) {
            const struct sapling_key_entry *other = &rebuilt->sapling_keys.keys[j];
            if (other->used && coverage_xfvk_equal(&pub->shielded[i], &other->xfvk)) {
                found = true;
                break;
            }
        }
        if (!found) return false;
    }
    return true;
}

enum wrc_coverage wrc_recovery_coverage(struct wallet_sqlite *ws, struct wallet *old,
                                        const uint8_t seed[32])
{
    if (!ws || !ws->open || !old || !seed || old->keystore.num_keys || old->sapling_keys.num_keys) return WRC_COVERAGE_UNKNOWN;
    int64_t counts[4] = {0};
    sqlite3_mutex *mu = sqlite3_db_mutex(ws->db);
    if (!mu) return WRC_COVERAGE_UNKNOWN;
    sqlite3_mutex_enter(mu);
    if (!sqlite3_get_autocommit(ws->db)) {
        sqlite3_mutex_leave(mu);
        return WRC_COVERAGE_UNKNOWN;
    }
    if (sqlite3_exec(ws->db, "BEGIN", NULL, NULL, NULL) != SQLITE_OK) {
        if (!sqlite3_get_autocommit(ws->db)) (void)sqlite3_exec(ws->db, "ROLLBACK", NULL, NULL, NULL);
        if (!sqlite3_get_autocommit(ws->db)) abort();
        sqlite3_mutex_leave(mu);
        return WRC_COVERAGE_UNKNOWN;
    }
    if (!coverage_counts(ws->db, counts)) {
        (void)sqlite3_exec(ws->db, "ROLLBACK", NULL, NULL, NULL);
        if (!sqlite3_get_autocommit(ws->db)) abort();
        sqlite3_mutex_leave(mu);
        return WRC_COVERAGE_UNKNOWN;
    }
    struct coverage_public *pub = zcl_calloc(1, sizeof(*pub), "coverage.public");
    if (!pub) {
        (void)sqlite3_exec(ws->db, "ROLLBACK", NULL, NULL, NULL);
        if (!sqlite3_get_autocommit(ws->db)) abort();
        sqlite3_mutex_leave(mu);
        return WRC_COVERAGE_UNKNOWN;
    }
    enum wrc_coverage result = WRC_COVERAGE_UNKNOWN;
    if (!wallet_sqlite_read_keys_r(ws, old).ok ||
        !wallet_sqlite_read_sapling_keys(ws, old) ||
        counts[0] != (int64_t)old->keystore.num_keys ||
        counts[1] != (int64_t)old->sapling_keys.num_keys ||
        keystore_num_sealed(&old->keystore) || old->sapling_keys.num_damaged ||
        old->sapling_keys.num_unscannable) goto done;
    zcl_mutex_lock(&old->sapling_keys.cs);
    bool sapling_ok = wallet_sqlite_verify_startup_sapling_in_tx_locked_r(ws, old, ws->db).ok;
    zcl_mutex_unlock(&old->sapling_keys.cs);
    if (!sapling_ok || !old->sapling_keys.has_seed ||
        memcmp(seed, old->sapling_keys.seed, 32) ||
        !coverage_transparent_rows(ws->db, old)) goto done;
    for (size_t i = 0; i < MAX_SAPLING_KEYS; i++)
        if (old->sapling_keys.keys[i].used && old->sapling_keys.keys[i].secret_wiped)
            goto done;
    if (counts[2] || counts[3]) { result = WRC_COVERAGE_INCOMPLETE; goto done; }
    coverage_collect(pub, old);
    result = WRC_COVERAGE_COMPLETE;
done:
    if (sqlite3_exec(ws->db, "COMMIT", NULL, NULL, NULL) != SQLITE_OK) {
        result = WRC_COVERAGE_UNKNOWN;
        if (!sqlite3_get_autocommit(ws->db)) (void)sqlite3_exec(ws->db, "ROLLBACK", NULL, NULL, NULL);
    }
    if (!sqlite3_get_autocommit(ws->db)) abort();
    sqlite3_mutex_leave(mu);
    if (result == WRC_COVERAGE_COMPLETE) {
        wallet_free(old);
        wallet_init(old);
        struct wallet_recovery_report report = {0};
        if (!wallet_init_hd(old, seed, 32) ||
            !sapling_keystore_set_seed(&old->sapling_keys, seed) ||
            !wrc_rebuild_keys(old, NULL, false, &report).ok)
            result = WRC_COVERAGE_UNKNOWN;
        else if (!coverage_contains_keys(pub, old))
            result = WRC_COVERAGE_INCOMPLETE;
    }
    free(pub);
    return result;
}
