/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Offline wallet creation prepare, commit, and cancellation. */
#include "wallet_recovery_internal.h"
#include "services/wallet_create_service.h"
#include "core/random.h"
#include "models/wallet_key.h"
#include "support/cleanse.h"
#include "util/ar_step_readonly.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"
#include "wallet/mnemonic.h"
#include "wallet/wallet.h"
#include "wallet/wallet_lock.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#define WRC_TAG "wallet_recovery"


struct zcl_result wrc_creation_wallet_free_r(sqlite3 *db)
{
    sqlite3_stmt *s = NULL;
    const char *sql = "SELECT EXISTS(SELECT 1 FROM wallet_keys), EXISTS(SELECT 1 FROM wallet_seed), "
        "EXISTS(SELECT 1 FROM wallet_sapling_keys), EXISTS(SELECT 1 FROM wallet_sapling_notes), "
        "EXISTS(SELECT 1 FROM wallet_transactions), EXISTS(SELECT 1 FROM wallet_utxos)";
    if (sqlite3_prepare_v2(db, sql, -1, &s, NULL) != SQLITE_OK) return ZCL_ERR(-62, "cannot inspect creation wallet");
    bool ok = ar_step_checked(s, "wallet creation: read", NULL) == ZCL_STEP_ROW;
    for (int i = 0; ok && i < 6; i++)
        ok = sqlite3_column_type(s, i) == SQLITE_INTEGER && sqlite3_column_int(s, i) == 0;
    if (ok) ok = ar_step_checked(s, "wallet creation: read completion", NULL) == ZCL_STEP_DONE;
    if (sqlite3_finalize(s) != SQLITE_OK || !ok) return ZCL_ERR(-62, "creation wallet is not empty");
    return ZCL_OK;
}
static bool wrc_creation_journal_durable(sqlite3 *db)
{
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(db, "PRAGMA journal_mode", -1, &s, NULL) != SQLITE_OK) {
        LOG_WARN(WRC_TAG, "cannot inspect creation journal mode: %s", sqlite3_errmsg(db));
        return false;
    }
    bool ok = ar_step_checked(s, "wallet creation: read", NULL) == ZCL_STEP_ROW;
    const unsigned char *mode = ok ? sqlite3_column_text(s, 0) : NULL;
    ok = mode && (!strcmp((const char *)mode, "wal") ||
        !strcmp((const char *)mode, "delete") || !strcmp((const char *)mode, "truncate") ||
        !strcmp((const char *)mode, "persist"));
    if (ok) ok = ar_step_checked(s, "wallet creation: read completion", NULL) == ZCL_STEP_DONE;
    int rc = sqlite3_finalize(s);
    if (!ok || rc != SQLITE_OK) LOG_WARN(WRC_TAG, "creation journal mode unavailable or unsafe");
    return rc == SQLITE_OK && ok;
}

static bool wrc_creation_durable(sqlite3 *db)
{
    if (!wrc_creation_journal_durable(db)) return false; // raw-return-ok:callee-logs-journal-failure
    if (sqlite3_exec(db, "PRAGMA synchronous=FULL", NULL, NULL, NULL) != SQLITE_OK) {
        LOG_WARN(WRC_TAG, "cannot set durable creation synchronization: %s", sqlite3_errmsg(db));
        return false;
    }
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(db, "PRAGMA synchronous", -1, &s, NULL) != SQLITE_OK) return false;
    bool ok = ar_step_checked(s, "wallet creation: read", NULL) == ZCL_STEP_ROW && sqlite3_column_int(s, 0) >= 2 &&
        ar_step_checked(s, "wallet creation: read completion", NULL) == ZCL_STEP_DONE;
    return sqlite3_finalize(s) == SQLITE_OK && ok;
}

struct zcl_result wrc_creation_no_auxiliary_keys_r(sqlite3 *db)
{
    sqlite3_stmt *s = NULL;
    const char *sql = "SELECT (SELECT count(*) FROM wallet_watch_only), (SELECT count(*) FROM wallet_scripts)";
    if (sqlite3_prepare_v2(db, sql, -1, &s, NULL) != SQLITE_OK) return ZCL_ERR(-62, "cannot inspect creation wallet");
    bool ok = ar_step_checked(s, "wallet creation: read", NULL) == ZCL_STEP_ROW && sqlite3_column_int64(s, 0) == 0 &&
        sqlite3_column_int64(s, 1) == 0 && ar_step_checked(s, "wallet creation: read completion", NULL) == ZCL_STEP_DONE;
    if (sqlite3_finalize(s) != SQLITE_OK || !ok) return ZCL_ERR(-62, "creation wallet is not empty");
    return ZCL_OK;
}

static bool wrc_creation_no_dek(sqlite3 *db)
{
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(db, "SELECT count(*) FROM wallet_key_encryption", -1, &s, NULL) != SQLITE_OK) return false;
    bool ok = ar_step_checked(s, "wallet creation: read", NULL) == ZCL_STEP_ROW && sqlite3_column_int64(s, 0) == 0 &&
        ar_step_checked(s, "wallet creation: read completion", NULL) == ZCL_STEP_DONE;
    return sqlite3_finalize(s) == SQLITE_OK && ok;
}

static struct zcl_result wrc_creation_prepare_wallet(const char *datadir, char *phrase, uint8_t nonce[32],
    struct wrc_run *st, struct wallet_recovery_report *report, struct wallet_create_pending *pending)
{
    struct zcl_result rc = ZCL_OK;
    char words[MNEMONIC_MAX_PHRASE_SIZE] = {0};
    struct wallet *w = zcl_malloc(sizeof(*w), "wallet_creation.prepare");
    if (!w) { rc = ZCL_ERR(-64, "cannot allocate creation wallet"); return rc; }
    wallet_init(w); w->sapling_keys.follows_wallet_lock = false;
    rc = wallet_create_phrase(words, sizeof(words));
    if (rc.ok) rc = wrc_phrase_to_addresses(&(struct wallet_recovery_request){.phrase = words}, report);
    if (rc.ok && !wallet_init_from_recovery_phrase(w, words)) rc = ZCL_ERR(-64, "cannot derive creation wallet");
    if (rc.ok) rc = wrc_rebuild_keys(w, NULL, true, report);
    if (rc.ok && !wallet_scan_identity(w, pending->identity)) rc = ZCL_ERR(-64, "cannot identify creation wallet");
    struct wrc_floor floor;
    if (rc.ok) {
        wrc_birthday_floor(datadir, &st->ndb, &floor);
        pending->floor = floor.height;
        memcpy(pending->floor_hash, floor.hash, 32);
        GetRandBytes(pending->nonce, sizeof(pending->nonce));
        if (!db_wallet_create_pending_insert(&st->ndb, pending)) rc = ZCL_ERR(-65, "cannot persist creation preparation");
    }
    if (rc.ok) { memcpy(phrase, words, strlen(words) + 1); memcpy(nonce, pending->nonce, 32); }
    memory_cleanse(words, sizeof(words)); wallet_free(w); free(w);
    return rc;
}

static struct zcl_result wrc_creation_prepare_locked(const char *datadir, char *phrase, uint8_t nonce[32],
    struct wrc_run *st, struct wallet_recovery_report *report)
{
    struct zcl_result rc = ZCL_OK;
    struct wallet_create_pending pending = {0}, existing;
    if (!wrc_creation_durable(st->ndb.db) || !wrc_creation_no_auxiliary_keys_r(st->ndb.db).ok || !wrc_creation_no_dek(st->ndb.db) ||
        db_wallet_create_pending_get(&st->ndb, &existing) != WALLET_BIRTHDAY_PROOF_ABSENT) {
        rc = ZCL_ERR(-62, "wallet or unfinished creation already exists"); return rc;
    }
    rc = wrc_creation_prepare_wallet(datadir, phrase, nonce, st, report, &pending);
    return rc;
}

struct zcl_result wallet_creation_prepare(const char *datadir, char *phrase, size_t phrase_cap,
                                           uint8_t nonce[32])
{
    if (phrase && phrase_cap) memory_cleanse(phrase, phrase_cap);
    if (nonce) memory_cleanse(nonce, 32);
    if (!datadir || !datadir[0] || !phrase || phrase_cap < MNEMONIC_MAX_PHRASE_SIZE || !nonce)
        return ZCL_ERR(-60, "invalid creation prepare output or datadir");
    struct zcl_result rc = wallet_recovery_refuse_live_process();
    if (!rc.ok) return rc;
    struct wallet_recovery_request req = {.datadir = datadir, .record_birthday = true, .shielded_only = true};
    struct wallet_recovery_report report;
    if (strlen(datadir) + sizeof("/node.db") > sizeof(report.target_db))
        return ZCL_ERR(-59, "creation datadir path is too long");
    wrc_reset(&report, datadir);
    struct wrc_run st = {0}; st.wlock.fd = -1;
    rc = wrc_take_writer_lock(&req, &report, &st);
    if (!rc.ok) return rc;
    struct stat sb;
    report.target_created = stat(report.target_db, &sb) != 0;
    bool seeded = false;
    rc = wrc_inspect_and_open_target(&req, &report, &st, &seeded, true);
    if (!rc.ok) return rc;
    rc = wrc_creation_prepare_locked(datadir, phrase, nonce, &st, &report);
    wrc_run_release(&st);
    return rc;
}
static struct zcl_result wrc_creation_derive(const char *words, struct wallet **wallet_out,
    struct wallet_recovery_report *report, uint8_t identity[32])
{
    *wallet_out = NULL;
    struct wallet_recovery_request req = {.phrase = words, .record_birthday = true, .shielded_only = true};
    struct zcl_result rc = wrc_phrase_to_addresses(&req, report);
    if (!rc.ok) return rc;
    struct wallet *w = zcl_malloc(sizeof(*w), "wallet_creation.commit");
    if (!w) return ZCL_ERR(-64, "cannot allocate creation wallet");
    wallet_init(w); w->sapling_keys.follows_wallet_lock = false;
    if (!wallet_init_from_recovery_phrase(w, words)) rc = ZCL_ERR(-64, "cannot derive creation wallet");
    if (rc.ok) rc = wrc_rebuild_keys(w, NULL, true, report);
    if (rc.ok && !wallet_scan_identity(w, identity)) rc = ZCL_ERR(-64, "cannot identify creation wallet");
    if (!rc.ok) { wallet_free(w); free(w); return rc; }
    *wallet_out = w;
    return ZCL_OK;
}

static bool wrc_creation_key_matches(struct wallet_sqlite *ws, const struct wallet *expected)
{
    if (expected->sapling_keys.num_keys == 0) return false;
    struct wallet *loaded = zcl_malloc(sizeof(*loaded), "wallet_creation.verify");
    if (!loaded) return false;
    wallet_init(loaded);
    loaded->sapling_keys.follows_wallet_lock = false;
    bool ok = wallet_sqlite_read_sapling_keys(ws, loaded);
    bool found = false;
    const struct sapling_key_entry *want = &expected->sapling_keys.keys[0];
    for (size_t i = 0; ok && i < loaded->sapling_keys.num_keys; i++) {
        const struct sapling_key_entry *got = &loaded->sapling_keys.keys[i];
        if (!memcmp(got->ivk, want->ivk, sizeof(got->ivk))) {
            found = !got->secret_wiped &&
                !memcmp(&got->xsk, &want->xsk, sizeof(got->xsk)) &&
                !memcmp(&got->xfvk, &want->xfvk, sizeof(got->xfvk)) &&
                !memcmp(got->diversifier, want->diversifier, sizeof(got->diversifier)) &&
                !memcmp(got->pk_d, want->pk_d, sizeof(got->pk_d));
            break;
        }
    }
    wallet_free(loaded);
    free(loaded);
    return ok && found;
}

static struct zcl_result wrc_creation_verify_committed(
    const struct wallet_recovery_request *req, struct wrc_run *st,
    const struct wallet *w)
{
    bool loaded = false;
    struct zcl_result rc = wrc_load_passphrase(req, &loaded);
    uint8_t seed[32] = {0};
    if (rc.ok) {
        enum wallet_seed_state state = wallet_sqlite_sapling_seed_state(&st->ws, seed);
        if ((state != WALLET_SEED_PLAINTEXT && state != WALLET_SEED_UNLOCKED) ||
            !w->sapling_keys.has_seed || memcmp(seed, w->sapling_keys.seed, sizeof(seed)))
            rc = ZCL_ERR(-62, "committed creation seed cannot be verified");
    }
    memory_cleanse(seed, sizeof(seed));
    if (rc.ok && !wrc_creation_key_matches(&st->ws, w))
        rc = ZCL_ERR(-62, "committed creation spending key cannot be verified");
    if (loaded) wallet_lock_lock(NULL);
    return rc;
}

static struct zcl_result wrc_creation_commit_wallet(const struct wallet_recovery_request *req,
    struct wrc_run *st, struct wallet_recovery_report *report, struct wallet *w,
    struct wallet_create_pending *pending, const char *passphrase)
{
    struct zcl_result rc = ZCL_OK;
    if (pending->committed) {
        if (!wrc_wallet_present(report)) rc = ZCL_ERR(-62, "committed creation wallet is missing");
        else {
            rc = wrc_creation_verify_committed(req, st, w);
            if (rc.ok) report->creation_replayed = true;
        }
        return rc;
    }
    if (!wrc_creation_wallet_free_r(st->ndb.db).ok || !wrc_creation_no_auxiliary_keys_r(st->ndb.db).ok) {
        rc = ZCL_ERR(-62, "creation target already holds wallet material"); return rc;
    }
    rc = wrc_at_rest_gate(passphrase);
    if (!rc.ok) return rc;
    report->creation_write_attempted = true;
    rc = wrc_swap_to_write_handle(report, st);
    if (!rc.ok) return rc;
    if (!wrc_creation_durable(st->ndb.db)) { rc = ZCL_ERR(-65, "cannot establish durable creation commit"); return rc; }
    bool loaded = false;
    rc = wrc_load_passphrase(req, &loaded);
    if (rc.ok) {
        wrc_settle_birthday(req, &st->ndb, w, false, report);
        rc = wallet_sqlite_flush_created_r(&st->ws, w, &st->ndb, pending);
    }
    if (loaded) wallet_lock_lock(w);
    return rc;
}

static struct zcl_result wrc_creation_commit_locked(const struct wallet_recovery_request *req,
    struct wrc_run *st, struct wallet_recovery_report *report, const char *words,
    const uint8_t nonce[32], const char *passphrase)
{
    struct zcl_result rc = ZCL_OK;
    struct wallet_create_pending pending;
    if (db_wallet_create_pending_get(&st->ndb, &pending) != WALLET_BIRTHDAY_PROOF_FOUND ||
        memcmp(pending.nonce, nonce, 32)) { rc = ZCL_ERR(-62, "creation preparation does not match"); return rc; }
    struct wallet *w = NULL;
    uint8_t identity[32];
    rc = wrc_creation_derive(words, &w, report, identity);
    if (!rc.ok) return rc;
    if (memcmp(identity, pending.identity, 32)) { rc = ZCL_ERR(-62, "creation phrase does not match preparation"); goto wallet_done; }
    rc = wrc_creation_commit_wallet(req, st, report, w, &pending, passphrase);
wallet_done:
    wallet_free(w); free(w);
    return rc;
}

struct zcl_result wallet_creation_commit(const char *datadir, const char *words,
    const uint8_t nonce[32], const char *passphrase, struct wallet_recovery_report *out)
{
    if (out) memset(out, 0, sizeof(*out));
    if (!datadir || !datadir[0] || !words || !nonce) return ZCL_ERR(-60, "invalid creation commit input");
    struct zcl_result rc = wallet_recovery_refuse_live_process();
    if (!rc.ok) return rc;
    struct wallet_recovery_request req = {.datadir = datadir, .phrase = words, .passphrase = passphrase,
        .record_birthday = true, .shielded_only = true};
    rc = wrc_check_request(&req);
    if (!rc.ok) return rc;
    struct wallet_recovery_report report;
    if (strlen(datadir) + sizeof("/node.db") > sizeof(report.target_db)) return ZCL_ERR(-59, "creation datadir path is too long");
    wrc_reset(&report, datadir);
    struct wrc_run st = {0}; st.wlock.fd = -1;
    rc = wrc_take_writer_lock(&req, &report, &st);
    if (!rc.ok) return rc;
    rc = wrc_open_existing_target_ro(&req, &report, &st);
    if (!rc.ok) return rc;
    rc = wrc_read_existing_wallet_facts(&report, &st);
    if (!rc.ok) { wrc_run_release(&st); return rc; }
    rc = wrc_creation_commit_locked(&req, &st, &report, words, nonce, passphrase);
    if (out) { if (rc.ok) report.seed_installed = true; *out = report; }
    wrc_run_release(&st);
    return rc;
}

static struct zcl_result wrc_creation_cancel_locked(struct wrc_run *st,
    struct wallet_recovery_report *report, const uint8_t nonce[32])
{
    struct zcl_result rc = ZCL_OK;
    struct wallet_create_pending pending;
    if (db_wallet_create_pending_get(&st->ndb, &pending) != WALLET_BIRTHDAY_PROOF_FOUND ||
        pending.committed || memcmp(pending.nonce, nonce, 32) || !wrc_creation_wallet_free_r(st->ndb.db).ok ||
        !wrc_creation_no_auxiliary_keys_r(st->ndb.db).ok || !wrc_creation_no_dek(st->ndb.db)) {
        rc = ZCL_ERR(-62, "creation preparation cannot be canceled"); return rc;
    }
    rc = wrc_swap_to_write_handle(report, st);
    if (rc.ok && !wrc_creation_durable(st->ndb.db)) rc = ZCL_ERR(-65, "cannot establish durable cancellation");
    if (rc.ok && !db_wallet_create_pending_cancel(&st->ndb, &pending))
        rc = ZCL_ERR(-65, "creation preparation cancellation failed");
    return rc;
}

struct zcl_result wallet_creation_cancel(const char *datadir, const uint8_t nonce[32])
{
    if (!datadir || !datadir[0] || !nonce) return ZCL_ERR(-60, "invalid creation cancel input");
    struct zcl_result rc = wallet_recovery_refuse_live_process();
    if (!rc.ok) return rc;
    struct wallet_recovery_request req = {.datadir = datadir};
    struct wallet_recovery_report report;
    if (strlen(datadir) + sizeof("/node.db") > sizeof(report.target_db)) return ZCL_ERR(-59, "creation datadir path is too long");
    wrc_reset(&report, datadir);
    struct wrc_run st = {0}; st.wlock.fd = -1;
    rc = wrc_take_writer_lock(&req, &report, &st);
    if (!rc.ok) return rc;
    rc = wrc_open_existing_target_ro(&req, &report, &st);
    if (!rc.ok) return rc;
    rc = wrc_read_existing_wallet_facts(&report, &st);
    if (!rc.ok) { wrc_run_release(&st); return rc; }
    rc = wrc_creation_cancel_locked(&st, &report, nonce);
    wrc_run_release(&st);
    return rc;
}
