/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * SQLite-backed wallet storage. Replaces wallet_db (LevelDB) for runtime.
 * Uses node.db's wallet_keys, wallet_sapling_keys, wallet_scripts,
 * wallet_seed, wallet_watch_only, and wallet_transactions tables.
 *
 * Two parallel APIs:
 *   - New rich-error primary:  *_r functions return `struct zcl_result`.
 *     Use these in new code.
 *   - Legacy bool wrappers:    the original `bool`-returning names are
 *     kept as thin wrappers that call the *_r implementation and
 *     LOG_FAIL on non-ok. Marked ZCL_DEPRECATED; migrate callers
 *     incrementally.
 *
 * Current deviation from the canonical §5.2 signatures (bare names
 * returning zcl_result) is transitional — controller work will migrate
 * callers, after which the bool wrappers can be dropped and the *_r
 * suffix removed. */

#ifndef ZCL_WALLET_SQLITE_H
#define ZCL_WALLET_SQLITE_H

#include "wallet/wallet.h"
#include "wallet/sapling_keys.h"
#include "script/script.h"
#include "core/uint256.h"
#include "util/result.h"
#include <sqlite3.h>
#include <stdbool.h>
#include <stdint.h>

/* Tag transitional bool wrappers so the compiler nudges callers to
 * the rich-error variant. */
#ifndef ZCL_DEPRECATED
#  if defined(__GNUC__) || defined(__clang__)
#    define ZCL_DEPRECATED(msg) __attribute__((deprecated(msg)))
#  else
#    define ZCL_DEPRECATED(msg)
#  endif
#endif

/* Error codes for the wallet_sqlite layer.  Negative to avoid colliding
 * with SQLITE_* which use small positive ints.  Keep in sync with
 * plan §5.2. */
enum wallet_sqlite_err {
    WSQL_OK                      = 0,
    WSQL_NULL_ARG                = -100,
    WSQL_DB_NOT_OPEN             = -101,
    WSQL_ALREADY_OPEN            = -102,
    WSQL_PREPARE_FAIL            = -103,
    WSQL_SCHEMA_MISSING          = -104,
    WSQL_CANARY_WRITE_FAIL       = -110,
    WSQL_CANARY_READ_MISMATCH    = -111,
    WSQL_WRITE_FAIL              = -120,
    WSQL_READ_FAIL               = -121,
    WSQL_TXN_BEGIN_FAIL          = -130,
    WSQL_TXN_COMMIT_FAIL         = -131,
    WSQL_INVARIANT_PUBKEY        = -140,
    WSQL_INVARIANT_PRIVKEY       = -141,
    WSQL_INVARIANT_HASH_MISMATCH = -142,
};

/* Aggregate health snapshot.  Non-destructive; safe from any thread
 * that has already published a wallet_sqlite struct. */
struct wallet_sqlite_health {
    bool    open;                    /* subsystem open */
    bool    canary_ok;               /* last self-test passed */
    int64_t canary_last_ok_ts;       /* unix time of last success */
    int     row_count;               /* SELECT count(*) FROM wallet_keys */
    int     keystore_count;          /* caller-supplied in-memory count */
    bool    mismatch;                /* row_count != keystore_count */
    char    last_error[ZCL_RESULT_MSG_MAX];  /* most recent failed call */
};

struct wallet_sqlite {
    sqlite3 *db;  /* borrowed handle to node.db */
    bool open;

    /* Prepared statements */
    sqlite3_stmt *stmt_key_write;
    sqlite3_stmt *stmt_key_read;
    sqlite3_stmt *stmt_key_read_one;   /* SELECT ... WHERE pubkey_hash = ? */
    sqlite3_stmt *stmt_key_delete;     /* DELETE ... WHERE pubkey_hash = ? */
    sqlite3_stmt *stmt_keypool_write;
    sqlite3_stmt *stmt_keypool_read;
    sqlite3_stmt *stmt_keypool_clear;
    sqlite3_stmt *stmt_tx_write;
    sqlite3_stmt *stmt_tx_read;
    sqlite3_stmt *stmt_seed_write;
    sqlite3_stmt *stmt_seed_read;
    sqlite3_stmt *stmt_zkey_write;
    sqlite3_stmt *stmt_zkey_read;
    sqlite3_stmt *stmt_script_write;
    sqlite3_stmt *stmt_script_read;
    sqlite3_stmt *stmt_watch_write;
    sqlite3_stmt *stmt_watch_read;

    /* Best-block and scan-height pointers live in node_state under
     * fixed keys.  Cached so hot paths (every post-block flush,
     * every rescan step) don't pay prepare+finalize per call. */
    sqlite3_stmt *stmt_best_block_write;
    sqlite3_stmt *stmt_best_block_read;
    sqlite3_stmt *stmt_scan_height_write;
    sqlite3_stmt *stmt_scan_height_read;

    /* Health bookkeeping. Updated by self-test and by every failed
     * public call.  Read by wallet_sqlite_get_health(). */
    bool    canary_ok;
    int64_t canary_last_ok_ts;
    char    last_error[ZCL_RESULT_MSG_MAX];
};

/* ── Rich-error API (preferred) ─────────────────────────────────── */

/* Rows dropped by wallet_sqlite_read_keys_r since process start.
 * Surfaces in getwalletinfo.persistence.corrupt_rows so operators
 * see decode/decrypt drift instead of learning about it when a
 * spend fails.  Reset only by process restart. */
int wallet_sqlite_read_keys_corrupt_count(void);

/* Zero *ws, adopt the borrowed db handle, and prepare every cached
 * statement. To reopen, wallet_sqlite_close() first. Returns ZCL_OK on
 * success; WSQL_NULL_ARG if ws or db is NULL; on a prepare failure the
 * partially-opened handle is closed and the prepare error is returned
 * (and recorded in ws->last_error). */
struct zcl_result wallet_sqlite_open_r(struct wallet_sqlite *ws, sqlite3 *db);
/* Round-trip a unique probe blob through node_state under the canary key
 * (INSERT, SELECT-back, then DELETE) to prove the DB is writable and
 * readable. On success sets ws->canary_ok/canary_last_ok_ts and returns
 * ZCL_OK. Returns WSQL_NULL_ARG if ws is NULL, WSQL_DB_NOT_OPEN if not
 * open, or a prepare/write/read-mismatch error (recorded in
 * ws->last_error). */
struct zcl_result wallet_sqlite_self_test(struct wallet_sqlite *ws);
/* Load every row of wallet_keys into w->keystore (decrypting legacy WKS1 or
 * wrapped-DEK WKD1 envelopes). Malformed or undecryptable rows are skipped, counted via
 * wallet_sqlite_read_keys_corrupt_count(), and do not fail the call.
 * Returns ZCL_OK once all rows are consumed; WSQL_NULL_ARG if ws or w is
 * NULL, WSQL_DB_NOT_OPEN if not open, or WSQL_READ_FAIL on a step error. */
struct zcl_result wallet_sqlite_read_keys_r(struct wallet_sqlite *ws,
                                             struct wallet *w);
struct zcl_result wallet_sqlite_read_keypool_r(struct wallet_sqlite *ws,
                                                struct wallet *w);
/* Read the single wallet_keys row whose pubkey_hash matches pk and
 * decode/decrypt its private key into *out_key. Returns ZCL_OK and fills
 * out_key on success; WSQL_NULL_ARG if ws/pk/out_key is NULL,
 * WSQL_DB_NOT_OPEN if not open, or WSQL_READ_FAIL if the key is absent,
 * the privkey column is too short, or decryption fails. */
struct zcl_result wallet_sqlite_read_single_key(struct wallet_sqlite *ws,
                                                const struct pubkey *pk,
                                                struct privkey *out_key);
/* Upsert one wallet_keys row (pubkey_hash, pubkey, privkey, compressed),
 * encrypting the privkey blob when wallet encryption is active. Returns
 * ZCL_OK on success; WSQL_NULL_ARG if ws is NULL, WSQL_DB_NOT_OPEN if not
 * open, a WSQL_INVARIANT_* error if pk/key fail validation, or
 * WSQL_WRITE_FAIL on a step error (recorded in ws->last_error). */
struct zcl_result wallet_sqlite_write_key_r(struct wallet_sqlite *ws,
                                            const struct pubkey *pk,
                                            const struct privkey *key);
/* Delete the wallet_keys row whose pubkey_hash matches pk. Succeeds
 * (ZCL_OK) even if no row matched. Returns WSQL_NULL_ARG if ws or pk is
 * NULL, WSQL_DB_NOT_OPEN if not open, or WSQL_WRITE_FAIL on a step error. */
struct zcl_result wallet_sqlite_delete_key_r(struct wallet_sqlite *ws,
                                             const struct pubkey *pk);
/* Persist the in-memory wallet to node.db inside one transaction: all
 * keystore keys, wallet transactions, the Sapling seed and keys, redeem
 * scripts, and the scan height. Holds w->cs across the writes. On the
 * first writer failure the whole transaction is rolled back and a
 * WSQL_WRITE_FAIL result describing the first failure is returned (so
 * persistence is all-or-nothing). Also returns WSQL_NULL_ARG if ws or w
 * is NULL, WSQL_DB_NOT_OPEN if not open, or WSQL_TXN_*_FAIL on
 * BEGIN/COMMIT failure. */
struct zcl_result wallet_sqlite_flush_r(struct wallet_sqlite *ws,
                                        struct wallet *w);
/* Persist mutable wallet transaction rows and the scan-height cursor without
 * rewriting immutable key/seed/script material.  This is the pre-relay hot
 * path after builders have already proven any consumed change key durable;
 * full-state checkpoints, key creation, recovery, and repair continue to use
 * wallet_sqlite_flush_r(). */
struct zcl_result wallet_sqlite_flush_transactions_r(
    struct wallet_sqlite *ws, struct wallet *w);

/* Test-only override for the flush BEGIN IMMEDIATE time budget (see
 * WALLET_FLUSH_BEGIN_BUDGET_MS in wallet_sqlite.c). Production never calls
 * this; the persistence tests shrink the budget so a contended flush fails
 * in milliseconds instead of waiting out the full production window.
 * Passing ms <= 0 restores the production default. */
void wallet_sqlite_flush_set_begin_budget_ms(int64_t ms);
/* One-time migration scrub for datadirs that hold PLAINTEXT secret rows
 * (written before at-rest encryption was configured, or by the deleted
 * plaintext mirror writer). When a passphrase is configured, upgrades
 * wallet_keys.privkey to a fast WKD1 envelope under one passphrase-wrapped
 * wallet DEK, while wallet_sapling_keys.xsk and wallet_seed.seed retain WKS1.
 * Byte content is preserved and nothing is deleted. No-op without a passphrase — raw 32-byte
 * secrets are the legitimate format for an unencrypted wallet.  Runs
 * inside one BEGIN IMMEDIATE transaction; any failure rolls back and
 * returns a WSQL_* error.  Idempotent. */
struct zcl_result wallet_sqlite_scrub_plaintext_r(struct wallet_sqlite *ws);
/* Rewrite loaded transparent keys under WKD1 in one transaction. This is the
 * one-time bridge from legacy WKS1 without paying its KDF twice: boot first
 * decrypts those rows into `w`, then this function persists the same keys
 * under the wallet DEK before the residual scrub handles unloaded rows. */
struct zcl_result wallet_sqlite_migrate_transparent_keys_r(
    struct wallet_sqlite *ws, struct wallet *w);
/* Return a non-destructive health snapshot: open/canary state, the live
 * SELECT COUNT(*) FROM wallet_keys row_count, the caller-supplied
 * keystore_count, their mismatch flag, and the last recorded error. If
 * ws is NULL the snapshot is zeroed with last_error set to a NULL-pointer
 * message. Safe to call from any thread that holds a published ws. */
struct wallet_sqlite_health
    wallet_sqlite_get_health(struct wallet_sqlite *ws, int keystore_count);

/* ── Legacy bool API (deprecated wrappers) ──────────────────────── */

ZCL_DEPRECATED("use wallet_sqlite_open_r for richer errors")
bool wallet_sqlite_open(struct wallet_sqlite *ws, sqlite3 *db);

void wallet_sqlite_close(struct wallet_sqlite *ws);

ZCL_DEPRECATED("use wallet_sqlite_write_key_r")
bool wallet_sqlite_write_key(struct wallet_sqlite *ws, const struct pubkey *pk,
                              const struct privkey *key);
ZCL_DEPRECATED("use wallet_sqlite_read_keys_r")
bool wallet_sqlite_read_keys(struct wallet_sqlite *ws, struct wallet *w);

bool wallet_sqlite_write_tx(struct wallet_sqlite *ws,
                              const struct wallet_tx *wtx);
bool wallet_sqlite_read_txs(struct wallet_sqlite *ws, struct wallet *w);

bool wallet_sqlite_write_scan_height(struct wallet_sqlite *ws, int height);
bool wallet_sqlite_read_scan_height(struct wallet_sqlite *ws, int *height);

bool wallet_sqlite_write_sapling_seed(struct wallet_sqlite *ws,
                                        const uint8_t seed[32]);

/* ── Seed presence, told apart from seed readability ────────────────
 *
 * wallet_sqlite_read_sapling_seed() answers bool, and that collapsed two
 * opposite facts into one value: "this wallet has no seed" and "this
 * wallet has a seed I cannot decrypt" both came back false. A caller
 * asking "can this wallet be rebuilt from its recovery phrase?" then told
 * the owner of an ENCRYPTED, phrase-backed wallet that their wallet
 * predates recovery phrases and their money can only be restored from a
 * file — when the truth was that they needed to unlock it first. The same
 * collapse also let a recovery overwrite the seed row of a locked wallet,
 * because "no seed present" is the condition that permits the write.
 *
 * Use this when the difference matters. LOCKED is not an empty result and
 * must never be reported as one. */
enum wallet_seed_state {
    WALLET_SEED_ABSENT = 0,   /* no wallet_seed row: no seed was ever stored */
    WALLET_SEED_PLAINTEXT,    /* row present, stored unencrypted, read out */
    WALLET_SEED_UNLOCKED,     /* row present, encrypted, decrypted fine */
    WALLET_SEED_LOCKED,       /* row present, encrypted, WRONG/NO passphrase */
    WALLET_SEED_MALFORMED,    /* row present but not a usable 32-byte seed */
    WALLET_SEED_UNREADABLE,   /* the wallet_sqlite handle is not open */
};

/* True when the seed row exists at all — i.e. everything except ABSENT and
 * UNREADABLE. This, not "did the read succeed", is the question a writer
 * must ask before installing a seed over an existing wallet. */
static inline bool wallet_seed_state_row_present(enum wallet_seed_state s)
{
    return s == WALLET_SEED_PLAINTEXT || s == WALLET_SEED_UNLOCKED
        || s == WALLET_SEED_LOCKED || s == WALLET_SEED_MALFORMED;
}

/* Read the seed row and say exactly what was found. `seed` is written only
 * on PLAINTEXT and UNLOCKED; on every other state it is left untouched, so
 * the caller cannot mistake a stale buffer for a recovered seed. */
enum wallet_seed_state wallet_sqlite_sapling_seed_state(
        struct wallet_sqlite *ws, uint8_t seed[32]);

/* Legacy shape: true exactly when the state is PLAINTEXT or UNLOCKED.
 * Prefer wallet_sqlite_sapling_seed_state() anywhere the answer is shown
 * to a user or gates a write. */
bool wallet_sqlite_read_sapling_seed(struct wallet_sqlite *ws,
                                       uint8_t seed[32]);
bool wallet_sqlite_write_sapling_key(struct wallet_sqlite *ws,
                                       uint32_t child_index,
                                       const struct sapling_key_entry *entry);
bool wallet_sqlite_read_sapling_keys(struct wallet_sqlite *ws,
                                       struct wallet *w);

bool wallet_sqlite_write_script(struct wallet_sqlite *ws,
                                  const struct uint160 *script_id,
                                  const struct script *redeem_script);
bool wallet_sqlite_read_scripts(struct wallet_sqlite *ws, struct wallet *w);

bool wallet_sqlite_write_watch_only(struct wallet_sqlite *ws,
                                      const uint8_t address_hash[20],
                                      const char *address);
bool wallet_sqlite_read_watch_only(struct wallet_sqlite *ws, struct wallet *w);

ZCL_DEPRECATED("use wallet_sqlite_flush_r")
bool wallet_sqlite_flush(struct wallet_sqlite *ws, struct wallet *w);

#endif
