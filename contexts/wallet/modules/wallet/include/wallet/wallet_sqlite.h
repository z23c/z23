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

/* Encrypted rows the last read_keys_r skipped because no passphrase was
 * loaded. A wallet booted locked has these on disk and in no keystore; they
 * are sealed, not corrupt, and are excluded from corrupt_rows. */
int wallet_sqlite_read_keys_locked_count(void);

/* Verdict of wallet_sqlite_check_passphrase(). */
enum wallet_passphrase_check {
    WALLET_PASS_OK,          /* at least one sealed row opened with it */
    WALLET_PASS_WRONG,       /* sealed rows exist and none opened */
    WALLET_PASS_NO_SEALED,   /* nothing on disk is sealed: nothing to check */
    WALLET_PASS_UNREADABLE   /* the database could not be read */
};

/* Test `passphrase` against the sealed rows on disk without touching any
 * wallet or lock state: the wrapped data key, the seed row, the Sapling
 * spending-key rows and legacy passphrase-wrapped transparent rows. One row
 * that opens is proof; damaged rows do not turn a right passphrase into a
 * wrong one. Reads only, never writes, never caches. */
enum wallet_passphrase_check wallet_sqlite_check_passphrase(
    struct wallet_sqlite *ws, const char *passphrase);

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
struct node_db;
struct wallet_create_pending;
#ifdef ZCL_TESTING
void wallet_sqlite_creation_exit_before_commit_for_test(void);
#endif

struct zcl_result wallet_sqlite_flush_created_r(struct wallet_sqlite *ws, struct wallet *w,
    struct node_db *ndb, const struct wallet_create_pending *pending);
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

enum wallet_height_encoding { WALLET_HEIGHT_ERROR, WALLET_HEIGHT_LEGACY, WALLET_HEIGHT_V2 };
/* Strictly read the height encoding and its paired depth reference. */
enum wallet_height_encoding wallet_sqlite_height_encoding(
    struct wallet_sqlite *ws, int *reference_height);
typedef bool (*wallet_height_resolver)(void *ctx, const uint8_t block_hash[32], int *height);
/* Requires the caller-owned open write transaction and stable verified chain.
 * Resolver must not acquire locks or perform writes; false refuses transition.
 * Caller commits or rolls back, including any partial rewrites on failure. */
bool wallet_sqlite_activate_height_v2_in_open_tx(
    struct wallet_sqlite *ws, int reference_height, wallet_height_resolver resolve, void *ctx);

bool wallet_sqlite_write_tx(struct wallet_sqlite *ws,
                              const struct wallet_tx *wtx);
bool wallet_sqlite_read_txs(struct wallet_sqlite *ws, struct wallet *w);

bool wallet_sqlite_write_scan_height(struct wallet_sqlite *ws, int height);
bool wallet_sqlite_read_scan_height(struct wallet_sqlite *ws, int *height);

/* Scan state. node_state 'wallet_scan_height' holds the height through which
 * every block was read (wallet_scanned_through_height()), and
 * 'wallet_scan_incomplete' exists only while a boot catch-up's range is
 * unread. The flush calls the write inside its transaction with w->cs held,
 * so the marker is cleared only with the tx rows its rescan found. The state
 * read loads both into `w`, restoring best_block_height to the marker's depth
 * height, and returns true when a scan height row exists. The marker read
 * returns true when the row exists; an unparseable row reads as incomplete
 * from height 0 under WALLET_SCAN_MARKER_UNREADABLE. */
struct wallet_scan_marker {
    int from;             /* lowest height not yet fully read */
    int depth_height;     /* best_block_height at the flush; -1 if unknown */
    int64_t since;        /* unix time the marker was first set */
    char blocker[48];     /* WALLET_RESCAN_BLOCKER_* name */
};
bool wallet_sqlite_write_scan_state(struct wallet_sqlite *ws,
                                    const struct wallet *w);
enum wallet_scan_state_status { WALLET_SCAN_STATE_ABSENT, WALLET_SCAN_STATE_OK, WALLET_SCAN_STATE_ERROR };
enum wallet_scan_state_status wallet_sqlite_validate_scan_state(struct wallet_sqlite *ws);
/* Strict startup read; ABSENT means no cursor or marker. The helper owns
 * a serialized read snapshot and refuses pre-existing transactions. */
enum wallet_scan_state_status wallet_sqlite_read_scan_state_checked(
    struct wallet_sqlite *ws, struct wallet *w);

bool wallet_sqlite_read_scan_state(struct wallet_sqlite *ws, struct wallet *w);
bool wallet_sqlite_read_scan_marker(struct wallet_sqlite *ws,
                                    struct wallet_scan_marker *out);

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
    WALLET_SEED_UNREADABLE,   /* the handle is closed or the read failed */
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
/* Fail closed unless all durable Sapling keys and seed match unlocked memory. */
struct zcl_result wallet_sqlite_verify_startup_sapling_r(struct wallet_sqlite *ws, struct wallet *w);
/* Caller holds the matching connection transaction and Sapling keystore lock. */
struct zcl_result wallet_sqlite_verify_startup_sapling_in_tx_locked_r(
    struct wallet_sqlite *ws, struct wallet *w, struct sqlite3 *db);
/* Number of persisted Sapling key rows, loaded or not; -1 when it cannot be
 * read. Read-only. */
int wallet_sqlite_sapling_key_count(struct wallet_sqlite *ws);

/* What the wallet tables hold, read by presence alone: WALLET_HOLDS_SEED when
 * a seed row is stored and WALLET_HOLDS_KEYS when any transparent or Sapling
 * key row is. No seed or key byte is read, so a locked wallet answers as an
 * unlocked one does, and each read stops at the first row. -1 when the tables
 * cannot be read. Read-only. */
enum { WALLET_HOLDS_SEED = 1, WALLET_HOLDS_KEYS = 2 };
int wallet_sqlite_holdings(struct wallet_sqlite *ws);

/* Diversifier indexes at or past this are never issued. */
#define WALLET_DIVERSIFIER_INDEX_MAX ((uint64_t)1 << 62)

/* Choose the next unused ZIP-32 diversified address of `acct` (a copy from
 * sapling_keystore_copy_account) and record its index in the wallet database
 * BEFORE returning it, so no address is ever returned twice from this
 * datadir. The record is synced to disk (synchronous=FULL for this write,
 * whatever the connection mode); when the sync fails no address is returned.
 * An account with no record starts at a random high index from the system
 * CSPRNG, so an address issued by an earlier copy of the wallet is not
 * reissued; when randomness fails no address is returned. Needs no spending
 * key. Refuses inside an open transaction. Serialized in-process. */
bool wallet_sqlite_diversifier_reserve(
    struct wallet_sqlite *ws, const struct sapling_key_entry *acct,
    uint8_t diversifier_out[ZC_DIVERSIFIER_SIZE], uint8_t pk_d_out[32]);

/* True while the connection runs at synchronous=OFF, the node's bulk-sync
 * mode, or when the level cannot be read (unknown is not "syncing").
 * wallet_sqlite_diversifier_reserve issues nothing then. */
bool wallet_sqlite_unsynced(struct wallet_sqlite *ws);

#ifdef ZCL_TESTING
/* Replace the CSPRNG that picks a starting index; NULL restores it. */
void wallet_sqlite_diversifier_set_rng_for_test(bool (*fn)(uint8_t *, size_t));
#endif

/* The durable reservation, which may not have reached a caller before failure. */
enum wallet_diversifier_current {
    WALLET_DIVERSIFIER_INVALID = -1,
    WALLET_DIVERSIFIER_ABSENT = 0,
    WALLET_DIVERSIFIER_PRESENT = 1,
};
enum wallet_diversifier_current wallet_sqlite_diversifier_current(
    struct wallet_sqlite *ws, const struct sapling_key_entry *acct,
    uint8_t diversifier_out[ZC_DIVERSIFIER_SIZE], uint8_t pk_d_out[32]);

/* Legacy lookup used by shield planning; false when no index can be read. */
bool wallet_sqlite_diversifier_latest(
    struct wallet_sqlite *ws, const struct sapling_key_entry *acct,
    uint8_t diversifier_out[ZC_DIVERSIFIER_SIZE], uint8_t pk_d_out[32]);

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

/* A pending startup cutover binds the unread wallet range to both chain
 * authorities. The byte arrays are the existing consensus hash and artifact
 * digest representations; generation presence is explicit. */
struct wallet_cutover_binding {
    bool old_generation_present;
    uint64_t old_generation;
    int32_t old_height;
    uint8_t old_hash[32];
    int32_t target_height;
    uint8_t target_hash[32];
    uint8_t artifact_digest[32];
};
/* A DISCOVER checkpoint is advisory until its caller validates all bindings. */
struct wallet_discover_checkpoint {
    struct wallet_cutover_binding binding;
    bool generation_present;
    uint64_t generation;
    int32_t floor, next_height, endpoint_height;
    uint8_t endpoint_hash[32], endpoint_root[32], scan_identity[32], key_digest[32];
    uint64_t event_end;
    uint8_t event_digest[32];
};
enum wallet_discover_checkpoint_status {
    WALLET_DISCOVER_ABSENT, WALLET_DISCOVER_FOUND,
    WALLET_DISCOVER_MALFORMED, WALLET_DISCOVER_IO_ERROR
};
/* Caller owns the wallet SQLite transaction. The separate durable generation
 * must be checked under its progress lock through wallet commit by the caller. */
bool wallet_sqlite_discover_checkpoint_save(struct wallet_sqlite *ws,
    const struct wallet_discover_checkpoint *checkpoint);
enum wallet_discover_checkpoint_status wallet_sqlite_discover_checkpoint_read(
    struct wallet_sqlite *ws, struct wallet_discover_checkpoint *out);

/* Both bindings must be non-NULL. */
bool wallet_cutover_binding_equal(const struct wallet_cutover_binding *a,
                                   const struct wallet_cutover_binding *b);
enum wallet_cutover_status {
    WALLET_CUTOVER_ABSENT, WALLET_CUTOVER_PENDING,
    WALLET_CUTOVER_MALFORMED, WALLET_CUTOVER_IO_ERROR
};
/* Read the exact persisted scan cursor and unread marker without coercion. */
enum wallet_cutover_floor_status {
    WALLET_CUTOVER_FLOOR_ABSENT, WALLET_CUTOVER_FLOOR_FOUND,
    WALLET_CUTOVER_FLOOR_MALFORMED, WALLET_CUTOVER_FLOOR_IO_ERROR
};
enum wallet_cutover_floor_status wallet_sqlite_cutover_scan_floor(
    struct wallet_sqlite *ws, int *floor);
/* Caller holds w->cs; cursor read, marker and binding share one savepoint.
 * As with prepare, an outer transaction must be durably committed by its owner. */
bool wallet_sqlite_cutover_prepare_preserving_cursor(struct wallet_sqlite *ws,
    struct wallet *w, const struct wallet_cutover_binding *binding);
/* Consumes caller-owned open write transaction on the exclusively held connection.
 * Writes transactions, keypool and completed cursor; keys and scripts are preserved
 * and must already be durable. Caller holds stable external generation/tip authority
 * and proves durable notes, spends and witnesses against scan_identity. Success
 * clears the in-memory marker and publishes READY before releasing wallet locks. */
struct zcl_result wallet_sqlite_cutover_complete_flush_in_open_tx_r(
    struct wallet_sqlite *ws, struct wallet *w,
    const struct wallet_cutover_binding *expected, bool generation_present,
    uint64_t generation, int completed_height, const uint8_t scan_identity[32]);
/* Validator runs before writes under the wallet, keystore and Sapling locks
 * and an owned write transaction. It must not wait or acquire locks. A NULL
 * or false validator refuses and rolls back the transaction. */
struct zcl_result wallet_sqlite_cutover_complete_checked_in_open_tx_r(
    struct wallet_sqlite *ws, struct wallet *w,
    const struct wallet_cutover_binding *expected, bool generation_present,
    uint64_t generation, int completed_height, const uint8_t scan_identity[32],
    bool (*validator)(void *, struct wallet *, sqlite3 *), void *validator_ctx);
struct node_db;
struct wallet_cutover_v2_entry {
    uint32_t slot;
    uint8_t txid[32], block_hash[32];
    int old_depth, new_depth;
};
struct wallet_cutover_v2_plan {
    struct wallet_cutover_v2_entry *entries;
    void *index, *slot_index, *active_spent, *confirmed_spent;
    size_t active_spent_count;
    uint8_t old_spent_digest[32];
    bool spends_ready;
    size_t capacity, count;
    int reference_height, old_best_height;
    uint8_t reference_hash[32], scan_identity[32];
};
typedef bool (*wallet_cutover_endpoint_check)(void *ctx, int height, const uint8_t hash[32]);
typedef bool (*wallet_cutover_projection_write)(void *ctx, struct node_db *ndb,
    struct wallet *wallet, struct wallet_cutover_v2_plan *plan);
struct wallet_cutover_v2_request {
    const struct wallet_cutover_binding *binding;
    bool generation_present;
    uint64_t generation;
    int reference_height;
    uint8_t reference_hash[32], scan_identity[32];
    wallet_height_resolver resolve;
    wallet_cutover_endpoint_check endpoint_current;
    void *chain_ctx;
    bool (*holds_valid)(void *ctx, struct wallet *wallet, sqlite3 *db);
    void *holds_ctx;
    wallet_cutover_projection_write project;
    void *projection_ctx;
};
/* Reserve outside authority locks; plan contains public identifiers only. */
bool wallet_cutover_v2_plan_init(struct wallet_cutover_v2_plan *plan, size_t capacity);
/* Caller holds wallet lock and uses a prepared, still-validated plan. */
const struct wallet_cutover_v2_entry *wallet_cutover_v2_plan_find(
    const struct wallet_cutover_v2_plan *plan, const struct wallet *wallet, const uint8_t txid[32]);
/* Projection builds these transient sets under the held wallet lock. */
bool wallet_cutover_v2_plan_mark_spent(struct wallet_cutover_v2_plan *plan,
    const uint8_t txid[32], uint32_t vout, bool confirmed);
bool wallet_cutover_v2_plan_has_spent(const struct wallet_cutover_v2_plan *plan,
    const uint8_t txid[32], uint32_t vout, bool confirmed_only);
void wallet_cutover_v2_plan_finish_spends(struct wallet_cutover_v2_plan *plan);
void wallet_cutover_v2_plan_free(struct wallet_cutover_v2_plan *plan);
/* After ownership is established, consumes the tracked node_db WRITE transaction.
 * The transaction must be fresh, with no queued AR after-commit hooks.
 * WSQL_TXN_BEGIN_FAIL leaves it untouched; an owning caller must roll it back.
 * Caller serializes the
 * connection and holds stable chain authority. Callbacks must not acquire locks
 * change transaction boundaries, mutate the wallet, or perform external delivery.
 * All callbacks and plan storage outlive COMMIT. */
struct zcl_result wallet_sqlite_cutover_complete_v2_in_open_tx_r(
    struct wallet_sqlite *ws, struct node_db *ndb, struct wallet *wallet,
    const struct wallet_cutover_v2_request *request, struct wallet_cutover_v2_plan *plan);

enum wallet_cutover_status wallet_sqlite_cutover_read(
    struct wallet_sqlite *ws, struct wallet_cutover_binding *out);
/* Caller owns exclusive access to db and must not have an open transaction.
 * The result describes one read snapshot, not a lease after return. */
enum wallet_cutover_status wallet_sqlite_cutover_read_snapshot(sqlite3 *db);
/* A successful nested savepoint only stages these rows in the caller transaction.
 * Cross-store activation must first ensure that transaction is durably committed;
 * success while sqlite3_get_autocommit(ws->db) is false is not durable. */
bool wallet_sqlite_cutover_prepare(struct wallet_sqlite *ws,
    const struct wallet *w, const struct wallet_cutover_binding *binding);

#endif
