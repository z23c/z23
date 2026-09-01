/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Wallet Backup Service — periodic, rotated, verified backups
 * of the wallet_* tables inside node.db.
 *
 * Invariant
 * ---------
 * node.db and its WAL/SHM sidecar files hold the `wallet_keys` and
 * `wallet_sapling_keys` rows, the sole source of truth for the user's
 * private keys. Deleting node.db (whether by an operator mistake or a
 * crash mid-reimport) wipes those keys; the next boot generates fresh ones
 * and any funds already sent to the original addresses become permanently
 * unspendable.
 *
 * The safety rails (recovery_policy, db_txn,
 * chain_state_repository, block_index_integrity) all make the
 * *running* node safer. None of them defend against an operator
 * mistake that takes the whole database file out of play before
 * the rails get a chance to run. The fix is an always-on,
 * always-external, always-versioned backup of just the wallet
 * tables — a copy the user can restore from even if node.db is
 * gone, corrupt, or deleted by mistake.
 *
 * Design
 * ------
 *
 *   - A background thread started from boot. Every
 *     `interval_seconds` the thread copies the nine wallet tables
 *     (`wallet_keys`, `wallet_keypool`, `wallet_key_encryption`,
 *     `wallet_sapling_keys`, `wallet_seed`,
 *     `wallet_scripts`, `wallet_transactions`, `wallet_utxos`,
 *     `wallet_sapling_notes`) via ATTACH + `CREATE TABLE AS
 *     SELECT` into a `wallet_backup_<unix_ts>.sqlite` file in
 *     `backup_dir`.
 *   - After each write the service reopens the copy and verifies the
 *     row count of EVERY wallet table against the source — not just
 *     wallet_keys. A table the source did not have is recorded, not
 *     skipped in silence. Every backup file also carries a
 *     `wallet_backup_manifest` table (one row per wallet table: was it
 *     in the source, how many rows landed) so a short copy stays
 *     detectable long after the run. Mismatch →
 *     EV_WALLET_BACKUP_FAILED and the file is left on disk for
 *     forensic inspection.
 *   - Rotation: if the count of `wallet_backup_*.sqlite` files in
 *     `backup_dir` exceeds `max_versions`, the oldest is deleted.
 *     The newest is always kept.
 *   - `wallet_backup_now()` runs one backup synchronously. It's
 *     the same code path the thread uses, so RPC callers and the
 *     thread share a single failure mode.
 *
 * Encryption
 * ----------
 * Phase 1 ships unencrypted. Phase 2 will add AES-256-GCM via
 * scrypt-derived keys. The header already carries the hooks so a
 * follow-up commit can land the crypto path without API churn.
 *
 * Thread safety
 * -------------
 * The service owns its own pthread + a mutex that guards
 * start/stop/now calls. `wallet_backup_now()` is safe to call
 * from any thread and blocks until the one-shot backup completes.
 */

#ifndef ZCL_SERVICES_WALLET_BACKUP_SERVICE_H
#define ZCL_SERVICES_WALLET_BACKUP_SERVICE_H

#include "models/database.h"
#include "util/result.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* ── Tunables ───────────────────────────────────────────────── */

#define WALLET_BACKUP_DEFAULT_INTERVAL_SEC 3600   /* 1 hour */
#define WALLET_BACKUP_DEFAULT_MAX_VERSIONS 168    /* 1 week @ hourly */
#define WALLET_BACKUP_FILENAME_PREFIX "wallet_backup_"
#define WALLET_BACKUP_FILENAME_SUFFIX ".sqlite"
#define WALLET_BACKUP_FILENAME_SUFFIX_ENC ".sqlite.enc"

/* Encrypted file format (phase 2):
 *
 *   offset   len  field
 *   ------   ---  -----
 *        0     4  magic  "WBE1"
 *        4     4  version (u32 LE, = 1)
 *        8     4  iterations (u32 LE, PBKDF2 rounds)
 *       12     4  reserved (u32 LE, 0)
 *       16    16  salt (PBKDF2)
 *       32    12  nonce (ChaCha20-Poly1305)
 *       44     N  ciphertext
 *     44+N    16  Poly1305 tag
 *
 * The 44-byte header is also the AAD for the AEAD, so any
 * tampering with magic, version, iterations, reserved, salt,
 * or nonce fails decryption (tag mismatch). */
#define WALLET_BACKUP_ENC_MAGIC       "WBE1"
#define WALLET_BACKUP_ENC_VERSION     1u
#define WALLET_BACKUP_ENC_HEADER_LEN  44
#define WALLET_BACKUP_ENC_TAG_LEN     16
#define WALLET_BACKUP_ENC_SALT_LEN    16
#define WALLET_BACKUP_ENC_NONCE_LEN   12
#define WALLET_BACKUP_ENC_KEY_LEN     32
#define WALLET_BACKUP_ENC_ITERATIONS  200000u /* PBKDF2 rounds */

/* ── Config ─────────────────────────────────────────────────── */

struct wallet_backup_config {
    const char *backup_dir;        /* absolute path, created 0700 if missing */
    int         interval_seconds;  /* 0 = use default */
    int         max_versions;      /* 0 = use default */
    bool        encrypt;           /* encrypt snapshots (WBE1); requires encrypt_password */
    const char *encrypt_password;  /* env WALLET_BACKUP_PASSWORD if encrypt */
};

void wallet_backup_config_defaults(struct wallet_backup_config *cfg);

/* ── Status snapshot (read-only) ────────────────────────────── */

struct wallet_backup_status {
    bool    running;               /* thread is active */
    int64_t total_runs;            /* successful backups since start */
    int64_t total_failures;        /* emitted EV_WALLET_BACKUP_FAILED */
    int64_t last_run_unix;         /* wall-clock time of last success, 0 if none */
    int64_t last_size_bytes;       /* size of last successful backup */
    int64_t last_key_count;        /* wallet_keys rows in last backup */
    int64_t last_duration_ms;      /* elapsed ms of the last run */
    /* Verification breadth of the last run. The service compares row counts
     * for EVERY wallet table, not just wallet_keys: last_tables_verified is
     * how many matched the source, wallet_table_count is how many exist, and
     * last_missing_tables is the comma-joined names the SOURCE did not have
     * (nothing to copy — recorded, never silently skipped). */
    int     last_tables_verified;
    int     wallet_table_count;
    char    last_missing_tables[256];
    char    last_path[512];        /* absolute path of last backup */
    /* Latest verified ENCRYPTED backup is separate authority. A later
     * scheduled plaintext snapshot must not erase proof that this file still
     * covers the current wallet keys. */
    int64_t last_encrypted_run_unix;
    int64_t last_encrypted_key_count;
    int     last_encrypted_tables_verified;
    char    last_encrypted_path[512];
    char    last_error[256];       /* most recent failure reason */
};

void wallet_backup_status_snapshot(struct wallet_backup_status *out);

/* See CLAUDE.md "Adding state introspection". Reentrant-safe. */
struct json_value;
bool wallet_backup_dump_state_json(struct json_value *out, const char *key);

/* ── Lifecycle ──────────────────────────────────────────────── */

/* Start the background backup thread. `db` is the opened node_db
 * that owns the wallet tables. If the service is already running,
 * this is a no-op and returns ZCL_OK. Returns a non-ok zcl_result on
 * any setup error (missing backup_dir permission, thread create
 * failure, etc) — the .message explains why. Safe to call from any
 * thread. */
struct zcl_result wallet_backup_start(const struct wallet_backup_config *cfg,
                                       struct node_db *db);

/* Stop the background thread. Safe to call even if not running. */
void wallet_backup_stop(void);

/* Run one backup synchronously. Returns ZCL_OK on success, otherwise
 * a non-ok zcl_result whose .message carries the failure reason.
 * Callable whether or not the thread is running. Safe to call from
 * any thread — serialised by the service mutex. */
struct zcl_result wallet_backup_now(void);

/* Run one synchronously verified backup with an invocation-scoped second
 * encryption layer. The password is consumed only while the service lock is
 * held; it is never retained in service state after this call returns. This
 * is the safe native-command path for operators who refuse to put
 * WALLET_BACKUP_PASSWORD in a process environment or unit file. */
struct zcl_result wallet_backup_now_encrypted(const char *password);

/* ── Event triggers (debounced) ─────────────────────────────── */

/* Minimum interval between trigger-driven backups. Triggers that
 * arrive inside the window coalesce to one backup at the end of
 * the window, protecting disk from e.g. a 1000-address import
 * script that would otherwise cause 1000 JSON writes. */
#define WALLET_BACKUP_TRIGGER_MIN_INTERVAL_SEC 30

/* Signal the background thread that wallet key state changed and a
 * fresh backup should run soon.
 *
 * Safe to call from any thread. No-op if the backup service is not
 * running (e.g. tests, or before boot finishes). Non-blocking.
 * Rate-limited: at most one backup per
 * WALLET_BACKUP_TRIGGER_MIN_INTERVAL_SEC; later triggers coalesce
 * into a single run.
 *
 * Called by the wallet controller after every successful key
 * persist (importprivkey, getnewaddress, z_getnewaddress, etc.)
 * so the JSON mirror never lags behind the SQLite store by more
 * than the debounce interval. */
void wallet_backup_service_on_key_change(void);

/* Same as on_key_change, but semantically meant for bulk keypool
 * top-ups that happen at boot or after drain. Distinct entry
 * point so tests can count each kind independently; currently
 * both share the same debounce and the same backup run. */
void wallet_backup_service_on_keypool_topup(void);

/* ── The wallet table set ───────────────────────────────────── */

/* The wallet tables a backup captures — and therefore the exact set a
 * restore merges back. ONE list, owned here, so backup and restore can
 * never disagree about what a complete wallet is. Returns a pointer to
 * static storage; *out_count (required) receives the length. */
const char *const *wallet_backup_tables(size_t *out_count);

/* ── Low-level primitive (testable) ─────────────────────────── */

/* Create one backup file in `backup_dir` reading from `db`. On
 * success, writes the full path to `out_path` (if non-NULL) and
 * the wallet_keys row count to `out_key_count` (if non-NULL).
 * Returns ZCL_OK on success or a non-ok zcl_result on any IO/SQL
 * error. This is the single entry point used by both the thread and
 * wallet_backup_now, exposed so tests can call it directly without
 * spinning a thread.
 *
 * err_out/err_cap take a optional caller-provided diagnostic buffer —
 * the same shape as bii_verify — populated with the failure reason on
 * error (a copy of the returned result's .message) so callers that
 * keep the buffer form still work. The returned zcl_result is the
 * source of truth. */
struct zcl_result wallet_backup_run_once(const char *backup_dir,
                             struct node_db *db,
                             char *out_path, size_t out_path_cap,
                             int64_t *out_key_count,
                             char *err_out, size_t err_cap);

/* Apply rotation in `backup_dir`, deleting the oldest
 * `wallet_backup_<ts>.sqlite` files until count <= max_versions.
 * Returns the number of files deleted. */
int wallet_backup_rotate(const char *backup_dir, int max_versions);

/* List `wallet_backup_<ts>.sqlite` files in `backup_dir`, newest
 * first. `out_paths` is a caller-provided array of `max` strings,
 * each `path_cap` bytes wide. Returns the number written. */
int wallet_backup_list(const char *backup_dir,
                        char (*out_paths)[512], int max);

/* ── Phase 2: encryption helpers ────────────────────────────── */

/* Encrypt `src_path` to `dst_path` using PBKDF2-HMAC-SHA256 to
 * derive a 256-bit ChaCha20-Poly1305 key from `password`. Generates
 * a fresh random salt + nonce and writes the header described
 * above followed by the ciphertext + tag. Returns ZCL_OK on success;
 * on failure a non-ok zcl_result (whose .message explains the cause)
 * and the partial dst file (if any) is removed. Passing NULL or empty
 * `password` is rejected. */
struct zcl_result wallet_backup_encrypt_file(const char *src_path,
                                 const char *dst_path,
                                 const char *password);

/* Decrypt `src_path` to `dst_path`. Returns ZCL_OK only when the
 * header magic, version, AEAD tag, and AAD all verify; otherwise a
 * non-ok zcl_result whose .message explains the failure. On any
 * failure the partial dst file is removed so callers never see
 * half-decrypted bytes. */
struct zcl_result wallet_backup_decrypt_file(const char *src_path,
                                 const char *dst_path,
                                 const char *password);

#endif /* ZCL_SERVICES_WALLET_BACKUP_SERVICE_H */
