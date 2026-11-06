/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Sapling seed and spending-key rows in the wallet SQLite store, and the
 * passphrase check that proves a passphrase against the sealed rows. */

#include "wallet/wallet_sqlite.h"
#include "wallet_sqlite_internal.h"
#include "wallet/wallet_keystore.h"
#include "wallet/wallet_lock.h"
#include "wallet/wallet_sqlite_key_crypto.h"
#include "base/serialize_le.h"
#include "support/cleanse.h"
#include "util/ar_step_readonly.h"
#include "util/log_macros.h"
#include "util/result.h"
#include "util/safe_alloc.h"
#include "util/sync.h"
#include "encoding/utilstrencodings.h"
#include "storage/event_log_payloads.h"
#include "event/event.h"
#include "crypto/random_secret.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* A secret row must never be written in the clear while a passphrase is
 * loaded or the wallet wraps its secrets at rest. */
static bool wsql_plaintext_forbidden(void)
{
    return wallet_lock_effective_passphrase() != NULL ||
           wallet_lock_encrypted_at_rest();
}

/* Event feed for a newly stored Sapling key. */
static void wsql_emit_sapling_key_add(void)
{
    event_emitf(EV_WALLET_KEY_SAVED, 0, "kind=sapling");
    event_emitf(EV_SAPLING_KEY_SAVED, 0, "kind=sapling");
}

/* True when the key row is already stored. A failed probe reads as new: a
 * duplicate emit is idempotent in the projection, a missed row write is not. */
bool wsql_sapling_key_row_exists(struct wallet_sqlite *ws,
                                 const uint8_t ivk[32])
{
    sqlite3_stmt *chk = NULL;
    bool existed = false;
    if (sqlite3_prepare_v2(ws->db,
            "SELECT 1 FROM wallet_sapling_keys WHERE ivk=?",
            -1, &chk, NULL) == SQLITE_OK && chk) {
        sqlite3_bind_blob(chk, 1, ivk, 32, SQLITE_STATIC);
        existed = (AR_STEP_ROW_READONLY(chk) == SQLITE_ROW);
    }
    if (chk) sqlite3_finalize(chk);
    return existed;
}

/* Try `pass` on every WKS1 blob in column 0 of `sql`. Counts the blobs seen
 * in *seen. True as soon as one opens; *unreadable is set on a read error. */
static bool wsql_pass_opens_any(sqlite3 *db, const char *sql, const char *pass,
                                int *seen, bool *unreadable)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK || !st) {
        if (st) sqlite3_finalize(st);
        return false;   /* table absent in an older database: no witness */
    }
    bool opened = false;
    int rc = SQLITE_DONE;
    while (!opened && (rc = AR_STEP_ROW_READONLY(st)) == SQLITE_ROW) {
        const void *blob = sqlite3_column_blob(st, 0);
        int len = sqlite3_column_bytes(st, 0);
        if (!blob || len < WKS_HEADER_LEN ||
            memcmp(blob, WKS_MAGIC, WKS_MAGIC_LEN) != 0)
            continue;
        (*seen)++;
        uint8_t *plain = zcl_malloc((size_t)len, "wallet_check_pass");
        size_t plain_len = 0;
        if (plain && wks_decrypt(blob, (size_t)len, pass, plain, (size_t)len,
                                 &plain_len))
            opened = true;
        wsql_wipe_free(plain, (size_t)len);
    }
    if (!opened && rc != SQLITE_DONE && rc != SQLITE_ROW)
        *unreadable = true;
    sqlite3_finalize(st);
    return opened;
}

enum wallet_passphrase_check wallet_sqlite_check_passphrase(
    struct wallet_sqlite *ws, const char *passphrase)
{
    if (!ws || !ws->open || !passphrase)
        return WALLET_PASS_UNREADABLE;
    static const char *const sources[] = {
        "SELECT wrapped_dek FROM wallet_key_encryption WHERE id=1",
        "SELECT seed FROM wallet_seed WHERE id=1",
        "SELECT xsk FROM wallet_sapling_keys",
        "SELECT privkey FROM wallet_keys",
    };
    int seen = 0;
    bool unreadable = false;
    for (size_t i = 0; i < sizeof(sources) / sizeof(sources[0]); i++)
        if (wsql_pass_opens_any(ws->db, sources[i], passphrase, &seen,
                                &unreadable))
            return WALLET_PASS_OK;
    if (unreadable)
        return WALLET_PASS_UNREADABLE;
    return seen > 0 ? WALLET_PASS_WRONG : WALLET_PASS_NO_SEALED;
}

/* ── Sapling seed & keys ───────────────────────────────────────── */

bool wallet_sqlite_write_sapling_seed(struct wallet_sqlite *ws,
                                        const uint8_t seed[32])
{
    if (!ws || !ws->open)
        LOG_FAIL("wallet_sqlite", "write_sapling_seed: not open");

    /* Never replace a stored seed with a different one. A seed this process
     * did not read back (locked, damaged, unreadable) is treated as present. */
    uint8_t stored[32];
    enum wallet_seed_state stored_state =
        wallet_sqlite_sapling_seed_state(ws, stored);
    bool same = (stored_state == WALLET_SEED_PLAINTEXT ||
                 stored_state == WALLET_SEED_UNLOCKED) &&
                memcmp(stored, seed, 32) == 0;
    memory_cleanse(stored, sizeof(stored));
    if (stored_state != WALLET_SEED_ABSENT && !same)
        LOG_FAIL("wallet_sqlite", "write_sapling_seed: refused, a different "
                 "seed is already stored (state %d)", (int)stored_state);

    int next_child = 0;
    sqlite3_reset(ws->stmt_seed_read);
    if (AR_STEP_ROW_READONLY(ws->stmt_seed_read) == SQLITE_ROW)
        next_child = sqlite3_column_int(ws->stmt_seed_read, 1);
    /* Release the cursor immediately. A cached SELECT left parked on
     * SQLITE_ROW keeps an implicit read transaction (WAL snapshot) open on
     * this shared connection; every later write on the same handle (wallet
     * flush, node_db state_set, catchup) then fails forever with
     * SQLITE_BUSY_SNAPSHOT ("database is locked"). See node_db lock-holder
     * fix. */
    sqlite3_reset(ws->stmt_seed_read);

    uint8_t *enc_blob = NULL;
    size_t enc_len = 0;
    bool encrypted = wsql_encrypt_blob(seed, 32, &enc_blob, &enc_len);
    if (!encrypted && wsql_plaintext_forbidden())
        LOG_FAIL("wallet_sqlite", "write_sapling_seed: refused, the wallet is "
                 "encrypted at rest and locked; plaintext seed not written");

    sqlite3_reset(ws->stmt_seed_write);
    if (encrypted)
        sqlite3_bind_blob(ws->stmt_seed_write, 1,
                          enc_blob, (int)enc_len, SQLITE_TRANSIENT);
    else
        sqlite3_bind_blob(ws->stmt_seed_write, 1, seed, 32, SQLITE_STATIC);
    sqlite3_bind_int(ws->stmt_seed_write, 2, next_child);

    bool ok = AR_STEP_WRITE(ws->stmt_seed_write) == SQLITE_DONE;
    if (enc_blob) { memory_cleanse(enc_blob, enc_len); free(enc_blob); }
    if (!ok)
        LOG_FAIL("wallet_sqlite", "write_sapling_seed: step failed: %s",
                 sqlite3_errmsg(ws->db));
    return true;
}

/* Copy the seed row out, then reset the cursor IMMEDIATELY and
 * unconditionally. A cached SELECT left parked on SQLITE_ROW keeps an implicit
 * read transaction (WAL snapshot) open on this shared connection; every later
 * write on the same handle (wallet flush's BEGIN IMMEDIATE, node_db
 * state_set, catchup COMMIT) then fails forever with SQLITE_BUSY_SNAPSHOT
 * ("database is locked"). The column pointer is invalidated by reset, so the
 * blob is copied into the caller's buffer before the reset.
 *
 * A failed read says nothing about whether a seed exists, so it is
 * UNREADABLE; reporting it as ABSENT would let a caller store a replacement
 * seed. No row is the ONLY "never had a seed". PLAINTEXT here means "a usable
 * row was copied out". */
static enum wallet_seed_state wsql_seed_fetch(struct wallet_sqlite *ws,
                                              uint8_t blob[512],
                                              size_t *blob_len)
{
    *blob_len = 0;
    sqlite3_reset(ws->stmt_seed_read);
    int rc = AR_STEP_ROW_READONLY(ws->stmt_seed_read);
    int len = rc == SQLITE_ROW ? sqlite3_column_bytes(ws->stmt_seed_read, 0) : 0;
    const void *data = len > 0 ? sqlite3_column_blob(ws->stmt_seed_read, 0)
                               : NULL;
    bool usable = data && len >= 32 && len <= 512;
    if (usable) {
        memcpy(blob, data, (size_t)len);
        *blob_len = (size_t)len;
    }
    sqlite3_reset(ws->stmt_seed_read);
    if (rc == SQLITE_DONE)
        return WALLET_SEED_ABSENT;
    if (rc != SQLITE_ROW) {
        LOG_WARN("wallet_sqlite", "read_sapling_seed: step rc=%d: %s",
                 rc, sqlite3_errmsg(ws->db));
        return WALLET_SEED_UNREADABLE;
    }
    return usable ? WALLET_SEED_PLAINTEXT : WALLET_SEED_MALFORMED;
}

/* Classify a stored seed blob. An encrypted blob that cannot be opened is
 * LOCKED, never ABSENT: telling an owner they have no recovery phrase because
 * we could not open their seed is how a recoverable wallet gets written off. */
static enum wallet_seed_state wsql_seed_classify(const uint8_t *blob,
                                                 size_t blob_len,
                                                 uint8_t *seed)
{
    if (!wsql_is_wks1_blob(blob, blob_len)) {
        if (seed) memcpy(seed, blob, 32);
        return WALLET_SEED_PLAINTEXT;
    }
    uint8_t *plain = NULL;
    size_t plain_len = 0;
    bool opened = wsql_decrypt_blob(blob, blob_len, &plain, &plain_len) &&
                  plain_len >= 32;
    if (opened && seed)
        memcpy(seed, plain, 32);
    if (!opened)
        LOG_WARN("wallet_sqlite",
                 "read_sapling_seed: decrypt failed (wrong passphrase?)");
    wsql_wipe_free(plain, plain_len);
    return opened ? WALLET_SEED_UNLOCKED : WALLET_SEED_LOCKED;
}

enum wallet_seed_state wallet_sqlite_sapling_seed_state(
        struct wallet_sqlite *ws, uint8_t seed[32])
{
    if (!ws || !ws->open) return WALLET_SEED_UNREADABLE;
    uint8_t blob[512];
    size_t blob_len = 0;
    enum wallet_seed_state st = wsql_seed_fetch(ws, blob, &blob_len);
    if (st == WALLET_SEED_PLAINTEXT)
        st = wsql_seed_classify(blob, blob_len, seed);
    memory_cleanse(blob, sizeof(blob));
    return st;
}

bool wsql_sapling_seed_row_exists(struct wallet_sqlite *ws)
{
    if (!ws || !ws->open) return false;
    uint8_t blob[512];
    size_t blob_len = 0;
    enum wallet_seed_state st = wsql_seed_fetch(ws, blob, &blob_len);
    memory_cleanse(blob, sizeof(blob));
    return st == WALLET_SEED_PLAINTEXT || st == WALLET_SEED_MALFORMED;
}

bool wallet_sqlite_read_sapling_seed(struct wallet_sqlite *ws, uint8_t seed[32])
{
    enum wallet_seed_state st = wallet_sqlite_sapling_seed_state(ws, seed);
    return st == WALLET_SEED_PLAINTEXT || st == WALLET_SEED_UNLOCKED;
}

bool wallet_sqlite_write_sapling_key(struct wallet_sqlite *ws,
                                       uint32_t child_index,
                                       const struct sapling_key_entry *entry)
{
    if (!ws || !ws->open)
        LOG_FAIL("wallet_sqlite", "write_sapling_key: not open");

    if (entry->secret_wiped)
        LOG_FAIL("wallet_sqlite", "write_sapling_key: refused, entry holds no "
                 "spending key (wallet locked)");

    bool existed = wsql_sapling_key_row_exists(ws, entry->ivk);

    uint8_t *enc_xsk = NULL;
    size_t enc_xsk_len = 0;
    size_t xsk_raw_len = sizeof(struct zip32_xsk);
    bool encrypted = wsql_encrypt_blob((const uint8_t *)&entry->xsk,
                                          xsk_raw_len,
                                          &enc_xsk, &enc_xsk_len);
    if (!encrypted && wsql_plaintext_forbidden())
        LOG_FAIL("wallet_sqlite", "write_sapling_key: refused, the wallet is "
                 "encrypted at rest and locked; plaintext key not written");

    sqlite3_stmt *s = ws->stmt_zkey_write;
    sqlite3_reset(s);
    sqlite3_bind_blob(s, 1, entry->ivk, 32, SQLITE_STATIC);
    if (encrypted)
        sqlite3_bind_blob(s, 2, enc_xsk, (int)enc_xsk_len, SQLITE_TRANSIENT);
    else
        sqlite3_bind_blob(s, 2, &entry->xsk, (int)xsk_raw_len, SQLITE_STATIC);
    sqlite3_bind_blob(s, 3, &entry->xfvk, (int)sizeof(struct zip32_xfvk),
                      SQLITE_STATIC);
    sqlite3_bind_blob(s, 4, entry->diversifier, 11, SQLITE_STATIC);
    sqlite3_bind_blob(s, 5, entry->pk_d, 32, SQLITE_STATIC);
    sqlite3_bind_int(s, 6, (int)child_index);

    bool ok = AR_STEP_WRITE(s) == SQLITE_DONE;
    if (enc_xsk) { memory_cleanse(enc_xsk, enc_xsk_len); free(enc_xsk); }

    if (!ok)
        LOG_FAIL("wallet_sqlite", "write_sapling_key: insert step failed: %s",
                 sqlite3_errmsg(ws->db));

    /* Bump next_child so future address derivation skips this index.
     * Every sqlite rc on this UPDATE must be observed and propagated:
     * if a SQLITE_BUSY from a concurrent reader silently left
     * next_child stale, the next derive_address() call would reuse the
     * child index — producing two addresses bound to the same spend
     * authority.  That collision voids receiver unlinkability, which
     * is the entire point of per-key diversifiers. */
    sqlite3_stmt *upd = NULL;
    int prep_rc = sqlite3_prepare_v2(ws->db,
        "UPDATE wallet_seed SET next_child=MAX(next_child,?+1) WHERE id=1",
        -1, &upd, NULL);
    if (prep_rc != SQLITE_OK || !upd) {
        if (upd) sqlite3_finalize(upd);
        LOG_FAIL("wallet_sqlite",
                 "write_sapling_key: prepare next_child UPDATE rc=%d: %s",
                 prep_rc, sqlite3_errmsg(ws->db));
    }
    if (sqlite3_bind_int(upd, 1, (int)child_index) != SQLITE_OK) {
        sqlite3_finalize(upd);
        LOG_FAIL("wallet_sqlite",
                 "write_sapling_key: bind next_child=%u failed: %s",
                 child_index, sqlite3_errmsg(ws->db));
    }
    int step_rc = AR_STEP_WRITE(upd);
    sqlite3_finalize(upd);
    if (step_rc != SQLITE_DONE) {
        /* SQLITE_BUSY, SQLITE_IOERR, etc. — the row either didn't
         * advance or we lost the update against a concurrent writer.
         * Either way, treat it as a hard failure so the caller (and
         * the flusher) rollback the whole transaction. */
        LOG_FAIL("wallet_sqlite",
                 "write_sapling_key: next_child UPDATE step rc=%d child=%u: %s",
                 step_rc, child_index, sqlite3_errmsg(ws->db));
    }
    if (!existed)
        wsql_emit_sapling_key_add();
    return true;
}

static bool wsql_sapling_xsk_decrypt(const void *blob, size_t len, uint8_t **out_plain, size_t *out_len)
{
    if (!wsql_decrypt_blob(blob, len, out_plain, out_len) ||
        *out_len < sizeof(struct zip32_xsk)) {
        wsql_wipe_free(*out_plain, *out_len);
        *out_plain = NULL;
        *out_len = 0;
        return false;
    }
    return true;
}

/* Outcome of decoding one wallet_sapling_keys row. */
enum wsql_zrow { WSQL_ZROW_DROP, WSQL_ZROW_ENTRY, WSQL_ZROW_UNSCANNABLE };

/* The columns every row needs before it can be decoded at all. */
static bool wsql_zrow_columns_valid(sqlite3_stmt *s)
{
    return sqlite3_column_blob(s, 0) && sqlite3_column_blob(s, 1) &&
           sqlite3_column_blob(s, 3) && sqlite3_column_blob(s, 4) &&
           sqlite3_column_bytes(s, 0) >= 32 &&
           sqlite3_column_bytes(s, 3) >= 11 &&
           sqlite3_column_bytes(s, 4) >= 32;
}

/* Fill the public fields of entry. True when the row stores a full viewing key. */
static bool wsql_zrow_fill_public(sqlite3_stmt *s, struct sapling_key_entry *entry)
{
    memset(entry, 0, sizeof(*entry));
    memcpy(entry->ivk, sqlite3_column_blob(s, 0), 32);
    memcpy(entry->diversifier, sqlite3_column_blob(s, 3), 11);
    memcpy(entry->pk_d, sqlite3_column_blob(s, 4), 32);
    entry->child_index = (uint32_t)sqlite3_column_int(s, 5);
    entry->used = true;
    const void *xfvk = sqlite3_column_blob(s, 2);
    bool have_xfvk = xfvk && sqlite3_column_bytes(s, 2) >=
                             (int)sizeof(struct zip32_xfvk);
    if (have_xfvk)
        memcpy(&entry->xfvk, xfvk, sizeof(struct zip32_xfvk));
    return have_xfvk;
}

/* Decode the current zkey_read row into entry. A row whose spending key
 * cannot be decrypted still yields a viewing entry when it stores a full
 * viewing key; without one it is unscannable until the wallet is unlocked. */
static enum wsql_zrow wsql_sapling_row_load(sqlite3_stmt *s,
                                            struct sapling_key_entry *entry)
{
    if (!wsql_zrow_columns_valid(s))
        return WSQL_ZROW_DROP;
    const void *xsk_data = sqlite3_column_blob(s, 1);
    size_t xsk_len = (size_t)sqlite3_column_bytes(s, 1);
    uint8_t *decrypted = NULL;
    size_t decrypted_len = 0;
    bool have_xsk = true;
    if (wsql_is_wks1_blob(xsk_data, xsk_len)) {
        have_xsk = wsql_sapling_xsk_decrypt(xsk_data, xsk_len, &decrypted,
                                            &decrypted_len);
        xsk_data = decrypted;
        xsk_len = decrypted_len;
    } else if (xsk_len < sizeof(struct zip32_xsk)) {
        return WSQL_ZROW_DROP;
    }

    bool have_xfvk = wsql_zrow_fill_public(s, entry);
    enum wsql_zrow kind = WSQL_ZROW_ENTRY;
    if (have_xsk && xsk_len >= sizeof(struct zip32_xsk)) {
        memcpy(&entry->xsk, xsk_data, sizeof(struct zip32_xsk));
        if (!have_xfvk)
            zip32_xsk_to_xfvk(&entry->xfvk, &entry->xsk);
    } else {
        entry->secret_wiped = true;
        kind = have_xfvk ? WSQL_ZROW_ENTRY : WSQL_ZROW_UNSCANNABLE;
    }
    wsql_wipe_free(decrypted, decrypted_len);
    return kind;
}

/* Load the Sapling seed and keys. Safe to call again on a loaded keystore:
 * rows already present are matched by ivk and regain their spending key
 * instead of being appended, so unlock after lock never duplicates an entry.
 * Rows whose spending key cannot be decrypted load as viewing entries. */
bool wallet_sqlite_read_sapling_keys(struct wallet_sqlite *ws,
                                       struct wallet *w)
{
    if (!ws || !ws->open) return false;

    struct sapling_keystore *sks = &w->sapling_keys;
    uint8_t seed[32];
    enum wallet_seed_state st = wallet_sqlite_sapling_seed_state(ws, seed);
    if (st == WALLET_SEED_PLAINTEXT || st == WALLET_SEED_UNLOCKED)
        sapling_keystore_restore_seed(sks, seed);
    memory_cleanse(seed, sizeof(seed));

    sqlite3_stmt *s = ws->stmt_zkey_read;
    sqlite3_reset(s);

    size_t unscannable = 0;
    int step_rc;
    while ((step_rc = AR_STEP_ROW_READONLY(s)) == SQLITE_ROW) {
        struct sapling_key_entry row;
        enum wsql_zrow kind = wsql_sapling_row_load(s, &row);
        if (kind == WSQL_ZROW_UNSCANNABLE)
            unscannable++;
        bool full = kind == WSQL_ZROW_ENTRY &&
            sapling_keystore_merge_entry(sks, &row) == SAPLING_MERGE_FULL;
        memory_cleanse(&row, sizeof(row));
        if (full) { step_rc = SQLITE_DONE; break; }
    }

    /* Unconditional cursor release. The loop breaks at MAX_SAPLING_KEYS
     * mid-iteration, leaving the cached SELECT parked on a row, which pins the
     * WAL snapshot on the shared connection and wedges every later writer with
     * SQLITE_BUSY_SNAPSHOT. Reset closes that (and the mid-iteration error
     * path) on every exit. */
    sqlite3_reset(s);

    sapling_keystore_settle_lock(
        sks, st == WALLET_SEED_LOCKED || st == WALLET_SEED_MALFORMED ||
             st == WALLET_SEED_UNREADABLE,
        wallet_lock_effective_passphrase() != NULL, unscannable);
    if (unscannable > 0)
        LOG_WARN("wallet_sqlite",
                 "read_sapling_keys: %zu stored key(s) have no readable "
                 "spending key and no stored viewing key; unlock to scan them",
                 unscannable);
    /* A failed read is not an empty wallet: the caller must not unlock on it. */
    return st != WALLET_SEED_UNREADABLE && step_rc == SQLITE_DONE;
}


/* ── Diversified receive addresses ────────────────────────────────────
 *
 * wallet_sapling_diversifier(ivk, next_index) holds, per account, the first
 * ZIP-32 diversifier index that this datadir has not handed out. A datadir
 * with no row for the account (a new wallet, a restore, a backup restore)
 * cannot know which addresses an earlier copy issued, and notes are found by
 * the incoming viewing key at any index, so it starts at a random high index:
 * an earlier sequential run is not reissued, and the choice needs no scan. */

#define WSQL_DIV_START_MIN ((uint64_t)1 << 40)
#define WSQL_DIV_START_SPAN ((uint64_t)1 << 60)

static zcl_mutex_t g_div_lock;
static zcl_once_t g_div_once = ZCL_ONCE_INIT;

static void wsql_div_lock_init(void)
{
    zcl_mutex_init(&g_div_lock);
}

#ifdef ZCL_TESTING
static bool (*g_div_rng)(uint8_t *buf, size_t n);

void wallet_sqlite_diversifier_set_rng_for_test(bool (*fn)(uint8_t *, size_t))
{
    g_div_rng = fn;
}
#endif

static bool wsql_div_random(uint8_t *buf, size_t n)
{
#ifdef ZCL_TESTING
    if (g_div_rng)
        return g_div_rng(buf, n);
#endif
    return zcl_random_secret_bytes(buf, n, "diversifier_start");
}

/* The stored next index for `ivk`; *have is false when the account has no row. */
static bool wsql_div_read(struct wallet_sqlite *ws, const uint8_t ivk[32],
                          uint64_t *next, bool *have)
{
    *next = 0;
    *have = false;
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(ws->db,
            "SELECT next_index FROM wallet_sapling_diversifier WHERE ivk=?",
            -1, &s, NULL) != SQLITE_OK || !s)
        LOG_FAIL("wallet_sqlite", "diversifier read: prepare failed: %s",
                 sqlite3_errmsg(ws->db));
    sqlite3_bind_blob(s, 1, ivk, 32, SQLITE_STATIC);
    int rc = AR_STEP_ROW_READONLY(s);
    if (rc == SQLITE_ROW) {
        sqlite3_int64 v = sqlite3_column_int64(s, 0);
        *next = v > 0 ? (uint64_t)v : 0;
        *have = true;
    }
    sqlite3_finalize(s);
    if (rc != SQLITE_ROW && rc != SQLITE_DONE)
        LOG_FAIL("wallet_sqlite", "diversifier read: step failed rc=%d", rc);
    return true;
}

/* The connection's synchronous level (0 OFF, 1 NORMAL, 2 FULL, 3 EXTRA), or
 * -1 when it cannot be read. */
static int wsql_synchronous_level(sqlite3 *db)
{
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(db, "PRAGMA synchronous", -1, &s, NULL) !=
            SQLITE_OK || !s)
        return -1;
    int level = sqlite3_step(s) == SQLITE_ROW ? sqlite3_column_int(s, 0) : -1;  // raw-sql-ok:wallet-pragma-read
    sqlite3_finalize(s);
    return level;
}

bool wallet_sqlite_unsynced(struct wallet_sqlite *ws)
{
    return ws && ws->open && wsql_synchronous_level(ws->db) == 0;
}

static bool wsql_set_synchronous(sqlite3 *db, int level)
{
    char sql[32];
    snprintf(sql, sizeof(sql), "PRAGMA synchronous=%d", level);
    return sqlite3_exec(db, sql, NULL, NULL, NULL) == SQLITE_OK &&
           wsql_synchronous_level(db) == level;
}

/* The first index to issue from: past the default diversifier and the stored
 * index, or a random high start when the account has no stored index. */
static bool wsql_div_first_free(struct wallet_sqlite *ws,
                                const struct sapling_key_entry *acct,
                                uint64_t *first_free)
{
    uint64_t stored = 0;
    bool have = false;
    if (!wsql_div_read(ws, acct->ivk, &stored, &have))
        return false;
    uint8_t d[11], pk_d[32];
    uint64_t slot = 0;
    if (!sapling_account_diversified_address(acct, 0, &slot, d, pk_d))
        return false;
    uint64_t start = slot + 1;
    if (!have) {
        uint8_t r[8];
        if (!wsql_div_random(r, sizeof(r)))
            LOG_FAIL("wallet_sqlite", "diversifier reserve: no randomness; "
                     "no address issued");
        uint64_t v = zcl_read_u64_le(r);
        memory_cleanse(r, sizeof(r));
        stored = WSQL_DIV_START_MIN + v % WSQL_DIV_START_SPAN;
    }
    *first_free = stored > start ? stored : start;
    return true;
}

/* Record next_index = `next` and return only once it is synced to disk: the
 * write runs at synchronous=FULL whatever the connection's mode (NORMAL syncs
 * the log only at checkpoints, OFF never), so power loss cannot take back an
 * index whose address was shown. */
static bool wsql_div_write_durable(struct wallet_sqlite *ws,
                                   const uint8_t ivk[32], uint64_t next)
{
    int prev = wsql_synchronous_level(ws->db);
    if (prev < 0)
        LOG_FAIL("wallet_sqlite", "diversifier reserve: cannot read the "
                 "synchronous level");
    if (!wsql_set_synchronous(ws->db, 2)) {
        (void)wsql_set_synchronous(ws->db, prev);
        LOG_FAIL("wallet_sqlite", "diversifier reserve: cannot raise "
                 "synchronous to FULL; no address issued");
    }
    sqlite3_stmt *s = NULL;
    bool ok = false;
    if (sqlite3_prepare_v2(ws->db,
            "INSERT INTO wallet_sapling_diversifier(ivk,next_index)"
            " VALUES(?,?) ON CONFLICT(ivk) DO UPDATE SET"
            " next_index=MAX(next_index,excluded.next_index)",
            -1, &s, NULL) == SQLITE_OK && s) {
        sqlite3_bind_blob(s, 1, ivk, 32, SQLITE_STATIC);
        sqlite3_bind_int64(s, 2, (sqlite3_int64)next);
        int rc = AR_STEP_WRITE(s);
        ok = rc == SQLITE_DONE;
        if (!ok)
            LOG_WARN("wallet_sqlite", "diversifier reserve: write failed "
                     "rc=%d: %s", rc, sqlite3_errmsg(ws->db));
    } else {
        LOG_WARN("wallet_sqlite", "diversifier reserve: prepare failed: %s",
                 sqlite3_errmsg(ws->db));
    }
    if (s)
        sqlite3_finalize(s);
    if (!wsql_set_synchronous(ws->db, prev))
        LOG_WARN("wallet_sqlite", "diversifier reserve: synchronous level "
                 "not restored");
    return ok;
}

bool wallet_sqlite_diversifier_reserve(
    struct wallet_sqlite *ws, const struct sapling_key_entry *acct,
    uint8_t diversifier_out[ZC_DIVERSIFIER_SIZE], uint8_t pk_d_out[32])
{
    if (!ws || !ws->open || !acct || !acct->used)
        LOG_FAIL("wallet_sqlite", "diversifier reserve: no open wallet or account");
    /* An open transaction would make the write below part of someone else's
     * commit: the index must be on disk before an address leaves. */
    if (!sqlite3_get_autocommit(ws->db))
        LOG_FAIL("wallet_sqlite", "diversifier reserve: refused inside an open "
                 "transaction");
    /* Bulk-sync mode never syncs, so a write made there could be taken back
     * by power loss after its address was shown: issue none. */
    if (wallet_sqlite_unsynced(ws))
        LOG_FAIL("wallet_sqlite", "diversifier reserve: the connection is not "
                 "syncing (bulk-sync mode); no address issued");
    /* Read, derive and write are one step: two callers must not read one
     * index, and the synchronous level is restored by whoever raised it. */
    if (!zcl_once_call(&g_div_once, wsql_div_lock_init))
        LOG_FAIL("wallet_sqlite", "diversifier reserve: lock unavailable");
    zcl_mutex_lock(&g_div_lock);
    bool ok = false;
    uint64_t first_free = 0;
    uint64_t slot = 0;
    uint8_t d[ZC_DIVERSIFIER_SIZE], pk_d[32];
    if (wsql_div_first_free(ws, acct, &first_free)) {
        if (!sapling_account_diversified_address(acct, first_free, &slot, d,
                                                 pk_d) ||
            slot >= WALLET_DIVERSIFIER_INDEX_MAX - 1)
            LOG_WARN("wallet_sqlite", "diversifier reserve: no address available");
        else if (wsql_div_write_durable(ws, acct->ivk, slot + 1))
            ok = true;
    }
    zcl_mutex_unlock(&g_div_lock);
    if (!ok)
        return false;
    memcpy(diversifier_out, d, ZC_DIVERSIFIER_SIZE);
    memcpy(pk_d_out, pk_d, 32);
    return true;
}

static enum wallet_diversifier_current wsql_current_row(
    sqlite3_stmt *s, const struct sapling_key_entry *acct,
    uint8_t diversifier_out[ZC_DIVERSIFIER_SIZE], uint8_t pk_d_out[32])
{
    if (sqlite3_column_type(s, 0) != SQLITE_INTEGER)
        return WALLET_DIVERSIFIER_INVALID;
    sqlite3_int64 next = sqlite3_column_int64(s, 0);
    if (next < 2 || (uint64_t)next >= WALLET_DIVERSIFIER_INDEX_MAX)
        return WALLET_DIVERSIFIER_INVALID;
    uint64_t first = 0, slot = 0;
    uint8_t d[ZC_DIVERSIFIER_SIZE], pk_d[32];
    if (!sapling_account_diversified_address(acct, 0, &first, d, pk_d) ||
        !sapling_account_diversified_address(acct, (uint64_t)next - 1,
                                             &slot, d, pk_d) ||
        slot != (uint64_t)next - 1 || slot <= first)
        return WALLET_DIVERSIFIER_INVALID;
    memcpy(diversifier_out, d, sizeof(d));
    memcpy(pk_d_out, pk_d, sizeof(pk_d));
    return WALLET_DIVERSIFIER_PRESENT;
}

/* Read without repairing or advancing the durable reservation. */
enum wallet_diversifier_current wallet_sqlite_diversifier_current(
    struct wallet_sqlite *ws, const struct sapling_key_entry *acct,
    uint8_t diversifier_out[ZC_DIVERSIFIER_SIZE], uint8_t pk_d_out[32])
{
    if (!ws || !ws->open || !ws->db || !acct || !acct->used ||
        !diversifier_out || !pk_d_out)
        return WALLET_DIVERSIFIER_INVALID;
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(ws->db,
            "SELECT next_index FROM wallet_sapling_diversifier WHERE ivk=?",
            -1, &s, NULL) != SQLITE_OK || !s) {
        if (s) sqlite3_finalize(s);
        return WALLET_DIVERSIFIER_INVALID;
    }
    enum wallet_diversifier_current result = WALLET_DIVERSIFIER_INVALID;
    if (sqlite3_bind_blob(s, 1, acct->ivk, 32, SQLITE_STATIC) == SQLITE_OK) {
        int rc = AR_STEP_ROW_READONLY(s);
        if (rc == SQLITE_DONE) result = WALLET_DIVERSIFIER_ABSENT;
        else if (rc == SQLITE_ROW)
            result = wsql_current_row(s, acct, diversifier_out, pk_d_out);
    }
    sqlite3_finalize(s);
    return result;
}

bool wallet_sqlite_diversifier_latest(
    struct wallet_sqlite *ws, const struct sapling_key_entry *acct,
    uint8_t diversifier_out[ZC_DIVERSIFIER_SIZE], uint8_t pk_d_out[32])
{
    if (!ws || !ws->open || !acct || !acct->used)
        return false;
    uint64_t next = 0;
    bool have = false;
    if (!wsql_div_read(ws, acct->ivk, &next, &have) || next == 0)
        return false;
    uint64_t slot = 0;
    return sapling_account_diversified_address(acct, next - 1, &slot,
                                               diversifier_out, pk_d_out);
}
