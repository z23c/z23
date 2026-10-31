/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Sapling seed and spending-key rows in the wallet SQLite store, and the
 * passphrase check that proves a passphrase against the sealed rows. */

#include "wallet/wallet_sqlite.h"
#include "wallet_sqlite_internal.h"
#include "wallet/wallet_keystore.h"
#include "wallet/wallet_lock.h"
#include "wallet/wallet_sqlite_key_crypto.h"
#include "support/cleanse.h"
#include "util/ar_step_readonly.h"
#include "util/log_macros.h"
#include "util/result.h"
#include "util/safe_alloc.h"
#include "encoding/utilstrencodings.h"
#include "storage/event_log_payloads.h"
#include "event/event.h"
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
 * ZIP-32 diversifier index that no address handed out by this datadir has
 * used. */

#define WSQL_DIV_NOTE_CAP 4096
#define WSQL_DIV_INDEX_MAX ((uint64_t)1 << 62)

/* The stored next index for `ivk`; 0 when the account has none. */
static bool wsql_div_read(struct wallet_sqlite *ws, const uint8_t ivk[32],
                          uint64_t *next)
{
    *next = 0;
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
    }
    sqlite3_finalize(s);
    if (rc != SQLITE_ROW && rc != SQLITE_DONE)
        LOG_FAIL("wallet_sqlite", "diversifier read: step failed rc=%d", rc);
    return true;
}

/* Every distinct diversifier the account's notes were received on. The
 * caller frees *out. */
static bool wsql_div_note_diversifiers(struct wallet_sqlite *ws,
                                       const uint8_t ivk[32],
                                       uint8_t (**out)[11], size_t *count)
{
    *out = NULL;
    *count = 0;
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(ws->db,
            "SELECT DISTINCT diversifier FROM wallet_sapling_notes"
            " WHERE ivk=? LIMIT ?",
            -1, &s, NULL) != SQLITE_OK || !s)
        LOG_FAIL("wallet_sqlite", "diversifier notes: prepare failed: %s",
                 sqlite3_errmsg(ws->db));
    uint8_t (*rows)[11] = zcl_calloc(WSQL_DIV_NOTE_CAP, 11,
                                     "wallet_sqlite.div_notes");
    if (!rows) {
        sqlite3_finalize(s);
        return false;
    }
    sqlite3_bind_blob(s, 1, ivk, 32, SQLITE_STATIC);
    sqlite3_bind_int(s, 2, WSQL_DIV_NOTE_CAP);
    int rc;
    while ((rc = AR_STEP_ROW_READONLY(s)) == SQLITE_ROW) {
        if (sqlite3_column_bytes(s, 0) == 11)
            memcpy(rows[(*count)++], sqlite3_column_blob(s, 0), 11);
    }
    sqlite3_finalize(s);
    if (rc != SQLITE_DONE) {
        free(rows);
        LOG_FAIL("wallet_sqlite", "diversifier notes: step failed rc=%d", rc);
    }
    *out = rows;
    return true;
}

static bool wsql_div_listed(const uint8_t (*list)[11], size_t n,
                            const uint8_t d[11])
{
    for (size_t i = 0; i < n; i++)
        if (memcmp(list[i], d, 11) == 0)
            return true;
    return false;
}

/* The next index to issue from: past the default diversifier, past the stored
 * index and past the highest diversifier any note of the account was
 * received on, found by walking the account's addresses upward and stopping
 * after WALLET_DIVERSIFIER_GAP unused ones. A restored wallet has no stored
 * index; this walk is what finds the addresses it already handed out. */
static bool wsql_div_first_free(struct wallet_sqlite *ws,
                                const struct sapling_key_entry *acct,
                                uint64_t *first_free)
{
    uint64_t stored = 0;
    if (!wsql_div_read(ws, acct->ivk, &stored))
        return false;
    uint8_t d[11], pk_d[32];
    uint64_t slot = 0;
    if (!sapling_account_diversified_address(acct, 0, &slot, d, pk_d))
        return false;
    uint64_t start = slot + 1;
    if (stored > start)
        start = stored;

    uint8_t (*notes)[11] = NULL;
    size_t note_count = 0;
    if (!wsql_div_note_diversifiers(ws, acct->ivk, &notes, &note_count))
        return false;
    uint64_t next = start;
    uint64_t probe = start;
    unsigned unused = 0;
    while (note_count > 0 && unused < WALLET_DIVERSIFIER_GAP) {
        if (probe >= WSQL_DIV_INDEX_MAX ||
            !sapling_account_diversified_address(acct, probe, &slot, d, pk_d))
            break;
        if (wsql_div_listed((const uint8_t (*)[11])notes, note_count, d)) {
            next = slot + 1;
            unused = 0;
        } else {
            unused++;
        }
        probe = slot + 1;
    }
    free(notes);
    *first_free = next;
    return true;
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
    uint64_t first_free = 0;
    if (!wsql_div_first_free(ws, acct, &first_free))
        return false;
    uint64_t slot = 0;
    uint8_t d[ZC_DIVERSIFIER_SIZE], pk_d[32];
    if (!sapling_account_diversified_address(acct, first_free, &slot, d, pk_d) ||
        slot >= WSQL_DIV_INDEX_MAX - 1)
        LOG_FAIL("wallet_sqlite", "diversifier reserve: no address available");

    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(ws->db,
            "INSERT INTO wallet_sapling_diversifier(ivk,next_index)"
            " VALUES(?,?) ON CONFLICT(ivk) DO UPDATE SET"
            " next_index=MAX(next_index,excluded.next_index)",
            -1, &s, NULL) != SQLITE_OK || !s)
        LOG_FAIL("wallet_sqlite", "diversifier reserve: prepare failed: %s",
                 sqlite3_errmsg(ws->db));
    sqlite3_bind_blob(s, 1, acct->ivk, 32, SQLITE_STATIC);
    sqlite3_bind_int64(s, 2, (sqlite3_int64)(slot + 1));
    int rc = AR_STEP_WRITE(s);
    sqlite3_finalize(s);
    if (rc != SQLITE_DONE)
        LOG_FAIL("wallet_sqlite", "diversifier reserve: write failed rc=%d: %s",
                 rc, sqlite3_errmsg(ws->db));
    memcpy(diversifier_out, d, ZC_DIVERSIFIER_SIZE);
    memcpy(pk_d_out, pk_d, 32);
    return true;
}

bool wallet_sqlite_diversifier_latest(
    struct wallet_sqlite *ws, const struct sapling_key_entry *acct,
    uint8_t diversifier_out[ZC_DIVERSIFIER_SIZE], uint8_t pk_d_out[32])
{
    if (!ws || !ws->open || !acct || !acct->used)
        return false;
    uint64_t next = 0;
    if (!wsql_div_read(ws, acct->ivk, &next) || next == 0)
        return false;
    uint64_t slot = 0;
    return sapling_account_diversified_address(acct, next - 1, &slot,
                                               diversifier_out, pk_d_out);
}
