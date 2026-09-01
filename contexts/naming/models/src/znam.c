/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ActiveRecord models for ZCL Names (ZNAM).
 *
 * Three sibling models — one per table:
 *   znam_names         (struct znam_entry)
 *   znam_text_records  (struct znam_text_record)
 *   znam_addr_records  (struct znam_addr_record)
 *
 * This file owns the integrity and persistence contract for the three
 * on-chain-derived tables. A malformed znam row at rest means a malformed
 * OP_RETURN was accepted earlier in the pipeline — these validators are the
 * last checkpoint before the row is written. The OP_RETURN parser/builder
 * stays in contexts/naming/modules/znam/src/znam.c. */

#include "models/znam.h"
#include "chain/chainparams.h"
#include "keys/key_io.h"
#include "platform/clock.h"
#include "script/standard.h"
#include "storage/znam_projection.h"
#include "util/ar_step_readonly.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"

#include <sqlite3.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef ZCL_TESTING
static int (*g_znam_count_step_fn)(void *stmt);

void db_znam_test_set_count_step(int (*step_fn)(void *stmt))
{
    g_znam_count_step_fn = step_fn;
}

#define ZNAM_COUNT_STEP(stmt) \
    (g_znam_count_step_fn ? g_znam_count_step_fn(stmt) \
                          : AR_STEP_ROW_READONLY(stmt))
#else
#define ZNAM_COUNT_STEP(stmt) AR_STEP_ROW_READONLY(stmt)
#endif

DEFINE_MODEL_CALLBACKS(znam_entry)
DEFINE_MODEL_CALLBACKS(znam_text)
DEFINE_MODEL_CALLBACKS(znam_addr)

static bool read_znam_blob(sqlite3_stmt *s, int col, void *dest,
                           int expected_len, const char *table,
                           const char *column)
{
    int got = sqlite3_column_bytes(s, col);
    const void *blob = sqlite3_column_blob(s, col);
    if (!blob || got != expected_len)
        LOG_FAIL("znam",
                 "%s.%s blob length mismatch: got=%d expected=%d",
                 table, column, got, expected_len);

    AR_READ_BLOB(s, col, dest, expected_len);
    return true;
}

static void znam_entry_after_save(void *record, void *ctx)
{
    const struct znam_entry *entry = record;

    (void)ctx;
    if (!entry || !znam_projection_event_log())
        return;

    /* Projection event emit. Always emit REGISTER — the projection uses
     * INSERT OR REPLACE so re-registers are idempotent and the primary-target
     * fields stay in sync without a separate UPDATE. */
    if (!znam_projection_emit_register(
            entry->name, entry->owner_address, entry->target_type,
            entry->target_value, entry->reg_txid, entry->reg_height,
            (uint32_t)(clock_now_wall_ms() / 1000), 0)) {
        fprintf(stderr,  // obs-ok:znam-projection-emit
                "znam projection emit failed for register\n");
    }
}

static void znam_text_after_save(void *record, void *ctx)
{
    const struct znam_text_record *rec = record;
    static const uint8_t zero_txid[32] = {0};

    (void)ctx;
    if (!rec || !znam_projection_event_log())
        return;

    /* update_txid unknown at this layer; the legacy caller didn't track it,
     * so pass zeros — consumers tolerate it because it only bumps
     * last_update_txid for audit. */
    if (!znam_projection_emit_update_text(rec->name, rec->key,
                                          rec->value, zero_txid)) {
        fprintf(stderr,  // obs-ok:znam-projection-emit
                "znam projection emit failed for text update\n");
    }
}

static void znam_addr_after_save(void *record, void *ctx)
{
    const struct znam_addr_record *rec = record;
    static const uint8_t zero_txid[32] = {0};

    (void)ctx;
    if (!rec || !znam_projection_event_log())
        return;

    if (!znam_projection_emit_update_addr(rec->name, rec->coin_type,
                                          rec->address, zero_txid)) {
        fprintf(stderr,  // obs-ok:znam-projection-emit
                "znam projection emit failed for addr update\n");
    }
}

static struct ar_callbacks *znam_entry_callbacks_ready(void)
{
    struct ar_callbacks *cbs = db_znam_entry_callbacks();
    static bool hooks_done = false;
    if (!hooks_done) {
        ar_register_after_save(cbs, znam_entry_after_save);
        hooks_done = true;
    }
    return cbs;
}

static struct ar_callbacks *znam_text_callbacks_ready(void)
{
    struct ar_callbacks *cbs = db_znam_text_callbacks();
    static bool hooks_done = false;
    if (!hooks_done) {
        ar_register_after_save(cbs, znam_text_after_save);
        hooks_done = true;
    }
    return cbs;
}

static struct ar_callbacks *znam_addr_callbacks_ready(void)
{
    struct ar_callbacks *cbs = db_znam_addr_callbacks();
    static bool hooks_done = false;
    if (!hooks_done) {
        ar_register_after_save(cbs, znam_addr_after_save);
        hooks_done = true;
    }
    return cbs;
}

bool db_znam_entry_validate(const struct znam_entry *entry,
                            struct ar_errors *errors)
{
    ar_errors_clear(errors);
    if (!entry) {
        ar_errors_add(errors, "entry", "is NULL");
        return false;
    }

    static const uint8_t zero32[32] = {0};

    validates_custom(errors,
        znam_validate_name(entry->name),
        "name", "is not a valid ZNAM name");
    validates_presence_of(errors, entry, owner_address);
    validates_range(errors, entry, target_type,
                    ZNAM_TYPE_ONION, ZNAM_TYPE_CONTENT);
    validates_presence_of(errors, entry, target_value);
    validates_custom(errors,
        strnlen(entry->target_value, ZNAM_VALUE_MAX + 1) <= ZNAM_VALUE_MAX,
        "target_value", "exceeds ZNAM_VALUE_MAX");
    validates_custom(errors,
        memcmp(entry->reg_txid, zero32, 32) != 0,
        "reg_txid", "can't be all zero");
    validates_non_negative(errors, entry, reg_height);
    validates_non_negative(errors, entry, expiry_height);

    return !ar_errors_any(errors);
}

bool db_znam_text_validate(const struct znam_text_record *rec,
                           struct ar_errors *errors)
{
    ar_errors_clear(errors);
    if (!rec) {
        ar_errors_add(errors, "rec", "is NULL");
        return false;
    }

    validates_custom(errors,
        znam_validate_name(rec->name),
        "name", "is not a valid ZNAM name");
    validates_presence_of(errors, rec, key);
    validates_custom(errors,
        strnlen(rec->key, ZNAM_TEXT_KEY_MAX + 1) <= ZNAM_TEXT_KEY_MAX,
        "key", "exceeds ZNAM_TEXT_KEY_MAX");
    /* value may be empty (deletion via empty string) */
    validates_custom(errors,
        strnlen(rec->value, ZNAM_TEXT_VAL_MAX + 1) <= ZNAM_TEXT_VAL_MAX,
        "value", "exceeds ZNAM_TEXT_VAL_MAX");

    return !ar_errors_any(errors);
}

bool db_znam_addr_validate(const struct znam_addr_record *rec,
                           struct ar_errors *errors)
{
    ar_errors_clear(errors);
    if (!rec) {
        ar_errors_add(errors, "rec", "is NULL");
        return false;
    }

    validates_custom(errors,
        znam_validate_name(rec->name),
        "name", "is not a valid ZNAM name");
    validates_range(errors, rec, coin_type,
                    ZNAM_TYPE_ONION, ZNAM_TYPE_CONTENT);
    validates_presence_of(errors, rec, address);
    validates_custom(errors,
        strnlen(rec->address, ZNAM_VALUE_MAX + 1) <= ZNAM_VALUE_MAX,
        "address", "exceeds ZNAM_VALUE_MAX");

    return !ar_errors_any(errors);
}

bool db_znam_save(struct node_db *ndb, const struct znam_entry *entry)
{
    if (!ndb || !ndb->open) LOG_FAIL("znam", "db_znam_save: db not open");
    if (!entry) LOG_FAIL("znam", "db_znam_save: entry is NULL");

    struct ar_callbacks *cbs = znam_entry_callbacks_ready();
    sqlite3_stmt *s = NULL;
    AR_BEGIN_SAVE(cbs, "znam_entry", entry, db_znam_entry_validate);
    AR_PREPARE_BOOL(ndb, s,
        "INSERT OR REPLACE INTO znam_names"
        "(name,owner_address,target_type,target_value,"
        "reg_txid,reg_height,last_update_txid,expiry_height)"
        " VALUES(?,?,?,?,?,?,?,?)");
    AR_BIND_TEXT(s, 1, entry->name);
    AR_BIND_TEXT(s, 2, entry->owner_address);
    AR_BIND_INT(s, 3, entry->target_type);
    AR_BIND_TEXT(s, 4, entry->target_value);
    AR_BIND_BLOB(s, 5, entry->reg_txid, 32);
    AR_BIND_INT(s, 6, entry->reg_height);
    AR_BIND_BLOB(s, 7, entry->last_update_txid, 32);
    AR_BIND_INT(s, 8, entry->expiry_height);

    bool ok = false;
    AR_FINALIZE_STEP_DONE(s, ok);
    AR_FINISH_SAVE(cbs, entry, ok);
}

static bool row_to_znam(sqlite3_stmt *s, struct znam_entry *out)
{
    memset(out, 0, sizeof(*out));
    const char *name = (const char *)sqlite3_column_text(s, 0);
    if (name) snprintf(out->name, sizeof(out->name), "%s", name);

    const char *owner = (const char *)sqlite3_column_text(s, 1);
    if (owner) snprintf(out->owner_address, sizeof(out->owner_address),
                        "%s", owner);

    out->target_type = (uint8_t)sqlite3_column_int(s, 2);

    const char *val = (const char *)sqlite3_column_text(s, 3);
    if (val) snprintf(out->target_value, sizeof(out->target_value),
                      "%s", val);

    if (!read_znam_blob(s, 4, out->reg_txid, 32, "znam_names", "reg_txid"))
        LOG_FAIL("znam", "znam_names.reg_txid rejected");

    out->reg_height = (int32_t)sqlite3_column_int(s, 5);

    if (!read_znam_blob(s, 6, out->last_update_txid, 32, "znam_names",
                        "last_update_txid"))
        LOG_FAIL("znam", "znam_names.last_update_txid rejected");

    out->expiry_height = (int32_t)sqlite3_column_int(s, 7);
    return true;
}

bool db_znam_find(struct node_db *ndb, const char *name,
                  struct znam_entry *out)
{
    if (!ndb || !ndb->open) return false;
    if (!name || !out) return false;

    sqlite3_stmt *s = NULL;
    AR_QUERY_ONE_BOOL(ndb, s,
        "SELECT name,owner_address,target_type,target_value,"
        "reg_txid,reg_height,last_update_txid,expiry_height"
        " FROM znam_names WHERE name=?",
        AR_BIND_TEXT(s, 1, name),
        if (!row_to_znam(s, out)) { AR_FINALIZE(s); return false; });
}

int db_znam_find_by_reg_txid(struct node_db *ndb, const uint8_t reg_txid[32],
                            struct znam_entry *out)
{
    sqlite3_stmt *s = NULL;
    int rc;

    if (!ndb || !ndb->open || !reg_txid || !out)
        LOG_RETURN(-1, "znam", "db_znam_find_by_reg_txid: invalid input");
    if (sqlite3_prepare_v2(
            ndb->db,
            "SELECT name,owner_address,target_type,target_value,"
            "reg_txid,reg_height,last_update_txid,expiry_height"
            " FROM znam_names WHERE reg_txid=? LIMIT 1",
            -1, &s, NULL) != SQLITE_OK || !s)
        LOG_RETURN(-1, "znam", "db_znam_find_by_reg_txid: prepare failed: %s",
                   sqlite3_errmsg(ndb->db));
    AR_BIND_BLOB(s, 1, reg_txid, 32);
    rc = AR_STEP_ROW_READONLY(s);
    if (rc == SQLITE_ROW) {
        bool ok = row_to_znam(s, out);
        AR_FINALIZE(s);
        return ok ? 1 : -1;
    }
    AR_FINALIZE(s);
    if (rc == SQLITE_DONE)
        return 0;
    LOG_RETURN(-1, "znam", "db_znam_find_by_reg_txid: step failed: %s",
               sqlite3_errmsg(ndb->db));
}

bool db_znam_count(struct node_db *ndb, size_t *count_out)
{
    sqlite3_stmt *s = NULL;
    int rc;

    if (count_out)
        *count_out = 0;
    if (!ndb || !ndb->open || !count_out)
        LOG_FAIL("znam", "db_znam_count: invalid input");
    if (sqlite3_prepare_v2(ndb->db, "SELECT COUNT(*) FROM znam_names", -1,
                           &s, NULL) != SQLITE_OK || !s)
        LOG_FAIL("znam", "db_znam_count: prepare failed: %s",
                 sqlite3_errmsg(ndb->db));
    rc = AR_STEP_ROW_READONLY(s);
    if (rc != SQLITE_ROW || sqlite3_column_int64(s, 0) < 0) {
        AR_FINALIZE(s);
        LOG_FAIL("znam", "db_znam_count: step failed: %s",
                 sqlite3_errmsg(ndb->db));
    }
    *count_out = (size_t)sqlite3_column_int64(s, 0);
    AR_FINALIZE(s);
    return true;
}

int db_znam_list(struct node_db *ndb, struct znam_entry *out, size_t max)
{
    if (!ndb || !ndb->open) return 0;
    if (!out && max > 0)
        LOG_RETURN(0, "znam", "db_znam_list: out is NULL");

    sqlite3_stmt *s = NULL;
    AR_QUERY_LIST(ndb, s,
        "SELECT name,owner_address,target_type,target_value,"
        "reg_txid,reg_height,last_update_txid,expiry_height"
        " FROM znam_names ORDER BY reg_height DESC LIMIT ?",
        out, max,
        AR_BIND_INT(s, 1, (int)max),
        if (!row_to_znam(s, &out[count])) continue);
}

int db_znam_list_by_owner(struct node_db *ndb, const char *owner,
                          struct znam_entry *out, size_t max)
{
    if (!ndb || !ndb->open) return 0;
    if (!owner) return 0;
    if (!out && max > 0)
        LOG_RETURN(0, "znam", "db_znam_list_by_owner: out is NULL");

    sqlite3_stmt *s = NULL;
    AR_QUERY_LIST(ndb, s,
        "SELECT name,owner_address,target_type,target_value,"
        "reg_txid,reg_height,last_update_txid,expiry_height"
        " FROM znam_names WHERE owner_address=? ORDER BY name LIMIT ?",
        out, max,
        AR_BIND_TEXT(s, 1, owner);
        AR_BIND_INT(s, 2, (int)max),
        if (!row_to_znam(s, &out[count])) continue);
}

/* ── Wallet-wide sweep ─────────────────────────────────────────────────
 *
 * znam_names.owner_address is the Base58Check address TEXT an on-chain
 * REGISTER named, while the wallet stores 20-byte hash160 keys — so unlike
 * the ZSLP ledger there is no blob to join on and the wallet's addresses
 * have to be rendered into that text form first. Rendering is one-way and
 * cheap (a keypool is hundreds of entries, and each owner lookup rides the
 * idx_znam_owner index), so the sweep encodes once and then asks the
 * registry per owner rather than materializing the whole registry. */

/* Upper bound on wallet addresses folded by one sweep. A keypool is two
 * orders of magnitude below this; the cap exists so a pathological wallet
 * bounds the scratch allocation instead of the allocation bounding the
 * node. */
#define ZNAM_WALLET_ADDRESS_MAX 4096

typedef char znam_address_text[64]; /* matches znam_entry.owner_address */

/* Base58Check-encode a wallet pubkey hash as this chain's P2PKH address.
 * False when chain params are not selected yet (a pre-boot caller) or the
 * encoding does not fit — either way the address contributes nothing and
 * the sweep simply folds one fewer address. */
static bool znam_encode_wallet_p2pkh(const uint8_t hash160[20],
                                     znam_address_text out)
{
    const struct chain_params *cp = chain_params_get();
    if (!cp)
        LOG_FAIL("znam", "wallet sweep: chain params not selected");

    size_t pk_len = 0;
    size_t sc_len = 0;
    const unsigned char *pk_pfx =
        chain_params_base58_prefix(cp, B58_PUBKEY_ADDRESS, &pk_len);
    const unsigned char *sc_pfx =
        chain_params_base58_prefix(cp, B58_SCRIPT_ADDRESS, &sc_len);

    struct tx_destination dest;
    memset(&dest, 0, sizeof(dest));
    dest.type = DEST_KEY_ID;
    memcpy(dest.id.key.id.data, hash160, 20);
    if (!encode_destination(&dest, pk_pfx, pk_len, sc_pfx, sc_len,
                            out, sizeof(znam_address_text)))
        LOG_FAIL("znam", "wallet sweep: address encoding overflowed");
    return true;
}

/* Append `addr` unless it is already present. The registry keys a name on
 * exactly one owner, so a duplicate address would list the same name twice
 * (a wallet that imported its own key as watch-only is the ordinary way to
 * get one). */
static bool znam_addr_append_unique(znam_address_text *list, int *count,
                                    int cap, const char *addr)
{
    if (!addr || !addr[0] || *count >= cap)
        return false;
    for (int i = 0; i < *count; i++) {
        if (strcmp(list[i], addr) == 0)
            return false;
    }
    snprintf(list[*count], sizeof(znam_address_text), "%s", addr);
    (*count)++;
    return true;
}

/* Every transparent address this wallet could own a name at: wallet_keys'
 * hashes encoded as P2PKH, plus wallet_watch_only's stored address text
 * verbatim (a watch-only entry may be a P2SH whose hash is a script hash,
 * so re-encoding it as P2PKH would invent an address the wallet does not
 * have). Returns how many were written. */
static int znam_wallet_addresses(struct node_db *ndb, znam_address_text *out,
                                 int max)
{
    int count = 0;
    sqlite3_stmt *s = NULL;

    AR_PREPARE_RET(ndb, s, "SELECT pubkey_hash FROM wallet_keys", count);
    while (count < max && AR_STEP_ROW(s)) {
        if (AR_COL_BYTES(s, 0) != 20)
            continue;
        uint8_t hash160[20];
        AR_READ_BLOB(s, 0, hash160, 20);
        znam_address_text addr;
        if (znam_encode_wallet_p2pkh(hash160, addr))
            (void)znam_addr_append_unique(out, &count, max, addr);
    }
    AR_FINALIZE(s);

    AR_PREPARE_RET(ndb, s, "SELECT address FROM wallet_watch_only", count);
    while (count < max && AR_STEP_ROW(s))
        (void)znam_addr_append_unique(out, &count, max, AR_COL_TEXT(s, 0));
    AR_FINALIZE(s);

    return count;
}

int db_znam_list_wallet_owned(struct node_db *ndb, struct znam_entry *out,
                              size_t max)
{
    if (!ndb || !ndb->open) return 0;
    if (!out && max > 0)
        LOG_RETURN(0, "znam", "db_znam_list_wallet_owned: out is NULL");
    if (max == 0) return 0;

    znam_address_text *addrs =
        zcl_malloc(sizeof(znam_address_text) * ZNAM_WALLET_ADDRESS_MAX,
                   "znam_wallet_addresses");
    if (!addrs)
        LOG_RETURN(0, "znam",
                   "db_znam_list_wallet_owned: address buffer alloc failed "
                   "(%d entries)", ZNAM_WALLET_ADDRESS_MAX);

    int num_addrs = znam_wallet_addresses(ndb, addrs, ZNAM_WALLET_ADDRESS_MAX);

    int count = 0;
    if (num_addrs > 0) {
        sqlite3_stmt *s = NULL;
        if (sqlite3_prepare_v2(ndb->db,
                "SELECT name,owner_address,target_type,target_value,"
                "reg_txid,reg_height,last_update_txid,expiry_height"
                " FROM znam_names WHERE owner_address=? ORDER BY name",
                -1, &s, NULL) != SQLITE_OK || !s) {
            free(addrs);
            LOG_RETURN(0, "znam",
                       "db_znam_list_wallet_owned: prepare failed: %s",
                       sqlite3_errmsg(ndb->db));
        }
        for (int i = 0; i < num_addrs && (size_t)count < max; i++) {
            sqlite3_reset(s);
            sqlite3_clear_bindings(s);
            AR_BIND_TEXT(s, 1, addrs[i]);
            while ((size_t)count < max && AR_STEP_ROW(s)) {
                memset(&out[count], 0, sizeof(out[count]));
                if (!row_to_znam(s, &out[count]))
                    continue;
                count++;
            }
        }
        AR_FINALIZE(s);
    }

    free(addrs);
    return count;
}

int db_znam_wallet_address_count(struct node_db *ndb)
{
    if (!ndb || !ndb->open) return 0;

    znam_address_text *addrs =
        zcl_malloc(sizeof(znam_address_text) * ZNAM_WALLET_ADDRESS_MAX,
                   "znam_wallet_addresses");
    if (!addrs)
        LOG_RETURN(0, "znam",
                   "db_znam_wallet_address_count: alloc failed (%d entries)",
                   ZNAM_WALLET_ADDRESS_MAX);
    int n = znam_wallet_addresses(ndb, addrs, ZNAM_WALLET_ADDRESS_MAX);
    free(addrs);
    return n;
}

bool db_znam_text_save(struct node_db *ndb, const char *name,
                       const char *key, const char *value)
{
    if (!ndb || !ndb->open) LOG_FAIL("znam", "db_znam_text_save: db not open");
    if (!name || !key) LOG_FAIL("znam", "db_znam_text_save: name/key NULL");

    struct znam_text_record rec;
    memset(&rec, 0, sizeof(rec));
    snprintf(rec.name, sizeof(rec.name), "%s", name);
    snprintf(rec.key, sizeof(rec.key), "%s", key);
    if (value) snprintf(rec.value, sizeof(rec.value), "%s", value);

    struct ar_callbacks *cbs = znam_text_callbacks_ready();
    sqlite3_stmt *s = NULL;
    AR_BEGIN_SAVE(cbs, "znam_text", &rec, db_znam_text_validate);
    AR_PREPARE_BOOL(ndb, s,
        "INSERT OR REPLACE INTO znam_text_records(name,key,value)"
        " VALUES(?,?,?)");
    AR_BIND_TEXT(s, 1, rec.name);
    AR_BIND_TEXT(s, 2, rec.key);
    AR_BIND_TEXT(s, 3, rec.value);

    bool ok = false;
    AR_FINALIZE_STEP_DONE(s, ok);
    AR_FINISH_SAVE(cbs, &rec, ok);
}

bool db_znam_text_get(struct node_db *ndb, const char *name,
                      const char *key, char *value_out, size_t max)
{
    if (!ndb || !ndb->open) return false;
    if (!name || !key || !value_out || max == 0) return false;

    sqlite3_stmt *s = NULL;
    AR_QUERY_ONE_BOOL(ndb, s,
        "SELECT value FROM znam_text_records WHERE name=? AND key=?",
        AR_BIND_TEXT(s, 1, name);
        AR_BIND_TEXT(s, 2, key),
        const char *v = (const char *)sqlite3_column_text(s, 0);
        if (v) snprintf(value_out, max, "%s", v));
}

static void row_to_znam_text(sqlite3_stmt *s, struct znam_text_record *out)
{
    memset(out, 0, sizeof(*out));
    const char *n = (const char *)sqlite3_column_text(s, 0);
    if (n) snprintf(out->name, sizeof(out->name), "%s", n);
    const char *k = (const char *)sqlite3_column_text(s, 1);
    if (k) snprintf(out->key, sizeof(out->key), "%s", k);
    const char *v = (const char *)sqlite3_column_text(s, 2);
    if (v) snprintf(out->value, sizeof(out->value), "%s", v);
}

int db_znam_text_list(struct node_db *ndb, const char *name,
                      struct znam_text_record *out, size_t max)
{
    if (!ndb || !ndb->open) return 0;
    if (!name) return 0;
    if (!out && max > 0)
        LOG_RETURN(0, "znam", "db_znam_text_list: out is NULL");

    sqlite3_stmt *s = NULL;
    AR_QUERY_LIST(ndb, s,
        "SELECT name,key,value FROM znam_text_records"
        " WHERE name=? ORDER BY key LIMIT ?",
        out, max,
        AR_BIND_TEXT(s, 1, name);
        AR_BIND_INT(s, 2, (int)max),
        row_to_znam_text(s, &out[count]));
}

int db_znam_text_count(struct node_db *ndb, const char *name)
{
    if (!ndb || !ndb->open)
        LOG_RETURN(-1, "znam", "db_znam_text_count: db not open");
    if (!name) LOG_RETURN(-1, "znam", "db_znam_text_count: name NULL");

    sqlite3_stmt *s = NULL;
    int64_t count = 0;
    AR_PREPARE_RET(ndb, s,
        "SELECT count(*) FROM znam_text_records WHERE name=?", -1);
    AR_BIND_TEXT(s, 1, name);
    int step_rc = ZNAM_COUNT_STEP(s);
    if (step_rc != SQLITE_ROW) {
        AR_FINALIZE(s);
        LOG_RETURN(-1, "znam",
                   "db_znam_text_count: count step failed rc=%d: %s",
                   step_rc, sqlite3_errmsg(ndb->db));
    }
    count = sqlite3_column_int64(s, 0);
    AR_FINALIZE(s);
    return count > INT_MAX ? INT_MAX : (int)count;
}

bool db_znam_addr_save(struct node_db *ndb, const char *name,
                       uint8_t coin_type, const char *address)
{
    if (!ndb || !ndb->open) LOG_FAIL("znam", "db_znam_addr_save: db not open");
    if (!name || !address)
        LOG_FAIL("znam", "db_znam_addr_save: name/address NULL");

    struct znam_addr_record rec;
    memset(&rec, 0, sizeof(rec));
    snprintf(rec.name, sizeof(rec.name), "%s", name);
    rec.coin_type = coin_type;
    snprintf(rec.address, sizeof(rec.address), "%s", address);

    struct ar_callbacks *cbs = znam_addr_callbacks_ready();
    sqlite3_stmt *s = NULL;
    AR_BEGIN_SAVE(cbs, "znam_addr", &rec, db_znam_addr_validate);
    AR_PREPARE_BOOL(ndb, s,
        "INSERT OR REPLACE INTO znam_addr_records(name,coin_type,address)"
        " VALUES(?,?,?)");
    AR_BIND_TEXT(s, 1, rec.name);
    AR_BIND_INT(s, 2, rec.coin_type);
    AR_BIND_TEXT(s, 3, rec.address);

    bool ok = false;
    AR_FINALIZE_STEP_DONE(s, ok);
    AR_FINISH_SAVE(cbs, &rec, ok);
}

bool db_znam_addr_get(struct node_db *ndb, const char *name,
                      uint8_t coin_type, char *addr_out, size_t max)
{
    if (!ndb || !ndb->open) return false;
    if (!name || !addr_out || max == 0) return false;

    sqlite3_stmt *s = NULL;
    AR_QUERY_ONE_BOOL(ndb, s,
        "SELECT address FROM znam_addr_records WHERE name=? AND coin_type=?",
        AR_BIND_TEXT(s, 1, name);
        AR_BIND_INT(s, 2, coin_type),
        const char *a = (const char *)sqlite3_column_text(s, 0);
        if (a) snprintf(addr_out, max, "%s", a));
}

static void row_to_znam_addr(sqlite3_stmt *s, struct znam_addr_record *out)
{
    memset(out, 0, sizeof(*out));
    const char *n = (const char *)sqlite3_column_text(s, 0);
    if (n) snprintf(out->name, sizeof(out->name), "%s", n);
    out->coin_type = (uint8_t)sqlite3_column_int(s, 1);
    const char *a = (const char *)sqlite3_column_text(s, 2);
    if (a) snprintf(out->address, sizeof(out->address), "%s", a);
}

int db_znam_addr_list(struct node_db *ndb, const char *name,
                      struct znam_addr_record *out, size_t max)
{
    if (!ndb || !ndb->open) return 0;
    if (!name) return 0;
    if (!out && max > 0)
        LOG_RETURN(0, "znam", "db_znam_addr_list: out is NULL");

    sqlite3_stmt *s = NULL;
    AR_QUERY_LIST(ndb, s,
        "SELECT name,coin_type,address FROM znam_addr_records"
        " WHERE name=? ORDER BY coin_type LIMIT ?",
        out, max,
        AR_BIND_TEXT(s, 1, name);
        AR_BIND_INT(s, 2, (int)max),
        row_to_znam_addr(s, &out[count]));
}

int db_znam_addr_count(struct node_db *ndb, const char *name)
{
    if (!ndb || !ndb->open)
        LOG_RETURN(-1, "znam", "db_znam_addr_count: db not open");
    if (!name) LOG_RETURN(-1, "znam", "db_znam_addr_count: name NULL");

    sqlite3_stmt *s = NULL;
    int64_t count = 0;
    AR_PREPARE_RET(ndb, s,
        "SELECT count(*) FROM znam_addr_records WHERE name=?", -1);
    AR_BIND_TEXT(s, 1, name);
    int step_rc = ZNAM_COUNT_STEP(s);
    if (step_rc != SQLITE_ROW) {
        AR_FINALIZE(s);
        LOG_RETURN(-1, "znam",
                   "db_znam_addr_count: count step failed rc=%d: %s",
                   step_rc, sqlite3_errmsg(ndb->db));
    }
    count = sqlite3_column_int64(s, 0);
    AR_FINALIZE(s);
    return count > INT_MAX ? INT_MAX : (int)count;
}
