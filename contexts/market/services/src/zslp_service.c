// one-result-type-ok:alphanumeric-hex-classifiers — zslp_service_is_
// alphanumeric and zslp_service_is_hex_string are the file's only
// remaining bare-bool exports: pure character-class scans with no
// LOG_FAIL/LOG_ERR path and no failure state to represent (struct
// zcl_result would always report OK). zslp_service_validate_token_key,
// zslp_service_decode_transparent_destination, and zslp_service_
// validate_recipient_addr — the genuinely fallible validators in this
// file, each with a distinct LOG_FAIL-guarded error branch — already
// return struct zcl_result.

/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * ZSLP application service — validation and persistence helpers. */

#include "services/zslp_service.h"
#include "adapters/outbound/persistence/zslp_store_sqlite.h"
#include "ports/zslp_store_port.h"
#include "config/runtime.h"
#include "models/database.h"
#include "models/wallet_tx.h"
#include "models/zslp.h"
#include "chain/chainparams.h"
#include "keys/key_io.h"
#include "sapling/address.h"
#include "sapling/constants.h"
#include "script/standard.h"
#include "util/log_macros.h"
#include "wallet/wallet.h"
#include <ctype.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>

#define ZSLP_MAX_TOKEN_KEY_LEN 64
#define ZSLP_MAX_TICKER_LEN 10
#define ZSLP_MAX_NAME_LEN 64
#define ZSLP_MAX_DECIMALS 8
#define ZSLP_MAX_SUPPLY 2100000000000000ULL

static void zslp_service_canonicalize_token_key(const char *src,
                                                char dest[ZSLP_MAX_TOKEN_KEY_LEN + 1])
{
    size_t i = 0;
    if (!dest)
        return;
    dest[0] = '\0';
    if (!src)
        return;
    for (; src[i] && i < ZSLP_MAX_TOKEN_KEY_LEN; i++)
        dest[i] = (char)toupper((unsigned char)src[i]);
    dest[i] = '\0';
}

static void zslp_service_wrap_sqlite(sqlite3 *db, struct node_db *ndb)
{
    memset(ndb, 0, sizeof(*ndb));
    ndb->db = db;
    ndb->open = (db != NULL);
}

bool zslp_service_is_alphanumeric(const char *str, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        if (!isalnum((unsigned char)str[i]))
            return false;  // raw-return-ok:plain-predicate-not-a-fallible-call
    }
    return true;
}

bool zslp_service_is_hex_string(const char *str, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        if (!isxdigit((unsigned char)str[i]))
            return false;  // raw-return-ok:plain-predicate-not-a-fallible-call
    }
    return true;
}

struct zcl_result zslp_service_validate_token_key(const char *token_key)
{
    size_t len;
    if (!token_key)
        return ZCL_ERR(-1, "validate_token_key: NULL token_key");
    len = strlen(token_key);
    if (len == 0 || len > ZSLP_MAX_TOKEN_KEY_LEN)
        return ZCL_ERR(-2, "validate_token_key: bad length %zu", len);

    /* Canonical full-txid form: exactly 64 hex chars. Always accepted. */
    if (len == 64 && zslp_service_is_hex_string(token_key, len))
        return ZCL_OK;

    /* All other keys must be alphanumeric. */
    if (!zslp_service_is_alphanumeric(token_key, len))
        return ZCL_ERR(-3, "validate_token_key: not alphanumeric: %s",
                       token_key);

    /* disambiguate ticker-style token IDs from truncated hex txid
     * prefixes. A string that is ALL hex digits ([0-9a-fA-F]) at any
     * length < 64 is indistinguishable from the first `len` chars of a
     * real txid, and both canonicalize (upper-cased) to the same key —
     * so a short/all-hex lookup can collide with a full txid key.
     * Legitimate ticker-style keys in this codebase contain at least
     * one non-hex alphanumeric character (e.g., "ZCL", "BTC",
     * "ZCL23ACCESS"). The narrow compat break: tickers that are purely
     * hex digits (e.g., "CAFE", "DEAD") can no longer be used as short
     * token-key lookups; those tokens must be referenced by their
     * 64-char txid instead. */
    if (zslp_service_is_hex_string(token_key, len))
        return ZCL_ERR(-4,
                       "validate_token_key: ambiguous hex-only ticker "
                       "(use the 64-char txid instead): %s", token_key);

    return ZCL_OK;
}

struct zcl_result zslp_service_decode_transparent_destination(
    const char *addr, struct tx_destination *dest)
{
    const struct chain_params *cp;
    size_t pk_len = 0, sc_len = 0;
    const unsigned char *pk_pfx;
    const unsigned char *sc_pfx;

    if (!addr || !dest)
        return ZCL_ERR(-1,
                       "decode_transparent_destination: NULL addr or dest");

    cp = chain_params_get();
    pk_pfx = chain_params_base58_prefix(cp, B58_PUBKEY_ADDRESS, &pk_len);
    sc_pfx = chain_params_base58_prefix(cp, B58_SCRIPT_ADDRESS, &sc_len);
    if (!decode_destination(addr, pk_pfx, pk_len, sc_pfx, sc_len, dest))
        return ZCL_ERR(-2,
                       "decode_transparent_destination: invalid address %s",
                       addr);
    return ZCL_OK;
}

struct zcl_result zslp_service_validate_recipient_addr(const char *addr,
                                          bool strict_chain_addr)
{
    size_t len;
    struct tx_destination dest;

    if (!addr)
        return ZCL_ERR(-1, "validate_recipient_addr: NULL addr");
    len = strlen(addr);
    if (len == 0 || len > 128)
        return ZCL_ERR(-2, "validate_recipient_addr: bad length %zu", len);
    if (strict_chain_addr)
        return zslp_service_decode_transparent_destination(addr, &dest);
    if (zslp_service_is_alphanumeric(addr, len))
        return ZCL_OK;
    return zslp_service_decode_transparent_destination(addr, &dest);
}

const char *zslp_service_validate_create_request(
    const struct zslp_token_create_request *req)
{
    size_t ticker_len, name_len;

    if (!req)
        return "request is required";
    if (!req->ticker || !req->name)
        return "ticker and name are required";

    ticker_len = strlen(req->ticker);
    if (ticker_len == 0 || ticker_len > ZSLP_MAX_TICKER_LEN)
        return "ticker must be 1-10 alphanumeric characters";
    if (!zslp_service_is_alphanumeric(req->ticker, ticker_len))
        return "ticker must be alphanumeric";

    name_len = strlen(req->name);
    if (name_len == 0 || name_len > ZSLP_MAX_NAME_LEN)
        return "name must be 1-64 printable characters";
    if (!zslp_service_is_alphanumeric(req->name, name_len) &&
        strspn(req->name,
               "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 -_./")
            != name_len)
        return "name contains unsupported characters";

    if (req->decimals > ZSLP_MAX_DECIMALS)
        return "decimals must be between 0 and 8";
    if (req->initial_supply > ZSLP_MAX_SUPPLY)
        return "initial supply exceeds maximum";
    return NULL;
}

const char *zslp_service_validate_transfer_request(
    const struct zslp_token_transfer_request *req)
{
    if (!req)
        return "request is required";
    if (!zslp_service_validate_token_key(req->token_id).ok)
        return "token_id must be alphanumeric or 64-char hex";
    if (!zslp_service_validate_recipient_addr(req->recipient_addr,
                                              req->strict_chain_addr).ok)
        return "address is invalid";
    if (req->amount == 0)
        return "amount must be a positive integer";
    if (req->amount > (uint64_t)INT64_MAX)
        return "amount exceeds supported maximum";
    return NULL;
}

struct zcl_result zslp_service_open_db(const char *datadir, sqlite3 **db_out,
                                       bool *owns_db)
{
    struct node_db *ndb = app_runtime_node_db();
    struct zslp_store_port store = {0};
    void *opened = NULL;

    if (!db_out || !owns_db)
        return ZCL_ERR(-1, "open_db: NULL output pointer");
    *db_out = NULL;
    *owns_db = false;

    if (ndb && ndb->open && ndb->db) {
        *db_out = ndb->db;
        return ZCL_OK;
    }
    if (!datadir)
        return ZCL_ERR(-2, "open_db: NULL datadir and no runtime db");

    /* No in-process runtime connection: acquire a fresh, owned connection
     * to "<datadir>/node.db" through the zslp_store port. The adapter under
     * platform/adapters/outbound/persistence/ is the only thing that names sqlite —
     * same open, busy timeout, and zslp_balances DDL as the inline code. */
    zslp_store_sqlite_bind(&store);
    if (!store.open(store.self, datadir, &opened)) {
        char db_path[1024];
        snprintf(db_path, sizeof(db_path), "%s/node.db", datadir);
        return ZCL_ERR(-3, "open_db: sqlite3_open failed for %s", db_path);
    }
    *db_out = (sqlite3 *)opened;
    *owns_db = true;
    return ZCL_OK;
}

void zslp_service_close_db(sqlite3 *db, bool owns_db)
{
    if (owns_db && db) {
        struct zslp_store_port store = {0};
        zslp_store_sqlite_bind(&store);
        store.close(store.self, db);
    }
}

uint64_t zslp_service_get_balance(sqlite3 *db, const char *token_id,
                                  const char *addr)
{
    struct node_db ndb;
    struct db_zslp_balance balance;
    char token_key[ZSLP_MAX_TOKEN_KEY_LEN + 1];

    if (!db || !zslp_service_validate_token_key(token_id).ok ||
        !zslp_service_validate_recipient_addr(addr, false).ok)
        return 0;

    zslp_service_canonicalize_token_key(token_id, token_key);
    zslp_service_wrap_sqlite(db, &ndb);
    if (!db_zslp_balance_find(&ndb, token_key, addr, &balance))
        return 0;
    return balance.balance < 0 ? 0 : (uint64_t)balance.balance;
}

struct zcl_result zslp_service_get_token(sqlite3 *db, const char *token_id,
                                         struct db_zslp_token_info *out)
{
    struct node_db ndb;
    char token_key[ZSLP_MAX_TOKEN_KEY_LEN + 1];

    if (!db || !out || !zslp_service_validate_token_key(token_id).ok)
        return ZCL_ERR(-1,
                 "get_token: invalid args (db=%p out=%p token_id=%s)",
                 (void *)db, (void *)out, token_id ? token_id : "NULL");

    zslp_service_canonicalize_token_key(token_id, token_key);
    zslp_service_wrap_sqlite(db, &ndb);
    if (!db_zslp_token_find(&ndb, token_key, out))
        return ZCL_ERR(-2, "get_token: token not found: %s", token_key);
    return ZCL_OK;
}

int zslp_service_list_tokens(sqlite3 *db, struct db_zslp_token_info *out,
                             size_t max_out)
{
    struct node_db ndb;

    if (!db || !out || max_out == 0)
        return 0;

    zslp_service_wrap_sqlite(db, &ndb);
    return db_zslp_token_list(&ndb, out, max_out);
}

int zslp_service_list_transfers(sqlite3 *db, const char *token_id,
                                struct db_zslp_transfer_info *out,
                                size_t max_out)
{
    struct node_db ndb;
    char token_key[ZSLP_MAX_TOKEN_KEY_LEN + 1];

    if (!db || !out || max_out == 0 ||
        !zslp_service_validate_token_key(token_id).ok)
        return 0;

    zslp_service_canonicalize_token_key(token_id, token_key);
    zslp_service_wrap_sqlite(db, &ndb);
    return db_zslp_transfer_list_by_token(&ndb, token_key, out, max_out);
}

struct zcl_result zslp_service_credit_balance(sqlite3 *db, const char *token_id,
                                              const char *recipient_addr,
                                              uint64_t amount)
{
    struct node_db ndb;
    char token_key[ZSLP_MAX_TOKEN_KEY_LEN + 1];

    if (!db || amount == 0 || !zslp_service_validate_token_key(token_id).ok ||
        !zslp_service_validate_recipient_addr(recipient_addr, false).ok)
        return ZCL_ERR(-1,
                 "credit_balance: invalid args (token=%s addr=%s amount=%llu)",
                 token_id ? token_id : "NULL", recipient_addr ? recipient_addr : "NULL",
                 (unsigned long long)amount);
    if (amount > (uint64_t)INT64_MAX)
        return ZCL_ERR(-2, "credit_balance: amount %llu exceeds INT64_MAX",
                 (unsigned long long)amount);
    zslp_service_canonicalize_token_key(token_id, token_key);
    zslp_service_wrap_sqlite(db, &ndb);
    if (!db_zslp_balance_credit(&ndb, token_key, recipient_addr, (int64_t)amount))
        return ZCL_ERR(-3, "credit_balance: db_zslp_balance_credit failed for token=%s",
                 token_key);
    return ZCL_OK;
}

struct zcl_result zslp_service_store_token(sqlite3 *db, const char *token_id,
                                           const char *ticker, const char *name,
                                           int decimals, int64_t initial_supply)
{
    struct node_db ndb;
    char token_key[ZSLP_MAX_TOKEN_KEY_LEN + 1];

    if (!db || !token_id || !ticker || !name)
        return ZCL_ERR(-1, "store_token: NULL argument (db=%p token_id=%s)",
                 (void *)db, token_id ? token_id : "NULL");

    zslp_service_canonicalize_token_key(token_id, token_key);
    zslp_service_wrap_sqlite(db, &ndb);
    if (!db_zslp_token_save_key(&ndb, token_key, ticker, name, decimals,
                                "", 0, initial_supply))
        return ZCL_ERR(-2, "store_token: db_zslp_token_save_key failed for %s",
                 token_key);
    return ZCL_OK;
}

struct zcl_result zslp_payment_generate_address(struct wallet *wallet,
                                                char *z_addr_out, size_t max)
{
    if (!z_addr_out || max < 80)
        return ZCL_ERR(-1,
                 "generate_address: NULL output or max too small (%zu)", max);

    /* A payment z-address MUST be a real, decryptable merchant Sapling
     * address. There is NO synthetic fallback: an order that binds to a
     * fake address can never be matched/decrypted, so the payment is lost.
     *
     * The merchant's keystore must already hold a deterministic seed (set
     * from the persisted wallet). We deliberately refuse an UNSEEDED
     * keystore even though sapling_keystore_new_address() would lazily mint
     * a *random* seed on the spot: that random seed is never persisted, so
     * the resulting address is unrecoverable after a restart and the
     * payment would be lost just like a synthetic placeholder. Fail loudly
     * so the caller refuses to create the order (store_controller serves a
     * 503) instead of binding to an unrecoverable address. */
    if (!wallet || !wallet->sapling_keys.has_seed) {
        z_addr_out[0] = '\0';
        return ZCL_ERR(-2,
            "generate_address: no seeded Sapling keystore "
            "(wallet=%p has_seed=%d num_keys=%zu) — refusing to mint an "
            "unrecoverable address",
            (const void *)wallet,
            wallet ? (int)wallet->sapling_keys.has_seed : 0,
            wallet ? (size_t)wallet->sapling_keys.num_keys : (size_t)0);
    }

    uint8_t diversifier[ZC_DIVERSIFIER_SIZE];
    uint8_t pk_d[32];
    const struct chain_params *cp = chain_params_get();

    if (!sapling_keystore_new_address(&wallet->sapling_keys,
                                      diversifier, pk_d)) {
        z_addr_out[0] = '\0';
        return ZCL_ERR(-3,
            "generate_address: sapling_keystore_new_address failed");
    }
    if (!sapling_encode_payment_address(diversifier, pk_d,
            cp->bech32HRPs[BECH32_SAPLING_PAYMENT_ADDRESS],
            z_addr_out, max)) {
        z_addr_out[0] = '\0';
        return ZCL_ERR(-4,
            "generate_address: sapling_encode_payment_address failed");
    }
    return ZCL_OK;
}

int64_t zslp_payment_check_received(const char *datadir,
                                    const char *z_addr,
                                    int64_t min_amount)
{
    struct node_db ndb;
    char db_path[1024];
    int64_t received = 0;

    if (!datadir || !z_addr)
        return 0;

    memset(&ndb, 0, sizeof(ndb));
    snprintf(db_path, sizeof(db_path), "%s/node.db", datadir);
    if (!node_db_open_runtime(&ndb, db_path, "zslp.payment_check"))
        return 0;

    received = db_sapling_note_balance_for_address(&ndb, z_addr);

    if (received < min_amount && min_amount > 0) {
        received = db_sapling_note_balance_for_exact_value(&ndb, min_amount);
    }

    node_db_close(&ndb);
    return received;
}
