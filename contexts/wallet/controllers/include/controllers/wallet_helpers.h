/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#ifndef ZCL_CONTROLLERS_WALLET_HELPERS_H
#define ZCL_CONTROLLERS_WALLET_HELPERS_H

#include "rpc/server.h"
#include "util/result.h"
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

struct wallet;
struct main_state;
struct wallet_sqlite;
struct tx_mempool;
struct connman;
struct node_db;
struct coins_view_cache;
struct json_value;
struct transaction;
struct wallet_tx;
struct db_wallet_tx;
struct tx_destination;

struct wallet_rpc_context {
    struct wallet *wallet;
    struct main_state *main_state;
    char datadir_storage[4096];
    const char *datadir;
    struct wallet_sqlite *wallet_db;
    struct tx_mempool *mempool;
    struct connman *connman;
    struct node_db *node_db;
    struct coins_view_cache *coins_tip;
};

/* Shared wallet controller state.
 * This centralizes wallet-controller composition in one context object. */
extern struct wallet_rpc_context g_wallet_ctx;

static inline struct wallet_rpc_context *wallet_rpc_context_current(void)
{
    return &g_wallet_ctx;
}

static inline struct wallet *wallet_rpc_wallet(void)
{
    return g_wallet_ctx.wallet;
}

static inline struct main_state *wallet_rpc_main_state(void)
{
    return g_wallet_ctx.main_state;
}

static inline const char *wallet_rpc_datadir(void)
{
    return g_wallet_ctx.datadir;
}

static inline struct wallet_sqlite *wallet_rpc_wallet_db(void)
{
    return g_wallet_ctx.wallet_db;
}

static inline struct tx_mempool *wallet_rpc_mempool(void)
{
    return g_wallet_ctx.mempool;
}

static inline struct connman *wallet_rpc_connman(void)
{
    return g_wallet_ctx.connman;
}

static inline struct node_db *wallet_rpc_node_db(void)
{
    return g_wallet_ctx.node_db;
}

static inline struct coins_view_cache *wallet_rpc_coins_tip(void)
{
    return g_wallet_ctx.coins_tip;
}

/* True when the shared node DB is attached and open. Used by every
 * wallet controller to decide between the authoritative SQLite path
 * and the in-memory fallback. Defined in wallet_helpers.c so callers
 * need not pull in the full struct node_db definition. */
bool wallet_ctx_db_ready(const struct wallet_rpc_context *ctx);

/* Transparent spendable balance from the freshest complete wallet view. The
 * finalized in-memory view leads async SQLite projection at the live tip;
 * boot/recovery fixtures with no complete memory view retain the durable DB
 * fallback. */
int64_t wallet_transparent_spendable_balance(
    const struct wallet_rpc_context *ctx);

struct wallet_balance_freshness {
    const char *source;
    bool sources_agree;
    int wallet_height;
    int chain_height;
    size_t memory_confirmed_txs;
    int durable_confirmed_txs;
};

int64_t wallet_transparent_spendable_balance_diagnose(
    const struct wallet_rpc_context *ctx,
    struct wallet_balance_freshness *freshness);

/* Submit a locally-authored transaction through the shared validation gate.
 * This is the only controller-side wallet commit entry point. */
struct zcl_result wallet_commit_from_context(
    const struct wallet_rpc_context *ctx, struct wallet_tx *wtx);

/* Revalidate and restore an already-durable exact transaction to the current
 * mempool without creating another wallet mutation. */
struct zcl_result wallet_reaccept_from_context(
    const struct wallet_rpc_context *ctx, struct wallet_tx *wtx);

/* Flush the in-memory wallet through the node.db single-writer lane. Any
 * open reducer batch is committed first, so wallet_sqlite never starts a
 * nested transaction on the shared SQLite handle. A missing wallet DB is a
 * deliberate in-memory configuration and returns ZCL_OK. */
struct zcl_result wallet_flush_from_context(
    const struct wallet_rpc_context *ctx);

/* Durably flush an admitted wallet transaction before relay. On failure the
 * unrelayed wallet+mempool commit is rolled back. */
struct zcl_result wallet_persist_commit_before_relay(
    const struct wallet_rpc_context *ctx, const struct wallet_tx *wtx);

/* Compensate a transaction that was already flushed but cannot proceed to
 * relay (for example, an atomic shielded-note reservation failed). Removes
 * it from mempool, the in-memory wallet, and wallet_transactions. */
struct zcl_result wallet_rollback_persisted_commit(
    const struct wallet_rpc_context *ctx, const struct wallet_tx *wtx);

#define ENSURE_WALLET(result) do {                        \
    if (!wallet_rpc_wallet()) {                           \
        json_set_str((result), "Wallet not available");   \
        return false;                                     \
    }                                                     \
} while (0)

void wallet_rpc_context_set_base(struct wallet *wallet,
                                 struct main_state *main_state,
                                 const char *datadir,
                                 struct wallet_sqlite *wallet_db,
                                 struct tx_mempool *mempool,
                                 struct connman *connman);
void wallet_rpc_context_set_node_db(struct node_db *node_db);
void wallet_rpc_context_set_coins_tip(struct coins_view_cache *coins_tip);

/* Amount formatting/parsing */
void format_amount(int64_t satoshis, char *out, size_t out_size);
/* Parse a JSON amount expressed in ZCL into zatoshi (1 ZCL =
 * ZATOSHI_PER_ZCL zatoshi, 8 fractional digits). Accepts a JSON int
 * (whole ZCL), real, or decimal string; fractional digits past the 8th
 * are truncated, and a leading '-' is honoured. Returns the amount in
 * zatoshi. Returns -1 (via LOG_ERR) if v is NULL or of an unsupported
 * JSON type; note -1 is indistinguishable from a parsed amount of -1
 * zatoshi, so reject negative/invalid amounts at the call site. */
int64_t parse_amount(const struct json_value *v);

/* Address codec wrappers — look up the active chain's base58 pubkey
 * and script prefixes and delegate to decode/encode_destination. These
 * collapse the four-line prefix-fetch idiom that was repeated at every
 * transparent-address call site. */
bool wallet_decode_address(const char *str, struct tx_destination *dest);
bool wallet_encode_destination(const struct tx_destination *dest,
                               char *out, size_t out_size);

/* Write a 64-char big-endian (display order) hex txid into out, which
 * must hold at least 65 bytes. The on-disk txid bytes are little-endian
 * so they are emitted reversed. */
void wallet_txid_hex_le(const uint8_t txid[32], char *out);

/* Transaction history helpers */
int wallet_history_count(void);
bool wallet_history_db_ready(void);
bool wallet_db_tx_deserialize(const struct db_wallet_tx *dbtx,
                              struct transaction *tx);
int wallet_db_tx_confirmations(const struct db_wallet_tx *dbtx);
void append_one_entry(struct json_value *result,
                      const char *txid, int vout_n,
                      const char *category, const char *address,
                      int64_t amount, int64_t fee,
                      int confirmations, int64_t time_received);
bool wallet_append_tx_entry(const struct transaction *tx,
                            bool from_me, int64_t fee,
                            int confirmations, int64_t time_received,
                            struct json_value *result);

#endif
