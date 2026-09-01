/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Wallet view — JSON serializers for wallet data.
 *
 * Pattern:
 *   struct json_value result;
 *   json_init(&result);
 *   wallet_view_utxo(&result, &coin, w);
 */

#ifndef ZCL_VIEWS_WALLET_VIEW_H
#define ZCL_VIEWS_WALLET_VIEW_H

#include "json/json.h"
#include <stdint.h>
#include <stddef.h>
#include <inttypes.h>

struct wallet;
struct wallet_tx;
struct coin_entry;

/* Diagnostic view: wallet key with per-key balance */
struct db_wallet_key;
void wallet_view_key_entry(struct json_value *out,
                           const struct db_wallet_key *key,
                           const char *address,
                           int unspent_count,
                           int64_t balance);

/* Diagnostic view: single UTXO trace result */
void wallet_view_utxo_trace(struct json_value *out,
                            const char *txid_hex, uint32_t vout,
                            const char *status,
                            int64_t value, int height,
                            const char *spent_by,
                            bool in_wallet, bool in_chainstate);

/* Diagnostic view: balance flow entry */
void wallet_view_flow_entry(struct json_value *out,
                            const char *txid_hex,
                            const char *category,
                            int64_t amount, int64_t fee,
                            int height, int64_t running_balance);

/* Diagnostic view: chainstate coin output */
void wallet_view_chain_coin(struct json_value *out,
                            uint32_t vout, int64_t value,
                            bool available, const char *address,
                            bool in_wallet);

/* Diagnostic view: reconciliation summary */
void wallet_view_reconcile_summary(struct json_value *out,
    int verified, int phantom, int spent_on_chain, int mismatched, int fixed,
    int64_t balance_before, int64_t balance_after);

/* Diagnostic view: purge summary */
void wallet_view_purge_summary(struct json_value *out,
    int utxos_deleted, int txs_deleted, int64_t amount_purged,
    int64_t balance_before, int64_t balance_after);

/* Diagnostic view: replay summary */
void wallet_view_replay_summary(struct json_value *out,
    int utxos_found, int txs_found,
    int64_t new_balance, int64_t old_balance);

/* Diagnostic view: syncwalletfromdb summary */
void wallet_view_sync_summary(struct json_value *out,
    int synced, int already_correct, int marked_spent,
    int64_t balance_before, int64_t balance_after);

/* ── HTML view layer ─────────────────────────────────────────
 * Controller fills struct with data, view renders HTML.
 * No SQLite calls in view functions. */

#include <stdbool.h>

/* ── Pulse (JSON, no HTML) ──────────────────────────────────── */

struct wv_pulse {
    int     height;
    int64_t balance;            /* transparent, zatoshi */
    int64_t shielded;           /* zatoshi */
    int64_t speed_balance;
    int     t_utxos;
    int     z_notes;
    int     peers;
    int     mempool;
    char    sync[32];
};

size_t wv_render_pulse(uint8_t *buf, size_t max, const struct wv_pulse *d);

/* ── Shield Confirm result ──────────────────────────────────── */

struct wv_shield_result {
    bool    success;
    double  amount;
    char    opid[128];
    char    error[256];
    int64_t new_transparent;
    int64_t new_shielded;
};

#endif
