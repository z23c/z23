/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "views/wallet_view.h"
#include "views/format_helpers.h"
#include "wallet/wallet.h"
#include "models/chain_snapshot.h"
#include "wallet/keystore.h"
#include "keys/key_io.h"
#include "chain/chainparams.h"
#include "core/uint256.h"
#include "json/json.h"
#include "script/standard.h"
#include "models/wallet_key.h"
#include "encoding/utilstrencodings.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <inttypes.h>

void wallet_view_key_entry(struct json_value *out,
                           const struct db_wallet_key *key,
                           const char *address,
                           int unspent_count,
                           int64_t balance)
{
    (void)key;
    json_set_object(out);
    json_push_kv_str(out, "address", address);

    char pkh[41];
    HexStr(key->pubkey_hash, 20, false, pkh, sizeof(pkh));
    json_push_kv_str(out, "pubkey_hash", pkh);
    json_push_kv_int(out, "unspent_count", unspent_count);

    char amt[32];
    zcl_format_zcl(amt, sizeof(amt), balance);
    json_push_kv_real(out, "balance", strtod(amt, NULL));
}

void wallet_view_utxo_trace(struct json_value *out,
                            const char *txid_hex, uint32_t vout,
                            const char *status,
                            int64_t value, int height,
                            const char *spent_by,
                            bool in_wallet, bool in_chainstate)
{
    json_set_object(out);
    json_push_kv_str(out, "txid", txid_hex);
    json_push_kv_int(out, "vout", vout);
    json_push_kv_str(out, "status", status);

    char amt[32];
    zcl_format_zcl(amt, sizeof(amt), value);
    json_push_kv_real(out, "value", strtod(amt, NULL));
    json_push_kv_int(out, "height", height);
    if (spent_by)
        json_push_kv_str(out, "spent_by", spent_by);
    json_push_kv_bool(out, "in_wallet", in_wallet);
    json_push_kv_bool(out, "in_chainstate", in_chainstate);
}

void wallet_view_flow_entry(struct json_value *out,
                            const char *txid_hex,
                            const char *category,
                            int64_t amount, int64_t fee,
                            int height, int64_t running_balance)
{
    json_set_object(out);
    json_push_kv_str(out, "txid", txid_hex);
    json_push_kv_str(out, "category", category);

    char amt[32];
    zcl_format_zcl(amt, sizeof(amt), amount);
    json_push_kv_real(out, "amount", strtod(amt, NULL));
    if (fee != 0) {
        zcl_format_zcl(amt, sizeof(amt), -fee);
        json_push_kv_real(out, "fee", strtod(amt, NULL));
    }
    json_push_kv_int(out, "height", height);
    zcl_format_zcl(amt, sizeof(amt), running_balance);
    json_push_kv_real(out, "running_balance", strtod(amt, NULL));
}

void wallet_view_reconcile_summary(struct json_value *out,
    int verified, int phantom, int spent_on_chain, int mismatched, int fixed,
    int64_t balance_before, int64_t balance_after)
{
    json_set_object(out);
    json_push_kv_int(out, "verified", verified);
    json_push_kv_int(out, "phantom", phantom);
    json_push_kv_int(out, "spent_on_chain", spent_on_chain);
    json_push_kv_int(out, "value_mismatch", mismatched);
    json_push_kv_int(out, "fixed", fixed);

    char amt[32];
    zcl_format_zcl(amt, sizeof(amt), balance_before);
    json_push_kv_real(out, "balance_before", strtod(amt, NULL));
    zcl_format_zcl(amt, sizeof(amt), balance_after);
    json_push_kv_real(out, "balance_after", strtod(amt, NULL));
}

void wallet_view_purge_summary(struct json_value *out,
    int utxos_deleted, int txs_deleted, int64_t amount_purged,
    int64_t balance_before, int64_t balance_after)
{
    json_set_object(out);
    json_push_kv_int(out, "utxos_deleted", utxos_deleted);
    json_push_kv_int(out, "txs_deleted", txs_deleted);

    char amt[32];
    zcl_format_zcl(amt, sizeof(amt), amount_purged);
    json_push_kv_real(out, "amount_purged", strtod(amt, NULL));
    zcl_format_zcl(amt, sizeof(amt), balance_before);
    json_push_kv_real(out, "balance_before", strtod(amt, NULL));
    zcl_format_zcl(amt, sizeof(amt), balance_after);
    json_push_kv_real(out, "balance_after", strtod(amt, NULL));
}

void wallet_view_replay_summary(struct json_value *out,
    int utxos_found, int txs_found,
    int64_t new_balance, int64_t old_balance)
{
    json_set_object(out);
    json_push_kv_int(out, "utxos_found", utxos_found);
    json_push_kv_int(out, "txs_found", txs_found);

    char amt[32];
    zcl_format_zcl(amt, sizeof(amt), new_balance);
    json_push_kv_real(out, "new_balance", strtod(amt, NULL));
    zcl_format_zcl(amt, sizeof(amt), old_balance);
    json_push_kv_real(out, "old_balance", strtod(amt, NULL));
}

void wallet_view_sync_summary(struct json_value *out,
    int synced, int already_correct, int marked_spent,
    int64_t balance_before, int64_t balance_after)
{
    json_set_object(out);
    json_push_kv_int(out, "utxos_unmarked_spent", synced);
    json_push_kv_int(out, "already_correct", already_correct);
    json_push_kv_int(out, "marked_spent", marked_spent);

    char amt[32];
    zcl_format_zcl(amt, sizeof(amt), balance_before);
    json_push_kv_real(out, "balance_before", strtod(amt, NULL));
    zcl_format_zcl(amt, sizeof(amt), balance_after);
    json_push_kv_real(out, "balance_after", strtod(amt, NULL));
}

void wallet_view_chain_coin(struct json_value *out,
                            uint32_t vout, int64_t value,
                            bool available, const char *address,
                            bool in_wallet)
{
    json_set_object(out);
    json_push_kv_int(out, "vout", vout);

    char amt[32];
    zcl_format_zcl(amt, sizeof(amt), value);
    json_push_kv_real(out, "value", strtod(amt, NULL));
    json_push_kv_str(out, "status", available ? "unspent" : "spent");
    if (address)
        json_push_kv_str(out, "address", address);
    json_push_kv_bool(out, "in_wallet", in_wallet);
}

/* ── HTML view render functions ─────────────────────────────── */

size_t wv_render_pulse(uint8_t *buf, size_t max, const struct wv_pulse *d) {
    return (size_t)snprintf((char *)buf, max,
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: application/json\r\n"
        "Cache-Control: no-cache\r\n"
        "Connection: close\r\n\r\n"
        "{\"height\":%d,\"balance\":%" PRId64 ",\"shielded\":%" PRId64
        ",\"speed_balance\":%" PRId64
        ",\"t_utxos\":%d,\"z_notes\":%d"
        ",\"peers\":%d,\"sync\":\"%s\",\"mempool\":%d}",
        d->height, d->balance, d->shielded, d->speed_balance,
        d->t_utxos, d->z_notes,
        d->peers, d->sync, d->mempool);
}
