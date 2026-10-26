/* Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#include "controllers/wallet_diagnostic_controller.h"
#include "controllers/rpc_chainstate_guard.h"
#include "controllers/wallet_helpers.h"
#include "controllers/strong_params.h"
#include "wallet_diagnostic_internal.h"
#include "wallet/wallet.h"
#include "wallet/sapling_keys.h"
#include "chain/chainparams.h"
#include "encoding/utilmoneystr.h"
#include "encoding/utilstrencodings.h"
#include "json/json.h"
#include "keys/key_io.h"
#include "sapling/fast_scan.h"
#include <stdatomic.h>
#include "script/standard.h"
#include "support/cleanse.h"
#include "core/utiltime.h"
#include "core/random.h"
#include "validation/main_state.h"
#include "validation/sighash.h"
#include "validation/txmempool.h"
#include "wallet/wallet_sqlite.h"
#include "net/connman.h"
#include "sapling/sapling.h"
#include "sapling/fr.h"
#include "sapling/incremental_merkle_tree.h"
#include "consensus/upgrades.h"
#include "models/database.h"
#include "models/block.h"
#include "models/utxo.h"
#include "models/wallet_key.h"
#include "models/wallet_tx.h"
#include "models/mempool_entry.h"
#include "models/peer.h"
#include "controllers/sync_controller.h"
#include "controllers/wallet_scan.h"
#include "models/chain_snapshot.h"
#include "controllers/legacy_import.h"
#include "core/serialize.h"
#include "coins/coins.h"
#include "coins/coins_view.h"
#include "views/wallet_view.h"
#include <stdio.h>
#include <stdlib.h>
#include "util/log_macros.h"
#include "util/safe_alloc.h"
#include <string.h>

/* One wallet transaction in the ledger, keyed by txid. */
struct ledger_event {
    uint8_t txid[32];
    int height;
    bool from_me;
    int64_t fee;
};

/* Debits and credits one ledger event produced in each pool. */
struct ledger_flows {
    int64_t t_credit;
    int64_t t_debit;
    int64_t z_credit;
    int64_t z_debit;
};

/* Running balances and accounting totals across the whole ledger. */
struct ledger_totals {
    int64_t t_balance;
    int64_t z_balance;
    int64_t total_t_received;
    int64_t total_t_sent;
    int64_t total_z_received;
    int64_t total_z_sent;
    int64_t total_shielded;
    int64_t total_unshielded;
    int64_t total_fees;
    int64_t total_z_fees;
};

/* Collect events from wallet transactions */
static void collect_ledger_events(const struct db_wallet_tx *all_txs, int ntxs,
                                  int min_h, int max_h,
                                  struct ledger_event *events, int *nevents)
{
    for (int i = 0; i < ntxs; i++) {
        if (all_txs[i].block_height < min_h || all_txs[i].block_height > max_h)
            continue;
        bool dup = false;
        for (int j = 0; j < *nevents; j++) {
            if (memcmp(events[j].txid, all_txs[i].txid, 32) == 0) {
                dup = true;
                break;
            }
        }
        if (!dup && *nevents < 4096) {
            memcpy(events[*nevents].txid, all_txs[i].txid, 32);
            events[*nevents].height = all_txs[i].block_height;
            events[*nevents].from_me = all_txs[i].from_me;
            events[*nevents].fee = all_txs[i].fee;
            (*nevents)++;
        }
    }
}

/* Sort by height ascending */
static void sort_ledger_events_by_height(struct ledger_event *events,
                                         int nevents)
{
    for (int i = 0; i < nevents - 1; i++) {
        for (int j = i + 1; j < nevents; j++) {
            if (events[j].height < events[i].height) {
                struct ledger_event tmp = events[i];
                events[i] = events[j];
                events[j] = tmp;
            }
        }
    }
}

/* For this tx, find: T credits, T debits, Z credits, Z debits */
static void sum_ledger_event_flows(const struct db_wallet_utxo *all_utxos,
                                   int nutxos,
                                   const struct db_sapling_note *all_notes,
                                   int nnotes, const struct ledger_event *ev,
                                   struct ledger_flows *fl)
{
    /* T credits: UTXOs created by this tx */
    for (int u = 0; u < nutxos; u++) {
        if (memcmp(all_utxos[u].txid, ev->txid, 32) == 0)
            fl->t_credit += all_utxos[u].value;
    }

    /* T debits: UTXOs spent by this tx */
    for (int u = 0; u < nutxos; u++) {
        if (all_utxos[u].is_spent &&
            memcmp(all_utxos[u].spent_txid, ev->txid, 32) == 0)
            fl->t_debit += all_utxos[u].value;
    }

    /* Z credits: notes created by this tx (received into wallet) */
    for (int n = 0; n < nnotes; n++) {
        if (memcmp(all_notes[n].txid, ev->txid, 32) == 0)
            fl->z_credit += all_notes[n].value;
    }

    /* Z debits: notes spent by this tx */
    for (int n = 0; n < nnotes; n++) {
        if (all_notes[n].is_spent &&
            memcmp(all_notes[n].spent_txid, ev->txid, 32) == 0)
            fl->z_debit += all_notes[n].value;
    }
}

/* Classify the transaction type */
/* Each row mirrors one branch of the original if-chain, in the same
 * order; the first row whose required pool bits match wins. Bits:
 * 8 = t_debit, 4 = t_credit, 2 = z_debit, 1 = z_credit; a NULL type
 * means "send" when from_me, "receive" else. */
static const char *ledger_event_type(int64_t t_debit, int64_t t_credit,
                                     int64_t z_debit, int64_t z_credit,
                                     bool from_me)
{
    static const struct {
        unsigned mask;
        unsigned match;
        const char *type;
    } rows[] = {
        { 15u, 8u | 1u, "shield" },     /* t → z (pure shielding) */
        { 13u, 13u, "shield" },         /* t → z with change */
        { 7u, 6u, "unshield" },         /* z → t */
        { 7u, 7u, "unshield" },         /* z → t with z-change */
        { 15u, 3u, "z_transfer" },      /* z → z */
        { 15u, 2u, "z_send" },          /* z → external */
        { 15u, 12u, NULL },             /* send/receive, by from_me */
        { 15u, 4u, "receive" },         /* external → t */
        { 15u, 1u, "z_receive" },       /* external → z */
        { 15u, 8u, "send" },            /* t → external */
    };
    unsigned pools = (t_debit > 0 ? 8u : 0u) | (t_credit > 0 ? 4u : 0u)
                   | (z_debit > 0 ? 2u : 0u) | (z_credit > 0 ? 1u : 0u);

    for (size_t i = 0; i < sizeof(rows) / sizeof(rows[0]); i++) {
        if ((pools & rows[i].mask) == rows[i].match) {
            if (rows[i].type != NULL)
                return rows[i].type;
            return from_me ? "send" : "receive";
        }
    }
    return "mixed";
}

/* Count funds credited from outside the wallet */
static void add_external_deposit_totals(struct ledger_totals *tot, bool from_me,
                                        int64_t t_credit, int64_t z_credit)
{
    if (!from_me && t_credit > 0)
        tot->total_t_received += t_credit;  /* external deposits */
    if (!from_me && z_credit > 0)
        tot->total_z_received += z_credit;  /* external z-deposits */
}

/* Count funds leaving the wallet in transactions we sent */
static void add_sender_outflow_totals(struct ledger_totals *tot, bool from_me,
                                      int64_t t_debit, int64_t t_credit,
                                      int64_t z_debit, int64_t z_credit,
                                      int64_t fee)
{
    if (from_me) {
        /* For our sends: external_out = debit - credit - shielded */
        int64_t t_external = t_debit - t_credit - fee;
        if (z_credit > 0) t_external -= z_credit; /* value went to z-pool */
        if (t_external > 0) tot->total_t_sent += t_external;
        /* z outflow: z_debit - z_credit (change) */
        int64_t z_external = z_debit - z_credit;
        if (t_credit > 0 && z_debit > 0) z_external -= 0; /* unshield */
        if (z_external > 0) tot->total_z_sent += z_external;
    }
}

/* Count funds moved between the transparent and shielded pools */
static void add_pool_transfer_totals(struct ledger_totals *tot, bool from_me,
                                     int64_t t_debit, int64_t t_credit,
                                     int64_t z_debit, int64_t z_credit)
{
    if (t_debit > 0 && z_credit > 0) tot->total_shielded += z_credit;
    if (z_debit > 0 && t_credit > 0 && !from_me)
        tot->total_unshielded += t_credit;
    else if (z_debit > 0 && t_credit > 0 && from_me && t_debit == 0)
        tot->total_unshielded += t_credit;
}

/* Build entry */
static void append_ledger_entry(struct json_value *entries,
                                const struct ledger_event *ev,
                                const struct ledger_flows *fl, int64_t fee,
                                const char *type,
                                const struct ledger_totals *tot)
{
    char txid_hex[65];
    struct uint256 tid;
    memcpy(tid.data, ev->txid, 32);
    uint256_get_hex(&tid, txid_hex);

    struct json_value entry = {0};
    json_set_object(&entry);
    json_push_kv_int(&entry, "height", ev->height);
    json_push_kv_str(&entry, "txid", txid_hex);
    json_push_kv_str(&entry, "type", type);

    char s[32];
    if (fl->t_debit > 0) {
        format_amount(fl->t_debit, s, sizeof(s));
        json_push_kv_str(&entry, "t_debit", s);
    }
    if (fl->t_credit > 0) {
        format_amount(fl->t_credit, s, sizeof(s));
        json_push_kv_str(&entry, "t_credit", s);
    }
    if (fl->z_debit > 0) {
        format_amount(fl->z_debit, s, sizeof(s));
        json_push_kv_str(&entry, "z_debit", s);
    }
    if (fl->z_credit > 0) {
        format_amount(fl->z_credit, s, sizeof(s));
        json_push_kv_str(&entry, "z_credit", s);
    }
    if (fee > 0) {
        format_amount(fee, s, sizeof(s));
        json_push_kv_str(&entry, "fee", s);
    }

    format_amount(tot->t_balance, s, sizeof(s));
    json_push_kv_str(&entry, "t_balance", s);
    format_amount(tot->z_balance, s, sizeof(s));
    json_push_kv_str(&entry, "z_balance", s);
    format_amount(tot->t_balance + tot->z_balance, s, sizeof(s));
    json_push_kv_str(&entry, "total_balance", s);

    json_push_back(entries, &entry);
    json_free(&entry);
}

/* Per-address breakdown of unspent transparent funds */
static void build_transparent_holdings(struct wallet_rpc_context *ctx,
                                       struct json_value *holdings,
                                       const unsigned char *pk_pfx,
                                       size_t pk_pfx_len,
                                       const unsigned char *sc_pfx,
                                       size_t sc_pfx_len,
                                       int64_t *verified_t, int *unspent_count)
{
    struct json_value t_holdings = {0};
    json_set_array(&t_holdings);

    struct db_wallet_utxo unspent[1024];
    int nu = db_wallet_utxo_list_unspent(ctx->node_db, unspent, 1024);

    for (int i = 0; i < nu; i++) {
        struct json_value h = {0};
        json_set_object(&h);

        char txid_hex[65];
        struct uint256 tid;
        memcpy(tid.data, unspent[i].txid, 32);
        uint256_get_hex(&tid, txid_hex);
        json_push_kv_str(&h, "txid", txid_hex);
        json_push_kv_int(&h, "vout", unspent[i].vout);

        /* Resolve address from script */
        char addr[128] = {0};
        if (unspent[i].script && unspent[i].script_len > 0) {
            struct script scr;
            script_init(&scr);
            size_t cplen = unspent[i].script_len < MAX_SCRIPT_SIZE
                         ? unspent[i].script_len : MAX_SCRIPT_SIZE;
            memcpy(scr.data, unspent[i].script, cplen);
            scr.size = cplen;
            struct tx_destination dest;
            if (script_extract_destination(&scr, &dest))
                encode_destination(&dest, pk_pfx, pk_pfx_len,
                                   sc_pfx, sc_pfx_len, addr, sizeof(addr));
        }
        if (addr[0]) json_push_kv_str(&h, "address", addr);

        char s[32];
        format_amount(unspent[i].value, s, sizeof(s));
        json_push_kv_str(&h, "amount", s);
        json_push_kv_int(&h, "height", unspent[i].height);

        *verified_t += unspent[i].value;

        json_push_back(&t_holdings, &h);
        json_free(&h);
        db_wallet_utxo_free(&unspent[i]);
    }

    json_push_kv(holdings, "transparent", &t_holdings);
    json_free(&t_holdings);
    *unspent_count = nu;
}

/* Shielded holdings */
static void build_shielded_holdings(struct wallet_rpc_context *ctx,
                                    struct json_value *holdings,
                                    int64_t *verified_z,
                                    int *unspent_note_count)
{
    struct json_value z_holdings = {0};
    json_set_array(&z_holdings);

    struct db_sapling_note unspent_notes[256];
    int nn = db_sapling_note_list_unspent(ctx->node_db, unspent_notes, 256);

    for (int i = 0; i < nn; i++) {
        struct json_value h = {0};
        json_set_object(&h);

        char txid_hex[65];
        struct uint256 tid;
        memcpy(tid.data, unspent_notes[i].txid, 32);
        uint256_get_hex(&tid, txid_hex);
        json_push_kv_str(&h, "txid", txid_hex);
        json_push_kv_int(&h, "output_index", unspent_notes[i].output_index);

        /* Derive z-address from diversifier + pk_d */
        char zaddr[128] = {0};
        sapling_encode_payment_address(
            unspent_notes[i].diversifier, unspent_notes[i].pk_d,
            "zs", zaddr, sizeof(zaddr));
        if (zaddr[0]) json_push_kv_str(&h, "address", zaddr);

        char s[32];
        format_amount(unspent_notes[i].value, s, sizeof(s));
        json_push_kv_str(&h, "amount", s);
        json_push_kv_int(&h, "height", unspent_notes[i].block_height);

        /* Decode memo if non-empty */
        if (unspent_notes[i].memo_len > 0 && unspent_notes[i].memo[0] != 0xf6) {
            size_t mlen = unspent_notes[i].memo_len;
            while (mlen > 0 && unspent_notes[i].memo[mlen - 1] == 0) mlen--;
            if (mlen > 0) {
                char memo_str[513];
                size_t copy_len = mlen < 512 ? mlen : 512;
                memcpy(memo_str, unspent_notes[i].memo, copy_len);
                memo_str[copy_len] = '\0';
                json_push_kv_str(&h, "memo", memo_str);
            }
        }

        *verified_z += unspent_notes[i].value;

        json_push_back(&z_holdings, &h);
        json_free(&h);
        db_sapling_note_free(&unspent_notes[i]);
    }

    json_push_kv(holdings, "shielded", &z_holdings);
    json_free(&z_holdings);
    *unspent_note_count = nn;
}

/* Accounting summary */
static void append_accounting_summary(struct json_value *result,
                                      const struct ledger_totals *tot,
                                      int64_t verified_t, int64_t verified_z,
                                      int nu, int nn, int nevents)
{
    struct json_value acct = {0};
    json_set_object(&acct);
    char s[32];

    format_amount(tot->total_t_received, s, sizeof(s));
    json_push_kv_str(&acct, "total_t_received", s);

    format_amount(tot->total_z_received, s, sizeof(s));
    json_push_kv_str(&acct, "total_z_received", s);

    format_amount(tot->total_shielded, s, sizeof(s));
    json_push_kv_str(&acct, "total_shielded_t_to_z", s);

    format_amount(tot->total_unshielded, s, sizeof(s));
    json_push_kv_str(&acct, "total_unshielded_z_to_t", s);

    format_amount(tot->total_fees + tot->total_z_fees, s, sizeof(s));
    json_push_kv_str(&acct, "total_fees", s);

    format_amount(verified_t, s, sizeof(s));
    json_push_kv_str(&acct, "current_t_balance", s);

    format_amount(verified_z, s, sizeof(s));
    json_push_kv_str(&acct, "current_z_balance", s);

    format_amount(verified_t + verified_z, s, sizeof(s));
    json_push_kv_str(&acct, "current_total", s);

    /* Verify: received - sent - fees should equal current balance */
    int64_t expected = tot->total_t_received + tot->total_z_received
                     - tot->total_t_sent - tot->total_z_sent
                     - (tot->total_fees + tot->total_z_fees);
    int64_t actual = verified_t + verified_z;
    int64_t unaccounted = expected - actual;
    if (unaccounted < 0) unaccounted = -unaccounted;
    format_amount(unaccounted, s, sizeof(s));
    json_push_kv_str(&acct, "unaccounted", s);

    json_push_kv_int(&acct, "transparent_utxos", nu);
    json_push_kv_int(&acct, "shielded_notes", nn);
    json_push_kv_int(&acct, "ledger_entries", nevents);

    json_push_kv(result, "accounting", &acct);
    json_free(&acct);
}

/* Cleanup */
static void free_ledger_batches(struct db_wallet_utxo *all_utxos, int nutxos,
                                struct db_sapling_note *all_notes, int nnotes,
                                struct db_wallet_tx *all_txs, int ntxs,
                                struct ledger_event *events)
{
    for (int i = 0; i < nutxos; i++) db_wallet_utxo_free(&all_utxos[i]);
    for (int i = 0; i < nnotes; i++) db_sapling_note_free(&all_notes[i]);
    free(all_utxos);
    free(all_notes);
    for (int i = 0; i < ntxs; i++) db_wallet_tx_free(&all_txs[i]);
    free(all_txs);
    free(events);
}

/* walletledger: Unified double-entry ledger for transparent + shielded pools.
 * Each transaction shows debits/credits in both pools with running balances.
 * Queries SQLite directly for complete accounting without deserialization. */
bool rpc_walletledger(const struct json_value *params, bool help,
                              struct json_value *result)
{
    struct wallet_rpc_context *ctx = wallet_ctx();
    RPC_HELP(help, result,
        "walletledger ( min_height max_height )\n"
        "\nUnified transparent + shielded ledger with double-entry accounting.\n"
        "Shows every fund movement in both pools chronologically.\n"
        "Each entry: debits, credits, fee, running balances per pool.\n"
        "\nArguments:\n"
        "1. min_height  (int, optional) Filter from this height\n"
        "2. max_height  (int, optional) Filter up to this height\n"
        "\nResult:\n"
        "  entries[]: Chronological list of wallet events\n"
        "  current_holdings: Per-address/note breakdown of current funds\n"
        "  accounting: Complete fund flow summary\n");

    struct rpc_params p;
    rpc_params_init(&p, params);
    rpc_params_expect(&p, 0, 2);
    int min_h = (int)rpc_permit_int(&p, 0, "min_height", 0);
    int max_h = (int)rpc_permit_int(&p, 1, "max_height", 999999999);
    if (rpc_params_invalid(&p)) { rpc_params_error(&p, result); return false; }

    if (!wallet_ctx_db_ready(ctx)) {
        json_set_str(result, "Wallet database not available");
        return false;
    }

    ENSURE_WALLET(result);

    const struct chain_params *cp = chain_params_get();
    size_t pk_pfx_len, sc_pfx_len;
    const unsigned char *pk_pfx = chain_params_base58_prefix(
        cp, B58_PUBKEY_ADDRESS, &pk_pfx_len);
    const unsigned char *sc_pfx = chain_params_base58_prefix(
        cp, B58_SCRIPT_ADDRESS, &sc_pfx_len);

    /* Load all data from SQLite */
    struct db_wallet_utxo *all_utxos = zcl_calloc(4096, sizeof(*all_utxos), "diag_utxos");
    int nutxos = all_utxos ? db_wallet_utxo_list_all(ctx->node_db, all_utxos, 4096) : 0;

    struct db_sapling_note *all_notes = zcl_calloc(1024, sizeof(*all_notes), "diag_notes");
    int nnotes = all_notes ? db_sapling_note_list_all(ctx->node_db, all_notes, 1024) : 0;

    struct db_wallet_tx *all_txs = zcl_calloc(2000, sizeof(*all_txs), "diag_txs");
    int ntxs = all_txs ? db_wallet_tx_list(ctx->node_db, all_txs, 2000, 0) : 0;

    /* Build a height-sorted list of unique txids */
    struct ledger_event *events = zcl_calloc(4096, sizeof(*events), "diag_events");
    int nevents = 0;

    collect_ledger_events(all_txs, ntxs, min_h, max_h, events, &nevents);
    sort_ledger_events_by_height(events, nevents);

    json_set_object(result);

    struct json_value entries = {0};
    json_set_array(&entries);

    struct ledger_totals tot = {0};

    for (int e = 0; e < nevents; e++) {
        struct ledger_flows fl = {0};
        sum_ledger_event_flows(all_utxos, nutxos, all_notes, nnotes,
                               &events[e], &fl);

        /* Fee */
        int64_t fee = events[e].from_me ? events[e].fee : 0;
        if (fee < 0) fee = -fee;

        const char *type = ledger_event_type(fl.t_debit, fl.t_credit,
                                             fl.z_debit, fl.z_credit,
                                             events[e].from_me);

        /* Update running balances */
        int64_t t_net = fl.t_credit - fl.t_debit;
        int64_t z_net = fl.z_credit - fl.z_debit;
        tot.t_balance += t_net;
        tot.z_balance += z_net;

        /* Track accounting totals (net flows, not gross) */
        add_external_deposit_totals(&tot, events[e].from_me,
                                    fl.t_credit, fl.z_credit);
        add_sender_outflow_totals(&tot, events[e].from_me, fl.t_debit,
                                  fl.t_credit, fl.z_debit, fl.z_credit, fee);
        add_pool_transfer_totals(&tot, events[e].from_me, fl.t_debit,
                                 fl.t_credit, fl.z_debit, fl.z_credit);
        tot.total_fees += fee;

        append_ledger_entry(&entries, &events[e], &fl, fee, type, &tot);
    }

    json_push_kv(result, "entries", &entries);
    json_free(&entries);

    /* Current holdings: per-address breakdown */
    struct json_value holdings = {0};
    json_set_object(&holdings);

    int64_t verified_t = 0, verified_z = 0;
    int nu = 0, nn = 0;
    build_transparent_holdings(ctx, &holdings, pk_pfx, pk_pfx_len,
                               sc_pfx, sc_pfx_len, &verified_t, &nu);
    build_shielded_holdings(ctx, &holdings, &verified_z, &nn);

    json_push_kv(result, "current_holdings", &holdings);
    json_free(&holdings);

    append_accounting_summary(result, &tot, verified_t, verified_z,
                              nu, nn, nevents);

    free_ledger_batches(all_utxos, nutxos, all_notes, nnotes,
                        all_txs, ntxs, events);

    return true;
}
