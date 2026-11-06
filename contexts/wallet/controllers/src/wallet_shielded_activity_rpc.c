/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * walletsummary and wallethistory node RPCs behind core.wallet.summary and
 * core.wallet.history. Read-only: they read the wallet fact rows, the loaded
 * viewing keys (ivk) and whether seed and key rows exist, never a seed or a
 * spending key, and write nothing. No amount, address or memo reaches a log
 * line. */

#include "controllers/wallet_shielded_internal.h"
#include "controllers/wallet_activity.h"
#include "controllers/wallet_spend_gate.h"
#include "controllers/sovereignty_controller.h"
#include "jobs/reducer_frontier.h"
#include "primitives/transaction.h"
#include "services/node_health_service.h"
#include "services/sync_monitor.h"
#include "validation/main_state.h"
#include "wallet/wallet_lock.h"
#include "wallet/wallet_sqlite.h"
#include "support/cleanse.h"
#include "core/uint256.h"

#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

/* The one place the summary asks whether the wallet may send. It reads the
 * guard's decision without the guard's progress-store stamp or its log line:
 * a summary is a read and attempts no spend. */
bool wallet_send_gate(char *reason, size_t cap)
{
    return sovereignty_guard_peek("wallet_spend", reason, cap);
}

static void wa_kv_null(struct json_value *obj, const char *key)
{
    struct json_value v;
    json_init(&v);
    json_set_null(&v);
    json_push_kv(obj, key, &v);
    json_free(&v);
}

static void wa_kv_amount(struct json_value *obj, const char *zat_key,
                         const char *str_key, int64_t v)
{
    char buf[32];
    format_amount(v, buf, sizeof(buf));
    json_push_kv_int(obj, zat_key, v);
    json_push_kv_str(obj, str_key, buf);
}

static int wa_max_int(int a, int b)
{
    return a > b ? a : b;
}

/* An amount that is unknown renders as null in both forms, never as 0. */
static void wa_kv_amount_known(struct json_value *obj, const char *zat_key,
                               const char *str_key, bool known, int64_t v)
{
    if (known) {
        wa_kv_amount(obj, zat_key, str_key, v);
        return;
    }
    wa_kv_null(obj, zat_key);
    wa_kv_null(obj, str_key);
}

/* The node has evidence the chain is live: at least one peer past the
 * handshake and a block the node connected, by its own suspend-proof clock,
 * within the last ten minutes. Peer start
 * heights go stale, so they say nothing about the chain's progress; a node
 * with no peer is offline, however recent its last block. */
static bool wa_chain_live(const struct wallet_chain_view *v)
{
    return v->peer_count > 0 && v->chain_fresh;
}

/* `current` needs a real tip, a real header, every shielded key loaded, a scan
 * that reached the tip, a node within one block of what it knows and evidence
 * the chain is live. */
static void wa_summary_chain(const struct wallet_chain_view *v,
                             struct json_value *out)
{
    int ahead = wa_max_int(v->header_height, v->peer_best_height);
    int behind = ahead > v->tip_height ? ahead - v->tip_height : 0;
    json_push_kv_int(out, "tip_height", v->tip_height);
    json_push_kv_int(out, "header_height", v->header_height);
    if (v->scanned_through >= 0)
        json_push_kv_int(out, "scanned_through_height", v->scanned_through);
    else
        wa_kv_null(out, "scanned_through_height");
    json_push_kv_int(out, "blocks_behind", behind);
    json_push_kv_int(out, "peer_count", (int64_t)v->peer_count);
    json_push_kv_bool(out, "current",
                      v->tip_height > 0 && v->header_height > 0 &&
                      v->shielded_known &&
                      v->scanned_through >= v->tip_height && behind <= 1 &&
                      wa_chain_live(v));
}

/* A holding that is held is true, one the wallet tables were read without is
 * false, and any other is unknown: null, never false. */
static void wa_kv_held(struct json_value *obj, const char *key, bool held,
                       bool read)
{
    if (held || read)
        json_push_kv_bool(obj, key, held);
    else
        wa_kv_null(obj, key);
}

void wallet_summary_to_json(const struct wallet_summary *s,
                            const struct wallet_chain_view *v,
                            bool send_allowed, const char *send_reason,
                            struct json_value *out)
{
    json_set_object(out);
    json_push_kv_str(out, "schema", "zcl.wallet_summary.v1");
    bool z = v->shielded_known;
    json_push_kv_str(out, "shielded_state", z ? "ok" : "keys_unavailable");
    wa_kv_amount_known(out, "spendable_zat", "spendable", z, s->spendable);
    wa_kv_amount_known(out, "spendable_total_zat", "spendable_total", z,
                       s->spendable_total);
    wa_kv_amount_known(out, "pending_zat", "pending", z, s->pending);
    if (z) {
        json_push_kv_int(out, "pending_notes", s->pending_count);
        json_push_kv_int(out, "pending_min_confirmations_needed",
                         s->pending_min_confs_needed);
    } else {
        wa_kv_null(out, "pending_notes");
        wa_kv_null(out, "pending_min_confirmations_needed");
    }
    wa_kv_amount_known(out, "unready_zat", "unready", z, s->unready);
    if (z) {
        json_push_kv_int(out, "unready_notes", s->unready_notes);
        json_push_kv_int(out, "reconciling_notes", s->reconciling_notes);
    } else {
        wa_kv_null(out, "unready_notes");
        wa_kv_null(out, "reconciling_notes");
    }
    wa_kv_amount_known(out, "sending_zat", "sending", z, s->sending);
    wa_kv_amount(out, "public_zat", "public", s->public_confirmed);
    wa_kv_amount(out, "immature_zat", "immature", s->immature);
    wa_summary_chain(v, out);
    json_push_kv_bool(out, "locked", v->locked);
    json_push_kv_bool(out, "encrypted", v->encrypted);
    json_push_kv_int(out, "shielded_keys", (int64_t)v->shielded_keys);
    wa_kv_held(out, "seed_present", v->seed_held, v->holdings_read);
    wa_kv_held(out, "keys_present", v->keys_held, v->holdings_read);
    json_push_kv_bool(out, "send_allowed", send_allowed);
    json_push_kv_str(out, "send_blocked_reason",
                     send_allowed || !send_reason ? "" : send_reason);
}

void wallet_history_entry_to_json(const struct wallet_history_entry *e,
                                  struct json_value *out)
{
    static const char *const dir[] = { "received", "sent", "internal",
                                       "unknown" };
    char hex[65];
    wallet_txid_hex_le(e->txid, hex);
    json_set_object(out);
    json_push_kv_str(out, "txid", hex);
    json_push_kv_str(out, "status", e->height > 0 ? "confirmed" : "pending");
    if (e->height > 0)
        json_push_kv_int(out, "height", e->height);
    else
        wa_kv_null(out, "height");
    json_push_kv_int(out, "confirmations", e->confirmations);
    if (e->time > 0)
        json_push_kv_int(out, "time", e->time);
    else
        wa_kv_null(out, "time");
    json_push_kv_str(out, "direction", dir[e->direction]);
    if (e->fully_shielded >= 0)
        json_push_kv_str(out, "kind", e->private_kind ? "private" : "public");
    else
        wa_kv_null(out, "kind");
    if (e->fully_shielded >= 0)
        json_push_kv_bool(out, "fully_shielded", e->fully_shielded != 0);
    else
        wa_kv_null(out, "fully_shielded");
    if (e->amount_known)
        wa_kv_amount(out, "amount_zat", "amount", e->amount);
    else {
        wa_kv_null(out, "amount_zat");
        wa_kv_null(out, "amount");
    }
    if (e->fee_known)
        wa_kv_amount(out, "fee_zat", "fee", e->fee);
    else {
        wa_kv_null(out, "fee_zat");
        wa_kv_null(out, "fee");
    }
    json_push_kv_int(out, "net_zat", e->net);
    json_push_kv_bool(out, "memo_present", e->memo_present);
}

/* ── wallet state ────────────────────────────────────────────────── */

struct wa_keys {
    uint8_t (*ivk)[32];
    size_t n;
    bool known; /* the viewing keys are loaded, or none can exist */
};

/* True when an empty keystore means the wallet has no shielded keys: it is
 * unlocked and no Sapling key row is persisted. While an unlock is still
 * reloading keys from disk the keystore is empty although rows exist, and the
 * count cannot be read when the database is unavailable; both are unknown. */
static bool wa_no_sapling_keys_certain(const struct wallet_rpc_context *ctx)
{
    return wallet_lock_is_unlocked() &&
           ctx->wallet_db &&
           wallet_sqlite_sapling_key_count(ctx->wallet_db) == 0;
}

/* Copy the distinct loaded viewing keys. A repeated ivk is kept once. A wallet
 * that is locked and holds none cannot say whether it has shielded keys, so
 * its shielded amounts are unknown, not zero. */
static bool wa_keys_collect(struct wallet_rpc_context *ctx, struct wa_keys *k)
{
    struct sapling_keystore *ks = &ctx->wallet->sapling_keys;
    k->n = 0;
    k->ivk = zcl_calloc(MAX_SAPLING_KEYS + 1, 32, "wallet ivk copy");
    if (!k->ivk)
        return false;
    zcl_mutex_lock(&ks->cs);
    for (size_t i = 0; i < ks->num_keys && i < MAX_SAPLING_KEYS; i++) {
        bool dup = false;
        for (size_t j = 0; j < k->n && !dup; j++)
            dup = memcmp(k->ivk[j], ks->keys[i].ivk, 32) == 0;
        if (ks->keys[i].used && !dup)
            memcpy(k->ivk[k->n++], ks->keys[i].ivk, 32);
    }
    zcl_mutex_unlock(&ks->cs);
    k->known = k->n > 0 || wa_no_sapling_keys_certain(ctx);
    return true;
}

/* False when the chain tip is unknown: every confirmation depends on it. */
static bool wa_chain_view(struct wallet_rpc_context *ctx,
                          const struct wa_keys *k,
                          struct wallet_chain_view *v)
{
    struct node_health_snapshot h = {0};
    node_health_collect(&h, ctx->node_db, ctx->main_state);
    memset(v, 0, sizeof(*v));
    if (h.tip_height <= 0)
        LOG_FAIL("wallet_activity", "chain tip unknown");
    const struct main_state *ms =
        ctx->main_state ? ctx->main_state : sync_monitor_main_state();
    v->tip_height = h.tip_height;
    v->header_height = ms && ms->pindex_best_header
        ? ms->pindex_best_header->nHeight : 0;
    v->peer_best_height = h.peer_best_height;
    v->peer_count = h.handshaked_peer_count;
    v->chain_fresh = wallet_chain_fresh(h.chain_progress_age_ms);
    v->scanned_through = wallet_read_scanned_through_height(ctx->wallet);
    v->encrypted = wallet_lock_encrypted_at_rest();
    v->locked = !wallet_lock_is_unlocked();
    v->shielded_keys = k->n;
    v->shielded_known = k->known;
    return true;
}

/* Whether the wallet holds a seed and any transparent or Sapling key, from its
 * tables and its loaded keystores. The tables are read by presence alone, so
 * no secret is read and a locked wallet answers too. */
static void wa_holdings(struct wallet_rpc_context *ctx,
                        struct wallet_chain_view *v)
{
    struct wallet *w = ctx->wallet;
    int stored = wallet_sqlite_holdings(ctx->wallet_db);
    zcl_mutex_lock(&w->sapling_keys.cs);
    bool seed = w->sapling_keys.has_seed;
    bool keys = w->sapling_keys.num_keys > 0;
    zcl_mutex_unlock(&w->sapling_keys.cs);
    zcl_mutex_lock(&w->keystore.cs);
    keys = keys || w->keystore.num_keys > 0;
    zcl_mutex_unlock(&w->keystore.cs);
    v->holdings_read = stored >= 0;
    v->seed_held = seed || (stored > 0 && (stored & WALLET_HOLDS_SEED));
    v->keys_held = keys || (stored > 0 && (stored & WALLET_HOLDS_KEYS));
}

struct wa_facts {
    struct db_wallet_note_fact *notes;
    struct db_wallet_coin_fact *coins;
    struct db_wallet_tx_fact *txs;
    int nn, nc, nt;
};

static void wa_facts_free(struct wa_facts *f)
{
    free(f->notes);
    free(f->coins);
    free(f->txs);
}

static bool wa_facts_load(struct node_db *ndb, struct wa_facts *f)
{
    memset(f, 0, sizeof(*f));
    f->nn = db_wallet_note_facts_alloc(ndb, &f->notes);
    f->nc = db_wallet_coin_facts_alloc(ndb, &f->coins);
    f->nt = db_wallet_tx_facts_alloc(ndb, &f->txs);
    if (f->nn >= 0 && f->nc >= 0 && f->nt >= 0)
        return true;
    wa_facts_free(f);
    return false;
}

static bool wa_ivk_in(const struct wa_keys *k, const uint8_t ivk[32])
{
    for (size_t i = 0; i < k->n; i++)
        if (memcmp(k->ivk[i], ivk, 32) == 0)
            return true;
    return false;
}

/* Fill each unspent loaded note's chain and witness state from the same two
 * authorities send consults: the durable spent set and the stored witness at
 * the authoritative tip. Both are read-only here. */
static void wa_notes_annotate(struct wallet_rpc_context *ctx,
                              const struct wa_keys *k,
                              struct db_wallet_note_fact *notes, int nn)
{
    int authoritative_tip = reducer_frontier_external_tip_height();
    for (int i = 0; i < nn; i++) {
        struct db_wallet_note_fact *n = &notes[i];
        bool spent_on_chain = false;
        if (n->spent || !wa_ivk_in(k, n->ivk))
            continue;
        if (!node_db_sapling_nullifier_is_spent(n->nullifier, &spent_on_chain))
            n->chain = WALLET_NOTE_CHAIN_UNKNOWN;
        else
            n->chain = spent_on_chain ? WALLET_NOTE_SPENT_ON_CHAIN
                                      : WALLET_NOTE_UNSPENT_ON_CHAIN;
        n->witness = wallet_note_witness_status(
                         ctx->node_db, n->txid, n->output_index,
                         authoritative_tip, NULL, NULL) == 0
            ? WALLET_WITNESS_READY : WALLET_WITNESS_UNUSABLE;
    }
}

/* Read the shape of each stored transaction, the wallet's own and others'. A
 * transaction that is absent or does not parse stays raw_known = false. */
static void wa_txs_enrich(struct node_db *ndb, struct db_wallet_tx_fact *txs,
                          int nt)
{
    for (int i = 0; i < nt; i++) {
        struct db_wallet_tx row;
        struct transaction tx;
        struct byte_stream bs;
        if (!db_wallet_tx_find(ndb, txs[i].txid, &row))
            continue;
        transaction_init(&tx);
        stream_init_from_data(&bs, row.raw_tx, row.raw_tx_len);
        if (row.raw_tx && transaction_deserialize(&tx, &bs)) {
            int64_t total = 0;
            for (size_t j = 0; j < tx.num_vout; j++)
                total += tx.vout[j].value;
            txs[i].raw_known = true;
            txs[i].vin_count = (uint32_t)tx.num_vin;
            txs[i].vout_count = (uint32_t)tx.num_vout;
            txs[i].vout_total = total;
            txs[i].value_balance = tx.value_balance;
        }
        transaction_free(&tx);
        db_wallet_tx_free(&row);
    }
}

static bool wa_ready(struct wallet_rpc_context *ctx, struct json_value *result)
{
    if (!ctx->wallet || !wallet_ctx_db_ready(ctx)) {
        json_set_str(result, "Wallet not available");
        LOG_FAIL("wallet_activity", "wallet or node database not ready");
    }
    return true;
}

/* Everything one summary or history reply is computed from. */
struct wa_state {
    struct wa_keys keys;
    struct wa_facts facts;
    struct wallet_chain_view view;
};

static void wa_state_free(struct wa_state *st)
{
    wa_facts_free(&st->facts);
    free(st->keys.ivk);
}

/* Load keys, fact rows and the chain view, or fail the command with the
 * reason in `result`. Nothing is half-loaded on failure. */
static bool wa_state_load(struct wallet_rpc_context *ctx, struct wa_state *st,
                          bool for_history, struct json_value *result)
{
    memset(st, 0, sizeof(*st));
    if (!wa_keys_collect(ctx, &st->keys)) {
        json_set_str(result, "Out of memory");
        LOG_FAIL("wallet_activity", "viewing key copy failed");
    }
    if (!wa_facts_load(ctx->node_db, &st->facts)) {
        free(st->keys.ivk);
        json_set_str(result, "Wallet database unreadable");
        LOG_FAIL("wallet_activity", "fact load failed");
    }
    if (!wa_chain_view(ctx, &st->keys, &st->view)) {
        wa_state_free(st);
        json_set_str(result, "Chain tip unknown");
        return false; // raw-return-ok:callee-logged
    }
    if (for_history)
        wa_txs_enrich(ctx->node_db, st->facts.txs, st->facts.nt);
    else
        wa_notes_annotate(ctx, &st->keys, st->facts.notes, st->facts.nn);
    return true;
}

bool rpc_walletsummary(const struct json_value *params, bool help,
                       struct json_value *result)
{
    struct wallet_rpc_context *ctx = wallet_ctx();
    RPC_HELP(help, result, "walletsummary\n"
        "\nReturns spendable, pending and public funds with sync state.\n");
    (void)params;
    if (!wa_ready(ctx, result))
        return false; // raw-return-ok:callee-logged

    struct wa_state st;
    struct wallet_summary sum;
    if (!wa_state_load(ctx, &st, false, result))
        return false; // raw-return-ok:callee-logged
    const struct wa_facts *f = &st.facts;
    if (!wallet_summary_accumulate(
            f->notes, (size_t)f->nn, f->coins, (size_t)f->nc, f->txs,
            (size_t)f->nt, (const uint8_t (*)[32])st.keys.ivk, st.keys.n,
            st.view.tip_height, &sum)) {
        wa_state_free(&st);
        json_set_str(result, "Out of memory");
        LOG_FAIL("wallet_activity", "walletsummary: working set failed");
    }
    char reason[96] = {0};
    bool allowed = wallet_send_gate(reason, sizeof(reason));
    wa_holdings(ctx, &st.view);
    wallet_summary_to_json(&sum, &st.view, allowed, reason, result);
    wa_state_free(&st);
    return true;
}

/* The fact row of a note: the facts are sorted by transaction id, then output. */
static const struct db_wallet_note_fact *wa_fact_of(
    const struct wa_facts *f, const struct db_sapling_note *n)
{
    size_t lo = 0, hi = (size_t)f->nn;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        const struct db_wallet_note_fact *m = &f->notes[mid];
        int c = memcmp(m->txid, n->txid, 32);
        if (c == 0)
            c = m->output_index == n->output_index
                ? 0 : (m->output_index < n->output_index ? -1 : 1);
        if (c == 0)
            return m;
        if (c < 0)
            lo = mid + 1;
        else
            hi = mid;
    }
    return NULL;
}

/* One note the send may use: confirmed deep enough, spendable by the wallet
 * summary's rule, and above the phone spend floor. The stricter limit wins; an
 * unknown height is at or below any floor. */
static bool wa_send_candidate(const struct db_wallet_note_fact *fact, int tip,
                              int min_conf, int32_t spend_floor,
                              const uint8_t (*sp)[32], size_t ns,
                              bool *floor_dropped, bool *conf_dropped)
{
    if (!fact || !wallet_note_is_spendable(fact, sp, ns, tip))
        return false;
    int confs = fact->block_height > 0 && fact->block_height <= tip
        ? tip - fact->block_height + 1 : 0;
    bool conf_ok = confs >= min_conf;
    bool floor_ok = wallet_spend_gate_height_ok(spend_floor, fact->block_height);
    *conf_dropped |= !conf_ok;
    *floor_dropped |= !floor_ok;
    return conf_ok && floor_ok;
}

int wallet_send_spendable_notes(struct wallet_rpc_context *ctx,
                                const uint8_t ivk[32], int min_conf,
                                int32_t spend_floor,
                                struct db_sapling_note *out, int cap)
{
    struct json_value unused;
    struct wa_state st;
    json_init(&unused);
    if (!wa_state_load(ctx, &st, false, &unused)) {
        json_free(&unused);
        return -1; // raw-return-ok:callee-logged
    }
    json_free(&unused);
    const struct wa_facts *f = &st.facts;
    size_t ns = 0;
    uint8_t (*sp)[32] = wallet_note_spenders(
        f->notes, (size_t)f->nn, f->coins, (size_t)f->nc,
        (const uint8_t (*)[32])st.keys.ivk, st.keys.n, &ns);
    int total = db_sapling_note_count_unspent(ctx->node_db);
    struct db_sapling_note *all = total >= 0
        ? zcl_calloc((size_t)total + 1, sizeof(*all), "send note scan") : NULL;
    int got = all ? db_sapling_note_list_unspent_for_ivk(
                        ctx->node_db, ivk, all, (size_t)total) : -1;
    int kept = got < 0 || !sp ? -1 : 0;
    bool floor_dropped = false, conf_dropped = false;
    for (int i = 0; i < got && kept >= 0 && kept < cap; i++) {
        const struct db_wallet_note_fact *fact = wa_fact_of(f, &all[i]);
        if (wa_send_candidate(fact, st.view.tip_height, min_conf, spend_floor,
                              (const uint8_t (*)[32])sp, ns, &floor_dropped,
                              &conf_dropped))
            out[kept++] = all[i];
    }
    wallet_spend_gate_note_scan(floor_dropped, conf_dropped);
    free(all);
    free(sp);
    wa_state_free(&st);
    return kept;
}

/* ── history ─────────────────────────────────────────────────────── */

/* Add the receiving address and memo of the wallet's own notes in one
 * transaction: the first address any of them has and the first memo any of
 * them carries. False when the notes could not be read. */
static bool wa_detail_memo(struct wallet_rpc_context *ctx,
                           const struct wa_keys *k, const uint8_t txid[32],
                           struct json_value *entry)
{
    struct db_wallet_note_memo memos[32];
    int n = db_wallet_note_memos_for_tx(ctx->node_db, txid, memos, 32);
    bool have_address = false, have_memo = false;
    if (n < 0)
        LOG_FAIL("wallet_activity", "wallethistory: note read failed");
    for (int i = 0; i < n; i++) {
        if (!wa_ivk_in(k, memos[i].ivk))
            continue;
        if (!have_address && memos[i].address[0]) {
            json_push_kv_str(entry, "address", memos[i].address);
            have_address = true;
        }
        if (!have_memo) {
            size_t before = entry->num_children;
            wallet_memo_to_json(entry, memos[i].memo, memos[i].memo_len);
            have_memo = entry->num_children > before;
        }
    }
    wa_kv_null(entry, "counterparty");
    json_push_kv_bool(entry, "counterparty_known", false);
    return true;
}

static bool wa_history_detail(struct wallet_rpc_context *ctx,
                              const struct wa_keys *k,
                              const struct wallet_history_entry *e, int n,
                              const char *txid_hex, bool shielded_known,
                              struct json_value *result)
{
    struct uint256 id;
    uint256_set_hex(&id, txid_hex);
    for (int i = 0; i < n; i++) {
        if (memcmp(e[i].txid, id.data, 32) != 0)
            continue;
        struct json_value entry;
        json_init(&entry);
        wallet_history_entry_to_json(&e[i], &entry);
        if (!wa_detail_memo(ctx, k, e[i].txid, &entry)) {
            json_free(&entry);
            json_set_str(result, "Wallet database unreadable");
            return false; // raw-return-ok:callee-logged
        }
        json_set_object(result);
        json_push_kv_str(result, "schema", "zcl.wallet_history.v1");
        json_push_kv_str(result, "shielded_state",
                         shielded_known ? "ok" : "keys_unavailable");
        json_push_kv(result, "entry", &entry);
        json_free(&entry);
        return true;
    }
    json_set_str(result, shielded_known
                 ? "Transaction is not in wallet history"
                 : "Shielded history is unavailable while the wallet is locked");
    return false;
}

static void wa_history_page(const struct wallet_history_entry *e, int n,
                            size_t start, size_t limit, bool shielded_known,
                            struct json_value *result)
{
    struct json_value list;
    json_init(&list);
    json_set_array(&list);
    size_t end = start + limit < (size_t)n ? start + limit : (size_t)n;
    for (size_t i = start; i < end; i++) {
        struct json_value item;
        json_init(&item);
        wallet_history_entry_to_json(&e[i], &item);
        json_push_back(&list, &item);
        json_free(&item);
    }
    json_set_object(result);
    json_push_kv_str(result, "schema", "zcl.wallet_history.v1");
    json_push_kv_str(result, "shielded_state",
                     shielded_known ? "ok" : "keys_unavailable");
    json_push_kv(result, "entries", &list);
    json_push_kv_int(result, "count", (int64_t)(end - start));
    json_free(&list);
    if (end < (size_t)n) {
        char cur[96];
        wallet_history_cursor_format(&e[end - 1], cur, sizeof(cur));
        json_push_kv_str(result, "next_cursor", cur);
    } else {
        wa_kv_null(result, "next_cursor");
    }
}

static bool wa_history_args(const struct json_value *params, size_t *limit,
                            struct wallet_history_page_key *cur,
                            const char **txid, struct json_value *result)
{
    struct rpc_params p;
    rpc_params_init(&p, params);
    rpc_params_expect(&p, 0, 3);
    int64_t lim = rpc_permit_int(&p, 0, "limit", WALLET_HISTORY_DEFAULT_LIMIT);
    const char *cursor = rpc_permit_str(&p, 1, "cursor", "");
    *txid = rpc_permit_str(&p, 2, "txid", "");
    if (rpc_params_invalid(&p)) {
        rpc_params_error(&p, result);
        LOG_FAIL("wallet_activity", "wallethistory: invalid params");
    }
    if (lim < 1 || lim > WALLET_HISTORY_MAX_LIMIT ||
        (cursor[0] && !wallet_history_cursor_parse(cursor, cur)) ||
        ((*txid)[0] && strlen(*txid) != 64)) {
        json_set_str(result, "Invalid limit, cursor or txid");
        LOG_FAIL("wallet_activity", "wallethistory: argument out of range");
    }
    *limit = (size_t)lim;
    return true;
}

bool rpc_wallethistory(const struct json_value *params, bool help,
                       struct json_value *result)
{
    struct wallet_rpc_context *ctx = wallet_ctx();
    RPC_HELP(help, result, "wallethistory ( limit \"cursor\" \"txid\" )\n"
        "\nReturns wallet transactions newest first, paged by cursor.\n");
    if (!wa_ready(ctx, result))
        return false; // raw-return-ok:callee-logged
    size_t limit = 0;
    const char *txid = "";
    struct wallet_history_page_key cur = {0};
    if (!wa_history_args(params, &limit, &cur, &txid, result))
        return false; // raw-return-ok:callee-logged

    struct wa_state st;
    if (!wa_state_load(ctx, &st, true, result))
        return false; // raw-return-ok:callee-logged
    const struct wa_facts *f = &st.facts;
    struct wallet_history_entry *e = NULL;
    int n = wallet_history_build(f->notes, (size_t)f->nn, f->coins,
                                 (size_t)f->nc, f->txs, (size_t)f->nt,
                                 (const uint8_t (*)[32])st.keys.ivk,
                                 st.keys.n, st.view.tip_height, &e);
    bool ok = n >= 0;
    if (!ok)
        json_set_str(result, "Out of memory");
    else if (txid[0])
        ok = wa_history_detail(ctx, &st.keys, e, n, txid,
                               st.keys.known, result);
    else
        wa_history_page(e, n, wallet_history_page_start(e, (size_t)n, &cur),
                        limit, st.keys.known, result);
    free(e);
    wa_state_free(&st);
    return ok;
}

/* Resolve the selected account's durable reservation without issuing one. */
static enum wallet_diversifier_current wa_current_receive(
    struct wallet_rpc_context *ctx, char *out, size_t cap)
{
    struct sapling_key_entry acct;
    if (!sapling_keystore_copy_receive_account(&ctx->wallet->sapling_keys, &acct))
        return WALLET_DIVERSIFIER_ABSENT;
    uint8_t d[ZC_DIVERSIFIER_SIZE], pk_d[32];
    enum wallet_diversifier_current current = ctx->wallet_db
        ? wallet_sqlite_diversifier_current(ctx->wallet_db, &acct, d, pk_d)
        : WALLET_DIVERSIFIER_INVALID;
    if (current == WALLET_DIVERSIFIER_ABSENT) {
        memcpy(d, acct.diversifier, sizeof(d));
        memcpy(pk_d, acct.pk_d, sizeof(pk_d));
    }
    const struct chain_params *cp = chain_params_get();
    bool encoded = current != WALLET_DIVERSIFIER_INVALID && cp &&
        sapling_encode_payment_address(d, pk_d,
            cp->bech32HRPs[BECH32_SAPLING_PAYMENT_ADDRESS], out, cap);
    memory_cleanse(&acct, sizeof(acct));
    return encoded ? WALLET_DIVERSIFIER_PRESENT : WALLET_DIVERSIFIER_INVALID;
}

bool rpc_walletlatestaddress(const struct json_value *params, bool help,
                             struct json_value *result)
{
    struct wallet_rpc_context *ctx = wallet_ctx();
    RPC_HELP(help, result, "walletlatestaddress\n"
        "\nReturns the current reserved receive address, or the account default. Creates nothing.\n");
    (void)params;
    if (!ctx->wallet) {
        json_set_str(result, "Wallet not available");
        LOG_FAIL("wallet_activity", "walletlatestaddress: no wallet");
    }
    char addr[128];
    enum wallet_diversifier_current current = wa_current_receive(ctx, addr, sizeof(addr));
    bool have = current == WALLET_DIVERSIFIER_PRESENT;
    json_set_object(result);
    json_push_kv_str(result, "schema", "zcl.wallet_latest_address.v1");
    if (have)
        json_push_kv_str(result, "address", addr);
    else
        wa_kv_null(result, "address");
    /* A wallet that holds no loaded key cannot say it has none unless it is
     * unlocked and no key is persisted. */
    json_push_kv_str(result, "state",
                     have ? "ok" : current == WALLET_DIVERSIFIER_INVALID
                         ? "address_unavailable" : wa_no_sapling_keys_certain(ctx)
                             ? "none" : "keys_unavailable");
    return true;
}

void register_wallet_activity_rpc_commands(struct rpc_table *t)
{
    struct rpc_command cmds[] = {
        { "wallet", "walletlatestaddress", rpc_walletlatestaddress, false },
        { "wallet", "walletsummary", rpc_walletsummary, false },
        { "wallet", "wallethistory", rpc_wallethistory, false },
    };
    for (size_t i = 0; i < sizeof(cmds) / sizeof(cmds[0]); i++)
        rpc_table_must_append(t, &cmds[i]);
}
