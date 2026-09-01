/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * simnet_wallet — deterministic transparent wallet helpers for simnet.
 */

#include "sim/simnet_wallet.h"

#include "base/hex.h"
#include "consensus/consensus.h"
#include "core/amount.h"
#include "platform/rng.h"
#include "policy/fees.h"
#include "primitives/transaction.h"
#include "script/standard.h"
#include "sim/simnet_mempool.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct simnet_wallet_utxo {
    struct uint256 txid;
    uint32_t vout;
    int64_t value;
    int mature_height;
    bool spent;
};

struct simnet_wallet {
    struct simnet *sim;
    uint8_t secret[32];
    uint8_t pubkey[33];
    struct key_id key;
    struct script script_pubkey;
    char address[48];
    struct simnet_wallet_utxo *utxos;
    size_t utxo_count;
    size_t utxo_cap;
};

static void tx_result_clear(struct simnet_tx_result *out)
{
    if (!out)
        return;
    memset(out, 0, sizeof(*out));
    uint256_set_null(&out->txid);
    out->change_vout = UINT32_MAX;
}

int64_t simnet_wallet_default_fee_per_k(void)
{
    return SIMNET_WALLET_DEFAULT_FEE_PER_K;
}

struct fee_rate simnet_wallet_default_fee_rate(void)
{
    struct fee_rate r;
    r.satoshis_per_k = simnet_wallet_default_fee_per_k();
    return r;
}

static void rng_bytes(uint8_t *out, size_t len)
{
    size_t off = 0;
    while (off < len) {
        uint64_t v = rng_u64();
        size_t take = len - off < sizeof(v) ? len - off : sizeof(v);
        memcpy(out + off, &v, take);
        off += take;
    }
}

static void wallet_make_address(struct simnet_wallet *w)
{
    memcpy(w->address, "sim1", 4);
    zcl_hex_encode(w->key.id.data, 20, w->address + 4);
}

struct simnet_wallet *simnet_wallet_create(struct simnet *s)
{
    if (!s || !s->initialized)
        LOG_NULL("simnet.wallet", "create called with uninitialized simnet");

    struct simnet_wallet *w =
        zcl_malloc(sizeof(*w), "simnet_wallet");
    if (!w)
        LOG_NULL("simnet.wallet", "alloc wallet failed");
    memset(w, 0, sizeof(*w));
    w->sim = s;

    rng_bytes(w->secret, sizeof(w->secret));
    w->pubkey[0] = 0x02 | (w->secret[0] & 1u);
    memcpy(w->pubkey + 1, w->secret, 32);
    hash160(w->pubkey, sizeof(w->pubkey), w->key.id.data);
    script_for_p2pkh(&w->script_pubkey, &w->key);
    wallet_make_address(w);
    return w;
}

void simnet_wallet_free(struct simnet_wallet *w)
{
    if (!w)
        return;
    free(w->utxos);
    memset(w, 0, sizeof(*w));
    free(w);
}

const char *simnet_wallet_address(const struct simnet_wallet *w)
{
    return w ? w->address : "";
}

const struct script *simnet_wallet_script(const struct simnet_wallet *w)
{
    return w ? &w->script_pubkey : NULL;
}

static bool wallet_add_utxo(struct simnet_wallet *w,
                            const struct uint256 *txid, uint32_t vout,
                            int64_t value, int mature_height)
{
    if (!w || !txid || !MoneyRange(value))
        LOG_FAIL("simnet.wallet", "invalid utxo add");
    if (w->utxo_count == w->utxo_cap) {
        size_t new_cap = w->utxo_cap ? w->utxo_cap * 2 : 8;
        if (new_cap < w->utxo_cap)
            LOG_FAIL("simnet.wallet", "utxo capacity overflow");
        struct simnet_wallet_utxo *nu =
            zcl_realloc(w->utxos, new_cap * sizeof(*nu),
                        "simnet_wallet_utxos");
        if (!nu)
            LOG_FAIL("simnet.wallet", "utxo realloc failed");
        w->utxos = nu;
        w->utxo_cap = new_cap;
    }

    struct simnet_wallet_utxo *u = &w->utxos[w->utxo_count++];
    memset(u, 0, sizeof(*u));
    u->txid = *txid;
    u->vout = vout;
    u->value = value;
    u->mature_height = mature_height;
    u->spent = false;
    return true;
}

static bool wallet_utxo_live(struct simnet_wallet *w, size_t idx,
                             int64_t *value_out)
{
    if (!w || idx >= w->utxo_count)
        return false;
    struct simnet_wallet_utxo *u = &w->utxos[idx];
    if (u->spent || w->sim->tip_height < u->mature_height)
        return false;
    int64_t chain_value = 0;
    if (!simnet_coin_value(w->sim, &u->txid, u->vout, &chain_value))
        return false;
    if (chain_value != u->value)
        return false;
    if (value_out)
        *value_out = u->value;
    return true;
}

int64_t simnet_wallet_balance(struct simnet_wallet *w)
{
    if (!w || !w->sim || !w->sim->initialized)
        return 0;
    int64_t total = 0;
    for (size_t i = 0; i < w->utxo_count; i++) {
        int64_t value = 0;
        if (!wallet_utxo_live(w, i, &value))
            continue;
        if (total > MAX_MONEY - value)
            return 0;
        total += value;
    }
    return total;
}

bool simnet_wallet_fund(struct simnet_wallet *w, int64_t amount,
                        struct simnet_tx_result *out)
{
    tx_result_clear(out);
    if (!w || !w->sim || !w->sim->initialized || !MoneyRange(amount) ||
        amount <= 0)
        LOG_FAIL("simnet.wallet", "invalid fund request");

    int fund_height = w->sim->tip_height + 1;
    struct uint256 txid;
    if (!simnet_mint_coinbase_to(w->sim, &w->script_pubkey, amount, &txid))
        return false;

    int mature_height = fund_height + COINBASE_MATURITY;
    if (!wallet_add_utxo(w, &txid, 0, amount, mature_height))
        return false;
    if (!simnet_mint_to_height(w->sim, mature_height))
        return false;

    if (out) {
        out->txid = txid;
        out->fee = 0;
        out->tx_size = 0;
        out->input_value = 0;
        out->output_value = amount;
        out->change_value = 0;
        out->change_vout = UINT32_MAX;
    }
    return true;
}

static bool recipient_script(const struct simnet_wallet_recipient *r,
                             const struct script **script_out)
{
    if (!r || r->amount <= 0)
        return false;
    if (r->script) {
        *script_out = r->script;
        return true;
    }
    if (r->wallet) {
        *script_out = &r->wallet->script_pubkey;
        return true;
    }
    return false;
}

static bool build_op_return_script(struct script *out,
                                   const uint8_t *payload, size_t payload_len)
{
    if (!out || (!payload && payload_len > 0) ||
        payload_len > MAX_OP_RETURN_RELAY)
        LOG_FAIL("simnet.wallet", "invalid OP_RETURN payload len=%zu",
                 payload_len);
    script_init(out);
    if (!script_push_op(out, OP_RETURN))
        LOG_FAIL("simnet.wallet", "failed to push OP_RETURN");
    if (payload_len > 0 && !script_push_data(out, payload, payload_len))
        LOG_FAIL("simnet.wallet", "failed to push OP_RETURN payload");
    return true;
}

static bool build_tx_from_selection(struct simnet_wallet *from,
                                    const size_t *selected, size_t nselected,
                                    const struct simnet_wallet_recipient *recips,
                                    size_t nrecips,
                                    const struct script *opret_script,
                                    bool include_change,
                                    int64_t change_value,
                                    struct transaction *tx)
{
    transaction_init(tx);
    if (!from || !selected || nselected == 0)
        LOG_FAIL("simnet.wallet", "invalid tx build selection");

    size_t nout = nrecips + (opret_script ? 1u : 0u) +
                  (include_change ? 1u : 0u);
    if (nout == 0)
        LOG_FAIL("simnet.wallet", "transaction would have no outputs");
    if (!transaction_alloc(tx, nselected, nout))
        LOG_FAIL("simnet.wallet", "transaction_alloc failed");

    tx->version = 1;
    for (size_t i = 0; i < nselected; i++) {
        const struct simnet_wallet_utxo *u = &from->utxos[selected[i]];
        tx->vin[i].prevout.hash = u->txid;
        tx->vin[i].prevout.n = u->vout;
        {
            uint8_t sig[] = {0x00, 0x00};
            script_set(&tx->vin[i].script_sig, sig, sizeof(sig));
        }
        tx->vin[i].sequence = 0xFFFFFFFFu;
    }

    size_t oi = 0;
    if (opret_script) {
        tx->vout[oi].value = 0;
        tx->vout[oi].script_pub_key = *opret_script;
        oi++;
    }
    for (size_t i = 0; i < nrecips; i++) {
        const struct script *sp = NULL;
        if (!recipient_script(&recips[i], &sp)) {
            transaction_free(tx);
            LOG_FAIL("simnet.wallet", "invalid recipient at index %zu", i);
        }
        tx->vout[oi].value = recips[i].amount;
        tx->vout[oi].script_pub_key = *sp;
        oi++;
    }
    if (include_change) {
        tx->vout[oi].value = change_value;
        tx->vout[oi].script_pub_key = from->script_pubkey;
    }

    transaction_compute_hash(tx);
    return true;
}

static bool sum_recipients(const struct simnet_wallet_recipient *recips,
                           size_t nrecips, int64_t *sum_out)
{
    int64_t total = 0;
    for (size_t i = 0; i < nrecips; i++) {
        const struct script *sp = NULL;
        if (!recipient_script(&recips[i], &sp))
            LOG_FAIL("simnet.wallet", "invalid recipient at index %zu", i);
        (void)sp;
        if (!MoneyRange(recips[i].amount) ||
            total > MAX_MONEY - recips[i].amount)
            LOG_FAIL("simnet.wallet", "recipient value overflow");
        total += recips[i].amount;
    }
    *sum_out = total;
    return true;
}

static bool build_funded_tx(struct simnet_wallet *from,
                            const size_t *selected, size_t nselected,
                            int64_t selected_value,
                            const struct simnet_wallet_recipient *recips,
                            size_t nrecips,
                            const struct script *opret_script,
                            int64_t send_value,
                            struct transaction *tx,
                            struct simnet_tx_result *res)
{
    struct fee_rate rate = simnet_wallet_default_fee_rate();
    bool include_change = true;

    for (int pass = 0; pass < 3; pass++) {
        struct transaction trial;
        if (!build_tx_from_selection(from, selected, nselected, recips,
                                     nrecips, opret_script, include_change,
                                     0, &trial))
            return false;
        size_t tx_size = transaction_serialize_size(&trial);
        transaction_free(&trial);
        if (tx_size == 0)
            LOG_FAIL("simnet.wallet", "trial serialization failed");
        int64_t fee = fee_rate_get_fee(&rate, tx_size);
        if (!MoneyRange(fee))
            LOG_FAIL("simnet.wallet", "fee out of range");
        if (fee > MAX_MONEY - send_value)
            LOG_FAIL("simnet.wallet", "send value plus fee overflows");
        if (selected_value < send_value + fee)
            return false;

        int64_t change = selected_value - send_value - fee;
        bool need_change = change > 0;
        if (need_change != include_change) {
            include_change = need_change;
            continue;
        }

        if (!build_tx_from_selection(from, selected, nselected, recips,
                                     nrecips, opret_script, need_change,
                                     change, tx))
            return false;
        size_t final_size = transaction_serialize_size(tx);
        int64_t final_fee = fee_rate_get_fee(&rate, final_size);
        if (final_fee != fee) {
            transaction_free(tx);
            include_change = need_change;
            continue;
        }
        if (res) {
            res->txid = tx->hash;
            res->fee = final_fee;
            res->tx_size = final_size;
            res->input_value = selected_value;
            res->output_value = send_value + change;
            res->change_value = change;
            res->change_vout = need_change ? (uint32_t)(tx->num_vout - 1)
                                           : UINT32_MAX;
        }
        return true;
    }

    LOG_FAIL("simnet.wallet", "fee/change calculation did not converge");
}

static bool wallet_enqueue_tx(struct simnet_wallet *from,
                              const size_t *selected, size_t nselected,
                              const struct simnet_wallet_recipient *recips,
                              size_t nrecips,
                              struct transaction *tx,
                              struct simnet_tx_result *res)
{
    struct simnet_mempool_result mr;
    if (!simnet_mempool_add(from->sim, tx, &mr)) {
        transaction_free(tx);
        LOG_FAIL("simnet.wallet", "mempool add failed: %s", mr.detail);
    }

    for (size_t i = 0; i < nselected; i++)
        from->utxos[selected[i]].spent = true;

    if (res && res->change_vout != UINT32_MAX && res->change_value > 0) {
        if (!wallet_add_utxo(from, &res->txid, res->change_vout,
                             res->change_value, from->sim->tip_height + 1)) {
            transaction_free(tx);
            return false;
        }
    }

    size_t offset = (tx->num_vout > nrecips &&
                     tx->vout[0].script_pub_key.size > 0 &&
                     tx->vout[0].script_pub_key.data[0] == OP_RETURN)
                    ? 1u : 0u;
    for (size_t i = 0; i < nrecips; i++) {
        if (!recips[i].wallet)
            continue;
        if (!wallet_add_utxo(recips[i].wallet, &res->txid,
                             (uint32_t)(offset + i), recips[i].amount,
                             from->sim->tip_height + 1)) {
            transaction_free(tx);
            return false;
        }
    }

    transaction_free(tx);
    return true;
}

static bool wallet_send_core(struct simnet_wallet *from,
                             const struct simnet_wallet_recipient *recips,
                             size_t nrecips,
                             const struct script *opret_script,
                             struct simnet_tx_result *out)
{
    tx_result_clear(out);
    if (!from || !from->sim || !from->sim->initialized)
        LOG_FAIL("simnet.wallet", "invalid sender wallet");
    if (nrecips == 0 && !opret_script)
        LOG_FAIL("simnet.wallet", "send needs a recipient or OP_RETURN");
    if (from->utxo_count == 0)
        LOG_FAIL("simnet.wallet", "insufficient spendable balance");

    int64_t send_value = 0;
    if (!sum_recipients(recips, nrecips, &send_value))
        return false;

    size_t *selected =
        zcl_malloc(from->utxo_count * sizeof(*selected),
                   "simnet_wallet_selected");
    if (!selected)
        LOG_FAIL("simnet.wallet", "selected utxo alloc failed");

    size_t nselected = 0;
    int64_t selected_value = 0;
    struct transaction tx;
    bool built = false;
    struct simnet_tx_result res;
    tx_result_clear(&res);

    for (size_t i = 0; i < from->utxo_count; i++) {
        int64_t value = 0;
        if (!wallet_utxo_live(from, i, &value))
            continue;
        if (selected_value > MAX_MONEY - value) {
            free(selected);
            LOG_FAIL("simnet.wallet", "selected value overflow");
        }
        selected[nselected++] = i;
        selected_value += value;
        if (build_funded_tx(from, selected, nselected, selected_value,
                            recips, nrecips, opret_script, send_value,
                            &tx, &res)) {
            built = true;
            break;
        }
    }

    if (!built) {
        free(selected);
        LOG_FAIL("simnet.wallet", "insufficient spendable balance");
    }

    if (out)
        *out = res;
    bool ok = wallet_enqueue_tx(from, selected, nselected, recips, nrecips,
                                &tx, &res);
    free(selected);
    return ok;
}

bool simnet_wallet_send_many(struct simnet_wallet *from,
                             const struct simnet_wallet_recipient *recips,
                             size_t nrecips,
                             struct simnet_tx_result *out)
{
    if (!recips || nrecips == 0)
        LOG_FAIL("simnet.wallet", "send_many needs recipients");
    return wallet_send_core(from, recips, nrecips, NULL, out);
}

bool simnet_wallet_send(struct simnet_wallet *from, const struct script *to,
                        int64_t amount, struct simnet_tx_result *out)
{
    struct simnet_wallet_recipient r = {
        .script = to,
        .wallet = NULL,
        .amount = amount,
    };
    return simnet_wallet_send_many(from, &r, 1, out);
}

bool simnet_wallet_send_to_wallet(struct simnet_wallet *from,
                                  struct simnet_wallet *to,
                                  int64_t amount,
                                  struct simnet_tx_result *out)
{
    struct simnet_wallet_recipient r = {
        .script = NULL,
        .wallet = to,
        .amount = amount,
    };
    return simnet_wallet_send_many(from, &r, 1, out);
}

bool simnet_wallet_op_return(struct simnet_wallet *from,
                             const uint8_t *payload, size_t payload_len,
                             const struct simnet_wallet_recipient *value_out,
                             struct simnet_tx_result *out)
{
    struct script opret;
    if (!build_op_return_script(&opret, payload, payload_len))
        return false;
    if (value_out)
        return wallet_send_core(from, value_out, 1, &opret, out);
    return wallet_send_core(from, NULL, 0, &opret, out);
}
