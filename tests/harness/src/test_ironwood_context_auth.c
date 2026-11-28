/* purpose: Check private v6 authorization components against an isolated coin view. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "jobs/ironwood_context_auth.h"
#include "base/hex.h"
#include "chain/chainparams.h"
#include "core/serialize.h"
#include "primitives/transaction_v6_decode.h"
#include "primitives/transaction_v6_wire.h"
#include "script/script_flags.h"
#include "storage/coins_kv.h"
#include <sqlite3.h>
#include <stdio.h>
#include <string.h>

#define SELECTED_BRANCH UINT32_C(0x37a5165b)
#define TEST_FLAGS (SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY)
struct auth_fixture { sqlite3 *db; uint8_t txid[32], script[25]; };
static bool coin_lookup(const struct uint256 *txid, uint32_t index,
    struct utxo_apply_lookup *out, void *user)
{
    struct auth_fixture *f = user;
    size_t size = 0; int32_t height = 0; bool coinbase = false;
    memset(out, 0, sizeof *out);
    if (!coins_kv_get_prevout(f->db, txid->data, index, &out->value,
            out->script, sizeof out->script, &size, &height, &coinbase)) return true;
    if (size > sizeof out->script || height < 0) return false;
    out->found = true; out->script_len = (uint32_t)size;
    out->height = (uint32_t)height; out->is_coinbase = coinbase;
    return true;
}
static bool load_transaction(const char *path, uint8_t *wire, size_t size, struct transaction *tx)
{
    FILE *f = fopen(path, "rb");
    if (!f) return false;
    bool ok = fread(wire, 1, size, f) == size && fgetc(f) == EOF && !ferror(f);
    if (fclose(f) != 0 || !ok) return false;
    struct byte_stream stream;
    stream_init_from_data(&stream, wire, size);
    transaction_init(tx);
    if (!transaction_v6_decode_prefix(tx, &stream, size) || stream_remaining(&stream)) {
        transaction_free(tx);
        return false;
    }
    return true;
}
static bool fixture_init(struct auth_fixture *f)
{
    memset(f, 0, sizeof *f);
    return zcl_hex_decode("e46d7568c0973fff0d0bb1daaf9fcb4ff98e2f91d2e253e9e40d772d5a5223b9", f->txid, 32) &&
        zcl_hex_decode("76a91479b000887626b294a914501a4cd226b58b23598388ac", f->script, 25) &&
        sqlite3_open(":memory:", &f->db) == SQLITE_OK && coins_kv_ensure_schema(f->db) &&
        coins_kv_add(f->db, f->txid, 0, 1250000000, 0, true, f->script, 25);
}
static enum ironwood_context_auth_result authenticate(struct auth_fixture *f,
    const struct transaction *tx, uint32_t branch)
{
    return ironwood_context_authenticate(tx, branch, TEST_FLAGS, coin_lookup, f);
}
static bool payment_controls(struct auth_fixture *f, struct transaction *tx)
{
    if (authenticate(f, tx, SELECTED_BRANCH) != IRONWOOD_CONTEXT_COMPONENTS_OK ||
        authenticate(f, tx, SELECTED_BRANCH ^ 1) != IRONWOOD_CONTEXT_UNSUPPORTED ||
        !coins_kv_spend(f->db, f->txid, 0) ||
        authenticate(f, tx, SELECTED_BRANCH) != IRONWOOD_CONTEXT_PREVOUT_UNAVAILABLE ||
        !coins_kv_add(f->db, f->txid, 0, 1249999999, 0, true, f->script, 25) ||
        authenticate(f, tx, SELECTED_BRANCH) != IRONWOOD_CONTEXT_CHECK_UNAVAILABLE ||
        !coins_kv_add(f->db, f->txid, 0, 1250000000, 0, true, f->script, 25)) return false;
    struct v6_wire_view view;
    if (v6_core_parse(tx->v6_wire.data, tx->v6_wire.size, &view) != V6_WIRE_OK ||
        view.ironwood.binding_signature.size != 64) return false;
    size_t offset = (size_t)(view.ironwood.binding_signature.data - tx->v6_wire.data);
    tx->v6_wire.data[offset] ^= 1;
    enum ironwood_context_auth_result r = authenticate(f, tx, SELECTED_BRANCH);
    tx->v6_wire.data[offset] ^= 1;
    return r == IRONWOOD_CONTEXT_CHECK_UNAVAILABLE;
}
static bool wrong_context_controls(struct auth_fixture *f, struct transaction *tx)
{
    if (ironwood_context_authenticate(tx, SELECTED_BRANCH, 0, coin_lookup, f) != IRONWOOD_CONTEXT_UNSUPPORTED) return false;
    chain_params_select(CHAIN_MAIN);
    enum ironwood_context_auth_result network = authenticate(f, tx, SELECTED_BRANCH);
    if (!chain_research_profile_select(CHAIN_RESEARCH_IRONWOOD) || network != IRONWOOD_CONTEXT_UNSUPPORTED) return false;
    f->script[3] ^= 1;
    bool inserted = coins_kv_add(f->db, f->txid, 0, 1250000000, 0, true, f->script, 25);
    f->script[3] ^= 1;
    if (!inserted) return false;
    enum ironwood_context_auth_result wrong_script = authenticate(f, tx, SELECTED_BRANCH);
    return coins_kv_add(f->db, f->txid, 0, 1250000000, 0, true, f->script, 25) &&
        wrong_script == IRONWOOD_CONTEXT_CHECK_UNAVAILABLE;
}
static bool proof_and_model_controls(struct auth_fixture *f, struct transaction *tx)
{
    struct v6_wire_view view;
    if (v6_core_parse(tx->v6_wire.data, tx->v6_wire.size, &view) != V6_WIRE_OK || !view.ironwood.proof.size) return false;
    size_t offset = (size_t)(view.ironwood.proof.data - tx->v6_wire.data);
    tx->v6_wire.data[offset] ^= 1;
    enum ironwood_context_auth_result proof = authenticate(f, tx, SELECTED_BRANCH);
    tx->v6_wire.data[offset] ^= 1;
    return proof == IRONWOOD_CONTEXT_CHECK_UNAVAILABLE;
}
static bool withdrawal_control(struct auth_fixture *f)
{
    uint8_t wire[9200]; struct transaction tx;
    if (!load_transaction("tests/fixtures/ironwood/postnu63-h1-reward-withdrawal.v6", wire, sizeof wire, &tx)) return false;
    bool ok = tx.num_vin == 0 && tx.num_vout == 1 && authenticate(f, &tx, SELECTED_BRANCH) == IRONWOOD_CONTEXT_COMPONENTS_OK;
    if (ok) {
        tx.vout[0].value ^= 1;
        ok = authenticate(f, &tx, SELECTED_BRANCH) == IRONWOOD_CONTEXT_CHECK_UNAVAILABLE;
        tx.vout[0].value ^= 1;
    }
    transaction_free(&tx);
    return ok;
}
int test_ironwood_context_auth(void)
{
    struct auth_fixture f = {0}; struct transaction tx; uint8_t wire[9313];
    bool loaded = false;
    bool ok = chain_research_profile_select(CHAIN_RESEARCH_IRONWOOD) && fixture_init(&f);
    if (ok) { loaded = load_transaction("tests/fixtures/ironwood/postnu63-h1-reward-spend.v6", wire, sizeof wire, &tx); ok = loaded; }
    if (ok) ok = payment_controls(&f, &tx) && wrong_context_controls(&f, &tx) && proof_and_model_controls(&f, &tx) && withdrawal_control(&f);
    if (loaded) transaction_free(&tx);
    if (f.db && sqlite3_close(f.db) != SQLITE_OK) ok = false;
    chain_params_select(CHAIN_MAIN);
    return ok ? 0 : 1;
}
