/* purpose: Reject divergence between Ironwood retained wire and decoded state. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "services/ironwood_checked_wire.h"
#include "core/serialize.h"
#include "primitives/transaction.h"
#include "primitives/transaction_v6_decode.h"
#include <stdio.h>
#include <string.h>

static bool refused(const struct transaction *tx, size_t max)
{
    struct v6_wire_view view, before;
    memset(&view, 0x59, sizeof view);
    memcpy(&before, &view, sizeof before);
    return !ironwood_checked_wire(tx, max, &view).ok && !memcmp(&view, &before, sizeof view);
}

static bool field_mutation(struct transaction *tx, uint8_t *field)
{
    *field ^= 1;
    bool ok = refused(tx, tx->v6_wire.size);
    *field ^= 1;
    return ok;
}

static bool check_transparent(struct transaction *tx)
{
    if (tx->num_vin) {
        struct tx_in *saved = tx->vin;
        tx->vin = NULL;
        bool ok = refused(tx, tx->v6_wire.size);
        tx->vin = saved;
        if (!ok || !field_mutation(tx, saved->prevout.hash.data)) return false;
        if (saved->script_sig.size && !field_mutation(tx, saved->script_sig.data)) return false;
    }
    if (tx->num_vout) {
        tx->vout->value ^= 1;
        bool ok = refused(tx, tx->v6_wire.size);
        tx->vout->value ^= 1;
        if (!ok) return false;
    }
    return true;
}

static bool check_sapling(struct transaction *tx)
{
    if (tx->num_shielded_spend) {
        struct spend_description *spend = tx->v_shielded_spend;
        if (!field_mutation(tx, spend->anchor.data) || !field_mutation(tx, spend->zkproof) ||
            !field_mutation(tx, spend->spend_auth_sig)) return false;
    }
    if (tx->num_shielded_output) {
        struct output_description *o = tx->v_shielded_output;
        if (!field_mutation(tx, o->out_ciphertext) || !field_mutation(tx, o->zkproof)) return false;
    }
    if (tx->num_shielded_spend || tx->num_shielded_output)
        return field_mutation(tx, tx->binding_sig);
    return true;
}

static bool check_ironwood_balance(struct transaction *tx)
{
    tx->ironwood_value_balance ^= 1;
    bool ok = refused(tx, tx->v6_wire.size);
    tx->ironwood_value_balance ^= 1;
    return ok;
}

static bool check_model(uint8_t *wire, size_t len)
{
    struct byte_stream s;
    stream_init_from_data(&s, wire, len);
    struct transaction tx;
    struct v6_wire_view view;
    bool decoded = transaction_v6_decode_prefix(&tx, &s, len);
    bool ok = decoded && !stream_remaining(&s) && ironwood_checked_wire(&tx, len, &view).ok &&
        view.header.data == tx.v6_wire.data && refused(&tx, len - 1) &&
        field_mutation(&tx, tx.hash.data) && check_transparent(&tx) && check_sapling(&tx) &&
        check_ironwood_balance(&tx);
    transaction_free(&tx);
    return ok;
}

static bool check_fixture(const char *path)
{
    uint8_t bytes[10000];
    FILE *f = fopen(path, "rb");
    if (!f) return false;
    size_t n = fread(bytes, 1, sizeof bytes, f);
    bool ok = feof(f) && !ferror(f) && n && check_model(bytes, n);
    fclose(f);
    return ok;
}

int test_ironwood_checked_wire(void)
{
    int failures = 0;
    failures += !check_fixture("tests/fixtures/ironwood/postnu63-h1-reward-spend.v6");
    failures += !check_fixture("tests/fixtures/ironwood/postnu63-h1-reward-withdrawal.v6");
    failures += !check_fixture("tests/fixtures/ironwood/postnu63-ballot-v6.bin");
    /* Structurally framed output-only Sapling data exercises split proof and
     * ciphertext encoding without claiming cryptographic authorization. */
    uint8_t wire[20+2+2+756+8+GROTH_PROOF_SIZE+64+2] = {6,0,0,128,152,182,132,216};
    wire[23] = 1;
    failures += !check_model(wire, sizeof wire);
    return failures;
}
