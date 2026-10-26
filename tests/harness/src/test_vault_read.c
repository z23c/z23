/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rhett Creighton
 *
 * Tests for the vault read model (contexts/wallet/services/src/vault_read.c).
 *
 * The bug this file pins down: funds committed to an atomic-swap HTLC are
 * owned — the node holds the redeem script, and can take them back with the
 * secret or, past locktime, with a refund — but no balance surface counted
 * them. `getbalance` calls db_wallet_utxo_spendable_balance, which reads
 * wallet_utxos alone; `walletledger` reconciles wallet_utxos against
 * wallet_sapling_notes. Neither one has ever read zswp_contracts. So a node
 * with a funded swap under-reports what it owns, silently.
 *
 * The first case below reproduces exactly that: a funded HTLC in
 * zswp_contracts, and both balance primitives answering zero. The second
 * shows the same amount surfacing in the vault as `encumbered` with grade
 * exact_contract_state. The rest hold the read model to its two rules —
 * every class emits a row, and an undeterminable class says so out loud.
 *
 * Hermetic: every case runs against a throwaway node.db under test-tmp/.
 */

#include "test/test_core.h"

#include "json/json.h"
#include "models/database.h"
#include "models/file_offer.h"
#include "models/swap_contract.h"
#include "models/wallet_tx.h"
#include "models/znam.h"
#include "models/zslp.h"
#include "controllers/swap_controller.h"
#include "script/htlc.h"
#include "services/vault_read.h"

#include <math.h>
#include <stdio.h>
#include <string.h>

#define VR_CHECK(name, expr) do {                       \
    printf("vault_read: %s... ", (name));               \
    if ((expr)) { printf("OK\n"); }                     \
    else { printf("FAIL\n"); failures++; }              \
} while (0)

/* The amount the swap locks up. Deliberately not a round number so it
 * cannot be confused with anything else in the output. */
#define VR_SWAP_AMOUNT 133742000LL

static void vr_fill_swap(struct swap_contract *sc, enum swap_state state)
{
    memset(sc, 0, sizeof(*sc));
    snprintf(sc->swap_id, sizeof(sc->swap_id), "%s",
             "abc123def456abc123def456abc123def456abc123def456abc123def4560011");
    sc->role  = SWAP_INITIATOR;
    sc->state = state;
    sc->chain = SWAP_CHAIN_ZCL;
    memset(sc->secret_hash, 0xA5, sizeof(sc->secret_hash));
    sc->amount   = VR_SWAP_AMOUNT;
    sc->locktime = 3200000;
    snprintf(sc->my_address, sizeof(sc->my_address), "t1VaultLaneAMine");
    snprintf(sc->counter_address, sizeof(sc->counter_address),
             "t1VaultLaneATheirs");
    sc->redeem_script[0]  = 0x63;   /* OP_IF */
    sc->redeem_script_len = 1;
    snprintf(sc->p2sh_address, sizeof(sc->p2sh_address), "t3VaultLaneAHtlc");
    sc->created_at = 1700000000;
}

static const struct vault_row *vr_row(const struct vault_snapshot *snap,
                                      const char *class_name)
{
    for (size_t i = 0; i < VAULT_CLASS_COUNT; i++)
        if (strcmp(snap->rows[i].class_name, class_name) == 0)
            return &snap->rows[i];
    return NULL;
}

static bool vr_seed_token_holdings(struct node_db *ndb)
{
    uint8_t owner[20], token_a[32], token_b[32], txid[32];
    sqlite3_stmt *s = NULL;
    bool ok = true;

    memset(owner, 0xA1, sizeof(owner));
    memset(token_a, 0x11, sizeof(token_a));
    memset(token_b, 0x22, sizeof(token_b));
    if (sqlite3_prepare_v2(ndb->db,
            "INSERT INTO wallet_keys"
            "(pubkey_hash,pubkey,privkey,compressed,created_at)"
            " VALUES(?,zeroblob(33),zeroblob(32),1,0)", -1, &s, NULL) !=
        SQLITE_OK)
        return false;
    sqlite3_bind_blob(s, 1, owner, 20, SQLITE_STATIC);
    ok = sqlite3_step(s) == SQLITE_DONE; /* raw-sql-ok:test-fixture-insert */
    sqlite3_finalize(s);

    if (sqlite3_prepare_v2(ndb->db,
            "INSERT INTO zslp_ledger"
            "(token_id,txid,vout,amount,address,created_height,role)"
            " VALUES(?,?,?,?,?,1,1)", -1, &s, NULL) != SQLITE_OK)
        return false;
    for (int i = 0; ok && i < 3; i++) {
        const uint8_t *token = i < 2 ? token_a : token_b;
        memset(txid, (unsigned char)(0x31 + i), sizeof(txid));
        sqlite3_reset(s);
        sqlite3_clear_bindings(s);
        sqlite3_bind_blob(s, 1, token, 32, SQLITE_STATIC);
        sqlite3_bind_blob(s, 2, txid, 32, SQLITE_STATIC);
        sqlite3_bind_int(s, 3, i + 1);
        sqlite3_bind_int64(s, 4, i == 0 ? 700 : i == 1 ? 300 : 9);
        sqlite3_bind_blob(s, 5, owner, 20, SQLITE_STATIC);
        ok = sqlite3_step(s) == SQLITE_DONE; /* raw-sql-ok:test-fixture-insert */
    }
    sqlite3_finalize(s);
    ok = ok && db_zslp_token_save(ndb, token_a, "ONE", "Token One", 2,
                                  "", 1, 1000);
    ok = ok && db_zslp_token_save(ndb, token_b, "TWO", "Token Two", 0,
                                  "", 1, 9);
    return ok && node_db_state_set_int(ndb, "zslp_ledger_cursor_height", 1);
}

static int vr_check_funded_htlc_invisible_to_balances(struct node_db *ndb,
                                                      struct swap_contract *sc)
{
    int failures = 0;

    vr_fill_swap(sc, SWAP_FUNDED);
    VR_CHECK("funded HTLC saved to zswp_contracts",
             db_swap_save(ndb, sc));

    {
        struct swap_contract found;
        VR_CHECK("the contract is really there, with its amount",
                 db_swap_find(ndb, sc->swap_id, &found) &&
                 found.amount == VR_SWAP_AMOUNT &&
                 found.state == SWAP_FUNDED);
    }

    /* This is the bug. Both numbers are zero while VR_SWAP_AMOUNT
     * zatoshi sit at a P2SH address this node can spend from. */
    VR_CHECK("BUG: getbalance's primitive cannot see the encumbered funds",
             db_wallet_utxo_spendable_balance(ndb, NULL) == 0);
    VR_CHECK("BUG: walletledger's two pools cannot see them either",
             db_wallet_utxo_balance_with_count(ndb, NULL) == 0 &&
             db_sapling_note_balance_with_count(ndb, NULL) == 0);
    return failures;
}

static int vr_check_vault_sees_encumbered_funds(struct node_db *ndb,
                                                struct vault_snapshot *snap)
{
    struct zcl_result r;
    int failures = 0;

    r = vault_read_snapshot(ndb, snap);
    VR_CHECK("vault snapshot builds", r.ok);

    {
        const struct vault_row *swap_row = vr_row(snap, "swap_encumbered");
        VR_CHECK("swap row exists", swap_row != NULL);
        VR_CHECK("the missing amount appears as encumbered",
                 swap_row && swap_row->encumbered == VR_SWAP_AMOUNT);
    }
    return failures;
}

static int vr_check_encumbered_row_grade_and_rollup(
    const struct vault_snapshot *snap)
{
    const struct vault_row *swap_row = vr_row(snap, "swap_encumbered");
    int failures = 0;

    VR_CHECK("graded exact_contract_state",
             swap_row && swap_row->determined &&
             strcmp(vault_evidence_name(swap_row->evidence),
                    "exact_contract_state") == 0);
    VR_CHECK("encumbered is NOT reported as spendable",
             swap_row && swap_row->spendable == 0);
    VR_CHECK("the rollup carries it where getbalance did not",
             snap->zcl_encumbered == VR_SWAP_AMOUNT &&
             snap->zcl_spendable == 0 &&
             snap->zcl_total == VR_SWAP_AMOUNT);
    return failures;
}

static int vr_check_every_class_emits_graded_row(
    const struct vault_snapshot *snap)
{
    static const char *expected[] = {
        "transparent_zcl", "shielded_zcl", "zslp_tokens",
        "znam_names", "swap_encumbered", "file_market_offers",
    };
    bool all_present = true, all_graded = true;
    int failures = 0;

    VR_CHECK("the table holds exactly six classes",
             VAULT_CLASS_COUNT == 6 &&
             sizeof(expected) / sizeof(expected[0]) == VAULT_CLASS_COUNT);

    for (size_t i = 0; i < VAULT_CLASS_COUNT; i++) {
        const struct vault_row *row = vr_row(snap, expected[i]);
        if (!row || !row->populated) {
            all_present = false;
            continue;
        }
        /* Determined rows carry an evidence grade; undetermined rows
         * carry a reason. Either way the line is never blank. */
        if (row->determined) {
            if (strcmp(vault_evidence_name(row->evidence), "unknown") == 0)
                all_graded = false;
        } else if (row->reason[0] == '\0') {
            all_graded = false;
        }
    }
    VR_CHECK("all six classes emit a row", all_present);
    VR_CHECK("every row carries a grade or a stated reason", all_graded);
    return failures;
}

static int vr_check_undetermined_market_admits_gap(
    const struct vault_snapshot *snap)
{
    int failures = 0;

    /* No Sapling key exists in this fixture, and file_offers has no
     * ownership column at all, so the market row must appear as an
     * admitted gap rather than as a confident zero. */
    const struct vault_row *market = vr_row(snap, "file_market_offers");
    VR_CHECK("market row is present even though it cannot be determined",
             market != NULL && market->populated);
    VR_CHECK("market row admits it cannot be determined",
             market && !market->determined && market->reason[0] != '\0');
    VR_CHECK("undetermined classes are counted, not hidden",
             snap->undetermined_classes >= 1);
    return failures;
}

/* Moves the fixture swap to `state`, checks the transition and the fresh
 * snapshot under the two given descriptions, and hands back the
 * swap_encumbered row of that snapshot. */
static int vr_check_swap_state_transition(struct node_db *ndb,
                                          struct swap_contract *sc,
                                          enum swap_state state,
                                          const char *moved_desc,
                                          const char *built_desc,
                                          struct vault_snapshot *snap,
                                          const struct vault_row **row_out)
{
    int failures = 0;

    VR_CHECK(moved_desc,
             db_swap_update_state(ndb, sc->swap_id, state, NULL));
    VR_CHECK(built_desc, vault_read_snapshot(ndb, snap).ok);
    *row_out = vr_row(snap, "swap_encumbered");
    return failures;
}

static int vr_check_contract_states_distinguished(
    struct node_db *ndb, struct swap_contract *sc)
{
    struct vault_snapshot s2;
    const struct vault_row *row;
    int failures = 0;

    /* PENDING: the contract exists but nothing is funded yet. */
    failures += vr_check_swap_state_transition(ndb, sc, SWAP_PENDING,
                                               "swap moved to PENDING",
                                               "pending snapshot builds",
                                               &s2, &row);
    VR_CHECK("an unfunded contract is pending, not encumbered",
             row && row->pending == VR_SWAP_AMOUNT &&
             row->encumbered == 0);

    /* EXPIRED: past locktime, but the refund path still recovers it,
     * so the funds are still owned. */
    failures += vr_check_swap_state_transition(ndb, sc, SWAP_EXPIRED,
                                               "swap moved to EXPIRED",
                                               "expired snapshot builds",
                                               &s2, &row);
    VR_CHECK("past locktime the refund path still counts as encumbered",
             row && row->encumbered == VR_SWAP_AMOUNT);

    /* REDEEMED: settled. The coins are back in wallet_utxos, so
     * counting them here too would double-count them. */
    failures += vr_check_swap_state_transition(ndb, sc, SWAP_REDEEMED,
                                               "swap moved to REDEEMED",
                                               "redeemed snapshot builds",
                                               &s2, &row);
    VR_CHECK("a settled swap is counted nowhere (no double-count)",
             row && row->encumbered == 0 && row->pending == 0 &&
             row->item_count == 0);
    return failures;
}

static int vr_check_transparent_funds_stay_separate(
    struct node_db *ndb, struct swap_contract *sc)
{
    struct vault_snapshot s3;
    const struct vault_row *t;
    int failures = 0;

    VR_CHECK("restore the funded swap",
             db_swap_update_state(ndb, sc->swap_id, SWAP_FUNDED, NULL));
    VR_CHECK("mixed snapshot builds", vault_read_snapshot(ndb, &s3).ok);

    t = vr_row(&s3, "transparent_zcl");
    VR_CHECK("transparent row traces to the wallet_utxos primitive",
             t && t->determined && t->is_money &&
             strcmp(vault_evidence_name(t->evidence),
                    "exact_wallet_utxo_sum") == 0 &&
             t->spendable == db_wallet_utxo_spendable_balance(ndb, NULL));
    VR_CHECK("spendable and encumbered are separate columns",
             s3.zcl_spendable == 0 &&
             s3.zcl_encumbered == VR_SWAP_AMOUNT);
    return failures;
}

static int vr_check_token_holdings_row(const struct vault_snapshot *snap)
{
    const struct vault_row *tokens = vr_row(snap, "zslp_tokens");
    int failures = 0;

    VR_CHECK("tokens remain two separately identified holdings",
             tokens && tokens->determined && tokens->spendable == 0 &&
             tokens->item_count == 2 &&
             snap->token_item_count == 2 &&
             snap->token_items[0].units == 1000 &&
             snap->token_items[0].utxo_count == 2 &&
             strcmp(snap->token_items[0].ticker, "ONE") == 0 &&
             snap->token_items[0].decimals == 2 &&
             snap->token_items[1].units == 9 &&
             strcmp(snap->token_items[1].name, "Token Two") == 0);
    return failures;
}

static const struct json_value *vr_find_class_json(
    const struct json_value *classes, const char *class_name)
{
    const struct json_value *found = NULL;

    for (size_t i = 0; classes && i < json_size(classes); i++) {
        const struct json_value *candidate = json_at(classes, i);
        const char *name = json_get_str(json_get(candidate, "class"));
        if (name && strcmp(name, class_name) == 0)
            found = candidate;
    }
    return found;
}

static int vr_check_token_json_items(struct vault_snapshot *snap)
{
    struct json_value out;
    const struct json_value *classes, *token_json, *items;
    int failures = 0;

    json_init(&out);
    VR_CHECK("token snapshot renders to json",
             vault_read_snapshot_to_json(snap, &out).ok);
    classes = json_get(&out, "classes");
    token_json = vr_find_class_json(classes, "zslp_tokens");
    items = token_json ? json_get(token_json, "items") : NULL;
    VR_CHECK("json carries two per-token unit balances",
             items && items->type == JSON_ARR && json_size(items) == 2 &&
             json_get_int(json_get(json_at(items, 0), "units")) == 1000 &&
             json_get_int(json_get(json_at(items, 1), "units")) == 9);
    VR_CHECK("token JSON has no cross-token zatoshi total",
             token_json && json_get(token_json, "total_zat") == NULL);
    json_free(&out);
    return failures;
}

static int vr_check_token_holdings_and_json(struct node_db *ndb)
{
    struct vault_snapshot token_snap;
    int failures = 0;

    VR_CHECK("two token holdings seeded", vr_seed_token_holdings(ndb));
    VR_CHECK("token snapshot builds",
             vault_read_snapshot(ndb, &token_snap).ok);
    failures += vr_check_token_holdings_row(&token_snap);
    failures += vr_check_token_json_items(&token_snap);
    return failures;
}

static int vr_check_json_surface_and_guards(struct node_db *ndb,
                                            struct vault_snapshot *snap)
{
    struct json_value out;
    int failures = 0;

    json_init(&out);
    VR_CHECK("snapshot renders to json",
             vault_read_snapshot_to_json(snap, &out).ok);
    {
        const struct json_value *classes = json_get(&out, "classes");
        VR_CHECK("json lists all six classes",
                 classes && json_size(classes) == VAULT_CLASS_COUNT);
    }
    json_free(&out);

    VR_CHECK("a NULL database is a stated error, not a zero balance",
             !vault_read_snapshot(NULL, snap).ok);
    VR_CHECK("a NULL out pointer is refused",
             !vault_read_snapshot(ndb, NULL).ok);
    VR_CHECK("class and evidence names never come back NULL",
             vault_class_name(VAULT_CLASS_COUNT) != NULL &&
             vault_evidence_name(VAULT_EVIDENCE_UNKNOWN) != NULL);
    return failures;
}

static int vr_check_swap_list_envelope(void)
{
    struct json_value out;
    const struct json_value *swaps;
    int failures = 0;

    /* A separate bug, found while wiring the encumbered row: swap_list
     * set a bare ARRAY as its result, and the native command bridge
     * rejects any non-object body — so `z23 app swap list`
     * answered BAD_TOOL_BODY for its entire existence, leaving the one
     * command that could have shown these funds unusable. The envelope
     * below is the schema the command already declared. */
    json_init(&out);
    VR_CHECK("swap list responds", api_swap_list(&out));
    VR_CHECK("swap list body is an OBJECT, not a bare array",
             out.type == JSON_OBJ);
    swaps = json_get(&out, "swaps");
    VR_CHECK("the array is carried inside the envelope",
             swaps && swaps->type == JSON_ARR);
    VR_CHECK("the envelope names the schema it already declared",
             json_get(&out, "schema") &&
             strcmp(json_get_str(json_get(&out, "schema")),
                    "zcl.app_swap_index.v1") == 0);
    VR_CHECK("and carries a count, matching rpc_name_list's shape",
             json_get(&out, "count") != NULL);
    json_free(&out);
    return failures;
}

static int vr_check_swap_amount_refusal_shapes(void)
{
    int64_t zat = -1;
    int failures = 0;

    VR_CHECK("swap amount 0 refused",
             !swap_amount_to_zat(0.0, &zat));
    VR_CHECK("negative swap amount refused",
             !swap_amount_to_zat(-0.00000001, &zat));
    VR_CHECK("NaN swap amount refused",
             !swap_amount_to_zat((double)NAN, &zat));
    VR_CHECK("infinite swap amount refused",
             !swap_amount_to_zat((double)INFINITY, &zat));
    VR_CHECK("int64-overflowing swap amount refused",
             !swap_amount_to_zat(1.0e12, &zat));
    VR_CHECK("positive sub-zatoshi swap amount refused",
             !swap_amount_to_zat(0.000000001, &zat));
    return failures;
}

static int vr_check_swap_amount_conversions(void)
{
    int64_t zat = -1;
    int failures = 0;

    VR_CHECK("one zatoshi swap amount accepted",
             swap_amount_to_zat(0.00000001, &zat) && zat == 1);
    VR_CHECK("whole-coin ceiling itself still converts",
             swap_amount_to_zat(92233720368.0, &zat) &&
             zat == 9223372036800000000LL);
    VR_CHECK("fractional amount converts to exact zatoshis",
             swap_amount_to_zat(1337.42, &zat) && zat == 133742000000LL);
    return failures;
}

int test_vault_read(void)
{
    int failures = 0;
    char dir[256];
    char dbpath[320];
    struct node_db ndb;
    struct vault_snapshot snap;
    struct swap_contract sc;

    test_make_tmpdir(dir, sizeof(dir), "vault_read", "db");
    snprintf(dbpath, sizeof(dbpath), "%s/node.db", dir);
    memset(&ndb, 0, sizeof(ndb));
    if (!node_db_open(&ndb, dbpath)) {
        printf("vault_read: node_db_open... FAIL\n");
        test_rm_rf(dir);
        return 1;
    }

    /* ── 1. Reproduce the bug ─────────────────────────────────────── */
    failures += vr_check_funded_htlc_invisible_to_balances(&ndb, &sc);

    /* ── 2. The vault sees them ───────────────────────────────────── */
    failures += vr_check_vault_sees_encumbered_funds(&ndb, &snap);
    failures += vr_check_encumbered_row_grade_and_rollup(&snap);

    /* ── 3. Every class emits a row, each with a grade ────────────── */
    failures += vr_check_every_class_emits_graded_row(&snap);

    /* ── 4. An undeterminable class says so; it does not vanish ───── */
    failures += vr_check_undetermined_market_admits_gap(&snap);

    /* ── 5. Contract states are distinguished, not lumped ─────────── */
    failures += vr_check_contract_states_distinguished(&ndb, &sc);

    /* ── 6. Transparent funds still add up, and stay separate ─────── */
    failures += vr_check_transparent_funds_stay_separate(&ndb, &sc);

    /* ── 7. JSON surface + guards ─────────────────────────────────── */
    failures += vr_check_token_holdings_and_json(&ndb);
    failures += vr_check_json_surface_and_guards(&ndb, &snap);

    /* ── 8. swap_list answers with a body the command bridge accepts ─ */
    failures += vr_check_swap_list_envelope();

    node_db_close(&ndb);
    test_rm_rf(dir);

    /* ── Money-shape guard on swap amounts ─────────────────────────────
     * The swap contract persists whatever double the JSON wire produced.
     * swap_amount_to_zat is the single gate between that double and an
     * int64_t zatoshis field, so every corrupting shape must be refused
     * here: zero (the absent-argument sentinel), negatives, NaN,
     * infinities, and magnitudes that overflow int64_t once scaled. */
    failures += vr_check_swap_amount_refusal_shapes();
    failures += vr_check_swap_amount_conversions();

    return failures;
}
