/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rhett Creighton
 *
 * Tests for the vault read model (app/services/src/vault_read.c).
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

int test_vault_read(void)
{
    int failures = 0;
    char dir[256];
    char dbpath[320];
    struct node_db ndb;
    struct vault_snapshot snap;
    struct zcl_result r;
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

    vr_fill_swap(&sc, SWAP_FUNDED);
    VR_CHECK("funded HTLC saved to zswp_contracts",
             db_swap_save(&ndb, &sc));

    {
        struct swap_contract found;
        VR_CHECK("the contract is really there, with its amount",
                 db_swap_find(&ndb, sc.swap_id, &found) &&
                 found.amount == VR_SWAP_AMOUNT &&
                 found.state == SWAP_FUNDED);
    }

    /* This is the bug. Both numbers are zero while VR_SWAP_AMOUNT
     * zatoshi sit at a P2SH address this node can spend from. */
    VR_CHECK("BUG: getbalance's primitive cannot see the encumbered funds",
             db_wallet_utxo_spendable_balance(&ndb, NULL) == 0);
    VR_CHECK("BUG: walletledger's two pools cannot see them either",
             db_wallet_utxo_balance_with_count(&ndb, NULL) == 0 &&
             db_sapling_note_balance_with_count(&ndb, NULL) == 0);

    /* ── 2. The vault sees them ───────────────────────────────────── */

    r = vault_read_snapshot(&ndb, &snap);
    VR_CHECK("vault snapshot builds", r.ok);

    {
        const struct vault_row *swap_row = vr_row(&snap, "swap_encumbered");
        VR_CHECK("swap row exists", swap_row != NULL);
        VR_CHECK("the missing amount appears as encumbered",
                 swap_row && swap_row->encumbered == VR_SWAP_AMOUNT);
        VR_CHECK("graded exact_contract_state",
                 swap_row && swap_row->determined &&
                 strcmp(vault_evidence_name(swap_row->evidence),
                        "exact_contract_state") == 0);
        VR_CHECK("encumbered is NOT reported as spendable",
                 swap_row && swap_row->spendable == 0);
        VR_CHECK("the rollup carries it where getbalance did not",
                 snap.zcl_encumbered == VR_SWAP_AMOUNT &&
                 snap.zcl_spendable == 0 &&
                 snap.zcl_total == VR_SWAP_AMOUNT);
    }

    /* ── 3. Every class emits a row, each with a grade ────────────── */

    {
        static const char *expected[] = {
            "transparent_zcl", "shielded_zcl", "zslp_tokens",
            "znam_names", "swap_encumbered", "file_market_offers",
        };
        bool all_present = true, all_graded = true;

        VR_CHECK("the table holds exactly six classes",
                 VAULT_CLASS_COUNT == 6 &&
                 sizeof(expected) / sizeof(expected[0]) == VAULT_CLASS_COUNT);

        for (size_t i = 0; i < VAULT_CLASS_COUNT; i++) {
            const struct vault_row *row = vr_row(&snap, expected[i]);
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
    }

    /* ── 4. An undeterminable class says so; it does not vanish ───── */

    {
        /* No Sapling key exists in this fixture, and file_offers has no
         * ownership column at all, so the market row must appear as an
         * admitted gap rather than as a confident zero. */
        const struct vault_row *market = vr_row(&snap, "file_market_offers");
        VR_CHECK("market row is present even though it cannot be determined",
                 market != NULL && market->populated);
        VR_CHECK("market row admits it cannot be determined",
                 market && !market->determined && market->reason[0] != '\0');
        VR_CHECK("undetermined classes are counted, not hidden",
                 snap.undetermined_classes >= 1);
    }

    /* ── 5. Contract states are distinguished, not lumped ─────────── */

    {
        struct vault_snapshot s2;
        const struct vault_row *row;

        /* PENDING: the contract exists but nothing is funded yet. */
        VR_CHECK("swap moved to PENDING",
                 db_swap_update_state(&ndb, sc.swap_id, SWAP_PENDING, NULL));
        VR_CHECK("pending snapshot builds", vault_read_snapshot(&ndb, &s2).ok);
        row = vr_row(&s2, "swap_encumbered");
        VR_CHECK("an unfunded contract is pending, not encumbered",
                 row && row->pending == VR_SWAP_AMOUNT &&
                 row->encumbered == 0);

        /* EXPIRED: past locktime, but the refund path still recovers it,
         * so the funds are still owned. */
        VR_CHECK("swap moved to EXPIRED",
                 db_swap_update_state(&ndb, sc.swap_id, SWAP_EXPIRED, NULL));
        VR_CHECK("expired snapshot builds", vault_read_snapshot(&ndb, &s2).ok);
        row = vr_row(&s2, "swap_encumbered");
        VR_CHECK("past locktime the refund path still counts as encumbered",
                 row && row->encumbered == VR_SWAP_AMOUNT);

        /* REDEEMED: settled. The coins are back in wallet_utxos, so
         * counting them here too would double-count them. */
        VR_CHECK("swap moved to REDEEMED",
                 db_swap_update_state(&ndb, sc.swap_id, SWAP_REDEEMED, NULL));
        VR_CHECK("redeemed snapshot builds", vault_read_snapshot(&ndb, &s2).ok);
        row = vr_row(&s2, "swap_encumbered");
        VR_CHECK("a settled swap is counted nowhere (no double-count)",
                 row && row->encumbered == 0 && row->pending == 0 &&
                 row->item_count == 0);
    }

    /* ── 6. Transparent funds still add up, and stay separate ─────── */

    {
        struct vault_snapshot s3;
        const struct vault_row *t;

        VR_CHECK("restore the funded swap",
                 db_swap_update_state(&ndb, sc.swap_id, SWAP_FUNDED, NULL));
        VR_CHECK("mixed snapshot builds", vault_read_snapshot(&ndb, &s3).ok);

        t = vr_row(&s3, "transparent_zcl");
        VR_CHECK("transparent row traces to the wallet_utxos primitive",
                 t && t->determined && t->is_money &&
                 strcmp(vault_evidence_name(t->evidence),
                        "exact_wallet_utxo_sum") == 0 &&
                 t->spendable == db_wallet_utxo_spendable_balance(&ndb, NULL));
        VR_CHECK("spendable and encumbered are separate columns",
                 s3.zcl_spendable == 0 &&
                 s3.zcl_encumbered == VR_SWAP_AMOUNT);
    }

    /* ── 7. JSON surface + guards ─────────────────────────────────── */

    {
        struct json_value out;
        json_init(&out);
        VR_CHECK("snapshot renders to json",
                 vault_read_snapshot_to_json(&snap, &out).ok);
        {
            const struct json_value *classes = json_get(&out, "classes");
            VR_CHECK("json lists all six classes",
                     classes && json_size(classes) == VAULT_CLASS_COUNT);
        }
        json_free(&out);

        VR_CHECK("a NULL database is a stated error, not a zero balance",
                 !vault_read_snapshot(NULL, &snap).ok);
        VR_CHECK("a NULL out pointer is refused",
                 !vault_read_snapshot(&ndb, NULL).ok);
        VR_CHECK("class and evidence names never come back NULL",
                 vault_class_name(VAULT_CLASS_COUNT) != NULL &&
                 vault_evidence_name(VAULT_EVIDENCE_UNKNOWN) != NULL);
    }

    /* ── 8. swap_list answers with a body the command bridge accepts ─ */

    {
        /* A separate bug, found while wiring the encumbered row: swap_list
         * set a bare ARRAY as its result, and the native command bridge
         * rejects any non-object body — so `z23 app swap list`
         * answered BAD_TOOL_BODY for its entire existence, leaving the one
         * command that could have shown these funds unusable. The envelope
         * below is the schema the command already declared. */
        struct json_value out;
        const struct json_value *swaps;

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
    }

    node_db_close(&ndb);
    test_rm_rf(dir);

    /* ── Money-shape guard on swap amounts ─────────────────────────────
     * The swap contract persists whatever double the JSON wire produced.
     * swap_amount_to_zat is the single gate between that double and an
     * int64_t zatoshis field, so every corrupting shape must be refused
     * here: zero (the absent-argument sentinel), negatives, NaN,
     * infinities, and magnitudes that overflow int64_t once scaled. */
    {
        int64_t zat = -1;
        VR_CHECK("swap amount 0 refused",
                 !swap_amount_to_zat(0.0, &zat));
        VR_CHECK("negative swap amount refused",
                 !swap_amount_to_zat(-0.00000001, &zat));
        VR_CHECK("NaN swap amount refused",
                 !swap_amount_to_zat(NAN, &zat));
        VR_CHECK("infinite swap amount refused",
                 !swap_amount_to_zat(INFINITY, &zat));
        VR_CHECK("int64-overflowing swap amount refused",
                 !swap_amount_to_zat(1.0e12, &zat));
        VR_CHECK("positive sub-zatoshi swap amount refused",
                 !swap_amount_to_zat(0.000000001, &zat));
        VR_CHECK("one zatoshi swap amount accepted",
                 swap_amount_to_zat(0.00000001, &zat) && zat == 1);
        VR_CHECK("whole-coin ceiling itself still converts",
                 swap_amount_to_zat(92233720368.0, &zat) &&
                 zat == 9223372036800000000LL);
        VR_CHECK("fractional amount converts to exact zatoshis",
                 swap_amount_to_zat(1337.42, &zat) && zat == 133742000000LL);
    }

    return failures;
}
