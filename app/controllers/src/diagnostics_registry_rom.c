/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ROM / trust-machine catalog dump — the "rom" g_dumpers[] subsystem.
 *
 * The L0-L3 trust machine (docs/ROM.md) had no single introspection
 * surface: an operator or agent could not ask one question and see what
 * the compiled checkpoint commits, what each layer covers, and where every
 * cheaply-readable projection's cursor currently sits. This dumper answers
 * that in one call.
 *
 * Every field here is either a compiled-in constant (the checkpoint, the
 * commitment enumeration, the ladder shape) or a cheap read through an
 * EXISTING public accessor:
 *   - L0  get_sha3_utxo_checkpoint()             (core/chainparams)
 *   - L1  chain_segment_dump_state_json()         (this shape, chain_segment_controller.c)
 *   - L2  reducer_frontier_floor() / _provable_tip_cached() / _is_published()
 *         (app/jobs/reducer_frontier.c)
 *   - L3  active_chain_tip() under cs_main, reducer_frontier_external_tip_height()
 *   - MMB rpc_blockchain_mmb_snapshot()            (this shape, blockchain_controller.c)
 *   - ladder g_utxo_root_ladder[] / g_utxo_root_ladder_dense_height (lib/chain)
 *
 * This file invents no new state and performs no writes — pure read-only
 * aggregation, off any fold hot path (bounded work: one segment-store
 * stat(), one mutex-guarded tip read, a handful of atomic loads, and a
 * loop over the (tiny, O(10)) compiled ladder table).
 *
 * Registered as the "rom" g_dumpers[] entry in diagnostics_registry.c;
 * declaration lives in diagnostics_internal.h (see CLAUDE.md "Adding state
 * introspection"). Lives in its own file — same pattern as
 * diagnostics_registry_bundle.c and diagnostics_sapling_checkpoint.c — so
 * diagnostics_registry.c stays a routing table, not a home for every
 * dumper's full body. */

#include "controllers/diagnostics_internal.h"
#include "controllers/blockchain_controller.h"
#include "controllers/chain_segment_controller.h"

#include "base/hex.h"
#include "chain/chain.h"
#include "chain/checkpoints.h"
#include "chain/utxo_root_ladder.h"
#include "jobs/reducer_frontier.h"
#include "json/json.h"
#include "util/log_macros.h"
#include "util/sync.h"
#include "validation/main_state.h"

#include <stddef.h>
#include <stdint.h>

bool rom_dump_state_json(struct json_value *out, const char *key)
{
    (void)key;
    if (!out)
        LOG_FAIL("rom", "output is NULL");
    json_set_object(out);

    /* ── L0: the compiled SHA3 UTXO checkpoint ────────────────────────── */
    const struct sha3_utxo_checkpoint *cp = get_sha3_utxo_checkpoint();

    struct json_value checkpoint;
    json_init(&checkpoint);
    json_set_object(&checkpoint);
    json_push_kv_bool(&checkpoint, "present", cp != NULL);
    if (cp) {
        char block_hash_hex[65];
        char sha3_hash_hex[65];
        zcl_hex_encode(cp->block_hash, 32, block_hash_hex);
        zcl_hex_encode(cp->sha3_hash, 32, sha3_hash_hex);
        json_push_kv_int(&checkpoint, "height", cp->height);
        json_push_kv_str(&checkpoint, "block_hash", block_hash_hex);
        json_push_kv_str(&checkpoint, "sha3_hash", sha3_hash_hex);
        json_push_kv_int(&checkpoint, "utxo_count", (int64_t)cp->utxo_count);
        json_push_kv_int(&checkpoint, "total_supply_zatoshi", cp->total_supply);
    }
    json_push_kv(out, "checkpoint", &checkpoint);
    json_free(&checkpoint);

    /* ── what ZClassic headers commit vs NOT commit — static enumeration,
     * the machine-readable form of docs/CONSENSUS_PARITY_DOCTRINE.md's
     * "headers do not commit the UTXO, Sapling/Sprout frontier, or
     * nullifier contents" fact. Never derived from live state — this is a
     * protocol-shape constant, true regardless of sync progress. ────────── */
    struct json_value commitments;
    json_init(&commitments);
    json_set_object(&commitments);
    json_push_kv_str(&commitments, "header_chain", "pow");
    json_push_kv_str(&commitments, "tx_bytes", "merkle");
    json_push_kv_str(&commitments, "sapling_frontier", "header");
    json_push_kv_str(&commitments, "nullifiers", "not_committed_rom_only");
    json_push_kv_str(&commitments, "sprout", "not_committed_rom_only");
    json_push_kv_str(&commitments, "transparent_utxo", "not_committed_rom_only");
    json_push_kv(out, "commitments", &commitments);
    json_free(&commitments);

    /* ── layer coverage: L0 ROM, L1 sealed history, L2 delta fold, L3 live
     * tip. Each sub-object is produced by that layer's own existing public
     * reader — this dumper aggregates, it does not re-derive. ──────────── */
    struct json_value layers;
    json_init(&layers);
    json_set_object(&layers);

    struct json_value l0;
    json_init(&l0);
    json_set_object(&l0);
    json_push_kv_str(&l0, "authority", "compiled_sha3_checkpoint");
    json_push_kv_int(&l0, "height", cp ? (int64_t)cp->height : -1);
    json_push_kv(&layers, "l0_rom", &l0);
    json_free(&l0);

    struct json_value l1;
    json_init(&l1);
    chain_segment_dump_state_json(&l1, NULL);
    json_push_kv(&layers, "l1_sealed_history", &l1);
    json_free(&l1);

    struct json_value l2;
    json_init(&l2);
    json_set_object(&l2);
    json_push_kv_str(&l2, "authority", "reducer_frontier_hstar");
    json_push_kv_int(&l2, "floor", reducer_frontier_floor());
    json_push_kv_int(&l2, "hstar", reducer_frontier_provable_tip_cached());
    json_push_kv_bool(&l2, "published",
                      reducer_frontier_provable_tip_is_published());
    json_push_kv(&layers, "l2_delta_fold", &l2);
    json_free(&l2);

    struct json_value l3;
    json_init(&l3);
    json_set_object(&l3);
    struct main_state *ms = diag_main_state();
    long long active_tip = -1;
    if (ms) {
        zcl_mutex_lock(&ms->cs_main);
        struct block_index *at = active_chain_tip(&ms->chain_active);
        if (at)
            active_tip = (long long)at->nHeight;
        zcl_mutex_unlock(&ms->cs_main);
    }
    json_push_kv_bool(&l3, "has_main_state", ms != NULL);
    json_push_kv_int(&l3, "active_tip", active_tip);
    json_push_kv_int(&l3, "external_tip",
                     reducer_frontier_external_tip_height());
    json_push_kv(&layers, "l3_live_tip", &l3);
    json_free(&l3);

    json_push_kv(out, "layers", &layers);
    json_free(&layers);

    /* ── cheaply-readable projection cursors: MMB, UTXO-root ladder. Only
     * surfaces here what already has a public reader — never invents new
     * state (per this lane's brief). ─────────────────────────────────── */
    struct json_value projections;
    json_init(&projections);
    json_set_object(&projections);

    struct json_value mmb;
    json_init(&mmb);
    json_set_object(&mmb);
    uint64_t mmb_leaves = 0;
    uint32_t mmb_mountains = 0;
    bool mmb_initialized =
        rpc_blockchain_mmb_snapshot(NULL, &mmb_leaves, &mmb_mountains);
    json_push_kv_bool(&mmb, "initialized", mmb_initialized);
    json_push_kv_int(&mmb, "leaves", (int64_t)mmb_leaves);
    json_push_kv_int(&mmb, "mountains", (int64_t)mmb_mountains);
    json_push_kv(&projections, "mmb", &mmb);
    json_free(&mmb);

    struct json_value ladder;
    json_init(&ladder);
    json_set_object(&ladder);
    json_push_kv_int(&ladder, "rung_count", (int64_t)g_utxo_root_ladder_count);
    json_push_kv_int(&ladder, "stride", UTXO_ROOT_LADDER_STRIDE);
    int32_t highest_rung = -1;
    for (size_t i = 0; i < g_utxo_root_ladder_count; i++) {
        if (g_utxo_root_ladder[i].height > highest_rung)
            highest_rung = g_utxo_root_ladder[i].height;
    }
    json_push_kv_int(&ladder, "highest_rung_height", highest_rung);
    json_push_kv_int(&ladder, "dense_height", g_utxo_root_ladder_dense_height);
    json_push_kv(&projections, "utxo_root_ladder", &ladder);
    json_free(&ladder);

    json_push_kv(out, "projections", &projections);
    json_free(&projections);

    diag_push_health(out, cp != NULL,
                     cp != NULL ? "" : "compiled SHA3 UTXO checkpoint missing");
    return true;
}
