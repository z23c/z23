/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The two dumpstate subsystems of the mesh observation surface:
 *
 *   mesh_observation — THIS node's own record, rendered through the SAME
 *                      emitter the onion mount uses, so the operator view
 *                      and the served document can never disagree.
 *   mesh_compose     — what THIS reader DERIVES from the records it
 *                      collected, recomputed against our own chain.
 *
 * Neither emits a `_health` rollup, and that is deliberate. The rollup's
 * own shape reports all_ok over zero reporting dumpers; feeding a surface
 * built to refuse vacuous passes into a rollup that grants them would undo
 * the point. The tri-state (unverified / agreeing / disagreeing /
 * split_view) with its coverage counts IS the report.
 */

#include "controllers/observation_site_controller.h"

#include "services/mesh_observation.h"
#include "services/sync_monitor.h"
#include "json/json.h"
#include "chain/chain.h"
#include "core/arith_uint256.h"
#include "core/uint256.h"
#include "platform/time_compat.h"
#include "util/sync.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"

#include <pthread.h>
#include <stdio.h>
#include <string.h>

bool mesh_observation_dump_state_json(struct json_value *out, const char *key)
{
    (void)key;
    if (!out)
        return false;
    json_set_object(out);

    struct mesh_observation rec;
    if (!mesh_observation_snapshot(&rec)) {
        /* R4: no sample is UNVERIFIED, and it says so in the same
         * vocabulary a reader uses. It is NOT an empty healthy record. */
        json_push_kv_str(out, "schema", MESH_OBS_SCHEMA);
        json_push_kv_bool(out, "sampled", false);
        json_push_kv_str(out, "unavailable_reason", "no_sample_yet");
        return true;
    }
    if (!mesh_observation_emit_json(&rec, out))
        return false;   // raw-return-ok:emitter-refusal-is-the-dumper-refusal
    json_push_kv_bool(out, "sampled", true);
    return true;
}

/* ── the reader's own chain, for RECOMPUTATION ──────────────────────── */

static bool reader_hash_at(void *ctx, int64_t height,
                           char outh[MESH_OBS_HEXHASH])
{
    (void)ctx;
    outh[0] = '\0';
    if (height < 0)
        return false;
    struct main_state *ms = sync_monitor_main_state();
    if (!ms)
        return false;
    struct block_index *bi = active_chain_at(&ms->chain_active, (int)height);
    if (!bi || !bi->phashBlock)
        return false;
    uint256_get_hex(bi->phashBlock, outh);
    return true;
}

/* The slot array is ~85 KB. It lives here as one fixed static guarded by a
 * leaf mutex rather than on a caller's stack, and nothing about it grows. */
static struct mesh_obs_slot g_slots[MESH_OBS_SLOTS_MAX + 1];
static pthread_mutex_t g_slots_lock = PTHREAD_MUTEX_INITIALIZER;

static void push_slot_coverage(struct json_value *out, int n)
{
    struct json_value arr = {0};
    json_set_array(&arr);
    for (int i = 0; i < n; i++) {
        struct json_value s = {0};
        json_set_object(&s);
        json_push_kv_str(&s, "onion", g_slots[i].onion);
        json_push_kv_str(&s, "fetch",
                         mesh_obs_outcome_name(g_slots[i].fetch));
        /* Elapsed is published beside the budget on EVERY outcome, so a
         * spent budget and a refusal can never be byte-identical. */
        json_push_kv_int(&s, "elapsed_us", g_slots[i].elapsed_us);
        json_push_kv_int(&s, "deadline_us", g_slots[i].deadline_us);
        json_push_kv_int(&s, "fetched_unix", g_slots[i].fetched_unix);
        json_push_kv_bool(&s, "parsed", g_slots[i].parsed);
        json_push_kv_str(&s, "refusal", g_slots[i].refusal);
        json_push_kv_int(&s, "record_sampled_unix",
                         g_slots[i].rec.self.sampled_unix);
        json_push_back(&arr, &s);
        json_free(&s);
    }
    json_push_kv(out, "records", &arr);
    json_free(&arr);
}

bool mesh_observation_compose_dump_state_json(struct json_value *out,
                                              const char *key)
{
    (void)key;
    if (!out)
        return false;
    json_set_object(out);

    struct mesh_reader_chain reader;
    memset(&reader, 0, sizeof(reader));
    reader.hash_at = reader_hash_at;
    reader.tip_height = -1;
    struct main_state *ms = sync_monitor_main_state();
    if (ms) {
        struct block_index *tip = active_chain_cached_tip(&ms->chain_active);
        if (tip) {
            reader.tip_height = (int64_t)tip->nHeight;
            arith_uint256_get_hex(&tip->nChainWork, reader.tip_chainwork_hex);
        }
    }

    struct mesh_compose_budget budget;
    mesh_compose_budget_defaults(&budget);
    struct mesh_conclusion c;
    memset(&c, 0, sizeof(c));

    pthread_mutex_lock(&g_slots_lock);
    memset(g_slots, 0, sizeof(g_slots));
    int n = 0;
    /* Slot 0 is OUR OWN record. It carries no privilege whatsoever — the
     * fold is a commutative tally over slots and the height walk is over
     * heights, so removing it or reordering it changes nothing but
     * coverage. It is here because a reader's own observation is one
     * observation, not because it is the reference. */
    if (mesh_observation_snapshot(&g_slots[0].rec)) {
        snprintf(g_slots[0].onion, MESH_OBS_ONION_MAX, "%s",
                 g_slots[0].rec.self.onion);
        g_slots[0].fetch = MESH_OBS_CONFIRMED;
        g_slots[0].parsed = true;
        g_slots[0].fetched_unix = g_slots[0].rec.self.sampled_unix;
        n = 1;
    }
    size_t room = (size_t)(MESH_OBS_SLOTS_MAX + 1 - n);
    n += mesh_observation_collect_snapshot(&g_slots[n], room);

    mesh_observation_compose(g_slots, (size_t)n, &reader, &budget,
                             platform_time_wall_unix(), &c);
    push_slot_coverage(out, n);
    pthread_mutex_unlock(&g_slots_lock);

    /* 1. COVERAGE FIRST, always. */
    struct json_value cov = {0};
    json_set_object(&cov);
    json_push_kv_int(&cov, "records_offered", c.records_offered);
    json_push_kv_int(&cov, "records_parsed", c.records_parsed);
    json_push_kv_int(&cov, "records_fresh", c.records_fresh);
    json_push_kv_int(&cov, "records_stale", c.records_stale);
    json_push_kv_int(&cov, "records_silent", c.records_silent);
    json_push_kv_int(&cov, "records_not_probed", c.records_not_probed);
    json_push_kv_int(&cov, "records_malformed", c.records_malformed);
    json_push_kv(out, "coverage", &cov);
    json_free(&cov);

    /* 2. Independence, by service identity — never by address group, which
     * is the identical key for every torv3 address and therefore an
     * unreachable bar on an onion-only fleet. The number is raw on purpose:
     * a reader must be able to see that it is 4 and not 400. */
    json_push_kv_int(out, "distinct_identities", c.distinct_identities);
    json_push_kv_int(out, "min_independent_required",
                     c.min_independent_required);
    json_push_kv_str(out, "min_independent_meaning",
                     "coverage_threshold_not_an_anti_sybil_bar");

    /* 3. Chain agreement, RECOMPUTED against our own chain. Three tallies,
     * never summed into one. */
    struct json_value ag = {0};
    json_set_object(&ag);
    json_push_kv_int(&ag, "agree_at_anchor", c.agree_at_anchor);
    json_push_kv_int(&ag, "disagree_at_anchor", c.disagree_at_anchor);
    json_push_kv_int(&ag, "no_common_height", c.no_common_height);
    json_push_kv_int(&ag, "checked_height", c.checked_height);
    json_push_kv_str(&ag, "reader_hash_at_checked", c.reader_hash_at_checked);
    json_push_kv(out, "agreement", &ag);
    json_free(&ag);

    /* 4. Adjacency: composed here, published by nobody, and it feeds the
     * state exactly nowhere. */
    struct json_value adj = {0};
    json_set_object(&adj);
    json_push_kv_int(&adj, "edges_asserted", c.edges_asserted);
    json_push_kv_int(&adj, "edges_reciprocated", c.edges_reciprocated);
    json_push_kv_int(&adj, "edges_one_sided", c.edges_one_sided);
    json_push_kv_int(&adj, "edges_contradicted", c.edges_contradicted);
    json_push_kv(out, "adjacency", &adj);
    json_free(&adj);

    /* 5. Work. Reported so a reader can go fetch and VALIDATE the headers
     * itself; nothing here acts on a claimed chainwork. */
    json_push_kv_str(out, "max_chainwork_hex", c.max_chainwork_hex);
    json_push_kv_bool(out, "reader_holds_max_chainwork",
                      c.reader_holds_max_chainwork);
    json_push_kv_int(out, "reader_tip_height", reader.tip_height);

    /* 6. The state, beside the arithmetic that produced it. */
    json_push_kv_str(out, "state", mesh_state_name(c.state));
    json_push_kv_str(out, "basis", c.basis);
    return true;
}
