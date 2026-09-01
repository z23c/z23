/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * reducer_stage_profile — bounded reducer hot-stage work/timing diagnostics. */

#include "sync/reducer_stage_profile.h"

#include "json/json.h"
#include "sync/stage.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stddef.h>
#include <string.h>

#define PROFILE_SCHEMA "zcl.reducer_stage_profile.v1"
#define PROFILE_HIST_BUCKETS 48u

/* The presence mask is one uint64_t and a field's bit is 1<<field, so the
 * highest legal field index is 63. Crossing this silently corrupts the mask
 * (undefined shift), so the bound is a build error, not a comment. */
_Static_assert(RPF_FIELD_COUNT <= 64,
               "reducer_stage_profile presence bitmask is 64 bits wide — "
               "widen it explicitly before adding a 65th field");

struct profile_domain {
    _Atomic uint64_t cumulative[RPF_FIELD_COUNT];
    _Atomic uint64_t last_batch[RPF_FIELD_COUNT];
    _Atomic uint64_t histogram[RPF_FIELD_COUNT][PROFILE_HIST_BUCKETS];
    _Atomic uint64_t last_histogram[RPF_FIELD_COUNT][PROFILE_HIST_BUCKETS];
    _Atomic uint64_t present;
    _Atomic uint64_t last_present;
    _Atomic uint64_t generation;
    pthread_mutex_t rollover_lock;
};

static struct profile_domain g_profiles[REDUCER_PROFILE_DOMAIN_COUNT] = {
    [REDUCER_PROFILE_BODY_PERSIST] = {
        .rollover_lock = PTHREAD_MUTEX_INITIALIZER,
    },
    [REDUCER_PROFILE_SCRIPT_VALIDATE] = {
        .rollover_lock = PTHREAD_MUTEX_INITIALIZER,
    },
    [REDUCER_PROFILE_TIP_FINALIZE] = {
        .rollover_lock = PTHREAD_MUTEX_INITIALIZER,
    },
    [REDUCER_PROFILE_UTXO_APPLY] = {
        .rollover_lock = PTHREAD_MUTEX_INITIALIZER,
    },
    [REDUCER_PROFILE_PROOF_VALIDATE] = {
        .rollover_lock = PTHREAD_MUTEX_INITIALIZER,
    },
};

/* Domain names — also the accepted values of the dump's `key` filter. */
static const char *const g_domain_names[REDUCER_PROFILE_DOMAIN_COUNT] = {
    [REDUCER_PROFILE_BODY_PERSIST]    = "body_persist",
    [REDUCER_PROFILE_SCRIPT_VALIDATE] = "script_validate",
    [REDUCER_PROFILE_TIP_FINALIZE]    = "tip_finalize",
    [REDUCER_PROFILE_UTXO_APPLY]      = "utxo_apply",
    [REDUCER_PROFILE_PROOF_VALIDATE]  = "proof_validate",
};

int reducer_stage_profile_domain_for(const char *stage_name)
{
    if (!stage_name || !stage_name[0])
        return -1;
    for (int d = 0; d < REDUCER_PROFILE_DOMAIN_COUNT; d++) {
        if (g_domain_names[d] && strcmp(stage_name, g_domain_names[d]) == 0)
            return d;
    }
    return -1;
}

static const char *const g_field_names[RPF_FIELD_COUNT] = {
    [RPF_BLOCKS] = "blocks",
    [RPF_TOTAL_US] = "total_us",
    [RPF_UPSTREAM_US] = "upstream_cursor_log_us",
    [RPF_CACHE_HITS] = "parsed_cache_hits",
    [RPF_CACHE_MISSES] = "parsed_cache_misses",
    [RPF_CACHE_PROBES] = "parsed_cache_lookup_probes",
    [RPF_CACHE_LOCK_WAIT_US] = "parsed_cache_lock_wait_us",
    [RPF_DISK_READ_US] = "parsed_disk_read_us",
    [RPF_PARSE_US] = "parsed_parse_us",
    [RPF_DEEP_CLONES] = "parsed_deep_clones",
    [RPF_DEEP_CLONE_BYTES] = "parsed_deep_clone_estimated_bytes",
    [RPF_BLOCK_HASH_US] = "block_hash_verify_us",
    [RPF_MERKLE_US] = "merkle_verify_us",
    [RPF_MERKLE_ALLOCS] = "merkle_temporary_allocations",
    [RPF_MERKLE_BYTES] = "merkle_temporary_bytes",
    [RPF_EVENT_ENCODE_US] = "block_event_wire_encode_us",
    [RPF_EVENT_APPEND_US] = "block_event_append_us",
    [RPF_CREATED_INDEX_BLOCKS] = "created_index_blocks",
    [RPF_CREATED_INDEX_TXS] = "created_index_transactions",
    [RPF_CREATED_INDEX_OUTPUTS] = "created_index_outputs",
    [RPF_CREATED_INDEX_PREPARES] = "created_index_statement_prepares",
    [RPF_CREATED_INDEX_STEPS] = "created_index_sqlite_steps",
    [RPF_CREATED_INDEX_US] = "created_index_us",
    [RPF_CONTEXTUAL_US] = "contextual_gate_us",
    [RPF_TX_PRECOMPUTE_US] = "transaction_precompute_us",
    [RPF_JOB_ARRAY_ALLOCS] = "job_array_allocations",
    [RPF_JOB_ARRAY_BYTES] = "job_array_bytes",
    [RPF_PREVOUT_CREATED_LOOKUPS] = "prevout_created_index_lookups",
    [RPF_PREVOUT_COINS_FALLBACKS] = "prevout_coins_kv_fallbacks",
    [RPF_PREVOUT_PREPARES] = "prevout_statement_prepares",
    [RPF_PREVOUT_HITS] = "prevout_hits",
    [RPF_PREVOUT_MISSES] = "prevout_misses",
    [RPF_PREVOUT_US] = "prevout_resolution_us",
    [RPF_POOL_SETUP_US] = "worker_pool_setup_us",
    [RPF_POOL_WAKE_US] = "worker_pool_wakeup_us",
    [RPF_VERIFY_SCRIPT_CPU_US] = "verify_script_cpu_us",
    [RPF_WORKER_WAIT_US] = "worker_join_wait_us",
    [RPF_ORDERED_REDUCTION_US] = "ordered_reduction_us",
    [RPF_HEADER_EVENT_US] = "header_event_emission_us",
    [RPF_STAGE_LOG_CURSOR_US] = "stage_log_cursor_us",
    [RPF_TF_LOG_INSERT_US] = "tf_log_insert_us",
    [RPF_TF_INCREMENTAL_SUM_US] = "tf_incremental_sum_us",
    [RPF_TF_WINDOW_MOVE_US] = "tf_window_move_us",
    [RPF_TF_PROVABLE_TIP_US] = "tf_provable_tip_us",
    [RPF_UA_PREVOUT_US] = "ua_prevout_us",
    [RPF_UA_APPLY_US] = "ua_apply_us",
    [RPF_UA_COMMIT_US] = "ua_commit_us",
    [RPF_PV_BODY_ACQUIRE_US] = "pv_body_acquire_us",
    [RPF_PV_VERIFY_US] = "pv_verify_us",
    [RPF_PV_LOG_INSERT_US] = "pv_log_insert_us",
    [RPF_PV_SPENDS] = "pv_sapling_spends",
    [RPF_PV_OUTPUTS] = "pv_sapling_outputs",
    [RPF_PV_SPROUT_GROTH16] = "pv_sprout_groth16_joinsplits",
    [RPF_PV_SPROUT_PHGR13] = "pv_sprout_phgr13_joinsplits",
    [RPF_PV_BINDING_SIGS] = "pv_binding_sigs",
    [RPF_PV_LOOKAHEAD_HITS] = "pv_lookahead_hits",
    [RPF_PV_LOOKAHEAD_MISSES] = "pv_lookahead_misses",
    [RPF_UA_SHIELDED_GATE_US] = "ua_shielded_gate_us",
    [RPF_UA_NULLIFIERS_US] = "ua_nullifiers_us",
    [RPF_UA_DELTA_PERSIST_US] = "ua_delta_persist_us",
    [RPF_TF_POST_FINALIZE_US] = "tf_post_finalize_us",
};

static void rollover_if_needed(struct profile_domain *p, uint64_t generation)
{
    if (atomic_load_explicit(&p->generation, memory_order_acquire) == generation)
        return;
    pthread_mutex_lock(&p->rollover_lock);
    if (atomic_load_explicit(&p->generation, memory_order_relaxed) != generation) {
        for (size_t i = 0; i < RPF_FIELD_COUNT; i++)
            atomic_store_explicit(&p->last_batch[i], 0, memory_order_relaxed);
        for (size_t i = 0; i < RPF_FIELD_COUNT; i++)
            for (size_t b = 0; b < PROFILE_HIST_BUCKETS; b++)
                atomic_store_explicit(&p->last_histogram[i][b], 0,
                                      memory_order_relaxed);
        atomic_store_explicit(&p->last_present, 0, memory_order_relaxed);
        atomic_store_explicit(&p->generation, generation, memory_order_release);
    }
    pthread_mutex_unlock(&p->rollover_lock);
}

static struct profile_domain *profile_for_add(
    enum reducer_profile_domain domain, enum reducer_profile_field field)
{
    if (domain < 0 || domain >= REDUCER_PROFILE_DOMAIN_COUNT ||
        field < 0 || field >= RPF_FIELD_COUNT)
        return NULL;
    struct profile_domain *p = &g_profiles[domain];
    uint64_t generation = stage_batch_active() ? stage_batch_generation() : 0;
    rollover_if_needed(p, generation);
    return p;
}

static void add_value(struct profile_domain *p,
                      enum reducer_profile_field field, uint64_t value)
{
    atomic_fetch_add_explicit(&p->cumulative[field], value,
                              memory_order_relaxed);
    atomic_fetch_add_explicit(&p->last_batch[field], value,
                              memory_order_relaxed);
    uint64_t bit = UINT64_C(1) << (unsigned)field;
    atomic_fetch_or_explicit(&p->present, bit, memory_order_relaxed);
    atomic_fetch_or_explicit(&p->last_present, bit, memory_order_relaxed);
}

void reducer_stage_profile_add(enum reducer_profile_domain domain,
                               enum reducer_profile_field field,
                               uint64_t value)
{
    struct profile_domain *p = profile_for_add(domain, field);
    if (p)
        add_value(p, field, value);
}

static size_t histogram_bucket(uint64_t value)
{
    if (value == 0)
        return 0;
    size_t bucket = 64u - (size_t)__builtin_clzll(value);
    return bucket < PROFILE_HIST_BUCKETS ? bucket
                                         : PROFILE_HIST_BUCKETS - 1u;
}

void reducer_stage_profile_observe_us(enum reducer_profile_domain domain,
                                      enum reducer_profile_field field,
                                      uint64_t value)
{
    struct profile_domain *p = profile_for_add(domain, field);
    if (!p)
        return;
    add_value(p, field, value);
    size_t bucket = histogram_bucket(value);
    atomic_fetch_add_explicit(&p->histogram[field][bucket], 1,
                              memory_order_relaxed);
    atomic_fetch_add_explicit(&p->last_histogram[field][bucket], 1,
                              memory_order_relaxed);
}

void reducer_stage_profile_reset(void)
{
    for (size_t d = 0; d < REDUCER_PROFILE_DOMAIN_COUNT; d++) {
        pthread_mutex_lock(&g_profiles[d].rollover_lock);
        for (size_t i = 0; i < RPF_FIELD_COUNT; i++) {
            atomic_store(&g_profiles[d].cumulative[i], 0);
            atomic_store(&g_profiles[d].last_batch[i], 0);
            for (size_t b = 0; b < PROFILE_HIST_BUCKETS; b++) {
                atomic_store(&g_profiles[d].histogram[i][b], 0);
                atomic_store(&g_profiles[d].last_histogram[i][b], 0);
            }
        }
        atomic_store(&g_profiles[d].present, 0);
        atomic_store(&g_profiles[d].last_present, 0);
        atomic_store(&g_profiles[d].generation, 0);
        pthread_mutex_unlock(&g_profiles[d].rollover_lock);
    }
}

static uint64_t bucket_upper_bound(size_t bucket)
{
    if (bucket == 0)
        return 0;
    return (UINT64_C(1) << bucket) - 1u;
}

static bool histogram_quantile(struct profile_domain *p, size_t field,
                               bool last, unsigned percentile,
                               uint64_t *value_out, uint64_t *samples_out)
{
    uint64_t samples = 0;
    for (size_t b = 0; b < PROFILE_HIST_BUCKETS; b++)
        samples += atomic_load(last ? &p->last_histogram[field][b]
                                    : &p->histogram[field][b]);
    if (samples_out)
        *samples_out = samples;
    if (samples == 0)
        return false;
    uint64_t target = (samples * percentile + 99u) / 100u;
    uint64_t seen = 0;
    for (size_t b = 0; b < PROFILE_HIST_BUCKETS; b++) {
        seen += atomic_load(last ? &p->last_histogram[field][b]
                                 : &p->histogram[field][b]);
        if (seen >= target) {
            *value_out = bucket_upper_bound(b);
            return true;
        }
    }
    return false;
}

static void push_latency_quantiles(struct json_value *out,
                                   struct profile_domain *p, bool last)
{
    struct json_value quantiles;
    json_init(&quantiles);
    json_set_object(&quantiles);
    for (size_t i = 0; i < RPF_FIELD_COUNT; i++) {
        uint64_t p50 = 0, p95 = 0, samples = 0;
        if (!histogram_quantile(p, i, last, 50, &p50, &samples))
            continue;
        (void)histogram_quantile(p, i, last, 95, &p95, NULL);
        struct json_value field;
        json_init(&field);
        json_set_object(&field);
        json_push_kv_int(&field, "samples", (int64_t)samples);
        json_push_kv_int(&field, "p50", (int64_t)p50);
        json_push_kv_int(&field, "p95", (int64_t)p95);
        json_push_kv(&quantiles, g_field_names[i], &field);
        /* json_push_kv COPIES the child (platform/modules/json/src/json.c json_copy), so
         * every temporary built here must be released or each dump call leaks
         * its whole tree — this dumper is sampled on a timer by
         * tools/scripts/fold_profile.sh, so the leak was unbounded. */
        json_free(&field);
    }
    json_push_kv(out, "latency_quantiles_us", &quantiles);
    json_free(&quantiles);
}

static void push_nullable_fields(struct json_value *out,
                                 struct profile_domain *p, bool last)
{
    uint64_t present = atomic_load(last ? &p->last_present : &p->present);
    for (size_t i = 0; i < RPF_FIELD_COUNT; i++) {
        struct json_value v;
        json_init(&v);
        if ((present & (UINT64_C(1) << i)) != 0) {
            uint64_t n = atomic_load(last ? &p->last_batch[i]
                                          : &p->cumulative[i]);
            json_set_int(&v, (int64_t)n);
        } else {
            json_set_null(&v);
        }
        json_push_kv(out, g_field_names[i], &v);
        json_free(&v);
    }
}

static void push_domain(struct json_value *out, struct profile_domain *p)
{
    struct json_value cumulative, last;
    json_init(&cumulative);
    json_init(&last);
    json_set_object(&cumulative);
    json_set_object(&last);
    push_nullable_fields(&cumulative, p, false);
    push_nullable_fields(&last, p, true);
    push_latency_quantiles(&cumulative, p, false);
    push_latency_quantiles(&last, p, true);
    json_push_kv_int(&last, "batch_generation",
                     (int64_t)atomic_load(&p->generation));
    json_push_kv(out, "cumulative", &cumulative);
    json_push_kv(out, "last_batch", &last);
    json_free(&cumulative);
    json_free(&last);
}

/* Emit ONE domain, COMPACTLY. The all-domains body is far over the native
 * command's 4096-byte state budget — `ops state --subsystem=reducer_stage_profile`
 * answers `skipped_oversize:"state"` and returns no numbers at all — and one
 * domain in the full shape is still over it, because the full shape spells out
 * every one of the RPF_FIELD_COUNT fields as an explicit null in BOTH the
 * cumulative and last_batch objects. So the keyed view drops what a caller
 * measuring an interval does not need: only fields this domain has actually
 * observed, and only the cumulative (monotonic) side, which is the side two
 * samples can be differenced. The unkeyed view is unchanged.
 *   z23 ops state --subsystem=reducer_stage_profile --key=proof_validate
 * An unknown key is named rather than silently answered with everything. */
static bool dump_one_domain(struct json_value *out, int domain)
{
    struct profile_domain *p = &g_profiles[domain];
    json_push_kv_str(out, "domain", g_domain_names[domain]);
    json_push_kv_str(out, "view", "cumulative_present_only");
    uint64_t present = atomic_load(&p->present);
    struct json_value cum;
    json_init(&cum);
    json_set_object(&cum);
    for (size_t i = 0; i < RPF_FIELD_COUNT; i++) {
        if ((present & (UINT64_C(1) << i)) == 0)
            continue;
        json_push_kv_int(&cum, g_field_names[i],
                         (int64_t)atomic_load(&p->cumulative[i]));
    }
    json_push_kv(out, "cumulative", &cum);
    json_free(&cum);
    push_latency_quantiles(out, p, false);
    json_push_kv_int(out, "batch_generation",
                     (int64_t)atomic_load(&p->generation));
    return true;
}

bool reducer_stage_profile_dump_state_json(struct json_value *out,
                                           const char *key)
{
    if (!out)
        return false;
    json_set_object(out);
    json_push_kv_str(out, "schema", PROFILE_SCHEMA);
    if (key && key[0]) {
        for (int d = 0; d < REDUCER_PROFILE_DOMAIN_COUNT; d++)
            if (strcmp(key, g_domain_names[d]) == 0)
                return dump_one_domain(out, d);
        json_push_kv_str(out, "unknown_key", key);
        return true;
    }
    struct json_value body, script;
    json_init(&body);
    json_init(&script);
    json_set_object(&body);
    json_set_object(&script);
    push_domain(&body, &g_profiles[REDUCER_PROFILE_BODY_PERSIST]);
    push_domain(&script, &g_profiles[REDUCER_PROFILE_SCRIPT_VALIDATE]);
    json_push_kv(out, "body_persist", &body);
    json_push_kv(out, "script_validate", &script);
    json_free(&body);
    json_free(&script);

    struct json_value tip_finalize, utxo_apply;
    json_init(&tip_finalize);
    json_init(&utxo_apply);
    json_set_object(&tip_finalize);
    json_set_object(&utxo_apply);
    push_domain(&tip_finalize, &g_profiles[REDUCER_PROFILE_TIP_FINALIZE]);
    push_domain(&utxo_apply, &g_profiles[REDUCER_PROFILE_UTXO_APPLY]);
    json_push_kv(out, "tip_finalize", &tip_finalize);
    json_push_kv(out, "utxo_apply", &utxo_apply);
    json_free(&tip_finalize);
    json_free(&utxo_apply);

    struct json_value proof_validate;
    json_init(&proof_validate);
    json_set_object(&proof_validate);
    push_domain(&proof_validate, &g_profiles[REDUCER_PROFILE_PROOF_VALIDATE]);
    json_push_kv(out, "proof_validate", &proof_validate);
    json_free(&proof_validate);
    return true;
}
