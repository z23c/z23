/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Bounded, monotonic reducer hot-stage measurements.  This is observability
 * only: writers add elapsed/work values, diagnostics take read-only snapshots.
 */
#ifndef ZCL_UTIL_REDUCER_STAGE_PROFILE_H
#define ZCL_UTIL_REDUCER_STAGE_PROFILE_H

#include <stdbool.h>
#include <stdint.h>

struct json_value;

enum reducer_profile_domain {
    REDUCER_PROFILE_BODY_PERSIST = 0,
    REDUCER_PROFILE_SCRIPT_VALIDATE,
    REDUCER_PROFILE_TIP_FINALIZE,
    REDUCER_PROFILE_UTXO_APPLY,
    REDUCER_PROFILE_PROOF_VALIDATE,
    REDUCER_PROFILE_DOMAIN_COUNT
};

enum reducer_profile_field {
    RPF_BLOCKS = 0,
    RPF_TOTAL_US,
    RPF_UPSTREAM_US,
    RPF_CACHE_HITS,
    RPF_CACHE_MISSES,
    RPF_CACHE_PROBES,
    RPF_CACHE_LOCK_WAIT_US,
    RPF_DISK_READ_US,
    RPF_PARSE_US,
    RPF_DEEP_CLONES,
    RPF_DEEP_CLONE_BYTES,
    RPF_BLOCK_HASH_US,
    RPF_MERKLE_US,
    RPF_MERKLE_ALLOCS,
    RPF_MERKLE_BYTES,
    RPF_EVENT_ENCODE_US,
    RPF_EVENT_APPEND_US,
    RPF_CREATED_INDEX_BLOCKS,
    RPF_CREATED_INDEX_TXS,
    RPF_CREATED_INDEX_OUTPUTS,
    RPF_CREATED_INDEX_PREPARES,
    RPF_CREATED_INDEX_STEPS,
    RPF_CREATED_INDEX_US,
    RPF_CONTEXTUAL_US,
    RPF_TX_PRECOMPUTE_US,
    RPF_JOB_ARRAY_ALLOCS,
    RPF_JOB_ARRAY_BYTES,
    RPF_PREVOUT_CREATED_LOOKUPS,
    RPF_PREVOUT_COINS_FALLBACKS,
    RPF_PREVOUT_PREPARES,
    RPF_PREVOUT_HITS,
    RPF_PREVOUT_MISSES,
    RPF_PREVOUT_US,
    RPF_POOL_SETUP_US,
    RPF_POOL_WAKE_US,
    RPF_VERIFY_SCRIPT_CPU_US,
    RPF_WORKER_WAIT_US,
    RPF_ORDERED_REDUCTION_US,
    RPF_HEADER_EVENT_US,
    RPF_STAGE_LOG_CURSOR_US,
    /* tip_finalize per-phase timings (REDUCER_PROFILE_TIP_FINALIZE) — splits the
     * finalize step so the "tip_finalize is 94% of the round" figure resolves
     * into which phase actually spends the time (historically the window move). */
    RPF_TF_LOG_INSERT_US,
    RPF_TF_INCREMENTAL_SUM_US,
    RPF_TF_WINDOW_MOVE_US,
    RPF_TF_PROVABLE_TIP_US,
    /* utxo_apply per-phase timings (REDUCER_PROFILE_UTXO_APPLY). */
    RPF_UA_PREVOUT_US,
    RPF_UA_APPLY_US,
    RPF_UA_COMMIT_US,
    /* proof_validate per-phase timings + shielded work counts
     * (REDUCER_PROFILE_PROOF_VALIDATE). The stage is repeatedly described as
     * 13-18 ms/block with no sub-phase evidence behind the figure; these split
     * a step into body acquisition, the proof sweep itself, and the terminal
     * log insert, and count the shielded primitives the sweep actually ran so
     * a per-proof cost is derivable instead of asserted.
     *
     * SCOPE: every field here is emitted from app/jobs/src/proof_validate_stage.c
     * (the stage state machine). Splitting RPF_PV_VERIFY_US further into
     * Groth16-spend vs Groth16-output vs Sprout vs binding-sig TIME needs a
     * clock pair inside the per-tx sweep in app/jobs/src/proof_validate_verify.c;
     * the COUNTS below carry the denominator for that split in the meantime. */
    RPF_PV_BODY_ACQUIRE_US,
    RPF_PV_VERIFY_US,
    RPF_PV_LOG_INSERT_US,
    RPF_PV_SPENDS,
    RPF_PV_OUTPUTS,
    RPF_PV_SPROUT_GROTH16,
    RPF_PV_SPROUT_PHGR13,
    RPF_PV_BINDING_SIGS,
    RPF_PV_LOOKAHEAD_HITS,
    RPF_PV_LOOKAHEAD_MISSES,
    /* utxo_apply / tip_finalize remaining-step coverage
     * (REDUCER_PROFILE_UTXO_APPLY / REDUCER_PROFILE_TIP_FINALIZE). The three
     * UA phases above plus the TF phases above left the majority of a fold's
     * per-block wall time unattributed ("the middle"); these bracket the
     * remaining hot segments so drain-level µs/advance resolves: the
     * shielded history gate, nullifier check + insert, inverse-delta
     * persist (all timed inside their utxo_apply_nullifiers.c /
     * utxo_apply_delta.c implementations), and tip_finalize's
     * post-finalize side effects (wallet/mempool/MMR/MMB). */
    RPF_UA_SHIELDED_GATE_US,
    RPF_UA_NULLIFIERS_US,
    RPF_UA_DELTA_PERSIST_US,
    RPF_TF_POST_FINALIZE_US,
    /* The `present`/`last_present` bitmask is ONE uint64_t per domain and a
     * field's bit is `UINT64_C(1) << field`, so the highest legal field index
     * is 63 and RPF_FIELD_COUNT must stay <= 64. Exceeding it shifts out of
     * range and silently corrupts the presence mask (fields start reporting
     * null while their counters keep moving). Widen the mask explicitly in the
     * same commit that crosses the bound — reducer_stage_profile.c holds a
     * _Static_assert on exactly this. */
    RPF_FIELD_COUNT
};

/* Reverse of the domain->stage-name table: map a reducer stage's name (the
 * same string it registers with stage_create) to its profile domain, or -1
 * when that stage has no profile domain. Lets the shared stage runner attribute
 * one whole committed step without every stage duplicating the bookkeeping. */
int reducer_stage_profile_domain_for(const char *stage_name);

void reducer_stage_profile_add(enum reducer_profile_domain domain,
                               enum reducer_profile_field field,
                               uint64_t value);
/* Add a duration and one sample to the bounded log2 histogram used for p50/p95
 * diagnostics. Use this rather than `_add` for elapsed-time fields. */
void reducer_stage_profile_observe_us(enum reducer_profile_domain domain,
                                      enum reducer_profile_field field,
                                      uint64_t value);
void reducer_stage_profile_reset(void);
bool reducer_stage_profile_dump_state_json(struct json_value *out,
                                           const char *key);

#endif /* ZCL_UTIL_REDUCER_STAGE_PROFILE_H */
