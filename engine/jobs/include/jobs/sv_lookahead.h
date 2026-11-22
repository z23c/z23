/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * sv_lookahead — cross-height transparent-script pre-verification, the
 * script_validate counterpart of pv_lookahead (jobs/pv_lookahead.h).
 *
 * script_validate verifies one block per step on the drive thread. Workers here
 * claim heights AHEAD of the script_validate cursor, read the body on the same
 * lock-free active_chain_at + pread path, run the EXISTING serial sweep
 * (script_verify_block, parallel=false) with the stage resolver, and cache the
 * whole script_verify_summary keyed by
 *     (height, block_hash, script flags, consensus branch id).
 *
 * Why a cached verdict equals the inline one:
 *   - the sweep is a pure function of (block bytes, prevout outputs, flags,
 *     branch id). The flags and branch id are computed for the CLAIMED height by
 *     script_verify_params_for_height, the one definition the sweep itself uses;
 *   - a prevout output is (value, scriptPubKey) of the transaction named by the
 *     outpoint hash, and that hash commits to the outputs. Whichever store
 *     resolved it (created_outputs index, coins_kv), the bytes are the same, so
 *     the verdict does not depend on how far utxo_apply has progressed. Whether
 *     the coin is still UNSPENT is not part of script verification: utxo_apply
 *     decides it, for the cached and the inline path alike;
 *   - a block ahead of the cursor may spend an output created between the cursor
 *     and its height (the lookahead is bounded by the body_persist cursor, so
 *     every creating block is already indexed). An output that cannot be
 *     resolved, in ANY input the sweep reaches, makes the sweep report
 *     internal_error, and such a verdict is NEVER cached (prevout_unresolved,
 *     block_decode_failed, out_of_memory); the drive verifies inline;
 *   - a verdict is consumed only on an exact key match plus the same resolver
 *     pair, so a reorg (different hash), a gap or a stale slot is a MISS and the
 *     stage runs the unchanged inline sweep.
 *
 * The drive applies the stage counters from the returned summary in height
 * order, exactly as after an inline sweep. The drive never waits on the pool.
 *
 * Default OFF: started only by -sv-lookahead (engine/composition/src/
 * boot_sv_lookahead.c) through script_validate_lookahead_start. */

#ifndef ZCL_JOBS_SV_LOOKAHEAD_H
#define ZCL_JOBS_SV_LOOKAHEAD_H

#include "core/uint256.h"
#include "jobs/script_validate_stage.h"
#include "jobs/script_validate_verify.h"

#include <stdbool.h>
#include <stdint.h>

struct main_state;

/* Heights ahead of the cursor workers may verify; also the verdict ring size. */
#define SV_LOOKAHEAD_WINDOW 512

/* Exclusive upper height bound the workers may verify: heights below it have
 * their bodies persisted AND their created outputs indexed (production:
 * body_persist_stage_cursor). */
typedef uint64_t (*sv_lookahead_limit_fn)(void);

/* Start min(cores-2, 4) (>=1) supervised workers. `reader` NULL selects the
 * production pread path. `prevout`/`prevout_user` must be the stage's resolver
 * pair; sv_lookahead_take re-checks it. false = pool stays off. */
bool sv_lookahead_start(struct main_state *ms, const char *datadir,
                        script_validate_reader_fn reader, void *reader_user,
                        script_validate_prevout_fn prevout, void *prevout_user,
                        sv_lookahead_limit_fn limit);

/* Signal stop, join workers, release the ring. Idempotent. */
void sv_lookahead_stop(void);

/* Consume the cached summary for the exact key if the pool is running and the
 * resolver pair matches. true = hit (*out filled, slot freed); anything else is
 * a miss and the caller verifies inline. */
bool sv_lookahead_take(int height, const struct uint256 *block_hash,
                       uint32_t flags, uint32_t branch_id,
                       script_validate_prevout_fn prevout, void *prevout_user,
                       struct script_verify_summary *out);

/* Telemetry. hit/miss count consumes while running; populated = verdicts warmed
 * and not yet consumed; verified = sweeps the workers ran; skipped = sweeps not
 * cached (internal_error / unreadable body). */
uint64_t sv_lookahead_hit_total(void);
uint64_t sv_lookahead_miss_total(void);
uint64_t sv_lookahead_populated(void);
uint64_t sv_lookahead_verified_total(void);
uint64_t sv_lookahead_skipped_total(void);

#ifdef ZCL_TESTING
/* Test-only (defined in script_validate_stage.c): replace the bound
 * script_validate_lookahead_start passes (default body_persist_stage_cursor,
 * which a test that does not step body_persist leaves at 0). NULL restores it. */
void script_validate_lookahead_set_limit_for_test(sv_lookahead_limit_fn fn);
#endif

#endif /* ZCL_JOBS_SV_LOOKAHEAD_H */
