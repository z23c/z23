/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * rewind_driver — THE one generic "nearest self-verified base -> rewind ->
 * O(delta) re-derive" recovery driver.
 *
 * Every recovery trigger that needs to un-wedge the reducer by re-deriving a
 * suffix of the chain routes through this single entry instead of hand-rolling
 * its own base picking + rewind + escalation. The driver:
 *
 *   1. resolves the NEAREST SELF-VERIFIED base at or below a caller ceiling
 *      (reducer_frontier_nearest_self_verified_base — a compiled SHA3
 *      checkpoint or a self-valid seal_kv coins_sha3 slot always beats a
 *      borrowed finalized_utxo_sha3, so recovery is ALWAYS sovereign), then
 *   2. preserves that base and re-derives base+1 through H* via THE universal
 *      re-derive
 *      primitive stage_rederive_range() (LCC-safe: it refuses rather than
 *      manufacture a coin hole, and NEVER deletes tip_finalize_log rows / the
 *      served floor), so recovery is O(delta-from-the-nearest-rung), never a
 *      full-chain redo, and
 *   3. on an LCC refusal (an applied height lacks its inverse delta) OR no
 *      reachable base, escalates ONCE by naming a typed blocker (and emitting
 *      EV_RECOVERY_ACTION) instead of looping — a named, escalatable dependency
 *      rather than a silent retry storm.
 *
 * CONSENSUS PARITY (inviolable): the driver changes NO validity. stage_rederive_
 * range only reschedules re-derivation; the forward fold re-executes the
 * identical validators over the same PoW-verified on-disk bodies and rewrites
 * byte-identical verdicts. */

#ifndef ZCL_JOBS_REWIND_DRIVER_H
#define ZCL_JOBS_REWIND_DRIVER_H

#include <stdbool.h>
#include <stdint.h>

struct rewind_driver_result {
    bool ok;          /* recovery committed a rewind (forward fold re-derives) */
    bool nothing;     /* no rewind needed (base already at/above H*)          */
    bool escalated;   /* LCC refusal or no base — named the typed blocker     */
    int32_t base_height;  /* the self-verified base selected (-1 if none)     */
    int32_t hstar;        /* H* at the time of the drive                      */
    bool base_self_derived; /* provenance of the selected base                */
    char base_kind[32];     /* "compiled_checkpoint" / "sealed_coins_sha3" …  */
    bool rewound;           /* at least one stage cursor was lowered          */
    bool coins_rewound;     /* the inverse-delta coins rewind fired           */
    int cursors_rewound;
};

/* Rewind to the nearest self-verified base at or below `at_or_below`
 * (pass INT32_MAX for "nearest at or below H*") and re-derive forward to H*.
 *
 * `reason` labels the trigger in logs/events (e.g. "tip_label_divergence").
 * `escalate_tag` is a short suffix from which the driver builds the typed
 * blocker id "rewind_driver.<escalate_tag>", set on an LCC refusal / no
 * reachable base; a committed (or no-op) recovery clears it. `out` may be NULL.
 *
 * Returns false ONLY on a hard store error (invalid state, SQL failure). A
 * committed rewind, a clean no-op, and a clean escalation all return true —
 * inspect `out->ok` / `out->nothing` / `out->escalated` to distinguish.
 *
 * The caller MUST NOT hold an open progress-store transaction (stage_rederive_
 * range opens its own BEGIN IMMEDIATE). */
bool rewind_to_nearest_self_verified_base(int32_t at_or_below,
                                          const char *reason,
                                          const char *escalate_tag,
                                          struct rewind_driver_result *out);

#endif /* ZCL_JOBS_REWIND_DRIVER_H */
