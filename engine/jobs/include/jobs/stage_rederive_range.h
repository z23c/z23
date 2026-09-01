/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * stage_rederive_range — THE universal re-derive primitive
 * (docs/work/fail-safe-architecture.md §0c).
 *
 * One general entry that re-derives a height range of the body-dependent
 * reducer stage logs by REWINDING their cursors to `from_height`, deleting the
 * stale suffix rows, and (iff `from_height` is below the coins frontier)
 * inverse-delta rewinding coins — so the normal forward fold re-runs the SAME
 * validators over the SAME PoW-verified on-disk bodies and rewrites
 * byte-identical consensus verdicts. It replaces the ad-hoc detector/refill
 * zoo with a single, mechanism-agnostic write path the recovery ladder rungs
 * call.
 *
 * CONSENSUS PARITY (inviolable): the primitive changes NO validity. It only
 * schedules re-derivation; the forward fold re-executes the identical
 * validation code, so a height that is a genuine consensus reject re-derives to
 * the SAME reject, and a height that was corrupted/stale/rowless re-derives to
 * its correct verdict. "Re-derive" == "re-fold the same bodies to the same
 * verdicts", never "relax a rule".
 *
 * LCC (Log-Cursor Contiguity, §0b): a cursor is never lowered below the deepest
 * downstream consumer (the applied coin set) without inverse-rewinding coins in
 * the SAME transaction. If any applied height in the range lacks its inverse
 * delta (no crypto-vetted way to rewind coins there), the primitive REFUSES
 * (returns true, out->ok=false, out->refused_no_inverse=true) rather than
 * manufacture a hole — the caller then escalates to a refold-from-anchor rung.
 *
 * Idempotent + crash-safe: one BEGIN IMMEDIATE / COMMIT; a crash mid-rederive
 * rolls back and self-heals on the next fold; a second call on an
 * already-rewound state is a no-op.
 *
 * NOT rewound: header_admit + validate_headers (header/PoW authority, not
 * body-derived — rung-1 semantics is "stages ≥ body_fetch"). tip_finalize_log
 * ROWS are never deleted (served-floor invariant); only the tip_finalize CURSOR
 * is rewound so the surviving rows re-finalize forward. */

#ifndef ZCL_JOBS_STAGE_REDERIVE_RANGE_H
#define ZCL_JOBS_STAGE_REDERIVE_RANGE_H

#include <stdbool.h>

struct sqlite3;
struct main_state;

struct stage_rederive_range_result {
    bool ok;                 /* the rewind transaction committed */
    bool rewound;            /* at least one cursor was actually lowered */
    bool coins_rewound;      /* the inverse-delta coins rewind fired */
    bool refused_no_inverse; /* LCC refusal: an applied height lacked its
                              * inverse delta — escalate to refold-from-anchor */
    int from_height;
    int to_height;
    int cursors_rewound;         /* count of stage cursors lowered to from_height */
    int coins_frontier_before;   /* utxo_apply cursor before the rewind */
};

/* Re-derive stage logs over the range [from_height, to_height].
 *
 * `db` is the progress store (progress_store_db()). `ms` is optional (may be
 * NULL): the forward fold re-creates created_outputs itself, so the coins
 * rewind does not depend on it; it is accepted for API symmetry with the replay
 * TU and future window-refold optimizations.
 *
 * Semantics: for every body-dependent stage whose cursor is strictly above
 * `from_height`, the stale suffix rows [from_height, cursor) are deleted and the
 * cursor is lowered to `from_height`; if `from_height` is below the coins
 * frontier the applied coins are inverse-rewound to `from_height` in the same
 * transaction. `to_height` bounds the caller's re-fold expectation (the forward
 * fold naturally re-derives from `from_height` up to and beyond it); it is
 * validated (from_height ≤ to_height) and echoed in `out`.
 *
 * Returns false ONLY on a hard store error (BEGIN/COMMIT/SQL failure or invalid
 * args). A committed rewind AND a clean LCC refusal both return true; inspect
 * `out->ok` / `out->refused_no_inverse` to distinguish. `out` may be NULL.
 *
 * The caller MUST NOT already hold an open progress-store transaction (this
 * function opens its own BEGIN IMMEDIATE); the recursive progress_store lock is
 * acquired internally, so holding the lock (but not a transaction) is safe. */
bool stage_rederive_range(struct sqlite3 *db, struct main_state *ms,
                          int from_height, int to_height,
                          struct stage_rederive_range_result *out);

#endif /* ZCL_JOBS_STAGE_REDERIVE_RANGE_H */
