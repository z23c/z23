/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * reducer_frontier_self_anchor — sourcing helper for
 * reducer_frontier_compiled_anchor() (reducer_frontier.c). Private, same-
 * directory header (same convention as reducer_frontier_evidence.h): not part
 * of the public jobs/ API surface.
 *
 * See the "SELF-DERIVED SOURCING" note on REDUCER_FRONTIER_TRUSTED_ANCHOR in
 * jobs/reducer_frontier.h for the contract this implements.
 */

#ifndef ZCL_JOBS_REDUCER_FRONTIER_SELF_ANCHOR_H
#define ZCL_JOBS_REDUCER_FRONTIER_SELF_ANCHOR_H

#include <stdint.h>

/* Returns THIS node's self-derived anchor height when a SHA3-verified
 * <datadir>/utxo-anchor.snapshot artifact is present and its recorded
 * SHA3/count/height reproduce `compiled_height` (the current compiled
 * checkpoint) exactly; returns a negative sentinel (< 0) otherwise — an
 * absent artifact and a present-but-mismatched artifact are BOTH sentinel
 * (never distinguished by the caller, which always falls back to
 * `compiled_height` in either case; never trust a borrowed/torn anchor).
 *
 * Resolved AT MOST ONCE per process (cached internally) — the probe opens
 * and full-body-SHA3-verifies a potentially ~100 MB file, so this must never
 * run on the hot reducer_frontier_floor() path. Cheap on every call after
 * the first (a single lock-free atomic load). Never allocates, never writes,
 * never crashes the caller — a probe or read failure resolves to the
 * negative sentinel, exactly like "no artifact yet". */
int32_t reducer_frontier_self_anchor_get(int32_t compiled_height);

#endif /* ZCL_JOBS_REDUCER_FRONTIER_SELF_ANCHOR_H */
