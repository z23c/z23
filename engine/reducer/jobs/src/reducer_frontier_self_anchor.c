/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * reducer_frontier_self_anchor — implementation. See
 * reducer_frontier_self_anchor.h and the "SELF-DERIVED SOURCING" note on
 * REDUCER_FRONTIER_TRUSTED_ANCHOR in jobs/reducer_frontier.h.
 *
 * Resolves THIS node's own self-derived anchor marker: the SHA3-verified
 * <datadir>/utxo-anchor.snapshot artifact, written either by the offline
 * -mint-anchor producer ceremony (engine/composition/src/boot_mint_anchor.c — read its
 * OUTPUT artifact only, never its fold/assert logic here) or by the in-fold
 * anchor_selfmint hook (services/anchor_selfmint.h) the very first time a
 * NORMAL fold lands the compiled checkpoint height. Either way the artifact
 * is the SAME uss-format file at the SAME default path, and
 * anchor_selfmint_snapshot_status is the existing read-only reader for it
 * (opens read-only, recomputes the full-body SHA3, and reports match
 * booleans against the CURRENT compiled checkpoint — no coins_kv mutation,
 * no write).
 *
 * NEVER accepts a present-but-mismatched artifact: `verified` already
 * requires the recomputed SHA3 to equal the compiled checkpoint's (uss_open's
 * expected_sha3 gate) AND the count to match; a height drift under a passing
 * verify would mean our own fold disagrees with the checkpoint, which is a
 * defect, not a legitimate advance — refused exactly like a SHA3/count
 * mismatch. Resolves to the negative sentinel (never FATAL) on any refusal
 * or on a genuinely absent artifact — this is a read path and must never
 * crash the node; the caller's compiled-literal fallback is always safe
 * because the two values are asserted equal by construction until a later
 * lane legitimately moves the self-derived value past the baked one. */

#include "reducer_frontier_self_anchor.h"

#include "services/anchor_selfmint.h"
#include "util/log_macros.h"
#include "util/util.h"                  /* GetDataDir */

#include <stdatomic.h>

/* Sentinel UNRESOLVED means "not probed yet this process"; ABSENT means
 * "probed, no admissible self-derived marker" — both fall back to the
 * compiled literal in the caller. Any value >= 0 is the self-derived height,
 * already asserted == compiled_height by resolve_impl before being cached. */
#define REDUCER_FRONTIER_SELF_ANCHOR_UNRESOLVED ((int32_t)-2)
#define REDUCER_FRONTIER_SELF_ANCHOR_ABSENT     ((int32_t)-1)
static _Atomic int32_t g_self_derived_anchor =
    REDUCER_FRONTIER_SELF_ANCHOR_UNRESOLVED;

#ifdef ZCL_TESTING
/* Test-only reset: a process-lifetime cache would otherwise leak a prior
 * test's resolved value (or its ABSENT verdict) into a later test that swaps
 * in a different datadir / checkpoint override / artifact. Mirrored
 * src-private by the test that uses it, same convention as
 * reducer_frontier_test_set_compiled_anchor (reducer_frontier.c). */
void reducer_frontier_test_reset_self_derived_anchor(void);
void reducer_frontier_test_reset_self_derived_anchor(void)
{
    atomic_store(&g_self_derived_anchor,
                 REDUCER_FRONTIER_SELF_ANCHOR_UNRESOLVED);
}
#endif

static int32_t resolve_impl(int32_t compiled_height)
{
    char datadir[2048] = {0};
    GetDataDir(/*fNetSpecific=*/true, datadir, sizeof(datadir));

    struct anchor_snapshot_status st;
    if (!anchor_selfmint_snapshot_status(datadir, &st)) {
        LOG_WARN("reducer",
                 "[reducer] self-derived anchor probe call failed "
                 "(datadir=%s) — falling back to the compiled checkpoint",
                 datadir[0] ? datadir : "(unset)");
        return REDUCER_FRONTIER_SELF_ANCHOR_ABSENT;
    }
    if (!st.stat_present || !st.header_read) {
        /* No artifact minted on THIS datadir yet (or not yet resolvable) —
         * success, not an error: the offline ceremony / in-fold self-mint
         * hook simply hasn't produced one here. Compiled-literal fallback. */
        return REDUCER_FRONTIER_SELF_ANCHOR_ABSENT;
    }
    if (!st.verified || (int32_t)st.snapshot_height != compiled_height) {
        LOG_WARN("reducer",
                 "[reducer] self-derived anchor artifact at %s does NOT "
                 "admit as the trust anchor (verified=%d snapshot_h=%u "
                 "compiled_h=%d) — REFUSING it (never trust a borrowed/torn "
                 "anchor); falling back to the compiled literal", st.path,
                 st.verified, st.snapshot_height, compiled_height);
        return REDUCER_FRONTIER_SELF_ANCHOR_ABSENT;
    }
    return (int32_t)st.snapshot_height;
}

int32_t reducer_frontier_self_anchor_get(int32_t compiled_height)
{
    int32_t cached = atomic_load(&g_self_derived_anchor);
    if (cached == REDUCER_FRONTIER_SELF_ANCHOR_UNRESOLVED) {
        cached = resolve_impl(compiled_height);
        atomic_store(&g_self_derived_anchor, cached);
    }
    return cached;
}
