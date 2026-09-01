/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * no_state_source — LOUD signage for a boot that selected NO fast-start state
 * source. On a fresh node with no complete-state bundle installed, no consumed
 * refold, and no from-anchor cutover, AND no meaningful local chain state, the
 * reducer folds from an empty genesis datadir. If it cannot make progress (no
 * bodies, no serving peers) the fold pins — previously surfacing only as a
 * MISLEADING downstream symptom (e.g. proof_validate.stale_upstream_hash at
 * h=0). boot_select_state_source now names the REAL problem the moment it
 * concludes with no state source: the typed bootstrap.no_state_source blocker,
 * carrying the fetch outcome, bundle status, and the exact operator next step.
 *
 * The node STILL proceeds with normal from-genesis IBD — that is a valid
 * fallback, so the blocker is honest signage, not a halt. This condition owns
 * the CLEAR: it witnesses on H* climb (the fold advanced past its genesis
 * baseline) or a state source landing (a sovereign consensus-bundle marker
 * appears), never on wall time. If the node stays genuinely stuck, the engine
 * pages the operator once the episode ages out — with the actionable hint. */

#ifndef ZCL_CONDITIONS_NO_STATE_SOURCE_H
#define ZCL_CONDITIONS_NO_STATE_SOURCE_H

#include <stdbool.h>
#include <stdint.h>

/* How the instant-on bundle fetch concluded for this boot — best-effort,
 * derived from observable datadir state at boot_select_state_source time. */
enum no_state_source_fetch_outcome {
    NO_STATE_SOURCE_FETCH_SKIPPED = 0,      /* opt-out (-nofilesync / ZCL_NO_BUNDLE_FETCH)
                                             * or connect-only with no -fileservice peer */
    NO_STATE_SOURCE_FETCH_NO_SEED,          /* eligible + attempted, but no reachable
                                             * file-service seed served a usable manifest */
    NO_STATE_SOURCE_FETCH_DOWNLOAD_FAILED,  /* a manifest was discovered
                                             * (bundles/directory.json present) but no
                                             * verified bundle landed */
    NO_STATE_SOURCE_FETCH_SEEDS_EMPTY,      /* eligible, but the file-service seed set
                                             * assembled to ZERO peers — nothing was ever
                                             * contacted. DISTINCT from NO_SEED (which
                                             * means seeds WERE contacted and none served
                                             * a usable manifest): conflating the two made
                                             * a structurally-off fetch read as a
                                             * discovery miss. */
};

/* Whether a consensus bundle is present-but-unusable on this datadir. */
enum no_state_source_bundle_status {
    NO_STATE_SOURCE_BUNDLE_NONE = 0,        /* no bundle staged under bundles/ */
    NO_STATE_SOURCE_BUNDLE_FAILED,          /* a staged bundle carries a .failed marker */
};

struct no_state_source_facts {
    enum no_state_source_fetch_outcome fetch;
    enum no_state_source_bundle_status bundle;
    int32_t baseline_hstar;   /* provable tip at raise time — the fold baseline the
                               * witness clears above (fresh node ~= 0) */
};

/* Raise the typed bootstrap.no_state_source DEPENDENCY blocker immediately with
 * structured detail + an operator hint. Called from boot_select_state_source
 * when NO fast-start state source was selected AND the datadir has no meaningful
 * chain state. The reason is STABLE (no volatile heights/timestamps) so a
 * re-raise is a rate-limited dup, not an identity churn. */
void no_state_source_raise(const struct no_state_source_facts *f);

void register_no_state_source(void);

#ifdef ZCL_TESTING
/* Reset module + engine state between tests. */
void no_state_source_test_reset(void);
/* Override the datadir the witness reads for the marker check (NULL = live).
 * The witness reads H* through reducer_frontier_provable_tip_cached(); drive it
 * in a test via reducer_frontier_provable_tip_set()/_reset(). */
void no_state_source_test_set_datadir(const char *datadir);
/* Directly drive detect/witness for the focused test. */
bool no_state_source_test_detect(void);
bool no_state_source_test_witness(void);
#endif

#endif /* ZCL_CONDITIONS_NO_STATE_SOURCE_H */
