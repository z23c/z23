/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * stale_offers_only — LOUD signage for a bounded first-boot wait
 * (engine/composition/include/config/state_offer_store.h, ZRC-0011) that
 * closed with nothing acceptable: every connected peer's newest offer was
 * more than the freshness window behind that peer's own tip, or no peer
 * offered a state at all. The store's decide() already returns
 * STATE_OFFER_DECIDE_FALL_BACK the instant that is true; this condition is
 * what turns that private decision into a typed, operator-visible blocker
 * instead of a silent from-genesis fold.
 *
 * The node STILL proceeds with normal from-genesis IBD — the fall-back is a
 * valid, working default, so the blocker is honest signage, not a halt. This
 * condition owns the CLEAR: it witnesses on H* climbing past the newest
 * height any peer offered (fold-forward self-heals it, same self-clearing
 * shape as bootstrap.no_state_source) or on the store reporting an
 * acceptable offer was chosen after all — never on wall time. */

#ifndef ZCL_CONDITIONS_STALE_OFFERS_ONLY_H
#define ZCL_CONDITIONS_STALE_OFFERS_ONLY_H

#include <stdbool.h>
#include <stdint.h>

struct stale_offers_only_facts {
    int32_t  newest_height_seen; /* newest bundle height ANY peer offered, 0 if none */
    uint32_t peers_offering;     /* distinct peers that sent an offer at all */
    uint32_t offers_seen;        /* verified offers this run, retained or not */
    int32_t  baseline_hstar;     /* provable tip at raise time, for the log/detail */
};

/* Raise the typed bootstrap.stale_offers_only DEPENDENCY blocker immediately
 * with structured detail (logged) + an operator hint. Called by the bounded-
 * wait caller when state_offer_store_decide() returns
 * STATE_OFFER_DECIDE_FALL_BACK. The reason is STABLE (no volatile height) so
 * a re-raise is a rate-limited dup, not an identity churn; the volatile
 * newest-height number goes to the log line and the test-visible facts, not
 * the reason string that keys the blocker's identity. */
void stale_offers_only_raise(const struct stale_offers_only_facts *f);

void register_stale_offers_only(void);

#ifdef ZCL_TESTING
/* Reset module + engine state between tests. */
void stale_offers_only_test_reset(void);
/* Directly drive detect/witness for the focused test. */
bool stale_offers_only_test_detect(void);
bool stale_offers_only_test_witness(void);
/* The newest-height-seen fact captured at the last raise (0 if never raised
 * this process) — proves the raise carried the structured detail an operator
 * needs, independent of log-line scraping. */
int32_t stale_offers_only_test_newest_height_seen(void);
#endif

#endif /* ZCL_CONDITIONS_STALE_OFFERS_ONLY_H */
