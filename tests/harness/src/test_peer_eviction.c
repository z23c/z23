/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Focused unit tests for peer_eviction_select() (core/modules/net/src/peer_eviction.c)
 * — a pure, allocation-free, lock-free function with no I/O and no clock
 * (the caller passes `now`). Table-driven over the protection classes:
 * outbound/whitelisted immunity, the longest-connected quartile, recent
 * novel block/tx relay, and the "evict newest" tie-break among what's left. */

#include "test/test_core.h"

#include "net/peer_eviction.h"

#include <stdio.h>
#include <string.h>

#define PE_CHECK(name, expr) do {                                    \
    printf("peer_eviction: %s... ", (name));                         \
    if (expr) { printf("OK\n"); }                                    \
    else { printf("FAIL\n"); failures++; }                           \
} while (0)

int test_peer_eviction(void)
{
    printf("\n=== peer_eviction_select tests ===\n");
    int failures = 0;
    const int64_t NOW = 1000000;

    /* empty array -> -1 */
    PE_CHECK("empty array returns -1",
             peer_eviction_select(NULL, 0, NOW) == -1);

    /* single unprotected inbound peer -> evicted */
    {
        struct peer_eviction_candidate c[1] = {
            { .is_outbound = false, .whitelisted = false,
              .connected_time = NOW - 10, .last_block_time = 0, .last_tx_time = 0 },
        };
        PE_CHECK("single inbound candidate is evicted",
                 peer_eviction_select(c, 1, NOW) == 0);
    }

    /* outbound-only -> never evicted, -1 */
    {
        struct peer_eviction_candidate c[3] = {
            { .is_outbound = true, .connected_time = NOW - 5 },
            { .is_outbound = true, .connected_time = NOW - 50 },
            { .is_outbound = true, .connected_time = NOW - 500 },
        };
        PE_CHECK("all-outbound candidates never evicted (-1)",
                 peer_eviction_select(c, 3, NOW) == -1);
    }

    /* whitelisted-only -> never evicted, -1 */
    {
        struct peer_eviction_candidate c[2] = {
            { .whitelisted = true, .connected_time = NOW - 5 },
            { .whitelisted = true, .connected_time = NOW - 50 },
        };
        PE_CHECK("all-whitelisted candidates never evicted (-1)",
                 peer_eviction_select(c, 2, NOW) == -1);
    }

    /* mixed outbound/inbound: only the inbound one is eligible */
    {
        struct peer_eviction_candidate c[2] = {
            { .is_outbound = true,  .connected_time = NOW - 1 },
            { .is_outbound = false, .connected_time = NOW - 2 },
        };
        PE_CHECK("outbound skipped, sole inbound candidate evicted",
                 peer_eviction_select(c, 2, NOW) == 1);
    }

    /* evict the NEWEST unprotected connection among several eligible
     * inbound peers with no relay activity and a quartile too small to
     * protect anyone (n=3 -> quartile=0). */
    {
        struct peer_eviction_candidate c[3] = {
            { .connected_time = NOW - 300 }, /* oldest */
            { .connected_time = NOW - 100 },
            { .connected_time = NOW - 10 },  /* newest -> evicted */
        };
        PE_CHECK("newest unprotected candidate is evicted",
                 peer_eviction_select(c, 3, NOW) == 2);
    }

    /* longest-connected quartile protection: 4 candidates -> quartile=1,
     * protecting the single oldest connection even though the eviction
     * rule otherwise favors newest-first. The 2nd-newest of the
     * remaining 3 unprotected candidates is still the evictee. */
    {
        struct peer_eviction_candidate c[4] = {
            { .connected_time = NOW - 1000 }, /* oldest: protected by quartile */
            { .connected_time = NOW - 300 },
            { .connected_time = NOW - 200 },
            { .connected_time = NOW - 100 },  /* newest unprotected -> evicted */
        };
        int idx = peer_eviction_select(c, 4, NOW);
        PE_CHECK("quartile protects the oldest; newest-of-rest is evicted",
                 idx == 3);
    }
    {
        /* n=3 -> quartile=0 (no longevity protection at all): confirms
         * the "evict newest" rule still never picks the oldest candidate
         * when a newer unprotected one is available, independent of
         * quartile protection kicking in. */
        struct peer_eviction_candidate c[3] = {
            { .connected_time = NOW - 1000 },
            { .connected_time = NOW - 300 },
            { .connected_time = NOW - 200 },  /* newest -> evicted */
        };
        PE_CHECK("n=3 (no quartile protection): newest is still evicted, not oldest",
                 peer_eviction_select(c, 3, NOW) == 2);
    }

    /* recent novel block relay protects a peer that would otherwise be
     * the newest (and thus the eviction target). */
    {
        struct peer_eviction_candidate c[2] = {
            { .connected_time = NOW - 50, .last_block_time = 0 },
            { .connected_time = NOW - 10,
              .last_block_time = NOW - 30 /* well within the window */ },
        };
        PE_CHECK("recent novel block relay protects the newest peer",
                 peer_eviction_select(c, 2, NOW) == 0);
    }

    /* recent novel tx relay protects a peer the same way. */
    {
        struct peer_eviction_candidate c[2] = {
            { .connected_time = NOW - 50, .last_tx_time = 0 },
            { .connected_time = NOW - 10,
              .last_tx_time = NOW - 30 },
        };
        PE_CHECK("recent novel tx relay protects the newest peer",
                 peer_eviction_select(c, 2, NOW) == 0);
    }

    /* relay OUTSIDE the recency window offers no protection — the
     * stale relayer is still evictable if it's also the newest. */
    {
        struct peer_eviction_candidate c[2] = {
            { .connected_time = NOW - 50, .last_block_time = 0 },
            { .connected_time = NOW - 10,
              .last_block_time = NOW - (PEER_EVICTION_RECENT_RELAY_SECS + 1) },
        };
        PE_CHECK("stale block relay (outside window) offers no protection",
                 peer_eviction_select(c, 2, NOW) == 1);
    }

    /* all inbound candidates protected (quartile + relay covers
     * everyone) -> -1, same behavior as before eviction existed. */
    {
        struct peer_eviction_candidate c[2] = {
            { .connected_time = NOW - 500, .last_block_time = NOW - 5 },
            { .connected_time = NOW - 5,   .last_tx_time = NOW - 5 },
        };
        PE_CHECK("every inbound candidate protected -> -1 (reject as before)",
                 peer_eviction_select(c, 2, NOW) == -1);
    }

    /* whitelisted peer is skipped even when the only other candidate
     * would otherwise be protected by relay activity, proving the two
     * exclusions (outbound/whitelisted) are independent of the
     * protection classes. */
    {
        struct peer_eviction_candidate c[2] = {
            { .whitelisted = true, .connected_time = NOW - 5 },
            { .connected_time = NOW - 3 },
        };
        PE_CHECK("whitelisted excluded, sole remaining inbound evicted",
                 peer_eviction_select(c, 2, NOW) == 1);
    }

    /* NULL candidates pointer with nonzero n is treated as empty. */
    PE_CHECK("NULL candidates with n>0 returns -1",
             peer_eviction_select(NULL, 5, NOW) == -1);

    return failures;
}
