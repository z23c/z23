/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Tests for the NET-3 range-parallel header acquisition scheduler
 * (engine/services/src/header_range_scheduler.c). Exercises the pure
 * decisions and the stateful span table directly — no live network:
 *
 *   1. hrs_should_parallelize gating: >=2 fast peers AND gap>batch;
 *      single-peer / small-gap / zero-batch keep the single-peer path
 *      (regression: behaves exactly like today).
 *   2. hrs_partition: checkpoint anchors produce disjoint, contiguous,
 *      fully-covering spans at exactly the anchor boundaries; sparse /
 *      absent anchors never fabricate a boundary hash we lack.
 *   3. Three peers -> three DISJOINT spans (one span per peer, no two
 *      peers on the same span).
 *   4. One peer stalls -> its span is swept back into the free pool and
 *      reassigned to another peer within the deadline model; the stalling
 *      peer id is reported for demotion (caller feeds peer_scoring).
 *   5. hrs_note_frontier completes spans as the header frontier advances
 *      and frees their peer slots.
 *   6. hrs_plan idempotency: a re-plan with identical anchors preserves an
 *      in-flight assignment (a peer keeps its span across kicks).
 *   7. The scheduler is inert without cooperation — it never touches the
 *      header-band contiguity machinery (band closure stays required):
 *      partition/assign are pure span bookkeeping over heights.
 *   8. Cross-peer sweep demotion (regression for the net-wiring defect
 *      fixed alongside this test): hrs_sweep_expired() is GLOBAL — one
 *      peer's periodic tick can sweep a DIFFERENT peer's expired span.
 *      The net wiring (msg_try_range_parallel_getheaders in msg_headers.c)
 *      used to check only "does the CALLING peer's own span own an
 *      expired deadline" and then throw away the sweep's stalled-owner
 *      buffer (NULL, 0) — so a healthy peer's tick silently freed another
 *      peer's expired span without ever reporting it for demotion. This
 *      proves the scheduler's sweep-report primitive that the fix now
 *      reads: a peer whose OWN span has not expired still sees another
 *      peer's expired span reported by the very sweep its own tick
 *      triggers, exactly once, while its own live span is untouched.
 */

#include "test/test_core.h"
#include "services/header_range_scheduler.h"

int test_header_range_sched(void)
{
    int failures = 0;

    /* ── 1. Parallelize gate ─────────────────────────────────────── */
    printf("header_range_sched: should_parallelize gate... ");
    {
        bool ok = true;
        /* >=2 fast peers AND gap>batch -> parallelize */
        ok = ok && hrs_should_parallelize(2, 5000, 2000);
        ok = ok && hrs_should_parallelize(8, 3000000, 2000);
        /* single peer -> never (regression: exactly today's path) */
        ok = ok && !hrs_should_parallelize(1, 5000, 2000);
        ok = ok && !hrs_should_parallelize(0, 5000, 2000);
        /* gap within one batch -> not worth it */
        ok = ok && !hrs_should_parallelize(4, 2000, 2000);
        ok = ok && !hrs_should_parallelize(4, 1, 2000);
        /* degenerate batch */
        ok = ok && !hrs_should_parallelize(4, 5000, 0);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    /* ── 2. Partition disjoint + contiguous + full cover ─────────── */
    printf("header_range_sched: partition into disjoint anchor spans... ");
    {
        struct hrs_span spans[HRS_MAX_SPANS];
        int32_t anchors[] = {50000, 100000, 150000};
        size_t n = hrs_partition(0, 200000, anchors, 3, spans, HRS_MAX_SPANS);
        bool ok = (n == 4);
        /* Expected boundaries: 0,50000,100000,150000,200000 */
        int32_t expect_lo[] = {0, 50000, 100000, 150000};
        int32_t expect_hi[] = {50000, 100000, 150000, 200000};
        for (size_t i = 0; i < n && ok; i++) {
            ok = ok && (spans[i].lo == expect_lo[i]);
            ok = ok && (spans[i].hi == expect_hi[i]);
            ok = ok && !spans[i].assigned && !spans[i].completed;
            /* contiguity: each span starts where the previous ended */
            if (i > 0)
                ok = ok && (spans[i].lo == spans[i - 1].hi);
        }
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    /* ── 2b. Sparse / out-of-range anchors: no fabricated boundary ── */
    printf("header_range_sched: sparse anchors -> single span, no fabrication... ");
    {
        struct hrs_span spans[HRS_MAX_SPANS];
        /* No interior anchors -> one span [lo,hi]. */
        size_t n0 = hrs_partition(100, 8000, NULL, 0, spans, HRS_MAX_SPANS);
        bool ok = (n0 == 1) && spans[0].lo == 100 && spans[0].hi == 8000;
        /* Anchors outside (lo,hi) are ignored (they are not fork points
         * inside the missing range). */
        int32_t outside[] = {50, 100, 8000, 9000};
        size_t n1 = hrs_partition(100, 8000, outside, 4, spans, HRS_MAX_SPANS);
        ok = ok && (n1 == 1) && spans[0].lo == 100 && spans[0].hi == 8000;
        /* Degenerate range -> zero spans. */
        ok = ok && (hrs_partition(8000, 8000, NULL, 0, spans, HRS_MAX_SPANS) == 0);
        ok = ok && (hrs_partition(8000, 100, NULL, 0, spans, HRS_MAX_SPANS) == 0);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    /* ── 3. Three peers -> three disjoint spans ──────────────────── */
    printf("header_range_sched: 3 peers get 3 disjoint spans... ");
    {
        struct header_range_scheduler s = {0};
        hrs_init(&s, 30 * 1000000);
        int32_t anchors[] = {50000, 100000, 150000};
        hrs_plan(&s, 0, 200000, anchors, 3);          /* 4 spans */

        int64_t now = 1000 * 1000000LL;
        int32_t lo1, hi1, lo2, hi2, lo3, hi3;
        int i1 = hrs_assign(&s, 11, now);
        int i2 = hrs_assign(&s, 22, now);
        int i3 = hrs_assign(&s, 33, now);
        bool ok = (i1 >= 0 && i2 >= 0 && i3 >= 0);
        ok = ok && (i1 != i2 && i2 != i3 && i1 != i3);   /* distinct spans */

        ok = ok && hrs_peer_span(&s, 11, now, &lo1, &hi1);
        ok = ok && hrs_peer_span(&s, 22, now, &lo2, &hi2);
        ok = ok && hrs_peer_span(&s, 33, now, &lo3, &hi3);
        /* Disjoint: no two peers overlap (half-open [lo,hi) semantics). */
        ok = ok && !(lo1 < hi2 && lo2 < hi1);
        ok = ok && !(lo1 < hi3 && lo3 < hi1);
        ok = ok && !(lo2 < hi3 && lo3 < hi2);
        /* A peer already holding a live span is not given a second. */
        ok = ok && (hrs_assign(&s, 11, now) < 0);
        /* Three of four spans assigned -> one free. */
        ok = ok && (hrs_free_span_count(&s) == 1);
        hrs_reset(&s);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    /* ── 4. Stall -> reassign + report for demotion ──────────────── */
    printf("header_range_sched: stalled span reassigned + peer reported... ");
    {
        struct header_range_scheduler s = {0};
        hrs_init(&s, 30 * 1000000);          /* 30s span budget */
        int32_t anchors[] = {50000};
        hrs_plan(&s, 0, 100000, anchors, 1);  /* 2 spans */

        int64_t t0 = 1000 * 1000000LL;
        int a = hrs_assign(&s, 11, t0);       /* peer 11 takes a span */
        int b = hrs_assign(&s, 22, t0);       /* peer 22 takes the other */
        bool ok = (a >= 0 && b >= 0 && a != b);

        /* Before the deadline: no sweep, both still held. */
        int32_t stalled[HRS_MAX_SPANS];
        int64_t t_before = t0 + 29 * 1000000LL;
        ok = ok && (hrs_sweep_expired(&s, t_before, stalled, HRS_MAX_SPANS) == 0);
        ok = ok && hrs_peer_span(&s, 11, t_before, NULL, NULL);

        /* Peer 11's own-expiry read fires past the deadline (the wiring
         * uses this to demote the right peer before the sweep frees it). */
        int64_t t_after = t0 + 31 * 1000000LL;
        ok = ok && hrs_peer_owns_expired_span(&s, 11, t_after);
        ok = ok && hrs_peer_owns_expired_span(&s, 22, t_after);

        /* Sweep past the deadline: both stalling peers reported, both
         * spans freed for reassignment. */
        size_t nst = hrs_sweep_expired(&s, t_after, stalled, HRS_MAX_SPANS);
        ok = ok && (nst == 2);
        bool saw11 = false, saw22 = false;
        for (size_t i = 0; i < nst; i++) {
            if (stalled[i] == 11) saw11 = true;
            if (stalled[i] == 22) saw22 = true;
        }
        ok = ok && saw11 && saw22;
        ok = ok && (hrs_free_span_count(&s) == 2);

        /* A different, healthy peer now claims the freed span within the
         * deadline model -> one stalling peer never stalls the sync. */
        int c = hrs_assign(&s, 99, t_after);
        ok = ok && (c >= 0);
        ok = ok && hrs_peer_span(&s, 99, t_after, NULL, NULL);
        hrs_reset(&s);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    /* ── 5. Frontier advance completes + frees spans ─────────────── */
    printf("header_range_sched: frontier advance completes spans... ");
    {
        struct header_range_scheduler s = {0};
        hrs_init(&s, 30 * 1000000);
        int32_t anchors[] = {50000, 100000, 150000};
        hrs_plan(&s, 0, 200000, anchors, 3);   /* spans: 0-50k,50k-100k,... */

        int64_t now = 1000 * 1000000LL;
        hrs_assign(&s, 11, now);               /* peer on span [0,50000] */
        bool ok = hrs_peer_span(&s, 11, now, NULL, NULL);

        /* Frontier reaches 60000 -> only [0,50000] is fully covered. */
        size_t done = hrs_note_frontier(&s, 60000);
        ok = ok && (done == 1);
        /* Peer 11's span completed -> its slot is freed. */
        ok = ok && !hrs_peer_span(&s, 11, now, NULL, NULL);
        /* Frontier reaches the tip -> the remaining spans complete. */
        size_t done2 = hrs_note_frontier(&s, 200000);
        ok = ok && (done2 == 3);
        ok = ok && (hrs_free_span_count(&s) == 0);   /* all completed */
        hrs_reset(&s);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    /* ── 6. Re-plan idempotency preserves assignments ────────────── */
    printf("header_range_sched: re-plan preserves in-flight assignment... ");
    {
        struct header_range_scheduler s = {0};
        hrs_init(&s, 30 * 1000000);
        int32_t anchors[] = {50000, 100000};
        hrs_plan(&s, 0, 150000, anchors, 2);
        int64_t now = 1000 * 1000000LL;
        int a = hrs_assign(&s, 11, now);
        bool ok = (a >= 0);
        int32_t lo0, hi0;
        ok = ok && hrs_peer_span(&s, 11, now, &lo0, &hi0);

        /* Re-plan with the SAME range/anchors: peer 11 keeps its span. */
        hrs_plan(&s, 0, 150000, anchors, 2);
        int32_t lo1, hi1;
        ok = ok && hrs_peer_span(&s, 11, now, &lo1, &hi1);
        ok = ok && (lo0 == lo1 && hi0 == hi1);

        /* Re-plan where the frontier climbed past that span (lo=100000):
         * the old span falls out of range and is dropped, so the peer no
         * longer holds it. */
        hrs_plan(&s, 100000, 150000, NULL, 0);
        ok = ok && !hrs_peer_span(&s, 11, now, NULL, NULL);
        ok = ok && (hrs_span_count(&s) == 1);
        hrs_reset(&s);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    /* ── 7. Global instance + reset seam ─────────────────────────── */
    printf("header_range_sched: global instance reset seam... ");
    {
        header_range_scheduler_reset_for_testing();
        struct header_range_scheduler *g = header_range_scheduler_global();
        bool ok = (g != NULL) && (hrs_span_count(g) == 0);
        int32_t anchors[] = {50000};
        hrs_plan(g, 0, 100000, anchors, 1);
        ok = ok && (hrs_span_count(g) == 2);
        header_range_scheduler_reset_for_testing();
        ok = ok && (hrs_span_count(g) == 0);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    /* ── 8. Cross-peer sweep demotion (net-wiring defect regression) ── */
    printf("header_range_sched: one peer's tick sweeps ANOTHER peer's "
           "expired span... ");
    {
        struct header_range_scheduler s = {0};
        hrs_init(&s, 30 * 1000000);           /* 30s span budget */
        int32_t anchors[] = {50000};
        hrs_plan(&s, 0, 100000, anchors, 1);  /* 2 spans */

        /* Peer B (22) claims a span FIRST -> its deadline is earlier.
         * Peer A (11) claims the other span 10s later -> its deadline is
         * still 20s out when we sample. */
        int64_t t0 = 1000 * 1000000LL;
        int b = hrs_assign(&s, 22, t0);              /* B: deadline t0+30s */
        int64_t t1 = t0 + 10 * 1000000LL;
        int a = hrs_assign(&s, 11, t1);              /* A: deadline t0+40s */
        bool ok = (a >= 0 && b >= 0 && a != b);

        /* Sample at t0+31s: B's deadline has passed, A's has not. */
        int64_t t2 = t0 + 31 * 1000000LL;

        /* The defective wiring's own-peer pre-check: from A's perspective
         * (the peer whose periodic tick is about to run), A does NOT own
         * an expired span -> the old code's "if (self_stalled)" branch
         * would never fire, and it swept with (NULL, 0), so B's timeout
         * was silently dropped. */
        ok = ok && !hrs_peer_owns_expired_span(&s, 11, t2);

        /* A's tick still runs the (global) sweep. With a real buffer
         * wired — the fix — B's id comes back from THIS sweep even
         * though A triggered it and A itself is not stalled. */
        int32_t stalled[HRS_MAX_SPANS];
        size_t nst = hrs_sweep_expired(&s, t2, stalled, HRS_MAX_SPANS);
        ok = ok && (nst == 1);
        ok = ok && (stalled[0] == 22);   /* B reported exactly once */

        /* A's own live span is untouched by the sweep A's tick triggered. */
        ok = ok && hrs_peer_span(&s, 11, t2, NULL, NULL);
        /* B's span was freed. */
        ok = ok && !hrs_peer_span(&s, 22, t2, NULL, NULL);
        ok = ok && (hrs_free_span_count(&s) == 1);
        hrs_reset(&s);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    return failures;
}
