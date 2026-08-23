/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Tests for the block download manager. */

#include "platform/time_compat.h"
#include "test/test_core.h"
#include "services/gap_fill_service.h"
#include "net/download.h"
#include "sync/sync_state.h"
#include "core/uint256.h"
#include "util/supervisor.h"
#include "validation/main_state.h"
#include <string.h>
#include <stdio.h>
#include <pthread.h>
#include <stdatomic.h>

/* Helper: make a uint256 from a single byte value */
static struct uint256 make_hash(uint8_t v)
{
    struct uint256 h;
    memset(h.data, 0, 32);
    h.data[0] = v;
    h.data[31] = v; /* non-zero in both positions for probe chain testing */
    return h;
}

static _Atomic int g_gap_fill_dispatch_wakes;

static void test_gap_fill_dispatch_wake(void *ctx)
{
    (void)ctx;
    atomic_fetch_add(&g_gap_fill_dispatch_wakes, 1);
}

static int test_dl_init_free(void)
{
    int failures = 0;
    TEST("dl_init and dl_free") {
        struct download_manager dm;
        dl_init(&dm);
        ASSERT(dm.num_slots > 0);
        ASSERT(dm.num_active == 0);
        ASSERT(dm.queue_len == 0);
        dl_free(&dm);
        ASSERT(dm.slots == NULL);
        ASSERT(dm.queue == NULL);
        PASS();
    } _test_next:;
    return failures;
}

static int test_dl_mark_requested(void)
{
    int failures = 0;
    TEST("dl_mark_requested basic") {
        struct download_manager dm;
        dl_init(&dm);

        struct uint256 h1 = make_hash(1);
        struct uint256 h2 = make_hash(2);

        ASSERT(dl_mark_requested(&dm, &h1, 100, 1));
        ASSERT(dl_is_in_flight(&dm, &h1));
        ASSERT(!dl_is_in_flight(&dm, &h2));

        ASSERT(dl_mark_requested(&dm, &h2, 101, 2));
        ASSERT(dl_is_in_flight(&dm, &h2));

        /* Duplicate request rejected */
        ASSERT(!dl_mark_requested(&dm, &h1, 100, 3));

        uint64_t req, recv, tout, inflight, queued;
        dl_get_stats(&dm, &req, &recv, &tout, &inflight, &queued);
        ASSERT(req == 2);
        ASSERT(inflight == 2);

        dl_free(&dm);
        PASS();
    } _test_next:;
    return failures;
}

static int test_dl_mark_received(void)
{
    int failures = 0;
    TEST("dl_mark_received removes from in-flight") {
        struct download_manager dm;
        dl_init(&dm);

        struct uint256 h1 = make_hash(1);
        struct uint256 h2 = make_hash(2);
        struct uint256 h3 = make_hash(3);

        dl_mark_requested(&dm, &h1, 100, 1);
        dl_mark_requested(&dm, &h2, 101, 1);
        dl_mark_requested(&dm, &h3, 102, 2);

        /* Receive h2 */
        uint32_t peer = dl_mark_received(&dm, &h2);
        ASSERT(peer == 1);
        ASSERT(!dl_is_in_flight(&dm, &h2));
        ASSERT(dl_is_in_flight(&dm, &h1));
        ASSERT(dl_is_in_flight(&dm, &h3));

        /* Receive unknown hash */
        struct uint256 h4 = make_hash(4);
        ASSERT(dl_mark_received(&dm, &h4) == 0);

        uint64_t req, recv, tout, inflight, queued;
        dl_get_stats(&dm, &req, &recv, &tout, &inflight, &queued);
        ASSERT(recv == 1);
        ASSERT(inflight == 2);

        dl_free(&dm);
        PASS();
    } _test_next:;
    return failures;
}

static int test_dl_queue_dedup(void)
{
    int failures = 0;
    TEST("dl_queue_blocks deduplicates") {
        struct download_manager dm;
        dl_init(&dm);

        struct uint256 hashes[5];
        int32_t heights[5];
        for (int i = 0; i < 5; i++) {
            hashes[i] = make_hash((uint8_t)(10 + i));
            heights[i] = 200 + i;
        }

        /* Queue 5 blocks */
        size_t added = dl_queue_blocks(&dm, hashes, heights, 5);
        ASSERT(added == 5);

        /* Queue same 5 again — should add 0 */
        added = dl_queue_blocks(&dm, hashes, heights, 5);
        ASSERT(added == 0);

        /* Mark one as in-flight, then try to queue it */
        dl_mark_requested(&dm, &hashes[0], 200, 1);
        added = dl_queue_blocks(&dm, hashes, heights, 5);
        ASSERT(added == 0); /* all either queued or in-flight */

        uint64_t req, recv, tout, inflight, queued;
        dl_get_stats(&dm, &req, &recv, &tout, &inflight, &queued);
        ASSERT(queued == 4); /* 5 queued minus 1 moved to in-flight */
        ASSERT(inflight == 1);

        dl_free(&dm);
        PASS();
    } _test_next:;
    return failures;
}

static int test_dl_assign_to_peer(void)
{
    int failures = 0;
    TEST("dl_assign_to_peer pulls from queue") {
        struct download_manager dm;
        dl_init(&dm);

        struct uint256 hashes[10];
        int32_t heights[10];
        for (int i = 0; i < 10; i++) {
            hashes[i] = make_hash((uint8_t)(20 + i));
            heights[i] = 300 + i;
        }

        dl_queue_blocks(&dm, hashes, heights, 10);

        struct uint256 out[5];
        size_t assigned = dl_assign_to_peer(&dm, 1, out, 5);
        ASSERT(assigned == 5);
        struct dl_diagnostics diag;
        dl_get_diagnostics(&dm, &diag);
        ASSERT(diag.assign_attempts == 1);
        ASSERT(diag.assign_successes == 1);
        ASSERT(diag.assign_zero_results == 0);
        ASSERT(diag.last_assign_peer_id == 1);
        ASSERT(diag.last_assign_max_requested == 5);
        ASSERT(diag.last_assign_available == 5);
        ASSERT(diag.last_assign_assigned == 5);
        ASSERT(diag.last_assign_queue_len == 10);
        ASSERT(diag.last_assign_active == 0);
        ASSERT(diag.last_assign_peer_in_flight == 0);
        ASSERT(diag.last_assign_peer_limit >= 5);
        ASSERT(diag.last_assign_global_limit >= 5);
        ASSERT(diag.last_assign_result == DL_ASSIGN_ASSIGNED);
        ASSERT(strcmp(dl_assign_result_name(diag.last_assign_result),
                      "assigned") == 0);

        /* First 5 should be in-flight for peer 1 */
        ASSERT(dl_peer_in_flight(&dm, 1) == 5);

        /* Queue should have 5 remaining */
        uint64_t req, recv, tout, inflight, queued;
        dl_get_stats(&dm, &req, &recv, &tout, &inflight, &queued);
        ASSERT(queued == 5);
        ASSERT(inflight == 5);

        /* Assign 5 more to peer 2 */
        assigned = dl_assign_to_peer(&dm, 2, out, 5);
        ASSERT(assigned == 5);
        ASSERT(dl_peer_in_flight(&dm, 2) == 5);

        /* Queue empty now */
        dl_get_stats(&dm, &req, &recv, &tout, &inflight, &queued);
        ASSERT(queued == 0);
        ASSERT(inflight == 10);

        assigned = dl_assign_to_peer(&dm, 3, out, 5);
        ASSERT(assigned == 0);
        dl_get_diagnostics(&dm, &diag);
        ASSERT(diag.assign_attempts == 3);
        ASSERT(diag.assign_successes == 2);
        ASSERT(diag.assign_zero_results == 1);
        ASSERT(diag.last_assign_peer_id == 3);
        ASSERT(diag.last_assign_queue_len == 0);
        ASSERT(diag.last_assign_assigned == 0);
        ASSERT(diag.last_assign_result == DL_ASSIGN_NO_QUEUE);
        ASSERT(strcmp(dl_assign_result_name(diag.last_assign_result),
                      "no_queue") == 0);

        dl_free(&dm);
        PASS();
    } _test_next:;
    return failures;
}

static int test_dl_assignment_generation_parking(void)
{
    int failures = 0;
    TEST("zero assignment parks until manager dependency generation changes") {
        struct download_manager dm;
        dl_init(&dm);
        struct uint256 out[1];
        struct dl_diagnostics diag;

        ASSERT(dl_assignment_should_attempt(&dm, 7));
        ASSERT(dl_assign_to_peer(&dm, 7, out, 1) == 0);
        dl_get_diagnostics(&dm, &diag);
        ASSERT(diag.assign_attempts == 1);
        ASSERT(diag.assign_zero_results == 1);
        ASSERT(diag.last_assign_result == DL_ASSIGN_NO_QUEUE);

        /* Both the cheap preflight and the defensive direct-call check stay
         * parked. A 100 ms message-pump loop can no longer inflate actual
         * assignment attempts while the queue/window state is unchanged. */
        ASSERT(!dl_assignment_should_attempt(&dm, 7));
        ASSERT(dl_assign_to_peer(&dm, 7, out, 1) == 0);
        dl_get_diagnostics(&dm, &diag);
        ASSERT(diag.assign_attempts == 1);
        ASSERT(diag.assign_zero_results == 1);

        /* Capacity movement is irrelevant to a peer parked because there is
         * no queued work; a receipt must not wake every empty-queue peer. */
        struct uint256 unrelated = make_hash(92);
        ASSERT(dl_mark_requested(&dm, &unrelated, 899, 8));
        ASSERT(dl_mark_received(&dm, &unrelated) == 8);
        ASSERT(!dl_assignment_should_attempt(&dm, 7));

        struct uint256 h = make_hash(93);
        int32_t height = 900;
        ASSERT(dl_queue_blocks(&dm, &h, &height, 1) == 1);
        dl_get_diagnostics(&dm, &diag);
        uint64_t queue_generation = diag.queue_generation;
        dl_queue_priority(&dm, &h, height);
        dl_get_diagnostics(&dm, &diag);
        ASSERT(diag.queue_generation == queue_generation);
        ASSERT(dl_assignment_should_attempt(&dm, 7));
        ASSERT(dl_assign_to_peer(&dm, 7, out, 1) == 1);
        ASSERT(uint256_eq(&out[0], &h));

        dl_free(&dm);
        PASS();
    } _test_next:;
    return failures;
}

static int test_dl_assignment_parking_is_per_peer(void)
{
    int failures = 0;
    TEST("full peer parks while another peer remains eligible") {
        struct download_manager dm;
        dl_init(&dm);

        struct uint256 hashes[DL_MAX_IN_FLIGHT_PER_PEER + 1];
        int32_t heights[DL_MAX_IN_FLIGHT_PER_PEER + 1];
        for (size_t i = 0; i < DL_MAX_IN_FLIGHT_PER_PEER + 1; i++) {
            hashes[i] = make_hash((uint8_t)(i + 1));
            hashes[i].data[1] = (uint8_t)(i >> 8);
            heights[i] = 1000 + (int32_t)i;
        }
        ASSERT(dl_queue_blocks(&dm, hashes, heights,
                               DL_MAX_IN_FLIGHT_PER_PEER + 1) ==
               DL_MAX_IN_FLIGHT_PER_PEER + 1);

        struct uint256 out[DL_MAX_IN_FLIGHT_PER_PEER];
        ASSERT(dl_assign_to_peer(&dm, 11, out,
                                 DL_MAX_IN_FLIGHT_PER_PEER) ==
               DL_MAX_IN_FLIGHT_PER_PEER);
        ASSERT(dl_assign_to_peer(&dm, 11, out, 1) == 0);
        ASSERT(!dl_assignment_should_attempt(&dm, 11));

        /* The generation cache is per peer: peer 12 can immediately take
         * the remaining body instead of being suppressed behind peer 11. */
        ASSERT(dl_assignment_should_attempt(&dm, 12));
        ASSERT(dl_assign_to_peer(&dm, 12, out, 1) == 1);

        dl_free(&dm);
        PASS();
    } _test_next:;
    return failures;
}

static int test_dl_assignment_peer_cache_capacity_and_reuse(void)
{
    int failures = 0;
    TEST("assignment parking tracks 300 active peers and reuses churn slots") {
        struct download_manager dm;
        dl_init(&dm);

        for (uint32_t peer_id = 1; peer_id <= 300; peer_id++)
            dl_set_peer_loopback(&dm, peer_id, false);
        ASSERT(dm.num_peers == 300);

        struct uint256 out[1];
        ASSERT(dl_assignment_should_attempt(&dm, 301));
        ASSERT(dl_assign_to_peer(&dm, 301, out, 1) == 0);
        ASSERT(!dl_assignment_should_attempt(&dm, 301));

        for (uint32_t peer_id = 1; peer_id <= 301; peer_id++)
            ASSERT(dl_peer_disconnected(&dm, peer_id) == 0);
        for (uint32_t peer_id = 302; peer_id <= 700; peer_id++) {
            dl_set_peer_loopback(&dm, peer_id, false);
            ASSERT(dl_peer_disconnected(&dm, peer_id) == 0);
        }
        ASSERT(dm.num_peers <= DL_MAX_TRACKED_PEERS);

        ASSERT(dl_assignment_should_attempt(&dm, 701));
        ASSERT(dl_assign_to_peer(&dm, 701, out, 1) == 0);
        ASSERT(!dl_assignment_should_attempt(&dm, 701));

        dl_free(&dm);
        PASS();
    } _test_next:;
    return failures;
}

static int test_dl_peer_disconnected(void)
{
    int failures = 0;
    TEST("dl_peer_disconnected re-queues blocks") {
        struct download_manager dm;
        dl_init(&dm);

        struct uint256 h1 = make_hash(1);
        struct uint256 h2 = make_hash(2);
        struct uint256 h3 = make_hash(3);

        dl_mark_requested(&dm, &h1, 100, 1);
        dl_mark_requested(&dm, &h2, 101, 1);
        dl_mark_requested(&dm, &h3, 102, 2);

        /* Disconnect peer 1 — h1 and h2 should be re-queued */
        size_t requeued = dl_peer_disconnected(&dm, 1);
        ASSERT(requeued == 2);

        ASSERT(!dl_is_in_flight(&dm, &h1));
        ASSERT(!dl_is_in_flight(&dm, &h2));
        ASSERT(dl_is_in_flight(&dm, &h3)); /* peer 2 still active */

        uint64_t req, recv, tout, inflight, queued;
        dl_get_stats(&dm, &req, &recv, &tout, &inflight, &queued);
        ASSERT(queued == 2);
        ASSERT(inflight == 1);

        /* Assign re-queued blocks to peer 3 */
        struct uint256 out[5];
        size_t assigned = dl_assign_to_peer(&dm, 3, out, 5);
        ASSERT(assigned == 2);

        dl_free(&dm);
        PASS();
    } _test_next:;
    return failures;
}

/* `notfound` names ONE block. It must not cost the peer its whole in-flight
 * window, which is what routing notfound through dl_peer_disconnected() did:
 * on the C3 cold-start stopwatch (one serving peer, 600 s) that turned 35
 * notfound messages into 16899 orphaned requests — 50% of every block request
 * the run made, ~483 per notfound. A single-peer client has no "another peer"
 * to re-ask, so the collateral requeue bought nothing at all. */
static int test_dl_mark_notfound_settles_only_named_block(void)
{
    int failures = 0;
    TEST("notfound requeues only the named block, not the peer's whole window") {
        struct download_manager dm;
        dl_init(&dm);

        struct uint256 h1 = make_hash(1);
        struct uint256 h2 = make_hash(2);
        struct uint256 h3 = make_hash(3);

        dl_mark_requested(&dm, &h1, 100, 1);
        dl_mark_requested(&dm, &h2, 101, 1);
        dl_mark_requested(&dm, &h3, 102, 1);

        /* Peer 1 does not have h2. h1 and h3 stay in flight to peer 1 — the
         * regression this guards is exactly them being thrown away too. */
        ASSERT(dl_mark_notfound(&dm, 1, &h2) == 1);
        ASSERT(dl_is_in_flight(&dm, &h1));
        ASSERT(!dl_is_in_flight(&dm, &h2));
        ASSERT(dl_is_in_flight(&dm, &h3));

        uint64_t req, recv, tout, inflight, queued;
        dl_get_stats(&dm, &req, &recv, &tout, &inflight, &queued);
        ASSERT(inflight == 2);
        ASSERT(queued == 1);

        /* Settled exactly once, so requested-vs-settled stays balanced. */
        struct dl_diagnostics diag;
        dl_get_diagnostics(&dm, &diag);
        ASSERT(diag.total_orphaned == 1);
        ASSERT(diag.accounting_drift == 0);

        /* A notfound naming a block this peer does not hold changes nothing —
         * a stale or hostile notfound must not cancel a live request. */
        ASSERT(dl_mark_notfound(&dm, 2, &h1) == 0);
        ASSERT(dl_is_in_flight(&dm, &h1));
        /* Nor may a repeat of an already-settled block double-count it. */
        ASSERT(dl_mark_notfound(&dm, 1, &h2) == 0);
        dl_get_diagnostics(&dm, &diag);
        ASSERT(diag.total_orphaned == 1);
        ASSERT(diag.accounting_drift == 0);

        /* The one missing block is re-queued and reassignable to another peer. */
        struct uint256 out[4];
        ASSERT(dl_assign_to_peer(&dm, 9, out, 4) == 1);

        dl_free(&dm);
        PASS();
    } _test_next:;
    return failures;
}

/* Every path that takes a request out of flight must settle it (received,
 * timed_out, or orphaned) — a leaked request once satisfied the old
 * requested>settled arm of download_queue_starved forever at tip. */
static int test_dl_settle_accounting(void)
{
    int failures = 0;
    TEST("disconnect and drain settle requests as orphaned, drift stays 0") {
        struct download_manager dm;
        dl_init(&dm);
        struct dl_diagnostics diag;

        struct uint256 h1 = make_hash(1);
        struct uint256 h2 = make_hash(2);
        dl_mark_requested(&dm, &h1, 100, 1);
        dl_mark_requested(&dm, &h2, 101, 1);

        /* Disconnect: both requests settle as orphaned. */
        ASSERT(dl_peer_disconnected(&dm, 1) == 2);
        dl_get_diagnostics(&dm, &diag);
        ASSERT(diag.total_orphaned == 2);
        ASSERT(diag.accounting_drift == 0);

        /* Requeued blocks re-request (total_requested counts them AGAIN)
         * and one completes — the identity must still hold. */
        struct uint256 out[5];
        ASSERT(dl_assign_to_peer(&dm, 3, out, 5) == 2);
        ASSERT(dl_mark_received(&dm, &out[0]) == 3);
        dl_get_diagnostics(&dm, &diag);
        ASSERT(diag.accounting_drift == 0);

        /* Backpressure drain settles the remaining in-flight request. */
        ASSERT(dl_drain_for_backpressure(&dm) == 1);
        dl_get_diagnostics(&dm, &diag);
        ASSERT(diag.total_orphaned == 3);
        ASSERT(diag.accounting_drift == 0);

        uint64_t req, recv, tout, inflight, queued;
        dl_get_stats(&dm, &req, &recv, &tout, &inflight, &queued);
        ASSERT(inflight == 0);
        ASSERT(queued == 0);

        dl_free(&dm);
        PASS();
    } _test_next:;
    return failures;
}

static int test_dl_check_timeouts(void)
{
    int failures = 0;
    TEST("dl_check_timeouts re-queues stale blocks") {
        struct download_manager dm;
        dl_init(&dm);

        struct uint256 h1 = make_hash(1);
        dl_mark_requested(&dm, &h1, 100, 1);

        /* No timeout at current time */
        int64_t now = (int64_t)platform_time_wall_time_t();
        ASSERT(dl_check_timeouts(&dm, now) == 0);
        ASSERT(dl_is_in_flight(&dm, &h1));

        /* Timeout after the current sync-mode request timeout. */
        int timeout = dl_get_request_timeout_secs();
        ASSERT(dl_check_timeouts(&dm, now + timeout + 1) == 1);
        ASSERT(!dl_is_in_flight(&dm, &h1));

        uint64_t req, recv, tout, inflight, queued;
        dl_get_stats(&dm, &req, &recv, &tout, &inflight, &queued);
        ASSERT(tout == 1);
        ASSERT(queued == 1); /* re-queued */
        ASSERT(inflight == 0);

        dl_free(&dm);
        PASS();
    } _test_next:;

    return failures;
}

/* Lane 3 hardening: dl_last_forced_settle_time() is the disambiguation
 * signal msg_blocks.c's PEER_OFFENCE_UNREQUESTED call-site consults —
 * both dl_drain_for_backpressure() and a dl_check_timeouts() reassignment
 * clear an in-flight slot the exact same way a truly-never-requested hash
 * would look, so the call-site withholds scoring for DL_STALL_TIMEOUT_SECS
 * after either event fires. Pin the underlying signal here so a future
 * refactor of drain/timeout internals can't silently stop stamping it. */
static int test_dl_last_forced_settle_time_initial(void)
{
    int failures = 0;
    TEST("dl_last_forced_settle_time: 0 until a drain or timeout reassign fires") {
        struct download_manager dm;
        dl_init(&dm);
        ASSERT(dl_last_forced_settle_time(&dm) == 0);
        ASSERT(dl_last_forced_settle_time(NULL) == 0); /* NULL-safe */
        dl_free(&dm);
        PASS();
    } _test_next:;
    return failures;
}

static int test_dl_last_forced_settle_time_drain(void)
{
    int failures = 0;
    TEST("dl_last_forced_settle_time: stamped by dl_drain_for_backpressure") {
        struct download_manager dm;
        dl_init(&dm);
        struct uint256 h1 = make_hash(1);
        dl_mark_requested(&dm, &h1, 100, 1);

        int64_t before = (int64_t)platform_time_wall_time_t();
        ASSERT(dl_drain_for_backpressure(&dm) == 1);
        int64_t after = (int64_t)platform_time_wall_time_t();

        int64_t stamped = dl_last_forced_settle_time(&dm);
        ASSERT(stamped >= before);
        ASSERT(stamped <= after);

        /* The drain wipes the slot without settling the peer — a late
         * "received" for the same hash looks exactly like an unrequested
         * push (returns 0), which is precisely the ambiguity the grace
         * window exists to cover. */
        ASSERT(dl_mark_received(&dm, &h1) == 0);

        dl_free(&dm);
        PASS();
    } _test_next:;
    return failures;
}

static int test_dl_last_forced_settle_time_timeout(void)
{
    int failures = 0;
    TEST("dl_last_forced_settle_time: stamped by a timeout reassignment") {
        struct download_manager dm;
        dl_init(&dm);
        struct uint256 h1 = make_hash(2);
        dl_mark_requested(&dm, &h1, 200, 1);
        ASSERT(dl_last_forced_settle_time(&dm) == 0);

        int64_t now = (int64_t)platform_time_wall_time_t();
        int timeout = dl_get_request_timeout_secs();
        ASSERT(dl_check_timeouts(&dm, now + timeout + 1) == 1);
        ASSERT(dl_last_forced_settle_time(&dm) >= now);

        /* Same trace as the drain case: the original (slow) peer's late
         * reply, if it ever arrives, is indistinguishable from unsolicited. */
        ASSERT(dl_mark_received(&dm, &h1) == 0);

        dl_free(&dm);
        PASS();
    } _test_next:;
    return failures;
}

static int test_dl_last_forced_settle_time_untouched(void)
{
    int failures = 0;
    TEST("dl_last_forced_settle_time: untouched when nothing times out") {
        struct download_manager dm;
        dl_init(&dm);
        struct uint256 h1 = make_hash(3);
        dl_mark_requested(&dm, &h1, 300, 1);

        int64_t now = (int64_t)platform_time_wall_time_t();
        ASSERT(dl_check_timeouts(&dm, now) == 0); /* nothing stale yet */
        ASSERT(dl_last_forced_settle_time(&dm) == 0);

        /* A hash genuinely never seen by this download manager still
         * reads as provably unrequested — the grace window only fires
         * around an ACTUAL drain/timeout event. */
        struct uint256 never_asked = make_hash(99);
        ASSERT(dl_mark_received(&dm, &never_asked) == 0);
        ASSERT(dl_last_forced_settle_time(&dm) == 0);

        dl_free(&dm);
        PASS();
    } _test_next:;
    return failures;
}

static int test_dl_timeout_retry_failover(void)
{
    int failures = 0;
    TEST("timeout requeue avoids the same peer and fails over") {
        struct download_manager dm;
        dl_init(&dm);

        struct uint256 h1 = make_hash(4);
        int64_t now = (int64_t)platform_time_wall_time_t();
        int timeout = dl_get_request_timeout_secs();
        ASSERT(dl_mark_requested(&dm, &h1, 150, 1));
        ASSERT(dl_check_timeouts(&dm, now + timeout + 1) == 1);

        struct dl_diagnostics diag;
        dl_get_diagnostics(&dm, &diag);
        ASSERT(diag.queue_peer_avoid_count == 1);
        ASSERT(diag.queue_peer_avoid_max_seconds > 0);

        struct uint256 out[1];
        ASSERT(dl_assign_to_peer(&dm, 1, out, 1) == 0);
        dl_get_diagnostics(&dm, &diag);
        ASSERT(diag.last_assign_result == DL_ASSIGN_PEER_AVOID_COOLDOWN);
        ASSERT(!dl_assignment_should_attempt(&dm, 1));
        ASSERT(strcmp(dl_assign_result_name(diag.last_assign_result),
                      "peer_avoid_cooldown") == 0);

        uint64_t queued = 0;
        dl_get_stats(&dm, NULL, NULL, NULL, NULL, &queued);
        ASSERT(queued == 1);

        ASSERT(dl_assign_to_peer(&dm, 2, out, 1) == 1);
        ASSERT(uint256_eq(&out[0], &h1));
        ASSERT(dl_is_in_flight(&dm, &h1));

        dl_free(&dm);
        PASS();
    } _test_next:;
    return failures;
}

static int test_dl_timeout_retry_failover_peer_zero(void)
{
    int failures = 0;
    TEST("timeout requeue avoids peer zero and fails over") {
        struct download_manager dm;
        dl_init(&dm);

        struct uint256 h1 = make_hash(6);
        int64_t now = (int64_t)platform_time_wall_time_t();
        int timeout = dl_get_request_timeout_secs();
        ASSERT(dl_mark_requested(&dm, &h1, 152, 0));
        ASSERT(dl_check_timeouts(&dm, now + timeout + 1) == 1);

        struct dl_diagnostics diag;
        dl_get_diagnostics(&dm, &diag);
        ASSERT(diag.queue_peer_avoid_count == 1);
        ASSERT(diag.queue_peer_avoid_max_seconds > 0);

        struct uint256 out[1];
        ASSERT(dl_assign_to_peer(&dm, 0, out, 1) == 0);
        dl_get_diagnostics(&dm, &diag);
        ASSERT(diag.last_assign_result == DL_ASSIGN_PEER_AVOID_COOLDOWN);

        uint64_t queued = 0;
        dl_get_stats(&dm, NULL, NULL, NULL, NULL, &queued);
        ASSERT(queued == 1);

        ASSERT(dl_assign_to_peer(&dm, 2, out, 1) == 1);
        ASSERT(uint256_eq(&out[0], &h1));
        ASSERT(dl_is_in_flight(&dm, &h1));

        dl_free(&dm);
        PASS();
    } _test_next:;
    return failures;
}

static int test_dl_timeout_retry_avoid_expiry(void)
{
    int failures = 0;
    TEST("same peer retry resumes after avoid cooldown expires") {
        struct download_manager dm;
        dl_init(&dm);

        struct uint256 h1 = make_hash(5);
        int64_t now = (int64_t)platform_time_wall_time_t();
        int timeout = dl_get_request_timeout_secs();
        ASSERT(dl_mark_requested(&dm, &h1, 151, 1));
        ASSERT(dl_check_timeouts(&dm, now + timeout + 1) == 1);

        struct uint256 out[1];
        ASSERT(dl_assign_to_peer(&dm, 1, out, 1) == 0);
        ASSERT(!dl_assignment_should_attempt(&dm, 1));

        zcl_mutex_lock(&dm.cs);
        ASSERT(dm.queue_len == 1);
        dm.queue_avoid_until[0] = now - 1;
        bool found_peer = false;
        for (size_t i = 0; i < dm.num_peers; i++) {
            if (dm.peers[i].peer_id != 1)
                continue;
            dm.peers[i].zero_assign_retry_after = now - 1;
            found_peer = true;
            break;
        }
        zcl_mutex_unlock(&dm.cs);
        ASSERT(found_peer);

        ASSERT(dl_assignment_should_attempt(&dm, 1));
        ASSERT(dl_assign_to_peer(&dm, 1, out, 1) == 1);
        ASSERT(uint256_eq(&out[0], &h1));

        dl_free(&dm);
        PASS();
    } _test_next:;
    return failures;
}

static int test_dl_peer_body_progress(void)
{
    int failures = 0;
    TEST("dl_peer_body_progress reports per-peer requested/received/timeouts") {
        struct download_manager dm;
        dl_init(&dm);

        uint64_t req = 9, recv = 9, to = 9;
        /* Untracked peer zeroes every out-pointer. */
        dl_peer_body_progress(&dm, 42, &req, &recv, &to);
        ASSERT(req == 0 && recv == 0 && to == 0);

        /* Assign two bodies to peer 7; both time out unfilled (the stalling
         * peer the body-stall discipline must fail over from). */
        struct uint256 h1 = make_hash(21);
        struct uint256 h2 = make_hash(22);
        int64_t now = (int64_t)platform_time_wall_time_t();
        int timeout = dl_get_request_timeout_secs();
        ASSERT(dl_mark_requested(&dm, &h1, 100, 7));
        ASSERT(dl_mark_requested(&dm, &h2, 101, 7));
        ASSERT(dl_check_timeouts(&dm, now + timeout + 1) == 2);

        dl_peer_body_progress(&dm, 7, &req, &recv, &to);
        ASSERT(req == 2);   /* two block getdata slots assigned */
        ASSERT(recv == 0);  /* zero bodies delivered */
        ASSERT(to == 2);    /* both requests expired unfilled */

        /* A delivered body is credited to received and clears the deadbeat
         * signal used by the stall predicate. Requeue h1 to a fresh peer 8
         * (h1 avoids peer 7 after the timeout), then deliver it. */
        struct uint256 out[1];
        ASSERT(dl_assign_to_peer(&dm, 8, out, 1) == 1);
        ASSERT(dl_mark_received(&dm, &out[0]) == 8);
        dl_peer_body_progress(&dm, 8, NULL, &recv, NULL);
        ASSERT(recv == 1);

        /* NULL out-pointers are tolerated. */
        dl_peer_body_progress(&dm, 7, NULL, NULL, NULL);
        dl_peer_body_progress(NULL, 7, &req, &recv, &to);
        ASSERT(req == 0 && recv == 0 && to == 0);

        dl_free(&dm);
        PASS();
    } _test_next:;
    return failures;
}

static int test_dl_peer_body_staleness(void)
{
    int failures = 0;
    TEST("dl_peer_body_staleness tracks the last-body cursor across going dark") {
        struct download_manager dm;
        dl_init(&dm);

        uint64_t recv = 9, to = 9;
        int64_t last_body = 9;
        /* Untracked peer zeroes every out-pointer. */
        dl_peer_body_staleness(&dm, 42, &recv, &to, &last_body);
        ASSERT(recv == 0 && to == 0 && last_body == 0);

        int64_t before = (int64_t)platform_time_wall_time_t();

        /* Peer 7 delivers one body: assign h1 then mark it received. */
        struct uint256 h1 = make_hash(31);
        ASSERT(dl_mark_requested(&dm, &h1, 200, 7));
        ASSERT(dl_mark_received(&dm, &h1) == 7);

        /* After a delivered body: received > 0 and the body cursor is set
         * to ~now (non-zero, not in the future). */
        dl_peer_body_staleness(&dm, 7, &recv, &to, &last_body);
        int64_t after = (int64_t)platform_time_wall_time_t();
        ASSERT(recv == 1);
        ASSERT(to == 0);
        ASSERT(last_body >= before && last_body <= after);
        int64_t pinned = last_body;

        /* Now the peer goes dark: two further getdata expire unfilled. The
         * body cursor stays pinned at the last delivery — exactly the
         * delivered-then-dark staleness signal Rule D keys on (received
         * stays > 0, so Rule C keeps exempting this peer). */
        struct uint256 h2 = make_hash(32);
        struct uint256 h3 = make_hash(33);
        int64_t now = (int64_t)platform_time_wall_time_t();
        int timeout = dl_get_request_timeout_secs();
        ASSERT(dl_mark_requested(&dm, &h2, 201, 7));
        ASSERT(dl_mark_requested(&dm, &h3, 202, 7));
        ASSERT(dl_check_timeouts(&dm, now + timeout + 1) == 2);

        dl_peer_body_staleness(&dm, 7, &recv, &to, &last_body);
        ASSERT(recv == 1);            /* still 1 — dark after the first body */
        ASSERT(to == 2);              /* two getdata expired unfilled */
        ASSERT(last_body == pinned);  /* cursor did NOT advance while dark */

        /* NULL out-pointers and NULL dm are tolerated. */
        dl_peer_body_staleness(&dm, 7, NULL, NULL, NULL);
        recv = 9; to = 9; last_body = 9;
        dl_peer_body_staleness(NULL, 7, &recv, &to, &last_body);
        ASSERT(recv == 0 && to == 0 && last_body == 0);

        dl_free(&dm);
        PASS();
    } _test_next:;
    return failures;
}

static int test_dl_diagnostics(void)
{
    int failures = 0;
    TEST("dl_get_diagnostics exposes oldest and overdue in-flight request") {
        struct download_manager dm;
        dl_init(&dm);

        struct dl_diagnostics diag;
        dl_get_diagnostics(&dm, &diag);
        ASSERT(diag.request_timeout_seconds == dl_get_request_timeout_secs());
        ASSERT(diag.oldest_in_flight_age_seconds == -1);
        ASSERT(diag.oldest_in_flight_height == -1);
        ASSERT(diag.oldest_in_flight_peer_id == 0);
        ASSERT(diag.overdue_in_flight == 0);
        ASSERT(diag.in_flight_peer_count == 0);
        ASSERT(diag.assign_attempts == 0);
        ASSERT(diag.assign_successes == 0);
        ASSERT(diag.assign_zero_results == 0);
        ASSERT(diag.last_assign_result == DL_ASSIGN_NONE);
        ASSERT(strcmp(dl_assign_result_name(diag.last_assign_result),
                      "none") == 0);

        struct uint256 h1 = make_hash(11);
        struct uint256 h2 = make_hash(12);
        int64_t now = (int64_t)platform_time_wall_time_t();
        int timeout = dl_get_request_timeout_secs();
        ASSERT(dl_mark_requested(&dm, &h1, 200, 7));
        ASSERT(dl_mark_requested(&dm, &h2, 201, 8));

        zcl_mutex_lock(&dm.cs);
        for (size_t i = 0; i < dm.num_slots; i++) {
            if (!dm.slots[i].active)
                continue;
            if (uint256_eq(&dm.slots[i].hash, &h1))
                dm.slots[i].request_time = now - timeout - 5;
            if (uint256_eq(&dm.slots[i].hash, &h2))
                dm.slots[i].request_time = now - 1;
        }
        zcl_mutex_unlock(&dm.cs);

        dl_get_diagnostics(&dm, &diag);
        ASSERT(diag.request_timeout_seconds == timeout);
        ASSERT(diag.oldest_in_flight_age_seconds >= timeout + 5);
        ASSERT(diag.oldest_in_flight_height == 200);
        ASSERT(diag.oldest_in_flight_peer_id == 7);
        ASSERT(diag.overdue_in_flight == 1);
        ASSERT(diag.in_flight_peer_count == 2);

        dl_free(&dm);
        PASS();
    } _test_next:;
    return failures;
}

static int test_gap_fill_timeout_sweep(void)
{
    int failures = 0;
    TEST("gap_fill timeout sweep re-queues stale in-flight blocks") {
        struct download_manager dm;
        dl_init(&dm);

        struct uint256 h1 = make_hash(13);
        int64_t now = (int64_t)platform_time_wall_time_t();
        ASSERT(dl_mark_requested(&dm, &h1, 300, 9));

        int timeout = dl_get_request_timeout_secs();
        size_t requeued =
            gap_fill_sweep_download_timeouts(&dm, now + timeout + 1);
        ASSERT(requeued == 1);

        uint64_t req, recv, tout, inflight, queued;
        dl_get_stats(&dm, &req, &recv, &tout, &inflight, &queued);
        ASSERT(req == 1);
        ASSERT(recv == 0);
        ASSERT(tout == 1);
        ASSERT(inflight == 0);
        ASSERT(queued == 1);
        ASSERT(!dl_is_in_flight(&dm, &h1));

        dl_free(&dm);
        PASS();
    } _test_next:;
    return failures;
}

static int test_gap_fill_timeout_wakes_dispatcher(void)
{
    int failures = 0;
    TEST("gap_fill timeout pass wakes network dispatcher") {
        bool ok = true;
        supervisor_reset_for_testing();

        struct main_state ms;
        main_state_init(&ms);
        struct download_manager dm;
        dl_init(&dm);

        struct uint256 h1 = make_hash(14);
        int64_t now = (int64_t)platform_time_wall_time_t();
        int timeout = dl_get_request_timeout_secs();
        ok = ok && dl_mark_requested(&dm, &h1, 301, 10);

        zcl_mutex_lock(&dm.cs);
        for (size_t i = 0; i < dm.num_slots; i++) {
            if (dm.slots[i].active && uint256_eq(&dm.slots[i].hash, &h1))
                dm.slots[i].request_time = now - timeout - 1;
        }
        zcl_mutex_unlock(&dm.cs);

        atomic_store(&g_gap_fill_dispatch_wakes, 0);
        gap_fill_set_dispatch_wake(test_gap_fill_dispatch_wake, NULL);
        struct zcl_result r = gap_fill_start(&ms, &dm);
        ok = ok && r.ok;
        if (r.ok) {
            for (int i = 0; i < 50 &&
                 atomic_load(&g_gap_fill_dispatch_wakes) == 0; i++) {
                struct timespec ts = { .tv_sec = 0,
                                       .tv_nsec = 20 * 1000 * 1000 };
                nanosleep(&ts, NULL);
            }
            gap_fill_stop();
        }

        uint64_t inflight = 0, queued = 0, timed_out = 0;
        dl_get_stats(&dm, NULL, NULL, &timed_out, &inflight, &queued);
        ok = ok && atomic_load(&g_gap_fill_dispatch_wakes) > 0;
        ok = ok && timed_out == 1;
        ok = ok && inflight == 0;
        ok = ok && queued == 1;

        dl_free(&dm);
        main_state_free(&ms);
        supervisor_reset_for_testing();
        ASSERT(ok);
        PASS();
    } _test_next:;
    return failures;
}

static int test_gap_fill_queued_idle_wakes_dispatcher(void)
{
    int failures = 0;
    TEST("gap_fill queued idle work wakes network dispatcher") {
        struct download_manager dm;
        dl_init(&dm);

        struct uint256 h1 = make_hash(15);
        int32_t h1_height = 401;
        ASSERT(dl_queue_blocks(&dm, &h1, &h1_height, 1) == 1);

        atomic_store(&g_gap_fill_dispatch_wakes, 0);
        gap_fill_set_dispatch_wake(test_gap_fill_dispatch_wake, NULL);
        ASSERT(gap_fill_wake_dispatch_if_idle(&dm, "unit_queued_idle"));
        ASSERT(atomic_load(&g_gap_fill_dispatch_wakes) == 1);

        struct uint256 h2 = make_hash(16);
        ASSERT(dl_mark_requested(&dm, &h2, 402, 2));
        ASSERT(!gap_fill_wake_dispatch_if_idle(&dm,
                                               "unit_queued_not_idle"));
        ASSERT(atomic_load(&g_gap_fill_dispatch_wakes) == 1);

        gap_fill_set_dispatch_wake(NULL, NULL);
        dl_free(&dm);
        PASS();
    } _test_next:;
    return failures;
}

static int test_dl_many_insertions(void)
{
    int failures = 0;
    TEST("dl hash table handles many insertions and deletions") {
        struct download_manager dm;
        dl_init(&dm);

        /* Insert 500 blocks */
        for (int i = 0; i < 500; i++) {
            struct uint256 h = make_hash((uint8_t)(i & 0xFF));
            h.data[1] = (uint8_t)(i >> 8);
            dl_mark_requested(&dm, &h, i, (uint32_t)(i % 10));
        }

        uint64_t req, recv, tout, inflight, queued;
        dl_get_stats(&dm, &req, &recv, &tout, &inflight, &queued);
        ASSERT(inflight == 500);

        /* Receive half */
        for (int i = 0; i < 250; i++) {
            struct uint256 h = make_hash((uint8_t)(i & 0xFF));
            h.data[1] = (uint8_t)(i >> 8);
            dl_mark_received(&dm, &h);
        }

        dl_get_stats(&dm, &req, &recv, &tout, &inflight, &queued);
        ASSERT(recv == 250);
        ASSERT(inflight == 250);

        /* Remaining 250 should still be findable */
        for (int i = 250; i < 500; i++) {
            struct uint256 h = make_hash((uint8_t)(i & 0xFF));
            h.data[1] = (uint8_t)(i >> 8);
            ASSERT(dl_is_in_flight(&dm, &h));
        }

        /* Received ones should NOT be findable */
        for (int i = 0; i < 250; i++) {
            struct uint256 h = make_hash((uint8_t)(i & 0xFF));
            h.data[1] = (uint8_t)(i >> 8);
            ASSERT(!dl_is_in_flight(&dm, &h));
        }

        dl_free(&dm);
        PASS();
    } _test_next:;
    return failures;
}

static void test_dl_force_sync_idle(void)
{
    enum sync_state cur = sync_get_state();
    if (cur == SYNC_IDLE)
        return;
    if (cur == SYNC_AT_TIP) {
        (void)sync_set_state(SYNC_IDLE, "download test cleanup");
        return;
    }
    if (cur == SYNC_REORG) {
        (void)sync_set_state(SYNC_AT_TIP, "download test cleanup");
        (void)sync_set_state(SYNC_IDLE, "download test cleanup");
        return;
    }
    (void)sync_set_state(SYNC_IDLE, "download test cleanup");
}

static void test_dl_force_blocks_download(void)
{
    test_dl_force_sync_idle();
    if (sync_get_state() != SYNC_IDLE)
        return;
    (void)sync_set_state(SYNC_FINDING_PEERS, "download ibd test");
    (void)sync_set_state(SYNC_HEADERS_DOWNLOAD, "download ibd test");
    (void)sync_set_state(SYNC_BLOCKS_DOWNLOAD, "download ibd test");
}

static int test_dl_ibd_windows(void)
{
    int failures = 0;
    TEST("IBD raises per-peer in-flight and request timeout") {
        test_dl_force_sync_idle();
        ASSERT(sync_get_state() == SYNC_IDLE);
        ASSERT(dl_get_max_in_flight_per_peer() == DL_MAX_IN_FLIGHT_PER_PEER);
        ASSERT(dl_get_request_timeout_secs() == DL_REQUEST_TIMEOUT_SECS);
        ASSERT(dl_get_max_in_flight_total() == DL_MAX_IN_FLIGHT_TOTAL);

        test_dl_force_blocks_download();
        ASSERT(sync_get_state() == SYNC_BLOCKS_DOWNLOAD);
        ASSERT(dl_get_max_in_flight_per_peer() == DL_MAX_IN_FLIGHT_PER_PEER_IBD);
        ASSERT(dl_get_request_timeout_secs() == DL_REQUEST_TIMEOUT_SECS_IBD);
        ASSERT(dl_get_max_in_flight_total() == DL_MAX_IN_FLIGHT_TOTAL_IBD);
        ASSERT(DL_MAX_IN_FLIGHT_PER_PEER_IBD > DL_MAX_IN_FLIGHT_PER_PEER);
        ASSERT(DL_REQUEST_TIMEOUT_SECS_IBD > DL_REQUEST_TIMEOUT_SECS);

        struct download_manager dm;
        dl_init(&dm);
        const size_t n = DL_MAX_IN_FLIGHT_PER_PEER_IBD + 8;
        struct uint256 hashes[DL_MAX_IN_FLIGHT_PER_PEER_IBD + 8];
        int32_t heights[DL_MAX_IN_FLIGHT_PER_PEER_IBD + 8];
        struct uint256 out[DL_MAX_IN_FLIGHT_PER_PEER_IBD + 8];
        for (size_t i = 0; i < n; i++) {
            hashes[i] = make_hash((uint8_t)(i + 1));
            hashes[i].data[1] = (uint8_t)(i >> 8);
            heights[i] = 2000 + (int32_t)i;
        }
        ASSERT(dl_queue_blocks(&dm, hashes, heights, n) == n);
        size_t assigned = dl_assign_to_peer(&dm, 3, out, n);
        ASSERT(assigned == DL_MAX_IN_FLIGHT_PER_PEER_IBD);
        ASSERT(dl_peer_in_flight(&dm, 3) == DL_MAX_IN_FLIGHT_PER_PEER_IBD);
        assigned = dl_assign_to_peer(&dm, 3, out, n);
        ASSERT(assigned == 0);
        dl_free(&dm);
        PASS();
    } _test_next:;
    test_dl_force_sync_idle();
    return failures;
}

static int test_dl_per_peer_limit(void)
{
    int failures = 0;
    TEST("dl_assign_to_peer respects per-peer limit") {
        test_dl_force_sync_idle();
        struct download_manager dm;
        dl_init(&dm);

        /* Queue 200 blocks */
        struct uint256 hashes[200];
        int32_t heights[200];
        for (int i = 0; i < 200; i++) {
            hashes[i] = make_hash((uint8_t)(i & 0xFF));
            hashes[i].data[1] = (uint8_t)(i >> 8);
            heights[i] = i;
        }
        dl_queue_blocks(&dm, hashes, heights, 200);

        /* Assign all to peer 1 — should cap at DL_MAX_IN_FLIGHT_PER_PEER */
        struct uint256 out[200];
        size_t assigned = dl_assign_to_peer(&dm, 1, out, 200);
        ASSERT(assigned == DL_MAX_IN_FLIGHT_PER_PEER);
        ASSERT(dl_peer_in_flight(&dm, 1) == DL_MAX_IN_FLIGHT_PER_PEER);

        /* Try to assign more to same peer — should get 0 */
        assigned = dl_assign_to_peer(&dm, 1, out, 200);
        ASSERT(assigned == 0);

        dl_free(&dm);
        PASS();
    } _test_next:;
    return failures;
}

/* Concurrency test: multiple threads hitting the download manager */
struct dl_thread_ctx {
    struct download_manager *dm;
    int thread_id;
    int ops_done;
};

static void *dl_concurrent_worker(void *arg)
{
    struct dl_thread_ctx *ctx = (struct dl_thread_ctx *)arg;
    struct download_manager *dm = ctx->dm;
    int tid = ctx->thread_id;
    int ops = 0;

    /* Each thread works on a unique range of hashes */
    for (int round = 0; round < 10; round++) {
        struct uint256 hashes[20];
        int32_t heights[20];
        for (int i = 0; i < 20; i++) {
            memset(hashes[i].data, 0, 32);
            hashes[i].data[0] = (uint8_t)(tid);
            hashes[i].data[1] = (uint8_t)(round);
            hashes[i].data[2] = (uint8_t)(i);
            heights[i] = tid * 10000 + round * 100 + i;
        }

        /* Queue blocks */
        dl_queue_blocks(dm, hashes, heights, 20);
        ops++;

        /* Assign to self */
        struct uint256 out[20];
        size_t assigned = dl_assign_to_peer(dm, (uint32_t)tid, out, 20);
        ops++;

        /* "Receive" them */
        for (size_t i = 0; i < assigned; i++) {
            dl_mark_received(dm, &out[i]);
            ops++;
        }
    }

    ctx->ops_done = ops;
    return NULL;
}

static int test_dl_concurrent(void)
{
    int failures = 0;
    TEST("download manager concurrent access (4 threads)") {
        struct download_manager dm;
        dl_init(&dm);

        #define DL_NUM_THREADS 4
        pthread_t threads[DL_NUM_THREADS];
        struct dl_thread_ctx ctxs[DL_NUM_THREADS];

        for (int i = 0; i < DL_NUM_THREADS; i++) {
            ctxs[i].dm = &dm;
            ctxs[i].thread_id = i + 1;
            ctxs[i].ops_done = 0;
            pthread_create(&threads[i], NULL, dl_concurrent_worker, &ctxs[i]);
        }

        for (int i = 0; i < DL_NUM_THREADS; i++)
            pthread_join(threads[i], NULL);

        /* Verify all threads completed */
        for (int i = 0; i < DL_NUM_THREADS; i++)
            ASSERT(ctxs[i].ops_done > 0);

        /* Verify stats are consistent: received <= requested, no negative */
        uint64_t req, recv, tout, inflight, queued;
        dl_get_stats(&dm, &req, &recv, &tout, &inflight, &queued);
        ASSERT(recv <= req);

        dl_free(&dm);
        PASS();
    } _test_next:;
    return failures;
}

static int test_dl_byte_tracking(void)
{
    int failures = 0;
    TEST("dl_add_bytes_received tracks total bytes") {
        struct download_manager dm;
        dl_init(&dm);

        /* Initially zero */
        uint64_t total_bytes = 0;
        double mbps = 0.0;
        dl_get_throughput(&dm, &total_bytes, &mbps);
        ASSERT(total_bytes == 0);
        ASSERT(mbps == 0.0);

        /* Record some block bytes */
        dl_add_bytes_received(&dm, 1048576);  /* 1 MB */
        dl_add_bytes_received(&dm, 524288);   /* 0.5 MB */
        dl_add_bytes_received(&dm, 2097152);  /* 2 MB */

        dl_get_throughput(&dm, &total_bytes, &mbps);
        ASSERT(total_bytes == 3670016);  /* 3.5 MB total */
        /* mbps > 0 since sync_start_time was set on first call */
        ASSERT(mbps >= 0.0);

        /* Verify sync_start_time was set */
        ASSERT(dm.sync_start_time > 0);

        dl_free(&dm);
        PASS();
    } _test_next:;
    return failures;
}

static int test_dl_byte_tracking_before_sync(void)
{
    int failures = 0;
    TEST("dl_get_throughput returns 0 before any bytes received") {
        struct download_manager dm;
        dl_init(&dm);

        uint64_t total_bytes = 99;
        double mbps = 99.0;
        dl_get_throughput(&dm, &total_bytes, &mbps);
        ASSERT(total_bytes == 0);
        ASSERT(mbps == 0.0);

        /* sync_start_time should not be set */
        ASSERT(dm.sync_start_time == 0);

        dl_free(&dm);
        PASS();
    } _test_next:;
    return failures;
}

static int test_dl_byte_tracking_large(void)
{
    int failures = 0;
    TEST("dl_add_bytes_received handles 11 GB (realistic sync)") {
        struct download_manager dm;
        dl_init(&dm);

        /* Simulate receiving ~11 GB in 1000-block chunks (~3.6 KB avg) */
        uint64_t expected_total = 0;
        for (int i = 0; i < 3000000; i += 1000) {
            uint64_t chunk_bytes = 3600 * 1000; /* ~3.6 MB per 1000 blocks */
            dl_add_bytes_received(&dm, chunk_bytes);
            expected_total += chunk_bytes;
        }

        uint64_t total_bytes = 0;
        double mbps = 0.0;
        dl_get_throughput(&dm, &total_bytes, &mbps);
        ASSERT(total_bytes == expected_total);
        /* ~10.8 GB */
        ASSERT(total_bytes > 10ULL * 1024 * 1024 * 1024);

        dl_free(&dm);
        PASS();
    } _test_next:;
    return failures;
}

static int test_dl_null_throughput_params(void)
{
    int failures = 0;
    TEST("dl_get_throughput handles NULL params") {
        struct download_manager dm;
        dl_init(&dm);

        dl_add_bytes_received(&dm, 1000);

        /* Should not crash with NULL params */
        dl_get_throughput(&dm, NULL, NULL);

        uint64_t total = 0;
        dl_get_throughput(&dm, &total, NULL);
        ASSERT(total == 1000);

        double mbps = 0;
        dl_get_throughput(&dm, NULL, &mbps);
        ASSERT(mbps >= 0.0);

        dl_free(&dm);
        PASS();
    } _test_next:;
    return failures;
}

/* Make a uint256 from a 16-bit value (for >256 distinct hashes). */
static struct uint256 make_hash16(uint16_t v)
{
    struct uint256 h;
    memset(h.data, 0, 32);
    h.data[0] = (uint8_t)(v & 0xFF);
    h.data[1] = (uint8_t)(v >> 8);
    h.data[31] = 0xAB; /* non-zero tail for probe-chain robustness */
    return h;
}

/* REGRESSION: the live wedge. gap_fill builds its window highest-first
 * and tail-appends, so the connectable bottom (tip+1) lands at the TAIL
 * of a deep FIFO queue while far-ahead live blocks saturate the front.
 * With strict FIFO, dl_assign_to_peer never reaches the bottom → the
 * tip-advancing body is perpetually starved → permanent wedge.
 *
 * The fix keeps the queue height-sorted, so dl_assign_to_peer always
 * hands out the LOWEST-height block first regardless of enqueue order.
 * This test reproduces the starvation layout and asserts the bottom is
 * NOT starved. */
static int test_dl_lowest_height_first(void)
{
    int failures = 0;
    TEST("dl_assign_to_peer hands out lowest height first (anti-starvation)") {
        struct download_manager dm;
        dl_init(&dm);

        /* Enqueue far-ahead blocks FIRST (heights 3127000..3127999),
         * exactly as a saturated front would look. */
        const int FAR_N = 1000;
        for (int i = 0; i < FAR_N; i++) {
            struct uint256 h = make_hash16((uint16_t)(2000 + i));
            int32_t height = 3127000 + i;
            dl_queue_blocks(&dm, &h, &height, 1);
        }

        /* Now enqueue the connectable bottom LAST (the tip+1 block at
         * height 3125315) — the one block that advances the tip. This is
         * the tail of the FIFO under the old behavior. */
        struct uint256 bottom = make_hash16(1);
        int32_t bottom_h = 3125315;
        dl_queue_blocks(&dm, &bottom, &bottom_h, 1);

        uint64_t req, recv, tout, inflight, queued;
        dl_get_stats(&dm, &req, &recv, &tout, &inflight, &queued);
        ASSERT(queued == (uint64_t)(FAR_N + 1));

        /* Assign a single block to a peer. It MUST be the connectable
         * bottom (lowest height), not a far-ahead block. Under the old
         * FIFO this returned the height-3127000 block and the bottom
         * stayed starved at the tail. */
        struct uint256 out[1];
        size_t assigned = dl_assign_to_peer(&dm, 1, out, 1);
        ASSERT(assigned == 1);
        ASSERT(uint256_eq(&out[0], &bottom)); /* lowest height wins */

        dl_free(&dm);
        PASS();
    } _test_next:;
    return failures;
}

/* The bottom must win even when it is appended into the MIDDLE of an
 * already-deep queue and via multiple enqueue paths (blocks + priority
 * + timeout requeue). All paths funnel through the sorted insert. */
static int test_dl_sorted_across_paths(void)
{
    int failures = 0;
    TEST("queue stays height-sorted across blocks/priority/timeout paths") {
        struct download_manager dm;
        dl_init(&dm);

        /* A deep spread of high heights. */
        for (int i = 0; i < 300; i++) {
            struct uint256 h = make_hash16((uint16_t)(5000 + i));
            int32_t height = 3126000 + i * 3;
            dl_queue_blocks(&dm, &h, &height, 1);
        }

        /* A mid-range block via the priority path. */
        struct uint256 mid = make_hash16(40);
        dl_queue_priority(&dm, &mid, 3125900);

        /* The connectable bottom via a plain enqueue, after everything. */
        struct uint256 bottom = make_hash16(41);
        int32_t bottom_h = 3125315;
        dl_queue_blocks(&dm, &bottom, &bottom_h, 1);

        /* Simulate a timeout requeue of a low block: mark in-flight then
         * time it out so it re-enters the queue via dl_queue_push. */
        struct uint256 reto = make_hash16(42);
        dl_mark_requested(&dm, &reto, 3125316, 7);
        int64_t now = (int64_t)platform_time_wall_time_t();
        ASSERT(dl_check_timeouts(&dm, now + DL_REQUEST_TIMEOUT_SECS + 1) == 1);

        /* Drain a handful and assert heights come out monotonically
         * non-decreasing, with the bottom (3125315) first. */
        struct uint256 out[8];
        size_t got = dl_assign_to_peer(&dm, 1, out, 8);
        ASSERT(got == 8);
        ASSERT(uint256_eq(&out[0], &bottom)); /* 3125315 is the global min */
        ASSERT(uint256_eq(&out[1], &reto));   /* 3125316 next */

        dl_free(&dm);
        PASS();
    } _test_next:;
    return failures;
}

/* Unknown-height (-1) blocks must sort to the BACK so they never preempt
 * a known tip-adjacent block. */
static int test_dl_unknown_height_sorts_last(void)
{
    int failures = 0;
    TEST("unknown-height (-1) blocks never preempt known low heights") {
        struct download_manager dm;
        dl_init(&dm);

        struct uint256 unk = make_hash16(100);
        int32_t unk_h = -1;
        dl_queue_blocks(&dm, &unk, &unk_h, 1); /* enqueued first */

        struct uint256 low = make_hash16(101);
        int32_t low_h = 3125315;
        dl_queue_blocks(&dm, &low, &low_h, 1); /* enqueued second */

        struct uint256 out[1];
        size_t got = dl_assign_to_peer(&dm, 1, out, 1);
        ASSERT(got == 1);
        ASSERT(uint256_eq(&out[0], &low)); /* known low beats unknown */

        dl_free(&dm);
        PASS();
    } _test_next:;
    return failures;
}

static int test_dl_history_lane_is_bounded_and_forward_wins(void)
{
    int failures = 0;
    TEST("history lane is bounded and saturated history cannot delay forward work") {
        struct download_manager dm;
        dl_init(&dm);

        struct uint256 history[40];
        int32_t history_heights[40];
        for (int i = 0; i < 40; i++) {
            history[i] = make_hash16((uint16_t)(8000 + i));
            history_heights[i] = 100 + i;
        }
        ASSERT(dl_queue_blocks_class(&dm, history, history_heights, 40,
                                     DL_WORK_HISTORY) == 40);

        /* Eight peers fill exactly 16 global history slots, two apiece. */
        struct uint256 out[4];
        for (uint32_t peer = 1; peer <= 8; peer++)
            ASSERT(dl_assign_to_peer(&dm, peer, out, 4) ==
                   DL_MAX_HISTORY_PER_PEER);
        ASSERT(dl_assign_to_peer(&dm, 9, out, 4) == 0);

        struct dl_diagnostics diag;
        dl_get_diagnostics(&dm, &diag);
        ASSERT(diag.in_flight_history == DL_MAX_HISTORY_IN_FLIGHT);
        ASSERT(diag.in_flight_forward == 0);
        ASSERT(diag.queued_history == 24);

        /* A forward hash avoided by this peer must not open a path around the
         * already saturated global history cap. */
        struct uint256 avoided_forward = make_hash16(8999);
        ASSERT(dl_mark_requested(&dm, &avoided_forward, 899999, 9));
        ASSERT(dl_peer_disconnected(&dm, 9) == 1);
        ASSERT(dl_assign_to_peer(&dm, 9, out, 4) == 0);
        dl_get_diagnostics(&dm, &diag);
        ASSERT(diag.in_flight_history == DL_MAX_HISTORY_IN_FLIGHT);
        ASSERT(diag.queued_history == 24);

        /* This peer is parked on the saturated history lane. Enqueuing a
         * forward item must invalidate that practical result even though no
         * history capacity was released, and the next assignment must be the
         * forward item despite its much higher height. */
        struct uint256 forward = make_hash16(9000);
        int32_t forward_height = 900000;
        ASSERT(dl_queue_blocks(&dm, &forward, &forward_height, 1) == 1);
        ASSERT(dl_assignment_should_attempt(&dm, 9));
        ASSERT(dl_assign_to_peer(&dm, 9, out, 4) == 1);
        ASSERT(uint256_eq(&out[0], &forward));

        dl_get_diagnostics(&dm, &diag);
        ASSERT(diag.in_flight_history == DL_MAX_HISTORY_IN_FLIGHT);
        ASSERT(diag.in_flight_forward == 1);
        ASSERT(diag.queued_forward == 1); /* avoided forward remains queued */

        dl_free(&dm);
        PASS();
    } _test_next:;

    return failures;
}

static int test_dl_history_promotion_wakes_parked_peer(void)
{
    int failures = 0;
    TEST("promoting queued history to forward wakes an avoid-parked peer") {
        struct download_manager dm;
        dl_init(&dm);
        struct uint256 hash = make_hash16(9100);
        int32_t height = 123;
        struct uint256 out[1];
        ASSERT(dl_queue_blocks_class(&dm, &hash, &height, 1,
                                     DL_WORK_HISTORY) == 1);
        ASSERT(dl_assign_to_peer(&dm, 7, out, 1) == 1);
        ASSERT(dl_peer_disconnected(&dm, 7) == 1);
        ASSERT(dl_assign_to_peer(&dm, 7, out, 1) == 0);
        ASSERT(!dl_assignment_should_attempt(&dm, 7));

        /* Deduplicated promotion returns zero new hashes, but is still a
         * material queue change and clears history/avoidance policy. */
        ASSERT(dl_queue_blocks(&dm, &hash, &height, 1) == 0);
        ASSERT(dl_assignment_should_attempt(&dm, 7));
        ASSERT(dl_assign_to_peer(&dm, 7, out, 1) == 1);
        ASSERT(uint256_eq(&out[0], &hash));
        struct dl_diagnostics diag;
        dl_get_diagnostics(&dm, &diag);
        ASSERT(diag.in_flight_forward == 1);
        ASSERT(diag.in_flight_history == 0);
        dl_free(&dm);
        PASS();
    } _test_next:;
    return failures;
}

static int test_gap_fill_registers_supervisor_contract(void)
{
    int failures = 0;
    TEST("gap_fill registers a chain supervisor contract") {
        bool ok = true;
        supervisor_reset_for_testing();

        struct main_state ms;
        main_state_init(&ms);
        struct download_manager dm;
        dl_init(&dm);

        struct zcl_result r = gap_fill_start(&ms, &dm);
        ok = ok && r.ok;
        if (r.ok) {
            struct supervisor_snapshot snaps[SUPERVISOR_CAP];
            int n = supervisor_snapshot_all(snaps, SUPERVISOR_CAP);
            const struct supervisor_snapshot *gap = NULL;
            for (int i = 0; i < n; i++) {
                if (strcmp(snaps[i].name, "chain.gap_fill") == 0) {
                    gap = &snaps[i];
                    break;
                }
            }
            ok = ok && gap != NULL;
            if (gap) {
                ok = ok && gap->period_secs == 0;
                ok = ok &&
                    gap->deadline_secs == (int64_t)GAPFILL_TICK_SECS * 3 + 30;
            }

            gap_fill_stop();
            ok = ok && supervisor_child_count_total() == 0;
        }

        dl_free(&dm);
        main_state_free(&ms);
        supervisor_reset_for_testing();
        ASSERT(ok);
        PASS();
    } _test_next:;
    return failures;
}

/* S2.3: a peer with a well-established, much lower bandwidth_score must not
 * claim the tip-adjacent (lowest-height) entries when a demonstrably faster
 * peer is also known — but it must still receive work (bias, not a hard
 * partition; no starvation). */
static int test_dl_tip_bias_prefers_fast_peer(void)
{
    int failures = 0;
    TEST("dl_assign_to_peer defers tip-adjacent entries to the faster peer") {
        struct download_manager dm;
        dl_init(&dm);

        const int N = DL_TIP_BIAS_RESERVE + 32;
        struct uint256 hs[DL_TIP_BIAS_RESERVE + 32];
        for (int i = 0; i < N; i++) {
            hs[i] = make_hash16((uint16_t)(500 + i));
            int32_t height = 1000 + i; /* ascending: hs[0] most urgent */
            dl_queue_blocks(&dm, &hs[i], &height, 1);
        }

        /* Register both peers (creates dl_peer_stats), then set a
         * deterministic bandwidth_score directly via dl_peer_block_received
         * so the bias decision does not depend on wall-clock timing. */
        struct uint256 dummy[1];
        dl_assign_to_peer(&dm, 1 /* fast */, dummy, 0);
        dl_assign_to_peer(&dm, 2 /* slow */, dummy, 0);
        dl_peer_block_received(&dm, 1, 100000);   /* 100ms -> high score */
        dl_peer_block_received(&dm, 2, 4000000);  /* 4s -> low score */

        /* Slow peer asks first. Must NOT get the most tip-adjacent block,
         * and whatever it gets must come from beyond the reserve. */
        struct uint256 slow_out[1];
        ASSERT(dl_assign_to_peer(&dm, 2, slow_out, 1) == 1);
        ASSERT(!uint256_eq(&slow_out[0], &hs[0]));
        int slow_idx = -1;
        for (int i = 0; i < N; i++)
            if (uint256_eq(&slow_out[0], &hs[i])) { slow_idx = i; break; }
        ASSERT(slow_idx >= DL_TIP_BIAS_RESERVE);

        /* Fast peer asks next and must receive the true tip-adjacent blocks
         * the slow peer deferred, in height order. */
        struct uint256 fast_out[4];
        ASSERT(dl_assign_to_peer(&dm, 1, fast_out, 4) == 4);
        ASSERT(uint256_eq(&fast_out[0], &hs[0]));
        ASSERT(uint256_eq(&fast_out[1], &hs[1]));
        ASSERT(uint256_eq(&fast_out[2], &hs[2]));
        ASSERT(uint256_eq(&fast_out[3], &hs[3]));

        dl_free(&dm);
        PASS();
    } _test_next:;
    return failures;
}

/* S2.3: when the queue is too shallow to support a reserve, the slow peer
 * must still receive tip-adjacent work immediately — no starvation. */
static int test_dl_tip_bias_no_starvation_shallow_queue(void)
{
    int failures = 0;
    TEST("slow peer still gets tip-adjacent work when the queue is shallow") {
        struct download_manager dm;
        dl_init(&dm);

        const int N = 5; /* well under DL_TIP_BIAS_RESERVE */
        struct uint256 hs[5];
        for (int i = 0; i < N; i++) {
            hs[i] = make_hash16((uint16_t)(700 + i));
            int32_t height = 2000 + i;
            dl_queue_blocks(&dm, &hs[i], &height, 1);
        }

        struct uint256 dummy[1];
        dl_assign_to_peer(&dm, 1 /* fast */, dummy, 0);
        dl_assign_to_peer(&dm, 2 /* slow */, dummy, 0);
        dl_peer_block_received(&dm, 1, 100000);
        dl_peer_block_received(&dm, 2, 4000000);

        struct uint256 out[5];
        size_t got = dl_assign_to_peer(&dm, 2, out, 5);
        ASSERT(got == 5); /* full quota despite being the slow peer */
        ASSERT(uint256_eq(&out[0], &hs[0])); /* even the most urgent one */

        dl_free(&dm);
        PASS();
    } _test_next:;
    return failures;
}

/* Batched-compaction hot path: a deep queue drained in large front-pop
 * batches must lose no block, duplicate none, and hand them all out in
 * strict height order. The single-pass dl_queue_remove_sorted() compaction
 * that replaced the per-pick O(queue_len) memmove must be exactly
 * equivalent to the loop it superseded — this drives the deep-queue batch
 * path (tip_bias_skip == 0, available == the full per-peer window) that
 * dominates fresh IBD, where the queue is pinned near its cap. */
static int test_dl_batch_compaction_deep_queue(void)
{
    int failures = 0;
    TEST("deep-queue large-batch drain: no loss, no dup, height-sorted") {
        struct download_manager dm;
        dl_init(&dm);

        const int N = 5000; /* deep enough to force the batch path */
        for (int i = 0; i < N; i++) {
            struct uint256 h = make_hash16((uint16_t)i);
            int32_t height = 100000 + i;   /* hash order == height order */
            ASSERT(dl_queue_blocks(&dm, &h, &height, 1) == 1);
        }
        uint64_t q0;
        dl_get_stats(&dm, NULL, NULL, NULL, NULL, &q0);
        ASSERT(q0 == (uint64_t)N);

        /* Drain everything to peer 1 in large batches (bounded by the
         * per-peer window), marking each received so the window reopens.
         * Verify the exact hand-out order and a per-index seen-count. */
        static uint8_t seen[5000];
        memset(seen, 0, sizeof(seen));
        struct uint256 out[200];
        int prev_v = -1;
        uint64_t total = 0;
        for (;;) {
            size_t got = dl_assign_to_peer(&dm, 1, out, 200);
            if (got == 0)
                break;
            for (size_t k = 0; k < got; k++) {
                int v = out[k].data[0] | (out[k].data[1] << 8);
                ASSERT(v >= 0 && v < N);
                ASSERT(seen[v] == 0);        /* no duplicate hand-out */
                seen[v] = 1;
                ASSERT(v > prev_v);          /* strict ascending == height order */
                prev_v = v;
                ASSERT(dl_mark_received(&dm, &out[k]) == 1);
            }
            total += got;
        }
        ASSERT(total == (uint64_t)N);        /* no loss */
        for (int i = 0; i < N; i++)
            ASSERT(seen[i] == 1);

        /* Accounting identity holds after the whole drain. */
        struct dl_diagnostics diag;
        dl_get_diagnostics(&dm, &diag);
        ASSERT(diag.accounting_drift == 0);
        uint64_t req, recv, tout, inflight, queued;
        dl_get_stats(&dm, &req, &recv, &tout, &inflight, &queued);
        ASSERT(req == (uint64_t)N);
        ASSERT(recv == (uint64_t)N);
        ASSERT(inflight == 0);
        ASSERT(queued == 0);

        dl_free(&dm);
        PASS();
    } _test_next:;
    return failures;
}

int test_download(void)
{
    int failures = 0;
    failures += test_dl_init_free();
    failures += test_dl_mark_requested();
    failures += test_dl_mark_received();
    failures += test_dl_queue_dedup();
    failures += test_dl_assign_to_peer();
    failures += test_dl_assignment_generation_parking();
    failures += test_dl_assignment_parking_is_per_peer();
    failures += test_dl_assignment_peer_cache_capacity_and_reuse();
    failures += test_dl_peer_disconnected();
    failures += test_dl_mark_notfound_settles_only_named_block();
    failures += test_dl_settle_accounting();
    failures += test_dl_check_timeouts();
    failures += test_dl_last_forced_settle_time_initial();
    failures += test_dl_last_forced_settle_time_drain();
    failures += test_dl_last_forced_settle_time_timeout();
    failures += test_dl_last_forced_settle_time_untouched();
    failures += test_dl_timeout_retry_failover();
    failures += test_dl_timeout_retry_failover_peer_zero();
    failures += test_dl_timeout_retry_avoid_expiry();
    failures += test_dl_peer_body_progress();
    failures += test_dl_peer_body_staleness();
    failures += test_dl_diagnostics();
    failures += test_gap_fill_timeout_sweep();
    failures += test_gap_fill_timeout_wakes_dispatcher();
    failures += test_gap_fill_queued_idle_wakes_dispatcher();
    failures += test_dl_many_insertions();
    failures += test_dl_ibd_windows();
    failures += test_dl_per_peer_limit();
    failures += test_dl_concurrent();
    failures += test_dl_byte_tracking();
    failures += test_dl_byte_tracking_before_sync();
    failures += test_dl_byte_tracking_large();
    failures += test_dl_null_throughput_params();
    failures += test_dl_lowest_height_first();
    failures += test_dl_sorted_across_paths();
    failures += test_dl_unknown_height_sorts_last();
    failures += test_dl_history_lane_is_bounded_and_forward_wins();
    failures += test_dl_history_promotion_wakes_parked_peer();
    failures += test_dl_tip_bias_prefers_fast_peer();
    failures += test_dl_tip_bias_no_starvation_shallow_queue();
    failures += test_dl_batch_compaction_deep_queue();
    failures += test_gap_fill_registers_supervisor_contract();
    return failures;
}
