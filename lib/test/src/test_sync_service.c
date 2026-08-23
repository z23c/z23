/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Tests for sync service policy extraction. */

#include "platform/time_compat.h"
#include "test/test_core.h"
#include "net/net.h"
#include "controllers/diagnostics_controller.h"
#include "controllers/diagnostics_internal.h"
#include "json/json.h"
#include "sync/sync_planner.h"
#include "validation/main_state.h"
#include "net/download.h"
#include "services/utxo_recovery_service.h"
#include "jobs/reducer_frontier.h"
#include "chain/checkpoints.h"
#include "util/blocker.h"
#include "util/safe_alloc.h"
#include <string.h>
#include <time.h>

static int test_sync_service_begin_sync(void)
{
    int failures = 0;

    TEST("sync_service begins outbound header sync") {
        struct p2p_node node;
        memset(&node, 0, sizeof(node));
        node.id = 7;
        node.state = PEER_ACTIVE;
        node.inbound = false;
        node.starting_height = 1000;

        sync_set_state(SYNC_IDLE, "reset");
        ASSERT(syncsvc_begin_peer_sync(&node, 0, 0));
        ASSERT(node.state == PEER_SYNCING_HEADERS);
        ASSERT(sync_get_state() == SYNC_HEADERS_DOWNLOAD);
        PASS();
    } _test_next:;

    return failures;
}

static int test_sync_service_rejects_inbound_sync(void)
{
    int failures = 0;

    TEST("sync_service does not start sync for inbound peer") {
        struct p2p_node node;
        memset(&node, 0, sizeof(node));
        node.id = 9;
        node.state = PEER_ACTIVE;
        node.inbound = true;

        sync_set_state(SYNC_IDLE, "reset");
        ASSERT(!syncsvc_begin_peer_sync(&node, 0, 0));
        ASSERT(node.state == PEER_ACTIVE);
        ASSERT(sync_get_state() == SYNC_IDLE);
        PASS();
    } _test_next:;

    return failures;
}

static int test_sync_service_keeps_caught_up_peers_active(void)
{
    int failures = 0;

    TEST("sync_service keeps caught-up outbound peers active") {
        struct p2p_node node;
        memset(&node, 0, sizeof(node));
        node.id = 11;
        node.state = PEER_ACTIVE;
        node.inbound = false;
        node.starting_height = 1000;

        ASSERT(!syncsvc_should_begin_peer_sync(&node, 1000, 1000,
                                               SYNC_AT_TIP));
        ASSERT(!syncsvc_begin_peer_sync(&node, 1000, 1000));
        ASSERT(node.state == PEER_ACTIVE);
        PASS();
    } _test_next:;

    return failures;
}

static int test_sync_service_begins_when_peer_one_block_ahead(void)
{
    int failures = 0;

    TEST("sync_service begins when active peer is one block ahead") {
        struct p2p_node node;
        memset(&node, 0, sizeof(node));
        node.id = 13;
        node.state = PEER_ACTIVE;
        node.inbound = false;
        node.starting_height = 1001;

        ASSERT(syncsvc_should_begin_peer_sync(&node, 1000, 1000,
                                              SYNC_AT_TIP));
        ASSERT(!syncsvc_should_mark_peer_caught_up(&node, 1000, 1000));
        PASS();
    } _test_next:;

    return failures;
}

static int test_sync_service_probes_equal_peer_after_restart(void)
{
    int failures = 0;

    TEST("sync_service probes an equal-height outbound peer after restart") {
        struct p2p_node node;
        memset(&node, 0, sizeof(node));
        node.id = 14;
        node.state = PEER_ACTIVE;
        node.inbound = false;
        node.starting_height = 1000;

        sync_set_state(SYNC_IDLE, "equal-peer restart reset");
        ASSERT(sync_set_state(SYNC_FINDING_PEERS,
                              "equal-peer restart P2P started"));
        ASSERT(syncsvc_begin_peer_sync(&node, 1000, 1000));
        ASSERT(node.state == PEER_SYNCING_HEADERS);
        ASSERT(sync_get_state() == SYNC_HEADERS_DOWNLOAD);
        PASS();
    } _test_next:;

    return failures;
}

static int test_sync_service_probes_zero_height_onion_once(void)
{
    int failures = 0;

    TEST("sync_service probes a zero-height ZCL23 onion edge exactly once") {
        struct p2p_node onion;
        struct p2p_node clearnet;

        memset(&onion, 0, sizeof(onion));
        onion.id = 15;
        onion.state = PEER_ACTIVE;
        onion.starting_height = 0;
        onion.services = NODE_NETWORK | NODE_ZCL23;
        onion.addr.svc.addr.has_torv3 = true;

        ASSERT(syncsvc_should_begin_peer_sync(&onion, 3225916, 3225916,
                                              SYNC_AT_TIP));
        ASSERT(syncsvc_begin_peer_sync(&onion, 3225916, 3225916));
        ASSERT(onion.state == PEER_SYNCING_HEADERS);
        ASSERT(!syncsvc_should_mark_peer_caught_up(&onion, 3225916,
                                                   3225916));
        ASSERT(syncsvc_should_request_headers(&onion, 3225916, 121));

        syncsvc_note_headers_requested(&onion, 121);
        ASSERT(syncsvc_should_mark_peer_caught_up(&onion, 3225916,
                                                  3225916));
        ASSERT(syncsvc_peer_is_behind(&onion, 3225916));
        ASSERT(!syncsvc_should_request_headers(&onion, 3225916, 1000));
        onion.state = PEER_ACTIVE;
        ASSERT(!syncsvc_should_begin_peer_sync(&onion, 3225916, 3225916,
                                               SYNC_AT_TIP));

        /* The exception is onion- and native-ZCL23-specific.  A generic
         * zero-height clearnet peer remains proven substantially behind. */
        memset(&clearnet, 0, sizeof(clearnet));
        clearnet.id = 16;
        clearnet.state = PEER_ACTIVE;
        clearnet.starting_height = 0;
        clearnet.services = NODE_NETWORK | NODE_ZCL23;
        net_addr_set_ipv4(&clearnet.addr.svc.addr,
                          (const unsigned char[4]){203, 0, 113, 16});
        ASSERT(!syncsvc_should_begin_peer_sync(&clearnet, 3225916, 3225916,
                                               SYNC_AT_TIP));
        ASSERT(syncsvc_peer_is_behind(&clearnet, 3225916));
        PASS();
    } _test_next:;

    return failures;
}

static int test_sync_service_marks_caught_up_syncing_peers_active(void)
{
    int failures = 0;

    TEST("sync_service marks caught-up syncing peers active") {
        struct p2p_node node;
        memset(&node, 0, sizeof(node));
        node.id = 12;
        node.state = PEER_SYNCING_HEADERS;
        node.inbound = false;
        node.starting_height = 1000;

        ASSERT(syncsvc_should_mark_peer_caught_up(&node, 1000, 1000));
        ASSERT(!syncsvc_should_mark_peer_caught_up(&node, 999, 1000));
        PASS();
    } _test_next:;

    return failures;
}

static int test_sync_service_request_policy(void)
{
    int failures = 0;

    TEST("sync_service header request interval depends on IBD") {
        struct p2p_node node;
        memset(&node, 0, sizeof(node));
        node.state = PEER_SYNCING_HEADERS;
        node.starting_height = 1000;
        node.last_getheaders_time = 100;

        /* IBD: 10s interval */
        ASSERT(syncsvc_is_initial_block_download(&node, 500));
        ASSERT(!syncsvc_should_request_headers(&node, 500, 109));
        ASSERT(syncsvc_should_request_headers(&node, 500, 111));

        /* Catching up (not IBD, but behind peer): 30s interval */
        ASSERT(!syncsvc_is_initial_block_download(&node, 900));
        ASSERT(!syncsvc_should_request_headers(&node, 900, 129));
        ASSERT(syncsvc_should_request_headers(&node, 900, 131));

        /* At tip (caught up to peer starting_height): 120s interval */
        ASSERT(!syncsvc_should_request_headers(&node, 1000, 219));
        ASSERT(syncsvc_should_request_headers(&node, 1000, 221));
        ASSERT(!syncsvc_should_request_headers(&node, 1500, 219));
        ASSERT(syncsvc_should_request_headers(&node, 1500, 221));
        PASS();
    } _test_next:;

    return failures;
}

static int test_sync_service_band_hole_forces_ibd_interval(void)
{
    int failures = 0;

    TEST("sync_service forces the IBD getheaders interval while a header "
         "band hole is open, regardless of at-tip appearance") {
        struct p2p_node node;
        struct blocker_record br;

        memset(&node, 0, sizeof(node));
        node.state = PEER_SYNCING_HEADERS;
        node.starting_height = 1000;
        node.last_getheaders_time = 100;

        blocker_reset_for_testing();
        syncsvc_header_band_reset_for_testing();

        /* Baseline: our_height == starting_height reads "at tip" — no band
         * hole recorded, so the slow 120s at-tip cadence applies (same
         * truth table as test_sync_service_request_policy). */
        ASSERT(!syncsvc_header_band_hole_open());
        ASSERT(!syncsvc_should_request_headers(&node, 1000, 219));
        ASSERT(syncsvc_should_request_headers(&node, 1000, 221));

        /* S8: band hole open (the typed blocker is recorded) — the same
         * "at tip" node/height inputs must now use the 10s IBD interval,
         * not the 120s at-tip cadence. Request side only. */
        ASSERT(blocker_init(&br, HEADER_BAND_BLOCKER_ID, "unit",
                            BLOCKER_DEPENDENCY, "unit fixture"));
        ASSERT(blocker_set(&br) >= 0);
        ASSERT(syncsvc_header_band_hole_open());

        ASSERT(!syncsvc_should_request_headers(&node, 1000, 109));
        ASSERT(syncsvc_should_request_headers(&node, 1000, 111));

        /* Band closed (blocker cleared): behavior reverts to the normal
         * at-tip cadence on the very next call — no lingering state. */
        blocker_clear(HEADER_BAND_BLOCKER_ID);
        ASSERT(!syncsvc_header_band_hole_open());
        ASSERT(!syncsvc_should_request_headers(&node, 1000, 219));
        ASSERT(syncsvc_should_request_headers(&node, 1000, 221));

        blocker_reset_for_testing();
        syncsvc_header_band_reset_for_testing();
        PASS();
    } _test_next:;

    return failures;
}

static int test_sync_service_periodic_getheaders_action(void)
{
    int failures = 0;

    TEST("sync_service plans periodic getheaders resend action") {
        struct p2p_node node;
        struct sync_getheaders_action action;

        memset(&node, 0, sizeof(node));
        memset(&action, 0, sizeof(action));
        node.state = PEER_SYNCING_HEADERS;
        node.starting_height = 1000;
        node.last_getheaders_time = 100;

        syncsvc_plan_periodic_getheaders(&action, &node, 500, 109);
        ASSERT(!action.should_send);

        syncsvc_plan_periodic_getheaders(&action, &node, 500, 111);
        ASSERT(action.should_send);
        ASSERT(action.anchor == SYNC_HEADER_REQUEST_TIP);
        ASSERT(action.should_log);
        PASS();
    } _test_next:;

    return failures;
}

static int test_sync_service_invalid_block_getheaders_action(void)
{
    int failures = 0;

    TEST("sync_service plans invalid-block getheaders retry during sync") {
        struct sync_getheaders_action action;

        memset(&action, 0, sizeof(action));
        syncsvc_plan_invalid_block_getheaders(&action, SYNC_BLOCKS_DOWNLOAD);
        ASSERT(action.should_send);
        ASSERT(action.anchor == SYNC_HEADER_REQUEST_TIP);
        ASSERT(!action.should_log);

        memset(&action, 0, sizeof(action));
        syncsvc_plan_invalid_block_getheaders(&action, SYNC_AT_TIP);
        ASSERT(!action.should_send);
        PASS();
    } _test_next:;

    return failures;
}

static int test_sync_service_headers_log_throttle(void)
{
    int failures = 0;

    TEST("sync_service throttles accepted-header logging during deep IBD") {
        struct p2p_node node;
        struct block_index tip;
        struct uint256 h = {0};

        memset(&node, 0, sizeof(node));
        memset(&tip, 0, sizeof(tip));
        h.data[0] = 9;
        node.starting_height = 5000;
        tip.phashBlock = &h;
        tip.nHeight = 2000;

        ASSERT(syncsvc_should_log_accepted_headers(&node, &tip));
        ASSERT(!syncsvc_should_log_accepted_headers(&node, &tip));
        ASSERT(!syncsvc_should_log_accepted_headers(&node, &tip));

        tip.nHeight = 4999;
        ASSERT(syncsvc_should_log_accepted_headers(&node, &tip));
        ASSERT(syncsvc_should_log_accepted_headers(&node, NULL));
        PASS();
    } _test_next:;

    return failures;
}

static int test_sync_service_header_batch_followup(void)
{
    int failures = 0;

    TEST("sync_service evaluates header batch follow-up decisions") {
        struct sync_header_batch batch;
        struct block_index tip;
        struct uint256 h = {0};

        memset(&batch, 0, sizeof(batch));
        memset(&tip, 0, sizeof(tip));
        h.data[0] = 14;
        tip.phashBlock = &h;

        syncsvc_evaluate_header_batch(&batch, 0, 3, NULL);
        ASSERT(batch.should_warn_all_rejected);
        ASSERT(!batch.should_emit_received);
        ASSERT(!batch.should_request_more_headers);
        /* All-rejected batches arm the recovery probe (the call site keys
         * on bad-prevblk and applies the per-peer rate limit). */
        ASSERT(batch.should_probe_after_reject);

        syncsvc_evaluate_header_batch(&batch, 0, 0, NULL);
        ASSERT(!batch.should_warn_all_rejected);
        ASSERT(!batch.should_probe_after_reject);

        syncsvc_evaluate_header_batch(&batch, 5, 5, &tip);
        ASSERT(!batch.should_warn_all_rejected);
        ASSERT(batch.should_emit_received);
        ASSERT(!batch.should_request_more_headers);
        ASSERT(!batch.should_probe_after_reject);

        syncsvc_evaluate_header_batch(&batch, 5, 2000, &tip);
        ASSERT(!batch.should_warn_all_rejected);
        ASSERT(batch.should_emit_received);
        ASSERT(batch.should_request_more_headers);
        ASSERT(!batch.should_probe_after_reject);

        tip.phashBlock = NULL;
        syncsvc_evaluate_header_batch(&batch, 2, 2000, &tip);
        ASSERT(batch.should_emit_received);
        ASSERT(!batch.should_request_more_headers);
        ASSERT(!batch.should_probe_after_reject);
        PASS();
    } _test_next:;

    return failures;
}

static int test_sync_service_reject_probe_rate_limit(void)
{
    int failures = 0;

    TEST("sync_service rate-limits the all-rejected recovery probe") {
        /* Never probed (0 / unset) → probe allowed. */
        ASSERT(syncsvc_should_probe_after_reject(1000, 0));
        /* Inside the interval → suppressed. */
        ASSERT(!syncsvc_should_probe_after_reject(
            1000, 1000 - SYNC_REJECT_PROBE_INTERVAL_SECS + 1));
        ASSERT(!syncsvc_should_probe_after_reject(1000, 1000));
        /* At and past the interval → allowed. */
        ASSERT(syncsvc_should_probe_after_reject(
            1000, 1000 - SYNC_REJECT_PROBE_INTERVAL_SECS));
        ASSERT(syncsvc_should_probe_after_reject(1000, 500));
        PASS();
    } _test_next:;

    return failures;
}

static int test_sync_service_reject_probe_pending(void)
{
    int failures = 0;

    TEST("sync_service arms and disarms the reject-probe pending flag") {
        struct p2p_node node;
        memset(&node, 0, sizeof(node));

        /* All-rejected bad-prevblk batch arms pending. */
        syncsvc_note_header_batch_outcome(&node, 0, true);
        ASSERT(node.reject_probe_pending);

        /* Periodic re-probe: pending with a fresh probe stamp → suppressed
         * inside the rate-limit window. */
        node.last_reject_probe_time = 1000;
        ASSERT(!syncsvc_should_fire_reject_probe(&node, 1001));
        /* Interval elapsed → fires. */
        ASSERT(syncsvc_should_fire_reject_probe(
            &node, 1000 + SYNC_REJECT_PROBE_INTERVAL_SECS));
        /* Never probed (stamp 0) → fires immediately. */
        node.last_reject_probe_time = 0;
        ASSERT(syncsvc_should_fire_reject_probe(&node, 42));

        /* All-rejected batch WITHOUT bad-prevblk does not arm. */
        node.reject_probe_pending = false;
        syncsvc_note_header_batch_outcome(&node, 0, false);
        ASSERT(!node.reject_probe_pending);
        ASSERT(!syncsvc_should_fire_reject_probe(&node, 100000));

        /* Any accepted header disarms — even with bad-prevblk rejects in
         * the same batch, the conversation is connected again. */
        node.reject_probe_pending = true;
        syncsvc_note_header_batch_outcome(&node, 3, true);
        ASSERT(!node.reject_probe_pending);
        ASSERT(!syncsvc_should_fire_reject_probe(&node, 100000));
        PASS();
    } _test_next:;

    return failures;
}

static int test_sync_service_block_file_scan_trigger(void)
{
    int failures = 0;

    TEST("sync_service only triggers post-header block-file scan once past threshold") {
        struct block_index tip;

        memset(&tip, 0, sizeof(tip));

        tip.nHeight = 1000;
        ASSERT(!syncsvc_should_scan_block_files_after_headers(1, &tip));

        tip.nHeight = 1001;
        ASSERT(syncsvc_should_scan_block_files_after_headers(1, &tip));
        ASSERT(!syncsvc_should_scan_block_files_after_headers(1, &tip));
        ASSERT(!syncsvc_should_scan_block_files_after_headers(0, &tip));
        ASSERT(!syncsvc_should_scan_block_files_after_headers(1, NULL));
        PASS();
    } _test_next:;

    return failures;
}

static int test_sync_service_block_assignment_plan(void)
{
    int failures = 0;

    TEST("sync_service plans block assignment based on peer readiness and load") {
        struct p2p_node node;
        struct sync_block_assignment plan;

        memset(&node, 0, sizeof(node));
        memset(&plan, 0, sizeof(plan));

        /* our_height=100000; peer ahead so the behind-gate keeps it
         * eligible (the gate only excludes peers proven SUBSTANTIALLY —
         * >SYNC_PEER_BEHIND_TOLERANCE blocks — behind us). */
        node.starting_height = 100200;
        const int our_height = 100000;

        syncsvc_plan_block_assignment(&plan, &node, 0, our_height);
        ASSERT(!plan.should_assign);

        node.state = PEER_HANDSHAKE_COMPLETE;
        syncsvc_plan_block_assignment(&plan, &node, 0, our_height);
        ASSERT(plan.should_assign);
        ASSERT(plan.max_assign == 64);

        syncsvc_plan_block_assignment(&plan, &node,
                                      (DL_MAX_IN_FLIGHT_PER_PEER / 2) + 1,
                                      our_height);
        ASSERT(plan.should_assign);
        ASSERT(plan.max_assign == 16);

        /* Behind-gate: a peer within the tolerance band is NOT gated (it
         * may be a long-lived at-tip peer with a stale-low handshake h). */
        node.starting_height = our_height;   /* exactly at our height */
        syncsvc_plan_block_assignment(&plan, &node, 0, our_height);
        ASSERT(plan.should_assign);
        node.starting_height = our_height - SYNC_PEER_BEHIND_TOLERANCE;
        syncsvc_plan_block_assignment(&plan, &node, 0, our_height);
        ASSERT(plan.should_assign);   /* exactly at the band edge: kept */
        /* Substantially behind (past the band): gated, no assignment. */
        node.starting_height = our_height - SYNC_PEER_BEHIND_TOLERANCE - 1;
        syncsvc_plan_block_assignment(&plan, &node, 0, our_height);
        ASSERT(!plan.should_assign);
        node.starting_height = -1;   /* unknown height: stays eligible */
        syncsvc_plan_block_assignment(&plan, &node, 0, our_height);
        ASSERT(plan.should_assign);
        PASS();
    } _test_next:;

    return failures;
}

static int test_sync_service_assigns_peer_blocks(void)
{
    int failures = 0;

    TEST("sync_service assigns queued blocks through download manager") {
        struct p2p_node node;
        struct download_manager dm;
        struct sync_block_batch batch;
        struct uint256 queued[2];
        int32_t heights[2] = {10, 11};
        struct uint256 assigned[DL_WINDOW_SIZE];

        memset(&node, 0, sizeof(node));
        memset(&batch, 0, sizeof(batch));
        memset(queued, 0, sizeof(queued));
        memset(assigned, 0, sizeof(assigned));
        node.id = 3;
        node.state = PEER_HANDSHAKE_COMPLETE;
        node.starting_height = 200;   /* ahead of our_height below */
        queued[0].data[0] = 1;
        queued[1].data[0] = 2;

        dl_init(&dm);
        ASSERT(dl_queue_blocks(&dm, queued, heights, 2) == 2);

        syncsvc_assign_peer_blocks(&batch, &dm, &node, assigned,
                                   DL_WINDOW_SIZE, /*our_height=*/100);
        ASSERT(batch.should_assign);
        ASSERT(batch.in_flight_before == 0);
        ASSERT(batch.assigned == 2);
        ASSERT(uint256_eq(&assigned[0], &queued[0]));
        ASSERT(uint256_eq(&assigned[1], &queued[1]));

        /* One empty-queue result records the peer's dependency generation;
         * later message cycles remain parked until queue/window state moves. */
        syncsvc_assign_peer_blocks(&batch, &dm, &node, assigned,
                                   DL_WINDOW_SIZE, /*our_height=*/100);
        struct dl_diagnostics before_park;
        dl_get_diagnostics(&dm, &before_park);
        ASSERT(before_park.assign_attempts == 2);
        ASSERT(before_park.last_assign_result == DL_ASSIGN_NO_QUEUE);

        syncsvc_assign_peer_blocks(&batch, &dm, &node, assigned,
                                   DL_WINDOW_SIZE, /*our_height=*/100);
        struct dl_diagnostics after_park;
        dl_get_diagnostics(&dm, &after_park);
        ASSERT(batch.should_assign);
        ASSERT(batch.assigned == 0);
        ASSERT(after_park.assign_attempts == before_park.assign_attempts);
        ASSERT(after_park.assign_zero_results ==
               before_park.assign_zero_results);

        dl_free(&dm);
        PASS();
    } _test_next:;

    return failures;
}

static int test_sync_service_body_stall_disconnect(void)
{
    int failures = 0;

    TEST("body-stall discipline disconnects a header-only peer with no bodies") {
        struct p2p_node node;
        memset(&node, 0, sizeof(node));
        node.id = 5;
        node.state = PEER_SYNCING_HEADERS;
        node.starting_height = 200000;   /* far ahead: we still need bodies */
        int our_height = 100000;         /* < starting_height - 144 ⇒ IBD */
        int64_t now = 1000000;
        node.time_connected = now - (SYNC_BODY_STALL_TIMEOUT_SECS + 5);

        /* A peer that served headers but returned zero bodies while
         * SYNC_BODY_STALL_MIN_TIMEOUTS block requests expired unfilled,
         * connected past the stall window: fail over off it. */
        ASSERT(syncsvc_should_disconnect_body_stalled_peer(
                   &node, our_height, /*received=*/0,
                   /*timed_out=*/SYNC_BODY_STALL_MIN_TIMEOUTS, now));

        /* Delivered at least one body ⇒ the peer can serve; keep it. */
        ASSERT(!syncsvc_should_disconnect_body_stalled_peer(
                   &node, our_height, /*received=*/1,
                   SYNC_BODY_STALL_MIN_TIMEOUTS, now));

        /* Not enough requests have timed out yet ⇒ not a deadbeat. */
        ASSERT(!syncsvc_should_disconnect_body_stalled_peer(
                   &node, our_height, 0,
                   SYNC_BODY_STALL_MIN_TIMEOUTS - 1, now));

        /* Inside the grace window (freshly connected) ⇒ keep it. */
        node.time_connected = now - (SYNC_BODY_STALL_TIMEOUT_SECS - 1);
        ASSERT(!syncsvc_should_disconnect_body_stalled_peer(
                   &node, our_height, 0, SYNC_BODY_STALL_MIN_TIMEOUTS, now));
        node.time_connected = now - (SYNC_BODY_STALL_TIMEOUT_SECS + 5);

        /* At/near tip (not IBD) a peer legitimately delivers no bodies. */
        ASSERT(!syncsvc_should_disconnect_body_stalled_peer(
                   &node, /*our_height=*/199999, 0,
                   SYNC_BODY_STALL_MIN_TIMEOUTS, now));

        /* Pre-handshake peer is never judged. */
        node.state = PEER_VERSION_SENT;
        ASSERT(!syncsvc_should_disconnect_body_stalled_peer(
                   &node, our_height, 0, SYNC_BODY_STALL_MIN_TIMEOUTS, now));
        node.state = PEER_SYNCING_HEADERS;

        /* Null node is a safe no-op. */
        ASSERT(!syncsvc_should_disconnect_body_stalled_peer(
                   NULL, our_height, 0, SYNC_BODY_STALL_MIN_TIMEOUTS, now));

        PASS();
    } _test_next:;

    return failures;
}

static int test_sync_service_body_dark_disconnect(void)
{
    int failures = 0;

    TEST("body-dark discipline disconnects a peer that delivered then went silent") {
        struct p2p_node node;
        memset(&node, 0, sizeof(node));
        node.id = 6;
        node.state = PEER_SYNCING_HEADERS;
        node.starting_height = 200000;   /* far ahead: we still need bodies */
        int our_height = 100000;         /* < starting_height - 144 ⇒ IBD */
        int64_t now = 1000000;
        /* Its most recent body arrived a full stall window + 5s ago (dark). */
        int64_t last_body = now - (SYNC_BODY_STALL_TIMEOUT_SECS + 5);

        /* Delivered >= 1 body, then SYNC_BODY_STALL_MIN_TIMEOUTS getdata
         * expired unfilled while the body cursor sat stale past the window:
         * fail over off it. This is the exact delivered-then-dark case
         * Rule C (syncsvc_should_disconnect_body_stalled_peer) exempts. */
        ASSERT(syncsvc_should_disconnect_body_dark_peer(
                   &node, our_height, /*received=*/5,
                   /*timed_out=*/SYNC_BODY_STALL_MIN_TIMEOUTS, last_body, now));

        /* Complement of Rule C: a peer that NEVER delivered a body is Rule
         * C's case, not this one. received == 0 ⇒ this predicate stays
         * false, guaranteeing the two never both fire on one peer (no
         * double-eviction). */
        ASSERT(!syncsvc_should_disconnect_body_dark_peer(
                   &node, our_height, /*received=*/0,
                   SYNC_BODY_STALL_MIN_TIMEOUTS, last_body, now));

        /* Legitimately in-flight requests (below the timed-out floor) ⇒ the
         * peer is not a deadbeat; keep it even though its cursor is stale. */
        ASSERT(!syncsvc_should_disconnect_body_dark_peer(
                   &node, our_height, 5,
                   SYNC_BODY_STALL_MIN_TIMEOUTS - 1, last_body, now));

        /* Body cursor still fresh (a body arrived within the window) ⇒ the
         * peer is actively serving; keep it regardless of timeouts. */
        ASSERT(!syncsvc_should_disconnect_body_dark_peer(
                   &node, our_height, 5, SYNC_BODY_STALL_MIN_TIMEOUTS,
                   now - (SYNC_BODY_STALL_TIMEOUT_SECS - 1), now));

        /* Zero/unknown cursor is never judged (defensive). */
        ASSERT(!syncsvc_should_disconnect_body_dark_peer(
                   &node, our_height, 5, SYNC_BODY_STALL_MIN_TIMEOUTS, 0, now));

        /* At/near tip (not IBD) a peer legitimately delivers no bodies. */
        ASSERT(!syncsvc_should_disconnect_body_dark_peer(
                   &node, /*our_height=*/199999, 5,
                   SYNC_BODY_STALL_MIN_TIMEOUTS, last_body, now));

        /* Pre-handshake peer is never judged. */
        node.state = PEER_VERSION_SENT;
        ASSERT(!syncsvc_should_disconnect_body_dark_peer(
                   &node, our_height, 5, SYNC_BODY_STALL_MIN_TIMEOUTS,
                   last_body, now));
        node.state = PEER_SYNCING_HEADERS;

        /* Null node is a safe no-op. */
        ASSERT(!syncsvc_should_disconnect_body_dark_peer(
                   NULL, our_height, 5, SYNC_BODY_STALL_MIN_TIMEOUTS,
                   last_body, now));

        PASS();
    } _test_next:;

    return failures;
}

static int test_sync_service_collects_needed_blocks_oldest_first(void)
{
    int failures = 0;

    TEST("sync_service collects missing blocks from accepted headers oldest-first") {
        struct uint256 h0 = {0}, h1 = {0}, h2 = {0}, h3 = {0};
        struct block_index genesis, tip, next, leaf;
        struct sync_needed_blocks result;
        struct uint256 hashes[4];
        int32_t heights[4];

        memset(&genesis, 0, sizeof(genesis));
        memset(&tip, 0, sizeof(tip));
        memset(&next, 0, sizeof(next));
        memset(&leaf, 0, sizeof(leaf));
        memset(&result, 0, sizeof(result));
        memset(hashes, 0, sizeof(hashes));
        memset(heights, 0, sizeof(heights));
        block_index_init(&genesis);
        block_index_init(&tip);
        block_index_init(&next);
        block_index_init(&leaf);

        h0.data[0] = 1; h1.data[0] = 2; h2.data[0] = 3; h3.data[0] = 4;
        genesis.phashBlock = &h0; genesis.nHeight = 0;
        tip.phashBlock = &h1; tip.nHeight = 1; tip.pprev = &genesis;
        next.phashBlock = &h2; next.nHeight = 2; next.pprev = &tip;
        leaf.phashBlock = &h3; leaf.nHeight = 3; leaf.pprev = &next;

        syncsvc_collect_needed_blocks(&result, &leaf, &tip, 1,
                                      hashes, heights, 4);
        ASSERT(result.chains_from_tip);
        ASSERT(!result.should_activate_chain);
        ASSERT(result.count == 2);
        ASSERT(uint256_eq(&hashes[0], &h2));
        ASSERT(uint256_eq(&hashes[1], &h3));
        ASSERT(heights[0] == 2);
        ASSERT(heights[1] == 3);
        PASS();
    } _test_next:;

    return failures;
}

static int test_sync_service_collects_needed_blocks_activation(void)
{
    int failures = 0;

    TEST("sync_service requests chain activation when accepted headers already have data") {
        struct uint256 h0 = {0}, h1 = {0}, h2 = {0};
        struct block_index genesis, tip, have_data;
        struct sync_needed_blocks result;
        struct uint256 hashes[2];
        int32_t heights[2];

        memset(&genesis, 0, sizeof(genesis));
        memset(&tip, 0, sizeof(tip));
        memset(&have_data, 0, sizeof(have_data));
        memset(&result, 0, sizeof(result));
        memset(hashes, 0, sizeof(hashes));
        memset(heights, 0, sizeof(heights));
        block_index_init(&genesis);
        block_index_init(&tip);
        block_index_init(&have_data);

        h0.data[0] = 10; h1.data[0] = 11; h2.data[0] = 12;
        genesis.phashBlock = &h0; genesis.nHeight = 0;
        tip.phashBlock = &h1; tip.nHeight = 1; tip.pprev = &genesis;
        have_data.phashBlock = &h2; have_data.nHeight = 2; have_data.pprev = &tip;
        have_data.nStatus = BLOCK_HAVE_DATA;

        syncsvc_collect_needed_blocks(&result, &have_data, &tip, 1,
                                      hashes, heights, 2);
        ASSERT(result.chains_from_tip);
        ASSERT(result.should_activate_chain);
        ASSERT(result.count == 0);
        PASS();
    } _test_next:;

    return failures;
}

static int test_sync_service_collects_needed_blocks_rejects_forks(void)
{
    int failures = 0;

    TEST("sync_service refuses needed-block collection for forked headers") {
        struct uint256 h0 = {0}, h1 = {0}, h2 = {0};
        struct block_index genesis, tip, fork;
        struct sync_needed_blocks result;
        struct uint256 hashes[2];
        int32_t heights[2];

        memset(&genesis, 0, sizeof(genesis));
        memset(&tip, 0, sizeof(tip));
        memset(&fork, 0, sizeof(fork));
        memset(&result, 0, sizeof(result));
        memset(hashes, 0, sizeof(hashes));
        memset(heights, 0, sizeof(heights));
        block_index_init(&genesis);
        block_index_init(&tip);
        block_index_init(&fork);

        h0.data[0] = 20; h1.data[0] = 21; h2.data[0] = 22;
        genesis.phashBlock = &h0; genesis.nHeight = 0;
        tip.phashBlock = &h1; tip.nHeight = 1; tip.pprev = &genesis;
        fork.phashBlock = &h2; fork.nHeight = 2; fork.pprev = &genesis;

        syncsvc_collect_needed_blocks(&result, &fork, &tip, 1,
                                      hashes, heights, 2);
        ASSERT(!result.chains_from_tip);
        ASSERT(!result.should_activate_chain);
        ASSERT(result.count == 0);
        PASS();
    } _test_next:;

    return failures;
}

static int test_sync_service_plans_header_download(void)
{
    int failures = 0;

    TEST("sync_service plans header download transition and needed blocks together") {
        struct uint256 h0 = {0}, h1 = {0}, h2 = {0}, h3 = {0};
        struct block_index genesis, tip, next, leaf;
        struct sync_header_download_plan plan;
        struct uint256 hashes[4];
        int32_t heights[4];

        memset(&genesis, 0, sizeof(genesis));
        memset(&tip, 0, sizeof(tip));
        memset(&next, 0, sizeof(next));
        memset(&leaf, 0, sizeof(leaf));
        memset(&plan, 0, sizeof(plan));
        memset(hashes, 0, sizeof(hashes));
        memset(heights, 0, sizeof(heights));
        block_index_init(&genesis);
        block_index_init(&tip);
        block_index_init(&next);
        block_index_init(&leaf);

        h0.data[0] = 30; h1.data[0] = 31; h2.data[0] = 32; h3.data[0] = 33;
        genesis.phashBlock = &h0; genesis.nHeight = 0;
        tip.phashBlock = &h1; tip.nHeight = 1; tip.pprev = &genesis;
        next.phashBlock = &h2; next.nHeight = 2; next.pprev = &tip;
        leaf.phashBlock = &h3; leaf.nHeight = 3; leaf.pprev = &next;

        syncsvc_plan_header_download(&plan, SYNC_HEADERS_DOWNLOAD,
                                     &leaf, &tip, 1,
                                     hashes, heights, 4);
        ASSERT(plan.has_candidate);
        ASSERT(plan.should_begin_blocks_download);
        ASSERT(plan.needed_blocks.chains_from_tip);
        ASSERT(plan.needed_blocks.count == 2);
        ASSERT(uint256_eq(&hashes[0], &h2));
        ASSERT(uint256_eq(&hashes[1], &h3));
        PASS();
    } _test_next:;

    return failures;
}

static int test_sync_service_plans_header_processing(void)
{
    int failures = 0;

    TEST("sync_service plans header-processing follow-up as one composite step") {
        struct uint256 h0 = {0}, h1 = {0}, h2 = {0};
        struct block_index genesis, tip, next;
        struct sync_header_processing_plan plan;
        struct uint256 hashes[2];
        int32_t heights[2];

        memset(&genesis, 0, sizeof(genesis));
        memset(&tip, 0, sizeof(tip));
        memset(&next, 0, sizeof(next));
        memset(&plan, 0, sizeof(plan));
        memset(hashes, 0, sizeof(hashes));
        memset(heights, 0, sizeof(heights));
        block_index_init(&genesis);
        block_index_init(&tip);
        block_index_init(&next);

        h0.data[0] = 40; h1.data[0] = 41; h2.data[0] = 42;
        genesis.phashBlock = &h0; genesis.nHeight = 0;
        tip.phashBlock = &h1; tip.nHeight = 1; tip.pprev = &genesis;
        next.phashBlock = &h2; next.nHeight = 2; next.pprev = &tip;

        syncsvc_plan_header_processing(&plan, 1, 2000, &next,
                                       SYNC_HEADERS_DOWNLOAD,
                                       &next, &tip, 1,
                                       hashes, heights, 2);
        ASSERT(plan.batch.should_emit_received);
        ASSERT(plan.batch.should_request_more_headers);
        ASSERT(!plan.should_scan_block_files);
        ASSERT(plan.download.has_candidate);
        ASSERT(plan.download.should_begin_blocks_download);
        ASSERT(plan.should_set_sync_state);
        ASSERT(plan.next_sync_state == SYNC_BLOCKS_DOWNLOAD);
        ASSERT(plan.should_queue_needed_blocks);
        ASSERT(plan.queue_count == 1);
        ASSERT(!plan.should_activate_chain);
        ASSERT(plan.download.needed_blocks.count == 1);
        ASSERT(uint256_eq(&hashes[0], &h2));

        /* A parsed empty answer to the warm-start equal-height probe closes
         * the header phase without inventing either a block or an at-tip
         * verdict.  The live node may remain BLOCKS_DOWNLOAD while its body
         * history is intentionally incomplete. */
        syncsvc_plan_header_processing(&plan, 0, 0, NULL,
                                       SYNC_HEADERS_DOWNLOAD,
                                       NULL, &tip, 1,
                                       hashes, heights, 2);
        ASSERT(!plan.batch.should_emit_received);
        ASSERT(!plan.download.has_candidate);
        ASSERT(plan.should_set_sync_state);
        ASSERT(plan.next_sync_state == SYNC_BLOCKS_DOWNLOAD);
        ASSERT(!plan.should_queue_needed_blocks);
        ASSERT(plan.queue_count == 0);
        PASS();
    } _test_next:;

    return failures;
}

static int test_sync_service_plans_header_processing_activation_from_disk(void)
{
    int failures = 0;

    TEST("sync_service plans activation instead of queueing when header-followed blocks are already on disk") {
        struct uint256 h0 = {0}, h1 = {0}, h2 = {0}, h3 = {0};
        struct block_index genesis, tip, next, leaf;
        struct sync_header_processing_plan plan;
        struct uint256 hashes[4];
        int32_t heights[4];
        struct sync_chain_activation activation;

        memset(&genesis, 0, sizeof(genesis));
        memset(&tip, 0, sizeof(tip));
        memset(&next, 0, sizeof(next));
        memset(&leaf, 0, sizeof(leaf));
        memset(&plan, 0, sizeof(plan));
        memset(&activation, 0, sizeof(activation));
        memset(hashes, 0, sizeof(hashes));
        memset(heights, 0, sizeof(heights));
        block_index_init(&genesis);
        block_index_init(&tip);
        block_index_init(&next);
        block_index_init(&leaf);

        h0.data[0] = 43; h1.data[0] = 44; h2.data[0] = 45; h3.data[0] = 46;
        genesis.phashBlock = &h0; genesis.nHeight = 0;
        tip.phashBlock = &h1; tip.nHeight = 1; tip.pprev = &genesis;
        next.phashBlock = &h2; next.nHeight = 2; next.pprev = &tip;
        leaf.phashBlock = &h3; leaf.nHeight = 3; leaf.pprev = &next;
        next.nStatus = BLOCK_HAVE_DATA;
        leaf.nStatus = BLOCK_HAVE_DATA;

        syncsvc_plan_header_processing(&plan, 2, 2, &leaf,
                                       SYNC_HEADERS_DOWNLOAD,
                                       &leaf, &tip, 1,
                                       hashes, heights, 4);
        ASSERT(plan.batch.should_emit_received);
        ASSERT(!plan.batch.should_request_more_headers);
        ASSERT(plan.download.has_candidate);
        ASSERT(plan.download.should_begin_blocks_download);
        ASSERT(plan.download.needed_blocks.chains_from_tip);
        ASSERT(plan.download.needed_blocks.should_activate_chain);
        ASSERT(plan.download.needed_blocks.count == 0);
        ASSERT(plan.should_set_sync_state);
        ASSERT(plan.next_sync_state == SYNC_BLOCKS_DOWNLOAD);
        ASSERT(!plan.should_queue_needed_blocks);
        ASSERT(plan.queue_count == 0);
        ASSERT(plan.should_activate_chain);
        syncsvc_build_header_processing_activation(&activation, &plan);
        ASSERT(activation.should_activate);
        PASS();
    } _test_next:;

    return failures;
}

static int test_sync_service_restarts_low_header_batches_from_tip(void)
{
    int failures = 0;

    TEST("sync_service treats below-tip header batches from far-ahead peers as non-progress") {
        struct block_index low;

        memset(&low, 0, sizeof(low));
        block_index_init(&low);
        low.nHeight = 2757;

        ASSERT(syncsvc_should_restart_headers_from_tip(
            160, &low, 3087298, 3107754, false));
        ASSERT(!syncsvc_should_restart_headers_from_tip(
            160, &low, 3087298, 3087300, false));
        ASSERT(!syncsvc_should_restart_headers_from_tip(
            0, &low, 3087298, 3107754, false));
        PASS();
    } _test_next:;

    return failures;
}

/* ── Header band backfill fixtures ──────────────────────────────────
 * Segments MUST root at get_sha3_utxo_checkpoint()->height + 1 (or the
 * compiled REDUCER_FRONTIER_TRUSTED_ANCHOR fallback): the trust-rooted
 * walker treats lower-height roots as trusted, so low fixtures would
 * false-pass. blocker_reset_for_testing() wraps each case (the blocker
 * registry is process-global). */

static int32_t band_anchor_height(void)
{
    const struct sha3_utxo_checkpoint *cp = get_sha3_utxo_checkpoint();
    return cp ? cp->height : REDUCER_FRONTIER_TRUSTED_ANCHOR;
}

static void band_make_block(struct block_index *bi, int32_t height,
                            struct block_index *prev, uint64_t work,
                            uint8_t tag)
{
    block_index_init(bi);
    bi->hashBlock.data[0] = tag;
    bi->hashBlock.data[1] = (uint8_t)(height & 0xff);
    bi->hashBlock.data[2] = (uint8_t)((height >> 8) & 0xff);
    bi->phashBlock = &bi->hashBlock;
    bi->nHeight = height;
    bi->pprev = prev;
    arith_uint256_set_u64(&bi->nChainWork, work);
}

static int test_sync_service_band_continue_is_progress_not_restart(void)
{
    int failures = 0;

    TEST("sync_service treats frontier-extending band batches as progress") {
        struct active_chain chain;
        struct block_index f0, f1, f2, low_fork;
        struct block_index is[6];
        const int32_t anchor = band_anchor_height();

        blocker_reset_for_testing();
        syncsvc_header_band_reset_for_testing();
        active_chain_init(&chain);

        /* Trust-rooted frontier segment rooted at anchor+1. */
        band_make_block(&f0, anchor + 1, NULL, 1, 0x10);
        band_make_block(&f1, anchor + 2, &f0, 2, 0x11);
        band_make_block(&f2, anchor + 3, &f1, 3, 0x12);
        ASSERT(active_chain_move_window_tip(&chain, &f2));

        /* Detached island above the band: contiguous internally, root
         * pprev-less at anchor+100, chainwork understated at 0. */
        for (int k = 0; k < 6; k++)
            band_make_block(&is[k], anchor + 100 + k,
                            k ? &is[k - 1] : NULL, 0, (uint8_t)(0x20 + k));
        ASSERT(active_chain_install_tip_slot(&chain, &is[5]));

        /* A low batch that extends the frontier is PROGRESS — and the
         * derivation records the band fact loudly. */
        ASSERT(syncsvc_header_band_continue(&chain, &f2));
        ASSERT(blocker_exists(HEADER_BAND_BLOCKER_ID));

        /* An island-side header is not band fill. */
        ASSERT(!syncsvc_header_band_continue(&chain, &is[1]));

        /* A detached low fork buys no restart-suppression. */
        band_make_block(&low_fork, anchor + 50, NULL, 0, 0x30);
        ASSERT(!syncsvc_header_band_continue(&chain, &low_fork));

        /* Band fill vetoes restart-from-tip; the existing truth table
         * holds when no band fill is in progress. */
        ASSERT(!syncsvc_should_restart_headers_from_tip(
            160, &f2, anchor + 105, anchor + 305, true));
        ASSERT(syncsvc_should_restart_headers_from_tip(
            160, &f2, anchor + 105, anchor + 305, false));

        blocker_reset_for_testing();
        syncsvc_header_band_reset_for_testing();  /* cursor points at stack */
        active_chain_free(&chain);
        PASS();
    } _test_next:;

    return failures;
}

static int test_sync_service_band_backfill_anchor_selects_frontier(void)
{
    int failures = 0;

    TEST("sync_service anchors band backfill at the contiguous frontier") {
        struct active_chain chain, rooted;
        struct block_index f0, f1, f2;
        struct block_index is[6];
        struct blocker_record br;
        const int32_t anchor = band_anchor_height();

        blocker_reset_for_testing();
        syncsvc_header_band_reset_for_testing();
        active_chain_init(&chain);
        active_chain_init(&rooted);

        band_make_block(&f0, anchor + 1, NULL, 1, 0x10);
        band_make_block(&f1, anchor + 2, &f0, 2, 0x11);
        band_make_block(&f2, anchor + 3, &f1, 3, 0x12);
        ASSERT(active_chain_move_window_tip(&chain, &f2));
        for (int k = 0; k < 6; k++)
            band_make_block(&is[k], anchor + 100 + k,
                            k ? &is[k - 1] : NULL, 0, (uint8_t)(0x20 + k));
        ASSERT(active_chain_install_tip_slot(&chain, &is[5]));

        /* No band fact recorded → NULL (the O(1) healthy-node path). */
        ASSERT(syncsvc_header_band_backfill_anchor(&chain) == NULL);

        ASSERT(blocker_init(&br, HEADER_BAND_BLOCKER_ID, "unit",
                            BLOCKER_DEPENDENCY, "unit fixture"));
        ASSERT(blocker_set(&br) >= 0);

        /* Band fact + detached tip → the highest populated slot below
         * the island root (band slots are NULL by construction). */
        ASSERT(syncsvc_header_band_backfill_anchor(&chain) == &f2);

        /* Fully trust-rooted chain → NULL even with the fact recorded
         * (closure is after_batch's job, not the anchor selector's). */
        ASSERT(active_chain_move_window_tip(&rooted, &f2));
        ASSERT(syncsvc_header_band_backfill_anchor(&rooted) == NULL);

        blocker_reset_for_testing();
        syncsvc_header_band_reset_for_testing();
        active_chain_free(&chain);
        active_chain_free(&rooted);
        PASS();
    } _test_next:;

    return failures;
}

static int test_sync_service_header_band_dumpstate(void)
{
    int failures = 0;

    TEST("sync_service exposes header band backfill via dumpstate") {
        struct main_state ms;
        struct block_index f0, f1, f2;
        struct block_index is[6];
        struct blocker_record br;
        const int32_t anchor = band_anchor_height();

        blocker_reset_for_testing();
        syncsvc_header_band_reset_for_testing();
        main_state_init(&ms);

        band_make_block(&f0, anchor + 1, NULL, 1, 0x10);
        band_make_block(&f1, anchor + 2, &f0, 2, 0x11);
        band_make_block(&f2, anchor + 3, &f1, 3, 0x12);
        ASSERT(active_chain_move_window_tip(&ms.chain_active, &f2));
        for (int k = 0; k < 6; k++)
            band_make_block(&is[k], anchor + 100 + k,
                            k ? &is[k - 1] : NULL, 0,
                            (uint8_t)(0x20 + k));
        ASSERT(active_chain_install_tip_slot(&ms.chain_active, &is[5]));
        ASSERT(blocker_init(&br, HEADER_BAND_BLOCKER_ID, "unit",
                            BLOCKER_DEPENDENCY, "unit fixture"));
        ASSERT(blocker_set(&br) >= 0);

        diagnostics_controller_set_state(&ms, "");
        struct json_value params;
        json_init(&params);
        json_set_array(&params);
        struct json_value sub;
        json_init(&sub);
        json_set_str(&sub, "header_band");
        ASSERT(json_push_back(&params, &sub));
        json_free(&sub);

        struct json_value result;
        json_init(&result);
        ASSERT(diag_rpc_dumpstate(&params, false, &result));
        const struct json_value *state = json_get(&result, "state");
        ASSERT(state != NULL && state->type == JSON_OBJ);
        ASSERT_STR_EQ(json_get_str(json_get(state, "state")), "backfilling");
        ASSERT(json_get_bool(json_get(state, "blocker_recorded")));
        ASSERT(json_get_bool(json_get(state, "band_open")));
        ASSERT(json_get_int(json_get(state, "active_tip_height")) ==
               anchor + 105);
        ASSERT(json_get_int(json_get(state, "island_root_height")) ==
               anchor + 100);
        ASSERT(json_get_int(json_get(state, "backfill_anchor_height")) ==
               anchor + 3);
        ASSERT(json_get_int(json_get(state, "remaining_headers")) == 97);

        json_free(&result);
        json_free(&params);
        diagnostics_controller_set_state(NULL, "");
        blocker_reset_for_testing();
        syncsvc_header_band_reset_for_testing();
        main_state_free(&ms);
        PASS();
    } _test_next:;

    return failures;
}

/* Defect #7 regression: a band walk that accepts
 * batches into the BLOCK INDEX without populating active-chain slots
 * pins the slot-derived kick anchor one batch back, and the
 * peer re-served the same already-known range (3,141,534..3,141,693,
 * accepted=160 newly_added=0) forever — nothing in that path populates
 * slots, so the anchor never advanced: livelock. The anchor must follow
 * the INDEX trust-rooted frontier, and an all-known batch must still
 * advance it. */
static int test_sync_service_band_anchor_follows_index_frontier(void)
{
    int failures = 0;

    TEST("band anchor follows the index frontier past stale slots (defect #7)") {
        struct active_chain chain;
        struct block_index f[8];
        struct block_index is[4];
        struct blocker_record br;
        const int32_t anchor = band_anchor_height();

        blocker_reset_for_testing();
        syncsvc_header_band_reset_for_testing();
        active_chain_init(&chain);

        /* Trust-rooted index segment anchor+1..anchor+8; only the first
         * THREE are slotted (the boot-restored extent) — f[3..7] are
         * index-only, exactly the live shape: header acceptance inserts
         * into the index, never into chain[] slots. */
        for (int k = 0; k < 8; k++)
            band_make_block(&f[k], anchor + 1 + k, k ? &f[k - 1] : NULL,
                            (uint64_t)(k + 1), (uint8_t)(0x50 + k));
        ASSERT(active_chain_move_window_tip(&chain, &f[2]));

        /* Detached island above the band (pprev-less root). */
        for (int k = 0; k < 4; k++)
            band_make_block(&is[k], anchor + 100 + k,
                            k ? &is[k - 1] : NULL, 0, (uint8_t)(0x60 + k));
        ASSERT(active_chain_install_tip_slot(&chain, &is[3]));

        ASSERT(blocker_init(&br, HEADER_BAND_BLOCKER_ID, "unit",
                            BLOCKER_DEPENDENCY, "unit fixture"));
        ASSERT(blocker_set(&br) >= 0);

        /* Before any batch: the slot frontier (f[2]) is the only
         * authority — the boot anchor. */
        ASSERT(syncsvc_header_band_backfill_anchor(&chain) == &f[2]);

        /* The livelock batch: every header already known (newly_added==0),
         * tail f[7] trust-rooted below the island. It is still PROGRESS
         * and the anchor must advance to the INDEX frontier — re-deriving
         * the stale slot anchor makes the peer re-serve f[3]..f[7]
         * forever. */
        ASSERT(syncsvc_header_band_continue(&chain, &f[7]));
        ASSERT(syncsvc_header_band_backfill_anchor(&chain) == &f[7]);

        /* Monotone: a re-served LOWER batch (a late response to an old
         * request) must not drag the anchor back below the frontier. */
        ASSERT(syncsvc_header_band_continue(&chain, &f[5]));
        ASSERT(syncsvc_header_band_backfill_anchor(&chain) == &f[7]);

        /* The cursor is a hint, never an authority: tear f[7] off the
         * trust root (repair ladders can rewrite ancestry) and the
         * selector must drop it and fall back to the slot frontier
         * rather than serve a detached anchor. */
        f[3].pprev = NULL;
        ASSERT(syncsvc_header_band_backfill_anchor(&chain) == &f[2]);
        f[3].pprev = &f[2];    /* relink; cursor re-establishes below */
        ASSERT(syncsvc_header_band_continue(&chain, &f[4]));
        ASSERT(syncsvc_header_band_backfill_anchor(&chain) == &f[4]);

        blocker_reset_for_testing();
        syncsvc_header_band_reset_for_testing();  /* cursor points at stack */
        active_chain_free(&chain);
        PASS();
    } _test_next:;

    return failures;
}

static int test_sync_service_band_closed_after_relink(void)
{
    int failures = 0;

    TEST("sync_service closes the band once the island root relinks") {
        struct main_state ms;
        struct block_index f0, f1, f2, b3, i0, i1;
        struct blocker_record br;
        const int32_t anchor = band_anchor_height();

        blocker_reset_for_testing();
        syncsvc_header_band_reset_for_testing();
        main_state_init(&ms);

        band_make_block(&f0, anchor + 1, NULL, 1, 0x40);
        band_make_block(&f1, anchor + 2, &f0, 2, 0x41);
        band_make_block(&f2, anchor + 3, &f1, 3, 0x42);
        /* The band block the peer back-filled. */
        band_make_block(&b3, anchor + 4, &f2, 4, 0x43);
        /* Island: root pprev-less, chainwork understated at 0. */
        band_make_block(&i0, anchor + 5, NULL, 0, 0x44);
        band_make_block(&i1, anchor + 6, &i0, 0, 0x45);

        ASSERT(active_chain_move_window_tip(&ms.chain_active, &b3));
        ASSERT(active_chain_install_tip_slot(&ms.chain_active, &i1));

        ASSERT(blocker_init(&br, HEADER_BAND_BLOCKER_ID, "unit",
                            BLOCKER_DEPENDENCY, "unit fixture"));
        ASSERT(blocker_set(&br) >= 0);

        /* Island root still pprev-less → band open → NO clear. */
        syncsvc_header_band_after_batch(&ms, &b3);
        ASSERT(blocker_exists(HEADER_BAND_BLOCKER_ID));

        /* The peer re-served the island root: hash-bound relink (heights
         * contiguous) — exactly what accept_block_header does live. */
        i0.pprev = &b3;
        ASSERT(arith_uint256_is_zero(&i1.nChainWork));
        /* The island root was never slotted (install_tip_slot published
         * the tip only) — the closure slot-fill must heal it. */
        ASSERT(active_chain_at(&ms.chain_active, anchor + 5) == NULL);

        syncsvc_header_band_after_batch(&ms, &i1);

        /* Closed: fact cleared + island chainwork repropagated upward
         * from the trust-rooted segment (strictly greater than the
         * understated 0 it was seeded with). */
        ASSERT(!blocker_exists(HEADER_BAND_BLOCKER_ID));
        ASSERT(!arith_uint256_is_zero(&i1.nChainWork));
        ASSERT(!arith_uint256_is_zero(&i0.nChainWork));

        /* The in-memory slot-fill healed active_chain_at across the
         * island WITHOUT disturbing the slots below it — the closure is
         * non-destructive by construction (no disk rebuild, no pprev
         * mutation, no slot ever set to NULL). */
        ASSERT(active_chain_at(&ms.chain_active, anchor + 5) == &i0);
        ASSERT(active_chain_at(&ms.chain_active, anchor + 6) == &i1);
        ASSERT(active_chain_at(&ms.chain_active, anchor + 4) == &b3);
        ASSERT(active_chain_at(&ms.chain_active, anchor + 3) == &f2);
        ASSERT(active_chain_at(&ms.chain_active, anchor + 1) == &f0);
        ASSERT(i0.pprev == &b3 && b3.pprev == &f2);

        blocker_reset_for_testing();
        syncsvc_header_band_reset_for_testing();  /* cursor points at stack */
        block_map_free(&ms.map_block_index);
        active_chain_free(&ms.chain_active);
        PASS();
    } _test_next:;

    return failures;
}

static int test_sync_service_band_producer_derives_from_ancestry(void)
{
    int failures = 0;

    TEST("band producers derive the fact from ancestry, not the log frontier") {
        struct block_index f0, f1, f2, island;
        const int32_t anchor = band_anchor_height();

        blocker_reset_for_testing();

        /* Trust-rooted chain — the clean two-step cold-import shape:
         * imported headers are pprev-contiguous down to the trust root.
         * The retired log-frontier derivation false-recorded a band here
         * on a fresh progress db (an empty validate_headers log collapses
         * the frontier to the compiled SHA3 anchor — it does NOT abstain)
         * and the first accepted batch then fired a false closure. The
         * ancestry derivation must abstain. */
        band_make_block(&f0, anchor + 1, NULL, 1, 0x50);
        band_make_block(&f1, anchor + 2, &f0, 2, 0x51);
        band_make_block(&f2, anchor + 3, &f1, 3, 0x52);
        utxo_recovery_note_band_unrooted_tip(&f2, "unit_contiguous");
        ASSERT(!blocker_exists(HEADER_BAND_BLOCKER_ID));

        /* A pprev-less anchor installed above the trust root IS the
         * island root — the fact must be recorded. */
        band_make_block(&island, anchor + 100, NULL, 0, 0x53);
        utxo_recovery_note_band_unrooted_tip(&island, "unit_island");
        ASSERT(blocker_exists(HEADER_BAND_BLOCKER_ID));

        blocker_reset_for_testing();
        PASS();
    } _test_next:;

    return failures;
}

static int test_sync_service_builds_getheaders_locator_from_chain(void)
{
    int failures = 0;

    TEST("sync_service builds getheaders locator with genesis fallback and suffix") {
        struct active_chain chain;
        struct uint256 hg = {0}, h1 = {0}, h2 = {0};
        struct block_index genesis, b1, b2;
        struct block_locator loc;

        memset(&chain, 0, sizeof(chain));
        memset(&genesis, 0, sizeof(genesis));
        memset(&b1, 0, sizeof(b1));
        memset(&b2, 0, sizeof(b2));
        block_index_init(&genesis);
        block_index_init(&b1);
        block_index_init(&b2);
        active_chain_init(&chain);

        hg.data[0] = 50; h1.data[0] = 51; h2.data[0] = 52;
        genesis.phashBlock = &hg; genesis.nHeight = 0;
        b1.phashBlock = &h1; b1.nHeight = 1; b1.pprev = &genesis;
        b2.phashBlock = &h2; b2.nHeight = 2; b2.pprev = &b1;
        ASSERT(active_chain_move_window_tip(&chain, &b2));

        ASSERT(syncsvc_build_getheaders_locator(&loc, &chain, NULL, NULL, &hg).ok);
        ASSERT(loc.num_hashes >= 2);
        ASSERT(uint256_eq(&loc.vhave[0], &h2));
        ASSERT(uint256_eq(&loc.vhave[1], &h1));
        ASSERT(uint256_eq(&loc.vhave[loc.num_hashes - 1], &hg));
        block_locator_free(&loc);

        active_chain_free(&chain);
        PASS();
    } _test_next:;

    return failures;
}

static int test_sync_service_builds_getheaders_locator_empty_chain(void)
{
    int failures = 0;

    TEST("sync_service builds genesis-only locator when chain is empty") {
        struct active_chain chain;
        struct uint256 hg = {0};
        struct block_locator loc;

        memset(&chain, 0, sizeof(chain));
        active_chain_init(&chain);
        hg.data[0] = 60;

        ASSERT(syncsvc_build_getheaders_locator(&loc, &chain, NULL, NULL, &hg).ok);
        ASSERT(loc.num_hashes == 1);
        ASSERT(uint256_eq(&loc.vhave[0], &hg));
        block_locator_free(&loc);
        active_chain_free(&chain);
        PASS();
    } _test_next:;

    return failures;
}

/* THE LINCHPIN regression: a full-index boot leaves the active_chain window
 * empty (active_chain_tip()==NULL) even though the header frontier is known.
 * The locator must anchor at that frontier (best_header_fallback), NEVER
 * collapse to a genesis-only locator that pins header sync near genesis. */
static int test_sync_service_locator_uses_best_header_when_window_empty(void)
{
    int failures = 0;

    TEST("sync_service anchors locator at best_header when active window empty") {
        struct active_chain chain;
        struct uint256 hg = {0}, h1 = {0}, h2 = {0};
        struct block_index genesis, b1, b2;
        struct block_locator loc;

        memset(&chain, 0, sizeof(chain));
        memset(&genesis, 0, sizeof(genesis));
        memset(&b1, 0, sizeof(b1));
        memset(&b2, 0, sizeof(b2));
        block_index_init(&genesis);
        block_index_init(&b1);
        block_index_init(&b2);
        active_chain_init(&chain);

        hg.data[0] = 70; h1.data[0] = 71; h2.data[0] = 72;
        genesis.phashBlock = &hg; genesis.nHeight = 0;
        b1.phashBlock = &h1; b1.nHeight = 1; b1.pprev = &genesis;
        b2.phashBlock = &h2; b2.nHeight = 2; b2.pprev = &b1;

        /* Deliberately DO NOT seat the active_chain window — active_chain_tip()
         * is NULL, exactly the full-index-boot state. b2 is the header
         * frontier (max height) supplied as the fallback anchor. */
        ASSERT(active_chain_tip(&chain) == NULL);
        ASSERT(syncsvc_build_getheaders_locator(&loc, &chain, NULL, &b2, &hg).ok);
        /* Anchored at the frontier, not a bare genesis-only locator. */
        ASSERT(loc.num_hashes >= 2);
        ASSERT(uint256_eq(&loc.vhave[0], &h2));
        ASSERT(!uint256_eq(&loc.vhave[0], &hg));
        ASSERT(uint256_eq(&loc.vhave[loc.num_hashes - 1], &hg));
        block_locator_free(&loc);

        active_chain_free(&chain);
        PASS();
    } _test_next:;

    return failures;
}

static int test_sync_service_header_log_policy(void)
{
    int failures = 0;

    TEST("sync_service chooses header request log mode from sync state") {
        struct p2p_node node;
        struct uint256 h = {0};
        struct block_index tip;

        memset(&node, 0, sizeof(node));
        memset(&tip, 0, sizeof(tip));
        h.data[0] = 7;
        tip.phashBlock = &h;
        tip.nHeight = 50;

        ASSERT(syncsvc_header_log_mode(&node, &tip, false) ==
               SYNC_HEADER_LOG_TIP);
        ASSERT(syncsvc_header_log_mode(&node, &tip, true) ==
               SYNC_HEADER_LOG_IBD);
        ASSERT(syncsvc_header_log_mode(&node, &tip, true) ==
               SYNC_HEADER_LOG_NONE);
        ASSERT(syncsvc_header_log_mode(&node, NULL, false) ==
               SYNC_HEADER_LOG_NONE);
        PASS();
    } _test_next:;

    return failures;
}

static int test_sync_service_progress_snapshot(void)
{
    int failures = 0;

    TEST("sync_service progress snapshot reflects download manager") {
        struct download_manager dm;
        struct sync_progress_snapshot snapshot;
        struct uint256 h;
        memset(&h, 0, sizeof(h));
        h.data[0] = 1;

        dl_init(&dm);
        ASSERT(dl_mark_requested(&dm, &h, 42, 1));
        dl_add_bytes_received(&dm, 8 * 1024 * 1024);

        syncsvc_collect_progress(&snapshot, &dm, SYNC_BLOCKS_DOWNLOAD,
                                 100, 120, 0, 1000);
        ASSERT(snapshot.should_log_progress);
        ASSERT(snapshot.requested == 1);
        ASSERT(snapshot.in_flight == 1);
        ASSERT(snapshot.chain_height == 100);
        ASSERT(snapshot.header_height == 120);
        ASSERT(snapshot.mbps_avg >= 0.0);

        dl_free(&dm);
        PASS();
    } _test_next:;

    return failures;
}

static int test_sync_service_tip_stale_threshold(void)
{
    int failures = 0;

    TEST("sync_service marks tip stale only after threshold") {
        struct sync_progress_snapshot snapshot;

        syncsvc_collect_progress(&snapshot, NULL, SYNC_AT_TIP,
                                 200, 200, 100, 650);
        ASSERT(!snapshot.tip_stale);
        ASSERT(snapshot.tip_stale_seconds == 550);
        ASSERT(!snapshot.should_log_progress);

        syncsvc_collect_progress(&snapshot, NULL, SYNC_AT_TIP,
                                 200, 200, 100, 701);
        ASSERT(snapshot.tip_stale);
        ASSERT(snapshot.tip_stale_seconds == 601);
        PASS();
    } _test_next:;

    return failures;
}

static int test_sync_service_tip_stale_warning_throttle(void)
{
    int failures = 0;

    TEST("sync_service throttles repeated stale-tip warnings") {
        struct sync_progress_snapshot snapshot;
        struct p2p_node node;

        memset(&snapshot, 0, sizeof(snapshot));
        memset(&node, 0, sizeof(node));
        snapshot.tip_stale = true;

        ASSERT(syncsvc_should_warn_tip_stale(&snapshot, &node, 1000));
        ASSERT(!syncsvc_should_warn_tip_stale(&snapshot, &node, 1200));
        ASSERT(syncsvc_should_warn_tip_stale(&snapshot, &node, 1301));

        node.inbound = true;
        ASSERT(!syncsvc_should_warn_tip_stale(&snapshot, &node, 1700));

        snapshot.tip_stale = false;
        node.inbound = false;
        ASSERT(!syncsvc_should_warn_tip_stale(&snapshot, &node, 2000));
        PASS();
    } _test_next:;

    return failures;
}

static int test_sync_service_tip_stale_getheaders_action(void)
{
    int failures = 0;

    TEST("sync_service plans tip-stale getheaders action") {
        struct sync_progress_snapshot snapshot;
        struct p2p_node node;
        struct sync_getheaders_action action;

        memset(&snapshot, 0, sizeof(snapshot));
        memset(&node, 0, sizeof(node));
        memset(&action, 0, sizeof(action));
        snapshot.tip_stale = true;

        syncsvc_plan_tip_stale_getheaders(&action, &snapshot, &node, 5000);
        ASSERT(action.should_send);
        ASSERT(action.anchor == SYNC_HEADER_REQUEST_TIP);
        ASSERT(action.should_log);
        PASS();
    } _test_next:;

    return failures;
}

static int test_sync_service_header_activation_policy(void)
{
    int failures = 0;

    TEST("sync_service decides chain activation from scan and header-processing results") {
        struct sync_header_processing_plan plan;
        struct sync_chain_activation activation;

        memset(&plan, 0, sizeof(plan));
        memset(&activation, 0, sizeof(activation));
        ASSERT(!syncsvc_should_activate_after_block_file_scan(0));
        ASSERT(syncsvc_should_activate_after_block_file_scan(3));
        syncsvc_build_block_file_scan_activation(&activation, 0);
        ASSERT(!activation.should_activate);
        syncsvc_build_block_file_scan_activation(&activation, 3);
        ASSERT(activation.should_activate);

        ASSERT(!syncsvc_should_activate_after_header_processing(&plan));
        plan.download.needed_blocks.should_activate_chain = true;
        plan.should_activate_chain = true;
        ASSERT(syncsvc_should_activate_after_header_processing(&plan));
        syncsvc_build_header_processing_activation(&activation, &plan);
        ASSERT(activation.should_activate);
        ASSERT(!syncsvc_should_activate_after_header_processing(NULL));
        PASS();
    } _test_next:;

    return failures;
}

static int test_sync_service_recovery_getheaders_action(void)
{
    int failures = 0;

    TEST("sync_service plans recovery getheaders action from tip parent when available") {
        struct sync_stall_recovery recovery;
        struct sync_getheaders_action action;
        struct block_index tip, parent;

        memset(&recovery, 0, sizeof(recovery));
        memset(&action, 0, sizeof(action));
        memset(&tip, 0, sizeof(tip));
        memset(&parent, 0, sizeof(parent));

        recovery.should_recover = true;
        recovery.should_request_tip_parent = true;
        tip.pprev = &parent;

        syncsvc_plan_recovery_getheaders(&action, &recovery, &tip);
        ASSERT(action.should_send);
        ASSERT(action.anchor == SYNC_HEADER_REQUEST_TIP_PARENT);
        ASSERT(!action.should_log);
        PASS();
    } _test_next:;

    return failures;
}

static int test_sync_service_valid_block_transition(void)
{
    int failures = 0;

    TEST("sync_service transitions to at-tip when blocks and headers catch peer height") {
        struct p2p_node node;
        struct sync_block_acceptance result;

        memset(&node, 0, sizeof(node));
        memset(&result, 0, sizeof(result));
        node.id = 5;
        node.state = PEER_SYNCING_BLOCKS;
        node.starting_height = 100;

        syncsvc_note_valid_block(&result, &node, SYNC_BLOCKS_DOWNLOAD, 100, 100, 0, 0, BODY_HISTORY_COMPLETE);
        ASSERT(result.reached_peer_tip);
        ASSERT(result.should_emit_tip_updated);
        ASSERT(result.should_set_sync_state);
        ASSERT(result.next_sync_state == SYNC_AT_TIP);
        ASSERT(result.should_set_flush_policy);
        ASSERT(result.should_update_peer_state);
        ASSERT(result.next_peer_state == PEER_ACTIVE);
        PASS();
    } _test_next:;

    return failures;
}

static int test_sync_service_valid_block_waits_for_headers(void)
{
    int failures = 0;

    TEST("sync_service does not transition to at-tip while headers are still ahead") {
        struct p2p_node node;
        struct sync_block_acceptance result;

        memset(&node, 0, sizeof(node));
        memset(&result, 0, sizeof(result));
        node.id = 6;
        node.state = PEER_SYNCING_BLOCKS;
        node.starting_height = 100;

        syncsvc_note_valid_block(&result, &node, SYNC_BLOCKS_DOWNLOAD, 100, 125, 0, 0, BODY_HISTORY_COMPLETE);
        ASSERT(result.reached_peer_tip);
        ASSERT(!result.should_set_sync_state);
        ASSERT(!result.should_emit_tip_updated);
        ASSERT(!result.should_update_peer_state);
        PASS();
    } _test_next:;

    return failures;
}

static int test_sync_service_header_chain_policy(void)
{
    int failures = 0;

    TEST("sync_service recognizes headers that chain from our tip") {
        struct uint256 h0 = {0}, h1 = {0}, h2 = {0}, hf = {0};
        struct block_index genesis, tip, next, fork;

        memset(&genesis, 0, sizeof(genesis));
        memset(&tip, 0, sizeof(tip));
        memset(&next, 0, sizeof(next));
        memset(&fork, 0, sizeof(fork));
        block_index_init(&genesis);
        block_index_init(&tip);
        block_index_init(&next);
        block_index_init(&fork);

        h0.data[0] = 1; h1.data[0] = 2; h2.data[0] = 3; hf.data[0] = 4;
        genesis.phashBlock = &h0; genesis.nHeight = 0;
        tip.phashBlock = &h1; tip.nHeight = 1; tip.pprev = &genesis;
        next.phashBlock = &h2; next.nHeight = 2; next.pprev = &tip;
        fork.phashBlock = &hf; fork.nHeight = 2; fork.pprev = &genesis;

        ASSERT(syncsvc_should_begin_blocks_download(SYNC_HEADERS_DOWNLOAD,
                                                    &next, 1));
        ASSERT(syncsvc_headers_chain_from_tip(&next, &tip, 1));
        ASSERT(!syncsvc_headers_chain_from_tip(&fork, &tip, 1));
        PASS();
    } _test_next:;

    return failures;
}

static int test_sync_service_builds_alt_recovery_plan(void)
{
    int failures = 0;

    TEST("sync_service finds same-chain alternate blocks for stall recovery") {
        struct main_state ms;
        struct p2p_node node;
        struct sync_stall_recovery recovery;
        struct uint256 hg = {0}, h1 = {0}, h2 = {0}, h3 = {0}, h4 = {0};
        struct block_index g, b1, alt2, alt3, fork2;

        memset(&node, 0, sizeof(node));
        memset(&g, 0, sizeof(g));
        memset(&b1, 0, sizeof(b1));
        memset(&alt2, 0, sizeof(alt2));
        memset(&alt3, 0, sizeof(alt3));
        memset(&fork2, 0, sizeof(fork2));
        main_state_init(&ms);
        block_index_init(&g);
        block_index_init(&b1);
        block_index_init(&alt2);
        block_index_init(&alt3);
        block_index_init(&fork2);

        hg.data[0] = 1; h1.data[0] = 2; h2.data[0] = 3; h3.data[0] = 4; h4.data[0] = 5;
        g.phashBlock = &hg; g.nHeight = 0;
        b1.phashBlock = &h1; b1.nHeight = 1; b1.pprev = &g;
        alt2.phashBlock = &h2; alt2.nHeight = 2; alt2.pprev = &b1;
        alt3.phashBlock = &h3; alt3.nHeight = 3; alt3.pprev = &alt2;
        fork2.phashBlock = &h4; fork2.nHeight = 2; fork2.pprev = &g;
        block_map_insert(&ms.map_block_index, &hg, &g);
        block_map_insert(&ms.map_block_index, &h1, &b1);
        block_map_insert(&ms.map_block_index, &h2, &alt2);
        block_map_insert(&ms.map_block_index, &h3, &alt3);
        block_map_insert(&ms.map_block_index, &h4, &fork2);
        ASSERT(active_chain_move_window_tip(&ms.chain_active, &b1));

        node.state = PEER_SYNCING_BLOCKS;
        node.starting_height = 30;
        ASSERT(syncsvc_build_stall_recovery(&recovery, &ms, &node, 0, 0, 1000));
        ASSERT(recovery.should_recover);
        ASSERT(recovery.next_height == 2);
        ASSERT(recovery.alt_count == 2);
        ASSERT(recovery.should_request_tip_parent);
        ASSERT(!recovery.should_reset_tip_next);
        syncsvc_free_stall_recovery(&recovery);
        main_state_free(&ms);
        PASS();
    } _test_next:;

    return failures;
}

static int test_sync_service_requests_reset_when_no_alts(void)
{
    int failures = 0;

    TEST("sync_service requests reset when no alternate blocks exist") {
        struct main_state ms;
        struct p2p_node node;
        struct sync_stall_recovery recovery;
        struct uint256 hg = {0}, h1 = {0}, h2 = {0};
        struct block_index g, b1, bad2;

        memset(&node, 0, sizeof(node));
        memset(&g, 0, sizeof(g));
        memset(&b1, 0, sizeof(b1));
        memset(&bad2, 0, sizeof(bad2));
        main_state_init(&ms);
        block_index_init(&g);
        block_index_init(&b1);
        block_index_init(&bad2);

        hg.data[0] = 11; h1.data[0] = 12; h2.data[0] = 13;
        g.phashBlock = &hg; g.nHeight = 0;
        b1.phashBlock = &h1; b1.nHeight = 1; b1.pprev = &g;
        bad2.phashBlock = &h2; bad2.nHeight = 2; bad2.pprev = &b1;
        bad2.nStatus = BLOCK_HAVE_DATA | BLOCK_FAILED_VALID;
        block_map_insert(&ms.map_block_index, &hg, &g);
        block_map_insert(&ms.map_block_index, &h1, &b1);
        block_map_insert(&ms.map_block_index, &h2, &bad2);
        ASSERT(active_chain_move_window_tip(&ms.chain_active, &b1));

        node.state = PEER_SYNCING_BLOCKS;
        node.starting_height = 30;
        ASSERT(syncsvc_build_stall_recovery(&recovery, &ms, &node, 0, 0, 2000));
        ASSERT(recovery.should_recover);
        ASSERT(recovery.alt_count == 0);
        ASSERT(recovery.should_reset_tip_next);
        syncsvc_free_stall_recovery(&recovery);
        main_state_free(&ms);
        PASS();
    } _test_next:;

    return failures;
}

static int test_sync_service_applies_alt_recovery(void)
{
    int failures = 0;

    TEST("sync_service apply queues alternate blocks into download manager") {
        struct main_state ms;
        struct download_manager dm;
        struct sync_stall_recovery recovery;
        struct uint256 h1 = {0}, h2 = {0};
        int cleared = -1;

        memset(&recovery, 0, sizeof(recovery));
        h1.data[0] = 21;
        h2.data[0] = 22;
        main_state_init(&ms);
        dl_init(&dm);

        recovery.alt_hashes = zcl_calloc(2, sizeof(struct uint256), "test_alt_hashes");
        recovery.alt_heights = zcl_calloc(2, sizeof(int32_t), "test_alt_heights");
        ASSERT(recovery.alt_hashes != NULL);
        ASSERT(recovery.alt_heights != NULL);
        recovery.alt_hashes[0] = h1;
        recovery.alt_hashes[1] = h2;
        recovery.alt_heights[0] = 10;
        recovery.alt_heights[1] = 11;
        recovery.alt_count = 2;

        syncsvc_apply_stall_recovery(&recovery, &ms, &dm, &cleared);
        ASSERT(cleared == 0);
        {
            uint64_t req = 0, recv = 0, tout = 0, inflight = 0, queued = 0;
            dl_get_stats(&dm, &req, &recv, &tout, &inflight, &queued);
            ASSERT(queued == 2);
            ASSERT(inflight == 0);
        }

        syncsvc_free_stall_recovery(&recovery);
        dl_free(&dm);
        main_state_free(&ms);
        PASS();
    } _test_next:;

    return failures;
}

static int test_sync_service_applies_reset_recovery(void)
{
    int failures = 0;

    TEST("sync_service apply preserves failed/data flags at stalled height") {
        struct main_state ms;
        struct download_manager dm;
        struct sync_stall_recovery recovery;
        struct uint256 hg = {0}, h1 = {0}, h2 = {0};
        struct block_index g, b1, stuck2;
        int cleared = 0;

        memset(&recovery, 0, sizeof(recovery));
        memset(&g, 0, sizeof(g));
        memset(&b1, 0, sizeof(b1));
        memset(&stuck2, 0, sizeof(stuck2));
        main_state_init(&ms);
        dl_init(&dm);
        block_index_init(&g);
        block_index_init(&b1);
        block_index_init(&stuck2);

        hg.data[0] = 31; h1.data[0] = 32; h2.data[0] = 33;
        g.phashBlock = &hg; g.nHeight = 0;
        b1.phashBlock = &h1; b1.nHeight = 1; b1.pprev = &g;
        stuck2.phashBlock = &h2; stuck2.nHeight = 2; stuck2.pprev = &b1;
        stuck2.nStatus = BLOCK_HAVE_DATA | BLOCK_FAILED_VALID;
        block_map_insert(&ms.map_block_index, &hg, &g);
        block_map_insert(&ms.map_block_index, &h1, &b1);
        block_map_insert(&ms.map_block_index, &h2, &stuck2);

        recovery.should_reset_tip_next = true;
        recovery.next_height = 2;
        syncsvc_apply_stall_recovery(&recovery, &ms, &dm, &cleared);
        ASSERT(cleared == 0);
        ASSERT((stuck2.nStatus & BLOCK_FAILED_MASK) != 0);
        ASSERT((stuck2.nStatus & BLOCK_HAVE_DATA) != 0);

        dl_free(&dm);
        main_state_free(&ms);
        PASS();
    } _test_next:;

    return failures;
}

static int test_sync_service_recovery_header_anchor(void)
{
    int failures = 0;

    TEST("sync_service selects recovery header anchor from tip parent when available") {
        struct sync_stall_recovery recovery;
        struct block_index tip, parent;

        memset(&recovery, 0, sizeof(recovery));
        memset(&tip, 0, sizeof(tip));
        memset(&parent, 0, sizeof(parent));

        recovery.should_recover = true;
        recovery.should_request_tip_parent = true;
        tip.pprev = &parent;

        ASSERT(syncsvc_recovery_header_anchor(&recovery, &tip) ==
               SYNC_HEADER_REQUEST_TIP_PARENT);

        recovery.should_request_tip_parent = false;
        ASSERT(syncsvc_recovery_header_anchor(&recovery, &tip) ==
               SYNC_HEADER_REQUEST_TIP);

        recovery.should_request_tip_parent = true;
        tip.pprev = NULL;
        ASSERT(syncsvc_recovery_header_anchor(&recovery, &tip) ==
               SYNC_HEADER_REQUEST_TIP);

        recovery.should_recover = false;
        tip.pprev = &parent;
        ASSERT(syncsvc_recovery_header_anchor(&recovery, &tip) ==
               SYNC_HEADER_REQUEST_TIP);
        PASS();
    } _test_next:;

    return failures;
}

static int test_sync_service_false_at_tip_peer_far_ahead(void)
{
    int failures = 0;

    TEST("BUG: headers_caught_up should be false when peer is 1M blocks ahead") {
        /* Scenario: node at 2,016,354, peer starting_height 3,078,009.
         * best_header == block_height, so headers_caught_up is true
         * even though the peer is ~1M blocks ahead.
         * BUG: headers_caught_up only checks local state, not peer height
         * — see wave 20 task for Agent2 */
        struct p2p_node node;
        struct sync_block_acceptance result;

        memset(&node, 0, sizeof(node));
        memset(&result, 0, sizeof(result));
        node.id = 20;
        node.state = PEER_SYNCING_BLOCKS;
        node.starting_height = 3078009;

        syncsvc_note_valid_block(&result, &node, SYNC_BLOCKS_DOWNLOAD,
                                 2016354, 2016354, 0, 3078009, BODY_HISTORY_COMPLETE);
        /* Node hasn't reached peer starting_height, so reached_peer_tip
         * should be false and no AT_TIP transition should happen. */
        ASSERT(!result.reached_peer_tip);
        ASSERT(!result.should_set_sync_state);
        PASS();
    } _test_next:;

    return failures;
}

static int test_sync_service_genuinely_at_tip(void)
{
    int failures = 0;

    TEST("sync_service transitions to at-tip when genuinely caught up with peer") {
        struct p2p_node node;
        struct sync_block_acceptance result;

        memset(&node, 0, sizeof(node));
        memset(&result, 0, sizeof(result));
        node.id = 21;
        node.state = PEER_SYNCING_BLOCKS;
        node.starting_height = 3078009;

        syncsvc_note_valid_block(&result, &node, SYNC_BLOCKS_DOWNLOAD,
                                 3078009, 3078010, 0, 3078009, BODY_HISTORY_COMPLETE);
        ASSERT(result.reached_peer_tip);
        ASSERT(result.should_set_sync_state);
        ASSERT(result.next_sync_state == SYNC_AT_TIP);
        PASS();
    } _test_next:;

    return failures;
}

static int test_sync_service_recent_tip_bypasses_headers(void)
{
    int failures = 0;

    TEST("sync_service transitions to at-tip when tip time is recent") {
        struct p2p_node node;
        struct sync_block_acceptance result;

        memset(&node, 0, sizeof(node));
        memset(&result, 0, sizeof(result));
        node.id = 22;
        node.state = PEER_SYNCING_BLOCKS;
        node.starting_height = 3078009;

        /* Tip time is 60 seconds ago — recent enough to bypass header check */
        uint32_t recent_time = (uint32_t)(platform_time_wall_time_t() - 60);
        syncsvc_note_valid_block(&result, &node, SYNC_BLOCKS_DOWNLOAD,
                                 3078000, 1000, recent_time, 3078009, BODY_HISTORY_COMPLETE);
        ASSERT(result.should_set_sync_state);
        ASSERT(result.next_sync_state == SYNC_AT_TIP);
        PASS();
    } _test_next:;

    return failures;
}

static int test_sync_service_periodic_tip_evaluator(void)
{
    int failures = 0;

    TEST("sync_service periodic evaluator is bounded and fail-closed") {
        struct sync_tip_state_evaluation result;

        /* The published tip may intentionally trail the active tip by one. */
        syncsvc_plan_periodic_tip_state(
            &result, SYNC_BLOCKS_DOWNLOAD, true,
            /*served*/99, /*local*/100, /*header*/100, /*peer*/98,
            /*peers*/23, /*queued*/0, /*in_flight*/0, /*intake*/0,
            BODY_HISTORY_COMPLETE);
        ASSERT(result.should_set_at_tip);
        ASSERT(result.target_height == 100);
        ASSERT(result.served_gap == 1);
        ASSERT(result.local_gap == 0);

        /* Unpublished evidence and a wider served gap are not at-tip. */
        syncsvc_plan_periodic_tip_state(
            &result, SYNC_BLOCKS_DOWNLOAD, false,
            100, 100, 100, 100, 3, 0, 0, 0, BODY_HISTORY_COMPLETE);
        ASSERT(!result.should_set_at_tip);
        syncsvc_plan_periodic_tip_state(
            &result, SYNC_BLOCKS_DOWNLOAD, true,
            98, 100, 100, 100, 3, 0, 0, 0, BODY_HISTORY_COMPLETE);
        ASSERT(!result.should_set_at_tip);
        ASSERT(result.served_gap == 2);

        /* Isolation and pending body work keep the state in catch-up. */
        syncsvc_plan_periodic_tip_state(
            &result, SYNC_BLOCKS_DOWNLOAD, true,
            99, 100, 100, 100, 0, 0, 0, 0, BODY_HISTORY_COMPLETE);
        ASSERT(!result.should_set_at_tip);
        syncsvc_plan_periodic_tip_state(
            &result, SYNC_BLOCKS_DOWNLOAD, true,
            99, 100, 100, 100, 3, 1, 0, 0, BODY_HISTORY_COMPLETE);
        ASSERT(!result.should_set_at_tip);
        syncsvc_plan_periodic_tip_state(
            &result, SYNC_BLOCKS_DOWNLOAD, true,
            99, 100, 100, 100, 3, 0, 1, 0, BODY_HISTORY_COMPLETE);
        ASSERT(!result.should_set_at_tip);
        syncsvc_plan_periodic_tip_state(
            &result, SYNC_BLOCKS_DOWNLOAD, true,
            99, 100, 100, 100, 3, 0, 0, 1, BODY_HISTORY_COMPLETE);
        ASSERT(!result.should_set_at_tip);

        /* A reorg owner or an internally inconsistent frontier view wins. */
        syncsvc_plan_periodic_tip_state(
            &result, SYNC_REORG, true,
            99, 100, 100, 100, 3, 0, 0, 0, BODY_HISTORY_COMPLETE);
        ASSERT(!result.should_set_at_tip);
        syncsvc_plan_periodic_tip_state(
            &result, SYNC_BLOCKS_DOWNLOAD, true,
            99, 100, 99, 100, 3, 0, 0, 0, BODY_HISTORY_COMPLETE);
        ASSERT(!result.should_set_at_tip);
        syncsvc_plan_periodic_tip_state(
            &result, SYNC_BLOCKS_DOWNLOAD, true,
            101, 100, 100, 100, 3, 0, 0, 0, BODY_HISTORY_COMPLETE);
        ASSERT(!result.should_set_at_tip);
        PASS();
    } _test_next:;

    return failures;
}

int test_sync_service(void)
{
    int failures = 0;
    failures += test_sync_service_begin_sync();
    failures += test_sync_service_rejects_inbound_sync();
    failures += test_sync_service_keeps_caught_up_peers_active();
    failures += test_sync_service_begins_when_peer_one_block_ahead();
    failures += test_sync_service_probes_equal_peer_after_restart();
    failures += test_sync_service_probes_zero_height_onion_once();
    failures += test_sync_service_marks_caught_up_syncing_peers_active();
    failures += test_sync_service_request_policy();
    failures += test_sync_service_band_hole_forces_ibd_interval();
    failures += test_sync_service_periodic_getheaders_action();
    failures += test_sync_service_invalid_block_getheaders_action();
    failures += test_sync_service_headers_log_throttle();
    failures += test_sync_service_header_batch_followup();
    failures += test_sync_service_reject_probe_rate_limit();
    failures += test_sync_service_reject_probe_pending();
    failures += test_sync_service_block_file_scan_trigger();
    failures += test_sync_service_block_assignment_plan();
    failures += test_sync_service_assigns_peer_blocks();
    failures += test_sync_service_body_stall_disconnect();
    failures += test_sync_service_body_dark_disconnect();
    failures += test_sync_service_collects_needed_blocks_oldest_first();
    failures += test_sync_service_collects_needed_blocks_activation();
    failures += test_sync_service_collects_needed_blocks_rejects_forks();
    failures += test_sync_service_plans_header_download();
    failures += test_sync_service_plans_header_processing();
    failures += test_sync_service_plans_header_processing_activation_from_disk();
    failures += test_sync_service_restarts_low_header_batches_from_tip();
    failures += test_sync_service_band_continue_is_progress_not_restart();
    failures += test_sync_service_band_backfill_anchor_selects_frontier();
    failures += test_sync_service_header_band_dumpstate();
    failures += test_sync_service_band_anchor_follows_index_frontier();
    failures += test_sync_service_band_closed_after_relink();
    failures += test_sync_service_band_producer_derives_from_ancestry();
    failures += test_sync_service_builds_getheaders_locator_from_chain();
    failures += test_sync_service_builds_getheaders_locator_empty_chain();
    failures += test_sync_service_locator_uses_best_header_when_window_empty();
    failures += test_sync_service_header_log_policy();
    failures += test_sync_service_progress_snapshot();
    failures += test_sync_service_tip_stale_threshold();
    failures += test_sync_service_tip_stale_warning_throttle();
    failures += test_sync_service_tip_stale_getheaders_action();
    failures += test_sync_service_header_activation_policy();
    failures += test_sync_service_recovery_getheaders_action();
    failures += test_sync_service_valid_block_transition();
    failures += test_sync_service_valid_block_waits_for_headers();
    failures += test_sync_service_header_chain_policy();
    failures += test_sync_service_builds_alt_recovery_plan();
    failures += test_sync_service_requests_reset_when_no_alts();
    failures += test_sync_service_applies_alt_recovery();
    failures += test_sync_service_applies_reset_recovery();
    failures += test_sync_service_recovery_header_anchor();
    failures += test_sync_service_false_at_tip_peer_far_ahead();
    failures += test_sync_service_genuinely_at_tip();
    failures += test_sync_service_recent_tip_bypasses_headers();
    failures += test_sync_service_periodic_tip_evaluator();
    sync_set_state(SYNC_IDLE, "done");
    return failures;
}
