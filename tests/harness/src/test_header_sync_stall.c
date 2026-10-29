/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Tests for header sync stall detection and recovery:
 * per-peer tracking, stall detection, inbound fallback, and these
 * peer-retention rules (P1-P3; a P4 sibling covers download backpressure
 * and lives in test_net.c):
 *   P1 — usefulness is credited from newly_added (new-to-index
 *        headers), NOT accepted: a known-header replay neither
 *        refreshes last_useful_headers_time (rule A) nor inflates
 *        total_headers_delivered (rule B's worst-peer pick);
 *   P2 — the stale-header disconnect is skipped at frontier parity
 *        (best_header_height >= starting_height - 144): when our
 *        header frontier already matches the peer's claimed tip,
 *        getheaders cannot be "useful" by construction and a
 *        disconnect is pure churn;
 *   P3 — loopback/whitelisted peers are exempt from the stale-header
 *        rules.  The exemption lives at the production call site
 *        (msgprocessor.c stale-header rules A/B):
 *          stall_peer_trusted =
 *              net_addr_is_local(&node->addr.svc.addr) ||
 *              node->whitelisted;
 *        and both rules run only when !stall_peer_trusted — the
 *        syncsvc predicate itself is deliberately trust-agnostic.
 *        Cases 9/10 pin that seam: the rule still fires for trusted
 *        peers (no exemption hides inside it), the predicate inputs
 *        classify correctly, and the composed call-site decision
 *        exempts loopback/whitelisted while a plain remote keeps
 *        full stall discipline. */

#include "test/test_core.h"
#include "net/net.h"
#include "sync/sync_planner.h"
#include "net/netaddr.h"

/* Helper: build a minimal p2p_node for testing stall detection. */
static struct p2p_node make_stall_node(int starting_height, bool inbound,
                                       int64_t connected_time)
{
    struct p2p_node n;
    memset(&n, 0, sizeof(n));
    n.id = 1;
    n.state = PEER_SYNCING_HEADERS;
    n.starting_height = starting_height;
    n.last_getheaders_time = 0;
    n.inbound = inbound;
    n.getheaders_stale_count = 0;
    n.time_connected = connected_time;
    n.last_useful_headers_time = 0;
    n.total_headers_delivered = 0;
    return n;
}

/* Case 1: new headers update the usefulness tracking fields. */
static int check_new_headers_credit_usefulness(void)
{
    int failures = 0;

    /* ── 1. last_useful_headers_time updated on NEW headers ──────
     * The call site (process_headers, msg_headers.c) credits
     * syncsvc_note_headers_received with newly_added (P1). */
    printf("header_sync_stall: tracking fields updated on new headers... ");
    {
        struct p2p_node n = make_stall_node(10000, false, 1000);
        n.getheaders_stale_count = 3;
        syncsvc_note_headers_received(&n, 50);
        bool ok = (n.last_useful_headers_time > 0);
        ok = ok && (n.total_headers_delivered == 50);
        ok = ok && (n.getheaders_stale_count == 0); /* useful resets backoff */
        /* Second batch accumulates */
        syncsvc_note_headers_received(&n, 30);
        ok = ok && (n.total_headers_delivered == 80);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    return failures;
}

/* Case 2: a zero-new-header delivery credits nothing. */
static int check_zero_new_headers_not_credited(void)
{
    int failures = 0;

    /* ── 2. Tracking fields NOT updated on zero new headers ─────── */
    printf("header_sync_stall: tracking fields unchanged on reject... ");
    {
        struct p2p_node n = make_stall_node(10000, false, 1000);
        n.last_useful_headers_time = 500;
        n.total_headers_delivered = 10;
        syncsvc_note_headers_received(&n, 0);
        bool ok = (n.last_useful_headers_time == 500);
        ok = ok && (n.total_headers_delivered == 10);
        ok = ok && (n.getheaders_stale_count == 1); /* empty = stale */
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    return failures;
}

/* Case 3 (P1): known-header replay earns no usefulness credit. */
static int check_known_header_replay_earns_no_credit(void)
{
    int failures = 0;

    /* ── 3. P1: known-header replay earns no usefulness credit ────
     * A replay is accepted but newly_added == 0, so the call site passes
     * 0. Crediting `accepted` would let a withholding peer defeat rule A
     * and deflect rule B's eviction onto honest peers. */
    printf("header_sync_stall: known-header replay earns no credit... ");
    {
        struct p2p_node n = make_stall_node(10000, false, 1000);
        /* First delivery: 50 headers genuinely new to our index. */
        syncsvc_note_headers_received(&n, 50);
        int64_t  useful_after_new = n.last_useful_headers_time;
        uint64_t total_after_new  = n.total_headers_delivered;
        /* Replay of the same 50: accepted=50 but newly_added=0 →
         * the P1 wiring credits 0. */
        syncsvc_note_headers_received(&n, 0);
        bool ok = (useful_after_new > 0);
        ok = ok && (n.last_useful_headers_time == useful_after_new);
        ok = ok && (n.total_headers_delivered == total_after_new);
        ok = ok && (total_after_new == 50);
        ok = ok && (n.getheaders_stale_count == 1); /* replay = stale */
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    return failures;
}

/* Case 4: the stale-peer disconnect fires after 120s in IBD. */
static int check_stale_peer_disconnect_after_120s(void)
{
    int failures = 0;

    /* ── 4. Stale peer disconnect fires after 120s in IBD ─────────
     * best_header_height far below the peer's claimed tip: the parity
     * gate (P2) stays out of the way. */
    printf("header_sync_stall: disconnect stale peer after 120s... ");
    {
        struct p2p_node n = make_stall_node(10000, false, 1000);
        /* 119s: not yet */
        bool at_119 = syncsvc_should_disconnect_stale_header_peer(
            &n, 100, 100, 0, 1119);
        /* 120s: fire */
        bool at_120 = syncsvc_should_disconnect_stale_header_peer(
            &n, 100, 100, 0, 1120);
        bool ok = !at_119 && at_120;
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    return failures;
}

/* Cases 5-6: active and non-IBD peers are not disconnected. */
static int check_active_and_non_ibd_peers_survive(void)
{
    int failures = 0;

    /* ── 5. Peer with recent useful headers not disconnected ─────── */
    printf("header_sync_stall: active peer not disconnected... ");
    {
        struct p2p_node n = make_stall_node(10000, false, 1000);
        n.last_useful_headers_time = 1050;
        n.total_headers_delivered = 100;
        bool ok = !syncsvc_should_disconnect_stale_header_peer(
            &n, 100, 100, 0, 1100);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    /* ── 6. Non-IBD peer not disconnected ────────────────────────── */
    printf("header_sync_stall: non-IBD peer not disconnected... ");
    {
        struct p2p_node n = make_stall_node(1000, false, 1000);
        /* height 900 = within 144 of starting_height, not IBD */
        bool ok = !syncsvc_should_disconnect_stale_header_peer(
            &n, 900, 900, 0, 9999);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    return failures;
}

/* Cases 7-8 (P2): parity skips the rule; far-below still cuts. */
static int check_parity_skip_and_far_below_disconnect(void)
{
    int failures = 0;

    /* ── 7. P2: frontier parity skips the stale-header rule ───────
     * Our BLOCK height is far behind (IBD true) while our HEADER frontier
     * tracks the network tip: no peer can look "useful" on a 120s clock,
     * so disconnecting is churn. Boundary is inclusive:
     * best_header_height >= starting_height - 144 skips. */
    printf("header_sync_stall: frontier parity skips stale rule... ");
    {
        struct p2p_node n = make_stall_node(10000, false, 1000);
        /* Arbitrarily stale (now=99999, ref=1000) — parity still wins. */
        bool at_parity = syncsvc_should_disconnect_stale_header_peer(
            &n, 100, 10000, 0, 99999);
        bool at_boundary = syncsvc_should_disconnect_stale_header_peer(
            &n, 100, 10000 - 144, 0, 99999);
        /* One below the boundary the rule is armed again. */
        bool below_boundary = syncsvc_should_disconnect_stale_header_peer(
            &n, 100, 10000 - 145, 0, 99999);
        bool ok = !at_parity && !at_boundary && below_boundary;
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    /* ── 8. P2: far-below frontier keeps full discipline ──────────
     * A genuinely withholding peer is still cut. */
    printf("header_sync_stall: far-below frontier still disconnects... ");
    {
        struct p2p_node n = make_stall_node(10000, false, 1000);
        bool ok = syncsvc_should_disconnect_stale_header_peer(
            &n, 100, 5000, 0, 1120);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    return failures;
}

/* A header-stale peer serving recent bodies is not churned. */
static int check_body_stall_boundary_rules(void)
{
    int failures = 0;

    /* A peer stale for header purposes but serving known bodies is not
     * churned by header accounting; once its body timestamp reaches the
     * body-stall boundary, the body rules own the failover decision. */
    printf("header_sync_stall: recent body source survives header stall... ");
    {
        struct p2p_node n = make_stall_node(10000, false, 1000);
        bool recent = syncsvc_should_disconnect_stale_header_peer(
            &n, 100, 5000, 1119, 1120);
        bool boundary = syncsvc_should_disconnect_stale_header_peer(
            &n, 100, 5000, 1000, 1120);
        bool future_clock = syncsvc_should_disconnect_stale_header_peer(
            &n, 100, 5000, 1200, 1120);
        bool ok = !recent && boundary && !future_clock;
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    return failures;
}

/* Case 9 (P3): loopback exemption at the call-site seam. */
static int check_loopback_exemption_seam(void)
{
    int failures = 0;

    /* ── 9. P3: loopback exemption seam ───────────────────────────────
     * Same conditions as case 4. (a) the syncsvc rule still says
     * "disconnect" for a loopback peer (it is trust-agnostic); (b) the
     * trust predicate classifies 127.0.0.1 as local, so the composed
     * rule-A decision, replicated from the msgprocessor.c call site,
     * exempts it. */
    printf("header_sync_stall: loopback trusted at the call-site seam... ");
    {
        struct p2p_node n = make_stall_node(10000, false, 1000);
        const unsigned char lo[4] = {127, 0, 0, 1};
        net_addr_set_ipv4(&n.addr.svc.addr, lo);
        /* (a) the rule fires — trust-agnostic by design. */
        bool rule_fires = syncsvc_should_disconnect_stale_header_peer(
            &n, 100, 100, 0, 99999);
        /* (b) the guard input classifies loopback as local. */
        bool is_local = net_addr_is_local(&n.addr.svc.addr);
        /* Composed decision exactly as written at the call site. */
        bool stall_peer_trusted = is_local || n.whitelisted;
        bool disconnects = !stall_peer_trusted && rule_fires;
        bool ok = rule_fires && is_local && !disconnects;
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    return failures;
}

/* Case 10 (P3): whitelist exempts; a plain remote is still cut. */
static int check_whitelist_exemption_seam(void)
{
    int failures = 0;

    /* ── 10. P3: whitelist exemption seam ─────────────────────────────
     * A public address is NOT local, so only the whitelist bit exempts
     * it; with the bit clear the rule's verdict passes through. */
    printf("header_sync_stall: whitelist trusted, plain remote cut... ");
    {
        struct p2p_node n = make_stall_node(10000, false, 1000);
        const unsigned char remote[4] = {93, 184, 216, 34};
        net_addr_set_ipv4(&n.addr.svc.addr, remote);
        bool is_local = net_addr_is_local(&n.addr.svc.addr);
        bool rule_fires = syncsvc_should_disconnect_stale_header_peer(
            &n, 100, 100, 0, 99999);
        /* Whitelisted: composed call-site decision exempts. */
        n.whitelisted = true;
        bool wl_disconnects =
            !(is_local || n.whitelisted) && rule_fires;
        /* Plain remote: no exemption — the verdict passes through. */
        n.whitelisted = false;
        bool plain_disconnects =
            !(is_local || n.whitelisted) && rule_fires;
        bool ok = !is_local && rule_fires && !wl_disconnects &&
                  plain_disconnects;
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    return failures;
}

/* Cases 11-13: the stall-detection gate on state and advance time. */
static int check_header_stall_detection_states(void)
{
    int failures = 0;

    /* ── 11. Header sync stall detection fires ───────────────────── */
    printf("header_sync_stall: stall detected after 120s no advance... ");
    {
        bool at_119 = syncsvc_is_header_sync_stalled(
            SYNC_HEADERS_DOWNLOAD, 5000, 1000, 1119);
        bool at_120 = syncsvc_is_header_sync_stalled(
            SYNC_HEADERS_DOWNLOAD, 5000, 1000, 1120);
        bool ok = !at_119 && at_120;
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    /* ── 12. Stall not detected in wrong sync state ──────────────── */
    printf("header_sync_stall: no stall in SYNC_BLOCKS_DOWNLOAD... ");
    {
        bool stalled = syncsvc_is_header_sync_stalled(
            SYNC_BLOCKS_DOWNLOAD, 5000, 1000, 9999);
        bool ok = !stalled;
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    /* ── 13. Stall not detected with zero last_advance_time ──────── */
    printf("header_sync_stall: no stall with zero advance time... ");
    {
        bool stalled = syncsvc_is_header_sync_stalled(
            SYNC_HEADERS_DOWNLOAD, 5000, 0, 9999);
        bool ok = !stalled;
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    return failures;
}

/* Cases 14-16: inbound fallback gating; the outbound path works. */
static int check_inbound_fallback_rules(void)
{
    int failures = 0;

    /* ── 14. Inbound fallback: normally skipped ──────────────────── */
    printf("header_sync_stall: inbound peer skipped normally... ");
    {
        struct p2p_node n = make_stall_node(10000, true, 0);
        bool ok = !syncsvc_should_request_headers_with_fallback(
            &n, 100, 9999, false);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    /* ── 15. Inbound fallback: allowed during stall ──────────────── */
    printf("header_sync_stall: inbound peer allowed during stall... ");
    {
        struct p2p_node n = make_stall_node(10000, true, 0);
        n.state = PEER_ACTIVE;
        bool ok = syncsvc_should_request_headers_with_fallback(
            &n, 100, 9999, true);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    /* ── 16. Outbound peer still works with fallback function ────── */
    printf("header_sync_stall: outbound peer works with fallback fn... ");
    {
        struct p2p_node n = make_stall_node(10000, false, 0);
        bool ok = syncsvc_should_request_headers_with_fallback(
            &n, 100, 15, false);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    return failures;
}

int test_header_sync_stall(void)
{
    int failures = 0;

    failures += check_new_headers_credit_usefulness();
    failures += check_zero_new_headers_not_credited();
    failures += check_known_header_replay_earns_no_credit();
    failures += check_stale_peer_disconnect_after_120s();
    failures += check_active_and_non_ibd_peers_survive();
    failures += check_parity_skip_and_far_below_disconnect();
    failures += check_body_stall_boundary_rules();
    failures += check_loopback_exemption_seam();
    failures += check_whitelist_exemption_seam();
    failures += check_header_stall_detection_states();
    failures += check_inbound_fallback_rules();

    return failures;
}
