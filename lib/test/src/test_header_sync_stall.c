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

int test_header_sync_stall(void)
{
    int failures = 0;

    /* ── 1. last_useful_headers_time updated on NEW headers ──────
     * The production call site (process_headers, msg_headers.c)
     * credits syncsvc_note_headers_received with newly_added —
     * headers not previously in our index — per design P1/B2. */
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

    /* ── 3. P1: known-header replay earns no usefulness credit ────
     * A withholding peer can replay headers we already have:
     * process_headers accepts them (accepted > 0, was_known) but
     * newly_added == 0, so the call site passes 0 here.  Crediting
     * `accepted` instead would let such a peer refresh
     * last_useful_headers_time forever (defeating rule A) and
     * inflate total_headers_delivered (deflecting rule B's
     * worst-peer eviction onto honest peers) — design B2. */
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

    /* ── 4. Stale peer disconnect fires after 120s in IBD ─────────
     * best_header_height far below the peer's claimed tip: the
     * parity gate (P2) stays out of the way and the rule keeps its
     * original semantics. */
    printf("header_sync_stall: disconnect stale peer after 120s... ");
    {
        struct p2p_node n = make_stall_node(10000, false, 1000);
        /* 119s: not yet */
        bool at_119 = syncsvc_should_disconnect_stale_header_peer(
            &n, 100, 100, 1119);
        /* 120s: fire */
        bool at_120 = syncsvc_should_disconnect_stale_header_peer(
            &n, 100, 100, 1120);
        bool ok = !at_119 && at_120;
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    /* ── 5. Peer with recent useful headers not disconnected ─────── */
    printf("header_sync_stall: active peer not disconnected... ");
    {
        struct p2p_node n = make_stall_node(10000, false, 1000);
        n.last_useful_headers_time = 1050;
        n.total_headers_delivered = 100;
        bool ok = !syncsvc_should_disconnect_stale_header_peer(
            &n, 100, 100, 1100);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    /* ── 6. Non-IBD peer not disconnected ────────────────────────── */
    printf("header_sync_stall: non-IBD peer not disconnected... ");
    {
        struct p2p_node n = make_stall_node(1000, false, 1000);
        /* height 900 = within 144 of starting_height, not IBD */
        bool ok = !syncsvc_should_disconnect_stale_header_peer(
            &n, 900, 900, 9999);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    /* ── 7. P2: frontier parity skips the stale-header rule ───────
     * The live-wedge regime: our BLOCK height is pinned far behind
     * (IBD predicate true) while our HEADER frontier tracks the
     * network tip.  At parity with the peer's handshake-claimed
     * height, new headers only arrive every ~150s block — no peer
     * can look "useful" on a 120s clock, so disconnecting is pure
     * churn (and with P1 crediting only new-to-index headers,
     * newly_added==0 for everyone here).  Boundary is inclusive:
     * best_header_height >= starting_height - 144 skips. */
    printf("header_sync_stall: frontier parity skips stale rule... ");
    {
        struct p2p_node n = make_stall_node(10000, false, 1000);
        /* Arbitrarily stale (now=99999, ref=1000) — parity still wins. */
        bool at_parity = syncsvc_should_disconnect_stale_header_peer(
            &n, 100, 10000, 99999);
        bool at_boundary = syncsvc_should_disconnect_stale_header_peer(
            &n, 100, 10000 - 144, 99999);
        /* One below the boundary the rule is armed again. */
        bool below_boundary = syncsvc_should_disconnect_stale_header_peer(
            &n, 100, 10000 - 145, 99999);
        bool ok = !at_parity && !at_boundary && below_boundary;
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    /* ── 8. P2: far-below frontier keeps full discipline ──────────
     * A genuinely withholding peer (claims a tip far above our
     * header frontier, delivers nothing useful for 120s) is still
     * cut — the parity gate must not weaken the rule where it
     * matters. */
    printf("header_sync_stall: far-below frontier still disconnects... ");
    {
        struct p2p_node n = make_stall_node(10000, false, 1000);
        bool ok = syncsvc_should_disconnect_stale_header_peer(
            &n, 100, 5000, 1120);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    /* ── 9. P3: loopback exemption seam — rule trust-agnostic,
     * call-site guard exempts ─────────────────────────────────────
     * Identical staleness/frontier conditions to case 4.  Pins both
     * halves of the seam: (a) the syncsvc rule itself still says
     * "disconnect" for a loopback peer — the exemption does NOT live
     * inside it (it has no trust knowledge, by design); (b) the
     * trust predicate's input classifies 127.0.0.1 as local, so the
     * composed rule-A decision — replicated verbatim from the
     * msgprocessor.c call site — never churns the co-located
     * zclassicd lifeline. */
    printf("header_sync_stall: loopback trusted at the call-site seam... ");
    {
        struct p2p_node n = make_stall_node(10000, false, 1000);
        const unsigned char lo[4] = {127, 0, 0, 1};
        net_addr_set_ipv4(&n.addr.svc.addr, lo);
        /* (a) the rule fires — trust-agnostic by design. */
        bool rule_fires = syncsvc_should_disconnect_stale_header_peer(
            &n, 100, 100, 99999);
        /* (b) the guard input classifies loopback as local. */
        bool is_local = net_addr_is_local(&n.addr.svc.addr);
        /* Composed decision exactly as written at the call site. */
        bool stall_peer_trusted = is_local || n.whitelisted;
        bool disconnects = !stall_peer_trusted && rule_fires;
        bool ok = rule_fires && is_local && !disconnects;
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    /* ── 10. P3: whitelist exemption seam; plain remote keeps full
     * stall discipline ─────────────────────────────────────────────
     * Same composed call-site decision as case 9: a public address
     * is NOT local, so only the explicit whitelist bit can exempt it;
     * with the bit clear, the rule's verdict passes through the guard
     * unmodified and the peer is cut. */
    printf("header_sync_stall: whitelist trusted, plain remote cut... ");
    {
        struct p2p_node n = make_stall_node(10000, false, 1000);
        const unsigned char remote[4] = {93, 184, 216, 34};
        net_addr_set_ipv4(&n.addr.svc.addr, remote);
        bool is_local = net_addr_is_local(&n.addr.svc.addr);
        bool rule_fires = syncsvc_should_disconnect_stale_header_peer(
            &n, 100, 100, 99999);
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
