/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Tests for headers-first sync refinement: exponential backoff on stale
 * peers, tighter getheaders intervals, locator construction. */

#include "test/test_core.h"
#include "chain/pow.h"
#include "net/net.h"
#include "sync/sync_planner.h"

/* Helper: build a minimal p2p_node for testing sync decisions. */
static struct p2p_node make_test_node(int starting_height, int64_t last_gh_time)
{
    struct p2p_node n;
    memset(&n, 0, sizeof(n));
    n.id = 1;
    n.state = PEER_SYNCING_HEADERS;
    n.starting_height = starting_height;
    n.last_getheaders_time = last_gh_time;
    n.inbound = false;
    n.getheaders_stale_count = 0;
    return n;
}

int test_header_sync(void)
{
    int failures = 0;

    /* ── 1. IBD base interval is 10s ──────────────────────── */
    printf("header_sync: IBD base interval 10s... ");
    {
        struct p2p_node n = make_test_node(10000, 0);
        bool ok = syncsvc_should_request_headers(&n, 100, 11);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    /* ── 2. Catching-up interval tightened to 30s ─────────── */
    printf("header_sync: catching-up interval 30s... ");
    {
        struct p2p_node n = make_test_node(1000, 0);
        /* at height 990 (within 144 of starting_height, not IBD) */
        bool at_25 = syncsvc_should_request_headers(&n, 990, 25);
        bool at_35 = syncsvc_should_request_headers(&n, 990, 35);
        bool ok = !at_25 && at_35;
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    /* ── 3. At-tip interval remains 120s ──────────────────── */
    printf("header_sync: at-tip interval 120s... ");
    {
        struct p2p_node n = make_test_node(1000, 0);
        bool at_100 = syncsvc_should_request_headers(&n, 1000, 100);
        bool at_125 = syncsvc_should_request_headers(&n, 1000, 125);
        bool ok = !at_100 && at_125;
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    /* ── 4. Stale count increases backoff ─────────────────── */
    printf("header_sync: stale count increases backoff... ");
    {
        struct p2p_node n = make_test_node(1000, 0);
        /* At tip, base=120. stale_count=2 → 120 * 4 = 480s */
        n.getheaders_stale_count = 2;
        bool at_400 = syncsvc_should_request_headers(&n, 1000, 400);
        bool at_500 = syncsvc_should_request_headers(&n, 1000, 500);
        bool ok = !at_400 && at_500;
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    /* ── 5. Backoff caps at 600s ──────────────────────────── */
    printf("header_sync: backoff caps at 600s... ");
    {
        struct p2p_node n = make_test_node(1000, 0);
        n.getheaders_stale_count = 10;  /* would be 120 * 1024 without cap */
        bool at_590 = syncsvc_should_request_headers(&n, 1000, 590);
        bool at_610 = syncsvc_should_request_headers(&n, 1000, 610);
        bool ok = !at_590 && at_610;
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    /* ── 6. note_headers_received resets stale count ──────── */
    printf("header_sync: good headers reset stale count... ");
    {
        struct p2p_node n = make_test_node(1000, 0);
        n.getheaders_stale_count = 5;
        syncsvc_note_headers_received(&n, 10);
        bool ok = (n.getheaders_stale_count == 0);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    /* ── 7. note_headers_received increments on empty ─────── */
    printf("header_sync: empty headers increment stale count... ");
    {
        struct p2p_node n = make_test_node(1000, 0);
        syncsvc_note_headers_received(&n, 0);
        syncsvc_note_headers_received(&n, 0);
        bool ok = (n.getheaders_stale_count == 2);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    /* ── 8. Inbound peers never get header requests ───────── */
    printf("header_sync: inbound peers never requested... ");
    {
        struct p2p_node n = make_test_node(1000, 0);
        n.inbound = true;
        bool ok = !syncsvc_should_request_headers(&n, 100, 9999);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    /* ── 9. Peer state below SYNCING_HEADERS not requested ── */
    printf("header_sync: pre-sync state not requested... ");
    {
        struct p2p_node n = make_test_node(1000, 0);
        n.state = PEER_ACTIVE;  /* not yet syncing */
        bool ok = !syncsvc_should_request_headers(&n, 100, 9999);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    /* ── 10. plan_periodic_getheaders sets should_send ────── */
    printf("header_sync: plan periodic getheaders... ");
    {
        struct p2p_node n = make_test_node(10000, 0);
        struct sync_getheaders_action action;
        syncsvc_plan_periodic_getheaders(&action, &n, 100, 15);
        bool ok = action.should_send;
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    /* ── 11. evaluate_header_batch: full batch requests more ─ */
    printf("header_sync: full batch requests more headers... ");
    {
        struct sync_header_batch batch;
        struct block_index dummy;
        memset(&dummy, 0, sizeof(dummy));
        struct uint256 hash;
        memset(&hash, 0xAB, sizeof(hash));
        dummy.phashBlock = &hash;

        syncsvc_evaluate_header_batch(&batch, 160, 160, &dummy);
        bool ok = batch.should_request_more_headers;
        ok = ok && batch.should_emit_received;
        ok = ok && !batch.should_warn_all_rejected;
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    /* ── 12. evaluate_header_batch: all rejected warns ────── */
    printf("header_sync: all-rejected batch warns... ");
    {
        struct sync_header_batch batch;
        syncsvc_evaluate_header_batch(&batch, 0, 50, NULL);
        bool ok = batch.should_warn_all_rejected;
        ok = ok && !batch.should_emit_received;
        ok = ok && !batch.should_request_more_headers;
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    /* ── 13. IBD detection threshold at 144 blocks ────────── */
    printf("header_sync: IBD detection threshold... ");
    {
        struct p2p_node n = make_test_node(1000, 0);
        bool in_ibd = syncsvc_is_initial_block_download(&n, 800);
        bool not_ibd = syncsvc_is_initial_block_download(&n, 900);
        bool ok = in_ibd && !not_ibd;
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    /* ── 14. Locator builds from chain with dense tip ─────── */
    printf("header_sync: locator includes genesis hash... ");
    {
        struct uint256 genesis;
        memset(&genesis, 0x01, sizeof(genesis));

        struct block_locator loc;
        struct zcl_result _r = syncsvc_build_getheaders_locator(&loc, NULL, NULL, NULL, &genesis);
        bool ok = _r.ok;
        ok = ok && (loc.num_hashes == 1);
        ok = ok && uint256_eq(&loc.vhave[0], &genesis);
        if (ok) {
            block_locator_free(&loc);
            printf("OK\n");
        } else { printf("FAIL\n"); failures++; }
    }

    /* ── 15. note_headers_requested updates timestamp ─────── */
    printf("header_sync: note_headers_requested updates time... ");
    {
        struct p2p_node n = make_test_node(1000, 0);
        syncsvc_note_headers_requested(&n, 12345);
        bool ok = (n.last_getheaders_time == 12345);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    /* ── 16. IBD stale backoff starts small ───────────────── */
    printf("header_sync: IBD stale backoff starts small... ");
    {
        struct p2p_node n = make_test_node(10000, 0);
        /* IBD base=10, stale_count=1 → 10*2=20s */
        n.getheaders_stale_count = 1;
        bool at_15 = syncsvc_should_request_headers(&n, 100, 15);
        bool at_25 = syncsvc_should_request_headers(&n, 100, 25);
        bool ok = !at_15 && at_25;
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    /* ── 17. Snapshot anchors release at finality depth ───── */
    printf("header_sync: snapshot anchor releases at finality depth... ");
    {
        struct block_index anchor, h9, h10;
        memset(&anchor, 0, sizeof(anchor));
        memset(&h9, 0, sizeof(h9));
        memset(&h10, 0, sizeof(h10));

        anchor.nHeight = 2000;
        h9.nHeight = 2009;
        h10.nHeight = 2010;

        bool too_early = syncsvc_should_release_snapshot_anchor(&anchor, &h9);
        bool at_finality = syncsvc_should_release_snapshot_anchor(&anchor, &h10);
        bool ok = !too_early && at_finality;
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    return failures;
}
