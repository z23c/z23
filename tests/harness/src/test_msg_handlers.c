/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Tests for the split message handler files:
 *   msg_version.c, msg_headers.c, msg_blocks.c, msg_tx.c, msg_compact.c
 *
 * These tests exercise the public/testable functions without requiring
 * a full msg_processor or live P2P connection. Coverage:
 *   1. msg_headers_get_stats — NULL safety, initial zeroed state
 *   2. block_already_seen / block_mark_seen / block_clear_seen — dedup ring
 *   3. tx_already_seen / tx_mark_seen — tx dedup ring
 *   4. Dandelion globals — initial state
 */

#include "test/test_core.h"
#include "chain/chain.h"
#include "chain/chainparams.h"
#include "core/hash.h"
#include "net/msgprocessor.h"
#include "net/msg_internal.h"
#include "net/version.h"
#include "net/download.h"
#include "net/file_market.h"
#include "net/peer_scoring.h"
#include "core/serialize.h"
#include "consensus/validation.h"
#include "core/uint256.h"
#include "primitives/block.h"
#include "sync/sync_state.h"
#include "util/safe_alloc.h"
#include "util/blocker.h"
#include "util/thread_registry.h"
#include "validation/main_state.h"
#include "validation/chainstate.h"
#include "platform/socket_compat.h"

#include <stdio.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static void test_msg_sleep_ms(long ms)
{
    struct timespec ts;
    ts.tv_sec = ms / 1000;
    ts.tv_nsec = (ms % 1000) * 1000000L;
    nanosleep(&ts, NULL);
}

static void test_msg_sync_to_idle(void)
{
    enum sync_state cur = sync_get_state();
    if (cur == SYNC_IDLE)
        return;
    if (cur == SYNC_AT_TIP) {
        (void)sync_set_state(SYNC_IDLE, "msg_handlers cleanup");
        return;
    }
    if (cur == SYNC_REORG) {
        (void)sync_set_state(SYNC_AT_TIP, "msg_handlers cleanup");
        (void)sync_set_state(SYNC_IDLE, "msg_handlers cleanup");
        return;
    }
    (void)sync_set_state(SYNC_IDLE, "msg_handlers cleanup");
}

static void test_msg_sync_to_blocks_download(void)
{
    test_msg_sync_to_idle();
    if (sync_get_state() != SYNC_IDLE)
        return;
    (void)sync_set_state(SYNC_FINDING_PEERS, "msg_handlers setup");
    (void)sync_set_state(SYNC_HEADERS_DOWNLOAD, "msg_handlers setup");
    (void)sync_set_state(SYNC_BLOCKS_DOWNLOAD, "msg_handlers setup");
}

/* ── msg_headers.c tests ───────────────────────────────────────── */

static int test_headers_stats_null_safe(void)
{
    int failures = 0;
    TEST("msg_handlers: msg_headers_get_stats(NULL) does not crash") {
        msg_headers_get_stats(NULL);
        ASSERT(true);  /* survived NULL arg without crashing */
        PASS();
    } _test_next:;
    return failures;
}

static int test_headers_stats_initial(void)
{
    int failures = 0;
    TEST("msg_handlers: msg_headers_get_stats returns zeroed counters initially") {
        struct msg_headers_stats st;
        memset(&st, 0xFF, sizeof(st));
        msg_headers_get_stats(&st);
        /* Counters start at zero (atomics initialized to 0). */
        ASSERT(st.batches_received == 0);
        ASSERT(st.total_accepted == 0);
        ASSERT(st.total_rejected == 0);
        ASSERT(st.already_known == 0);
        PASS();
    } _test_next:;
    return failures;
}

/* ── msgprocessor.c dedup ring buffer tests ─────────────────────── */

static struct uint256 make_test_hash(uint8_t seed)
{
    struct uint256 h;
    memset(h.data, seed, 32);
    return h;
}

static int test_block_dedup_basic(void)
{
    int failures = 0;
    TEST("msg_handlers: block dedup — unseen hash returns false") {
        struct uint256 h = make_test_hash(0xAA);
        ASSERT(!block_already_seen(&h));
        PASS();
    } _test_next:;
    return failures;
}

static int test_block_dedup_mark_and_check(void)
{
    int failures = 0;
    TEST("msg_handlers: block dedup — mark then check returns true") {
        struct uint256 h = make_test_hash(0xBB);
        block_mark_seen(&h);
        ASSERT(block_already_seen(&h));
        PASS();
    } _test_next:;
    return failures;
}

static int test_block_dedup_clear(void)
{
    int failures = 0;
    TEST("msg_handlers: block dedup — clear removes hash") {
        struct uint256 h = make_test_hash(0xCC);
        block_mark_seen(&h);
        ASSERT(block_already_seen(&h));
        block_clear_seen(&h);
        ASSERT(!block_already_seen(&h));
        PASS();
    } _test_next:;
    return failures;
}

static int test_block_dedup_multiple(void)
{
    int failures = 0;
    TEST("msg_handlers: block dedup — multiple hashes tracked independently") {
        struct uint256 h1 = make_test_hash(0xD1);
        struct uint256 h2 = make_test_hash(0xD2);
        struct uint256 h3 = make_test_hash(0xD3);
        block_mark_seen(&h1);
        block_mark_seen(&h2);
        ASSERT(block_already_seen(&h1));
        ASSERT(block_already_seen(&h2));
        ASSERT(!block_already_seen(&h3));
        PASS();
    } _test_next:;
    return failures;
}

static int test_tx_dedup_basic(void)
{
    int failures = 0;
    TEST("msg_handlers: tx dedup — unseen tx returns false") {
        struct uint256 h = make_test_hash(0xE1);
        ASSERT(!tx_already_seen(&h));
        PASS();
    } _test_next:;
    return failures;
}

static int test_tx_dedup_mark_and_check(void)
{
    int failures = 0;
    TEST("msg_handlers: tx dedup — mark then check returns true") {
        struct uint256 h = make_test_hash(0xE2);
        tx_mark_seen(&h);
        ASSERT(tx_already_seen(&h));
        PASS();
    } _test_next:;
    return failures;
}

/* ── Dandelion state tests ─────────────────────────────────────── */

static int test_dandelion_initial_state(void)
{
    int failures = 0;
    TEST("msg_handlers: dandelion not initialized at start") {
        /* g_dandelion_init should be false before any peer handshake */
        ASSERT(!g_dandelion_init);
        PASS();
    } _test_next:;
    return failures;
}

/* ── msg_blocks_should_mark_seen tests ───────────────────────
 *
 * mark_seen is gated on "block reached active chain" via
 * msg_blocks_should_mark_seen(), a pure function: a block that was indexed
 * but not activated (e.g. ACTIVATION_SKIP_ALREADY_RUNNING) must stay
 * retryable. */

static int test_p148_should_mark_seen_rejects_null(void)
{
    int failures = 0;
    TEST("should_mark_seen rejects NULL chain or pindex") {
        struct active_chain ac;
        active_chain_init(&ac);
        struct block_index bi;
        block_index_init(&bi);

        ASSERT(!msg_blocks_should_mark_seen(NULL, &bi));
        ASSERT(!msg_blocks_should_mark_seen(&ac, NULL));
        ASSERT(!msg_blocks_should_mark_seen(NULL, NULL));

        active_chain_free(&ac);
        PASS();
    } _test_next:;
    return failures;
}

static int test_p148_should_mark_seen_rejects_orphan(void)
{
    int failures = 0;
    TEST("should_mark_seen rejects block NOT in active chain") {
        /* Block was indexed but activation SKIP'd, so it is not in the active
         * chain and must NOT be marked seen (the dedup ring would hide retries). */
        struct active_chain ac;
        active_chain_init(&ac);

        struct block_index tip;
        block_index_init(&tip);
        tip.nHeight = 100;
        active_chain_move_window_tip(&ac, &tip);

        struct block_index orphan;
        block_index_init(&orphan);
        orphan.nHeight = 101; /* indexed above tip, not connected */

        ASSERT(!msg_blocks_should_mark_seen(&ac, &orphan));

        active_chain_free(&ac);
        PASS();
    } _test_next:;
    return failures;
}

static int test_p148_should_mark_seen_accepts_active(void)
{
    int failures = 0;
    TEST("should_mark_seen accepts block that IS in active chain") {
        struct active_chain ac;
        active_chain_init(&ac);

        struct block_index tip;
        block_index_init(&tip);
        tip.nHeight = 42;
        active_chain_move_window_tip(&ac, &tip);

        ASSERT(msg_blocks_should_mark_seen(&ac, &tip));

        active_chain_free(&ac);
        PASS();
    } _test_next:;
    return failures;
}

static int test_should_announce_getblocks(void)
{
    int failures = 0;
    TEST("getblocks announce requires HAVE_DATA and a hash") {
        struct block_index bi;
        struct uint256 hash;
        uint256_set_null(&hash);
        hash.data[0] = 1;
        block_index_init(&bi);
        ASSERT(!msg_blocks_should_announce_getblocks(NULL));
        ASSERT(!msg_blocks_should_announce_getblocks(&bi));
        bi.phashBlock = &hash;
        ASSERT(!msg_blocks_should_announce_getblocks(&bi));
        bi.nStatus = BLOCK_HAVE_DATA;
        ASSERT(msg_blocks_should_announce_getblocks(&bi));
        bi.nStatus = BLOCK_VALID_TREE;
        ASSERT(!msg_blocks_should_announce_getblocks(&bi));
        PASS();
    } _test_next:;
    return failures;
}

static int test_source_header_echo_policy(void)
{
    int failures = 0;
    TEST("msg_handlers: source gets only its negotiated header proof") {
        struct p2p_node peer;
        memset(&peer, 0, sizeof(peer));
        peer.id = 42;
        peer.state = PEER_HANDSHAKE_COMPLETE;
        peer.prefer_headers = true;

        ASSERT(msg_blocks_should_echo_source_header(&peer, 42));
        ASSERT(!msg_blocks_should_echo_source_header(&peer, 41));
        peer.prefer_headers = false;
        ASSERT(!msg_blocks_should_echo_source_header(&peer, 42));
        peer.prefer_headers = true;
        peer.disconnect = true;
        ASSERT(!msg_blocks_should_echo_source_header(&peer, 42));
        peer.disconnect = false;
        peer.state = PEER_CONNECTED;
        ASSERT(!msg_blocks_should_echo_source_header(&peer, 42));
        ASSERT(!msg_blocks_should_echo_source_header(NULL, 42));
        PASS();
    } _test_next:;
    return failures;
}

static int test_block_validation_retryable_classifier(void)
{
    int failures = 0;
    TEST("msg_handlers: reducer-pending block verdict is retryable") {
        struct validation_state st;
        validation_state_init(&st);
        validation_state_invalid(&st, false, REJECT_INVALID,
                                 "block-not-finalized-by-reducer",
                                 "h=7 tf_cursor=6 ua_ok=1");
        ASSERT(msg_block_validation_is_retryable(&st));
        ASSERT(strstr(st.debug_message, "tf_cursor=6") != NULL);

        const char *const intake_reasons[] = {
            "p2p-block-queued-for-reducer",
            "p2p-block-staged-for-reducer",
            "p2p-block-header-missing",
            "header-admit-inbox-full",
            "reducer-body-header-missing",
            "reducer-body-runtime-unwired",
            "reducer-body-write-failed",
            "reducer-body-verify-failed",
            "p2p-block-intake-unavailable",
            "p2p-block-intake-stopped",
            "p2p-block-intake-full",
            "p2p-block-clone-failed",
        };
        for (size_t i = 0; i < sizeof(intake_reasons) /
                               sizeof(intake_reasons[0]); i++) {
            validation_state_init(&st);
            validation_state_error(&st, intake_reasons[i]);
            ASSERT(msg_block_validation_is_retryable(&st));
        }

        validation_state_init(&st);
        validation_state_invalid(&st, false, REJECT_INVALID,
                                 "bad-txns-inputs-missingorspent", NULL);
        ASSERT(!msg_block_validation_is_retryable(&st));

        validation_state_init(&st);
        ASSERT(!msg_block_validation_is_retryable(&st));
        PASS();
    } _test_next:;
    return failures;
}

static bool submit_reducer_pending_block(struct block *block,
                                         struct validation_state *out,
                                         void *ctx)
{
    (void)block;
    int *calls = (int *)ctx;
    if (calls)
        (*calls)++;
    validation_state_invalid(out, false, REJECT_INVALID,
                             "block-not-finalized-by-reducer", NULL);
    return false;
}

static int test_process_block_msg_reducer_pending_stays_retryable(void)
{
    int failures = 0;
    TEST("msg_handlers: reducer-pending process_block_msg does not mark seen") {
        struct block blk;
        block_init(&blk);
        blk.header.nVersion = 4;
        blk.header.nTime = 1700000000u;
        blk.header.nBits = 0x1f00ffffu;
        blk.header.nNonce.data[0] = 7;

        struct uint256 hash;
        block_get_hash(&blk, &hash);
        block_clear_seen(&hash);

        struct byte_stream s;
        stream_init(&s, 256);
        ASSERT(block_serialize(&blk, &s));

        int submit_calls = 0;
        struct msg_processor mp;
        memset(&mp, 0, sizeof(mp));
        mp.block_submit = submit_reducer_pending_block;
        mp.block_submit_ctx = &submit_calls;

        struct p2p_node node;
        memset(&node, 0, sizeof(node));
        node.id = 77;
        snprintf(node.addr_name, sizeof(node.addr_name), "test-peer");

        ASSERT(process_block_msg(&mp, &node, &s));
        ASSERT(submit_calls == 1);
        ASSERT(!block_already_seen(&hash));

        stream_free(&s);
        block_free(&blk);
        PASS();
    } _test_next:;
    return failures;
}

/* ── PEER_OFFENCE_UNREQUESTED wiring ─────────────────────────────────
 *
 * process_block_msg() (msg_blocks.c) scores PEER_OFFENCE_UNREQUESTED when
 * dl_mark_received() returns UINT32_MAX (no in-flight slot) for the delivered
 * hash from any peer: a "block" message is only a getdata response here.
 * Pinned: scored when never requested, not scored when requested, not scored
 * inside the drain/timeout grace window (see
 * tests/harness/src/test_download.c::test_dl_last_forced_settle_time). */

static void unreq_setup_node(struct p2p_node *node, uint32_t id)
{
    memset(node, 0, sizeof(*node));
    node->id = id;
    snprintf(node->addr_name, sizeof(node->addr_name), "unreq-peer-%u", id);
    /* Non-localhost, non-whitelisted so is_trusted_peer() doesn't exempt
     * it from scoring (mirrors test_peer_scoring.c's setup_node()). */
    node->addr.svc.addr.ip[10] = 0xff;
    node->addr.svc.addr.ip[11] = 0xff;
    node->addr.svc.addr.ip[12] = 198;
    node->addr.svc.addr.ip[13] = 51;
    node->addr.svc.addr.ip[14] = 100;
    node->addr.svc.addr.ip[15] = (unsigned char)id;
}

static int test_process_block_msg_scores_unrequested(void)
{
    int failures = 0;
    TEST("msg_handlers: process_block_msg scores PEER_OFFENCE_UNREQUESTED "
         "when the block was never requested from anyone") {
        peer_scoring_init();
        /* Hermetic: a prior test in this forked process may have left the
         * process-wide download manager in a drain/timeout grace window. */
        dl_init(get_download_mgr());

        struct block blk;
        block_init(&blk);
        blk.header.nVersion = 4;
        blk.header.nTime = 1700000010u;
        blk.header.nBits = 0x1f00ffffu;
        blk.header.nNonce.data[0] = 21;

        struct uint256 hash;
        block_get_hash(&blk, &hash);
        block_clear_seen(&hash);

        struct byte_stream s;
        stream_init(&s, 256);
        ASSERT(block_serialize(&blk, &s));

        int submit_calls = 0;
        struct net_manager nm;
        memset(&nm, 0, sizeof(nm));
        struct msg_processor mp;
        memset(&mp, 0, sizeof(mp));
        mp.block_submit = submit_reducer_pending_block;
        mp.block_submit_ctx = &submit_calls;
        mp.net_mgr = &nm;

        struct p2p_node node;
        unreq_setup_node(&node, 501);

        ASSERT(process_block_msg(&mp, &node, &s));
        ASSERT(atomic_load(&node.misbehavior) ==
              peer_offence_weight(PEER_OFFENCE_UNREQUESTED));

        stream_free(&s);
        block_free(&blk);
        PASS();
    } _test_next:;
    return failures;
}

static int test_process_block_msg_no_score_when_requested(void)
{
    int failures = 0;
    TEST("msg_handlers: process_block_msg does NOT score a block we "
         "actually asked this peer for") {
        peer_scoring_init();
        dl_init(get_download_mgr());

        struct block blk;
        block_init(&blk);
        blk.header.nVersion = 4;
        blk.header.nTime = 1700000011u;
        blk.header.nBits = 0x1f00ffffu;
        blk.header.nNonce.data[0] = 22;

        struct uint256 hash;
        block_get_hash(&blk, &hash);
        block_clear_seen(&hash);

        struct p2p_node node;
        unreq_setup_node(&node, 502);

        /* We DID ask this peer for it before it arrived. */
        ASSERT(dl_mark_requested(get_download_mgr(), &hash, 1, node.id));

        struct byte_stream s;
        stream_init(&s, 256);
        ASSERT(block_serialize(&blk, &s));

        int submit_calls = 0;
        struct net_manager nm;
        memset(&nm, 0, sizeof(nm));
        struct msg_processor mp;
        memset(&mp, 0, sizeof(mp));
        mp.block_submit = submit_reducer_pending_block;
        mp.block_submit_ctx = &submit_calls;
        mp.net_mgr = &nm;

        ASSERT(process_block_msg(&mp, &node, &s));
        ASSERT(atomic_load(&node.misbehavior) == 0);

        stream_free(&s);
        block_free(&blk);
        PASS();
    } _test_next:;
    return failures;
}

static int test_process_block_msg_no_score_when_requested_from_peer_zero(void)
{
    int failures = 0;
    TEST("msg_handlers: peer id zero remains a requested block, not the "
         "not-found sentinel") {
        peer_scoring_init();
        dl_init(get_download_mgr());

        struct block blk;
        block_init(&blk);
        blk.header.nVersion = 4;
        blk.header.nTime = 1700000014u;
        blk.header.nBits = 0x1f00ffffu;
        blk.header.nNonce.data[0] = 25;

        struct uint256 hash;
        block_get_hash(&blk, &hash);
        block_clear_seen(&hash);

        struct p2p_node node;
        unreq_setup_node(&node, 0);
        ASSERT(dl_mark_requested(get_download_mgr(), &hash, 1, node.id));

        struct byte_stream s;
        stream_init(&s, 256);
        ASSERT(block_serialize(&blk, &s));

        int submit_calls = 0;
        struct net_manager nm;
        memset(&nm, 0, sizeof(nm));
        struct msg_processor mp;
        memset(&mp, 0, sizeof(mp));
        mp.block_submit = submit_reducer_pending_block;
        mp.block_submit_ctx = &submit_calls;
        mp.net_mgr = &nm;

        ASSERT(process_block_msg(&mp, &node, &s));
        ASSERT(atomic_load(&node.misbehavior) == 0);

        stream_free(&s);
        block_free(&blk);
        PASS();
    } _test_next:;
    return failures;
}

static int test_process_block_msg_no_score_within_settle_grace(void)
{
    int failures = 0;
    TEST("msg_handlers: process_block_msg withholds scoring inside the "
         "post-drain/timeout grace window (honest-but-late delivery)") {
        peer_scoring_init();
        struct download_manager *dm = get_download_mgr();
        dl_init(dm);
        /* A drain or timeout reassignment force-clears in-flight state, so a
         * requested body can arrive with no trace it was asked for. */
        (void)dl_drain_for_backpressure(dm);

        struct block blk;
        block_init(&blk);
        blk.header.nVersion = 4;
        blk.header.nTime = 1700000012u;
        blk.header.nBits = 0x1f00ffffu;
        blk.header.nNonce.data[0] = 23;

        struct uint256 hash;
        block_get_hash(&blk, &hash);
        block_clear_seen(&hash);

        struct byte_stream s;
        stream_init(&s, 256);
        ASSERT(block_serialize(&blk, &s));

        int submit_calls = 0;
        struct net_manager nm;
        memset(&nm, 0, sizeof(nm));
        struct msg_processor mp;
        memset(&mp, 0, sizeof(mp));
        mp.block_submit = submit_reducer_pending_block;
        mp.block_submit_ctx = &submit_calls;
        mp.net_mgr = &nm;

        struct p2p_node node;
        unreq_setup_node(&node, 503);

        ASSERT(process_block_msg(&mp, &node, &s));
        ASSERT(atomic_load(&node.misbehavior) == 0);

        stream_free(&s);
        block_free(&blk);
        PASS();
    } _test_next:;
    return failures;
}

static int test_process_block_msg_no_score_during_shutdown(void)
{
    int failures = 0;
    TEST("msg_handlers: process_block_msg withholds unrequested scoring "
         "during orderly shutdown") {
        peer_scoring_init();
        dl_init(get_download_mgr());
        thread_registry_reset_for_test();
        thread_registry_request_shutdown();

        struct block blk;
        block_init(&blk);
        blk.header.nVersion = 4;
        blk.header.nTime = 1700000013u;
        blk.header.nBits = 0x1f00ffffu;
        blk.header.nNonce.data[0] = 24;

        struct uint256 hash;
        block_get_hash(&blk, &hash);
        block_clear_seen(&hash);

        struct byte_stream s;
        stream_init(&s, 256);
        ASSERT(block_serialize(&blk, &s));

        int submit_calls = 0;
        struct net_manager nm;
        memset(&nm, 0, sizeof(nm));
        struct msg_processor mp;
        memset(&mp, 0, sizeof(mp));
        mp.block_submit = submit_reducer_pending_block;
        mp.block_submit_ctx = &submit_calls;
        mp.net_mgr = &nm;

        struct p2p_node node;
        unreq_setup_node(&node, 504);

        ASSERT(process_block_msg(&mp, &node, &s));
        ASSERT(atomic_load(&node.misbehavior) == 0);

        thread_registry_reset_for_test();
        stream_free(&s);
        block_free(&blk);
        PASS();
    } _test_next:;
    /* ASSERT can jump past the in-body cleanup.  Never leak the process-wide
     * shutdown bit into later tests in this forked group. */
    thread_registry_reset_for_test();
    return failures;
}

struct async_block_submit_ctx {
    atomic_int entered;
    atomic_int release;
    atomic_int drains;
    atomic_int batch_begins;
    atomic_int batch_ends;
};

static void count_async_batch_begin(void *ctx)
{
    struct async_block_submit_ctx *submit_ctx = ctx;
    atomic_fetch_add_explicit(&submit_ctx->batch_begins, 1,
                              memory_order_relaxed);
}

static void count_async_batch_end(void *ctx)
{
    struct async_block_submit_ctx *submit_ctx = ctx;
    atomic_fetch_add_explicit(&submit_ctx->batch_ends, 1,
                              memory_order_relaxed);
}

static int count_async_catchup_drain(void *ctx)
{
    struct async_block_submit_ctx *submit_ctx = ctx;
    atomic_fetch_add_explicit(&submit_ctx->drains, 1,
                              memory_order_relaxed);
    return 0;
}

static bool submit_async_blocking_pending(struct block *block,
                                          struct validation_state *out,
                                          void *ctx)
{
    (void)block;
    struct async_block_submit_ctx *submit_ctx = ctx;
    atomic_fetch_add_explicit(&submit_ctx->entered, 1,
                              memory_order_relaxed);
    while (!atomic_load_explicit(&submit_ctx->release,
                                 memory_order_acquire)) {
        test_msg_sleep_ms(1);
    }
    validation_state_invalid(out, false, REJECT_INVALID,
                             "block-not-finalized-by-reducer", NULL);
    return false;
}

static int test_process_block_msg_queues_reducer_during_catchup(void)
{
    int failures = 0;
    TEST("msg_handlers: catch-up block intake does not block message thread") {
        test_msg_sync_to_blocks_download();
        ASSERT(sync_get_state() == SYNC_BLOCKS_DOWNLOAD);

        struct block blk;
        block_init(&blk);
        blk.header.nVersion = 4;
        blk.header.nTime = 1700000001u;
        blk.header.nBits = 0x1f00ffffu;
        blk.header.nNonce.data[0] = 9;

        struct uint256 hash;
        block_get_hash(&blk, &hash);
        block_clear_seen(&hash);

        struct byte_stream s;
        stream_init(&s, 256);
        ASSERT(block_serialize(&blk, &s));

        struct main_state ms;
        main_state_init(&ms);
        struct async_block_submit_ctx submit_ctx = {0};
        struct msg_processor mp;
        memset(&mp, 0, sizeof(mp));
        mp.main_state = &ms;
        mp.params = chain_params_get();
        mp.block_submit = submit_async_blocking_pending;
        mp.block_submit_ctx = &submit_ctx;
        mp.catchup_drain = count_async_catchup_drain;
        mp.catchup_drain_ctx = &submit_ctx;
        msg_processor_set_catchup_batch_scope(
            &mp, count_async_batch_begin, count_async_batch_end, &submit_ctx);

        struct p2p_node node;
        memset(&node, 0, sizeof(node));
        node.id = 88;
        snprintf(node.addr_name, sizeof(node.addr_name), "test-peer");

        ASSERT(process_block_msg(&mp, &node, &s));
        ASSERT(!atomic_load_explicit(&submit_ctx.release,
                                     memory_order_acquire));

        for (int i = 0; i < 200 &&
             atomic_load_explicit(&submit_ctx.entered,
                                  memory_order_acquire) == 0; i++) {
            test_msg_sleep_ms(1);
        }
        ASSERT(atomic_load_explicit(&submit_ctx.entered,
                                    memory_order_acquire) == 1);

        struct msg_block_intake_stats stats;
        msg_processor_get_block_intake_stats(&mp, &stats);
        ASSERT(stats.running);
        ASSERT(stats.capacity > 0);
        ASSERT(stats.enqueued == 1);
        ASSERT(stats.processed == 0);
        ASSERT(!block_already_seen(&hash));

        /* The periodic evaluator may commit while this worker owns the final
         * historical body; its post-submit reducer drain must survive. */
        ASSERT(sync_try_transition(SYNC_BLOCKS_DOWNLOAD, SYNC_AT_TIP,
                                   "unit periodic edge"));
        atomic_store_explicit(&submit_ctx.release, 1,
                              memory_order_release);
        msg_processor_stop_block_intake(&mp);
        ASSERT(atomic_load_explicit(&submit_ctx.drains,
                                    memory_order_acquire) == 1);
        ASSERT(atomic_load_explicit(&submit_ctx.batch_begins,
                                    memory_order_acquire) == 1);
        ASSERT(atomic_load_explicit(&submit_ctx.batch_ends,
                                    memory_order_acquire) == 1);
        stream_free(&s);
        block_free(&blk);
        main_state_free(&ms);
        test_msg_sync_to_idle();
        PASS();
    } _test_next:;
    return failures;
}

static int test_msg_block_intake_full_stays_retryable(void)
{
    int failures = 0;
    TEST("msg_handlers: full catch-up block intake stays retryable") {
        test_msg_sync_to_blocks_download();
        ASSERT(sync_get_state() == SYNC_BLOCKS_DOWNLOAD);

        struct block blk;
        block_init(&blk);
        blk.header.nVersion = 4;
        blk.header.nTime = 1700000002u;
        blk.header.nBits = 0x1f00ffffu;
        blk.header.nNonce.data[0] = 10;

        struct uint256 hash;
        block_get_hash(&blk, &hash);

        struct main_state ms;
        main_state_init(&ms);
        struct async_block_submit_ctx submit_ctx = {0};
        struct msg_processor mp;
        memset(&mp, 0, sizeof(mp));
        mp.main_state = &ms;
        mp.params = chain_params_get();
        mp.block_submit = submit_async_blocking_pending;
        mp.block_submit_ctx = &submit_ctx;

        bool saw_full = false;
        struct validation_state state;
        validation_state_init(&state);
        ASSERT(msg_processor_enqueue_p2p_block(&mp, &blk, &hash,
                                               89, &state));

        struct msg_block_intake_stats stats;
        msg_processor_get_block_intake_stats(&mp, &stats);
        ASSERT(stats.capacity > 0);
        /* Fill with distinct hashes: re-deliveries of a queued hash reuse its
         * slot (p2p-block-already-queued) and never reach the full arm, which
         * is only for first-seen bodies. */
        for (uint64_t i = 0; i <= stats.capacity && !saw_full; i++) {
            struct block other;
            block_init(&other);
            other.header.nVersion = 4;
            other.header.nTime = 1700000002u;
            other.header.nBits = 0x1f00ffffu;
            memset(&other.header.nNonce, 0, sizeof(other.header.nNonce));
            other.header.nNonce.data[0] = 10;
            uint64_t tag = i + 1;
            memcpy(&other.header.nNonce.data[8], &tag, sizeof(tag));
            struct uint256 other_hash;
            block_get_hash(&other, &other_hash);
            validation_state_init(&state);
            ASSERT(msg_processor_enqueue_p2p_block(&mp, &other, &other_hash,
                                                   89, &state));
            saw_full = strcmp(state.reject_reason,
                              "p2p-block-intake-full") == 0;
            block_free(&other);
        }

        ASSERT(saw_full);
        ASSERT(msg_block_validation_is_retryable(&state));

        msg_processor_get_block_intake_stats(&mp, &stats);
        ASSERT(stats.capacity > 0);
        ASSERT(stats.current_depth <= stats.capacity);
        ASSERT(stats.dropped > 0);
        ASSERT(stats.enqueued > 0);
        ASSERT(stats.duplicates == 0);

        atomic_store_explicit(&submit_ctx.release, 1,
                              memory_order_release);
        msg_processor_stop_block_intake(&mp);
        block_free(&blk);
        main_state_free(&ms);
        test_msg_sync_to_idle();
        PASS();
    } _test_next:;
    return failures;
}

static int test_msg_block_intake_duplicate_reuses_slot(void)
{
    int failures = 0;
    TEST("msg_handlers: duplicate block body reuses its intake slot") {
        test_msg_sync_to_blocks_download();
        ASSERT(sync_get_state() == SYNC_BLOCKS_DOWNLOAD);

        struct block blk;
        block_init(&blk);
        blk.header.nVersion = 4;
        blk.header.nTime = 1700000002u;
        blk.header.nBits = 0x1f00ffffu;
        blk.header.nNonce.data[0] = 10;

        struct uint256 hash;
        block_get_hash(&blk, &hash);

        struct main_state ms;
        main_state_init(&ms);
        struct async_block_submit_ctx submit_ctx = {0};
        struct msg_processor mp;
        memset(&mp, 0, sizeof(mp));
        mp.main_state = &ms;
        mp.params = chain_params_get();
        mp.block_submit = submit_async_blocking_pending;
        mp.block_submit_ctx = &submit_ctx;

        struct validation_state state;
        struct msg_block_intake_stats stats;

        /* Re-delivered bodies (timeout reassignment / grace) must reuse the
         * existing slot: capacity+1 copies of one hash take at most two slots
         * (ring + worker), so a first-seen body is still admitted. The worker
         * may dequeue the first copy early, so assert only invariants that
         * hold either way. */
        validation_state_init(&state);
        ASSERT(msg_processor_enqueue_p2p_block(&mp, &blk, &hash,
                                               89, &state));
        msg_processor_get_block_intake_stats(&mp, &stats);
        const uint64_t capacity = stats.capacity;
        ASSERT(capacity > 0);
        for (uint64_t i = 0; i < capacity; i++) {
            validation_state_init(&state);
            ASSERT(msg_processor_enqueue_p2p_block(&mp, &blk, &hash,
                                                   89, &state));
            ASSERT(strcmp(state.reject_reason,
                          "p2p-block-queued-for-reducer") == 0 ||
                   strcmp(state.reject_reason,
                          "p2p-block-already-queued") == 0);
            ASSERT(msg_block_validation_is_retryable(&state));
        }
        msg_processor_get_block_intake_stats(&mp, &stats);
        ASSERT(stats.enqueued + stats.duplicates == capacity + 1);
        ASSERT(stats.enqueued <= 2);
        ASSERT(stats.duplicates >= capacity - 1);
        ASSERT(stats.current_depth <= 1);
        ASSERT(stats.dropped == 0);

        /* The ring is nearly empty: a first-seen body is admitted
         * immediately, not dropped as full. */
        struct block other;
        block_init(&other);
        other.header.nVersion = 4;
        other.header.nTime = 1700000002u;
        other.header.nBits = 0x1f00ffffu;
        other.header.nNonce.data[0] = 11;
        struct uint256 other_hash;
        block_get_hash(&other, &other_hash);
        validation_state_init(&state);
        ASSERT(msg_processor_enqueue_p2p_block(&mp, &other, &other_hash,
                                               89, &state));
        ASSERT(strcmp(state.reject_reason,
                      "p2p-block-queued-for-reducer") == 0);
        msg_processor_get_block_intake_stats(&mp, &stats);
        ASSERT(stats.enqueued <= 3);
        ASSERT(stats.dropped == 0);
        block_free(&other);

        atomic_store_explicit(&submit_ctx.release, 1,
                              memory_order_release);
        msg_processor_stop_block_intake(&mp);
        block_free(&blk);
        main_state_free(&ms);
        test_msg_sync_to_idle();
        PASS();
    } _test_next:;
    return failures;
}

static void test_init_complete_empty_message(struct net_message *msg,
                                             const char *command)
{
    static const unsigned char msgstart[MESSAGE_START_SIZE] = {
        0x24, 0xe9, 0x27, 0x64
    };
    unsigned char hash[SHA256_OUTPUT_SIZE];
    net_message_init(msg, msgstart);
    msg_header_init_full(&msg->hdr, msgstart, command, 0);
    hash256(NULL, 0, hash);
    memcpy(&msg->hdr.nChecksum, hash, sizeof(msg->hdr.nChecksum));
    msg->in_data = true;
    msg->data_pos = 0;
}

static int test_msg_process_messages_yields_after_bounded_batch(void)
{
    int failures = 0;
    TEST("msg_handlers: inbound processing yields after bounded batch") {
        const size_t total = ZCL_MSG_PROCESS_MAX_PER_CYCLE + 3;
        struct p2p_node node;
        struct msg_processor mp;
        memset(&node, 0, sizeof(node));
        memset(&mp, 0, sizeof(mp));
        node.id = 88;
        node.version = 170011;
        atomic_store(&node.state, PEER_ACTIVE);
        zcl_mutex_init(&node.cs_recv);
        node.recv_msg_cap = total;
        node.recv_msg_count = total;
        node.recv_msgs = zcl_calloc(total, sizeof(*node.recv_msgs),
                                    "test_recv_msgs");
        ASSERT(node.recv_msgs != NULL);
        snprintf(node.addr_name, sizeof(node.addr_name), "test-peer");
        for (size_t i = 0; i < total; i++)
            test_init_complete_empty_message(&node.recv_msgs[i], "noop");

        ASSERT(msg_process_messages(&mp, &node));
        ASSERT(!node.disconnect);
        ASSERT(node.recv_msg_count == total - ZCL_MSG_PROCESS_MAX_PER_CYCLE);

        for (size_t i = 0; i < node.recv_msg_count; i++)
            net_message_free(&node.recv_msgs[i]);
        free(node.recv_msgs);
        zcl_mutex_destroy(&node.cs_recv);
        PASS();
    } _test_next:;
    return failures;
}

/* ── D1: swarm aggregate SHA3 UTXO-snapshot mismatch is not a
 * silent-accept ───────────────────────────────────────────────────
 *
 * Via msgprocessor_test_swarm_utxo_sha3_verify: PASSED records nothing and
 * returns true; a mismatch records PEER_OFFENCE_INVALID_PROOF, names the
 * "snapshot_sync.utxo_sha3_mismatch" typed DEPENDENCY blocker, and returns
 * false (sync not complete). */

static int test_swarm_utxo_sha3_verify_passed_is_quiet(void)
{
    int failures = 0;
    TEST("msg_handlers: swarm UTXO SHA3 verify PASSED records nothing, "
         "returns true") {
        blocker_module_init();
        blocker_reset_for_testing();

        struct net_manager nm;
        memset(&nm, 0, sizeof(nm));
        struct msg_processor mp;
        memset(&mp, 0, sizeof(mp));
        mp.net_mgr = &nm;

        struct p2p_node node;
        unreq_setup_node(&node, 601);

        uint8_t root[32];
        memset(root, 0x42, sizeof(root));

        bool ok = msgprocessor_test_swarm_utxo_sha3_verify(
            &mp, &node, root, root, 12345);

        ASSERT(ok);
        ASSERT(atomic_load(&node.misbehavior) == 0);
        ASSERT(!blocker_exists("snapshot_sync.utxo_sha3_mismatch"));

        blocker_reset_for_testing();
        PASS();
    } _test_next:;
    return failures;
}

static int test_swarm_utxo_sha3_verify_mismatch_is_not_silent(void)
{
    int failures = 0;
    TEST("msg_handlers: swarm UTXO SHA3 mismatch scores the peer, names "
         "a typed blocker, and reports sync NOT complete") {
        blocker_module_init();
        blocker_reset_for_testing();

        struct net_manager nm;
        net_manager_init(&nm);
        struct msg_processor mp;
        memset(&mp, 0, sizeof(mp));
        mp.net_mgr = &nm;

        struct p2p_node node;
        unreq_setup_node(&node, 602);

        uint8_t local_root[32];
        uint8_t expected_root[32];
        memset(local_root, 0x11, sizeof(local_root));
        memset(expected_root, 0x99, sizeof(expected_root));

        bool ok = msgprocessor_test_swarm_utxo_sha3_verify(
            &mp, &node, local_root, expected_root, 999);
        net_manager_free(&nm);

        /* Sync must NOT be reported complete on a mismatch. */
        ASSERT(!ok);

        /* Peer offence recorded — PEER_OFFENCE_INVALID_PROOF weight. */
        ASSERT_EQ(atomic_load(&node.misbehavior),
                  peer_offence_weight(PEER_OFFENCE_INVALID_PROOF));

        /* Typed blocker named (visible to dumpstate blocker). */
        ASSERT(blocker_exists("snapshot_sync.utxo_sha3_mismatch"));
        struct blocker_snapshot snaps[16];
        int n = blocker_snapshot_all(snaps, 16);
        bool found = false;
        for (int i = 0; i < n; i++) {
            if (strcmp(snaps[i].id, "snapshot_sync.utxo_sha3_mismatch") == 0) {
                found = true;
                ASSERT(snaps[i].class == BLOCKER_DEPENDENCY);
                ASSERT(snaps[i].retry_budget == -1);
                break;
            }
        }
        ASSERT(found);

        blocker_reset_for_testing();
        PASS();
    } _test_next:;
    return failures;
}

/* ── Characterization: zfilelist handler (via the dispatch table) ───
 * Pins handle_zfilelist: empty/truncated/paid/TTL-0 payloads are no-ops, TTL
 * clamps, at most 50 offers are read, and the relay gate runs only for a NEW
 * TTL>1 offer with a net manager. */
struct zfl_probe {
    int saves;
    int relay_calls;
    bool relay_answer;
};

static bool zfl_save(const struct file_offer *offer, void *ctx)
{
    (void)offer;
    ((struct zfl_probe *)ctx)->saves++;
    return true;
}

static bool zfl_relay_allowed(const struct file_offer *offer, void *ctx)
{
    struct zfl_probe *probe = ctx;
    (void)offer;
    probe->relay_calls++;
    return probe->relay_answer;
}

static void zfl_put(struct byte_stream *s, uint8_t id, uint8_t ttl,
                    int64_t price)
{
    struct file_offer o;
    memset(&o, 0, sizeof(o));
    o.root_hash[0] = 0xD0;
    o.root_hash[1] = id;
    snprintf(o.filename, sizeof(o.filename), "zfl-%u", (unsigned)id);
    o.size_bytes = 1024 * 1024;
    o.num_chunks = 1;
    o.price_per_mb = price;
    o.ttl = ttl;
    (void)file_offer_serialize(&o, s);
}

static bool zfl_stored(uint8_t id, struct file_offer *out)
{
    uint8_t root[32] = {0xD0, id};
    return file_market_find_offer(root, out);
}

/* Delivers the payload in s through the dispatch-table zfilelist row. */
static bool zfl_run(struct msg_processor *mp, struct byte_stream *s)
{
    const struct msg_dispatch_entry *e = msg_get_dispatch_table();
    while (e->handler && strcmp(e->command, "zfilelist") != 0)
        e++;
    struct p2p_node node = {.id = 901};
    snprintf(node.addr_name, sizeof(node.addr_name), "test-peer");
    return e->handler && e->handler(mp, &node, s);
}

/* One payload carrying exactly one offer. */
static bool zfl_send1(struct msg_processor *mp, uint8_t id, uint8_t ttl,
                      int64_t price)
{
    struct byte_stream s;
    stream_init(&s, 512);
    (void)stream_write_compact_size(&s, 1);
    zfl_put(&s, id, ttl, price);
    bool ok = zfl_run(mp, &s);
    stream_free(&s);
    return ok;
}

static int test_zfilelist_empty_and_dropped_offers(void)
{
    int failures = 0;
    TEST("msg_handlers: zfilelist no-ops on empty, paid, TTL-0 and truncated "
         "payloads; relay gate needs a net manager") {
        struct msg_processor mp;
        struct zfl_probe probe = {0};
        struct file_offer got;
        struct byte_stream s;
        memset(&mp, 0, sizeof(mp));
        probe.relay_answer = true;
        msg_processor_set_file_offer_save(&mp, zfl_save, &probe);
        msg_processor_set_offer_relay_allowed(&mp, zfl_relay_allowed, &probe);

        stream_init(&s, 64);
        ASSERT(zfl_run(&mp, &s));
        stream_free(&s);

        stream_init(&s, 256);
        ASSERT(stream_write_compact_size(&s, 3));
        zfl_put(&s, 21, 2, 1);
        zfl_put(&s, 22, 0, 0);
        ASSERT(zfl_run(&mp, &s));
        stream_free(&s);
        ASSERT(!zfl_stored(21, &got));
        ASSERT(!zfl_stored(22, &got));
        ASSERT_EQ(probe.saves, 0);
        ASSERT_EQ(probe.relay_calls, 0);

        ASSERT(zfl_send1(&mp, 26, 3, 0));
        ASSERT(zfl_stored(26, &got));
        ASSERT_EQ(got.ttl, 3);
        ASSERT_EQ(probe.saves, 1);
        ASSERT_EQ(probe.relay_calls, 0);
        PASS();
    } _test_next:;
    return failures;
}

static int test_zfilelist_ttl_clamp_relay_gate_and_update(void)
{
    int failures = 0;
    TEST("msg_handlers: zfilelist clamps TTL, counts relay refusals, and "
         "skips the gate for TTL 1 and updates") {
        struct msg_processor mp;
        struct net_manager nm;
        struct zfl_probe probe = {0};
        struct file_offer got;
        memset(&mp, 0, sizeof(mp));
        net_manager_init(&nm);
        mp.net_mgr = &nm;
        msg_processor_set_file_offer_save(&mp, zfl_save, &probe);
        msg_processor_set_offer_relay_allowed(&mp, zfl_relay_allowed, &probe);

        ASSERT(zfl_send1(&mp, 23, 200, 0));
        ASSERT(zfl_stored(23, &got));
        ASSERT_EQ(got.ttl, FILE_MARKET_MAX_TTL);
        ASSERT_EQ(probe.saves, 1);
        ASSERT_EQ(probe.relay_calls, 1);
        ASSERT_EQ(msg_processor_offer_relay_hidden(&mp), 1);

        ASSERT(zfl_send1(&mp, 24, 1, 0));
        ASSERT(zfl_stored(24, &got));
        ASSERT_EQ(probe.relay_calls, 1);

        ASSERT(zfl_send1(&mp, 23, 200, 0));
        ASSERT_EQ(probe.saves, 3);
        ASSERT_EQ(probe.relay_calls, 1);

        probe.relay_answer = true;
        ASSERT(zfl_send1(&mp, 27, 3, 0));
        ASSERT_EQ(probe.relay_calls, 2);
        ASSERT_EQ(msg_processor_offer_relay_hidden(&mp), 1);
        net_manager_free(&nm);
        PASS();
    } _test_next:;
    return failures;
}

static int test_zfilelist_count_clamp_and_truncated_batch(void)
{
    int failures = 0;
    TEST("msg_handlers: zfilelist reads at most 50 offers and stops at a "
         "truncated one") {
        struct msg_processor mp;
        struct zfl_probe probe = {0};
        struct file_offer got;
        struct byte_stream s;
        memset(&mp, 0, sizeof(mp));
        msg_processor_set_file_offer_save(&mp, zfl_save, &probe);
        msg_processor_set_offer_relay_allowed(&mp, zfl_relay_allowed, &probe);

        stream_init(&s, 1 << 16);
        ASSERT(stream_write_compact_size(&s, 60));
        for (uint8_t i = 0; i < 55; i++)
            zfl_put(&s, (uint8_t)(10 + i), 1, 0);
        ASSERT(zfl_run(&mp, &s));
        stream_free(&s);
        ASSERT(zfl_stored(59, &got));
        ASSERT(!zfl_stored(60, &got));
        ASSERT_EQ(probe.saves, 50);

        stream_init(&s, 256);
        ASSERT(stream_write_compact_size(&s, 2));
        zfl_put(&s, 70, 1, 0);
        ASSERT(zfl_run(&mp, &s));
        stream_free(&s);
        ASSERT_EQ(probe.saves, 51);
        PASS();
    } _test_next:;
    return failures;
}

static bool submit_async_nonretryable(struct block *block,
                                      struct validation_state *out, void *ctx)
{
    (void)block;
    struct async_block_submit_ctx *submit_ctx = ctx;
    atomic_fetch_add_explicit(&submit_ctx->entered, 1, memory_order_relaxed);
    validation_state_invalid(out, false, REJECT_INVALID, "bad-block-test",
                             NULL);
    return false;
}

static bool submit_async_accept(struct block *block,
                                struct validation_state *out, void *ctx)
{
    (void)block; (void)out; (void)ctx;
    return true;
}

/* Enqueues one body and waits for its outcome; snapshot precedes stop. */
static bool intake_run(struct msg_processor *mp, uint8_t tag,
                       struct uint256 *hash, struct msg_block_intake_stats *snap)
{
    struct block blk;
    struct validation_state state;
    block_init(&blk);
    blk.header.nVersion = 4;
    blk.header.nTime = 1700000003u;
    blk.header.nBits = 0x1f00ffffu;
    blk.header.nNonce.data[0] = tag;
    block_get_hash(&blk, hash);
    block_clear_seen(hash);
    validation_state_init(&state);
    bool queued = msg_processor_enqueue_p2p_block(mp, &blk, hash, 90 + tag,
                                                  &state);
    block_free(&blk);
    for (int i = 0; queued && i < 2000; i++) {
        msg_processor_get_block_intake_stats(mp, snap);
        if (snap->accepted + snap->rejected + snap->retryable > 0)
            return true;
        test_msg_sleep_ms(1);
    }
    return false;
}

static int test_intake_worker_rejects_nonretryable_body(void)
{
    int failures = 0;
    TEST("msg_handlers: intake worker rejects a non-retryable body, marks it "
         "seen, and brackets the batch") {
        test_msg_sync_to_blocks_download();
        ASSERT(sync_get_state() == SYNC_BLOCKS_DOWNLOAD);
        struct main_state ms;
        main_state_init(&ms);
        struct async_block_submit_ctx submit_ctx = {0};
        struct msg_processor mp;
        memset(&mp, 0, sizeof(mp));
        mp.main_state = &ms;
        mp.params = chain_params_get();
        mp.block_submit = submit_async_nonretryable;
        mp.block_submit_ctx = &submit_ctx;
        mp.catchup_drain = count_async_catchup_drain;
        mp.catchup_drain_ctx = &submit_ctx;
        msg_processor_set_catchup_batch_scope(
            &mp, count_async_batch_begin, count_async_batch_end, &submit_ctx);

        struct uint256 hash; struct msg_block_intake_stats stats;
        ASSERT(intake_run(&mp, 0x61, &hash, &stats));
        ASSERT_EQ(stats.rejected, 1);
        ASSERT_EQ(stats.accepted, 0);
        msg_processor_stop_block_intake(&mp);

        ASSERT(block_already_seen(&hash));
        ASSERT_EQ(atomic_load(&submit_ctx.entered), 1);
        ASSERT_EQ(atomic_load(&submit_ctx.batch_begins), 1);
        ASSERT_EQ(atomic_load(&submit_ctx.batch_ends), 1);
        ASSERT_EQ(atomic_load(&submit_ctx.drains), 1);
        main_state_free(&ms);
        test_msg_sync_to_idle();
        PASS();
    } _test_next:;
    return failures;
}

static int test_intake_worker_submit_unavailable_rejects(void)
{
    int failures = 0;
    TEST("msg_handlers: intake worker without a block submitter rejects the "
         "body as non-retryable") {
        test_msg_sync_to_blocks_download();
        ASSERT(sync_get_state() == SYNC_BLOCKS_DOWNLOAD);
        struct main_state ms;
        main_state_init(&ms);
        struct msg_processor mp;
        memset(&mp, 0, sizeof(mp));
        mp.main_state = &ms;
        mp.params = chain_params_get();

        struct uint256 hash; struct msg_block_intake_stats stats;
        ASSERT(intake_run(&mp, 0x62, &hash, &stats));
        ASSERT_EQ(stats.rejected, 1);
        msg_processor_stop_block_intake(&mp);

        ASSERT(block_already_seen(&hash));
        main_state_free(&ms);
        test_msg_sync_to_idle();
        PASS();
    } _test_next:;
    return failures;
}

static int test_intake_worker_accept_without_landing_not_marked_seen(void)
{
    int failures = 0;
    TEST("msg_handlers: intake worker accepts a valid body that did not land "
         "on the active chain without marking it seen") {
        test_msg_sync_to_blocks_download();
        ASSERT(sync_get_state() == SYNC_BLOCKS_DOWNLOAD);
        struct main_state ms;
        main_state_init(&ms);
        struct msg_processor mp;
        memset(&mp, 0, sizeof(mp));
        mp.main_state = &ms;
        mp.params = chain_params_get();
        mp.block_submit = submit_async_accept;

        struct uint256 hash; struct msg_block_intake_stats stats;
        ASSERT(intake_run(&mp, 0x63, &hash, &stats));
        ASSERT_EQ(stats.accepted, 1);
        ASSERT_EQ(stats.rejected, 0);
        msg_processor_stop_block_intake(&mp);

        ASSERT(!block_already_seen(&hash));
        main_state_free(&ms);
        test_msg_sync_to_idle();
        PASS();
    } _test_next:;
    return failures;
}

/* ── process_getdata / self-suspicion-gate pins (msg_blocks.c) ─────────
 *
 * Characterization: pin today's observable behaviour of process_getdata()
 * for each early return and for the notfound branches that need no mempool
 * or block file, and of msg_block_reject_self_suspected() as reached through
 * process_block_msg(). Wire output is read from node->send_head. */

#define PIN_NOTFOUND_PAYLOAD_SIZE 37 /* compact count(1) + inv type(4) + hash(32) */

static struct p2p_node *pin_peer_node(struct net_manager *nm, uint32_t id)
{
    struct net_address addr;
    net_address_init(&addr);
    unsigned char ip[4] = {198, 51, 100, (unsigned char)id};
    net_addr_set_ipv4(&addr.svc.addr, ip);
    addr.svc.port = 8033;
    return p2p_node_create(nm, ZCL_INVALID_SOCKET, &addr, "pin-peer", true);
}

static size_t pin_segment_count(struct p2p_node *node)
{
    size_t n = 0;
    for (struct send_segment *seg = node->send_head; seg; seg = seg->next)
        n++;
    return n;
}

/* True when exactly one wire "notfound" message carrying `hash` is queued. */
static bool pin_is_single_notfound(struct p2p_node *node,
                                   const struct uint256 *hash)
{
    const struct send_segment *seg = node->send_head;
    if (!seg || seg->next)
        return false;
    if (seg->size != MSG_HEADER_SIZE + PIN_NOTFOUND_PAYLOAD_SIZE)
        return false;
    if (strcmp((const char *)seg->data + MESSAGE_START_SIZE, "notfound") != 0)
        return false;
    const unsigned char *p =
        (const unsigned char *)seg->data + MSG_HEADER_SIZE;
    return p[0] == 1 && memcmp(p + 5, hash->data, 32) == 0;
}

static void pin_mp_init(struct msg_processor *mp, struct main_state *ms,
                        struct net_manager *nm)
{
    memset(mp, 0, sizeof(*mp));
    mp->main_state = ms;
    mp->params = chain_params_get();
    mp->net_mgr = nm;
}

static void pin_inv_stream(struct byte_stream *s, uint32_t type,
                           const struct uint256 *hash)
{
    struct inv_item inv;
    inv_item_init_typed(&inv, type, hash);
    inv_item_serialize(&inv, s);
}

static int test_pin_getdata_manifest_defers(void)
{
    int failures = 0;
    TEST("msg_handlers: getdata while a snapshot manifest is sent is deferred") {
        struct net_manager nm;
        net_manager_init(&nm);
        struct msg_processor mp;
        pin_mp_init(&mp, NULL, &nm);
        struct p2p_node *node = pin_peer_node(&nm, 611);
        ASSERT(node != NULL);
        node->swarm_manifest_sent = true;

        struct uint256 h;
        memset(h.data, 0x61, sizeof(h.data));
        struct byte_stream s;
        stream_init(&s, 64);
        stream_write_compact_size(&s, 1);
        pin_inv_stream(&s, MSG_BLOCK, &h);

        ASSERT(process_getdata(&mp, node, &s) == true);
        ASSERT(pin_segment_count(node) == 0);
        ASSERT(!node->disconnect);
        ASSERT(atomic_load(&node->misbehavior) == 0);
        stream_free(&s);
        p2p_node_free(node);
        net_manager_free(&nm);
        PASS();
    } _test_next:;
    return failures;
}

static int test_pin_getdata_count_unreadable(void)
{
    int failures = 0;
    TEST("msg_handlers: getdata with an empty payload fails, no reply, no penalty") {
        struct net_manager nm;
        net_manager_init(&nm);
        struct msg_processor mp;
        pin_mp_init(&mp, NULL, &nm);
        struct p2p_node *node = pin_peer_node(&nm, 612);
        ASSERT(node != NULL);

        struct byte_stream s;
        stream_init(&s, 8);
        ASSERT(process_getdata(&mp, node, &s) == false);
        ASSERT(pin_segment_count(node) == 0);
        ASSERT(!node->disconnect);
        ASSERT(atomic_load(&node->misbehavior) == 0);
        stream_free(&s);
        p2p_node_free(node);
        net_manager_free(&nm);
        PASS();
    } _test_next:;
    return failures;
}

static int test_pin_getdata_oversized_count(void)
{
    int failures = 0;
    TEST("msg_handlers: getdata count above MAX_INV_SZ refuses, disconnects, scores 20") {
        struct net_manager nm;
        net_manager_init(&nm);
        struct msg_processor mp;
        pin_mp_init(&mp, NULL, &nm);
        struct p2p_node *node = pin_peer_node(&nm, 613);
        ASSERT(node != NULL);

        struct byte_stream s;
        stream_init(&s, 8);
        stream_write_compact_size(&s, MAX_INV_SZ + 1);
        ASSERT(process_getdata(&mp, node, &s) == false);
        ASSERT(node->disconnect);
        ASSERT(atomic_load(&node->misbehavior) == 20);
        ASSERT(pin_segment_count(node) == 0);
        stream_free(&s);
        p2p_node_free(node);
        net_manager_free(&nm);
        PASS();
    } _test_next:;
    return failures;
}

static int test_pin_getdata_empty_count(void)
{
    int failures = 0;
    TEST("msg_handlers: getdata count 0 succeeds with nothing queued") {
        struct net_manager nm;
        net_manager_init(&nm);
        struct msg_processor mp;
        pin_mp_init(&mp, NULL, &nm);
        struct p2p_node *node = pin_peer_node(&nm, 614);
        ASSERT(node != NULL);

        struct byte_stream s;
        stream_init(&s, 8);
        stream_write_compact_size(&s, 0);
        ASSERT(process_getdata(&mp, node, &s) == true);
        ASSERT(pin_segment_count(node) == 0);
        ASSERT(!node->disconnect);
        stream_free(&s);
        p2p_node_free(node);
        net_manager_free(&nm);
        PASS();
    } _test_next:;
    return failures;
}

static int test_pin_getdata_truncated_item(void)
{
    int failures = 0;
    TEST("msg_handlers: getdata whose declared inv is truncated fails, no reply") {
        struct net_manager nm;
        net_manager_init(&nm);
        struct msg_processor mp;
        pin_mp_init(&mp, NULL, &nm);
        struct p2p_node *node = pin_peer_node(&nm, 615);
        ASSERT(node != NULL);

        struct byte_stream s;
        stream_init(&s, 8);
        stream_write_compact_size(&s, 1);
        ASSERT(process_getdata(&mp, node, &s) == false);
        ASSERT(pin_segment_count(node) == 0);
        stream_free(&s);
        p2p_node_free(node);
        net_manager_free(&nm);
        PASS();
    } _test_next:;
    return failures;
}

static int test_pin_getdata_unknown_type_notfound(void)
{
    int failures = 0;
    TEST("msg_handlers: getdata inv of an unserved type gets one notfound") {
        struct net_manager nm;
        net_manager_init(&nm);
        struct msg_processor mp;
        pin_mp_init(&mp, NULL, &nm);
        struct p2p_node *node = pin_peer_node(&nm, 616);
        ASSERT(node != NULL);

        struct uint256 h;
        memset(h.data, 0x62, sizeof(h.data));
        struct byte_stream s;
        stream_init(&s, 64);
        stream_write_compact_size(&s, 1);
        pin_inv_stream(&s, MSG_FILTERED_BLOCK, &h);
        ASSERT(process_getdata(&mp, node, &s) == true);
        ASSERT(pin_segment_count(node) == 1);
        ASSERT(pin_is_single_notfound(node, &h));
        stream_free(&s);
        p2p_node_free(node);
        net_manager_free(&nm);
        PASS();
    } _test_next:;
    return failures;
}

static int test_pin_getdata_unindexed_block_notfound(void)
{
    int failures = 0;
    TEST("msg_handlers: getdata for a block absent from the index gets notfound") {
        struct main_state ms;
        main_state_init(&ms);
        struct net_manager nm;
        net_manager_init(&nm);
        struct msg_processor mp;
        pin_mp_init(&mp, &ms, &nm);
        struct p2p_node *node = pin_peer_node(&nm, 617);
        ASSERT(node != NULL);

        struct uint256 h;
        memset(h.data, 0x63, sizeof(h.data));
        struct byte_stream s;
        stream_init(&s, 64);
        stream_write_compact_size(&s, 1);
        pin_inv_stream(&s, MSG_BLOCK, &h);
        ASSERT(process_getdata(&mp, node, &s) == true);
        ASSERT(pin_is_single_notfound(node, &h));
        stream_free(&s);
        p2p_node_free(node);
        net_manager_free(&nm);
        main_state_free(&ms);
        PASS();
    } _test_next:;
    return failures;
}

static int test_pin_getdata_unservable_indexed_block_notfound(void)
{
    int failures = 0;
    TEST("msg_handlers: getdata for an indexed block without stored data gets notfound") {
        struct main_state ms;
        main_state_init(&ms);
        struct net_manager nm;
        net_manager_init(&nm);
        struct msg_processor mp;
        pin_mp_init(&mp, &ms, &nm);
        struct p2p_node *node = pin_peer_node(&nm, 618);
        ASSERT(node != NULL);

        struct uint256 h;
        memset(h.data, 0x64, sizeof(h.data));
        struct block_index *bi =
            chainstate_insert_block_index((struct chainstate *)&ms, &h);
        ASSERT(bi != NULL);
        bi->nStatus = 0; /* header only: BLOCK_HAVE_DATA not set */

        struct byte_stream s;
        stream_init(&s, 64);
        stream_write_compact_size(&s, 1);
        pin_inv_stream(&s, MSG_BLOCK, &h);
        ASSERT(process_getdata(&mp, node, &s) == true);
        ASSERT(pin_is_single_notfound(node, &h));
        stream_free(&s);
        p2p_node_free(node);
        net_manager_free(&nm);
        main_state_free(&ms);
        PASS();
    } _test_next:;
    return failures;
}

/* ── process_block_msg reject path: self-suspicion gate ───────────── */

enum pin_reject_mode {
    PIN_REJECT_NO_INDEX,
    PIN_REJECT_EQUAL_WORK,
    PIN_REJECT_MORE_WORK,
};

static bool pin_submit_invalid(struct block *block,
                               struct validation_state *out, void *ctx)
{
    (void)block;
    (void)ctx;
    validation_state_invalid(out, false, REJECT_INVALID,
                             "bad-txns-inputs-missingorspent", NULL);
    return false;
}

/* Feed one locally-rejected, non-retryable block through process_block_msg.
 * Premise: sync is AT_TIP, so msg_processor_enqueue_p2p_block declines and
 * block_submit runs the invalid verdict. (At any other sync state the block
 * would be queued as retryable and never reach block_mark_seen.) The gate
 * declines to self-suspect in every mode here (no index, equal work, or a
 * more-work block that the height or body gate declines), so the block must
 * be dedup-marked. */
static bool pin_reject_marks_seen(enum pin_reject_mode mode)
{
    struct block blk;
    block_init(&blk);
    blk.header.nVersion = 4;
    blk.header.nTime = 1700000030u + (uint32_t)mode;
    blk.header.nBits = 0x1f00ffffu;
    blk.header.nNonce.data[0] = (uint8_t)(40 + mode);

    struct uint256 hash;
    block_get_hash(&blk, &hash);
    block_clear_seen(&hash);

    struct byte_stream s;
    stream_init(&s, 256);
    bool ok = block_serialize(&blk, &s);

    struct main_state ms;
    main_state_init(&ms);
    struct uint256 gh = chain_params_get()->consensus.hashGenesisBlock;
    struct block_index *gen =
        chainstate_insert_block_index((struct chainstate *)&ms, &gh);
    if (gen) {
        gen->nHeight = 0;
        gen->nStatus = BLOCK_HAVE_DATA | BLOCK_VALID_SCRIPTS;
        active_chain_move_window_tip(&ms.chain_active, gen);
        ms.pindex_best_header = gen;
    }
    if (mode != PIN_REJECT_NO_INDEX) {
        struct block_index *bi =
            chainstate_insert_block_index((struct chainstate *)&ms, &hash);
        if (bi) {
            bi->nHeight = 1;
            if (mode == PIN_REJECT_MORE_WORK) {
                bool neg = false, ovf = false;
                arith_uint256_set_compact(&bi->nChainWork, 0x1f00ffffu,
                                          &neg, &ovf);
            }
        }
    }

    peer_scoring_init();
    dl_init(get_download_mgr());
    struct net_manager nm;
    net_manager_init(&nm);
    struct msg_processor mp;
    pin_mp_init(&mp, &ms, &nm);
    mp.block_submit = pin_submit_invalid;
    mp.block_submit_ctx = NULL;
    struct p2p_node *node = pin_peer_node(&nm, 621);

    /* Establish the AT_TIP premise explicitly; restored to IDLE below. */
    test_msg_sync_to_blocks_download();
    bool at_tip = sync_try_transition(SYNC_BLOCKS_DOWNLOAD, SYNC_AT_TIP,
                                      "msg_handlers reject premise");

    bool ret = at_tip && ok && node && process_block_msg(&mp, node, &s);
    bool seen = block_already_seen(&hash);

    msg_processor_stop_block_intake(&mp);
    test_msg_sync_to_idle();
    if (node)
        p2p_node_free(node);
    net_manager_free(&nm);
    stream_free(&s);
    block_free(&blk);
    main_state_free(&ms);
    block_clear_seen(&hash);
    return ret && seen;
}

static int test_pin_reject_no_index_marks_seen(void)
{
    int failures = 0;
    TEST("msg_handlers: rejected block with no header index is marked seen (ban path)") {
        ASSERT(pin_reject_marks_seen(PIN_REJECT_NO_INDEX));
        PASS();
    } _test_next:;
    return failures;
}

static int test_pin_reject_equal_work_marks_seen(void)
{
    int failures = 0;
    TEST("msg_handlers: rejected block with work equal to tip is marked seen (ban path)") {
        ASSERT(pin_reject_marks_seen(PIN_REJECT_EQUAL_WORK));
        PASS();
    } _test_next:;
    return failures;
}

static int test_pin_reject_more_work_marks_seen(void)
{
    int failures = 0;
    TEST("msg_handlers: more-work block the self-suspicion gate declines is marked seen (ban path)") {
        ASSERT(pin_reject_marks_seen(PIN_REJECT_MORE_WORK));
        PASS();
    } _test_next:;
    return failures;
}

/* Build-identity prefix reader (msg_version_parse_build_identity_prefix),
 * one row per branch. A "(src:" candidate whose first 12 characters are not
 * lowercase hex is skipped and the scan moves to the next marker. Success
 * writes the 12-character prefix; a refusal once the scan starts leaves
 * out[0] == '\0', while a short buffer is refused with out untouched. */
struct msg_prefix_row {
    const char *subver;
    bool ok;
    const char *want;
};

static int test_msg_build_identity_prefix_branches(void)
{
    int failures = 0;
    static const struct msg_prefix_row rows[] = {
        {"/ZClassic23:0.1.0(src:0123456789ab)/", true, "0123456789ab"},
        {"/ZClassic23:0.1.0(src:0123456789ab)zzz", true, "0123456789ab"},
        {"(src:zzzzzzzzzzzz)(src:fedcba987654)", true, "fedcba987654"},
        {"(src:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef)/",
         true, "0123456789ab"},
        {"(src:0123456789a)", false, ""},
        {"(src:0123456789AB)", false, ""},
        {"(src:0123456789abx)", false, ""},
        {"(src:0123456789abcd", false, ""},
        {"(src:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdefx",
         false, ""},
        {"/ZClassic23:0.1.0/", false, ""},
    };
    TEST("msg_handlers: build identity prefix reader, one row per branch") {
        char out[ZCL_BUILD_IDENTITY_PREFIX_BUFSIZE];
        for (size_t i = 0; i < sizeof(rows) / sizeof(rows[0]); i++) {
            memset(out, 'x', sizeof(out));
            ASSERT_EQ(msg_version_parse_build_identity_prefix(
                          rows[i].subver, out, sizeof(out)), rows[i].ok);
            ASSERT(strcmp(out, rows[i].ok ? rows[i].want : "") == 0);
        }

        /* Refusals before any scan: a short buffer is left untouched. */
        memset(out, 'x', sizeof(out));
        ASSERT(!msg_version_parse_build_identity_prefix(
            "(src:0123456789ab)", out, ZCL_BUILD_IDENTITY_PREFIX_BUFSIZE - 1));
        ASSERT(out[0] == 'x');
        ASSERT(!msg_version_parse_build_identity_prefix(
            "(src:0123456789ab)", NULL, sizeof(out)));
        ASSERT(!msg_version_parse_build_identity_prefix(NULL, out, sizeof(out)));
        ASSERT(out[0] == '\0');
        PASS();
    } _test_next:;
    return failures;
}

/* ── Entry point ───────────────────────────────────────────────── */

int test_msg_handlers(void);

int test_msg_handlers(void)
{
    int failures = 0;

    failures += test_headers_stats_null_safe();
    failures += test_headers_stats_initial();
    failures += test_block_dedup_basic();
    failures += test_block_dedup_mark_and_check();
    failures += test_block_dedup_clear();
    failures += test_block_dedup_multiple();
    failures += test_tx_dedup_basic();
    failures += test_tx_dedup_mark_and_check();
    failures += test_dandelion_initial_state();
    failures += test_p148_should_mark_seen_rejects_null();
    failures += test_p148_should_mark_seen_rejects_orphan();
    failures += test_p148_should_mark_seen_accepts_active();
    failures += test_should_announce_getblocks();
    failures += test_source_header_echo_policy();
    failures += test_block_validation_retryable_classifier();
    failures += test_process_block_msg_reducer_pending_stays_retryable();
    failures += test_process_block_msg_scores_unrequested();
    failures += test_process_block_msg_no_score_when_requested();
    failures += test_process_block_msg_no_score_when_requested_from_peer_zero();
    failures += test_process_block_msg_no_score_within_settle_grace();
    failures += test_process_block_msg_no_score_during_shutdown();
    failures += test_process_block_msg_queues_reducer_during_catchup();
    failures += test_msg_block_intake_full_stays_retryable();
    failures += test_msg_block_intake_duplicate_reuses_slot();
    failures += test_msg_process_messages_yields_after_bounded_batch();
    failures += test_swarm_utxo_sha3_verify_passed_is_quiet();
    failures += test_swarm_utxo_sha3_verify_mismatch_is_not_silent();
    failures += test_zfilelist_empty_and_dropped_offers();
    failures += test_zfilelist_ttl_clamp_relay_gate_and_update();
    failures += test_zfilelist_count_clamp_and_truncated_batch();
    failures += test_intake_worker_rejects_nonretryable_body();
    failures += test_intake_worker_submit_unavailable_rejects();
    failures += test_intake_worker_accept_without_landing_not_marked_seen();
    failures += test_pin_getdata_manifest_defers();
    failures += test_pin_getdata_count_unreadable();
    failures += test_pin_getdata_oversized_count();
    failures += test_pin_getdata_empty_count();
    failures += test_pin_getdata_truncated_item();
    failures += test_pin_getdata_unknown_type_notfound();
    failures += test_pin_getdata_unindexed_block_notfound();
    failures += test_pin_getdata_unservable_indexed_block_notfound();
    failures += test_pin_reject_no_index_marks_seen();
    failures += test_pin_reject_equal_work_marks_seen();
    failures += test_pin_reject_more_work_marks_seen();
    failures += test_msg_build_identity_prefix_branches();

    return failures;
}
