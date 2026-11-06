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
#include "net/fast_sync.h"
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
#include "validation/check_block.h"
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

/* The grouped tests share the process-wide download manager. dl_init
 * overwrites its buffers without freeing them, so release the previous
 * set first, and release the last set when the group finishes. */
static void test_msg_dl_reset(void)
{
    struct download_manager *dm = get_download_mgr();
    dl_free(dm);
    dl_init(dm);
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
        test_msg_dl_reset();

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
        test_msg_dl_reset();

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
        test_msg_dl_reset();

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
        test_msg_dl_reset();
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
        test_msg_dl_reset();
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

static int test_pin_getdata_serving_defers(void)
{
    int failures = 0;
    TEST("msg_handlers: getdata while a snapshot is served to the peer is deferred") {
        struct net_manager nm;
        net_manager_init(&nm);
        struct msg_processor mp;
        pin_mp_init(&mp, NULL, &nm);
        struct p2p_node *node = pin_peer_node(&nm, 611);
        ASSERT(node != NULL);
        node->state = PEER_SNAPSHOT_SERVING;

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

/* ── a peer's snapshot chunks stay out of the live utxos table ─────────
 *
 * Driven through the real zmanifest and zchunkdata handlers against a fixture
 * node.db. Chunks can only be trusted once they can go to staging, so a manifest
 * starts no swarm and a chunk changes nothing. swarm_manifest_received still says
 * only that a manifest with a good root arrived. */
bool mp_handle_zcl23_sync(struct msg_processor *mp, struct p2p_node *node,
                          struct byte_stream *s, const char *cmd);

#define SWARM_REFUSE_ROWS_MAX 1024
#define SWARM_REFUSE_REPEATS 64

struct swarm_refuse_fx {
    char dir[512];
    char path[600];
    struct net_manager nm;
    struct main_state ms;
    struct msg_processor mp;
    struct p2p_node *node;
    struct utxo_chunk *chunk;
    uint8_t hash[32];
    uint8_t root[32];
};

/* Every row, every column, as text, so a comparison sees any changed byte. */
static bool swarm_refuse_read_rows(const char *path,
                                   char out[SWARM_REFUSE_ROWS_MAX])
{
    sqlite3 *db = NULL;
    sqlite3_stmt *st = NULL;
    bool ok = false;
    out[0] = '\0';
    if (sqlite3_open(path, &db) == SQLITE_OK &&
        sqlite3_prepare_v2(db,
            "SELECT count(*) || ':' || group_concat(hex(txid) || '/' || vout "
            "|| '/' || value || '/' || hex(script) || '/' || script_type || "
            "'/' || hex(address_hash) || '/' || height || '/' || is_coinbase, "
            "';') FROM utxos", -1, &st, NULL) == SQLITE_OK &&
        sqlite3_step(st) == SQLITE_ROW && sqlite3_column_text(st, 0)) {
        snprintf(out, SWARM_REFUSE_ROWS_MAX, "%s",
                 (const char *)sqlite3_column_text(st, 0));
        ok = true;
    }
    sqlite3_finalize(st);
    sqlite3_close(db);
    return ok;
}

/* One honest row, on the outpoint the chunk below also carries. */
static bool swarm_refuse_seed_db(const char *path, const uint8_t txid[32])
{
    sqlite3 *db = NULL;
    sqlite3_stmt *st = NULL;
    bool ok = sqlite3_open(path, &db) == SQLITE_OK &&
        sqlite3_exec(db,
            "CREATE TABLE utxos (txid BLOB NOT NULL, vout INTEGER NOT NULL, "
            "value INTEGER NOT NULL, script BLOB NOT NULL, "
            "script_type INTEGER NOT NULL DEFAULT 0, address_hash BLOB, "
            "height INTEGER NOT NULL, is_coinbase INTEGER NOT NULL DEFAULT 0, "
            "PRIMARY KEY (txid, vout))", NULL, NULL, NULL) == SQLITE_OK &&
        sqlite3_prepare_v2(db,
            "INSERT INTO utxos VALUES (?,0,7000,x'76a9',2,x'0102',50,1)",
            -1, &st, NULL) == SQLITE_OK;
    if (ok) {
        sqlite3_bind_blob(st, 1, txid, 32, SQLITE_STATIC);
        ok = sqlite3_step(st) == SQLITE_DONE;
    }
    sqlite3_finalize(st);
    sqlite3_close(db);
    return ok;
}

static bool swarm_refuse_fx_init(struct swarm_refuse_fx *fx, uint32_t peer)
{
    memset(fx, 0, sizeof(*fx));
    test_make_tmpdir(fx->dir, sizeof(fx->dir), "msg_handlers", "swarm_refuse");
    snprintf(fx->path, sizeof(fx->path), "%s/node.db", fx->dir);
    net_manager_init(&fx->nm);
    main_state_init(&fx->ms);
    pin_mp_init(&fx->mp, &fx->ms, &fx->nm);
    fx->mp.datadir = fx->dir;
    fx->node = pin_peer_node(&fx->nm, peer);
    fx->chunk = zcl_calloc(1, sizeof(*fx->chunk), "swarm_refuse_chunk");
    if (!fx->node || !fx->chunk)
        return false;
    fx->node->services = NODE_ZCL23;
    fx->chunk->num_entries = 1;
    memset(fx->chunk->entries[0].txid, 0xB1, 32);
    fx->chunk->entries[0].value = 9000;
    fx->chunk->entries[0].height = 60;
    fx->chunk->entries[0].script[0] = 0x51;
    fx->chunk->entries[0].script_len = 1;
    fast_sync_chunk_hash(fx->chunk, fx->hash);
    fast_sync_merkle_root((const uint8_t (*)[32])&fx->hash, 1, fx->root);
    msgprocessor_test_swarm_release();
    return swarm_refuse_seed_db(fx->path, fx->chunk->entries[0].txid);
}

static void swarm_refuse_fx_free(struct swarm_refuse_fx *fx)
{
    msgprocessor_test_swarm_release();
    free(fx->chunk);
    if (fx->node)
        p2p_node_free(fx->node);
    main_state_free(&fx->ms);
    net_manager_free(&fx->nm);
    test_cleanup_tmpdir(fx->dir);
}

static bool swarm_refuse_send_manifest(struct swarm_refuse_fx *fx,
                                       int32_t height, const uint8_t root[32])
{
    uint8_t zero[32] = {0};
    struct byte_stream s;
    stream_init(&s, 256);
    stream_write_i32_le(&s, height);
    stream_write_bytes(&s, zero, 32);
    stream_write_u64_le(&s, 1);
    stream_write_u32_le(&s, 1);
    stream_write_u32_le(&s, SYNC_CHUNK_SIZE);
    stream_write_bytes(&s, root, 32);
    stream_write_bytes(&s, zero, 32);
    stream_write_bytes(&s, fx->hash, 32);
    bool ok = mp_handle_zcl23_sync(&fx->mp, fx->node, &s, MSG_MANIFEST);
    stream_free(&s);
    return ok;
}

static bool swarm_refuse_send_chunk(struct swarm_refuse_fx *fx)
{
    const struct utxo_chunk *c = fx->chunk;
    struct byte_stream s;
    stream_init(&s, 256);
    stream_write_u32_le(&s, c->chunk_index);
    stream_write_u32_le(&s, c->num_entries);
    stream_write_bytes(&s, c->entries[0].txid, 32);
    stream_write_i32_le(&s, (int32_t)c->entries[0].vout);
    stream_write_i64_le(&s, c->entries[0].value);
    stream_write_i32_le(&s, c->entries[0].height);
    stream_write_u8(&s, 0);
    stream_write_u16_le(&s, (uint16_t)c->entries[0].script_len);
    stream_write_bytes(&s, c->entries[0].script, c->entries[0].script_len);
    bool ok = mp_handle_zcl23_sync(&fx->mp, fx->node, &s, MSG_CHUNK_DATA);
    stream_free(&s);
    return ok;
}

/* What one manifest-then-chunk exchange left behind. Asserted after teardown,
 * so a failure leaves no swarm claimed for the cases that follow. */
struct swarm_refuse_seen {
    bool setup_ok;
    bool handlers_ok;
    bool started;
    bool received;
    size_t segments;
    int misbehavior;
    int32_t inflight;
    bool rows_read;
    char before[SWARM_REFUSE_ROWS_MAX];
    char after[SWARM_REFUSE_ROWS_MAX];
};

/* `above` is how far the manifest's height sits past our own tip. */
static void swarm_refuse_exchange(struct swarm_refuse_seen *seen, uint32_t peer,
                                  int32_t above, int repeats)
{
    struct swarm_refuse_fx fx;
    memset(seen, 0, sizeof(*seen));
    seen->setup_ok = swarm_refuse_fx_init(&fx, peer);
    if (seen->setup_ok) {
        int32_t height = active_chain_height(&fx.ms.chain_active) + above;
        fx.node->swarm_inflight_chunk = -1;
        seen->rows_read = swarm_refuse_read_rows(fx.path, seen->before);
        seen->handlers_ok = true;
        for (int i = 0; i < repeats; i++) {
            seen->handlers_ok &=
                swarm_refuse_send_manifest(&fx, height, fx.root);
            seen->started |= msgprocessor_test_swarm_is_active();
            seen->handlers_ok &= swarm_refuse_send_chunk(&fx);
        }
        seen->rows_read &= swarm_refuse_read_rows(fx.path, seen->after);
        seen->received = fx.node->swarm_manifest_received;
        seen->segments = pin_segment_count(fx.node);
        seen->misbehavior = atomic_load(&fx.node->misbehavior);
        seen->inflight = fx.node->swarm_inflight_chunk;
        printf("swarm refuse: above=%d started=%d segments=%zu\n  before %s\n"
               "  after  %s\n", above, seen->started, seen->segments,
               seen->before, seen->after);
    }
    swarm_refuse_fx_free(&fx);
}

static bool swarm_refuse_left_nothing(const struct swarm_refuse_seen *seen)
{
    return seen->setup_ok && seen->handlers_ok && seen->rows_read &&
           seen->received && !seen->started && seen->segments == 0 &&
           seen->inflight == -1 && seen->misbehavior == 0;
}

static int test_swarm_manifest_above_tip_starts_nothing(void)
{
    int failures = 0;
    TEST("msg_handlers: a manifest above our tip starts no swarm, a chunk changes no row") {
        struct swarm_refuse_seen *seen = zcl_calloc(1, sizeof(*seen), "swarm_seen");
        ASSERT(seen != NULL);
        swarm_refuse_exchange(seen, 619, 100000, 1);
        bool same = seen->rows_read && strcmp(seen->before, seen->after) == 0;
        bool nothing = swarm_refuse_left_nothing(seen);
        free(seen);
        ASSERT(same);
        ASSERT(nothing);
        PASS();
    } _test_next:;
    return failures;
}

static int test_swarm_manifest_repeats_cost_nothing_lasting(void)
{
    int failures = 0;
    TEST("msg_handlers: repeated manifests and chunks queue nothing and score nothing") {
        struct swarm_refuse_seen *seen = zcl_calloc(1, sizeof(*seen), "swarm_seen");
        ASSERT(seen != NULL);
        swarm_refuse_exchange(seen, 620, 100000, SWARM_REFUSE_REPEATS);
        bool same = seen->rows_read && strcmp(seen->before, seen->after) == 0;
        bool nothing = swarm_refuse_left_nothing(seen);
        free(seen);
        ASSERT(same);
        ASSERT(nothing);
        PASS();
    } _test_next:;
    return failures;
}

static int test_swarm_manifest_near_tip_as_before(void)
{
    int failures = 0;
    TEST("msg_handlers: a manifest at or below our tip + 100 only records it") {
        struct swarm_refuse_seen *seen = zcl_calloc(1, sizeof(*seen), "swarm_seen");
        ASSERT(seen != NULL);
        swarm_refuse_exchange(seen, 621, 100, 1);
        bool same = seen->rows_read && strcmp(seen->before, seen->after) == 0;
        bool nothing = swarm_refuse_left_nothing(seen);
        free(seen);
        ASSERT(same);
        ASSERT(nothing);
        PASS();
    } _test_next:;
    return failures;
}

/* A manifest whose hashes do not rebuild its root is not recorded as received
 * and starts nothing, whatever its height. */
static int test_swarm_manifest_bad_root_not_recorded(void)
{
    int failures = 0;
    TEST("msg_handlers: a manifest with a bad root is not recorded as received") {
        struct swarm_refuse_fx fx;
        bool setup = swarm_refuse_fx_init(&fx, 622);
        bool received = true;
        bool started = true;
        if (setup) {
            uint8_t wrong[32];
            memset(wrong, 0x5c, sizeof(wrong));
            (void)swarm_refuse_send_manifest(&fx, 100000, wrong);
            received = fx.node->swarm_manifest_received;
            started = msgprocessor_test_swarm_is_active();
        }
        swarm_refuse_fx_free(&fx);
        ASSERT(setup);
        ASSERT(!received);
        ASSERT(!started);
        PASS();
    } _test_next:;
    return failures;
}

/* The manifest goes out at the handshake and says what this node can offer. A
 * peer that got one and is not pulling a snapshot still gets its answers. */
static int test_pin_getdata_after_manifest_answers(void)
{
    int failures = 0;
    TEST("msg_handlers: getdata from a peer that was sent a manifest is answered") {
        struct net_manager nm;
        net_manager_init(&nm);
        struct msg_processor mp;
        pin_mp_init(&mp, NULL, &nm);
        struct p2p_node *node = pin_peer_node(&nm, 618);
        ASSERT(node != NULL);
        node->swarm_manifest_sent = true;

        struct uint256 h;
        memset(h.data, 0x64, sizeof(h.data));
        struct byte_stream s;
        stream_init(&s, 64);
        stream_write_compact_size(&s, 1);
        pin_inv_stream(&s, MSG_FILTERED_BLOCK, &h);

        ASSERT(process_getdata(&mp, node, &s) == true);
        ASSERT(pin_segment_count(node) == 1);
        ASSERT(pin_is_single_notfound(node, &h));
        ASSERT(atomic_load(&node->misbehavior) == 0);
        stream_free(&s);
        p2p_node_free(node);
        net_manager_free(&nm);
        PASS();
    } _test_next:;
    return failures;
}

/* A reply on the socketless fixture latches a local-shutdown disconnect from the
 * failed send, and the replay skips a peer that is going away. */
static void pin_clear_fixture_disconnect(struct p2p_node *node)
{
    node->disconnect = false;
    node->disconnect_reason = P2P_DISCONNECT_NONE;
}

/* A block asked for while a snapshot is served goes in the peer's slot and waits:
 * no reply during the stream, and the send tick finishes it once the stream is
 * over. The block is unknown here, so finishing it means its notfound. */
static int test_getdata_held_while_serving_finishes_after(void)
{
    int failures = 0;
    TEST("msg_handlers: a block asked for while serving is kept and finished after") {
        struct net_manager nm;
        net_manager_init(&nm);
        struct main_state ms;
        main_state_init(&ms);
        struct msg_processor mp;
        pin_mp_init(&mp, &ms, &nm);
        struct p2p_node *node = pin_peer_node(&nm, 623);
        ASSERT(node != NULL);
        node->state = PEER_SNAPSHOT_SERVING;

        struct uint256 h;
        memset(h.data, 0x65, sizeof(h.data));
        struct byte_stream s;
        stream_init(&s, 64);
        stream_write_compact_size(&s, 1);
        pin_inv_stream(&s, MSG_BLOCK, &h);
        ASSERT(process_getdata(&mp, node, &s) == true);
        ASSERT(pin_segment_count(node) == 0);
        ASSERT(node->getdata_kept_count == 1);
        ASSERT(atomic_load(&node->misbehavior) == 0);

        msg_send_replay_held(&mp, node);
        ASSERT(pin_segment_count(node) == 0);
        ASSERT(node->getdata_kept_count == 1);
        ASSERT(atomic_load(&node->misbehavior) == 0);

        node->state = PEER_ACTIVE;
        msg_send_replay_held(&mp, node);
        ASSERT(node->getdata_kept_count == 0);
        ASSERT(pin_is_single_notfound(node, &h));
        ASSERT(atomic_load(&node->misbehavior) == 0);
        stream_free(&s);
        p2p_node_free(node);
        main_state_free(&ms);
        net_manager_free(&nm);
        PASS();
    } _test_next:;
    return failures;
}

/* Past the slot a block gets notfound at once; an item that is not a block gets
 * no reply, as past the send budget. */
static int test_getdata_held_while_serving_past_the_slot(void)
{
    int failures = 0;
    TEST("msg_handlers: past the slot while serving a block gets notfound at once") {
        struct net_manager nm;
        net_manager_init(&nm);
        struct main_state ms;
        main_state_init(&ms);
        struct msg_processor mp;
        pin_mp_init(&mp, &ms, &nm);
        struct p2p_node *node = pin_peer_node(&nm, 624);
        ASSERT(node != NULL);
        node->state = PEER_SNAPSHOT_SERVING;

        struct uint256 h;
        memset(h.data, 0x66, sizeof(h.data));
        struct byte_stream s;
        stream_init(&s, 1024);
        stream_write_compact_size(&s, GETDATA_KEPT_BLOCKS_MAX + 2);
        for (uint8_t i = 0; i <= GETDATA_KEPT_BLOCKS_MAX; i++) {
            h.data[0] = i;
            pin_inv_stream(&s, MSG_BLOCK, &h);
        }
        pin_inv_stream(&s, MSG_TX, &h);
        ASSERT(process_getdata(&mp, node, &s) == true);
        ASSERT(node->getdata_kept_count == GETDATA_KEPT_BLOCKS_MAX);
        h.data[0] = GETDATA_KEPT_BLOCKS_MAX;
        ASSERT(pin_is_single_notfound(node, &h));
        ASSERT(atomic_load(&node->misbehavior) == 0);

        pin_clear_fixture_disconnect(node);
        node->state = PEER_ACTIVE;
        msg_send_replay_held(&mp, node);
        ASSERT(node->getdata_kept_count == 0);
        ASSERT(pin_segment_count(node) == 2);
        ASSERT(atomic_load(&node->misbehavior) == 0);
        stream_free(&s);
        p2p_node_free(node);
        main_state_free(&ms);
        net_manager_free(&nm);
        PASS();
    } _test_next:;
    return failures;
}

/* A truncated getdata fails while a snapshot is served, as at any other time,
 * with no reply. Items read before the cut are kept as usual and still wait for
 * the serve to end. */
static int test_getdata_truncated_while_serving(void)
{
    int failures = 0;
    TEST("msg_handlers: a truncated getdata while serving fails, no reply") {
        struct net_manager nm;
        net_manager_init(&nm);
        struct msg_processor mp;
        pin_mp_init(&mp, NULL, &nm);
        struct p2p_node *node = pin_peer_node(&nm, 625);
        ASSERT(node != NULL);
        node->state = PEER_SNAPSHOT_SERVING;

        /* The count promises an item and no item follows. */
        struct byte_stream s;
        stream_init(&s, 64);
        stream_write_compact_size(&s, 1);
        ASSERT(process_getdata(&mp, node, &s) == false);
        ASSERT(pin_segment_count(node) == 0);
        ASSERT(node->getdata_kept_count == 0);
        stream_free(&s);

        /* One whole item, then a second cut off part way through its bytes. */
        struct uint256 h;
        memset(h.data, 0x67, sizeof(h.data));
        struct byte_stream cut;
        stream_init(&cut, 64);
        stream_write_compact_size(&cut, 2);
        pin_inv_stream(&cut, MSG_BLOCK, &h);
        const uint8_t partial[3] = { 0x02, 0x00, 0x00 };
        stream_write(&cut, partial, sizeof(partial));
        ASSERT(process_getdata(&mp, node, &cut) == false);
        ASSERT(pin_segment_count(node) == 0);
        ASSERT(node->getdata_kept_count == 1);
        ASSERT(node->state == PEER_SNAPSHOT_SERVING);
        stream_free(&cut);

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
    /* More work, and the gate's own body re-check runs out of memory. */
    PIN_REJECT_MORE_WORK_RECHECK_OOM,
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
 * be dedup-marked. PIN_REJECT_MORE_WORK_RECHECK_OOM is the exception: its gate
 * has no verdict, so the block stays unseen and its peer unpenalised. */
struct pin_reject_outcome {
    bool handled;
    bool seen;
    bool penalised;
    bool alloc_fault_fired;
};

static struct pin_reject_outcome pin_reject_run(enum pin_reject_mode mode)
{
    bool recheck_oom = mode == PIN_REJECT_MORE_WORK_RECHECK_OOM;
    struct block blk;
    block_init(&blk);
    blk.header.nVersion = 4;
    blk.header.nTime = 1700000030u + (uint32_t)mode;
    blk.header.nBits = 0x1f00ffffu;
    blk.header.nNonce.data[0] = (uint8_t)(40 + mode);
    if (recheck_oom)
        blk.header.nSolutionSize = MAX_SOLUTION_SIZE; /* reaches the allocations */

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
            if (mode == PIN_REJECT_MORE_WORK || recheck_oom) {
                bool neg = false, ovf = false;
                arith_uint256_set_compact(&bi->nChainWork, 0x1f00ffffu,
                                          &neg, &ovf);
            }
        }
    }

    peer_scoring_init();
    test_msg_dl_reset();
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

    if (recheck_oom && node) {
        (void)dl_mark_requested(get_download_mgr(), &hash, 1, node->id);
        zcl_alloc_fault_fail_nth("equihash_indices", 1);
    }
    struct pin_reject_outcome out = {0};
    out.handled = at_tip && ok && node && process_block_msg(&mp, node, &s);
    out.alloc_fault_fired = zcl_alloc_fault_armed_label() == NULL;
    zcl_alloc_fault_clear();
    out.seen = block_already_seen(&hash);
    out.penalised = node && atomic_load(&node->misbehavior) != 0;

    msg_processor_stop_block_intake(&mp);
    test_msg_sync_to_idle();
    if (node)
        p2p_node_free(node);
    net_manager_free(&nm);
    stream_free(&s);
    block_free(&blk);
    main_state_free(&ms);
    block_clear_seen(&hash);
    return out;
}

static bool pin_reject_marks_seen(enum pin_reject_mode mode)
{
    struct pin_reject_outcome out = pin_reject_run(mode);
    return out.handled && out.seen;
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

static int test_pin_reject_recheck_memory_failure_stays_retryable(void)
{
    int failures = 0;
    TEST("msg_handlers: a self-suspicion re-check that runs out of memory leaves the block unseen and the peer unpenalised") {
        struct pin_reject_outcome out =
            pin_reject_run(PIN_REJECT_MORE_WORK_RECHECK_OOM);
        ASSERT(out.handled);
        ASSERT(out.alloc_fault_fired);
        ASSERT(!out.seen);
        ASSERT(!out.penalised);
        PASS();
    } _test_next:;
    return failures;
}

/* A one-transaction block whose header commits to that transaction. */
static bool pin_matching_block(struct block *blk, uint8_t marker)
{
    block_init(blk);
    blk->vtx = zcl_calloc(1, sizeof(*blk->vtx), "pin_matching_block");
    if (!blk->vtx)
        return false;
    blk->num_vtx = 1;
    transaction_init(&blk->vtx[0]);
    blk->vtx[0].lock_time = marker;
    transaction_compute_hash(&blk->vtx[0]);
    blk->header.nVersion = 4;
    blk->header.nTime = 1700000100u + marker;
    blk->header.nBits = 0x1f00ffffu;
    blk->header.hashMerkleRoot = blk->vtx[0].hash;
    return true;
}

/* Runs the merkle check the way check_block does at submission. */
static bool pin_submit_checks_merkle(struct block *block,
                                     struct validation_state *out, void *ctx)
{
    (void)ctx;
    return check_block(block, out, chain_params_get(), false, true, false);
}

/* The body check passes, then the check at submission cannot get memory for its
 * txid array. That says nothing about the block: the block is not marked seen,
 * so a later delivery is processed, and the sender is not penalized. */
static int test_block_local_memory_failure_stays_retryable(void)
{
    int failures = 0;
    TEST("msg_handlers: a block check that runs out of memory leaves the block unseen") {
        struct block blk;
        ASSERT(pin_matching_block(&blk, 0x31));
        struct uint256 hash;
        block_get_hash(&blk, &hash);
        block_clear_seen(&hash);
        struct byte_stream s;
        stream_init(&s, 256);
        ASSERT(block_serialize(&blk, &s));

        struct main_state ms;
        main_state_init(&ms);
        peer_scoring_init();
        test_msg_dl_reset();
        struct net_manager nm;
        net_manager_init(&nm);
        struct msg_processor mp;
        pin_mp_init(&mp, &ms, &nm);
        mp.block_submit = pin_submit_checks_merkle;
        mp.block_submit_ctx = NULL;
        struct p2p_node *node = pin_peer_node(&nm, 626);
        ASSERT(node != NULL);
        test_msg_sync_to_blocks_download();
        ASSERT(sync_try_transition(SYNC_BLOCKS_DOWNLOAD, SYNC_AT_TIP,
                                   "msg_handlers memory premise"));

        /* Asked for, so an unrequested-block penalty cannot hide the result. */
        ASSERT(dl_mark_requested(get_download_mgr(), &hash, 1, node->id));
        zcl_alloc_fault_fail_nth("domain_check_block_txids", 2);
        ASSERT(process_block_msg(&mp, node, &s));
        bool fired = zcl_alloc_fault_armed_label() == NULL;
        zcl_alloc_fault_clear();
        ASSERT(fired);
        ASSERT(!block_already_seen(&hash));
        ASSERT(atomic_load(&node->misbehavior) == 0);

        struct validation_state state;
        validation_state_init(&state);
        validation_state_error(&state, "out-of-memory");
        ASSERT(msg_block_validation_is_retryable(&state));

        msg_processor_stop_block_intake(&mp);
        test_msg_sync_to_idle();
        p2p_node_free(node);
        net_manager_free(&nm);
        stream_free(&s);
        block_free(&blk);
        main_state_free(&ms);
        block_clear_seen(&hash);
        PASS();
    } _test_next:;
    return failures;
}

/* A zblkdata message for piece 0 carrying one block, under `named_hash`. */
static void pin_block_data_stream(struct byte_stream *s,
                                  const struct byte_stream *body,
                                  const struct uint256 *named_hash)
{
    stream_init(s, body->size + 64);
    (void)stream_write_u32_le(s, 0);
    (void)stream_write_u32_le(s, 1);
    (void)stream_write(s, named_hash->data, 32);
    (void)stream_write_compact_size(s, body->size);
    (void)stream_write(s, body->data, body->size);
}

/* The sender's penalty for one zblkdata message, with `label` failing if given. */
static int pin_block_data_penalty(const struct byte_stream *body,
                                  const struct uint256 *named_hash,
                                  const char *label, bool *fired)
{
    peer_scoring_init();
    struct net_manager nm;
    net_manager_init(&nm);
    struct msg_processor mp;
    pin_mp_init(&mp, NULL, &nm);
    struct p2p_node *node = pin_peer_node(&nm, 627);
    if (!node) {
        net_manager_free(&nm);
        return -1;
    }
    struct byte_stream s;
    pin_block_data_stream(&s, body, named_hash);
    if (label)
        zcl_alloc_fault_fail_next(label);
    msgprocessor_test_block_data_during_swarm(&mp, node, &s);
    *fired = zcl_alloc_fault_armed_label() == NULL;
    zcl_alloc_fault_clear();
    int penalty = atomic_load(&node->misbehavior);
    stream_free(&s);
    p2p_node_free(node);
    net_manager_free(&nm);
    return penalty;
}

/* zblkdata the node cannot check for want of memory costs the sender nothing,
 * at each allocation on the way; the same message naming the wrong block is
 * still penalized. */
static int test_block_data_local_memory_failure_not_scored(void)
{
    int failures = 0;
    TEST("msg_handlers: zblkdata checked with no memory does not penalize the sender") {
        struct block blk;
        ASSERT(pin_matching_block(&blk, 0x32));
        struct uint256 hash;
        block_get_hash(&blk, &hash);
        struct byte_stream body;
        stream_init(&body, 256);
        ASSERT(block_serialize(&blk, &body));

        static const char *const labels[] = {
            "blk_piece_hashes", "block_piece_payload_refs", "block_vtx",
            "domain_check_block_txids",
        };
        bool fired = false;
        for (size_t i = 0; i < sizeof(labels) / sizeof(labels[0]); i++) {
            fired = false;
            ASSERT(pin_block_data_penalty(&body, &hash, labels[i], &fired) == 0);
            ASSERT(fired);
        }

        struct uint256 wrong = hash;
        wrong.data[0] ^= 0xff;
        ASSERT(pin_block_data_penalty(&body, &wrong, NULL, &fired) > 0);

        stream_free(&body);
        block_free(&blk);
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

/* ── mp_block_payload_submit_all (msgprocessor_snapshot_payload.c) ──
 *
 * The function and struct block_piece_payload_ref live in the private src/
 * header msgprocessor_snapshot_internal.h, which this file does not include.
 * Declared here the way test_block_swarm_loopback.c declares its private
 * helpers; the two-field struct is mirrored and must stay in step. */

struct block_piece_payload_ref {
    const unsigned char *data;
    size_t len;
};

bool mp_block_payload_submit_all(struct msg_processor *mp,
                                 struct p2p_node *node,
                                 const struct block_piece_payload_ref *refs,
                                 uint32_t count);

struct pay_probe {
    int submit_calls;
    int drain_calls;
    int scope_begins;
    int scope_ends;
    int drain_ret;
    int ok_on;           /* 1-based submit call that returns true */
    bool ok_always;
    bool snapshot;
    const char *reason;  /* reject reason for every other submit call */
};

static const unsigned char pay_junk[1] = {0x00};

static bool pay_probe_submit(struct block *b, struct validation_state *out,
                             void *ctx)
{
    (void)b;
    struct pay_probe *p = ctx;
    p->submit_calls++;
    if (p->ok_always || p->submit_calls == p->ok_on)
        return true;
    validation_state_invalid(out, false, REJECT_INVALID, p->reason, NULL);
    return false;
}

static int pay_probe_drain(void *ctx)
{
    struct pay_probe *p = ctx;
    p->drain_calls++;
    return p->drain_ret;
}

static void pay_probe_begin(void *ctx)
{
    ((struct pay_probe *)ctx)->scope_begins++;
}

static void pay_probe_end(void *ctx)
{
    ((struct pay_probe *)ctx)->scope_ends++;
}

static bool pay_probe_snapshot_active(void *ctx)
{
    return ((struct pay_probe *)ctx)->snapshot;
}

static void pay_wire(struct msg_processor *mp, struct pay_probe *p, bool scope)
{
    memset(mp, 0, sizeof(*mp));
    mp->block_submit = pay_probe_submit;
    mp->block_submit_ctx = p;
    mp->catchup_drain = pay_probe_drain;
    mp->catchup_drain_ctx = p;
    mp->snapshot_active = pay_probe_snapshot_active;
    mp->snapshot_active_ctx = p;
    if (scope) {
        mp->catchup_batch_begin = pay_probe_begin;
        mp->catchup_batch_end = pay_probe_end;
        mp->catchup_batch_scope_ctx = p;
    }
}

/* Serializes a minimal block into out; returns its length, 0 on failure. */
static size_t pay_block_bytes(uint8_t nonce, unsigned char *out, size_t cap,
                              struct uint256 *hash_out)
{
    struct block blk;
    block_init(&blk);
    blk.header.nVersion = 4;
    blk.header.nTime = 1700000002u;
    blk.header.nBits = 0x1f00ffffu;
    blk.header.nNonce.data[0] = nonce;
    block_get_hash(&blk, hash_out);
    struct byte_stream s;
    stream_init(&s, 256);
    size_t n = 0;
    if (block_serialize(&blk, &s) && s.size <= cap) {
        memcpy(out, s.data, s.size);
        n = s.size;
    }
    stream_free(&s);
    block_free(&blk);
    return n;
}

static void pay_node(struct p2p_node *node)
{
    memset(node, 0, sizeof(*node));
    node->id = 91;
    snprintf(node->addr_name, sizeof(node->addr_name), "test-peer");
}
static int test_pay_refusal_branches(void)
{
    int failures = 0;
    TEST("msg_handlers: submit_all refuses NULL inputs and balances scope on early exits") {
        struct pay_probe p = {0};
        struct msg_processor mp;
        pay_wire(&mp, &p, true);
        struct p2p_node node;
        pay_node(&node);
        struct block_piece_payload_ref ref = {pay_junk, 1};
        ASSERT(mp_block_payload_submit_all(NULL, NULL, NULL, 0));
        ASSERT(mp_block_payload_submit_all(&mp, &node, NULL, 3));
        ASSERT(!mp_block_payload_submit_all(NULL, &node, &ref, 1));
        ASSERT(!mp_block_payload_submit_all(&mp, NULL, &ref, 1));
        ASSERT_EQ(p.scope_begins, 0);
        ASSERT_EQ(p.submit_calls, 0);

        /* Zero count: scope opened and closed, nothing submitted. */
        ASSERT(mp_block_payload_submit_all(&mp, &node, &ref, 0));
        ASSERT_EQ(p.scope_begins, 1);
        ASSERT_EQ(p.scope_ends, 1);

        /* Malformed first piece refuses before any submit. */
        ASSERT(!mp_block_payload_submit_all(&mp, &node, &ref, 1));
        ASSERT_EQ(p.scope_begins, 2);
        ASSERT_EQ(p.scope_ends, 2);
        ASSERT_EQ(p.submit_calls, 0);

        /* Without scope hooks the same refusal still happens. */
        struct pay_probe q = {0};
        pay_wire(&mp, &q, false);
        ASSERT(!mp_block_payload_submit_all(&mp, &node, &ref, 1));
        ASSERT_EQ(q.scope_begins, 0);

        /* Unwired block_submit refuses a valid piece with the scope balanced. */
        unsigned char vb[512];
        struct uint256 vh;
        size_t nv = pay_block_bytes(1, vb, sizeof(vb), &vh);
        ASSERT(nv > 0);
        struct block_piece_payload_ref valid = {vb, nv};
        struct pay_probe r = {0};
        pay_wire(&mp, &r, true);
        mp.block_submit = NULL;
        ASSERT(!mp_block_payload_submit_all(&mp, &node, &valid, 1));
        ASSERT_EQ(r.scope_begins, 1);
        ASSERT_EQ(r.scope_ends, 1);
        ASSERT_EQ(r.submit_calls, 0);
        PASS();
    } _test_next:;
    return failures;
}

static int test_pay_accept_and_skip_branches(void)
{
    int failures = 0;
    TEST("msg_handlers: submit_all accepts pieces and skips snapshot or have-data pieces") {
        struct p2p_node node;
        pay_node(&node);
        unsigned char a[512], b[512];
        struct uint256 ha, hb;
        size_t na = pay_block_bytes(1, a, sizeof(a), &ha);
        size_t nb = pay_block_bytes(2, b, sizeof(b), &hb);
        ASSERT(na > 0 && nb > 0);

        /* Two accepted pieces: one submit each, one scope, no drain. */
        struct pay_probe p = {0};
        p.ok_always = true;
        struct msg_processor mp;
        pay_wire(&mp, &p, true);
        struct block_piece_payload_ref refs[2] = {{a, na}, {b, nb}};
        ASSERT(mp_block_payload_submit_all(&mp, &node, refs, 2));
        ASSERT_EQ(p.submit_calls, 2);
        ASSERT_EQ(p.drain_calls, 0);
        ASSERT_EQ(p.scope_begins, 1);
        ASSERT_EQ(p.scope_ends, 1);

        /* A malformed later piece refuses after the earlier submit. */
        struct pay_probe m = {0};
        m.ok_always = true;
        pay_wire(&mp, &m, true);
        struct block_piece_payload_ref bad[2] = {{a, na}, {pay_junk, 1}};
        ASSERT(!mp_block_payload_submit_all(&mp, &node, bad, 2));
        ASSERT_EQ(m.submit_calls, 1);
        ASSERT_EQ(m.scope_begins, 1);
        ASSERT_EQ(m.scope_ends, 1);

        /* Snapshot active: no submit at all. */
        struct pay_probe s = {0};
        s.snapshot = true;
        pay_wire(&mp, &s, true);
        struct block_piece_payload_ref ref = {a, na};
        ASSERT(mp_block_payload_submit_all(&mp, &node, &ref, 1));
        ASSERT_EQ(s.submit_calls, 0);
        ASSERT_EQ(s.scope_begins, 1);
        ASSERT_EQ(s.scope_ends, 1);

        /* BLOCK_HAVE_DATA skips; a piece without it is submitted. */
        struct pay_probe d = {0};
        d.ok_always = true;
        pay_wire(&mp, &d, true);
        struct main_state ms;
        main_state_init(&ms);
        struct block_index bi;
        memset(&bi, 0, sizeof(bi));
        bi.hashBlock = ha;
        bi.nStatus = BLOCK_HAVE_DATA;
        ASSERT(block_map_insert(&ms.map_block_index, &ha, &bi));
        mp.main_state = &ms;
        ASSERT(mp_block_payload_submit_all(&mp, &node, &ref, 1));
        ASSERT_EQ(d.submit_calls, 0);
        bi.nStatus = 0;
        ASSERT(mp_block_payload_submit_all(&mp, &node, &ref, 1));
        ASSERT_EQ(d.submit_calls, 1);
        main_state_free(&ms);
        PASS();
    } _test_next:;
    return failures;
}

static int test_pay_reject_retry_branches(void)
{
    static const char *const retry_reasons[] = {
        "header-admit-inbox-full", "p2p-block-header-missing",
        "p2p-block-intake-full"};
    static const char *const accept_reasons[] = {
        "p2p-block-queued-for-reducer", "p2p-block-already-queued",
        "p2p-block-staged-for-reducer"};
    int failures = 0;
    TEST("msg_handlers: submit_all reject, retry and queued-reason branches") {
        struct p2p_node node;
        pay_node(&node);
        unsigned char a[512];
        struct uint256 h;
        size_t na = pay_block_bytes(6, a, sizeof(a), &h);
        ASSERT(na > 0);
        struct block_piece_payload_ref ref = {a, na};

        /* Non-retryable reject: one submit, no drain. */
        struct pay_probe n = {0};
        n.reason = "block-not-finalized-by-reducer";
        struct msg_processor mp;
        pay_wire(&mp, &n, true);
        ASSERT(!mp_block_payload_submit_all(&mp, &node, &ref, 1));
        ASSERT_EQ(n.submit_calls, 1);
        ASSERT_EQ(n.drain_calls, 0);

        /* Retry reasons with a draining catch-up: three attempts, three drains. */
        struct pay_probe t = {0};
        t.drain_ret = 1;
        pay_wire(&mp, &t, true);
        for (size_t i = 0; i < sizeof(retry_reasons) / sizeof(retry_reasons[0]); i++) {
            t.submit_calls = 0;
            t.drain_calls = 0;
            t.reason = retry_reasons[i];
            ASSERT(!mp_block_payload_submit_all(&mp, &node, &ref, 1));
            ASSERT_EQ(t.submit_calls, 3);
            ASSERT_EQ(t.drain_calls, 3);
        }
        /* No drain progress: stop after the first attempt. */
        t.submit_calls = 0;
        t.drain_calls = 0;
        t.drain_ret = 0;
        t.reason = retry_reasons[0];
        ASSERT(!mp_block_payload_submit_all(&mp, &node, &ref, 1));
        ASSERT_EQ(t.submit_calls, 1);
        ASSERT_EQ(t.drain_calls, 1);

        /* Accepted on a later retry attempt. */
        struct pay_probe l = {0};
        l.ok_on = 2;
        l.drain_ret = 1;
        l.reason = "p2p-block-header-missing";
        pay_wire(&mp, &l, true);
        ASSERT(mp_block_payload_submit_all(&mp, &node, &ref, 1));
        ASSERT_EQ(l.submit_calls, 2);
        ASSERT_EQ(l.drain_calls, 1);

        /* Queued, already-queued and staged reasons count as accepted. */
        for (size_t i = 0; i < sizeof(accept_reasons) / sizeof(accept_reasons[0]); i++) {
            struct pay_probe q = {0};
            q.reason = accept_reasons[i];
            pay_wire(&mp, &q, true);
            ASSERT(mp_block_payload_submit_all(&mp, &node, &ref, 1));
            ASSERT_EQ(q.submit_calls, 1);
            ASSERT_EQ(q.drain_calls, 0);
        }
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
    failures += test_pay_refusal_branches();
    failures += test_pay_accept_and_skip_branches();
    failures += test_pay_reject_retry_branches();
    failures += test_zfilelist_empty_and_dropped_offers();
    failures += test_zfilelist_ttl_clamp_relay_gate_and_update();
    failures += test_zfilelist_count_clamp_and_truncated_batch();
    failures += test_intake_worker_rejects_nonretryable_body();
    failures += test_intake_worker_submit_unavailable_rejects();
    failures += test_intake_worker_accept_without_landing_not_marked_seen();
    failures += test_pin_getdata_serving_defers();
    failures += test_swarm_manifest_above_tip_starts_nothing();
    failures += test_swarm_manifest_repeats_cost_nothing_lasting();
    failures += test_swarm_manifest_near_tip_as_before();
    failures += test_swarm_manifest_bad_root_not_recorded();
    failures += test_pin_getdata_after_manifest_answers();
    failures += test_getdata_held_while_serving_finishes_after();
    failures += test_getdata_held_while_serving_past_the_slot();
    failures += test_getdata_truncated_while_serving();
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
    failures += test_pin_reject_recheck_memory_failure_stays_retryable();
    failures += test_block_local_memory_failure_stays_retryable();
    failures += test_block_data_local_memory_failure_not_scored();
    failures += test_msg_build_identity_prefix_branches();
    { extern int msg_block_body_identity_tests(void); failures += msg_block_body_identity_tests(); }

    dl_free(get_download_mgr());
    return failures;
}
