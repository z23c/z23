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
#include "chain/chainparams.h"
#include "core/hash.h"
#include "net/msgprocessor.h"
#include "net/msg_internal.h"
#include "net/download.h"
#include "net/peer_scoring.h"
#include "consensus/validation.h"
#include "core/uint256.h"
#include "primitives/block.h"
#include "sync/sync_state.h"
#include "util/safe_alloc.h"
#include "util/blocker.h"
#include "validation/main_state.h"

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
 * bug: block_mark_seen was called BEFORE process_new_block.
 * If the block was received + indexed but not activated (e.g.
 * ACTIVATION_SKIP_ALREADY_RUNNING under 6-peer concurrent arrival),
 * it was permanently dedup'd and never retried.
 *
 * mark_seen is gated on "block reached active chain"
 * via msg_blocks_should_mark_seen(). The helper is a pure function
 * so it can be exercised without full P2P plumbing.
 */

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
        /* Mirrors the bug shape: block was indexed (has a pindex)
         * but activation SKIP'd, so it's not in the active chain.
         * Pre-fix, block_mark_seen was unconditional. Post-fix, we
         * must NOT mark seen — the dedup ring would otherwise hide
         * the block from subsequent arrival + retry. */
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

/* ── Lane 3 hardening: PEER_OFFENCE_UNREQUESTED wiring ─────────────
 *
 * process_block_msg() (msg_blocks.c) scores PEER_OFFENCE_UNREQUESTED
 * when dl_mark_received() finds no in-flight slot for the delivered
 * hash from ANY peer — a plain "block" message is only ever a getdata
 * response in this protocol (unsolicited fast-relay goes through
 * process_cmpctblock(), a different message entirely), so that is
 * normally a provable unsolicited push. These three tests pin: scored
 * when never requested, NOT scored when it was requested, and NOT
 * scored inside the drain/timeout grace window (the one case where
 * "never in-flight" does not prove "never requested" — see
 * lib/test/src/test_download.c::test_dl_last_forced_settle_time). */

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
        /* Hermetic: the download manager is a process-wide singleton —
         * a prior test in this SAME forked group process may have left
         * a drain/timeout grace window active, which would silently
         * suppress the very assertion under test. */
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

static int test_process_block_msg_no_score_within_settle_grace(void)
{
    int failures = 0;
    TEST("msg_handlers: process_block_msg withholds scoring inside the "
         "post-drain/timeout grace window (honest-but-late delivery)") {
        peer_scoring_init();
        struct download_manager *dm = get_download_mgr();
        dl_init(dm);
        /* A drain (or a timeout reassignment — see test_download.c)
         * force-clears in-flight state without telling the peer, so a
         * legitimately-requested body can still arrive afterward with
         * no trace it was ever asked for. */
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
         * historical body. Its post-submit reducer drain must survive the
         * raw-state edge or that last body can remain staged forever. */
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
        for (int i = 0; i < 512 && !saw_full; i++) {
            validation_state_init(&state);
            ASSERT(msg_processor_enqueue_p2p_block(&mp, &blk, &hash,
                                                   89, &state));
            saw_full = strcmp(state.reject_reason,
                              "p2p-block-intake-full") == 0;
        }

        ASSERT(saw_full);
        ASSERT(msg_block_validation_is_retryable(&state));

        struct msg_block_intake_stats stats;
        msg_processor_get_block_intake_stats(&mp, &stats);
        ASSERT(stats.capacity > 0);
        ASSERT(stats.current_depth <= stats.capacity);
        ASSERT(stats.dropped > 0);
        ASSERT(stats.enqueued > 0);

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

/* ── D1: swarm aggregate SHA3 UTXO-snapshot mismatch is NOT a
 * silent-accept ───────────────────────────────────────────────────
 *
 * lib/net/src/msgprocessor_snapshot.c's swarm chunk-download path used
 * to print "SHA3 UTXO verification: FAILED" on an aggregate-root
 * mismatch and then fall straight through into the exact same cleanup
 * as a PASSED verify — no peer_scoring_record, no blocker, no record
 * that the sync did not complete trustworthily. These tests pin the
 * fix via msgprocessor_test_swarm_utxo_sha3_verify: PASSED records
 * nothing and returns true; a mismatch records PEER_OFFENCE_INVALID_PROOF,
 * names the "snapshot_sync.utxo_sha3_mismatch" typed DEPENDENCY blocker,
 * and returns false (sync NOT complete). */

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
        memset(&nm, 0, sizeof(nm));
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

        /* Sync must NOT be reported complete on a mismatch. */
        ASSERT(!ok);

        /* Peer offence recorded — PEER_OFFENCE_INVALID_PROOF weight. */
        ASSERT_EQ(atomic_load(&node.misbehavior),
                  peer_offence_weight(PEER_OFFENCE_INVALID_PROOF));

        /* Typed blocker named — visible to dumpstate blocker / the
         * blocker_stall_meta_detector safety net, not invisible. */
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
    failures += test_source_header_echo_policy();
    failures += test_block_validation_retryable_classifier();
    failures += test_process_block_msg_reducer_pending_stays_retryable();
    failures += test_process_block_msg_scores_unrequested();
    failures += test_process_block_msg_no_score_when_requested();
    failures += test_process_block_msg_no_score_within_settle_grace();
    failures += test_process_block_msg_queues_reducer_during_catchup();
    failures += test_msg_block_intake_full_stays_retryable();
    failures += test_msg_process_messages_yields_after_bounded_batch();
    failures += test_swarm_utxo_sha3_verify_passed_is_quiet();
    failures += test_swarm_utxo_sha3_verify_mismatch_is_not_silent();

    return failures;
}
