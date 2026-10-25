/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Tests for the event log ring buffer and state machines. */

#include "test/test_core.h"
#include "event/event.h"
#include "sync/sync_state.h"
#include "json/json.h"
#include <string.h>
#include <stdio.h>
#include <pthread.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#if !defined(_WIN32)
#include <sys/wait.h>
#endif
#include <sys/stat.h>
#include <stdlib.h>
#include "util/safe_alloc.h"
#include "util/signal_handler.h"

static _Atomic int g_async_observer_calls = 0;

static void test_async_observer(enum event_type type, uint32_t peer_id,
                                const void *payload, uint32_t payload_len,
                                void *ctx)
{
    (void)type;
    (void)peer_id;
    (void)payload;
    (void)payload_len;
    (void)ctx;
    atomic_fetch_add(&g_async_observer_calls, 1);
}

static int test_emit_dump_roundtrip(void)
{
    int failures = 0;

    TEST("event_emit + event_dump_json round-trip") {
        event_log_init();

        event_emitf(EV_NODE_STARTING, 0, "test v1.0");
        event_emitf(EV_TCP_CONNECTED, 42, "127.0.0.1:8033");
        event_emit(EV_PEER_VERSION, 42, "hello", 5);

        char buf[4096];
        size_t len = event_dump_json(buf, sizeof(buf), 10);
        ASSERT(len > 0);
        ASSERT(len < sizeof(buf));
        buf[len] = '\0';

        ASSERT(buf[0] == '[');
        ASSERT(buf[len - 1] == ']');
        ASSERT(strstr(buf, "sys.starting") != NULL);
        ASSERT(strstr(buf, "tcp.connected") != NULL);
        ASSERT(strstr(buf, "peer.version") != NULL);
        ASSERT(strstr(buf, "\"peer\":42") != NULL);
        ASSERT(strstr(buf, "test v1.0") != NULL);
        ASSERT(strstr(buf, "127.0.0.1:8033") != NULL);
        PASS();
    } _test_next:;

    return failures;
}

static int test_dump_count(void)
{
    int failures = 0;

    TEST("event_dump_json respects count") {
        event_log_init();

        for (int i = 0; i < 50; i++)
            event_emitf(EV_MSG_RECEIVED, (uint32_t)i, "msg%d", i);

        char buf[4096];
        size_t len = event_dump_json(buf, sizeof(buf), 5);
        ASSERT(len > 0);
        buf[len] = '\0';

        ASSERT(strstr(buf, "msg49") != NULL);
        ASSERT(strstr(buf, "msg45") != NULL);
        ASSERT(strstr(buf, "msg44") == NULL);
        PASS();
    } _test_next:;

    return failures;
}

static int test_peer_state_legal(void)
{
    int failures = 0;

    TEST("peer_set_state_checked legal transitions") {
        event_log_init();
        _Atomic enum peer_state state = PEER_DISCONNECTED;

        ASSERT(peer_set_state_checked(1, &state, PEER_CONNECTING, "outbound"));
        ASSERT(state == PEER_CONNECTING);
        ASSERT(peer_set_state_checked(1, &state, PEER_CONNECTED, "tcp ok"));
        ASSERT(state == PEER_CONNECTED);
        ASSERT(peer_set_state_checked(1, &state, PEER_VERSION_SENT, "sent ver"));
        ASSERT(state == PEER_VERSION_SENT);
        ASSERT(peer_set_state_checked(1, &state, PEER_HANDSHAKE_COMPLETE, "verack"));
        ASSERT(state == PEER_HANDSHAKE_COMPLETE);
        ASSERT(peer_set_state_checked(1, &state, PEER_ACTIVE, "relay mode"));
        ASSERT(state == PEER_ACTIVE);
        ASSERT(peer_set_state_checked(1, &state, PEER_SYNCING_HEADERS, "IBD"));
        ASSERT(state == PEER_SYNCING_HEADERS);
        ASSERT(peer_set_state_checked(1, &state, PEER_SYNCING_BLOCKS, "blocks"));
        ASSERT(state == PEER_SYNCING_BLOCKS);
        ASSERT(peer_set_state_checked(1, &state, PEER_ACTIVE, "sync done"));
        ASSERT(state == PEER_ACTIVE);
        ASSERT(peer_set_state_checked(1, &state, PEER_SNAPSHOT_SERVING, "zsync"));
        ASSERT(state == PEER_SNAPSHOT_SERVING);
        ASSERT(peer_set_state_checked(1, &state, PEER_ACTIVE, "zsync done"));
        ASSERT(state == PEER_ACTIVE);
        ASSERT(peer_set_state_checked(1, &state, PEER_DISCONNECTING, "bye"));
        ASSERT(state == PEER_DISCONNECTING);
        ASSERT(peer_set_state_checked(1, &state, PEER_DISCONNECTED, "closed"));
        ASSERT(state == PEER_DISCONNECTED);
        PASS();
    } _test_next:;

    return failures;
}

static int test_peer_state_snapshot_takeover(void)
{
    int failures = 0;

    TEST("peer_set_state_checked allows snapshot takeover during sync") {
        event_log_init();
        _Atomic enum peer_state state = PEER_SYNCING_HEADERS;

        ASSERT(peer_set_state_checked(1, &state, PEER_SNAPSHOT_RECEIVING,
                                      "accepted snapshot offer"));
        ASSERT(state == PEER_SNAPSHOT_RECEIVING);
        ASSERT(peer_set_state_checked(1, &state, PEER_ACTIVE,
                                      "snapshot complete"));
        ASSERT(state == PEER_ACTIVE);

        state = PEER_SYNCING_BLOCKS;
        ASSERT(peer_set_state_checked(1, &state, PEER_SNAPSHOT_RECEIVING,
                                      "accepted snapshot offer"));
        ASSERT(state == PEER_SNAPSHOT_RECEIVING);
        ASSERT(peer_set_state_checked(1, &state, PEER_ACTIVE,
                                      "snapshot complete"));
        ASSERT(state == PEER_ACTIVE);
        PASS();
    } _test_next:;

    return failures;
}

static int test_peer_state_illegal(void)
{
    int failures = 0;

    TEST("peer_set_state_checked rejects illegal transitions") {
        event_log_init();
        _Atomic enum peer_state state = PEER_DISCONNECTED;

        /* DISCONNECTED -> ACTIVE (skip handshake) */
        ASSERT(!peer_set_state_checked(1, &state, PEER_ACTIVE, "skip"));
        ASSERT(state == PEER_DISCONNECTED);

        /* DISCONNECTED -> SYNCING_HEADERS */
        ASSERT(!peer_set_state_checked(1, &state, PEER_SYNCING_HEADERS, "nope"));
        ASSERT(state == PEER_DISCONNECTED);

        /* DISCONNECTED -> BANNED */
        ASSERT(!peer_set_state_checked(1, &state, PEER_BANNED, "nope"));
        ASSERT(state == PEER_DISCONNECTED);

        /* Get to ACTIVE legally */
        peer_set_state_checked(1, &state, PEER_CONNECTING, "out");
        peer_set_state_checked(1, &state, PEER_CONNECTED, "tcp");
        peer_set_state_checked(1, &state, PEER_VERSION_SENT, "ver");
        peer_set_state_checked(1, &state, PEER_HANDSHAKE_COMPLETE, "ack");
        peer_set_state_checked(1, &state, PEER_ACTIVE, "go");

        /* ACTIVE -> CONNECTING (can't go back) */
        ASSERT(!peer_set_state_checked(1, &state, PEER_CONNECTING, "back"));
        ASSERT(state == PEER_ACTIVE);

        /* ACTIVE -> DISCONNECTED (must go through DISCONNECTING) */
        ASSERT(!peer_set_state_checked(1, &state, PEER_DISCONNECTED, "skip"));
        ASSERT(state == PEER_ACTIVE);
        PASS();
    } _test_next:;

    return failures;
}

static int test_peer_transition_valid(void)
{
    int failures = 0;

    TEST("peer_transition_valid") {
        ASSERT(peer_transition_valid(PEER_DISCONNECTED, PEER_CONNECTING));
        ASSERT(peer_transition_valid(PEER_DISCONNECTED, PEER_CONNECTED));
        ASSERT(peer_transition_valid(PEER_ACTIVE, PEER_BANNED));
        ASSERT(peer_transition_valid(PEER_BANNED, PEER_DISCONNECTED));
        ASSERT(peer_transition_valid(PEER_DISCONNECTING, PEER_DISCONNECTED));

        ASSERT(!peer_transition_valid(PEER_DISCONNECTED, PEER_ACTIVE));
        ASSERT(!peer_transition_valid(PEER_ACTIVE, PEER_CONNECTING));
        ASSERT(!peer_transition_valid(PEER_BANNED, PEER_ACTIVE));
        PASS();
    } _test_next:;

    return failures;
}

static int test_peer_state_name(void)
{
    int failures = 0;

    TEST("peer_state_name") {
        ASSERT_STR_EQ(peer_state_name(PEER_DISCONNECTED), "disconnected");
        ASSERT_STR_EQ(peer_state_name(PEER_ACTIVE), "active");
        ASSERT_STR_EQ(peer_state_name(PEER_SNAPSHOT_SERVING), "snapshot_serving");
        ASSERT_STR_EQ(peer_state_name(PEER_BANNED), "banned");
        PASS();
    } _test_next:;

    return failures;
}

static int test_sync_state_transitions(void)
{
    int failures = 0;

    TEST("sync_set_state legal transitions") {
        event_log_init();

        ASSERT(sync_set_state(SYNC_FINDING_PEERS, "test"));
        ASSERT(sync_set_state(SYNC_HEADERS_DOWNLOAD, "test"));
        ASSERT(sync_set_state(SYNC_BLOCKS_DOWNLOAD, "test"));
        ASSERT(sync_set_state(SYNC_CONNECTING_BLOCKS, "test"));
        ASSERT(sync_set_state(SYNC_AT_TIP, "test"));
        ASSERT(sync_set_state(SYNC_REORG, "test"));
        ASSERT(sync_set_state(SYNC_AT_TIP, "test"));
        ASSERT(sync_set_state(SYNC_IDLE, "test"));
        PASS();
    } _test_next:;

    return failures;
}

static int test_sync_state_illegal(void)
{
    int failures = 0;

    TEST("sync_set_state rejects illegal transitions") {
        ASSERT(sync_get_state() == SYNC_IDLE);

        ASSERT(!sync_set_state(SYNC_AT_TIP, "illegal"));
        ASSERT(sync_get_state() == SYNC_IDLE);

        ASSERT(!sync_set_state(SYNC_REORG, "illegal"));
        ASSERT(sync_get_state() == SYNC_IDLE);
        PASS();
    } _test_next:;

    return failures;
}

static int test_sync_state_name(void)
{
    int failures = 0;

    TEST("sync_state_name") {
        ASSERT_STR_EQ(sync_state_name(SYNC_IDLE), "idle");
        ASSERT_STR_EQ(sync_state_name(SYNC_AT_TIP), "at_tip");
        ASSERT_STR_EQ(sync_state_name(SYNC_SNAPSHOT_RECEIVE), "snapshot_receive");
        ASSERT_STR_EQ(sync_state_name(SYNC_FAILED), "failed");
        PASS();
    } _test_next:;

    return failures;
}

static int test_ring_buffer_wrapping(void)
{
    int failures = 0;

    TEST("ring buffer wrapping (>65536 events)") {
        event_log_init();

        for (int i = 0; i < 70000; i++)
            event_emitf(EV_MSG_SENT, 0, "e%d", i);

        char buf[65536];
        size_t len = event_dump_json(buf, sizeof(buf), 100);
        ASSERT(len > 0);
        buf[len] = '\0';

        ASSERT(strstr(buf, "e69999") != NULL);
        ASSERT(strstr(buf, "e69900") != NULL);
        ASSERT(strstr(buf, "\"e0\"") == NULL);
        ASSERT(strstr(buf, "\"e1\"") == NULL);

        char *big = zcl_malloc(64 * 1024 * 1024, "test_event_buf");
        ASSERT(big != NULL);
        len = event_dump_json(big, 64 * 1024 * 1024, 70000);
        ASSERT(len > 0);
        big[len] = '\0';

        ASSERT(strstr(big, "e69999") != NULL);
        ASSERT(strstr(big, "e69998") != NULL);
        ASSERT(strstr(big, "\"e0\"") == NULL);

        free(big);
        PASS();
    } _test_next:;

    return failures;
}

static int test_event_type_name(void)
{
    int failures = 0;

    TEST("event_type_name") {
        ASSERT_STR_EQ(event_type_name(EV_TCP_CONNECTED), "tcp.connected");
        ASSERT_STR_EQ(event_type_name(EV_BLOCK_CONNECTED), "val.block_connected");
        ASSERT_STR_EQ(event_type_name(EV_NODE_READY), "sys.ready");
        ASSERT_STR_EQ(event_type_name(EV_CRASH), "sys.crash");
        ASSERT_STR_EQ(event_type_name(EV_CHAIN_ADVANCE_DECISION),
                      "chain.advance_decision");
        ASSERT_STR_EQ(event_type_name(EV_MIRROR_CONSENSUS_DECISION),
                      "mirror.consensus_decision");
        ASSERT_STR_EQ(event_type_name(EV_NUM_TYPES), "unknown");
        PASS();
    } _test_next:;

    return failures;
}

static int test_dump_small_buffer(void)
{
    int failures = 0;

    TEST("event_dump_json truncates gracefully") {
        event_log_init();
        event_emitf(EV_NODE_STARTING, 0, "test");

        char tiny[16];
        size_t len = event_dump_json(tiny, sizeof(tiny), 10);
        ASSERT(len > 0);
        ASSERT(len <= sizeof(tiny));
        ASSERT(tiny[0] == '[');
        PASS();
    } _test_next:;

    return failures;
}

static int test_dump_empty_log(void)
{
    int failures = 0;

    TEST("event_dump_json empty log") {
        event_log_init();

        char buf[256];
        size_t len = event_dump_json(buf, sizeof(buf), 100);
        ASSERT(len == 2);
        ASSERT(buf[0] == '[');
        ASSERT(buf[1] == ']');
        PASS();
    } _test_next:;

    return failures;
}

static int test_dump_filtered(void)
{
    int failures = 0;

    TEST("event_dump_json_filtered by type prefix") {
        event_log_init();

        event_emitf(EV_TCP_CONNECTED, 1, "peer1");
        event_emitf(EV_PEER_VERSION, 1, "v170011");
        event_emitf(EV_MSG_RECEIVED, 1, "block size=1000");
        event_emitf(EV_BLOCK_CONNECTED, 1, "h=100");
        event_emitf(EV_TX_ACCEPTED, 2, "txid");
        event_emitf(EV_PEER_MISBEHAVE, 1, "+10=10 bad");

        char buf[4096];

        /* Filter: peer. should match PEER_VERSION and PEER_MISBEHAVE */
        size_t len = event_dump_json_filtered(buf, sizeof(buf), 100, "peer.");
        ASSERT(len > 0);
        buf[len] = '\0';
        ASSERT(strstr(buf, "peer.version") != NULL);
        ASSERT(strstr(buf, "peer.misbehave") != NULL);
        ASSERT(strstr(buf, "tcp.connected") == NULL);
        ASSERT(strstr(buf, "val.block_connected") == NULL);

        /* Filter: val. should match BLOCK_CONNECTED only */
        len = event_dump_json_filtered(buf, sizeof(buf), 100, "val.");
        buf[len] = '\0';
        ASSERT(strstr(buf, "val.block_connected") != NULL);
        ASSERT(strstr(buf, "peer.") == NULL);

        /* Empty prefix = all events */
        len = event_dump_json_filtered(buf, sizeof(buf), 100, "");
        buf[len] = '\0';
        ASSERT(strstr(buf, "tcp.connected") != NULL);
        ASSERT(strstr(buf, "val.block_connected") != NULL);

        PASS();
    } _test_next:;

    return failures;
}

static int test_dump_filtered_latest(void)
{
    int failures = 0;

    TEST("event_dump_json_filtered returns newest matching events") {
        event_log_init();

        for (int i = 0; i < 30; i++) {
            event_emitf(EV_MSG_RECEIVED, 0, "noise%d", i);
            if (i == 0)
                event_emitf(EV_PEER_VERSION, 1, "peer-old");
        }
        event_emitf(EV_PEER_VERSION, 1, "peer-new-1");
        event_emitf(EV_MSG_RECEIVED, 0, "noise-final");
        event_emitf(EV_PEER_MISBEHAVE, 1, "peer-new-2");

        char buf[4096];
        size_t len = event_dump_json_filtered(buf, sizeof(buf), 2, "peer.");
        ASSERT(len > 0);
        buf[len] = '\0';
        ASSERT(strstr(buf, "peer-new-1") != NULL);
        ASSERT(strstr(buf, "peer-new-2") != NULL);
        ASSERT(strstr(buf, "peer-old") == NULL);
        ASSERT(event_log_head_sequence() >= 33);

        PASS();
    } _test_next:;

    return failures;
}

static int test_sync_full_lifecycle(void)
{
    int failures = 0;

    TEST("sync state machine full IBD lifecycle with events") {
        event_log_init();

        /* Full IBD path: idle -> finding -> headers -> blocks -> connect -> tip */
        ASSERT(sync_get_state() == SYNC_IDLE);
        ASSERT(sync_set_state(SYNC_FINDING_PEERS, "bootstrap"));
        ASSERT(sync_set_state(SYNC_HEADERS_DOWNLOAD, "got peers"));
        ASSERT(sync_set_state(SYNC_BLOCKS_DOWNLOAD, "headers done"));
        ASSERT(sync_set_state(SYNC_CONNECTING_BLOCKS, "blocks arrived"));
        ASSERT(sync_set_state(SYNC_AT_TIP, "chain synced"));
        ASSERT(sync_get_state() == SYNC_AT_TIP);

        /* Reorg recovery: tip -> reorg -> tip */
        ASSERT(sync_set_state(SYNC_REORG, "fork detected"));
        ASSERT(sync_get_state() == SYNC_REORG);
        ASSERT(sync_set_state(SYNC_AT_TIP, "reorg resolved"));

        /* Return to idle */
        ASSERT(sync_set_state(SYNC_IDLE, "shutdown"));

        /* Verify events were emitted for transitions */
        char buf[16384];
        size_t len = event_dump_json_filtered(buf, sizeof(buf), 100, "sync.");
        ASSERT(len > 0);
        buf[len] = '\0';
        ASSERT(strstr(buf, "sync.state_change") != NULL);

        PASS();
    } _test_next:;

    return failures;
}

static int test_sync_snapshot_path(void)
{
    int failures = 0;

    TEST("sync state machine snapshot receive path") {
        event_log_init();

        /* Snapshot path: idle -> finding -> snapshot -> connecting -> tip */
        ASSERT(sync_set_state(SYNC_FINDING_PEERS, "bootstrap"));
        ASSERT(sync_set_state(SYNC_SNAPSHOT_RECEIVE, "fast sync"));
        ASSERT(sync_get_state() == SYNC_SNAPSHOT_RECEIVE);
        ASSERT(sync_set_state(SYNC_CONNECTING_BLOCKS, "apply snapshot"));
        ASSERT(sync_set_state(SYNC_AT_TIP, "synced via snapshot"));
        ASSERT(sync_get_state() == SYNC_AT_TIP);

        /* Reset for next test */
        ASSERT(sync_set_state(SYNC_IDLE, "done"));
        PASS();
    } _test_next:;

    return failures;
}

static int test_sync_snapshot_from_headers(void)
{
    int failures = 0;

    TEST("sync state machine allows snapshot receive during header sync") {
        event_log_init();

        ASSERT(sync_set_state(SYNC_FINDING_PEERS, "bootstrap"));
        ASSERT(sync_set_state(SYNC_HEADERS_DOWNLOAD, "headers"));
        ASSERT(sync_set_state(SYNC_SNAPSHOT_RECEIVE, "verified snapshot"));
        ASSERT(sync_get_state() == SYNC_SNAPSHOT_RECEIVE);
        ASSERT(sync_set_state(SYNC_HEADERS_DOWNLOAD, "resume after snapshot"));
        ASSERT(sync_set_state(SYNC_IDLE, "done"));
        PASS();
    } _test_next:;

    return failures;
}

static int test_peer_full_lifecycle(void)
{
    int failures = 0;

    TEST("peer state machine full lifecycle with ban") {
        event_log_init();
        _Atomic enum peer_state s = PEER_DISCONNECTED;

        /* Normal connect -> handshake -> active -> snapshot -> ban */
        ASSERT(peer_set_state_checked(1, &s, PEER_CONNECTING, "outbound"));
        ASSERT(peer_set_state_checked(1, &s, PEER_CONNECTED, "tcp"));
        ASSERT(peer_set_state_checked(1, &s, PEER_VERSION_SENT, "ver"));
        ASSERT(peer_set_state_checked(1, &s, PEER_VERSION_RECEIVED, "verack"));
        ASSERT(s == PEER_VERSION_RECEIVED);
        ASSERT(peer_set_state_checked(1, &s, PEER_HANDSHAKE_COMPLETE, "hs"));
        ASSERT(peer_set_state_checked(1, &s, PEER_ACTIVE, "ready"));

        /* Snapshot serving cycle */
        ASSERT(peer_set_state_checked(1, &s, PEER_SNAPSHOT_SERVING, "zsync"));
        ASSERT(s == PEER_SNAPSHOT_SERVING);
        ASSERT(peer_set_state_checked(1, &s, PEER_ACTIVE, "done"));

        /* Misbehavior -> ban */
        ASSERT(peer_set_state_checked(1, &s, PEER_BANNED, "bad peer"));
        ASSERT(s == PEER_BANNED);
        ASSERT(peer_set_state_checked(1, &s, PEER_DISCONNECTED, "cleanup"));
        ASSERT(s == PEER_DISCONNECTED);

        /* Verify events captured the lifecycle */
        char buf[8192];
        size_t len = event_dump_json_filtered(buf, sizeof(buf), 50, "peer.state");
        ASSERT(len > 0);
        buf[len] = '\0';
        ASSERT(strstr(buf, "peer.state_change") != NULL);
        PASS();
    } _test_next:;

    return failures;
}

static int test_peer_stale_recovery(void)
{
    int failures = 0;

    TEST("peer state machine stale -> active recovery") {
        event_log_init();
        _Atomic enum peer_state s = PEER_DISCONNECTED;

        /* Get to active */
        peer_set_state_checked(1, &s, PEER_CONNECTING, "out");
        peer_set_state_checked(1, &s, PEER_CONNECTED, "tcp");
        peer_set_state_checked(1, &s, PEER_VERSION_SENT, "ver");
        peer_set_state_checked(1, &s, PEER_HANDSHAKE_COMPLETE, "hs");
        peer_set_state_checked(1, &s, PEER_ACTIVE, "go");

        /* Go stale and recover */
        ASSERT(peer_set_state_checked(1, &s, PEER_STALE, "no response"));
        ASSERT(s == PEER_STALE);
        ASSERT(peer_set_state_checked(1, &s, PEER_ACTIVE, "responded"));
        ASSERT(s == PEER_ACTIVE);

        /* Clean disconnect from stale */
        peer_set_state_checked(1, &s, PEER_STALE, "stale again");
        ASSERT(peer_set_state_checked(1, &s, PEER_DISCONNECTING, "give up"));
        ASSERT(peer_set_state_checked(1, &s, PEER_DISCONNECTED, "closed"));
        PASS();
    } _test_next:;

    return failures;
}

static void *event_emit_worker(void *arg)
{
    int id = *(int *)arg;
    for (int i = 0; i < 5000; i++)
        event_emitf(EV_MSG_RECEIVED, (uint32_t)id, "t%d_e%d", id, i);
    return NULL;
}

static int test_concurrent_emit(void)
{
    int failures = 0;

    TEST("concurrent event emission (4 threads x 5000 events)") {
        event_log_init();

        #define EV_NUM_THREADS 4
        pthread_t threads[EV_NUM_THREADS];
        int ids[EV_NUM_THREADS];

        for (int i = 0; i < EV_NUM_THREADS; i++) {
            ids[i] = i + 1;
            pthread_create(&threads[i], NULL, event_emit_worker, &ids[i]);
        }
        for (int i = 0; i < EV_NUM_THREADS; i++)
            pthread_join(threads[i], NULL);

        /* 20,000 events emitted total — ring buffer holds 65536 so all fit */
        char buf[65536];
        size_t len = event_dump_json(buf, sizeof(buf), 100);
        ASSERT(len > 0);
        buf[len] = '\0';

        /* Verify events from all threads are present in the last 100 */
        ASSERT(strstr(buf, "msg.received") != NULL);

        /* Dump large to verify no corruption */
        char *big = zcl_malloc(16 * 1024 * 1024, "test_event_buf");
        ASSERT(big != NULL);
        len = event_dump_json(big, 16 * 1024 * 1024, 20000);
        ASSERT(len > 0);
        big[len] = '\0';

        /* Must be valid JSON array */
        ASSERT(big[0] == '[');
        ASSERT(big[len - 1] == ']');

        /* Verify events from all 4 threads present */
        ASSERT(strstr(big, "t1_e") != NULL);
        ASSERT(strstr(big, "t2_e") != NULL);
        ASSERT(strstr(big, "t3_e") != NULL);
        ASSERT(strstr(big, "t4_e") != NULL);

        free(big);
        PASS();
    } _test_next:;

    return failures;
}

static int test_async_dispatch_lifecycle(void)
{
    int failures = 0;

    TEST("event async dispatcher starts, drains, and stops idempotently") {
        event_log_init();
        event_clear_all_observers();
        atomic_store(&g_async_observer_calls, 0);

        ASSERT(event_observe_async(EV_NODE_READY, test_async_observer, NULL));
        ASSERT(event_async_start());
        ASSERT(event_async_start());

        event_emitf(EV_NODE_READY, 7, "ready");

        struct timespec deadline;
        clock_gettime(CLOCK_MONOTONIC, &deadline);  // platform-ok:test-async-observer-realtime-deadline
        deadline.tv_sec += 10;
        while (atomic_load(&g_async_observer_calls) == 0) {
            struct timespec now;
            clock_gettime(CLOCK_MONOTONIC, &now);  // platform-ok:test-async-observer-realtime-deadline
            if (now.tv_sec > deadline.tv_sec ||
                (now.tv_sec == deadline.tv_sec && now.tv_nsec >= deadline.tv_nsec))
                break;
            struct timespec pause = {0, 10000000};
            nanosleep(&pause, NULL);
        }

        event_async_stop();
        ASSERT(atomic_load(&g_async_observer_calls) > 0);
        event_async_stop();
        PASS();
    } _test_next:;

    return failures;
}

/* Overflow regression: the async ring must refuse (not silently overwrite)
 * when a burst outruns the dispatcher. The observer gates on a condition
 * until every event is emitted, so production deterministically fills the
 * ring while the dispatcher is parked. Pre-fix, writes past the 4096 slot
 * ring overwrote unconsumed slots: the dispatcher then read 5000 slots,
 * delivering the newest events twice and never delivering 0..903. Post-fix,
 * the producer drops the overflow with accounting and the oldest 4096
 * events survive intact. */
static pthread_mutex_t g_gate_mtx = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_gate_cond = PTHREAD_COND_INITIALIZER;
static _Atomic bool g_gate_open;
static _Atomic uint32_t g_ovf_calls;
static _Atomic uint32_t g_ovf_first;
static _Atomic uint32_t g_ovf_last;
static _Atomic bool g_ovf_ordered;

static void overflow_observer(enum event_type type, uint32_t peer_id,
                              const void *payload, uint32_t payload_len,
                              void *ctx)
{
    (void)type;
    (void)peer_id;
    (void)ctx;
    if (!atomic_load_explicit(&g_gate_open, memory_order_acquire)) {
        pthread_mutex_lock(&g_gate_mtx);
        while (!atomic_load_explicit(&g_gate_open, memory_order_acquire))
            pthread_cond_wait(&g_gate_cond, &g_gate_mtx);
        pthread_mutex_unlock(&g_gate_mtx);
    }
    if (payload_len < sizeof(uint32_t) || !payload)
        return;
    uint32_t seq;
    memcpy(&seq, payload, sizeof(seq));
    if (seq != atomic_load(&g_ovf_calls))
        atomic_store(&g_ovf_ordered, false);
    uint32_t first = atomic_load(&g_ovf_first);
    while (seq < first &&
           !atomic_compare_exchange_weak(&g_ovf_first, &first, seq))
        ;
    uint32_t last = atomic_load(&g_ovf_last);
    while (seq > last &&
           !atomic_compare_exchange_weak(&g_ovf_last, &last, seq))
        ;
    atomic_fetch_add(&g_ovf_calls, 1u);
}

static int test_async_queue_overflow_accounting(void)
{
    int failures = 0;
    enum { OVERFLOW_TOTAL = 5000, RING = 4096 };

    TEST("event async queue refuses overflow, keeping the oldest events") {
        event_log_init();
        event_clear_all_observers();
        atomic_store_explicit(&g_gate_open, false, memory_order_release);
        atomic_store(&g_ovf_calls, 0);
        atomic_store(&g_ovf_first, UINT32_MAX);
        atomic_store(&g_ovf_last, 0);
        atomic_store(&g_ovf_ordered, true);

        ASSERT(event_observe_async(EV_NODE_READY, overflow_observer, NULL));
        ASSERT(event_async_start());

        for (uint32_t i = 0; i < OVERFLOW_TOTAL; i++)
            event_emit(EV_NODE_READY, 7, &i, sizeof(i));

        pthread_mutex_lock(&g_gate_mtx);
        atomic_store_explicit(&g_gate_open, true, memory_order_release);
        pthread_cond_broadcast(&g_gate_cond);
        pthread_mutex_unlock(&g_gate_mtx);

        event_async_stop();

        ASSERT(atomic_load(&g_ovf_calls) == RING);
        ASSERT(atomic_load(&g_ovf_first) == 0);
        ASSERT(atomic_load(&g_ovf_last) == RING - 1);
        ASSERT(event_async_dropped() == OVERFLOW_TOTAL - RING);
        ASSERT(atomic_load(&g_ovf_ordered));
        ASSERT(event_async_start());
        ASSERT(event_async_dropped() == 0);
        event_async_stop();
        PASS();
    } _test_next:;

    event_async_stop();
    event_clear_all_observers();
    return failures;
}

/* Crash-handler output must survive a fully-buffered stderr and _exit():
 * fork a child, redirect its stderr to a temp file, install the crash
 * handler, raise(SIGABRT), and assert the file has BOTH the header literal
 * AND at least 3 hex-shaped backtrace addresses. */
static int test_crash_handler_stderr_survives_exit(void)
{
    int failures = 0;

#if defined(_WIN32)
    /* POSIX crash-handler lane: fork()+raise(SIGABRT) against sigaction
     * handlers and backtrace_symbols_fd (unavailable on Windows). */
    printf("crash_handler: header + ≥3 backtrace frames reach stderr... "
           "SKIP (Windows): POSIX fatal-signal backtrace lane\n");
#else
    TEST("crash_handler: header + ≥3 backtrace frames reach stderr") {
        mkdir("./test-tmp", 0700);
        char path[256];
        char path2[256];
        snprintf(path, sizeof(path),
                 "./test-tmp/crash_stderr_%d.log", (int)getpid());
        snprintf(path2, sizeof(path2),
                 "./test-tmp/crash_durable_%d.log", (int)getpid());
        unlink(path);
        unlink(path2);

        /* Drain any pending stdio in the parent so the post-fork child
         * doesn't double-emit its inherited buffer. */
        fflush(stdout);
        fflush(stderr);

        pid_t pid = fork();
        ASSERT(pid >= 0);

        if (pid == 0) {
            /* Child: redirect stderr to the temp file first; parent stderr
             * was flushed above. */
            int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
            if (fd < 0) _exit(42);
            dup2(fd, STDERR_FILENO);
            close(fd);

            /* Kill stdout noise too — keeps the test log tidy. */
            int dn = open("/dev/null", O_WRONLY);
            if (dn >= 0) { dup2(dn, STDOUT_FILENO); close(dn); }

            /* Install the crash handler after the fork so the parent's
             * signal disposition is untouched. */
            event_log_init();
            event_install_crash_handler();
            /* Arm the durable, stderr-independent crash log; its fd is never
             * dup2'd onto stderr. */
            signal_handler_set_crash_log(path2);

            /* Bound a reporter deadlock; original frame and exit assertions remain. */
            alarm(5);
            /* Trigger. Handler must emit and retain its _exit contract. */
            raise(SIGABRT);

            /* If the handler didn't _exit (a real bug), use a distinct exit
             * code so the parent's WEXITSTATUS check surfaces it. */
            _exit(99);
        }

        int status = 0;
        pid_t done = waitpid(pid, &status, 0);
        ASSERT(done == pid);
        ASSERT(WIFEXITED(status));
        ASSERT_EQ(WEXITSTATUS(status), 128 + SIGABRT);  /* 134 */

        /* Slurp the temp file. */
        FILE *f = fopen(path, "r");
        ASSERT(f != NULL);
        fseek(f, 0, SEEK_END);
        long sz = ftell(f);
        fseek(f, 0, SEEK_SET);
        ASSERT(sz > 0);
        char *buf = zcl_malloc((size_t)sz + 1, "crash_log_slurp");
        ASSERT(buf != NULL);
        size_t got = fread(buf, 1, (size_t)sz, f);
        buf[got] = '\0';
        fclose(f);

        /* Acceptance 1: the header literal landed. */
        ASSERT(strstr(buf, "FATAL SIGNAL 6") != NULL);

        /* Acceptance 2: at least 3 backtrace frames (distinct 0x hex runs,
         * "[0x...]" or "+0x..."). */
        int hex_hits = 0;
        for (const char *p = buf; (p = strstr(p, "0x")) != NULL; ) {
            hex_hits++;
            p += 2;  /* advance past "0x" to avoid infinite loop */
        }
        ASSERT(hex_hits >= 3);

        /* Acceptance 3 (DURABLE path): the stderr-independent, fsync'd crash
         * log armed via signal_handler_set_crash_log() (a fd never dup2'd
         * onto stderr) holds the same header + frames. */
        FILE *f2 = fopen(path2, "r");
        ASSERT(f2 != NULL);
        fseek(f2, 0, SEEK_END);
        long sz2 = ftell(f2);
        fseek(f2, 0, SEEK_SET);
        ASSERT(sz2 > 0);
        char *buf2 = zcl_malloc((size_t)sz2 + 1, "crash_durable_slurp");
        ASSERT(buf2 != NULL);
        size_t got2 = fread(buf2, 1, (size_t)sz2, f2);
        buf2[got2] = '\0';
        fclose(f2);

        ASSERT(strstr(buf2, "FATAL SIGNAL 6") != NULL);
        int hex2 = 0;
        for (const char *p = buf2; (p = strstr(p, "0x")) != NULL; ) {
            hex2++;
            p += 2;
        }
        ASSERT(hex2 >= 3);
        free(buf2);

        free(buf);
        unlink(path);
        unlink(path2);
        PASS();
    } _test_next:;
#endif
    return failures;
}



/* The error accumulator's JSON has one consumer, api_json_push_recent_errors,
 * which replaces an unparseable document with an empty array ("no recent
 * errors"). These tests parse the dump the same way. */
static int test_error_ring_dump_json_parses(void)
{
    int failures = 0;

    TEST("error_ring_dump_json is parseable JSON for 0, 1 and many errors") {
        static const int counts[] = { 0, 1, 2, ERROR_RING_SIZE + 3 };

        for (size_t c = 0; c < sizeof(counts) / sizeof(counts[0]); c++) {
            struct error_ring ring;
            error_ring_init(&ring);
            for (int i = 0; i < counts[c]; i++) {
                char msg[32];
                snprintf(msg, sizeof(msg), "err%d", i);
                error_ring_observer(EV_DB_ERROR, 0, msg, (uint32_t)strlen(msg),
                                    &ring);
            }

            char buf[2048];
            size_t len = error_ring_dump_json(&ring, buf, sizeof(buf));
            ASSERT(len > 0);
            ASSERT(len < sizeof(buf));

            struct json_value doc;
            json_init(&doc);
            ASSERT(json_read(&doc, buf, len));

            const struct json_value *total = json_get(&doc, "total");
            ASSERT(total != NULL);
            ASSERT(json_get_int(total) == counts[c]);

            const struct json_value *errors = json_get(&doc, "errors");
            ASSERT(errors != NULL);
            /* The ring keeps the most recent ERROR_RING_SIZE entries: array
             * length is the count clamped to the ring, "total" the lifetime
             * count. */
            size_t expect = (size_t)(counts[c] < ERROR_RING_SIZE
                                     ? counts[c] : ERROR_RING_SIZE);
            ASSERT(errors->num_children == expect);

            json_free(&doc);
        }
        PASS();
    } _test_next:;

    return failures;
}

/* Model the observer's retained bytes without acquiring a real timestamp. */
static void error_json_fixture(struct error_ring *ring, const char *message,
                                size_t length, int count)
{
    error_ring_init(ring);
    size_t retained = length;
    if (retained >= sizeof(ring->entries[0].message))
        retained = sizeof(ring->entries[0].message) - 1;
    for (int i = 0; i < count; i++) {
        ring->entries[i].type = EV_DB_ERROR;
        ring->entries[i].timestamp_us = 123000000;
        memcpy(ring->entries[i].message, message, retained);
        ring->entries[i].message[retained] = '\0';
    }
    atomic_store(&ring->write_pos, count);
    atomic_store(&ring->total_count, count);
}

static int test_error_ring_dump_json_escaped_message(void)
{
    int failures = 0;
    struct json_value doc;
    json_init(&doc);

    TEST("error_ring_dump_json preserves escaped message bytes") {
        const char message[] = "bad \"input\"\\next\n\t\b\f\r\001\037"
                               "\xc2\xa2\xe2\x82\xac\xf0\x9f\x98\x80";
        struct error_ring ring;
        error_json_fixture(&ring, message, sizeof(message) - 1, 1);

        char buf[2048];
        size_t len = error_ring_dump_json(&ring, buf, sizeof(buf));
        ASSERT(len > 0 && len < sizeof(buf));
        ASSERT(json_read(&doc, buf, len));
        const struct json_value *total = json_get(&doc, "total");
        ASSERT(total != NULL && total->type == JSON_INT);
        ASSERT(json_get_int(total) == 1);
        const struct json_value *errors = json_get(&doc, "errors");
        ASSERT(errors != NULL && errors->type == JSON_ARR);
        ASSERT(errors->num_children == 1);
        const struct json_value *entry = json_at(errors, 0);
        const struct json_value *msg = json_get(entry, "msg");
        ASSERT(msg != NULL && msg->type == JSON_STR);
        ASSERT(strcmp(json_get_str(msg), message) == 0);
        const struct json_value *type = json_get(entry, "type");
        ASSERT(type != NULL && type->type == JSON_STR);
        ASSERT(strcmp(json_get_str(type), event_type_name(EV_DB_ERROR)) == 0);
        const struct json_value *time = json_get(entry, "time");
        ASSERT(time != NULL && time->type == JSON_INT);
        ASSERT(json_get_int(time) == 123);
        PASS();
    } _test_next:;

    json_free(&doc);
    return failures;
}

static int test_error_ring_dump_json_invalid_utf8(void)
{
    int failures = 0;
    TEST("error_ring_dump_json refuses invalid retained UTF-8") {
        char split[257];
        memset(split, 'a', 254);
        split[254] = '\xc2';
        split[255] = '\xa2';
        split[256] = '\0';
        const char *messages[] = { "\xff", split };
        const size_t lengths[] = { 1, 256 };
        for (size_t i = 0; i < 2; i++) {
            struct error_ring ring;
            error_json_fixture(&ring, messages[i], lengths[i], 1);
            char buf[2048];
            memset(buf, 'X', sizeof(buf));
            ASSERT(error_ring_dump_json(&ring, buf, sizeof(buf)) == 0);
            ASSERT(buf[0] == '\0');
        }
        PASS();
    } _test_next:;
    return failures;
}

static int test_error_ring_dump_json_capacity(void)
{
    int failures = 0;
    struct json_value doc;
    json_init(&doc);
    TEST("error_ring_dump_json refuses partial documents at every boundary") {
        char message[256];
        memset(message, 1, sizeof(message) - 1);
        message[sizeof(message) - 1] = '\0';
        struct error_ring ring;
        char small[64];
        error_json_fixture(&ring, message, sizeof(message) - 1, 1);
        ASSERT(error_ring_dump_json(&ring, small, sizeof(small)) == 0);
        ASSERT(small[0] == '\0');
        error_json_fixture(&ring, message, sizeof(message) - 1, ERROR_RING_SIZE);
        char full[16384];
        size_t len = error_ring_dump_json(&ring, full, sizeof(full));
        ASSERT(len > 2048 && len < sizeof(full));
        ASSERT(json_read(&doc, full, len));
        ASSERT(json_get_int(json_get(&doc, "total")) == ERROR_RING_SIZE);
        const struct json_value *errors = json_get(&doc, "errors");
        ASSERT(errors != NULL && errors->num_children == ERROR_RING_SIZE);
        char buf[sizeof(full)];
        for (size_t capacity = 3; capacity <= len; capacity++) {
            memset(buf, 'X', sizeof(buf));
            ASSERT(error_ring_dump_json(&ring, buf, capacity) == 0);
            ASSERT(buf[0] == '\0');
            ASSERT(buf[capacity] == 'X');
        }
        ASSERT(error_ring_dump_json(&ring, buf, len + 1) == len);
        ASSERT(memcmp(full, buf, len + 1) == 0);
        PASS();
    } _test_next:;
    json_free(&doc);
    return failures;
}

/* A buffer too small to hold even an empty result is refused, not written
 * into (the dump's clamping is size_t and wraps under size 3). */
static int test_error_ring_dump_json_tiny_buffer(void)
{
    int failures = 0;

    TEST("error_ring_dump_json refuses a buffer it cannot fill") {
        struct error_ring ring;
        error_ring_init(&ring);
        error_ring_observer(EV_DB_ERROR, 0, "boom", 4, &ring);

        char guard[8];
        memset(guard, 'X', sizeof(guard));
        for (size_t sz = 0; sz < 3; sz++) {
            ASSERT(error_ring_dump_json(&ring, guard, sz) == 0);
            /* Nothing was written at any offset. */
            for (size_t i = 0; i < sizeof(guard); i++)
                ASSERT(guard[i] == 'X');
        }
        ASSERT(error_ring_dump_json(NULL, guard, sizeof(guard)) == 0);
        PASS();
    } _test_next:;

    return failures;
}

/* Regression: event_emitf must clamp the vsnprintf would-be length to the
 * stack buffer before synchronous observers run. Pre-fix it passed the
 * raw n (> 255 possible) to notify_observers, and the registered
 * length-scanning observers (prometheus parse_peer_kind,
 * consensus_reject_index cri_parse_payload) walked payload[i] for
 * i < payload_len -- an OOB read past the 256-byte buffer. The observer
 * here scans like those consumers after checking the buffer bound. */
static uint32_t g_emitf_seen_len;
static uint8_t g_emitf_scan_sum;
static char g_emitf_seen_payload[EVENT_PAYLOAD_SIZE];

static void emitf_len_observer(enum event_type type, uint32_t peer_id,
                               const void *payload, uint32_t payload_len,
                               void *ctx)
{
    const uint8_t *p = payload;
    (void)type;
    (void)peer_id;
    (void)ctx;
    g_emitf_seen_len = payload_len;
    g_emitf_scan_sum = 0;
    g_emitf_seen_payload[0] = '\0';
    /* Report the broken contract without making the regression itself read
     * beyond a formatted emitter's stack buffer. */
    if (payload_len > EVENT_PAYLOAD_SIZE - 1)
        return;
    for (uint32_t i = 0; i < payload_len; i++)
        g_emitf_scan_sum = (uint8_t)(g_emitf_scan_sum + p[i]);
    memcpy(g_emitf_seen_payload, payload, payload_len);
    g_emitf_seen_payload[payload_len] = '\0';
}

static int test_emitf_clamps_observer_length(void)
{
    int failures = 0;

    TEST("event_emitf clamps a >255-byte format to the payload buffer") {
        event_log_init();
        event_clear_all_observers();
        g_emitf_seen_len = 0;
        g_emitf_scan_sum = 0;
        ASSERT(event_observe(EV_TCP_CONNECTED, emitf_len_observer, NULL));

        /* 300 digits plus text: vsnprintf reports a would-be length well
         * over EVENT_PAYLOAD_SIZE while truncating the buffer. */
        event_emitf(EV_TCP_CONNECTED, 7, "reject reason overflow %0300d", 42);

        ASSERT(g_emitf_seen_len > 0);
        ASSERT(g_emitf_seen_len <= EVENT_PAYLOAD_SIZE - 1);
        ASSERT(g_emitf_seen_len == EVENT_PAYLOAD_SIZE - 1);
        char expected[EVENT_PAYLOAD_SIZE];
        memcpy(expected, "reject reason overflow ", 23);
        memset(expected + 23, '0', sizeof(expected) - 24);
        expected[sizeof(expected) - 1] = '\0';
        ASSERT(strcmp(g_emitf_seen_payload, expected) == 0);
        uint8_t sum = 0;
        for (size_t i = 0; i < sizeof(expected) - 1; i++)
            sum = (uint8_t)(sum + (uint8_t)expected[i]);
        ASSERT(g_emitf_scan_sum == sum);
        PASS();
    } _test_next:;

    event_clear_all_observers();
    return failures;
}

static int test_emitf_truncation_boundary(void)
{
    int failures = 0;

    TEST("event_emitf preserves the truncation boundary and short messages") {
        event_log_init();
        event_clear_all_observers();
        g_emitf_seen_len = 0;
        ASSERT(event_observe(EV_TCP_CONNECTED, emitf_len_observer, NULL));

        /* Both sides of the truncation boundary and a short message. */
        event_emitf(EV_TCP_CONNECTED, 7, "%0255d", 42);
        ASSERT(g_emitf_seen_len == EVENT_PAYLOAD_SIZE - 1);
        ASSERT(strcmp(g_emitf_seen_payload + 253, "42") == 0);
        event_emitf(EV_TCP_CONNECTED, 7, "%0256d", 42);
        ASSERT(g_emitf_seen_len == EVENT_PAYLOAD_SIZE - 1);
        ASSERT(strcmp(g_emitf_seen_payload + 254, "4") == 0);
        event_emitf(EV_TCP_CONNECTED, 7, "short %d", 42);
        ASSERT(g_emitf_seen_len == 8);
        ASSERT(strcmp(g_emitf_seen_payload, "short 42") == 0);
        PASS();
    } _test_next:;

    event_clear_all_observers();
    return failures;
}

static int test_peer_state_legal_clamps_observer_length(void)
{
    int failures = 0;
    char reason[301];
    memset(reason, 'x', sizeof(reason) - 1);
    reason[sizeof(reason) - 1] = '\0';

    TEST("legal peer transition clamps a long reason before observers") {
        event_log_init();
        g_emitf_seen_len = 0;
        _Atomic enum peer_state state = PEER_DISCONNECTED;
        ASSERT(event_observe(EV_PEER_STATE_CHANGE, emitf_len_observer, NULL));
        ASSERT(peer_set_state_checked(7, &state, PEER_CONNECTING, reason));
        ASSERT(state == PEER_CONNECTING);
        ASSERT(g_emitf_seen_len == EVENT_PAYLOAD_SIZE - 1);
        PASS();
    } _test_next:;

    event_clear_all_observers();
    return failures;
}

static int test_peer_state_illegal_clamps_observer_length(void)
{
    int failures = 0;
    char reason[301];
    memset(reason, 'x', sizeof(reason) - 1);
    reason[sizeof(reason) - 1] = '\0';

    TEST("illegal peer transition clamps a long reason before observers") {
        event_log_init();
        g_emitf_seen_len = 0;
        _Atomic enum peer_state state = PEER_DISCONNECTED;
        ASSERT(event_observe(EV_PEER_STATE_CHANGE, emitf_len_observer, NULL));
        ASSERT(!peer_set_state_checked(7, &state, PEER_ACTIVE, reason));
        ASSERT(state == PEER_DISCONNECTED);
        ASSERT(g_emitf_seen_len == EVENT_PAYLOAD_SIZE - 1);
        PASS();
    } _test_next:;

    event_clear_all_observers();
    return failures;
}

int test_event(void)
{
    int failures = 0;

    failures += test_emit_dump_roundtrip();
    failures += test_emitf_clamps_observer_length();
    failures += test_emitf_truncation_boundary();
    failures += test_peer_state_legal_clamps_observer_length();
    failures += test_peer_state_illegal_clamps_observer_length();
    failures += test_async_queue_overflow_accounting();
    failures += test_dump_count();
    failures += test_peer_state_legal();
    failures += test_peer_state_snapshot_takeover();
    failures += test_peer_state_illegal();
    failures += test_peer_transition_valid();
    failures += test_peer_state_name();
    failures += test_sync_state_transitions();
    failures += test_sync_state_illegal();
    failures += test_sync_state_name();
    failures += test_ring_buffer_wrapping();
    failures += test_event_type_name();
    failures += test_dump_small_buffer();
    failures += test_dump_empty_log();
    failures += test_dump_filtered();
    failures += test_dump_filtered_latest();
    failures += test_sync_full_lifecycle();
    failures += test_sync_snapshot_path();
    failures += test_sync_snapshot_from_headers();
    failures += test_peer_full_lifecycle();
    failures += test_peer_stale_recovery();
    failures += test_concurrent_emit();
    failures += test_async_dispatch_lifecycle();
    failures += test_crash_handler_stderr_survives_exit();
    failures += test_error_ring_dump_json_parses();
    failures += test_error_ring_dump_json_escaped_message();
    failures += test_error_ring_dump_json_invalid_utf8();
    failures += test_error_ring_dump_json_capacity();
    failures += test_error_ring_dump_json_tiny_buffer();

    return failures;
}
