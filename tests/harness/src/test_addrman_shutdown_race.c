#define _DEFAULT_SOURCE

/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Regression: addrman shutdown-ordering race.
 *
 * CRASH SHAPE: during a graceful shutdown, AFTER
 * "[shutdown] connman stopped" is logged, a detached message-cycle thread can
 * still be processing a P2P `addr` message:
 *
 *   connman_run_message_cycle -> msg_process_messages -> mp_handle_addr
 *     -> addrman_add -> (find_addr: "bad args") -> SIGSEGV at addrman_add+0x79f
 *
 * Root cause: connman_join()'s bounded timed_join() on the message thread timed
 * out and DETACHED the still-running thread, then connman_free() -> net_manager_free()
 * -> addrman_free() nulled am->entries and destroyed am->cs out from under it.
 * find_addr() returned NULL (its guard fired) but addrman_add() kept going into
 * create_entry() and dereferenced the freed am->entries.
 *
 * The fix is defense in depth:
 *  1. OWNERSHIP — connman_join() never detaches a timed-out worker; it retains
 *     dependencies until the worker exits. Optional discovery cadence waits
 *     are stop-aware, so a healthy 300-second wait returns promptly instead
 *     of forcing a pre-durability watchdog exit.
 *  2. FAIL-CLOSED — addrman_add() guards the SAME condition find_addr() does
 *     (torn-down/invalid addrman) BEFORE locking, returning false rather than
 *     dereferencing freed entries or locking a destroyed mutex.
 *
 * These tests assert both layers hold and neither path crashes. */

#include "platform/time_compat.h"
#include "test/test_core.h"
#include "net/addrman.h"
#include "net/connman.h"
#include "net/net.h"
#include "net/netaddr.h"
#include "net/protocol.h"
#include "net/msgprocessor.h"
#include "core/serialize.h"
#include "util/timedata.h"
#include "controllers/diagnostics_internal.h"
#include "controllers/network_controller.h"
#include "json/json.h"
#include <string.h>
#include <stdio.h>

/* mp_handle_addr is declared only in the msgprocessor src-internal header;
 * declare it here (non-static) to drive the exact crash path from the test. */
extern bool mp_handle_addr(struct msg_processor *mp, struct p2p_node *node,
                           struct byte_stream *s);

/* Build a routable IPv4-mapped address (::ffff:a.b.c.d) using a public range. */
static struct net_address make_pub_addr(uint8_t a, uint8_t b, uint8_t c,
                                        uint8_t d, uint16_t port)
{
    struct net_address addr;
    memset(&addr, 0, sizeof(addr));
    addr.svc.addr.ip[10] = 0xff;
    addr.svc.addr.ip[11] = 0xff;
    addr.svc.addr.ip[12] = a;
    addr.svc.addr.ip[13] = b;
    addr.svc.addr.ip[14] = c;
    addr.svc.addr.ip[15] = d ? d : 1;
    addr.svc.port = port;
    addr.nTime = (uint32_t)platform_time_wall_time_t();
    addr.nServices = 1;
    return addr;
}

/* Layer 2: addrman_add() fails closed on a torn-down / NULL addrman. */
static int test_addrman_add_failclosed_on_teardown(void)
{
    int failures = 0;
    TEST("addrman_shutdown_race: addrman_add fails closed on freed/NULL addrman") {
        struct net_address addr = make_pub_addr(52, 10, 20, 30, 8033);
        struct net_addr src; net_addr_init(&src);

        /* NULL manager — must not deref, must return false. */
        ASSERT(addrman_add(NULL, &addr, &src, 0) == false);

        /* Freed manager: addrman_free() nulls entries and destroys cs — exactly
         * the post-teardown state the detached thread observed live. The guard
         * must return BEFORE touching entries or locking the destroyed mutex. */
        struct addr_man am;
        addrman_init(&am);
        addrman_free(&am);
        ASSERT(am.entries == NULL);            /* sanity: torn down */
        ASSERT(addrman_add(&am, &addr, &src, 0) == false);  /* no crash, closed */

        PASS();
    } _test_next:;
    return failures;
}

/* Layer 2 (integration): an addr message driven through mp_handle_addr against a
 * torn-down addrman must not crash — this is the literal crashing call chain. */
static int test_mp_handle_addr_survives_torndown_addrman(void)
{
    int failures = 0;
    TEST("addrman_shutdown_race: mp_handle_addr survives a torn-down addrman") {
        /* net_manager whose addrman has been freed (entries == NULL). */
        struct net_manager nm;
        memset(&nm, 0, sizeof(nm));
        addrman_init(&nm.addrman);
        addrman_free(&nm.addrman);
        ASSERT(nm.addrman.entries == NULL);

        struct msg_processor mp;
        memset(&mp, 0, sizeof(mp));
        mp.net_mgr = &nm;

        struct p2p_node node;
        memset(&node, 0, sizeof(node));
        snprintf(node.addr_name, sizeof(node.addr_name), "torn-peer");
        /* Give the observing peer a routable source IP. */
        struct net_address peer = make_pub_addr(51, 40, 50, 60, 8033);
        node.addr = peer;

        /* One routable address in the addr message body. */
        struct net_address gossip = make_pub_addr(52, 70, 80, 90, 8033);
        struct byte_stream s;
        stream_init(&s, 64);
        ASSERT(stream_write_compact_size(&s, 1));
        ASSERT(net_address_serialize(&gossip, &s, true));

        /* Drive the exact crashing path. It must return (true) without a
         * SIGSEGV; addrman_add's fail-closed guard swallows the write. */
        bool ok = mp_handle_addr(&mp, &node, &s);
        ASSERT(ok == true);

        stream_free(&s);
        PASS();
    } _test_next:;
    return failures;
}

struct discovery_wait_ctx {
    _Atomic bool observed_stop;
};

static void *discovery_wait_worker(void *arg)
{
    struct discovery_wait_ctx *ctx = arg;
    atomic_store(&ctx->observed_stop,
                 connman_wait_for_stop_for_test(2));
    return NULL;
}

/* Layer 1: the exact production failure was a healthy DNS discovery thread in
 * sleep(300) while shutdown waited in connman_join(). Exercise a nominal wait
 * in another owned thread, request stop, and prove the thread returns in well
 * under the two-second cadence instead of sleeping to its deadline. */
static int test_connman_discovery_wait_is_interruptible(void)
{
    int failures = 0;
    TEST("addrman_shutdown_race: discovery cadence observes stop promptly") {
        struct discovery_wait_ctx ctx;
        atomic_init(&ctx.observed_stop, false);
        connman_set_stop_for_test(false);

        int64_t start_us = platform_time_monotonic_us();
        pthread_t thread;
        ASSERT(pthread_create(&thread, NULL, discovery_wait_worker, &ctx) == 0);
        usleep(50000);
        connman_signal_stop(NULL);
        ASSERT(pthread_join(thread, NULL) == 0);
        int64_t elapsed_us = platform_time_monotonic_us() - start_us;
        bool observed_stop = atomic_load(&ctx.observed_stop);
        connman_set_stop_for_test(false);

        ASSERT(observed_stop);
        ASSERT(elapsed_us >= 0 && elapsed_us < 500000);

        PASS();
    } _test_next:;
    return failures;
}

/* Production incident regression: an automatic debug bundle raced orderly
 * shutdown after connman_free(), reached addrman_diag_dump_state_json, and
 * dereferenced entries[0] after addrman_free had nulled entries.  A stale
 * fixture/publication must now degrade to an explicit unavailable snapshot. */
static int test_addrman_diagnostic_fails_closed_after_teardown(void)
{
    int failures = 0;
    TEST("addrman_shutdown_race: diagnostic refuses torn-down addrman") {
        struct connman cm;
        memset(&cm, 0, sizeof(cm));
        addrman_init(&cm.manager.addrman);
        addrman_free(&cm.manager.addrman);
        rpc_net_set_connman(&cm);

        struct json_value out;
        json_init(&out);
        json_set_object(&out);
        ASSERT(addrman_diag_dump_state_json(&out, NULL));
        const struct json_value *valid = json_get(&out, "snapshot_valid");
        const struct json_value *reason = json_get(&out, "unavailable_reason");
        ASSERT(valid && !json_get_bool(valid));
        ASSERT(reason && strcmp(json_get_str(reason),
                                "addrman_torn_down") == 0);
        json_free(&out);
        rpc_net_set_connman(NULL);
        PASS();
    } _test_next:;
    return failures;
}

int test_addrman_shutdown_race(void)
{
    int failures = 0;
    failures += test_addrman_add_failclosed_on_teardown();
    failures += test_mp_handle_addr_survives_torndown_addrman();
    failures += test_connman_discovery_wait_is_interruptible();
    failures += test_addrman_diagnostic_fails_closed_after_teardown();
    return failures;
}
