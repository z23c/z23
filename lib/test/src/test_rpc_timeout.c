/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Tests for the HTTP RPC request timeout watchdog (wave 6 #1).
 *
 * These exercise the module synchronously via `rpc_timeout_sweep()`
 * with a controlled `now_us` argument so we never sleep in the test
 * process — the background watchdog thread is only stressed by one
 * targeted test at the end. */

#include "test/test_core.h"
#include "platform/time_compat.h"
#include "rpc/rpc_timeout.h"
#include "event/event.h"

#include <stdlib.h>
#include <string.h>
#if !defined(_WIN32)
#include <sys/socket.h>
#endif
#include <time.h>
#include <unistd.h>

#if defined(_WIN32)
#include "platform/socket_compat.h"

#include <stdint.h>

/* Fixture peer sockets held as int fds; socketpair becomes the verified
 * loopback-TCP pair and close() a SOCKET close. Every close() in this TU
 * targets one of those sockets. */
static int rt_socketpair(int sv[2])
{
    platform_socket_t pair[2];
    if (!platform_socket_pair(pair))
        return -1;
    sv[0] = (int)(intptr_t)pair[0];
    sv[1] = (int)(intptr_t)pair[1];
    return 0;
}

#define socketpair(domain, type, protocol, sv) rt_socketpair(sv)
#define close(fd) \
    (platform_socket_close((platform_socket_t)(intptr_t)(fd)) == 0 ? 0 : -1)
#endif

static struct rpc_timeout_mgr mgr;

static void fresh_mgr(void)
{
    if (mgr.initialized) rpc_timeout_destroy(&mgr);
    rpc_timeout_init(&mgr);
}

static int64_t now_us_local(void)
{
    return platform_time_monotonic_us();
}

/* ── Basic lifecycle ────────────────────────────────────────── */

static int test_init_defaults(void)
{
    int failures = 0;
    TEST("rpc_timeout: init populates sane defaults") {
        fresh_mgr();
        ASSERT(mgr.initialized);
        ASSERT(mgr.timeout_ms == 10000);
        ASSERT(mgr.proof_timeout_ms == RPC_PROOF_BUILD_TIMEOUT_MS);
        ASSERT(mgr.watchdog_period_ms == 250);
        ASSERT(mgr.stat_registered == 0);
        ASSERT(mgr.stat_completed == 0);
        ASSERT(mgr.stat_killed == 0);
        PASS();
    } _test_next:;
    return failures;
}

/* ── Registration + completion path ────────────────────────── */

static int test_register_unregister_roundtrip(void)
{
    int failures = 0;
    TEST("rpc_timeout: register+unregister bumps completed counter") {
        fresh_mgr();
        int s = rpc_timeout_register(&mgr, 42, 0x0100007F);
        ASSERT(s >= 0);
        ASSERT(mgr.slots[s].in_use);
        ASSERT(mgr.slots[s].client_fd == 42);
        ASSERT(mgr.stat_registered == 1);
        ASSERT(mgr.stat_completed == 0);

        rpc_timeout_unregister(&mgr, s);
        ASSERT(!mgr.slots[s].in_use);
        ASSERT(mgr.stat_completed == 1);
        ASSERT(mgr.stat_killed == 0);
        PASS();
    } _test_next:;
    return failures;
}

static int test_set_method_truncates(void)
{
    int failures = 0;
    TEST("rpc_timeout: set_method truncates oversize method name") {
        fresh_mgr();
        int s = rpc_timeout_register(&mgr, 10, 0);
        ASSERT(s >= 0);

        char huge[200];
        memset(huge, 'a', sizeof(huge) - 1);
        huge[sizeof(huge) - 1] = '\0';
        rpc_timeout_set_method(&mgr, s, huge);

        /* Stored buffer must be NUL-terminated within the declared
         * length and must not overflow into neighbouring fields. */
        ASSERT(mgr.slots[s].method[RPC_TIMEOUT_METHOD_LEN - 1] == '\0');
        ASSERT(strlen(mgr.slots[s].method) == RPC_TIMEOUT_METHOD_LEN - 1);

        rpc_timeout_unregister(&mgr, s);
        PASS();
    } _test_next:;
    return failures;
}

static int test_proof_methods_receive_bounded_extension(void)
{
    int failures = 0;
    TEST("rpc_timeout: bounded slow wallet operations receive scoped deadlines") {
        fresh_mgr();
        int ordinary_pair[2] = { -1, -1 };
        int proof_pair[2] = { -1, -1 };
        int commit_pair[2] = { -1, -1 };
        int shielded_pair[2] = { -1, -1 };
        int key_pair[2] = { -1, -1 };
        int witness_pair[2] = { -1, -1 };
        int retrieve_pair[2] = { -1, -1 };
        ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, ordinary_pair) == 0);
        ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, proof_pair) == 0);
        ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, commit_pair) == 0);
        ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, shielded_pair) == 0);
        ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, key_pair) == 0);
        ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, witness_pair) == 0);
        ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, retrieve_pair) == 0);

        int ordinary = rpc_timeout_register(&mgr, ordinary_pair[0], 0);
        int proof = rpc_timeout_register(&mgr, proof_pair[0], 0);
        int commit = rpc_timeout_register(&mgr, commit_pair[0], 0);
        int shielded = rpc_timeout_register(&mgr, shielded_pair[0], 0);
        int key = rpc_timeout_register(&mgr, key_pair[0], 0);
        int witness = rpc_timeout_register(&mgr, witness_pair[0], 0);
        int retrieve = rpc_timeout_register(&mgr, retrieve_pair[0], 0);
        ASSERT(ordinary >= 0 && proof >= 0 && commit >= 0 && shielded >= 0 &&
               key >= 0 && witness >= 0 && retrieve >= 0);
        rpc_timeout_set_method(&mgr, ordinary, "getwalletinfo");
        rpc_timeout_set_method(&mgr, proof, "vault_intent_plan");
        rpc_timeout_set_method(&mgr, commit, "vault_intent_commit");
        rpc_timeout_set_method(&mgr, shielded, "z_sendmany");
        rpc_timeout_set_method(&mgr, key, "z_getnewaddress");
        rpc_timeout_set_method(&mgr, witness, "rescanwitnesses");
        rpc_timeout_set_method(&mgr, retrieve, "zmarket_purchase_retrieve");
        ASSERT(mgr.slots[ordinary].timeout_ms == 10000);
        ASSERT(mgr.slots[proof].timeout_ms == RPC_PROOF_BUILD_TIMEOUT_MS);
        ASSERT(mgr.slots[commit].timeout_ms == RPC_PROOF_BUILD_TIMEOUT_MS);
        ASSERT(mgr.slots[shielded].timeout_ms == RPC_PROOF_BUILD_TIMEOUT_MS);
        ASSERT(mgr.slots[key].timeout_ms == RPC_WALLET_MUTATION_TIMEOUT_MS);
        ASSERT(mgr.slots[witness].timeout_ms == RPC_PROOF_BUILD_TIMEOUT_MS);
        ASSERT(mgr.slots[retrieve].timeout_ms == RPC_MARKET_DELIVERY_TIMEOUT_MS);
        rpc_timeout_unregister(&mgr, commit);
        rpc_timeout_unregister(&mgr, shielded);
        rpc_timeout_unregister(&mgr, key);
        rpc_timeout_unregister(&mgr, witness);
        rpc_timeout_unregister(&mgr, retrieve);

        ASSERT(rpc_timeout_sweep(
                   &mgr, mgr.slots[ordinary].start_us + 11000 * 1000LL) == 1);
        ASSERT(rpc_timeout_was_killed(&mgr, ordinary));
        ASSERT(!rpc_timeout_was_killed(&mgr, proof));
        ASSERT(rpc_timeout_sweep(
                   &mgr, mgr.slots[proof].start_us +
                         (RPC_PROOF_BUILD_TIMEOUT_MS + 1) * 1000LL) == 1);
        ASSERT(rpc_timeout_was_killed(&mgr, proof));

        rpc_timeout_unregister(&mgr, ordinary);
        rpc_timeout_unregister(&mgr, proof);
        close(ordinary_pair[0]);
        close(ordinary_pair[1]);
        close(proof_pair[0]);
        close(proof_pair[1]);
        close(commit_pair[0]);
        close(commit_pair[1]);
        close(shielded_pair[0]);
        close(shielded_pair[1]);
        close(key_pair[0]);
        close(key_pair[1]);
        close(witness_pair[0]);
        close(witness_pair[1]);
        close(retrieve_pair[0]);
        close(retrieve_pair[1]);
        PASS();
    }
    TEST("rpc_timeout: mesh_machines fleet collection receives its bounded extension") {
        fresh_mgr();
        int mesh_pair[2] = { -1, -1 };
        int generic_pair[2] = { -1, -1 };
        ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, mesh_pair) == 0);
        ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, generic_pair) == 0);
        int mesh = rpc_timeout_register(&mgr, mesh_pair[0], 0);
        int generic = rpc_timeout_register(&mgr, generic_pair[0], 0);
        ASSERT(mesh >= 0 && generic >= 0);
        rpc_timeout_set_method(&mgr, mesh, "mesh_machines");
        rpc_timeout_set_method(&mgr, generic, "mesh_status_poll");
        ASSERT(mgr.slots[mesh].timeout_ms == RPC_MESH_COLLECT_TIMEOUT_MS);
        ASSERT(mgr.slots[generic].timeout_ms == 10000);
        rpc_timeout_unregister(&mgr, mesh);
        rpc_timeout_unregister(&mgr, generic);
        close(mesh_pair[0]);
        close(mesh_pair[1]);
        close(generic_pair[0]);
        close(generic_pair[1]);
        PASS();
    } _test_next:;
    return failures;
}

static int test_table_full_returns_minus_one(void)
{
    int failures = 0;
    TEST("rpc_timeout: table full returns -1") {
        fresh_mgr();
        int slots[RPC_TIMEOUT_MAX_SLOTS];
        for (int i = 0; i < RPC_TIMEOUT_MAX_SLOTS; i++) {
            slots[i] = rpc_timeout_register(&mgr, i, 0);
            ASSERT(slots[i] >= 0);
        }
        /* One past capacity */
        int overflow = rpc_timeout_register(&mgr, 9999, 0);
        ASSERT(overflow == -1);

        /* Freeing one makes room. */
        rpc_timeout_unregister(&mgr, slots[0]);
        int reused = rpc_timeout_register(&mgr, 9999, 0);
        ASSERT(reused >= 0);

        for (int i = 1; i < RPC_TIMEOUT_MAX_SLOTS; i++) {
            rpc_timeout_unregister(&mgr, slots[i]);
        }
        rpc_timeout_unregister(&mgr, reused);
        PASS();
    } _test_next:;
    return failures;
}

/* ── Disabled module path ──────────────────────────────────── */

static int test_disabled_module_skips_registration(void)
{
    int failures = 0;
    TEST("rpc_timeout: timeout_ms=0 disables registration entirely") {
        fresh_mgr();
        mgr.timeout_ms = 0;
        int s = rpc_timeout_register(&mgr, 77, 0);
        ASSERT(s == -1);
        ASSERT(mgr.stat_registered == 0);

        /* Sweep must be a no-op. */
        int killed = rpc_timeout_sweep(&mgr, now_us_local() + 1000000000LL);
        ASSERT(killed == 0);
        ASSERT(mgr.stat_killed == 0);
        PASS();
    } _test_next:;
    return failures;
}

/* ── Sweep: no expiries ────────────────────────────────────── */

static int test_sweep_no_expiries(void)
{
    int failures = 0;
    TEST("rpc_timeout: sweep returns 0 when no request is past deadline") {
        fresh_mgr();
        mgr.timeout_ms = 1000;   /* 1s */
        int s = rpc_timeout_register(&mgr, 42, 0x0100007F);
        ASSERT(s >= 0);

        int64_t t0 = mgr.slots[s].start_us;
        /* Sweep at start + 500ms → still within deadline. */
        int killed = rpc_timeout_sweep(&mgr, t0 + 500 * 1000);
        ASSERT(killed == 0);
        ASSERT(!rpc_timeout_was_killed(&mgr, s));
        ASSERT(mgr.stat_killed == 0);
        ASSERT(mgr.stat_sweeps == 1);

        rpc_timeout_unregister(&mgr, s);
        ASSERT(mgr.stat_completed == 1);
        PASS();
    } _test_next:;
    return failures;
}

/* ── Sweep: single expiry kills + emits event ──────────────── */

static int g_tmo_observed = 0;
static char g_tmo_payload[256];

static void timeout_observer(enum event_type type, uint32_t peer_id,
                              const void *payload, uint32_t payload_len,
                              void *ctx)
{
    (void)type; (void)peer_id; (void)ctx;
    g_tmo_observed++;
    if (payload && payload_len > 0 && payload_len < sizeof(g_tmo_payload)) {
        memcpy(g_tmo_payload, payload, payload_len);
        g_tmo_payload[payload_len] = '\0';
    }
}

static int test_sweep_expiry_kills_and_emits(void)
{
    int failures = 0;
    TEST("rpc_timeout: expired slot killed + EV_RPC_TIMEOUT payload") {
        fresh_mgr();
        mgr.timeout_ms = 100;    /* 100ms deadline */

        event_clear_observers(EV_RPC_TIMEOUT);
        g_tmo_observed = 0;
        g_tmo_payload[0] = '\0';
        event_observe(EV_RPC_TIMEOUT, timeout_observer, NULL);

        /* Use a real fd so shutdown() succeeds — socketpair gives us
         * a connected pair we can tear down without needing a real
         * TCP listener. */
        int sv[2] = { -1, -1 };
        ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);

        int s = rpc_timeout_register(&mgr, sv[0], 0x0100007F);
        ASSERT(s >= 0);
        rpc_timeout_set_method(&mgr, s, "getblockcount");

        /* Jump forward 500ms. */
        int64_t t0 = mgr.slots[s].start_us;
        int killed = rpc_timeout_sweep(&mgr, t0 + 500 * 1000);
        ASSERT(killed == 1);
        ASSERT(rpc_timeout_was_killed(&mgr, s));
        ASSERT(mgr.stat_killed == 1);

        ASSERT(g_tmo_observed == 1);
        ASSERT(strstr(g_tmo_payload, "method=getblockcount") != NULL);
        ASSERT(strstr(g_tmo_payload, "elapsed_ms=500") != NULL);
        ASSERT(strstr(g_tmo_payload, "ip=127.0.0.1") != NULL);

        /* unregister should NOT bump completed because it was killed. */
        rpc_timeout_unregister(&mgr, s);
        ASSERT(mgr.stat_completed == 0);

        event_clear_observers(EV_RPC_TIMEOUT);
        close(sv[0]);
        close(sv[1]);
        PASS();
    } _test_next:;
    return failures;
}

/* ── Sweep: empty-method path ──────────────────────────────── */

static int test_sweep_kills_before_method_set(void)
{
    int failures = 0;
    TEST("rpc_timeout: kill before set_method uses '(none)' label") {
        fresh_mgr();
        mgr.timeout_ms = 50;

        event_clear_observers(EV_RPC_TIMEOUT);
        g_tmo_observed = 0;
        g_tmo_payload[0] = '\0';
        event_observe(EV_RPC_TIMEOUT, timeout_observer, NULL);

        int sv[2] = { -1, -1 };
        ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);

        int s = rpc_timeout_register(&mgr, sv[0], 0);
        ASSERT(s >= 0);
        int64_t t0 = mgr.slots[s].start_us;
        (void)rpc_timeout_sweep(&mgr, t0 + 100 * 1000);

        ASSERT(g_tmo_observed == 1);
        ASSERT(strstr(g_tmo_payload, "method=(none)") != NULL);

        rpc_timeout_unregister(&mgr, s);
        event_clear_observers(EV_RPC_TIMEOUT);
        close(sv[0]);
        close(sv[1]);
        PASS();
    } _test_next:;
    return failures;
}

/* ── Sweep: second sweep doesn't re-emit ──────────────────── */

static int test_sweep_second_pass_no_reemit(void)
{
    int failures = 0;
    TEST("rpc_timeout: sweep skips slots already marked killed") {
        fresh_mgr();
        mgr.timeout_ms = 100;

        event_clear_observers(EV_RPC_TIMEOUT);
        g_tmo_observed = 0;
        event_observe(EV_RPC_TIMEOUT, timeout_observer, NULL);

        int sv[2] = { -1, -1 };
        ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);

        int s = rpc_timeout_register(&mgr, sv[0], 0x0100007F);
        ASSERT(s >= 0);
        int64_t t0 = mgr.slots[s].start_us;

        ASSERT(rpc_timeout_sweep(&mgr, t0 + 500 * 1000) == 1);
        ASSERT(g_tmo_observed == 1);
        ASSERT(rpc_timeout_sweep(&mgr, t0 + 700 * 1000) == 0);
        ASSERT(g_tmo_observed == 1);
        ASSERT(mgr.stat_killed == 1);
        ASSERT(mgr.stat_sweeps == 2);

        rpc_timeout_unregister(&mgr, s);
        event_clear_observers(EV_RPC_TIMEOUT);
        close(sv[0]);
        close(sv[1]);
        PASS();
    } _test_next:;
    return failures;
}

/* ── Env overrides ─────────────────────────────────────────── */

static int test_env_overrides(void)
{
    int failures = 0;
    TEST("rpc_timeout: ZCL_RPC_TIMEOUT_MS + sweep_ms env overrides") {
        fresh_mgr();
        setenv("ZCL_RPC_TIMEOUT_MS",       "3500", 1);
        setenv("ZCL_RPC_PROOF_TIMEOUT_MS", "45000", 1);
        setenv("ZCL_RPC_TIMEOUT_SWEEP_MS", "125",  1);
        rpc_timeout_load_from_env(&mgr);
        ASSERT(mgr.timeout_ms == 3500);
        ASSERT(mgr.proof_timeout_ms == 45000);
        ASSERT(mgr.watchdog_period_ms == 125);

        /* Clamping at the lower bound */
        setenv("ZCL_RPC_TIMEOUT_SWEEP_MS", "1", 1);
        rpc_timeout_load_from_env(&mgr);
        ASSERT(mgr.watchdog_period_ms == 10);

        unsetenv("ZCL_RPC_TIMEOUT_MS");
        unsetenv("ZCL_RPC_PROOF_TIMEOUT_MS");
        unsetenv("ZCL_RPC_TIMEOUT_SWEEP_MS");
        PASS();
    } _test_next:;
    return failures;
}

/* ── Snapshot ──────────────────────────────────────────────── */

static int test_snapshot_mirrors_live(void)
{
    int failures = 0;
    TEST("rpc_timeout: snapshot reflects counters + active slots") {
        fresh_mgr();
        mgr.timeout_ms = 50;

        int sv[2] = { -1, -1 };
        ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);

        int s1 = rpc_timeout_register(&mgr, sv[0], 0);
        int s2 = rpc_timeout_register(&mgr, sv[1], 0);
        ASSERT(s1 >= 0 && s2 >= 0);

        int64_t t0 = mgr.slots[s1].start_us;
        rpc_timeout_sweep(&mgr, t0 + 200 * 1000);

        struct rpc_timeout_snapshot snap;
        rpc_timeout_snapshot_take(&mgr, &snap);
        ASSERT(snap.timeout_ms == 50);
        ASSERT(snap.proof_timeout_ms == RPC_PROOF_BUILD_TIMEOUT_MS);
        ASSERT(snap.active_slots == 2);
        ASSERT(snap.registered == 2);
        ASSERT(snap.killed == 2);
        ASSERT(snap.completed == 0);
        ASSERT(snap.sweeps == 1);

        rpc_timeout_unregister(&mgr, s1);
        rpc_timeout_unregister(&mgr, s2);
        close(sv[0]);
        close(sv[1]);
        PASS();
    } _test_next:;
    return failures;
}

/* ── Global handle ─────────────────────────────────────────── */

static int test_global_handle_set_get(void)
{
    int failures = 0;
    TEST("rpc_timeout: set/get global handle") {
        fresh_mgr();
        rpc_timeout_set_global(&mgr);
        ASSERT(rpc_timeout_get_global() == &mgr);
        rpc_timeout_set_global(NULL);
        ASSERT(rpc_timeout_get_global() == NULL);
        PASS();
    } _test_next:;
    return failures;
}

/* ── Watchdog thread — single end-to-end ──────────────────── */

static int test_watchdog_thread_kills(void)
{
    int failures = 0;
    TEST("rpc_timeout: watchdog thread sweeps + kills autonomously") {
        fresh_mgr();
        mgr.timeout_ms = 50;
        mgr.watchdog_period_ms = 20;

        event_clear_observers(EV_RPC_TIMEOUT);
        g_tmo_observed = 0;
        event_observe(EV_RPC_TIMEOUT, timeout_observer, NULL);

        int sv[2] = { -1, -1 };
        ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);

        ASSERT(rpc_timeout_start_watchdog(&mgr));
        int s = rpc_timeout_register(&mgr, sv[0], 0x0100007F);
        ASSERT(s >= 0);
        rpc_timeout_set_method(&mgr, s, "slowmethod");

        /* Wait ~200ms for the watchdog to fire at least once past
         * the 50ms deadline.  We poll the "killed" flag so the test
         * exits as soon as the kill lands. */
        for (int i = 0; i < 50; i++) {
            if (rpc_timeout_was_killed(&mgr, s)) break;
            struct timespec req = { .tv_sec = 0, .tv_nsec = 10 * 1000000L };
            nanosleep(&req, NULL);
        }
        ASSERT(rpc_timeout_was_killed(&mgr, s));
        ASSERT(g_tmo_observed >= 1);
        ASSERT(strstr(g_tmo_payload, "method=slowmethod") != NULL);

        rpc_timeout_stop_watchdog(&mgr);
        rpc_timeout_unregister(&mgr, s);
        event_clear_observers(EV_RPC_TIMEOUT);
        close(sv[0]);
        close(sv[1]);
        PASS();
    } _test_next:;
    return failures;
}

/* ── Reset state clears slots + stats ──────────────────────── */

static int test_reset_state_clears(void)
{
    int failures = 0;
    TEST("rpc_timeout: reset_state wipes slots + counters") {
        fresh_mgr();
        int s1 = rpc_timeout_register(&mgr, 1, 0);
        int s2 = rpc_timeout_register(&mgr, 2, 0);
        (void)s1; (void)s2;

        rpc_timeout_reset_state(&mgr);
        struct rpc_timeout_snapshot snap;
        rpc_timeout_snapshot_take(&mgr, &snap);
        ASSERT(snap.active_slots == 0);
        ASSERT(snap.registered == 0);
        ASSERT(snap.completed == 0);
        ASSERT(snap.killed == 0);
        PASS();
    } _test_next:;
    return failures;
}

/* ── Entry point ────────────────────────────────────────────── */

int test_rpc_timeout(void)
{
    int failures = 0;
    event_log_init();

    failures += test_init_defaults();
    failures += test_register_unregister_roundtrip();
    failures += test_set_method_truncates();
    failures += test_proof_methods_receive_bounded_extension();
    failures += test_table_full_returns_minus_one();
    failures += test_disabled_module_skips_registration();
    failures += test_sweep_no_expiries();
    failures += test_sweep_expiry_kills_and_emits();
    failures += test_sweep_kills_before_method_set();
    failures += test_sweep_second_pass_no_reemit();
    failures += test_env_overrides();
    failures += test_snapshot_mirrors_live();
    failures += test_global_handle_set_get();
    failures += test_watchdog_thread_kills();
    failures += test_reset_state_clears();

    if (mgr.initialized) rpc_timeout_destroy(&mgr);
    return failures;
}
