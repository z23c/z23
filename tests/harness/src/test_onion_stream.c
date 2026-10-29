/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Fail-closed guarantees of the onion dial path (core/modules/net/src/onion_stream.c)
 * that hold WITHOUT a live Tor network, so they run in default CI:
 *
 *   1. onion_stream_connect() refuses a non-tor service (usage error).
 *   2. onion_stream_connect() refuses a tor service when the embedded Tor
 *      runtime is not up (stub build OR simply not started in this
 *      process) — the dial fails with a named error instead of falling
 *      back to clearnet.
 *   3. connect_socket_start() refuses a torv3 service outright, so an
 *      onion address that somehow reaches the clearnet dialer can never
 *      connect(2) the all-zero IPv6 address.
 *
 * The happy path (real circuit, byte pump, EOF propagation) needs a live
 * Tor network and a real peer; it is exercised by the operator acceptance
 * flow, not here — same gating posture as test_onion_bootstrap.c. */

#include "platform/time_compat.h"
#include "test/test_core.h"
#include "net/onion_stream.h"
#include "net/onion_stream_telemetry.h"
#include "net/onion_v3_address.h"

#include <stdint.h>
#include <string.h>

static bool verify_connect_budget_two_circuits(void)
{
    int budgets[2] = {-1, -1};
    size_t attempts = onion_stream_connect_plan_for_test(
        ONION_STREAM_CONNECT_TIMEOUT_MS, budgets);
    bool ok = attempts == 2 &&
              budgets[0] == ONION_STREAM_RETRY_MIN_TOTAL_MS / 2 &&
              budgets[1] == ONION_STREAM_RETRY_MIN_TOTAL_MS / 2 &&
              budgets[0] + budgets[1] ==
                  ONION_STREAM_CONNECT_TIMEOUT_MS;

    budgets[0] = -1;
    budgets[1] = -1;
    attempts = onion_stream_connect_plan_for_test(
        ONION_STREAM_RETRY_MIN_TOTAL_MS - 1, budgets);
    ok = ok && attempts == 1 &&
         budgets[0] == ONION_STREAM_RETRY_MIN_TOTAL_MS - 1 &&
         budgets[1] == 0;
    return ok;
}

static bool verify_non_tor_service_refused(void)
{
    onion_stream_reset_stages_for_test();
    struct net_service svc;
    net_service_init(&svc);
    unsigned char ip4[4] = {10, 0, 0, 9};
    net_addr_set_ipv4(&svc.addr, ip4);
    svc.port = 8033;
    zcl_socket_t sock = ZCL_INVALID_SOCKET;
    bool ok = !onion_stream_connect(&svc, &sock, 1000) &&
              sock == ZCL_INVALID_SOCKET;
    struct onion_last_dial last;
    onion_stream_get_last_dial(&last);
    ok = ok && strcmp(last.result, "not_tor") == 0;
    return ok;
}

static bool verify_tor_dial_fails_closed_with_tor_down(void)
{
    /* A syntactically valid torv3 service (real checksum via the
     * codec). The connect must fail immediately — named "tor not
     * running/not ready" — never resolve or dial clearnet. */
    onion_stream_reset_stages_for_test();
    uint8_t pub[32];
    for (int i = 0; i < 32; i++)
        pub[i] = (uint8_t)(0x40 + i);
    char host[ONION_V3_ADDRESS_LEN + 1];
    bool ok = onion_v3_address_from_pubkey(pub, host);

    struct net_service svc;
    net_service_init(&svc);
    ok = ok && net_addr_from_onion(host, &svc.addr);
    svc.port = 8033;

    zcl_socket_t sock = ZCL_INVALID_SOCKET;
    ok = ok && !onion_stream_connect(&svc, &sock, 1000) &&
         sock == ZCL_INVALID_SOCKET;
    struct onion_last_dial last;
    onion_stream_get_last_dial(&last);
    ok = ok && strstr(last.target, ".onion:8033") != NULL &&
         (strcmp(last.result, "tor_not_running") == 0 ||
          strcmp(last.result, "dynhost_not_ready") == 0 ||
          strcmp(last.result, "stub_build") == 0) &&
         last.attempted_unix > 0;
    return ok;
}

static bool verify_clearnet_dialer_refuses_torv3(void)
{
    struct net_service svc;
    net_service_init(&svc);
    svc.addr.has_torv3 = true;
    memset(svc.addr.torv3, 0x77, TORV3_ADDR_SIZE);
    svc.port = 8033;
    zcl_socket_t sock = ZCL_INVALID_SOCKET;
    enum zcl_connect_start st = connect_socket_start(&svc, &sock);
    bool ok = st == ZCL_CONNECT_START_ERROR &&
              sock == ZCL_INVALID_SOCKET;
    return ok;
}

static bool verify_last_dial_records_state(void)
{
    onion_stream_reset_stages_for_test();
    struct onion_last_dial empty;
    onion_stream_get_last_dial(&empty);
    bool ok = empty.target[0] == '\0' &&
              empty.attempted_unix == 0 &&
              strcmp(empty.result, "none") == 0;
    onion_stream_note_last_dial(
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion:8055",
        "queued");
    struct onion_last_dial queued;
    onion_stream_get_last_dial(&queued);
    ok = ok && strstr(queued.target, ".onion:8055") != NULL &&
         queued.attempted_unix > 0 &&
         strcmp(queued.result, "queued") == 0;
    onion_stream_note_last_dial(
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion:8055",
        "circuit_ready");
    struct onion_last_dial ready;
    onion_stream_get_last_dial(&ready);
    ok = ok && strcmp(ready.result, "circuit_ready") == 0 &&
         ready.attempted_unix >= queued.attempted_unix;
    onion_stream_reset_stages_for_test();
    struct onion_last_dial reset;
    onion_stream_get_last_dial(&reset);
    ok = ok && reset.target[0] == '\0' && reset.attempted_unix == 0;
    return ok;
}

/* Characterization of onion_stream_dial_bump(): driven through
 * onion_stream_dial_begin() so the per-dial record exists, read back through
 * onion_stream_get_stages / onion_stream_get_recent_dials / last dial. */
static void bump_test_service(struct net_service *svc)
{
    net_service_init(svc);
    unsigned char ip4[4] = {10, 0, 0, 9};
    net_addr_set_ipv4(&svc->addr, ip4);
    svc->port = 8033;
}

static uint64_t bump_stage_value(const struct onion_stream_stages *st,
                                 enum onion_stream_dial_stage stage)
{
    switch (stage) {
    case ONION_DIAL_STREAM_QUEUED:     return st->stream_queued;
    case ONION_DIAL_CIRCUIT_READY:     return st->circuit_ready;
    case ONION_DIAL_BRIDGE_UP:         return st->bridge_up;
    case ONION_DIAL_OPEN_REFUSED:      return st->open_refused;
    case ONION_DIAL_CIRCUIT_TIMEOUT:   return st->circuit_timeout;
    case ONION_DIAL_CIRCUIT_TORN_DOWN: return st->circuit_torn_down;
    case ONION_DIAL_BRIDGE_CLOSED:     return st->bridge_closed;
    case ONION_DIAL_BYTES_TO_PEER:     return st->bytes_to_peer;
    case ONION_DIAL_BYTES_FROM_PEER:   return st->bytes_from_peer;
    case ONION_DIAL_PEERS_ANSWERED:    return st->peers_answered;
    case ONION_DIAL_STAGE_COUNT:       break;
    }
    return UINT64_MAX;
}

static bool bump_newest_snapshot(struct onion_stream_dial_snapshot *snap)
{
    return onion_stream_get_recent_dials(snap, 1) == 1;
}

static bool verify_bump_out_of_range_is_noop(void)
{
    onion_stream_reset_stages_for_test();
    struct net_service svc;
    bump_test_service(&svc);
    struct onion_stream_dial_record *rec = onion_stream_dial_begin(&svc);
    bool ok = rec != NULL;
    onion_stream_dial_bump(rec, (enum onion_stream_dial_stage)-1, 5);
    onion_stream_dial_bump(rec, ONION_DIAL_STAGE_COUNT, 5);

    struct onion_stream_stages st;
    onion_stream_get_stages(&st);
    ok = ok && st.dial_started == 1;
    for (int i = 0; i < ONION_DIAL_STAGE_COUNT; i++)
        ok = ok && bump_stage_value(&st, (enum onion_stream_dial_stage)i) == 0;

    struct onion_stream_dial_snapshot snap;
    ok = ok && bump_newest_snapshot(&snap);
    for (int i = 0; i < ONION_DIAL_STAGE_COUNT; i++)
        ok = ok && bump_stage_value(&snap.stages,
                                    (enum onion_stream_dial_stage)i) == 0;

    struct onion_last_dial last;
    onion_stream_get_last_dial(&last);
    ok = ok && strcmp(last.result, "dial_started") == 0 &&
         strcmp(last.target, "10.0.0.9:8033") == 0;
    onion_stream_reset_stages_for_test();
    return ok;
}

static bool verify_bump_without_record_counts_totals_only(void)
{
    onion_stream_reset_stages_for_test();
    onion_stream_dial_bump(NULL, ONION_DIAL_STREAM_QUEUED, 3);
    onion_stream_dial_bump(NULL, ONION_DIAL_BYTES_TO_PEER, 2);

    struct onion_stream_stages st;
    onion_stream_get_stages(&st);
    bool ok = st.stream_queued == 3 && st.bytes_to_peer == 2 &&
              st.dial_started == 0 && st.circuit_ready == 0 &&
              st.bytes_from_peer == 0 && st.bridge_closed == 0;

    /* Mapped stage with no record still publishes the last-dial result,
     * but has no target to record, so no timestamp is stamped either. */
    struct onion_last_dial last;
    onion_stream_get_last_dial(&last);
    ok = ok && last.target[0] == '\0' && last.attempted_unix == 0 &&
         strcmp(last.result, "stream_queued") == 0;

    /* Unmapped stage: no last-dial note, result stays as it was. */
    onion_stream_dial_bump(NULL, ONION_DIAL_BYTES_TO_PEER, 1);
    onion_stream_get_last_dial(&last);
    ok = ok && strcmp(last.result, "stream_queued") == 0;
    onion_stream_reset_stages_for_test();
    return ok;
}

static bool verify_bump_mapped_stages_record_result(void)
{
    static const struct {
        enum onion_stream_dial_stage stage;
        const char *result;
    } rows[] = {
        {ONION_DIAL_STREAM_QUEUED, "stream_queued"},
        {ONION_DIAL_CIRCUIT_READY, "circuit_ready"},
        {ONION_DIAL_BRIDGE_UP, "bridge_up"},
        {ONION_DIAL_OPEN_REFUSED, "open_refused"},
        {ONION_DIAL_CIRCUIT_TIMEOUT, "circuit_timeout"},
        {ONION_DIAL_CIRCUIT_TORN_DOWN, "circuit_torn_down"},
    };
    bool ok = true;
    for (size_t r = 0; r < sizeof(rows) / sizeof(rows[0]); r++) {
        onion_stream_reset_stages_for_test();
        struct net_service svc;
        bump_test_service(&svc);
        struct onion_stream_dial_record *rec = onion_stream_dial_begin(&svc);
        onion_stream_dial_bump(rec, rows[r].stage, 2);

        struct onion_stream_stages st;
        onion_stream_get_stages(&st);
        struct onion_stream_dial_snapshot snap;
        struct onion_last_dial last;
        onion_stream_get_last_dial(&last);
        ok = ok && rec != NULL &&
             bump_stage_value(&st, rows[r].stage) == 2 &&
             bump_newest_snapshot(&snap) &&
             bump_stage_value(&snap.stages, rows[r].stage) == 2 &&
             strcmp(last.result, rows[r].result) == 0 &&
             strcmp(last.target, "10.0.0.9:8033") == 0 &&
             last.attempted_unix > 0;
    }
    onion_stream_reset_stages_for_test();
    return ok;
}

static bool verify_bump_unmapped_stages_keep_last_result(void)
{
    onion_stream_reset_stages_for_test();
    struct net_service svc;
    bump_test_service(&svc);
    struct onion_stream_dial_record *rec = onion_stream_dial_begin(&svc);
    onion_stream_dial_bump(rec, ONION_DIAL_BRIDGE_UP, 1);

    static const enum onion_stream_dial_stage unmapped[] = {
        ONION_DIAL_BRIDGE_CLOSED,
        ONION_DIAL_BYTES_TO_PEER,
        ONION_DIAL_BYTES_FROM_PEER,
        ONION_DIAL_PEERS_ANSWERED,
    };
    for (size_t i = 0; i < sizeof(unmapped) / sizeof(unmapped[0]); i++)
        onion_stream_dial_bump(rec, unmapped[i], 4);

    struct onion_stream_stages st;
    onion_stream_get_stages(&st);
    struct onion_stream_dial_snapshot snap;
    bool ok = rec != NULL && bump_newest_snapshot(&snap);
    for (size_t i = 0; i < sizeof(unmapped) / sizeof(unmapped[0]); i++)
        ok = ok && bump_stage_value(&st, unmapped[i]) == 4 &&
             bump_stage_value(&snap.stages, unmapped[i]) == 4;
    ok = ok && bump_stage_value(&st, ONION_DIAL_BRIDGE_UP) == 1;

    struct onion_last_dial last;
    onion_stream_get_last_dial(&last);
    ok = ok && strcmp(last.result, "bridge_up") == 0;
    onion_stream_reset_stages_for_test();
    return ok;
}

static bool verify_bump_zero_adds_nothing_and_accumulates(void)
{
    onion_stream_reset_stages_for_test();
    struct net_service svc;
    bump_test_service(&svc);
    struct onion_stream_dial_record *rec = onion_stream_dial_begin(&svc);
    onion_stream_dial_bump(rec, ONION_DIAL_CIRCUIT_READY, 0);

    struct onion_stream_stages st;
    onion_stream_get_stages(&st);
    struct onion_stream_dial_snapshot snap;
    bool ok = rec != NULL && bump_newest_snapshot(&snap) &&
              st.circuit_ready == 0 && snap.stages.circuit_ready == 0;
    /* by == 0 still publishes the mapped last-dial result. */
    struct onion_last_dial last;
    onion_stream_get_last_dial(&last);
    ok = ok && strcmp(last.result, "circuit_ready") == 0;

    onion_stream_dial_bump(rec, ONION_DIAL_STREAM_QUEUED, 1);
    onion_stream_dial_bump(rec, ONION_DIAL_STREAM_QUEUED, 2);
    onion_stream_get_stages(&st);
    ok = ok && bump_newest_snapshot(&snap) &&
         st.stream_queued == 3 && snap.stages.stream_queued == 3;
    onion_stream_reset_stages_for_test();
    return ok;
}

int test_onion_stream(void);
int test_onion_stream(void)
{
    int failures = 0;

    printf("onion_stream: default connect budget uses two bounded fresh "
           "circuits... ");
    if (verify_connect_budget_two_circuits()) printf("OK\n");
    else { printf("FAIL\n"); failures++; }

    printf("onion_stream: refuses a non-tor service... ");
    if (verify_non_tor_service_refused()) printf("OK\n");
    else { printf("FAIL\n"); failures++; }

    printf("onion_stream: tor dial fails closed with Tor down... ");
    if (verify_tor_dial_fails_closed_with_tor_down()) printf("OK\n");
    else { printf("FAIL\n"); failures++; }

    printf("onion_stream: clearnet dialer refuses torv3... ");
    if (verify_clearnet_dialer_refuses_torv3()) printf("OK\n");
    else { printf("FAIL\n"); failures++; }

    printf("onion_stream: last dial records target, timestamp, result... ");
    if (verify_last_dial_records_state()) printf("OK\n");
    else { printf("FAIL\n"); failures++; }

    printf("onion_stream: dial bump ignores out-of-range stages... ");
    if (verify_bump_out_of_range_is_noop()) printf("OK\n");
    else { printf("FAIL\n"); failures++; }

    printf("onion_stream: dial bump without a record counts totals only... ");
    if (verify_bump_without_record_counts_totals_only()) printf("OK\n");
    else { printf("FAIL\n"); failures++; }

    printf("onion_stream: dial bump maps each result stage to last dial... ");
    if (verify_bump_mapped_stages_record_result()) printf("OK\n");
    else { printf("FAIL\n"); failures++; }

    printf("onion_stream: dial bump keeps last dial for unmapped stages... ");
    if (verify_bump_unmapped_stages_keep_last_result()) printf("OK\n");
    else { printf("FAIL\n"); failures++; }

    printf("onion_stream: dial bump by zero adds nothing and accumulates... ");
    if (verify_bump_zero_adds_nothing_and_accumulates()) printf("OK\n");
    else { printf("FAIL\n"); failures++; }

    return failures;
}
