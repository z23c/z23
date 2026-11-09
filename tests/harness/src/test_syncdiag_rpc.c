/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Regression test: `getsyncdiag` RPC crashes via `json_free` on uninitialized
 * stack memory.
 *
 * The bug: `rpc_getsyncdiag` in `engine/controllers/src/health_controller.c`
 * declares `struct json_value wd;` (and `hdr`) without `json_init()` or
 * `= {0}`. `json_set_object(&wd)` internally calls `json_free(&wd)`,
 * which reads uninitialized `type`, `num_children`, and `children` —
 * typically crashing with SIGSEGV/SIGABRT once the stack region holds
 * non-zero residue from earlier RPCs (which is always the case on a
 * live node).
 *
 * This test dirties the lower stack with 0xCC before calling the RPC
 * to force the uninitialized read to observe garbage in a fresh test
 * process, making the repro deterministic. Post-fix (wd/hdr explicitly
 * zero-initialized), the RPC must return a well-formed JSON object
 * containing non-empty `watchdog` and `headers` sub-objects. */


#include "test/syncdiag_rpc_fixture.h"
#include "services/chain_evidence_authority_service.h"
#include "net/peer_lifecycle.h"
#include "net/net.h"

static bool syncdiag_queue_rpc(struct json_value *result)
{
    struct json_value params = {0}, arg = {0};
    json_set_array(&params); json_set_str(&arg, "network");
    bool ok = json_push_back(&params, &arg);
    json_set_str(&arg, "queue_memory");
    ok = ok && json_push_back(&params, &arg) &&
        diag_rpc_dumpstate_builtin(&params, false, result);
    json_free(&arg); json_free(&params);
    return ok;
}

static bool syncdiag_queue_absent(void)
{
    struct json_value result = {0};
    rpc_net_set_connman(NULL);
    bool ok = syncdiag_queue_rpc(&result);
    const struct json_value *state = json_get(&result, "state");
    const struct json_value *reason = json_get(state, "reason");
    const char *keys[] = {"recv_bytes", "recv_cap_bytes", "send_bytes", "send_cap_bytes"};
    ok = ok && !json_get_bool(json_get(state, "available")) && reason && reason->type == JSON_STR &&
        strcmp(json_get_str(reason), "node_not_in_process") == 0;
    for (size_t i = 0; i < 4; i++) {
        const struct json_value *v = json_get(state, keys[i]);
        if (!v || v->type != JSON_NULL) ok = false;
    }
    json_free(&result); return ok;
}

static bool syncdiag_queue_field(const struct json_value *state, const char *key, size_t expected)
{
    const struct json_value *v = json_get(state, key);
    return v && v->type == JSON_INT && json_get_int(v) >= 0 && (size_t)json_get_int(v) == expected;
}

static bool syncdiag_queue_values(const struct json_value *result, size_t recv_before, size_t send_before)
{
    const struct json_value *state = json_get(result, "state");
    return json_get_bool(json_get(state, "available")) &&
        net_recv_total_bytes() >= recv_before + 2048 && net_send_total_bytes() > send_before &&
        syncdiag_queue_field(state, "recv_bytes", net_recv_total_bytes()) &&
        syncdiag_queue_field(state, "recv_cap_bytes", 1048576) &&
        syncdiag_queue_field(state, "send_bytes", net_send_total_bytes()) &&
        syncdiag_queue_field(state, "send_cap_bytes", 2097152) && json_write(result, NULL, 0) < 4096;
}

static bool syncdiag_restore_env(const char *name, char *value)
{
    bool ok = value ? setenv(name, value, 1) == 0 : unsetenv(name) == 0;
    free(value); return ok;
}

static bool syncdiag_queue_live(struct connman *cm)
{
    struct json_value result = {0};
    uint8_t magic[MESSAGE_START_SIZE] = {0x24, 0xe9, 0x27, 0x64};
    struct net_message msg; struct msg_header hdr;
    struct net_manager manager; struct net_address address;
    char payload[2048] = {0};
    size_t before = net_recv_total_bytes();
    size_t send_before = net_send_total_bytes();
    net_manager_init(&manager); memcpy(manager.message_start, magic, sizeof(magic));
    net_address_init(&address);
    unsigned char ip[4] = {127, 0, 0, 1};
    net_addr_set_ipv4(&address.svc.addr, ip); address.svc.port = 8033;
    struct p2p_node *node = p2p_node_create(&manager, ZCL_INVALID_SOCKET, &address, "fixture", true);
    if (node) {
        p2p_node_begin_message(node, "ping", magic);
        p2p_node_write_message_data(node, payload, sizeof(payload));
        p2p_node_end_message(node);
    }
    net_message_init(&msg, magic);
    msg_header_init_full(&hdr, magic, "ping", sizeof(payload));
    net_message_read_header(&msg, (const char *)&hdr, MSG_HEADER_SIZE);
    bool read_ok = net_message_read_data(&msg, payload, sizeof(payload)) == (int)sizeof(payload);
    rpc_net_set_connman(cm);
    bool got = syncdiag_queue_rpc(&result);
    bool ok = node && read_ok && got && syncdiag_queue_values(&result, before, send_before);
    json_free(&result); net_message_free(&msg); if (node) p2p_node_free(node); net_manager_free(&manager);
    bool cleaned = net_recv_total_bytes() == before && net_send_total_bytes() == send_before;
    if (!cleaned) printf("FAIL: network queue fixture did not release allocations\n");
    return cleaned && ok;
}

static int syncdiag_queue_memory(void)
{
    struct connman *prior = rpc_net_get_connman();
    struct connman cm = {0};
    const char *recv_env = getenv("ZCL_MAX_RECVBUFFER_TOTAL_BYTES");
    const char *send_env = getenv("ZCL_MAX_SENDBUFFER_TOTAL_BYTES");
    char *saved_recv = recv_env ? strdup(recv_env) : NULL;
    char *saved_send = send_env ? strdup(send_env) : NULL;
    if ((recv_env && !saved_recv) || (send_env && !saved_send)) {
        free(saved_recv); free(saved_send); return 1;
    }
    bool env_ok = setenv("ZCL_MAX_RECVBUFFER_TOTAL_BYTES", "1048576", 1) == 0 &&
        setenv("ZCL_MAX_SENDBUFFER_TOTAL_BYTES", "2097152", 1) == 0;
    bool absent = syncdiag_queue_absent();
    bool live = syncdiag_queue_live(&cm);
    rpc_net_set_connman(prior);
    bool ok = env_ok && absent && live;
    ok = syncdiag_restore_env("ZCL_MAX_RECVBUFFER_TOTAL_BYTES", saved_recv) && ok;
    ok = syncdiag_restore_env("ZCL_MAX_SENDBUFFER_TOTAL_BYTES", saved_send) && ok;
    if (!ok) printf("FAIL: resident network queue memory snapshot\n");
    return ok ? 0 : 1;
}

static int syncdiag_peer_summary(void)
{
    struct json_value params = {0}, arg = {0}, result = {0};
    json_set_array(&params);
    json_set_str(&arg, "peer_lifecycle");
    json_push_back(&params, &arg);
    json_set_str(&arg, "summary");
    json_push_back(&params, &arg);
    peer_lifecycle_note_attempt(NULL, PEER_LIFECYCLE_SOURCE_UNKNOWN);
    bool ok = diag_rpc_dumpstate_builtin(&params, false, &result);
    const struct json_value *state = json_get(&result, "state");
    const struct json_value *attempted = json_get(state, "attempted");
    bool valid = ok && attempted && attempted->type == JSON_INT &&
                 json_get_int(attempted) > 0 && !json_get(state, "peers") &&
                 json_write(&result, NULL, 0) < 4096;
    json_free(&result);
    json_free(&params);
    json_set_array(&params);
    json_set_str(&arg, "peer_lifecycle");
    json_push_back(&params, &arg);
    ok = diag_rpc_dumpstate_builtin(&params, false, &result);
    state = json_get(&result, "state");
    valid = valid && ok && json_get(state, "peers") != NULL;
    json_free(&result);
    json_set_str(&arg, "incidents");
    json_push_back(&params, &arg);
    ok = diag_rpc_dumpstate_builtin(&params, false, &result);
    state = json_get(&result, "state");
    valid = valid && ok && json_get(state, "incident_count") != NULL;
    if (!valid)
        printf("FAIL: peer lifecycle summary must contain totals without peer rows\n");
    json_free(&result);
    json_free(&arg);
    json_free(&params);
    return valid ? 0 : 1;
}

int test_syncdiag_rpc(void)
{
    int failures = 0;
    agent_security_posture_test_override_review_required(0);

    syncdiag_reset_rpc_globals_for_test();

    failures += syncdiag_queue_memory();
    failures += syncdiag_peer_summary();

    failures += syncdiag_cases_anchorstatus();
    failures += syncdiag_cases_network();
    failures += syncdiag_cases_health();
    failures += syncdiag_cases_api_catalog();
    failures += syncdiag_cases_agent_status();
    failures += syncdiag_cases_agent_projection();
    failures += syncdiag_cases_agent_codemap();
    failures += syncdiag_cases_agent_contracts();
    failures += syncdiag_cases_agent_ops();
    failures += syncdiag_cases_agent_interface();
    failures += syncdiag_cases_operator();
    /* Reap the one-shot evidence-maintenance thread healthcheck reads spawn. */
    chain_evidence_maintain_quiesce();

    syncdiag_reset_rpc_globals_for_test();
    agent_security_posture_test_override_review_required(-1);
    return failures;
}
