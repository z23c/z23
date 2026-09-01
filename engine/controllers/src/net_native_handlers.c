/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Native bodies for peer-incident and onion-health commands. See
 * controllers/native_handler_body.h for their shared contract. */

#include "controllers/net_native_handlers.h"

#include "controllers/network_controller.h"
#include "json/json.h"
#include "controllers/rpc_client.h"
#include "net/onion_service.h"
#include "platform/time_compat.h"
#include "rpc/protocol.h"
#include "util/log_macros.h"
#include "util/path_check.h"
#include "util/safe_alloc.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* ── Peer incidents ──────────────────────────────────────────────── */

static bool rpc_body_is_method_not_found(const char *body,
                                         char *message,
                                         size_t message_len)
{
    if (message && message_len)
        message[0] = '\0';
    if (!body || !body[0])
        return false;

    struct json_value root;
    json_init(&root);
    if (!json_read(&root, body, strlen(body)) || root.type != JSON_OBJ) {
        json_free(&root);
        return false;
    }

    const struct json_value *rerr = json_get(&root, "error");
    const struct json_value *obj =
        rerr && rerr->type == JSON_OBJ ? rerr : &root;
    int64_t code = json_get_int(json_get(obj, "code"));
    const char *msg = json_get_str(json_get(obj, "message"));
    if (message && message_len)
        snprintf(message, message_len, "%s", msg);
    json_free(&root);
    return code == RPC_METHOD_NOT_FOUND;
}

static char *peer_incidents_dumpstate_fallback_body(const char *reason)
{
    char *raw = node_rpc_call("dumpstate",
                             "[\"peer_lifecycle\",\"incidents\"]");
    if (!raw)
        return NULL;

    struct json_value dumpstate;
    json_init(&dumpstate);
    char *out = NULL;
    if (json_read(&dumpstate, raw, strlen(raw)) &&
        dumpstate.type == JSON_OBJ) {
        struct json_value normalized;
        json_init(&normalized);
        if (peer_incidents_from_dumpstate_result_json(&dumpstate, &normalized,
                                                      reason)) {
            size_t need = json_write(&normalized, NULL, 0) + 1;
            out = zcl_malloc(need, "peer_incidents_fallback_json");
            if (out)
                json_write(&normalized, out, need);
        }
        json_free(&normalized);
    }
    json_free(&dumpstate);
    free(raw);
    return out;
}

char *zcl_native_peer_incidents_body(const struct json_value *args,
                                     struct zcl_native_body_err *err)
{
    (void)args;
    char *out = node_rpc_call("peerincidents", NULL);
    char message[192];
    if (rpc_body_is_method_not_found(out, message, sizeof(message))) {
        char *fallback = peer_incidents_dumpstate_fallback_body(message);
        if (fallback) {
            free(out);
            return fallback;
        }
    }
    if (!out) {
        err->status = ZCL_NATIVE_BODY_UNAVAILABLE;
        snprintf(err->message, sizeof(err->message),
                 "RPC peerincidents returned null");
        LOG_NULL("native.net", "RPC peerincidents returned null");
    }
    return out;
}

/* ── Onion health command body ────────────────────────────────────────────── */

/* Set a contextual allocation failure and return NULL. cap==0 means no single
 * byte count applies; both current call sites pass a nonzero cap. */
static char *net_native_oom(struct zcl_native_body_err *err, size_t cap,
                            const char *what)
{
    err->status = ZCL_NATIVE_BODY_INTERNAL;
    snprintf(err->message, sizeof(err->message), "malloc failed for %s", what);
    if (cap > 0)
        LOG_NULL("native.net", "malloc failed for %s (%zu bytes)", what, cap);
    LOG_NULL("native.net", "malloc failed for %s", what);
}

/* Probe the in-process onion service by calling
 * `onion_service_handle_request()` directly and measuring the
 * response size + wall-clock latency.  Synchronous: one call per
 * invocation.  Bypasses Tor and the SOCKS layer entirely (dynhost
 * has no SOCKS per the project memory), so this is a cheap
 * liveness check, not a full end-to-end test — the latter would
 * require an actual Tor circuit roundtrip and can't run from a
 * trusted-peer tool.
 *
 * Returns:
 *   { onion_address, path, ok, latency_ms, response_bytes, error? }
 * When onion service is not started:
 *   { ok: false, error: "not_started" }
 *
 * err->status = ZCL_NATIVE_BODY_INVALID on a bad `path` arg — the
 * wrapper maps this to the native command's handler-failed status for
 * this tool (byte-compat trumps the generic INVALID mapping). */
char *zcl_native_onion_health_body(const struct json_value *args,
                                   struct zcl_native_body_err *err)
{
    const char *probe_path = json_get_str_or(args, "path", "/directory.json");
    if (!probe_path || !*probe_path) probe_path = "/directory.json";
    if (!path_check_url_arg(probe_path, 256)) {
        err->status = ZCL_NATIVE_BODY_INVALID;
        snprintf(err->message, sizeof(err->message),
                 "path: must start with '/', "
                 "be 1..256 chars, contain no control chars or '..' segments");
        LOG_WARN("native.net", "onion_health: %s", err->message);
        return NULL;
    }

    const char *addr = onion_service_get_address();

    char *body = zcl_malloc(512, "onion_health_body");
    if (!body)
        return net_native_oom(err, 512, "onion health response");

    if (!addr) {
        snprintf(body, 512,
            "{\"ok\":false,\"error\":\"not_started\","
             "\"onion_address\":null,\"path\":\"%s\","
             "\"latency_ms\":0,\"response_bytes\":0}",
            probe_path);
        return body;
    }

    struct timespec t0, t1;
    platform_time_monotonic_timespec(&t0);

    /* Heap, NOT a function-static buffer: the middleware runs handlers on a
     * detached worker thread and abandons it on timeout, so two invocations
     * could race a shared static. 64 KB is also borderline for the stack —
     * allocate per call and free before return. */
    const size_t resp_cap = 65536;
    uint8_t *resp = zcl_malloc(resp_cap, "onion_health_resp");
    if (!resp) {
        free(body);
        return net_native_oom(err, resp_cap, "onion health probe buffer");
    }
    size_t n = onion_service_handle_request("GET", probe_path, NULL, 0,
                                              resp, resp_cap);

    platform_time_monotonic_timespec(&t1);
    free(resp);  /* only the byte count `n` is needed past this point */
    int64_t latency_us =
        (t1.tv_sec - t0.tv_sec) * 1000000LL +
        (t1.tv_nsec - t0.tv_nsec) / 1000LL;
    int64_t latency_ms = latency_us / 1000;

    bool ok = (n > 0);

    snprintf(body, 512,
        "{\"ok\":%s,\"onion_address\":\"%s\",\"path\":\"%s\","
         "\"latency_ms\":%lld,\"response_bytes\":%zu%s}",
        ok ? "true" : "false",
        addr, probe_path,
        (long long)latency_ms, n,
        ok ? "" : ",\"error\":\"empty_response\"");

    return body;
}

/* ── Tier-1 hot-swap: native.leaves generation entrypoint ──────
 * Dev-only (compiled only under -DZCL_HOTSWAP_GEN, a generation .so build;
 * expands to nothing in the node/release TU — see ZCL_HOTSWAP_EXPORT_LEAVES
 * in engine/modules/hotswap/include/hotswap/hotswap.h). Stages every native command
 * leaf this controller owns; the resident bridge re-points them at THIS
 * TU's freshly-compiled bodies via zcl_native_bridge_run(). Probe is
 * core.network.peers.incidents: zcl_native_peer_incidents_body ignores
 * `args` entirely (RPC "peerincidents" takes no parameters) and never
 * emits a top-level "error" key on success, so it tolerates the empty-args
 * dispatch the generation self-test uses. core.network.onion.health is
 * NOT the probe: with no onion service started (the default dev/test build
 * links the Tor stub) it returns {"ok":false,"error":"not_started",...},
 * which would make the self-test spuriously fail depending on whether Tor
 * happens to be up. See config/hotswap_eligible.def. */
#ifdef ZCL_HOTSWAP_GEN
#define ZCL_HOTSWAP_PROBE_LEAF "core.network.peers.incidents"
#include "hotswap/hotswap.h"
#include "kernel/command_registry.h"
#include "command/native_command.h"

ZCL_HOTSWAP_TRAMPOLINE(tramp_peer_incidents, zcl_native_peer_incidents_body)

ZCL_HOTSWAP_TRAMPOLINE(tramp_onion_health, zcl_native_onion_health_body)

static const struct zcl_hotswap_leaf_replacement k_leaves[] = { /* hotswap-static-ok: leaf registration tables are immutable */    { "core.network.peers.incidents", tramp_peer_incidents },
    { "core.network.onion.health",    tramp_onion_health },
};

ZCL_HOTSWAP_EXPORT_LEAVES(k_leaves, sizeof(k_leaves) / sizeof(k_leaves[0]))
#endif /* ZCL_HOTSWAP_GEN */

/* REAL (activatable) single-handler module ABI export. Compiled only under a
 * `make hotswap-module-so HANDLER=core.network.peers.incidents` build
 * (-DZCL_HOTSWAP_MODULE_GEN); expands to nothing in the node/release TU. The
 * module re-points ONLY the `core.network.peers.incidents` leaf to this TU's
 * freshly-compiled body via the same zcl_native_bridge_run() seam the leaf
 * provider uses. See hotswap_module.h and hotswap_activate() (engine/modules/hotswap). */
#ifdef ZCL_HOTSWAP_MODULE_GEN
#include "hotswap/hotswap_module.h"
#include "kernel/command_registry.h"
#include "command/native_command.h"

ZCL_HOTSWAP_TRAMPOLINE(module_tramp_peer_incidents, zcl_native_peer_incidents_body)

/* The module's own health hook — runs before the loader publishes it. Kept
 * node-independent (no RPC): a structural OK. */
static bool module_selftest_peer_incidents(char *err, size_t cap)
{
    (void)err;
    (void)cap;
    return true;
}

ZCL_HOTSWAP_TRAMPOLINE(module_tramp_onion_health, zcl_native_onion_health_body)

/* Mirrors k_leaves above — both leaves this controller owns, published in ONE
 * all-or-nothing batch. Batch size, not authority: both are READY read-only
 * leaves of this same allowlisted TU. */
static const struct zcl_hotswap_leaf k_module_leaves[] = { /* hotswap-static-ok: immutable leaf registration tables */    { "core.network.peers.incidents", module_tramp_peer_incidents },
    { "core.network.onion.health",    module_tramp_onion_health },
};

ZCL_HOTSWAP_MODULE_LEAVES(k_module_leaves, module_selftest_peer_incidents)
#endif /* ZCL_HOTSWAP_MODULE_GEN */
