/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Shared Commons join posture for toolchain, offered, and guide. */

#include "command/native_zcode_join.h"

#include "base/log_macros.h"
#include "json/json.h"
#include "util/util.h"
#include "vcs/zcode_work_node.h"

#include <string.h>

bool zcl_zcode_join_posture_fill(struct zcl_zcode_join_posture *out)
{
    if (!out)
        LOG_FAIL("zcode.join", "fill: out is NULL");
    memset(out, 0, sizeof(*out));
    struct json_value work;
    json_init(&work);
    bool dumped = vcs_zcode_work_node_dump_state_json(&work, NULL);
    bool worker_enabled = dumped && json_get_bool(json_get(&work, "enabled"));
    json_free(&work);
    out->package_hosting = GetBoolArg("-packagehost", false);
    out->build_worker = worker_enabled || GetBoolArg("-buildworker", false);
    out->joined = out->package_hosting && out->build_worker;
    out->join_flags = ZCL_ZCODE_JOIN_FLAGS;
    out->hosting_requirement = ZCL_ZCODE_HOSTING_REQUIREMENT;
    out->offline_next_command =
        "restart this node with " ZCL_ZCODE_JOIN_FLAGS
        ", then z23 zcode package offered";
    return true;
}

bool zcl_zcode_join_posture_push_json(
    struct json_value *data, const struct zcl_zcode_join_posture *join)
{
    if (!data || !join)
        LOG_FAIL("zcode.join", "push_json: data or join is NULL");
    if (!json_push_kv_str(data, "join_flags", join->join_flags) ||
        !json_push_kv_bool(data, "package_hosting", join->package_hosting) ||
        !json_push_kv_bool(data, "build_worker", join->build_worker) ||
        !json_push_kv_bool(data, "joined", join->joined) ||
        !json_push_kv_str(data, "hosting_requirement",
                          join->hosting_requirement))
        LOG_FAIL("zcode.join", "push_json: reply object refused join fields");
    return true;
}

/* ── the composed verdict ──────────────────────────────────────────────────
 * See native_zcode_join.h for why speed is never a term of the verdict and
 * why READY needs all four stages. Nothing below reads latency_ms. */

const char *zcl_join_signal_name(enum zcl_join_signal signal)
{
    switch (signal) {
    case ZCL_JOIN_SIGNAL_CONFIRMED:    return "confirmed";
    case ZCL_JOIN_SIGNAL_FAILED:       return "failed";
    case ZCL_JOIN_SIGNAL_UNOBSERVABLE: return "unobservable";
    case ZCL_JOIN_SIGNAL_UNCONFIRMED:  break;
    }
    return "unconfirmed";
}

const char *zcl_join_readiness_state(const struct zcl_join_readiness *ready)
{
    if (!ready)
        return "publishing-descriptor";
    /* Order is the announcement order, so the name is always the FIRST thing
     * still outstanding rather than an arbitrary one of several. Only
     * CONFIRMED advances: UNOBSERVABLE and UNCONFIRMED both stop here, which
     * is what keeps "ready" a promise instead of an assumption. */
    if (ready->descriptor_published != ZCL_JOIN_SIGNAL_CONFIRMED)
        return "publishing-descriptor";
    if (ready->rendezvous_established != ZCL_JOIN_SIGNAL_CONFIRMED)
        return "establishing-rendezvous";
    if (ready->circuit_built != ZCL_JOIN_SIGNAL_CONFIRMED)
        return "building-circuit";
    if (ready->listener_accepting != ZCL_JOIN_SIGNAL_CONFIRMED)
        return "opening-listener";
    /* All four confirmed. This branch is REACHABLE by construction and
     * test_zcode_node_command proves it — a passing condition that cannot be
     * met is worse than no check at all. */
    return "ready";
}

enum zcl_join_signal zcl_join_readiness_outstanding(
    const struct zcl_join_readiness *ready)
{
    if (!ready)
        return ZCL_JOIN_SIGNAL_UNCONFIRMED;
    if (ready->descriptor_published != ZCL_JOIN_SIGNAL_CONFIRMED)
        return ready->descriptor_published;
    if (ready->rendezvous_established != ZCL_JOIN_SIGNAL_CONFIRMED)
        return ready->rendezvous_established;
    if (ready->circuit_built != ZCL_JOIN_SIGNAL_CONFIRMED)
        return ready->circuit_built;
    if (ready->listener_accepting != ZCL_JOIN_SIGNAL_CONFIRMED)
        return ready->listener_accepting;
    return ZCL_JOIN_SIGNAL_CONFIRMED;
}

bool zcl_join_verdict_push_json(struct json_value *data,
                                const struct zcl_join_verdict *verdict,
                                const struct zcl_join_readiness *ready)
{
    if (!data)
        LOG_FAIL("zcode.join", "verdict_push_json: data is NULL");
    if (verdict) {
        struct json_value v;
        json_init(&v);
        json_set_object(&v);
        bool ok =
            json_push_kv_str(&v, "reachable",
                             zcl_join_signal_name(verdict->reachable)) &&
            json_push_kv_str(&v, "responsive",
                             zcl_join_signal_name(verdict->responsive)) &&
            json_push_kv_str(&v, "fresh",
                             zcl_join_signal_name(verdict->fresh)) &&
            json_push_kv_str(&v, "serving",
                             zcl_join_signal_name(verdict->serving)) &&
            /* Speed sits BESIDE the dimensions, in its own clearly named
             * telemetry sub-object, so no reader can mistake it for one of
             * them. -1 means not measured, which is neither fast nor slow. */
            json_push_kv_int(&v, "latency_ms", verdict->latency_ms) &&
            json_push_kv_int(&v, "data_age_s", verdict->data_age_s) &&
            json_push_kv_bool(&v, "speed_is_telemetry_not_a_gate", true) &&
            json_push_kv_str(&v, "vantage",
                             verdict->vantage ? verdict->vantage : "") &&
            json_push_kv(data, "verdict", &v);
        json_free(&v);
        if (!ok)
            LOG_FAIL("zcode.join", "verdict_push_json: verdict refused");
    }
    if (ready) {
        struct json_value r;
        json_init(&r);
        json_set_object(&r);
        bool ok =
            json_push_kv_str(&r, "state", zcl_join_readiness_state(ready)) &&
            json_push_kv_str(&r, "state_signal",
                             zcl_join_signal_name(
                                 zcl_join_readiness_outstanding(ready))) &&
            json_push_kv_str(&r, "descriptor_published",
                             zcl_join_signal_name(ready->descriptor_published)) &&
            json_push_kv_str(&r, "rendezvous_established",
                             zcl_join_signal_name(ready->rendezvous_established)) &&
            json_push_kv_str(&r, "circuit_built",
                             zcl_join_signal_name(ready->circuit_built)) &&
            json_push_kv_str(&r, "listener_accepting",
                             zcl_join_signal_name(ready->listener_accepting)) &&
            json_push_kv(data, "announcement", &r);
        json_free(&r);
        if (!ok)
            LOG_FAIL("zcode.join", "verdict_push_json: announcement refused");
    }
    return true;
}
