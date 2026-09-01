// one-result-type-ok:telemetry-fill-provider — E2 (one way out): the sole public
// function is a telemetry COLLECTOR, the same shape as the `_dump_state_json`
// dumpers it reads (CLAUDE.md "Adding state introspection"): bool, where false
// means "could not populate at all". struct zcl_result is the wrong carrier
// here specifically — it formats a message, and the telemetry contract
// (docs/TELEMETRY_CONTRACT.md) requires every failure reason to be a STATIC
// greppable token with program lifetime, because the reason is borrowed by the
// rendered document rather than copied into it. That is what the `const char
// **why` out-parameter carries. There is no fallible service surface here.
/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The `runtime` telemetry domain's collector. Contract, and why it reads the
 * node over RPC instead of reading itself: services/runtime_telemetry.h.
 *
 * The shape of every fill_* function below is the same and is the point: read
 * a value, and if it is not there, say so with a static token. A leaf is never
 * left at its zero value on a failed read, because zero is TELEMETRY_UNSET and
 * the render layer counts that as a provider defect — which is exactly what a
 * forgotten field is, and exactly what an unreadable one is not.
 */

#include "services/runtime_telemetry.h"

/* Upward include, deliberate: rpc_client.h is the loopback TRANSPORT (a socket
 * + a cookie), not controller policy, and this collector is a client of the
 * running node by design — see the header for why an in-process read here would
 * return a true answer about the wrong process. It calls one function,
 * node_rpc_call, and reads no controller state. */
#include "controllers/rpc_client.h" // shape-layer-ok:telemetry-collector-is-an-rpc-client
#include "json/json.h"
#include "util/log_macros.h"
#include "util/telemetry_render.h"
#include "util/telemetry_snapshots.h"

#include <stdlib.h>
#include <string.h>

/* Static reason tokens. Greppable, never formatted, never prose — they travel
 * into the rendered document as the leaf's `reason`. */
#define RT_WHY_NODE       "node_unreachable"
#define RT_WHY_NULL       "snapshot_null"
#define RT_WHY_DUMP       "subsystem_dump_unavailable"
#define RT_WHY_FIELD      "field_absent_from_dump"
#define RT_WHY_SENTINEL   "value_unknown_sentinel"
#define RT_WHY_NO_CHILD   "no_supervised_children"

/* ── the dumpstate transport ─────────────────────────────────────────────
 * One subsystem per call, the same `dumpstate` method `ops state` uses. The
 * reply is { subsystem, description, captured_at, state:{...} } on success and
 * either a string or an {error|code+message} object on failure. */

struct rt_dump {
    struct json_value doc; /* owns the parsed reply */
    const struct json_value *state; /* borrowed from doc, NULL when unusable */
};

static void rt_dump_free(struct rt_dump *d)
{
    if (!d)
        return;
    json_free(&d->doc);
    d->state = NULL;
}

/* True when the reply carries a usable `state` object. `*reached` is cleared
 * only for a transport-level failure, so one subsystem whose dumper is missing
 * never makes the whole node look down. */
static bool rt_fetch(const char *subsystem, struct rt_dump *out, bool *reached)
{
    json_init(&out->doc);
    out->state = NULL;

    char params[128];
    struct json_value arr, item;
    json_init(&arr);
    json_set_array(&arr);
    json_init(&item);
    json_set_str(&item, subsystem);
    (void)json_push_back(&arr, &item);
    json_free(&item);
    size_t pn = json_write(&arr, params, sizeof params);
    json_free(&arr);
    if (pn == 0 || pn >= sizeof params) {
        LOG_FAIL("runtime_telemetry", "could not encode dumpstate params for %s",
                subsystem);
    }

    char *raw = node_rpc_call("dumpstate", params);
    if (!raw) {
        if (reached)
            *reached = false;
        LOG_FAIL("runtime_telemetry", "dumpstate %s returned no body",
                subsystem);
    }
    bool parsed = json_read(&out->doc, raw, strlen(raw));
    free(raw);
    if (!parsed || out->doc.type != JSON_OBJ) {
        /* A JSON-RPC transport failure comes back as an error STUB, not as an
         * object with a `state` — treat a non-object as the node not being
         * there rather than as a broken dumper. */
        if (reached)
            *reached = false;
        LOG_FAIL("runtime_telemetry", "dumpstate %s returned a non-object body",
                subsystem);
    }
    const struct json_value *err = json_get(&out->doc, "error");
    if (err && !json_is_null(err)) {
        if (reached)
            *reached = false;
        LOG_FAIL("runtime_telemetry", "dumpstate %s reported an RPC error",
                subsystem);
    }
    const struct json_value *st = json_get(&out->doc, "state");
    if (!st || st->type != JSON_OBJ) {
        LOG_FAIL("runtime_telemetry", "dumpstate %s carried no state object",
                subsystem);
    }
    out->state = st;
    return true;
}

/* ── typed reads out of one dump ─────────────────────────────────────────
 * Each returns whether the key was present AND of the expected type. A key of
 * the wrong type is a missing key: guessing at it is how a null became a false
 * bool once already. */

static bool rt_int(const struct json_value *o, const char *k, int64_t *out)
{
    const struct json_value *v = json_get(o, k);
    if (!v || v->type != JSON_INT)
        return false;
    *out = json_get_int(v);
    return true;
}

static bool rt_bool(const struct json_value *o, const char *k, bool *out)
{
    const struct json_value *v = json_get(o, k);
    if (!v || v->type != JSON_BOOL)
        return false;
    *out = json_get_bool(v);
    return true;
}

static const char *rt_str(const struct json_value *o, const char *k)
{
    const struct json_value *v = json_get(o, k);
    if (!v || v->type != JSON_STR)
        return NULL;
    return json_get_str(v);
}

/* ── the supervisor child walk ───────────────────────────────────────────
 * The registry is variable-length, so nothing per-child is representable as a
 * leaf. What IS representable is the set of aggregates an operator reads
 * first, and they are computed here once over every child in every domain plus
 * the root orphans. */

struct rt_children {
    bool any;             /* at least one child was seen */
    int64_t stalled;
    int64_t ticks_run;
    int64_t idle_ticks;
    int64_t stall_fires;
    int64_t no_results;   /* ran, never progressed, never declared idle */
    int64_t worst_age_us;
    char worst_name[TELEMETRY_TEXT_MAX];
};

static void rt_walk_child(const struct json_value *c, struct rt_children *agg)
{
    if (!c || c->type != JSON_OBJ)
        return;
    agg->any = true;

    int64_t ticks = 0, idle = 0, fires = 0, marker = 0, age = 0;
    (void)rt_int(c, "ticks_run", &ticks);
    (void)rt_int(c, "idle_ticks", &idle);
    (void)rt_int(c, "stall_fires", &fires);
    (void)rt_int(c, "progress_marker", &marker);
    agg->ticks_run += ticks;
    agg->idle_ticks += idle;
    agg->stall_fires += fires;

    const char *reason = rt_str(c, "stall_reason");
    if (reason && strcmp(reason, "none") != 0)
        agg->stalled++;

    /* Ran at least once, never moved a marker, never said "nothing to do".
     * This is the population the no-progress detector was off for. */
    if (ticks > 0 && marker == 0 && idle == 0)
        agg->no_results++;

    bool completed = false;
    (void)rt_bool(c, "completed", &completed);
    if (!completed && rt_int(c, "last_tick_age_us", &age) &&
        age > agg->worst_age_us) {
        agg->worst_age_us = age;
        const char *name = rt_str(c, "name");
        if (name) {
            size_t n = strlen(name);
            if (n >= sizeof agg->worst_name)
                n = sizeof agg->worst_name - 1;
            memcpy(agg->worst_name, name, n);
            agg->worst_name[n] = '\0';
        }
    }
}

static void rt_walk_array(const struct json_value *arr, struct rt_children *agg)
{
    if (!arr || arr->type != JSON_ARR)
        return;
    size_t n = json_size(arr);
    for (size_t i = 0; i < n; i++)
        rt_walk_child(json_at(arr, i), agg);
}

static void rt_collect_children(const struct json_value *state,
                                struct rt_children *agg)
{
    memset(agg, 0, sizeof *agg);
    const struct json_value *domains = json_get(state, "domains");
    if (domains && domains->type == JSON_ARR) {
        size_t dn = json_size(domains);
        for (size_t i = 0; i < dn; i++)
            rt_walk_array(json_get(json_at(domains, i), "children"), agg);
    }
    rt_walk_array(json_get(state, "root_orphans"), agg);
}

/* ── group fillers ───────────────────────────────────────────────────────
 * One per group. Each takes the dump it needs (NULL when that dump could not
 * be read) and leaves NO leaf untouched on either path. */

#define RT_I64(m_, ok_, val_, src_, why_)                                     \
    do {                                                                      \
        if (ok_) { TELEMETRY_SET_I64(s, m_, (val_), (src_)); }                \
        else { TELEMETRY_UNAVAILABLE_LEAF(s, m_, (why_)); }                   \
    } while (0)

#define RT_BOOL(m_, ok_, val_, src_, why_)                                    \
    do {                                                                      \
        if (ok_) { TELEMETRY_SET_BOOL(s, m_, (val_), (src_)); }               \
        else { TELEMETRY_UNAVAILABLE_LEAF(s, m_, (why_)); }                   \
    } while (0)

#define RT_TEXT(m_, ok_, val_, src_, why_)                                    \
    do {                                                                      \
        if (ok_) { TELEMETRY_SET_TEXT(s, m_, (val_), (src_)); }               \
        else { TELEMETRY_UNAVAILABLE_LEAF(s, m_, (why_)); }                   \
    } while (0)

/* Read one int key straight through to one leaf. */
#define RT_PASS_I64(m_, obj_, key_)                                           \
    do {                                                                      \
        int64_t v_ = 0;                                                       \
        bool ok_ = (obj_) && rt_int((obj_), (key_), &v_);                     \
        RT_I64(m_, ok_, v_, TELEMETRY_SRC_CACHED_PUBLICATION,                 \
               (obj_) ? RT_WHY_FIELD : RT_WHY_DUMP);                          \
    } while (0)

#define RT_PASS_BOOL(m_, obj_, key_)                                          \
    do {                                                                      \
        bool v_ = false;                                                      \
        bool ok_ = (obj_) && rt_bool((obj_), (key_), &v_);                    \
        RT_BOOL(m_, ok_, v_, TELEMETRY_SRC_CACHED_PUBLICATION,                \
                (obj_) ? RT_WHY_FIELD : RT_WHY_DUMP);                         \
    } while (0)

#define RT_PASS_TEXT(m_, obj_, key_)                                          \
    do {                                                                      \
        const char *v_ = (obj_) ? rt_str((obj_), (key_)) : NULL;              \
        RT_TEXT(m_, v_ != NULL, v_, TELEMETRY_SRC_CACHED_PUBLICATION,         \
                (obj_) ? RT_WHY_FIELD : RT_WHY_DUMP);                         \
    } while (0)

/* A count whose producer reports -1 when it does not know the value. Storing
 * that -1 would publish a plausible number for "never measured", so the leaf
 * is marked unavailable instead. */
#define RT_PASS_SENTINEL(m_, obj_, key_)                                      \
    do {                                                                      \
        int64_t v_ = 0;                                                       \
        bool ok_ = (obj_) && rt_int((obj_), (key_), &v_) && v_ >= 0;          \
        RT_I64(m_, ok_, v_, TELEMETRY_SRC_CACHED_PUBLICATION,                 \
               !(obj_) ? RT_WHY_DUMP : RT_WHY_SENTINEL);                      \
    } while (0)

/* The same idea for the two producers that spell "never measured" as 0 rather
 * than as -1: mem_pressure's last_poll_unix is 0 until its first poll, and
 * hw_profile's ram_bytes is 0 when the probe fails or has not run. Passing
 * those through would publish 1970-01-01 as a poll time and 0 bytes as a
 * machine's RAM — two plausible-looking numbers for "we do not know", which is
 * exactly what presence UNAVAILABLE exists to say instead. Verified against
 * platform/modules/util/src/mem_pressure.c (g_last_poll_unix starts 0; current/denominator/
 * rss all start -1) and platform/modules/util/src/hw_profile.c (probe_ram_bytes returns 0
 * on failure, and g_state is zero-initialized before init). */
#define RT_PASS_POSITIVE(m_, obj_, key_)                                      \
    do {                                                                      \
        int64_t v_ = 0;                                                       \
        bool ok_ = (obj_) && rt_int((obj_), (key_), &v_) && v_ > 0;           \
        RT_I64(m_, ok_, v_, TELEMETRY_SRC_CACHED_PUBLICATION,                 \
               !(obj_) ? RT_WHY_DUMP : RT_WHY_SENTINEL);                      \
    } while (0)

static void rt_fill_services(struct runtime_snapshot *s,
                             const struct json_value *sup)
{
    RT_PASS_I64(child_count, sup, "child_count");
    RT_PASS_I64(child_headroom, sup, "child_headroom");
    RT_PASS_I64(progress_undeclared_count, sup, "progress_undeclared_count");

    struct rt_children agg;
    if (sup)
        rt_collect_children(sup, &agg);
    else
        memset(&agg, 0, sizeof agg);

    /* With the dump in hand, "zero children" is a real answer, not a failed
     * read: the aggregates below are genuinely 0 and are reported as present.
     * Without the dump every one of them is unavailable. */
    const bool have = sup != NULL;
    const enum telemetry_source src = TELEMETRY_SRC_DERIVED;
    RT_I64(children_stalled, have, agg.stalled, src, RT_WHY_DUMP);
    RT_I64(children_no_results, have, agg.no_results, src, RT_WHY_DUMP);
    RT_I64(ticks_run_total, have, agg.ticks_run, src, RT_WHY_DUMP);
    RT_I64(idle_ticks_total, have, agg.idle_ticks, src, RT_WHY_DUMP);
    RT_I64(stall_fires_total, have, agg.stall_fires, src, RT_WHY_DUMP);

    /* The worst age and the name that owns it travel together or not at all —
     * a duration with no owner sends a reader to the wrong subsystem. */
    RT_I64(worst_tick_age_us, have && agg.any, agg.worst_age_us, src,
           have ? RT_WHY_NO_CHILD : RT_WHY_DUMP);
    RT_TEXT(worst_tick_child, have && agg.any, agg.worst_name, src,
            have ? RT_WHY_NO_CHILD : RT_WHY_DUMP);
}

static void rt_fill_threads(struct runtime_snapshot *s,
                            const struct json_value *sup,
                            const struct json_value *topo)
{
    RT_PASS_BOOL(supervisor_running, sup, "running");
    RT_PASS_I64(sweep_last_age_us, sup, "sweep_last_age_us");
    RT_PASS_BOOL(tick_runner_running, sup, "tick_runner_running");
    RT_PASS_I64(tick_runner_last_hb_age_us, sup, "tick_runner_last_hb_age_us");
    RT_PASS_I64(tick_runner_stall_fires, sup, "tick_runner_stall_fires");
    RT_PASS_I64(logical_cpus, topo, "logical_cpus");
    RT_PASS_TEXT(topology_source, topo, "source");
}

static void rt_fill_resources(struct runtime_snapshot *s,
                              const struct json_value *mem,
                              const struct json_value *hw)
{
    RT_PASS_TEXT(mem_level, mem, "level");
    RT_PASS_SENTINEL(mem_current_bytes, mem, "current_bytes");
    RT_PASS_SENTINEL(mem_denominator_bytes, mem, "denominator_bytes");
    RT_PASS_TEXT(mem_denominator_basis, mem, "denominator_basis");
    RT_PASS_SENTINEL(rss_bytes, mem, "rss_bytes");
    RT_PASS_BOOL(mem_polling_active, mem, "polling_active");
    RT_PASS_POSITIVE(mem_last_poll_unix, mem, "last_poll_unix");
    RT_PASS_POSITIVE(ram_bytes, hw, "ram_bytes");
}

/* ── the provider ────────────────────────────────────────────────────── */

bool runtime_dump_state_fill(struct runtime_snapshot *s, const char **why)
{
    if (why)
        *why = "";
    if (!s) {
        if (why)
            *why = RT_WHY_NULL;
        LOG_FAIL("runtime_telemetry", "fill: snapshot is NULL");
    }

    TELEMETRY_SET_I64(s, collected_unix, telemetry_now_unix(),
                      TELEMETRY_SRC_IN_PROCESS);

    bool reached = true;
    struct rt_dump sup = {0}, topo = {0}, mem = {0}, hw = {0};
    bool have_sup  = rt_fetch("supervisor", &sup, &reached);
    bool have_topo = rt_fetch("cpu_topology", &topo, &reached);
    bool have_mem  = rt_fetch("mem_pressure", &mem, &reached);
    bool have_hw   = rt_fetch("hw_profile", &hw, &reached);

    /* Nothing at all came back: that is a dead transport, not a node whose
     * every subsystem simultaneously lost its dumper. Say so once, loudly,
     * instead of returning twenty-six unavailable leaves. */
    if (!reached && !have_sup && !have_topo && !have_mem && !have_hw) {
        rt_dump_free(&sup);
        rt_dump_free(&topo);
        rt_dump_free(&mem);
        rt_dump_free(&hw);
        if (why)
            *why = RT_WHY_NODE;
        LOG_FAIL("runtime_telemetry", "no dumpstate subsystem answered");
    }

    rt_fill_services(s, have_sup ? sup.state : NULL);
    rt_fill_threads(s, have_sup ? sup.state : NULL,
                    have_topo ? topo.state : NULL);
    rt_fill_resources(s, have_mem ? mem.state : NULL,
                      have_hw ? hw.state : NULL);

    rt_dump_free(&sup);
    rt_dump_free(&topo);
    rt_dump_free(&mem);
    rt_dump_free(&hw);
    return true;
}
