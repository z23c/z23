/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Tier-1 hot-swap — the REAL (activatable) MULTI-LEAF module loader.
 *
 * See hotswap/hotswap_module.h for the ABI. The pure surface (swappable
 * allowlist, probe map, activation flag, the activation GATE, admission, and
 * telemetry) compiles in every build; only the dlopen/dlsym/dlclose activation
 * core is DEV-ONLY. A release build links the refusal stub at the bottom.
 *
 * Publish order is fixed and all-or-nothing:
 *   dlopen -> dlsym -> admit EVERY leaf -> probe the file's DECLARED probe leaf
 *   against the registry's public contract -> ONE batch replace.
 * Any failure before the batch replace publishes ZERO leaves and leaves every
 * resident handler untouched.
 *
 * Safety of the dlclose-after-drain reclamation: the superseded module .so is
 * closed ONLY after the resident quiesced callback confirms every retired
 * command registry override snapshot has drained (no in-flight dispatch can
 * still enter an old handler). If drain cannot be confirmed within a bounded
 * window the old .so is KEPT mapped forever — the pilot's never-close behavior,
 * always memory-safe. dlclose is thus best-effort reclamation, never a
 * correctness dependency.
 */

#define _GNU_SOURCE
#include "hotswap/hotswap_module.h"
#include "hotswap/hotfork_capsule.h"
#include "hotswap/hotswap.h"
#include "hotswap/hotswap_retire_blocker.h"

#include "json/json.h"
#include "platform/time_compat.h"
#include "util/log_macros.h"

#include <limits.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* ── swappable allowlist, compiled from config/hotswap_swappable.def ───────
 * ONE row per source TU; `leaves` is the space-separated set of canonical
 * leaf paths that TU's module may re-point. */
static const struct {
    const char *source;
    const char *leaves;
} g_swappable[] = {
#define HOTSWAP_SWAPPABLE(source_, leaves_) { .source = source_, .leaves = leaves_ },
#include "../../../config/hotswap_swappable.def"
#undef HOTSWAP_SWAPPABLE
};

/* ── probe map, compiled from config/hotswap_eligible.def ─────────────────
 * The declared param-free probe leaf per eligible TU. A module never chooses
 * its own probe: the loader looks it up here by source_tu. */
static const struct {
    const char *source;
    const char *probe;
} g_probes[] = {
#define HOTSWAP_ELIGIBLE(path_) { .source = path_,
#define HOTSWAP_PROBE(tool_) .probe = tool_ },
#include "../../../config/hotswap_eligible.def"
#undef HOTSWAP_ELIGIBLE
#undef HOTSWAP_PROBE
};

static const struct zcl_hotswap_probe_case g_probe_cases[] = {
#define HOTSWAP_PROBE_CASE(case_id_, kind_, operation_, input_, schema_, budget_) \
    { (case_id_), (kind_), (operation_), (input_), (schema_), (budget_) },
#include "../../../config/hotswap_probe_cases.def"
#undef HOTSWAP_PROBE_CASE
};

#define SWAPPABLE_COUNT (sizeof(g_swappable) / sizeof(g_swappable[0]))
#define PROBE_COUNT (sizeof(g_probes) / sizeof(g_probes[0]))

/* Space/tab-separated membership test over a `leaves` column. No allocation. */
static bool leaf_list_contains(const char *list, const char *leaf)
{
    if (!list || !leaf || !leaf[0])
        return false;
    size_t want = strlen(leaf);
    const char *p = list;
    while (*p) {
        while (*p == ' ' || *p == '\t')
            p++;
        const char *start = p;
        while (*p && *p != ' ' && *p != '\t')
            p++;
        size_t len = (size_t)(p - start);
        if (len == want && strncmp(start, leaf, want) == 0)
            return true;
    }
    return false;
}

const char *hotswap_swappable_source_for_leaf(const char *leaf)
{
    if (!leaf || !leaf[0])
        return NULL;
    for (size_t i = 0; i < SWAPPABLE_COUNT; i++) {
        if (leaf_list_contains(g_swappable[i].leaves, leaf))
            return g_swappable[i].source;
    }
    return NULL;
}

bool hotswap_handler_is_swappable(const char *leaf)
{
    return hotswap_swappable_source_for_leaf(leaf) != NULL;
}

static const char *swappable_leaves_for_source(const char *source_tu)
{
    if (!source_tu || !source_tu[0])
        return NULL;
    for (size_t i = 0; i < SWAPPABLE_COUNT; i++) {
        if (strcmp(source_tu, g_swappable[i].source) == 0)
            return g_swappable[i].leaves;
    }
    return NULL;
}

const struct zcl_hotswap_probe_case *hotswap_probe_case_for_operation(
    const char *operation)
{
    if (!operation || !operation[0])
        return NULL;
    for (size_t i = 0; i < sizeof(g_probe_cases) /
                            sizeof(g_probe_cases[0]); i++)
        if (strcmp(operation, g_probe_cases[i].operation) == 0)
            return &g_probe_cases[i];
    return NULL;
}

const struct zcl_hotswap_probe_case *hotswap_module_probe_case(
    const char *source_tu)
{
    if (!source_tu || !source_tu[0])
        return NULL;
    for (size_t i = 0; i < PROBE_COUNT; i++) {
        if (strcmp(source_tu, g_probes[i].source) == 0)
            return hotswap_probe_case_for_operation(g_probes[i].probe);
    }
    return NULL;
}

const char *hotswap_module_probe_leaf(const char *source_tu)
{
    const struct zcl_hotswap_probe_case *probe =
        hotswap_module_probe_case(source_tu);
    return probe ? probe->operation : NULL;
}

static void act_copy(char *dst, size_t cap, const char *src)
{
    if (!dst || cap == 0)
        return;
    snprintf(dst, cap, "%s", src ? src : "");
}

bool hotswap_module_admit(const struct zcl_hotswap_module *module,
                          char *stage, size_t stage_cap,
                          char *why, size_t why_cap)
{
    if (stage && stage_cap) stage[0] = '\0';
    if (why && why_cap) why[0] = '\0';
    if (!module) {
        act_copy(stage, stage_cap, "abi");
        act_copy(why, why_cap, "null module");
        return false;
    }
    if (module->abi_version != ZCL_HOTSWAP_MODULE_ABI_V2) {
        act_copy(stage, stage_cap, "abi");
        if (why && why_cap)
            snprintf(why, why_cap,
                     "module abi_version %u != required %u (rebuild the module "
                     "against the current hotswap_module.h)",
                     module->abi_version, ZCL_HOTSWAP_MODULE_ABI_V2);
        return false;
    }
    if (!module->source_tu || !module->source_tu[0] || !module->leaves ||
        !module->self_test || module->leaf_count == 0) {
        act_copy(stage, stage_cap, "fields");
        act_copy(why, why_cap,
                 "module fields incomplete (source_tu/leaves/leaf_count/self_test)");
        return false;
    }
    if (module->leaf_count > ZCL_HOTSWAP_MODULE_MAX_LEAVES) {
        act_copy(stage, stage_cap, "capacity");
        if (why && why_cap)
            snprintf(why, why_cap,
                     "module declares %u leaves, ceiling is %u (one batch "
                     "replace must carry them all)",
                     module->leaf_count, ZCL_HOTSWAP_MODULE_MAX_LEAVES);
        return false;
    }
    for (uint32_t i = 0; i < module->leaf_count; i++) {
        if (!module->leaves[i].name || !module->leaves[i].name[0] ||
            !module->leaves[i].fn) {
            act_copy(stage, stage_cap, "fields");
            if (why && why_cap)
                snprintf(why, why_cap,
                         "leaf %u has an empty name or NULL handler", i);
            return false;
        }
    }

    const char *allowed = swappable_leaves_for_source(module->source_tu);
    if (!allowed) {
        act_copy(stage, stage_cap, "allowlist");
        if (why && why_cap)
            snprintf(why, why_cap,
                     "source '%s' is not on the swappable shape-leaf allowlist",
                     module->source_tu);
        return false;
    }

    for (uint32_t i = 0; i < module->leaf_count; i++) {
        const char *leaf = module->leaves[i].name;
        if (!leaf_list_contains(allowed, leaf)) {
            act_copy(stage, stage_cap, "allowlist");
            if (why && why_cap)
                snprintf(why, why_cap,
                         "leaf '%s' is not on the swappable allowlist for '%s'",
                         leaf, module->source_tu);
            return false;
        }
        for (uint32_t j = 0; j < i; j++) {
            if (strcmp(leaf, module->leaves[j].name) == 0) {
                act_copy(stage, stage_cap, "duplicate");
                if (why && why_cap)
                    snprintf(why, why_cap,
                             "leaf '%s' is declared twice in one module", leaf);
                return false;
            }
        }
    }

    /* The declared probe leaf must exist for this file AND be one of the
     * leaves this module actually re-points; otherwise probe-before-publish
     * would validate code the module never installs. */
    const char *probe = hotswap_module_probe_leaf(module->source_tu);
    if (!probe || !probe[0]) {
        act_copy(stage, stage_cap, "probe");
        if (why && why_cap)
            snprintf(why, why_cap,
                     "source '%s' declares no probe leaf in "
                     "config/hotswap_eligible.def", module->source_tu);
        return false;
    }
    bool probe_exported = false;
    for (uint32_t i = 0; i < module->leaf_count && !probe_exported; i++)
        probe_exported = strcmp(module->leaves[i].name, probe) == 0;
    if (!probe_exported) {
        act_copy(stage, stage_cap, "probe");
        if (why && why_cap)
            snprintf(why, why_cap,
                     "module does not export its declared probe leaf '%s'",
                     probe);
        return false;
    }

    char st_err[192] = {0};
    if (!module->self_test(st_err, sizeof(st_err))) {
        act_copy(stage, stage_cap, "self_test");
        act_copy(why, why_cap,
                 st_err[0] ? st_err : "module self_test returned false");
        return false;
    }
    return true;
}

/* ── activation flag + gate (pure; compiled in every build) ─────────────── */
static _Atomic bool g_activate_flag = false;

void hotswap_set_activate_flag(bool enabled)
{
    atomic_store_explicit(&g_activate_flag, enabled, memory_order_release);
}

bool hotswap_activate_flag(void)
{
    return atomic_load_explicit(&g_activate_flag, memory_order_acquire);
}

static bool env_opt_in(void)
{
    const char *v = getenv("ZCL_HOTSWAP_ACTIVATE");
    return v && strcmp(v, "1") == 0;
}

static bool dir_equals(const char *a, const char *b)
{
    if (!a || !a[0] || !b || !b[0])
        return false;
    char ra[PATH_MAX], rb[PATH_MAX];
    const char *pa = realpath(a, ra) ? ra : a;
    const char *pb = realpath(b, rb) ? rb : b;
    size_t la = strlen(pa), lb = strlen(pb);
    if (la && pa[la - 1] == '/') la--;
    if (lb && pb[lb - 1] == '/') lb--;
    return la == lb && strncmp(pa, pb, la) == 0;
}

static bool datadir_is_canonical(const char *datadir)
{
    if (!datadir || !datadir[0])
        return false;
    const char *home = getenv("HOME");
    if (!home || home[0] != '/')
        return false;
    char canonical[PATH_MAX];
    snprintf(canonical, sizeof(canonical), "%s/.zclassic-c23", home);
    return dir_equals(datadir, canonical);
}

bool hotswap_activation_authorized(const char *resolved_datadir,
                                   char *why, size_t why_sz)
{
    if (why && why_sz)
        why[0] = '\0';
    if (!hotswap_activate_flag()) {
        if (why) snprintf(why, why_sz,
            "activation refused: -hotswap-activate flag is not set");
        return false;
    }
    if (!env_opt_in()) {
        if (why) snprintf(why, why_sz,
            "activation refused: ZCL_HOTSWAP_ACTIVATE=1 is not set");
        return false;
    }
    if (datadir_is_canonical(resolved_datadir)) {
        if (why) snprintf(why, why_sz,
            "activation refused on the canonical datadir ~/.zclassic-c23 "
            "(canonical activation stays behind the owner's Phase-3 ritual)");
        return false;
    }
    if (!hotswap_datadir_is_dev(resolved_datadir)) {
        if (why) snprintf(why, why_sz,
            "activation requires the exact dev datadir ~/.zclassic-c23-dev, got '%s'",
            resolved_datadir ? resolved_datadir : "");
        return false;
    }
    return true;
}

/* ── activation telemetry state (written only on the dev activate path) ──── */
#define HOTSWAP_ACT_MAX_SLOTS 32

struct hotswap_act_slot {
    char source[256];        /* one slot per swappable source TU */
    void *handle;            /* currently-live module .so for this source */
    int artifact_fd;
    char artifact_sha256[65];
    uint32_t generation;
    uint32_t leaf_count;
    time_t activated_at;
    uint64_t swaps;
    bool in_use;
};

struct hotswap_act_event {
    bool present;
    time_t at;
    char source[256];
    char leaves[512];
    uint32_t leaf_count;
    char stage[64];
    char error[256];
    bool activated;
    bool ok;
};

static pthread_mutex_t g_act_lock = PTHREAD_MUTEX_INITIALIZER;
static struct hotswap_act_slot g_slots[HOTSWAP_ACT_MAX_SLOTS];
static size_t g_slot_count;
static struct hotswap_act_event g_last_activation;
static struct hotswap_act_event g_last_rejection;
static _Atomic uint64_t g_activation_count;
static _Atomic uint64_t g_rollback_count;
static _Atomic uint64_t g_verify_count;
static _Atomic uint64_t g_probe_reject_count;
static _Atomic uint64_t g_leaves_published;
static _Atomic uint64_t g_dlclose_count;
static _Atomic uint64_t g_retained_mapped_count;

static void event_json(struct json_value *obj, const struct hotswap_act_event *ev)
{
    json_set_object(obj);
    json_push_kv_bool(obj, "present", ev->present);
    if (!ev->present)
        return;
    json_push_kv_int(obj, "at", (int64_t)ev->at);
    json_push_kv_str(obj, "source", ev->source);
    json_push_kv_str(obj, "leaves", ev->leaves);
    json_push_kv_int(obj, "leaf_count", (int64_t)ev->leaf_count);
    json_push_kv_str(obj, "stage", ev->stage);
    if (ev->error[0])
        json_push_kv_str(obj, "error", ev->error);
    json_push_kv_bool(obj, "activated", ev->activated);
    json_push_kv_bool(obj, "ok", ev->ok);
}

void hotswap_activate_dump_json(struct json_value *out)
{
    if (!out)
        return;
    struct json_value act = {0};
    json_set_object(&act);
    json_push_kv_str(&act, "abi", "zcl.hotswap_module.v2");
    json_push_kv_int(&act, "abi_version", (int64_t)ZCL_HOTSWAP_MODULE_ABI_V2);
    json_push_kv_int(&act, "max_leaves_per_module",
                     (int64_t)ZCL_HOTSWAP_MODULE_MAX_LEAVES);
#ifdef ZCL_DEV_BUILD
    json_push_kv_bool(&act, "available", true);
#else
    json_push_kv_bool(&act, "available", false);
    json_push_kv_str(&act, "note", "activation unavailable in release build");
#endif
    bool flag = hotswap_activate_flag();
    bool env = env_opt_in();
    json_push_kv_bool(&act, "activate_flag", flag);
    json_push_kv_bool(&act, "env_opt_in", env);
    /* Containment state: only "armed" once BOTH gates are on; the datadir/
     * canonical check is still applied per-activation. */
    json_push_kv_str(&act, "containment",
                     (flag && env) ? "armed_dev_lane_only" : "verify_only");
    json_push_kv_int(&act, "activation_count",
                     (int64_t)atomic_load(&g_activation_count));
    json_push_kv_int(&act, "verify_only_count",
                     (int64_t)atomic_load(&g_verify_count));
    json_push_kv_int(&act, "rollback_count",
                     (int64_t)atomic_load(&g_rollback_count));
    json_push_kv_int(&act, "probe_reject_count",
                     (int64_t)atomic_load(&g_probe_reject_count));
    json_push_kv_int(&act, "leaves_published",
                     (int64_t)atomic_load(&g_leaves_published));
    json_push_kv_int(&act, "dlclose_count",
                     (int64_t)atomic_load(&g_dlclose_count));
    json_push_kv_int(&act, "retained_mapped_count",
                     (int64_t)atomic_load(&g_retained_mapped_count));

    struct json_value allow = {0};
    json_set_array(&allow);
    for (size_t i = 0; i < SWAPPABLE_COUNT; i++) {
        struct json_value row = {0};
        json_set_object(&row);
        json_push_kv_str(&row, "source", g_swappable[i].source);
        json_push_kv_str(&row, "leaves", g_swappable[i].leaves);
        const char *probe = hotswap_module_probe_leaf(g_swappable[i].source);
        json_push_kv_str(&row, "probe_leaf", probe ? probe : "");
        json_push_back(&allow, &row);
        json_free(&row);
    }
    json_push_kv(&act, "swappable_allowlist", &allow);
    json_free(&allow);

    pthread_mutex_lock(&g_act_lock);
    struct json_value slots = {0};
    json_set_array(&slots);
    for (size_t i = 0; i < g_slot_count; i++) {
        if (!g_slots[i].in_use)
            continue;
        struct json_value s = {0};
        json_set_object(&s);
        json_push_kv_str(&s, "source", g_slots[i].source);
        json_push_kv_int(&s, "generation", (int64_t)g_slots[i].generation);
        json_push_kv_int(&s, "leaf_count", (int64_t)g_slots[i].leaf_count);
        json_push_kv_str(&s, "artifact_sha256", g_slots[i].artifact_sha256);
        json_push_kv_int(&s, "activated_at", (int64_t)g_slots[i].activated_at);
        json_push_kv_int(&s, "swaps", (int64_t)g_slots[i].swaps);
        json_push_back(&slots, &s);
        json_free(&s);
    }
    json_push_kv(&act, "active_slots", &slots);
    json_free(&slots);

    struct json_value last_a = {0}, last_r = {0};
    event_json(&last_a, &g_last_activation);
    event_json(&last_r, &g_last_rejection);
    pthread_mutex_unlock(&g_act_lock);
    json_push_kv(&act, "last_activation", &last_a);
    json_push_kv(&act, "last_rejection", &last_r);
    json_free(&last_a);
    json_free(&last_r);

    json_push_kv(out, "activation", &act);
    json_free(&act);
}

static void record_event(struct hotswap_act_event *ev,
                         const struct hotswap_activate_report *report,
                         const char *stage, const char *error,
                         bool activated, bool ok)
{
    pthread_mutex_lock(&g_act_lock);
    memset(ev, 0, sizeof(*ev));
    ev->present = true;
    ev->at = platform_time_wall_time_t();
    act_copy(ev->source, sizeof(ev->source), report->source_tu);
    act_copy(ev->leaves, sizeof(ev->leaves), report->leaves);
    ev->leaf_count = report->leaf_count;
    act_copy(ev->stage, sizeof(ev->stage), stage);
    act_copy(ev->error, sizeof(ev->error), error);
    ev->activated = activated;
    ev->ok = ok;
    pthread_mutex_unlock(&g_act_lock);
}

/* Populate the report, log, record the rejection, count it, and return false.
 * Any dlopen/fd cleanup is the caller's, done BEFORE calling this. */
static bool act_reject(struct hotswap_activate_report *report,
                       const char *stage, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    (void)vsnprintf(report->error, sizeof(report->error), fmt, ap);
    va_end(ap);
    act_copy(report->stage, sizeof(report->stage), stage);
    report->ok = false;
    report->rolled_back = true;
    atomic_fetch_add_explicit(&g_rollback_count, 1, memory_order_relaxed);
    record_event(&g_last_rejection, report, stage, report->error, false, false);
    LOG_WARN("hotswap.activate", "reject stage=%s: %s", stage, report->error);
    return false;
}

/* Fill report->leaves / leaf_count / handler_name from an admitted module. */
static void report_describe_leaves(struct hotswap_activate_report *report,
                                   const struct zcl_hotswap_module *mod)
{
    report->leaf_count = mod->leaf_count;
    act_copy(report->handler_name, sizeof(report->handler_name),
             mod->leaves[0].name);
    size_t used = 0;
    report->leaves[0] = '\0';
    for (uint32_t i = 0; i < mod->leaf_count; i++) {
        int n = snprintf(report->leaves + used, sizeof(report->leaves) - used,
                         "%s%s", i ? "," : "", mod->leaves[i].name);
        if (n < 0 || (size_t)n >= sizeof(report->leaves) - used)
            break;              /* clipped; report->leaf_count stays exact */
        used += (size_t)n;
    }
}

bool hotswap_module_publish(const struct zcl_hotswap_module *module,
                            bool request_activate,
                            const struct hotswap_publish_hooks *hooks,
                            struct hotswap_activate_report *report)
{
    if (!report)
        return false;
    report->ok = false;
    report->activated = false;
    report->probed = false;
    report->verify_only = !request_activate;
    if (module && module->abi_version == ZCL_HOTSWAP_MODULE_ABI_V2 &&
        module->source_tu)
        act_copy(report->source_tu, sizeof(report->source_tu),
                 module->source_tu);

    hotswap_commit_batch_cb commit_cb = hooks ? hooks->commit : NULL;
    hotswap_probe_leaf_cb probe_cb = hooks ? hooks->probe : NULL;
    void *cb_ctx = hooks ? hooks->ctx : NULL;

    /* ABI version + required fields + leaf ceiling + the swappable file/leaf
     * allowlist + intra-module leaf uniqueness + the declared probe leaf +
     * module self_test, all in one pure gauntlet. Any failure => refuse
     * LOUDLY, ZERO leaves published, every resident handler untouched. */
    char stage[64] = {0}, why[256] = {0};
    if (!hotswap_module_admit(module, stage, sizeof(stage), why, sizeof(why)))
        return act_reject(report, stage[0] ? stage : "abi", "%s", why);
    report_describe_leaves(report, module);

    const char *probe_leaf = hotswap_module_probe_leaf(module->source_tu);
    act_copy(report->probe_leaf, sizeof(report->probe_leaf), probe_leaf);
    zcl_hotswap_handler_fn probe_fn = NULL;
    for (uint32_t i = 0; i < module->leaf_count && !probe_fn; i++) {
        if (strcmp(module->leaves[i].name, probe_leaf) == 0)
            probe_fn = module->leaves[i].fn;
    }

    /* PROBE BEFORE PUBLISH. A module asserting its own health is
     * self-certification; this dispatches the DECLARED probe leaf against the
     * registry's public spec/input-validation/reply contract and checks the
     * reply against that leaf's declared output schema. Publishing without it
     * is refused outright. */
    if (probe_cb) {
        why[0] = '\0';
        if (!probe_cb(cb_ctx, probe_leaf, probe_fn, why, sizeof(why))) {
            atomic_fetch_add_explicit(&g_probe_reject_count, 1,
                                      memory_order_relaxed);
            return act_reject(report, "probe", "probe leaf '%s' failed: %s",
                              probe_leaf,
                              why[0] ? why
                                     : "reply did not match its declared schema");
        }
        report->probed = true;
    } else if (request_activate) {
        return act_reject(report, "probe",
                          "no probe callback supplied; publishing without a "
                          "probe-before-publish check is refused");
    }

    if (!request_activate) {
        report->ok = true;
        report->verify_only = true;
        act_copy(report->stage, sizeof(report->stage), "verified");
        atomic_fetch_add_explicit(&g_verify_count, 1, memory_order_relaxed);
        record_event(&g_last_activation, report, "verified", "", false, true);
        LOG_INFO("hotswap.activate",
                 "verify-only OK source=%s leaves=%u (not activated)",
                 report->source_tu, report->leaf_count);
        return true;
    }

    if (!commit_cb)
        return act_reject(report, "commit",
                          "no registry commit callback supplied");
    uint32_t gen = 0;
    why[0] = '\0';
    if (!commit_cb(cb_ctx, module->leaves, (size_t)module->leaf_count, &gen,
                   why, sizeof(why))) {
        /* Rollback: the registry never published, old handlers untouched. */
        return act_reject(report, "commit", "%s",
                          why[0] ? why : "registry commit failed");
    }

    report->ok = true;
    report->activated = true;
    report->verify_only = false;
    report->generation = gen;
    act_copy(report->stage, sizeof(report->stage), "activated");
    atomic_fetch_add_explicit(&g_activation_count, 1, memory_order_relaxed);
    atomic_fetch_add_explicit(&g_leaves_published, module->leaf_count,
                              memory_order_relaxed);
    record_event(&g_last_activation, report, "activated", "", true, true);
    LOG_INFO("hotswap.activate",
             "activated source=%s leaves=%u (%s) gen=%u",
             report->source_tu, report->leaf_count, report->leaves, gen);
    return true;
}

#ifdef ZCL_DEV_BUILD

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <sys/stat.h>
#include <unistd.h>

#include "crypto/sha256.h"
#include "hotswap/hotswap_artifact_digest.h"
#include "hotswap/hotswap_elf_probe.h"
#include "hotswap/hotswap_sealed_image.h"

static bool artifact_sha256_fd(int fd, char hex_out[65])
{
    if (fd < 0 || !hex_out || lseek(fd, 0, SEEK_SET) < 0)
        return false;
    hex_out[0] = '\0';
    struct sha256_ctx ctx;
    sha256_init(&ctx);
    unsigned char buf[64 * 1024];
    for (;;) {
        ssize_t n = read(fd, buf, sizeof(buf));
        if (n > 0) { sha256_write(&ctx, buf, (size_t)n); continue; }
        if (n == 0) break;
        if (errno == EINTR) continue;
        return false;
    }
    if (lseek(fd, 0, SEEK_SET) < 0)
        return false;
    unsigned char digest[SHA256_OUTPUT_SIZE];
    sha256_finalize(&ctx, digest);
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < SHA256_OUTPUT_SIZE; i++) {
        hex_out[i * 2] = hex[digest[i] >> 4];
        hex_out[i * 2 + 1] = hex[digest[i] & 0x0f];
    }
    hex_out[64] = '\0';
    return true;
}

bool zcl_hotswap_hotfork_visit_so(
    const char *so_path, const char *expected_sha256,
    zcl_hotfork_capsule_visit_fn visit, void *ctx,
    char actual_sha256[65])
{
    if (!so_path || !expected_sha256 || strlen(expected_sha256) != 64 ||
        !visit || !actual_sha256)
        return false;
    actual_sha256[0] = '\0';
    int fd = open(so_path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    struct stat st;
    if (fd < 0 || fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) ||
        !artifact_sha256_fd(fd, actual_sha256) ||
        strcmp(actual_sha256, expected_sha256) != 0) {
        if (fd >= 0) (void)close(fd);
        return false;
    }
    char pinned[64];
    (void)snprintf(pinned, sizeof(pinned), "/proc/self/fd/%d", fd);
    void *handle = dlopen(pinned, RTLD_LAZY | RTLD_LOCAL);
    if (!handle) {
        (void)close(fd);
        return false;
    }
    dlerror();
    const struct zcl_hotfork_capsule_v1 *capsule =
        dlsym(handle, ZCL_HOTFORK_CAPSULE_SYMBOL);
    const char *sym_error = dlerror();
    bool ok = !sym_error && capsule && visit(capsule, ctx);
    (void)dlclose(handle);
    (void)close(fd);
    return ok;
}

/* Find (or, if activating a not-yet-seen source, add) the per-source slot.
 * ASSUMES g_act_lock held. Returns NULL only when the fixed table is full. */
static struct hotswap_act_slot *slot_for_source_locked(const char *source)
{
    for (size_t i = 0; i < g_slot_count; i++) {
        if (g_slots[i].in_use && strcmp(g_slots[i].source, source) == 0)
            return &g_slots[i];
    }
    if (g_slot_count >= HOTSWAP_ACT_MAX_SLOTS)
        return NULL;
    struct hotswap_act_slot *slot = &g_slots[g_slot_count++];
    memset(slot, 0, sizeof(*slot));
    slot->artifact_fd = -1;
    act_copy(slot->source, sizeof(slot->source), source);
    slot->in_use = true;
    return slot;
}

/* Pending-retire table: mappings kept because drain was unconfirmed. This
 * exists so the retention is RECLAIMABLE (the escape retries it) instead of
 * being an unbounded silent leak. Bounded: past the cap we still never
 * dlclose an undrained handle — we just stop tracking it for retry, and the
 * blocker (raised below) keeps saying so. */
#define HOTSWAP_PENDING_RETIRE_MAX 32
struct pending_retire {
    void *handle;
    int fd;
    hotswap_quiesced_cb quiesced_cb;
    void *ctx;
};
static struct pending_retire g_pending[HOTSWAP_PENDING_RETIRE_MAX];
static size_t g_pending_count;  /* guarded by g_act_lock */

/* Reclaim seam invoked from the blocker escape (outside the registry lock).
 * Returns true only when NOTHING is left retained — the escape refuses to
 * clear the blocker on a partial reclaim. */
static bool hotswap_reclaim_pending(void *unused)
{
    (void)unused;
    pthread_mutex_lock(&g_act_lock);
    size_t kept = 0;
    for (size_t i = 0; i < g_pending_count; i++) {
        struct pending_retire p = g_pending[i];
        bool drained = p.quiesced_cb ? p.quiesced_cb(p.ctx) : false;
        if (drained) {
            dlclose(p.handle);
            if (p.fd >= 0) close(p.fd);
            atomic_fetch_add_explicit(&g_dlclose_count, 1,
                                      memory_order_relaxed);
            atomic_fetch_sub_explicit(&g_retained_mapped_count, 1,
                                      memory_order_relaxed);
            hotswap_retire_blocker_note_reclaimed();
            continue;
        }
        g_pending[kept++] = p;
    }
    g_pending_count = kept;
    bool all_clear = (kept == 0);
    pthread_mutex_unlock(&g_act_lock);
    return all_clear;
}

/* Drain then dlclose a superseded module .so. Bounded wait; on doubt, keep it
 * mapped (always memory-safe) — but NAMED, and queued for a reclaim retry.
 * The old behaviour kept it mapped forever behind one LOG_WARN, which at a
 * high swap rate is a mapping + fd leaked per swap with no operator signal. */
static void retire_handle(void *handle, int fd,
                          hotswap_quiesced_cb quiesced_cb, void *ctx)
{
    if (!handle)
        return;
    bool drained = false;
    if (quiesced_cb) {
        /* ~2 s worst case: cheap sched_yield spin, escalating to a 1 ms sleep. */
        for (int i = 0; i < 20000; i++) {
            if (quiesced_cb(ctx)) { drained = true; break; }
            if (i % 1000 == 999) {
                struct timespec ts = { .tv_sec = 0, .tv_nsec = 1000000 };
                nanosleep(&ts, NULL);
            } else {
                sched_yield();
            }
        }
    }
    if (drained) {
        dlclose(handle);
        if (fd >= 0) close(fd);
        atomic_fetch_add_explicit(&g_dlclose_count, 1, memory_order_relaxed);
        LOG_INFO("hotswap.activate",
                 "retired superseded module .so after drain (dlclosed)");
        return;
    }

    atomic_fetch_add_explicit(&g_retained_mapped_count, 1,
                              memory_order_relaxed);
    hotswap_retire_blocker_set_reclaimer(hotswap_reclaim_pending, NULL);
    pthread_mutex_lock(&g_act_lock);
    bool queued = false;
    if (g_pending_count < HOTSWAP_PENDING_RETIRE_MAX) {
        g_pending[g_pending_count++] = (struct pending_retire){
            .handle = handle, .fd = fd, .quiesced_cb = quiesced_cb,
            .ctx = ctx,
        };
        queued = true;
    }
    pthread_mutex_unlock(&g_act_lock);
    /* Raise unconditionally, queued or not: an untracked retention is a
     * WORSE fault than a tracked one, so it must not be the quiet case. */
    hotswap_retire_blocker_raise();
    LOG_WARN("hotswap.activate",
             "drain unconfirmed; keeping superseded module .so mapped "
             "(safe leak) — blocker %s raised, reclaim retry %s",
             HOTSWAP_RETIRE_UNDRAINED_BLOCKER_ID,
             queued ? "queued" : "NOT queued (pending table full)");
}

/* ── the consensus pin ─────────────────────────────────────────────────────
 *
 * A module .so is compiled from ONE shape-leaf TU; the resident supplies every
 * other body it calls. The admit gauntlet below checks abi_version, fields,
 * capacity, the allowlist row, duplicates and the probe leaf — six stages, none
 * of which is about the consensus layer the two halves share. Nothing was.
 *
 * That matters because the sealed core ships `static inline` bodies, consensus
 * arithmetic among them (consensus_last_founders_reward_height(),
 * consensus_subsidy_slow_start_shift(), the compact-size sizing in
 * core/serialize.h). A controller that includes one of those headers compiles a
 * PRIVATE COPY into its .so. Re-cut the seal, rebuild the node, and a module
 * built before the change still mounted, still passed all six stages, and still
 * ran its stale copy — a cloned ledger reached through a dlopen.
 *
 * So the artifact carries the ZCL_CORE_SEAL_ROOT its compile saw, and the
 * resident compares it to its own before admitting anything. dlopen may have
 * run ELF constructors already, so this prevents stale leaf publication, not
 * arbitrary module execution. The pin is the
 * SEAL ROOT, deliberately, not a whole-tree build id: editing a controller must
 * not invalidate a module — that is the fast loop — while editing consensus
 * must invalidate every one of them.
 *
 * A missing symbol is a rejection, not a pass. Absence is exactly what an
 * artifact built before the pin existed looks like, and those are the ones
 * whose consensus vintage cannot be established. */
static bool module_consensus_pin_ok(void *handle, char *stage, size_t stage_cap,
                                    char *err, size_t err_cap)
{
    const char *host = ZCL_CORE_SEAL_ROOT;
    if (strlen(host) != 64) {
        act_copy(stage, stage_cap, "consensus");
        (void)snprintf(err, err_cap,
                       "resident has no sealed-core ROOT to pin against "
                       "(run 'make core-seal')");
        return false;
    }
    (void)dlerror();
    const char *mod =
        (const char *)dlsym(handle, ZCL_HOTSWAP_MODULE_CORE_SEAL_ROOT_SYMBOL);
    const char *sym_err = dlerror();
    if (!mod || sym_err) {
        act_copy(stage, stage_cap, "consensus");
        (void)snprintf(err, err_cap,
                       "artifact exports no %s — built before the consensus "
                       "pin existed; rebuild it",
                       ZCL_HOTSWAP_MODULE_CORE_SEAL_ROOT_SYMBOL);
        return false;
    }
    if (strncmp(mod, host, 65) != 0) {
        act_copy(stage, stage_cap, "consensus");
        (void)snprintf(err, err_cap,
                       "sealed-core ROOT mismatch: artifact=%.64s resident=%s "
                       "(the module was compiled against a different consensus "
                       "core; rebuild it)",
                       mod, host);
        return false;
    }
    return true;
}

/* The dlopen half: confinement, authorization, pin+hash, dlopen/dlsym. The
 * admit -> probe -> ONE batch commit half is hotswap_module_publish(), which
 * compiles in every build and is unit-tested directly with fabricated modules
 * (lib/test/src/test_hotswap_module_v2.c). */
static bool activate_run(const char *so_path, const char *resolved_datadir,
                         bool request_activate, bool require_authorization,
                         const struct hotswap_publish_hooks *hooks,
                         struct hotswap_activate_report *report)
{
    if (!report)
        return false;
    memset(report, 0, sizeof(*report));
    report->verify_only = !request_activate;

    char why[256] = {0};
    if (!hotswap_path_is_acceptable(so_path, why, sizeof(why)))
        return act_reject(report, "precheck", "rejected so_path: %s", why);
    if (!hotswap_datadir_is_dev(resolved_datadir))
        return act_reject(report, "precheck",
            "hot-swap requires the exact dev datadir ~/.zclassic-c23-dev, got '%s'",
            resolved_datadir ? resolved_datadir : "");

    if (require_authorization && request_activate &&
        !hotswap_activation_authorized(resolved_datadir, why, sizeof(why)))
        return act_reject(report, "authorize", "%s", why);

    /* ── LOAD ORDER IS THE SECURITY PROPERTY ───────────────────────────────
     * seal -> probe -> hash -> map, and every step after the seal reads the
     * SAME immutable image.
     *
     * Sealing first is what makes the rest meaningful. The previous order
     * (open, hash the fd, dlopen /proc/self/fd/N) is redirect-proof but not
     * tamper-proof: dlopen re-reads the inode, so a writer overwriting that
     * inode in place between the hash and the map makes the node hash bytes A
     * and run bytes B. Measured, not theorised. A sealed memfd cannot change
     * after F_SEAL_WRITE, so "the bytes I checked" and "the bytes I ran" stop
     * being two different questions.
     *
     * Probing before mapping fixes a second ordering defect. Every identity
     * fact used to come from dlsym -- which means the module was already
     * mapped and its ELF constructors had ALREADY RUN before a single
     * admission stage was consulted. We lint our own sources for
     * __attribute__((constructor)), but a packaged artifact built elsewhere
     * never passed our lint. Reading the file's own claims first turns "run
     * it, then check it" into "check it, then run it".
     *
     * What this does NOT buy: DT_INIT (the crt `_init` stub) is present on
     * every clean module and still runs at dlopen, so a determined attacker
     * who controls the artifact can still execute code inside this process.
     * This raises the bar; it is not an isolation boundary. The only complete
     * answer is a process boundary, which is a different design. */
    int src_fd = open(so_path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    struct stat st;
    if (src_fd < 0 || fstat(src_fd, &st) != 0 || !S_ISREG(st.st_mode)) {
        if (src_fd >= 0) close(src_fd);
        return act_reject(report, "dlopen",
                          "could not pin a regular module artifact");
    }

    char seal_err[200];
    int fd = hotswap_sealed_image_from_fd(src_fd, seal_err, sizeof(seal_err));
    close(src_fd);              /* the on-disk inode is no longer load-bearing */
    if (fd < 0)
        return act_reject(report, "seal", "%s", seal_err);

    /* Pre-map shape check, against the sealed image. */
    {
        struct hotswap_elf_facts facts;
        char probe_err[200];
        if (!hotswap_elf_probe_fd(fd, &facts, probe_err, sizeof(probe_err))) {
            close(fd);
            return act_reject(report, "shape", "%s", probe_err);
        }
        /* Baseline is 1, NOT 0: the C runtime's own frame_dummy always
         * occupies one .init_array slot. Comparing against zero would refuse
         * every clean module ever built here. */
        if (facts.init_array_entries >
            ZCL_HOTSWAP_ELF_PROBE_CLEAN_INIT_ARRAY_ENTRIES) {
            close(fd);
            return act_reject(report, "shape",
                "module declares %zu .init_array entries (clean baseline %zu): "
                "it runs its own code at dlopen, before any admission stage",
                facts.init_array_entries,
                ZCL_HOTSWAP_ELF_PROBE_CLEAN_INIT_ARRAY_ENTRIES);
        }
        if (facts.preinit_array_entries > 0) {
            close(fd);
            return act_reject(report, "shape",
                "module declares %zu .preinit_array entries; no toolchain in "
                "this tree emits one", facts.preinit_array_entries);
        }
        /* DT_NEEDED is the LARGEST pre-admission execution vector, larger than
         * this object's own .init_array: ld.so loads every needed library and
         * runs ITS constructors before ours. A module whose own init_array is
         * a clean 1 can still name evil.so here and get arbitrary code run at
         * dlopen. DT_RPATH/DT_RUNPATH is the same hole one level down — it
         * redirects which file a baseline-looking name resolves to.
         *
         * Measured baseline across all 93 artifacts in this tree: exactly one
         * entry, "libc.so.6", and no runpath. The allowlist below is therefore
         * as tight as the evidence allows. If a module ever legitimately needs
         * another library, widen THIS list deliberately — do not relax the
         * check. */
        static const char *const k_allowed_needed[] = {
            "libc.so.6", "libm.so.6",
        };
        if (facts.has_runpath) {
            close(fd);
            return act_reject(report, "shape",
                "module carries DT_RPATH/DT_RUNPATH, which redirects where its "
                "dependencies load from");
        }
        if (facts.needed_truncated) {
            close(fd);
            return act_reject(report, "shape",
                "module declares %zu DT_NEEDED libraries, more than this probe "
                "can enumerate; refusing what cannot be audited",
                facts.needed_count);
        }
        for (size_t i = 0; i < facts.needed_count; i++) {
            bool allowed = false;
            for (size_t k = 0;
                 k < sizeof(k_allowed_needed) / sizeof(k_allowed_needed[0]); k++)
                if (strcmp(facts.needed[i], k_allowed_needed[k]) == 0) {
                    allowed = true;
                    break;
                }
            if (!allowed) {
                close(fd);
                return act_reject(report, "shape",
                    "module depends on '%s'; its constructors would run at "
                    "dlopen before any admission stage",
                    facts.needed[i]);
            }
        }
        /* The pin is re-checked by dlsym after the map. Checking it here too
         * is not redundant: this reads the FILE, that reads what the loader
         * actually bound, and a disagreement between them means the artifact
         * is lying about itself. */
        if (facts.core_seal_root[0] &&
            strncmp(facts.core_seal_root, ZCL_CORE_SEAL_ROOT, 65) != 0) {
            close(fd);
            return act_reject(report, "consensus",
                "module was built against sealed core %.16s..., this node runs "
                "%.16s...", facts.core_seal_root, ZCL_CORE_SEAL_ROOT);
        }
    }

    if (!artifact_sha256_fd(fd, report->artifact_sha256) ||
        !hotswap_artifact_sha3_fd(fd, report->artifact_sha3_256)) {
        close(fd);
        return act_reject(report, "dlopen",
                          "could not hash the sealed module image");
    }
    char pinned[64];
    (void)snprintf(pinned, sizeof(pinned), "/proc/self/fd/%d", fd);
    void *handle = dlopen(pinned, RTLD_NOW | RTLD_LOCAL);
    if (!handle) {
        const char *dl = dlerror();
        char msg[200];
        snprintf(msg, sizeof(msg), "dlopen failed: %s", dl ? dl : "(unknown)");
        close(fd);
        return act_reject(report, "dlopen", "%s", msg);
    }

    dlerror();
    const struct zcl_hotswap_module *mod = dlsym(handle, ZCL_HOTSWAP_MODULE_SYMBOL);
    const char *sym_err = dlerror();
    if (!mod || sym_err) {
        char msg[200];
        snprintf(msg, sizeof(msg), "missing %s symbol: %s",
                 ZCL_HOTSWAP_MODULE_SYMBOL, sym_err ? sym_err : "not found");
        dlclose(handle);
        close(fd);
        return act_reject(report, "abi", "%s", msg);
    }

    /* Consensus pin BEFORE admit: a module compiled against a different sealed
     * core never reaches a stage that could publish a leaf. */
    {
        char pin_stage[32], pin_err[256];
        if (!module_consensus_pin_ok(handle, pin_stage, sizeof(pin_stage),
                                     pin_err, sizeof(pin_err))) {
            dlclose(handle);
            close(fd);
            return act_reject(report, pin_stage, "%s", pin_err);
        }
    }

    /* admit -> probe -> ONE all-or-nothing batch replace. ZERO leaves publish
     * on any failure, and the resident handlers are untouched. */
    if (!hotswap_module_publish(mod, request_activate, hooks, report)) {
        dlclose(handle);
        close(fd);
        return false;
    }
    if (!report->activated) {
        /* Verify-only: nothing referenced the candidate, drop it now. */
        dlclose(handle);
        close(fd);
        LOG_INFO("hotswap.activate", "verify-only OK sha=%s (not activated)",
                 report->artifact_sha256);
        return true;
    }

    void *prev_handle = NULL;
    int prev_fd = -1;
    pthread_mutex_lock(&g_act_lock);
    struct hotswap_act_slot *slot = slot_for_source_locked(mod->source_tu);
    if (slot) {
        prev_handle = slot->handle;
        prev_fd = slot->artifact_fd;
        slot->handle = handle;
        slot->artifact_fd = fd;
        slot->generation = report->generation;
        slot->leaf_count = mod->leaf_count;
        slot->activated_at = platform_time_wall_time_t();
        slot->swaps++;
        act_copy(slot->artifact_sha256, sizeof(slot->artifact_sha256),
                 report->artifact_sha256);
    }
    pthread_mutex_unlock(&g_act_lock);

    if (!slot) {
        /* Committed but untrackable (table full): keep this .so mapped. */
        atomic_fetch_add_explicit(&g_retained_mapped_count, 1,
                                  memory_order_relaxed);
        LOG_WARN("hotswap.activate",
                 "activation slot table full; keeping module .so mapped");
    }

    /* Retire the previous module .so for this source once dispatch drains. */
    retire_handle(prev_handle, prev_fd, hooks ? hooks->quiesced : NULL,
                  hooks ? hooks->ctx : NULL);
    return true;
}

bool hotswap_activate(const char *so_path, const char *resolved_datadir,
                      bool request_activate,
                      const struct hotswap_publish_hooks *hooks,
                      struct hotswap_activate_report *report)
{
    return activate_run(so_path, resolved_datadir, request_activate,
                        /*require_authorization=*/true, hooks, report);
}

bool hotswap_activate_local(const char *so_path, const char *resolved_datadir,
                            const struct hotswap_publish_hooks *hooks,
                            struct hotswap_activate_report *report)
{
    /* Process-local commit in the operator's own one-shot CLI: probe-class
     * authority, so the resident gate (-hotswap-activate +
     * ZCL_HOTSWAP_ACTIVATE=1) does not apply. The overrides die with the
     * process. Path confinement, the dev-datadir check, the admit gauntlet,
     * probe-before-publish, and the registry's READY/EFFECT_READ re-check all
     * still apply. */
    struct hotswap_publish_hooks local = {0};
    if (hooks)
        local = *hooks;
    local.quiesced = NULL;      /* nothing to reclaim in a one-shot process */
    return activate_run(so_path, resolved_datadir, /*request_activate=*/true,
                        /*require_authorization=*/false, &local, report);
}

bool hotswap_verify_module_so(const char *so_path, const char *expect_tu,
                              struct hotswap_activate_report *report)
{
    if (!report)
        return false;
    memset(report, 0, sizeof(*report));
    report->verify_only = true;
    report->rolled_back = true;

    if (!so_path || !so_path[0]) {
        act_copy(report->stage, sizeof(report->stage), "precheck");
        act_copy(report->error, sizeof(report->error), "empty so_path");
        return false;
    }

    /* Same fd discipline as activate_run(): open ONCE, hash that descriptor,
     * and dlopen the identical descriptor through /proc/self/fd/N, so the
     * digest describes the inode that is actually mapped rather than whatever
     * the path resolves to a moment later. The descriptor is closed as soon as
     * dlopen has mapped it — the mapping outlives the fd, and unlike the
     * resident path there is no later retire step here that needs it.
     *
     * SHA3-256 ONLY on this path, deliberately. report->artifact_sha256 stays
     * empty here: this verifier is linked standalone by tools/dev/
     * hotswap-verify.sh and tools/dev/hotswap-package.sh from a handful of
     * sources plus --gc-sections, and pulling in lib/crypto's SHA-256 (with
     * its CPU-dispatch table and logging macros) to fill a field nothing in
     * the verification or packaging lane reads would buy nothing for a real
     * dependency cost. The RESIDENT loader still computes BOTH over its own
     * fd — see activate_run(). */
    /* Same seal -> probe -> hash -> map order as activate_run(); see the long
     * comment there for why the order IS the property. The offline verifier
     * matters here as much as the resident does: it is the tool a human runs
     * to decide whether a packaged artifact is worth mounting, so it must not
     * form that opinion by running the artifact's constructors first. */
    int vsrc_fd = open(so_path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    struct stat vst;
    if (vsrc_fd < 0 || fstat(vsrc_fd, &vst) != 0 || !S_ISREG(vst.st_mode)) {
        if (vsrc_fd >= 0)
            (void)close(vsrc_fd);
        act_copy(report->stage, sizeof(report->stage), "dlopen");
        act_copy(report->error, sizeof(report->error),
                 "not a regular readable module artifact");
        return false;
    }

    char vseal_err[200];
    int fd = hotswap_sealed_image_from_fd(vsrc_fd, vseal_err, sizeof(vseal_err));
    (void)close(vsrc_fd);
    if (fd < 0) {
        act_copy(report->stage, sizeof(report->stage), "seal");
        act_copy(report->error, sizeof(report->error), vseal_err);
        return false;
    }

    {
        struct hotswap_elf_facts vfacts;
        char vprobe_err[200];
        if (!hotswap_elf_probe_fd(fd, &vfacts, vprobe_err, sizeof(vprobe_err))) {
            (void)close(fd);
            act_copy(report->stage, sizeof(report->stage), "shape");
            act_copy(report->error, sizeof(report->error), vprobe_err);
            return false;
        }
        if (vfacts.init_array_entries >
                ZCL_HOTSWAP_ELF_PROBE_CLEAN_INIT_ARRAY_ENTRIES ||
            vfacts.preinit_array_entries > 0) {
            (void)close(fd);
            act_copy(report->stage, sizeof(report->stage), "shape");
            snprintf(report->error, sizeof(report->error),
                     "module runs its own code at dlopen "
                     "(.init_array %zu, baseline %zu; .preinit_array %zu)",
                     vfacts.init_array_entries,
                     ZCL_HOTSWAP_ELF_PROBE_CLEAN_INIT_ARRAY_ENTRIES,
                     vfacts.preinit_array_entries);
            return false;
        }
    }

    if (!hotswap_artifact_sha3_fd(fd, report->artifact_sha3_256)) {
        (void)close(fd);
        act_copy(report->stage, sizeof(report->stage), "dlopen");
        act_copy(report->error, sizeof(report->error),
                 "could not SHA3-hash the sealed module image");
        return false;
    }
    char vpinned[64];
    (void)snprintf(vpinned, sizeof(vpinned), "/proc/self/fd/%d", fd);

    /* RTLD_LOCAL so the candidate's symbols never join the global scope and
     * interpose on anything the verifying process later resolves. RTLD_LAZY
     * defers function imports the resident node would satisfy, which is exactly
     * what lets a build-time verifier open an artifact with no node running.
     * ELF constructors may still run during dlopen; this verifier is not an
     * execution sandbox for an untrusted artifact.
     * Data and address-taken relocations still resolve eagerly, so a module
     * that references a body defined in a TU outside its own island still
     * fails here — correctly, since re-pointing such a leaf would dispatch
     * into resident code and the swap would silently do nothing for it. */
    void *handle = dlopen(vpinned, RTLD_LAZY | RTLD_LOCAL);
    (void)close(fd);
    if (!handle) {
        const char *e = dlerror();
        act_copy(report->stage, sizeof(report->stage), "dlopen");
        act_copy(report->error, sizeof(report->error), e ? e : "dlopen failed");
        return false;
    }

    (void)dlerror();
    const struct zcl_hotswap_module *module =
        (const struct zcl_hotswap_module *)dlsym(handle,
                                                 ZCL_HOTSWAP_MODULE_SYMBOL);
    const char *sym_err = dlerror();
    if (!module || sym_err) {
        act_copy(report->stage, sizeof(report->stage), "symbol");
        snprintf(report->error, sizeof(report->error),
                 "'%s' not exported (%s)", ZCL_HOTSWAP_MODULE_SYMBOL,
                 sym_err ? sym_err : "resolved to NULL");
        dlclose(handle);
        return false;
    }

    act_copy(report->source_tu, sizeof(report->source_tu),
             module->source_tu ? module->source_tu : "");
    report->leaf_count = module->leaf_count;
    if (module->leaves) {
        size_t used = 0;
        for (uint32_t i = 0; i < module->leaf_count &&
                             i < ZCL_HOTSWAP_MODULE_MAX_LEAVES; i++) {
            const char *nm = module->leaves[i].name;
            if (!nm)
                continue;
            int w = snprintf(report->leaves + used,
                             sizeof(report->leaves) - used, "%s%s",
                             used ? "," : "", nm);
            if (w < 0 || (size_t)w >= sizeof(report->leaves) - used)
                break;
            used += (size_t)w;
        }
    }
    const char *probe = hotswap_module_probe_leaf(
        module->source_tu ? module->source_tu : "");
    act_copy(report->probe_leaf, sizeof(report->probe_leaf),
             probe ? probe : "");

    /* A module cannot mislabel its allowlist row: the build recipe stamps
     * -DZCL_HOTSWAP_MODULE_SOURCE_TU, so a mismatch means the artifact and the
     * file the caller believes it built have diverged. */
    if (expect_tu && expect_tu[0] &&
        strcmp(expect_tu, module->source_tu ? module->source_tu : "") != 0) {
        act_copy(report->stage, sizeof(report->stage), "source_tu");
        snprintf(report->error, sizeof(report->error),
                 "artifact declares '%s', expected '%s'",
                 module->source_tu ? module->source_tu : "(null)", expect_tu);
        dlclose(handle);
        return false;
    }

    /* The same consensus pin the resident enforces. Verification must not be
     * looser than the mount it stands in for — the -z lazy re-link this path
     * dlopens already costs it the unresolved-symbol check (hotswap-symbols.sh
     * covers that separately); it does not get to skip this one too. */
    if (!module_consensus_pin_ok(handle, report->stage, sizeof(report->stage),
                                 report->error, sizeof(report->error))) {
        dlclose(handle);
        return false;
    }

    /* The REAL gauntlet the resident loader runs — not a copy of it. */
    if (!hotswap_module_admit(module, report->stage, sizeof(report->stage),
                              report->error, sizeof(report->error))) {
        dlclose(handle);
        return false;
    }

    act_copy(report->stage, sizeof(report->stage), "verified");
    report->ok = true;
    report->rolled_back = false;
    dlclose(handle);
    return true;
}

#else /* !ZCL_DEV_BUILD — release: no dynamic activation surface */

bool hotswap_verify_module_so(const char *so_path, const char *expect_tu,
                              struct hotswap_activate_report *report)
{
    (void)so_path;
    (void)expect_tu;
    if (!report)
        return false;
    memset(report, 0, sizeof(*report));
    report->verify_only = true;
    report->rolled_back = true;
    act_copy(report->stage, sizeof(report->stage), "release");
    act_copy(report->error, sizeof(report->error),
             "hot-swap module load verification unavailable in release build");
    return false;
}

bool zcl_hotswap_hotfork_visit_so(
    const char *so_path, const char *expected_sha256,
    zcl_hotfork_capsule_visit_fn visit, void *ctx,
    char actual_sha256[65])
{
    (void)so_path;
    (void)expected_sha256;
    (void)visit;
    (void)ctx;
    if (actual_sha256)
        actual_sha256[0] = '\0';
    return false;
}

bool hotswap_activate(const char *so_path, const char *resolved_datadir,
                      bool request_activate,
                      const struct hotswap_publish_hooks *hooks,
                      struct hotswap_activate_report *report)
{
    (void)so_path;
    (void)resolved_datadir;
    (void)request_activate;
    (void)hooks;
    if (!report)
        return false;
    memset(report, 0, sizeof(*report));
    report->verify_only = true;
    report->rolled_back = true;
    act_copy(report->stage, sizeof(report->stage), "release");
    act_copy(report->error, sizeof(report->error),
             "hot-swap activation unavailable in release build");
    return false;
}

bool hotswap_activate_local(const char *so_path, const char *resolved_datadir,
                            const struct hotswap_publish_hooks *hooks,
                            struct hotswap_activate_report *report)
{
    (void)so_path;
    (void)resolved_datadir;
    (void)hooks;
    if (!report)
        return false;
    memset(report, 0, sizeof(*report));
    report->verify_only = true;
    report->rolled_back = true;
    act_copy(report->stage, sizeof(report->stage), "release");
    act_copy(report->error, sizeof(report->error),
             "hot-swap activation unavailable in release build");
    return false;
}

#endif /* ZCL_DEV_BUILD */
