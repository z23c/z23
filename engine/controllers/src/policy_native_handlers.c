/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * SWAPPABLE half of the package-policy projection — the pure decision leaf.
 *
 * THE TRAMPOLINE SPLIT, concretely:
 *
 *   this file (swappable)          policy_native_resident.c (resident)
 *   ────────────────────           ─────────────────────────────────────
 *   pure decision + render         the mutable file-scope statics
 *   zero file-scope mutable state  zcl_native_policy_resident_*()
 *   recompiled into a module .so   never recompiled, never in the .so
 *
 * A generation .so recompiles THIS translation unit (plus its island member
 * contexts/commons/modules/vcs/src/package_policy.c, the frozen policy table itself) and re-points
 * the `zcode.package.policy.limits` leaf at the freshly compiled body. The
 * resident counters are NOT in the .so, so -Wl,-Bsymbolic cannot bind them
 * internally: they resolve against the -rdynamic host at dlopen and the swap
 * reads and writes the process's single copy. Nothing is cloned.
 *
 * Everything here answers from `args` plus compiled-in constants. No RPC, no
 * datadir, no wall-clock, no filesystem. That is deliberate and load-bearing:
 * it is what lets the hot-swap loader dispatch this leaf as its own
 * probe-before-publish case IN-PROCESS with no running node — the property
 * every RPC-front-door swappable TU lacks, and the reason the module harness
 * could not previously activate hermetically.
 */

#include "controllers/policy_native_handlers.h"
#include "controllers/policy_native_resident.h"

#include "json/json.h"
#include "base/log_macros.h"
#include "util/safe_alloc.h"
#include "vcs/package_policy.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Rendered projection ceiling. The document is a fixed key set over integers
 * plus one short tier name, so this is generous by an order of magnitude. */
#define PNH_LIMITS_CAP 1024u

/* Contextual allocation failure. LOG_NULL expands to `return NULL`, so this
 * helper never falls through — the caller's `return pnh_oom(...)` is what
 * types it. */
static char *pnh_oom(struct zcl_native_body_err *err, const char *what)
{
    err->status = ZCL_NATIVE_BODY_INTERNAL;
    (void)snprintf(err->message, sizeof(err->message), "malloc failed for %s",
                   what);
    LOG_NULL("native.policy", "malloc failed for %s", what);
}

/* Clamp a JSON integer to an unsigned 64-bit fact. Negative counters are not
 * representable facts here; they clamp to zero rather than wrapping. */
static uint64_t pnh_fact(const struct json_value *args, const char *key)
{
    int64_t v = json_get_int_or(args, key, 0);
    return v > 0 ? (uint64_t)v : 0u;
}

/* Resolve an explicit tier name. Returns false when `name` is not one of the
 * three frozen tier strings, so an unknown tier is a typed INVALID rather
 * than a silent fallback to the free row. */
static bool pnh_tier_from_name(const char *name, enum vcs_policy_tier *out)
{
    if (!name || !name[0])
        return false;
    for (int t = 0; t < VCS_POLICY_TIER_COUNT; t++) {
        if (strcmp(name, vcs_policy_tier_string((enum vcs_policy_tier)t)) == 0) {
            *out = (enum vcs_policy_tier)t;
            return true;
        }
    }
    return false;
}

char *zcl_native_policy_limits_body(const struct json_value *args,
                                    struct zcl_native_body_err *err)
{
    uint64_t score = pnh_fact(args, "earned_score");
    uint64_t up = pnh_fact(args, "uploaded_bytes");
    uint64_t down = pnh_fact(args, "downloaded_bytes");

    const char *want = json_get_str_or(args, "tier", NULL);
    enum vcs_policy_tier tier;
    const char *source;
    if (want && want[0]) {
        if (!pnh_tier_from_name(want, &tier)) {
            err->status = ZCL_NATIVE_BODY_INVALID;
            (void)snprintf(err->message, sizeof(err->message),
                           "unknown tier '%s': expected one of %s, %s, %s",
                           want,
                           vcs_policy_tier_string(VCS_POLICY_TIER_NEW_USER),
                           vcs_policy_tier_string(
                               VCS_POLICY_TIER_EARNED_CONTRIBUTOR),
                           vcs_policy_tier_string(
                               VCS_POLICY_TIER_VERIFIED_SEEDER));
            return NULL;
        }
        source = "declared";
    } else {
        tier = vcs_policy_tier_for(score, up, down);
        source = "derived";
    }

    const struct vcs_policy_limits *lim = vcs_policy_limits_for(tier);
    uint64_t ratio = vcs_policy_ratio_milli(up, down);

    /* The resident counters. These four symbols live ONLY in the resident
     * sibling, so a module .so imports them from the host: the numbers below
     * are the process's, not a zeroed generation copy. `resident_booted`
     * is the falsifiable half of that claim — a cloned static reports false. */
    bool booted = zcl_native_policy_resident_booted();
    uint64_t dispatches = zcl_native_policy_resident_note_dispatch();

    char *out = zcl_malloc(PNH_LIMITS_CAP, "policy_limits_body");
    if (!out)
        return pnh_oom(err, "package policy limits body");

    int n = snprintf(out, PNH_LIMITS_CAP,
        "{\"tier\":\"%s\",\"tier_source\":\"%s\",\"ratio_milli\":%llu,"
        "\"publish_per_week\":%llu,\"weekly_download_bytes\":%llu,"
        "\"max_concurrent_downloads\":%llu,\"queue_priority\":%llu,"
        "\"pin_allowance_bytes\":%llu,\"announces_per_hour\":%llu,"
        "\"request_burst_per_window\":%llu,"
        "\"resident_booted\":%s,\"resident_dispatches\":%llu}",
        vcs_policy_tier_string(tier), source,
        (unsigned long long)ratio,
        (unsigned long long)lim->publish_per_week,
        (unsigned long long)lim->weekly_download_bytes,
        (unsigned long long)lim->max_concurrent_downloads,
        (unsigned long long)lim->queue_priority,
        (unsigned long long)lim->pin_allowance_bytes,
        (unsigned long long)lim->announces_per_hour,
        (unsigned long long)lim->request_burst_per_window,
        booted ? "true" : "false",
        (unsigned long long)dispatches);
    if (n < 0 || (size_t)n >= PNH_LIMITS_CAP) {
        free(out);
        err->status = ZCL_NATIVE_BODY_INTERNAL;
        (void)snprintf(err->message, sizeof(err->message),
                       "package policy limits body exceeded its %u-byte frame",
                       (unsigned)PNH_LIMITS_CAP);
        return NULL;
    }
    return out;
}

/* ── Tier-1 hot-swap: native.leaves generation entrypoint ──────────────────
 * Dev-only (compiled only under -DZCL_HOTSWAP_GEN). Stages the single leaf
 * this controller owns. The declared probe is zcode.package.policy.limits
 * itself: the body ignores nothing and needs nothing — with an empty argument
 * object it derives the NEW_USER row (the free allowance) from compiled-in
 * constants and emits an object with no top-level "error" key, so the probe
 * dispatch succeeds with no node, no datadir and no RPC.
 * See config/hotswap_eligible.def. */
#ifdef ZCL_HOTSWAP_GEN
#define ZCL_HOTSWAP_PROBE_LEAF "zcode.package.policy.limits"
#include "hotswap/hotswap.h"
#include "kernel/command_registry.h"
#include "command/native_command.h"

ZCL_HOTSWAP_TRAMPOLINE(tramp_policy_limits, zcl_native_policy_limits_body)

static const struct zcl_hotswap_leaf_replacement k_leaves[] = { /* hotswap-static-ok: leaf registration tables are immutable */    { "zcode.package.policy.limits", tramp_policy_limits },
};

ZCL_HOTSWAP_EXPORT_LEAVES(k_leaves, sizeof(k_leaves) / sizeof(k_leaves[0]))
#endif /* ZCL_HOTSWAP_GEN */

/* ── REAL (activatable) multi-leaf module ABI export ───────────────────────
 * Compiled only under `make hotswap-module-so FILE=<this file>`
 * (-DZCL_HOTSWAP_MODULE_GEN); expands to nothing in the node and release TUs.
 *
 * The leaf body lives in THIS translation unit and the policy table it reads
 * is compiled into the same island (engine/composition/hotswap_islands.def), so the
 * re-pointed dispatch enters freshly compiled code. A leaf whose body lived
 * outside the island would be imported from the resident node at dlopen and
 * the swap would silently do nothing while reporting success. */
#ifdef ZCL_HOTSWAP_MODULE_GEN
#include "hotswap/hotswap_module.h"
#include "kernel/command_registry.h"
#include "command/native_command.h"

ZCL_HOTSWAP_TRAMPOLINE(module_tramp_policy_limits, zcl_native_policy_limits_body)

/* Structural health hook, run before the loader publishes this module. It is
 * a real check here rather than a bare `return true`: the projection is pure,
 * so the module can verify the frozen free-allowance invariant the owner
 * directive fixes — a new user with zero score always keeps a nonzero weekly
 * download allowance and at least one publication per week. A module that
 * broke that is refused at stage=self_test before any leaf is published. */
static bool module_selftest_policy_limits(char *err, size_t cap)
{
    const struct vcs_policy_limits *free_row =
        vcs_policy_limits_for(VCS_POLICY_TIER_NEW_USER);
    if (!free_row || free_row->weekly_download_bytes == 0u ||
        free_row->publish_per_week == 0u) {
        if (err && cap)
            (void)snprintf(err, cap,
                           "free allowance violated: a zero-score user must "
                           "keep a nonzero weekly download allowance and at "
                           "least one publication per week");
        return false;
    }
    return true;
}

ZCL_HOTSWAP_MODULE("zcode.package.policy.limits", module_tramp_policy_limits,
                   module_selftest_policy_limits)
#endif /* ZCL_HOTSWAP_MODULE_GEN */
