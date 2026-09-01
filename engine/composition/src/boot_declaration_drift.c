/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Naming surface + escape wiring for the declared-vs-observed faults. See
 * config/boot_declaration_drift.h for the contract, the "declaration is not
 * authoritative" rule, and the handoff status.
 */

#include "config/boot_declaration_drift.h"

#include "util/blocker.h"
#include "util/log_macros.h"

#include <pthread.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#define DRIFT_SCOPE_MAX 64
#define DRIFT_KIND_COUNT 2

/* FIXED reason texts. No config key, no service name, no timestamp: the
 * reason is part of fault identity in blocker_set, so a varying reason
 * re-anchors the escape deadline on every refire and the blocker never
 * converges toward escalation. */
static const char *const CONFIG_RELOAD_REASON =
    "configuration reload completed but the effective configuration does "
    "not match the requested configuration";
static const char *const SERVICE_DECL_REASON =
    "declared service catalog does not match observed running services "
    "(declaration is observation only, never authoritative)";

static pthread_mutex_t g_drift_lock = PTHREAD_MUTEX_INITIALIZER;
static char g_last_scope[DRIFT_KIND_COUNT][DRIFT_SCOPE_MAX];
static declaration_drift_reconcile_fn g_reconcile[DRIFT_KIND_COUNT];
static void *g_reconcile_ctx[DRIFT_KIND_COUNT];

static bool kind_valid(enum declaration_drift_kind kind)
{
    return kind == DECLARATION_DRIFT_CONFIG_RELOAD ||
           kind == DECLARATION_DRIFT_SERVICE_DECL;
}

static void record_scope(enum declaration_drift_kind kind, const char *scope)
{
    pthread_mutex_lock(&g_drift_lock);
    snprintf(g_last_scope[kind], DRIFT_SCOPE_MAX, "%s",
             (scope && scope[0]) ? scope : "(unspecified)");
    pthread_mutex_unlock(&g_drift_lock);
}

const char *boot_declaration_drift_last_scope(enum declaration_drift_kind kind)
{
    if (!kind_valid(kind))
        return "";
    return g_last_scope[kind];
}

void boot_declaration_drift_set_reconciler(enum declaration_drift_kind kind,
                                           declaration_drift_reconcile_fn fn,
                                           void *ctx)
{
    if (!kind_valid(kind))
        return;
    pthread_mutex_lock(&g_drift_lock);
    g_reconcile[kind] = fn;
    g_reconcile_ctx[kind] = ctx;
    pthread_mutex_unlock(&g_drift_lock);
}

/* Shared escape body. A reconciler that reports convergence clears the
 * blocker; no reconciler, or a reconciler that still sees divergence,
 * leaves it standing. Never claims a fix it did not make. */
static void drift_escape(enum declaration_drift_kind kind,
                         const char *blocker_id, const char *action)
{
    pthread_mutex_lock(&g_drift_lock);
    declaration_drift_reconcile_fn fn = g_reconcile[kind];
    void *ctx = g_reconcile_ctx[kind];
    pthread_mutex_unlock(&g_drift_lock);

    if (!fn) {
        LOG_WARN("boot.declaration_drift",
                 "escape %s: no reconciler installed (the detecting organ is "
                 "not wired yet) — blocker %s stays named for the operator",
                 action, blocker_id);
        return;
    }
    if (fn(ctx)) {
        blocker_clear(blocker_id);
        LOG_INFO("boot.declaration_drift",
                 "escape %s: reconciler reports convergence; cleared %s",
                 action, blocker_id);
        return;
    }
    LOG_WARN("boot.declaration_drift",
             "escape %s: still diverged after reconcile attempt — %s stays "
             "named", action, blocker_id);
}

static void config_reload_escape(const struct blocker_snapshot *snap)
{
    (void)snap;
    drift_escape(DECLARATION_DRIFT_CONFIG_RELOAD,
                 CONFIG_RELOAD_DIVERGED_BLOCKER_ID,
                 CONFIG_RELOAD_ESCAPE_ACTION);
}

static void service_declaration_escape(const struct blocker_snapshot *snap)
{
    (void)snap;
    drift_escape(DECLARATION_DRIFT_SERVICE_DECL,
                 SERVICE_DECLARATION_DIVERGED_BLOCKER_ID,
                 SERVICE_DECLARATION_ESCAPE_ACTION);
}

void boot_declaration_drift_register_escapes(void)
{
    if (!blocker_lookup_escape(CONFIG_RELOAD_ESCAPE_ACTION))
        (void)blocker_register_escape(CONFIG_RELOAD_ESCAPE_ACTION,
                                      config_reload_escape);
    if (!blocker_lookup_escape(SERVICE_DECLARATION_ESCAPE_ACTION))
        (void)blocker_register_escape(SERVICE_DECLARATION_ESCAPE_ACTION,
                                      service_declaration_escape);
}

/* Common record shaping. The id is NOT threaded through here: the remedy
 * gate resolves a blocker id only from a literal / `#define *_BLOCKER_ID`
 * at the blocker_init() call site, so each raise below calls blocker_init
 * itself with its own macro and this helper only finishes the record. */
static void drift_finish_and_set(struct blocker_record *r, const char *action)
{
    r->escape_deadline_secs = DECLARATION_DRIFT_ESCAPE_DEADLINE_SECS;
    snprintf(r->escape_action, sizeof(r->escape_action), "%s", action);
    r->retry_budget = -1;  /* divergence is never auto-expired */
    (void)blocker_set(r);
}

void boot_config_reload_divergence_raise(const char *scope)
{
    /* Self-registering: the escape is armed by the raise that needs it, so
     * there is no boot-order coupling to forget and no window where a live
     * blocker names an action the sweep cannot resolve. Idempotent. */
    boot_declaration_drift_register_escapes();
    record_scope(DECLARATION_DRIFT_CONFIG_RELOAD, scope);
    struct blocker_record r;
    if (blocker_init(&r, CONFIG_RELOAD_DIVERGED_BLOCKER_ID, "config.reload",
                     BLOCKER_DEPENDENCY, CONFIG_RELOAD_REASON))
        drift_finish_and_set(&r, CONFIG_RELOAD_ESCAPE_ACTION);
    LOG_WARN("boot.declaration_drift",
             "config reload diverged from request (scope=%s) — blocker %s",
             boot_declaration_drift_last_scope(DECLARATION_DRIFT_CONFIG_RELOAD),
             CONFIG_RELOAD_DIVERGED_BLOCKER_ID);
}

void boot_service_declaration_divergence_raise(const char *scope)
{
    boot_declaration_drift_register_escapes();  /* see the note above */
    record_scope(DECLARATION_DRIFT_SERVICE_DECL, scope);
    struct blocker_record r;
    if (blocker_init(&r, SERVICE_DECLARATION_DIVERGED_BLOCKER_ID,
                     "config.service_decl", BLOCKER_DEPENDENCY,
                     SERVICE_DECL_REASON))
        drift_finish_and_set(&r, SERVICE_DECLARATION_ESCAPE_ACTION);
    LOG_WARN("boot.declaration_drift",
             "service declaration diverged from observation (scope=%s) — "
             "blocker %s; the declaration is NOT applied to reality",
             boot_declaration_drift_last_scope(DECLARATION_DRIFT_SERVICE_DECL),
             SERVICE_DECLARATION_DIVERGED_BLOCKER_ID);
}

void boot_config_reload_divergence_clear(void)
{
    blocker_clear(CONFIG_RELOAD_DIVERGED_BLOCKER_ID);
}

void boot_service_declaration_divergence_clear(void)
{
    blocker_clear(SERVICE_DECLARATION_DIVERGED_BLOCKER_ID);
}

void boot_declaration_drift_reset_for_testing(void)
{
    pthread_mutex_lock(&g_drift_lock);
    memset(g_last_scope, 0, sizeof(g_last_scope));
    memset(g_reconcile, 0, sizeof(g_reconcile));
    memset(g_reconcile_ctx, 0, sizeof(g_reconcile_ctx));
    pthread_mutex_unlock(&g_drift_lock);
}
