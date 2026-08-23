/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "kernel/command_registry.h"

#include "crypto/sha256.h"
#include "platform/time_compat.h"
#include "services/agent_spend_policy.h"  // lib-layer-ok:agent-spend-policy-gate
#include "util/log_macros.h"
#include "util/safe_alloc.h"
/* Included for the *_MAX_WIRE_BYTES constants only — no lib/vcs symbol is
 * referenced, so this adds no link edge. The include is what makes the
 * package input bounds below DERIVED rather than restated: change a wire's
 * own limit and the input validator follows it in the same build. */
#include "vcs/package_manifest.h"
#include "vcs/package_recipe.h"
#include "vcs/package_release.h"

#include <ctype.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef ZCL_HOTFORK_COMMAND_INPUT_CORE
static bool command_is_branch(const struct zcl_command_spec *spec);

static _Atomic uint64_t g_request_sequence = 1;

/* ── Per-leaf latency ring (OS-B2) ───────────────────────────────────────
 * A small in-process ring of the last ZCL_COMMAND_LATENCY_RING_CAP dispatch
 * durations per catalog leaf, indexed by the leaf's offset into whichever
 * `registry->commands` array it was dispatched through. Feeds the
 * `observed_p99_us`/`observed_samples` fields in
 * zcl_command_registry_describe_json.
 *
 * PROCESS-LIFETIME CAVEAT (read before treating p99 as durable): the plain
 * CLI path (`zclassic23 <command>`) is a FRESH OS PROCESS PER INVOCATION —
 * main() dispatches once and returns. A ring that lives in static process
 * memory therefore starts EMPTY on every plain CLI call; `discover describe`
 * run immediately after one CLI command will usually show observed_samples=1
 * (that command's own dispatch), not a historical p99. The ring accumulates
 * real history only within a long-lived process, such as the REST server once
 * OS-B3b wires it through this same execute path, or
 * a test/fixture process that dispatches the same leaf repeatedly. This is
 * deliberate phase-1 scope (the acceptance bar is an in-process fixture test)
 * — a cross-process persistence layer (mmap'd or on-disk ring, keyed like
 * progress.kv) is explicitly follow-on work, not part of B2. */
#define ZCL_COMMAND_LATENCY_RING_CAP 64U

struct zcl_command_latency_ring {
    _Atomic int64_t samples_us[ZCL_COMMAND_LATENCY_RING_CAP];
    _Atomic uint32_t next;
    _Atomic uint32_t filled;
};

static struct zcl_command_latency_ring
    g_latency_rings[ZCL_COMMAND_LATENCY_TABLE_MAX];

/* Bound-checked against BOTH `registry->count` (the caller's own array) and
 * ZCL_COMMAND_LATENCY_TABLE_MAX (the side-table's fixed size) before indexing —
 * an ad hoc test registry larger than the compiled catalog, or a `spec` pointer
 * that isn't actually inside `registry->commands`, silently no-ops rather than
 * indexing out of bounds. KNOWN LIMITATION: two DIFFERENT registries dispatched
 * in the SAME process share slot space by raw offset (e.g. index 3 in the real
 * catalog and index 3 in a small ad hoc test registry write the same ring). The
 * only production caller always passes zcl_command_catalog(), so this only
 * matters inside test binaries that build small ad hoc registries in the SAME
 * test process as catalog-based tests — acceptable for phase 1. */
static void latency_ring_record(const struct zcl_command_registry *registry,
                                const struct zcl_command_spec *spec,
                                int64_t elapsed_us)
{
    if (!registry || !spec || !registry->commands || elapsed_us < 0)
        return;
    if (spec < registry->commands ||
        spec >= registry->commands + registry->count)
        return;
    size_t idx = (size_t)(spec - registry->commands);
    if (idx >= ZCL_COMMAND_LATENCY_TABLE_MAX)
        return;
    struct zcl_command_latency_ring *ring = &g_latency_rings[idx];
    uint32_t slot = atomic_fetch_add_explicit(&ring->next, 1,
                                              memory_order_relaxed) %
                    ZCL_COMMAND_LATENCY_RING_CAP;
    atomic_store_explicit(&ring->samples_us[slot], elapsed_us,
                          memory_order_relaxed);
    uint32_t filled = atomic_load_explicit(&ring->filled,
                                           memory_order_relaxed);
    if (filled < ZCL_COMMAND_LATENCY_RING_CAP)
        atomic_fetch_add_explicit(&ring->filled, 1, memory_order_relaxed);
}

static int latency_cmp_i64(const void *a, const void *b)
{
    int64_t x = *(const int64_t *)a, y = *(const int64_t *)b;
    return (x > y) - (x < y);
}

/* p99 + sample count for the ring at `spec`'s offset in `registry`. Returns
 * false with *count=0 when no samples exist yet (fresh process — see the
 * PROCESS-LIFETIME CAVEAT above); *p99_us is 0 in that case, never garbage. */
static bool latency_ring_p99(const struct zcl_command_registry *registry,
                             const struct zcl_command_spec *spec,
                             int64_t *p99_us, uint32_t *count)
{
    *p99_us = 0;
    *count = 0;
    if (!registry || !spec || !registry->commands ||
        spec < registry->commands ||
        spec >= registry->commands + registry->count)
        return false;
    size_t idx = (size_t)(spec - registry->commands);
    if (idx >= ZCL_COMMAND_LATENCY_TABLE_MAX)
        return false;
    struct zcl_command_latency_ring *ring = &g_latency_rings[idx];
    uint32_t filled = atomic_load_explicit(&ring->filled,
                                           memory_order_relaxed);
    if (filled == 0)
        return false;
    int64_t tmp[ZCL_COMMAND_LATENCY_RING_CAP];
    for (uint32_t i = 0; i < filled; i++)
        tmp[i] = atomic_load_explicit(&ring->samples_us[i],
                                      memory_order_relaxed);
    qsort(tmp, filled, sizeof(int64_t), latency_cmp_i64);
    *p99_us = tmp[(size_t)((filled - 1) * 99 / 100)];
    *count = filled;
    return true;
}

/* ── Hot-swap leaf-handler override layer ─────────────────────────────
 *
 * A heap-cloned, immutable snapshot of
 * {path,handler} overrides published with ONE release-store on a static
 * _Atomic pointer. Readers acquire-load; a NULL active pointer is the zero-cost
 * fast path (no override ever installed). Published snapshots are never freed —
 * a dispatch that acquired an older snapshot must finish without a UAF race.
 * Writes are rare (hot swaps) and serialized by a tiny spin lock; readers stay
 * lock-free. */
struct zcl_command_handler_snapshot {
    uint32_t generation;
    size_t count;
    struct zcl_command_handler_override slots[ZCL_COMMAND_HANDLER_OVERRIDE_MAX];
    /* In-flight dispatches that acquired THIS snapshot. Held across the
     * override handler call so a hot-swap loader can dlclose a superseded .so
     * only after every retired snapshot referencing it has drained to zero.
     * Snapshots themselves are NEVER freed, so acquire's optimistic increment
     * can never touch reclaimed memory (see handler_snapshot_acquire). */
    _Atomic uint32_t refs;
    /* Immutable publish list (append-only, never freed); walked by the
     * quiescence query. Links every published snapshot newest-first. */
    struct zcl_command_handler_snapshot *published_prev;
};

static struct zcl_command_handler_snapshot *_Atomic g_active_handlers = NULL;
/* Head of the append-only publish list (newest snapshot). Never freed. */
static struct zcl_command_handler_snapshot *_Atomic g_published_head = NULL;
static atomic_flag g_handler_write_lock = ATOMIC_FLAG_INIT;
static const struct zcl_command_registry *_Atomic g_active_registry = NULL;

static inline void handler_write_lock(void)
{
    while (atomic_flag_test_and_set_explicit(&g_handler_write_lock,
                                             memory_order_acquire))
        ; /* spin: writes are rare and short */
}

static inline void handler_write_unlock(void)
{
    atomic_flag_clear_explicit(&g_handler_write_lock, memory_order_release);
}

static zcl_command_handler_fn snapshot_lookup(
    const struct zcl_command_handler_snapshot *snap, const char *path)
{
    if (!snap || !path)
        return NULL;
    for (size_t i = 0; i < snap->count; i++) {
        if (snap->slots[i].path && strcmp(snap->slots[i].path, path) == 0)
            return snap->slots[i].handler;
    }
    return NULL;
}

static zcl_command_handler_fn handler_override_lookup(const char *path)
{
    const struct zcl_command_handler_snapshot *snap =
        atomic_load_explicit(&g_active_handlers, memory_order_acquire);
    if (!snap) /* zero-overhead fast path when no snapshot exists */
        return NULL;
    return snapshot_lookup(snap, path);
}

/* Acquire the active override snapshot for the duration of a dispatch,
 * incrementing its in-flight refcount. Returns NULL when no override is
 * installed (the common, zero-RMW fast path). The optimistic increment +
 * revalidate is UAF-safe because snapshots are never freed: if the snapshot
 * was retired between the load and the increment, the revalidate fails and we
 * decrement and retry; a retired snapshot's refs can never rise into a
 * VALIDATED state again (no reader can newly load a pointer the active slot no
 * longer holds), so its refcount is monotone-draining to zero. */
static struct zcl_command_handler_snapshot *handler_snapshot_acquire(void)
{
    for (;;) {
        struct zcl_command_handler_snapshot *snap =
            atomic_load_explicit(&g_active_handlers, memory_order_acquire);
        if (!snap)
            return NULL;
        atomic_fetch_add_explicit(&snap->refs, 1, memory_order_acq_rel);
        if (atomic_load_explicit(&g_active_handlers, memory_order_acquire) == snap)
            return snap; /* still current: reference validated */
        atomic_fetch_sub_explicit(&snap->refs, 1, memory_order_acq_rel);
        /* snap was retired between load and incref; retry with the newer one. */
    }
}

static void handler_snapshot_release(struct zcl_command_handler_snapshot *snap)
{
    if (snap)
        atomic_fetch_sub_explicit(&snap->refs, 1, memory_order_release);
}

/* True iff every RETIRED override snapshot (published but no longer active) has
 * drained to a zero in-flight refcount — i.e. no dispatch can still be inside a
 * superseded handler. A hot-swap loader polls this before dlclosing a
 * superseded module .so. The active snapshot is skipped (it is always live).
 * The publish list is append-only and never freed, so the walk is UAF-safe. */
bool zcl_command_registry_all_retired_quiesced(void)
{
    const struct zcl_command_handler_snapshot *active =
        atomic_load_explicit(&g_active_handlers, memory_order_acquire);
    const struct zcl_command_handler_snapshot *p =
        atomic_load_explicit(&g_published_head, memory_order_acquire);
    for (; p; p = p->published_prev) {
        if (p == active)
            continue;
        if (atomic_load_explicit(&p->refs, memory_order_acquire) != 0)
            return false;
    }
    return true;
}

void zcl_command_registry_set_active(const struct zcl_command_registry *registry)
{
    atomic_store_explicit(&g_active_registry, registry, memory_order_release);
}

uint32_t zcl_command_registry_active_generation(void)
{
    const struct zcl_command_handler_snapshot *snap =
        atomic_load_explicit(&g_active_handlers, memory_order_acquire);
    return snap ? snap->generation : 0u;
}

zcl_command_handler_fn zcl_command_registry_effective_handler(
    const struct zcl_command_spec *spec)
{
    if (!spec)
        return NULL;
    zcl_command_handler_fn override = handler_override_lookup(spec->path);
    return override ? override : spec->handler;
}

void zcl_command_registry_reset_overrides(void)
{
    handler_write_lock();
    /* Retire the active snapshot per the never-free discipline (an in-flight
     * reader may still hold it); just re-point at NULL under the write lock. */
    atomic_store_explicit(&g_active_handlers, NULL, memory_order_release);
    handler_write_unlock();
}

bool zcl_command_registry_replace_batch(
    uint32_t generation,
    const struct zcl_command_handler_override *overrides,
    size_t count, char *why, size_t why_sz)
{
    if (why && why_sz)
        why[0] = '\0';

    if (!overrides || count == 0 || count > ZCL_COMMAND_HANDLER_OVERRIDE_MAX) {
        if (why && why_sz)
            snprintf(why, why_sz, "invalid override count: %zu", count);
        LOG_FAIL("kernel.command", "invalid override count: %zu", count);
    }

    const struct zcl_command_registry *registry =
        atomic_load_explicit(&g_active_registry, memory_order_acquire);
    if (!registry) {
        if (why && why_sz)
            snprintf(why, why_sz, "no active registry bound");
        LOG_FAIL("kernel.command", "no active registry bound for override batch");
    }

    /* ── Validate the ENTIRE batch against the immutable registry before
     * touching the active snapshot (no lock needed — the registry is
     * immutable). Any rejection leaves the active snapshot untouched. */
    for (size_t i = 0; i < count; i++) {
        const struct zcl_command_handler_override *ovr = &overrides[i];
        if (!ovr->path || !ovr->path[0] || !ovr->handler) {
            if (why && why_sz)
                snprintf(why, why_sz, "override %zu: null/empty path or handler",
                         i);
            LOG_FAIL("kernel.command",
                     "override %zu: null/empty path or handler", i);
        }
        bool was_alias = false;
        const struct zcl_command_spec *spec =
            zcl_command_registry_find(registry, ovr->path, &was_alias);
        if (!spec || was_alias || strcmp(spec->path, ovr->path) != 0) {
            if (why && why_sz)
                snprintf(why, why_sz, "no canonical leaf named '%s'", ovr->path);
            LOG_FAIL("kernel.command", "no canonical leaf named '%s'",
                     ovr->path);
        }
        if (command_is_branch(spec)) {
            if (why && why_sz)
                snprintf(why, why_sz, "leaf '%s' is a branch, not swappable",
                         ovr->path);
            LOG_FAIL("kernel.command", "leaf '%s' is a branch, not swappable",
                     ovr->path);
        }
        if (spec->availability != ZCL_COMMAND_READY) {
            if (why && why_sz)
                snprintf(why, why_sz, "leaf '%s' is not READY", ovr->path);
            LOG_FAIL("kernel.command", "leaf '%s' is not READY", ovr->path);
        }
        if (spec->effect != ZCL_COMMAND_EFFECT_READ) {
            if (why && why_sz)
                snprintf(why, why_sz,
                         "leaf '%s' is mutating/destructive (effect=%s)",
                         ovr->path, zcl_command_effect_name(spec->effect));
            LOG_FAIL("kernel.command",
                     "refusing mutating/destructive leaf '%s' (effect=%s)",
                     ovr->path, zcl_command_effect_name(spec->effect));
        }
        for (size_t j = 0; j < i; j++) {
            if (strcmp(overrides[j].path, ovr->path) == 0) {
                if (why && why_sz)
                    snprintf(why, why_sz, "duplicate override '%s'", ovr->path);
                LOG_FAIL("kernel.command", "duplicate override '%s'",
                         ovr->path);
            }
        }
    }

    handler_write_lock();
    const struct zcl_command_handler_snapshot *old =
        atomic_load_explicit(&g_active_handlers, memory_order_acquire);
    uint32_t old_gen = old ? old->generation : 0u;

    uint32_t next_generation = generation ? generation : old_gen + 1u;
    if (next_generation <= old_gen) {
        handler_write_unlock();
        if (why && why_sz)
            snprintf(why, why_sz,
                     "generation %u is not newer than active generation %u",
                     next_generation, old_gen);
        LOG_FAIL("kernel.command",
                 "generation %u not newer than active generation %u",
                 next_generation, old_gen);
    }

    struct zcl_command_handler_snapshot *next =
        zcl_malloc(sizeof(*next), "command handler override snapshot");
    if (!next) {
        handler_write_unlock();
        if (why && why_sz)
            snprintf(why, why_sz, "snapshot allocation failed");
        LOG_FAIL("kernel.command", "override snapshot allocation failed");
    }
    if (old)
        memcpy(next, old, sizeof(*next));
    else
        memset(next, 0, sizeof(*next));
    next->generation = next_generation;
    /* A fresh snapshot starts with no in-flight readers and is not yet linked
     * into the publish list (the memcpy copied old's bookkeeping). */
    atomic_store_explicit(&next->refs, 0, memory_order_relaxed);
    next->published_prev = NULL;

    /* Merge: overwrite an existing override slot with the same path, else
     * append. Capacity is bounded by ZCL_COMMAND_HANDLER_OVERRIDE_MAX. */
    for (size_t i = 0; i < count; i++) {
        const struct zcl_command_handler_override *ovr = &overrides[i];
        size_t idx = next->count;
        for (size_t k = 0; k < next->count; k++) {
            if (next->slots[k].path && strcmp(next->slots[k].path, ovr->path) == 0) {
                idx = k;
                break;
            }
        }
        if (idx == next->count) {
            if (next->count >= ZCL_COMMAND_HANDLER_OVERRIDE_MAX) {
                handler_write_unlock();
                /* next is a private, unpublished clone — safe to free. */
                free(next);
                if (why && why_sz)
                    snprintf(why, why_sz, "override capacity exceeded");
                LOG_FAIL("kernel.command", "override capacity exceeded (max %u)",
                         (unsigned)ZCL_COMMAND_HANDLER_OVERRIDE_MAX);
            }
            next->count++;
        }
        next->slots[idx] = *ovr;
    }

    /* Link into the append-only publish list BEFORE swapping the active
     * pointer, so the quiescence walk (head then active) always finds the
     * active snapshot in the list. Both stores happen under the write lock. */
    next->published_prev =
        atomic_load_explicit(&g_published_head, memory_order_acquire);
    atomic_store_explicit(&g_published_head, next, memory_order_release);
    atomic_store_explicit(&g_active_handlers, next, memory_order_release);
    handler_write_unlock();
    return true;
}

static const char *const g_layer_names[] = {
    "root", "core", "app", "dev", "ops", "discover", "code"
};
static const char *const g_effect_names[] = {
    "read", "mutate", "destructive"
};
static const char *const g_risk_names[] = {
    "read", "app-write", "wallet", "core-recovery", "destructive",
    "dev-mutation"
};
static const char *const g_scope_names[] = {
    "local", "node", "dev-lane", "offline-copy"
};
static const char *const g_authority_names[] = {
    "public", "operator", "owner"
};
static const char *const g_availability_names[] = {
    "ready", "compat", "planned"
};
static const char *const g_mode_names[] = {
    "branch", "sync", "job", "stream"
};
static const char *const g_latency_names[] = {
    "instant", "fast", "foreground", "background", "persistent"
};
static const char *const g_cost_names[] = {
    "tiny", "low", "moderate", "high", "stream"
};
static const char *const g_confirmation_names[] = {
    "none", "idempotency", "plan-commit"
};
static const char *const g_status_names[] = {
    "passed", "accepted", "blocked", "failed"
};

#define NAME_FN(name, values, max_value)                                    \
    const char *name(max_value value)                                       \
    {                                                                       \
        size_t index = (size_t)value;                                       \
        return index < sizeof(values) / sizeof(values[0])                   \
            ? values[index] : "invalid";                                  \
    }

NAME_FN(zcl_command_layer_name, g_layer_names, enum zcl_command_layer)
NAME_FN(zcl_command_effect_name, g_effect_names, enum zcl_command_effect)
NAME_FN(zcl_command_risk_name, g_risk_names, enum zcl_command_risk)
NAME_FN(zcl_command_scope_name, g_scope_names, enum zcl_command_scope)
NAME_FN(zcl_command_authority_name, g_authority_names,
        enum zcl_command_authority)
NAME_FN(zcl_command_availability_name, g_availability_names,
        enum zcl_command_availability)
NAME_FN(zcl_command_mode_name, g_mode_names, enum zcl_command_mode)
NAME_FN(zcl_command_latency_name, g_latency_names, enum zcl_command_latency)

/* Per-latency dispatch budget in ms (OS-B2). For MODE_JOB/MODE_STREAM leaves
 * this budgets the dispatch/kickoff call (accept-and-return-a-handle), NEVER
 * the job's own completion time — jobs are polled, not blocked on. Do not
 * "fix" BACKGROUND/PERSISTENT to mean job-completion latency. */
static const int64_t g_latency_budget_ms[] = {
    [ZCL_COMMAND_LATENCY_INSTANT]    = ZCL_COMMAND_LATENCY_BUDGET_INSTANT_MS,
    [ZCL_COMMAND_LATENCY_FAST]       = ZCL_COMMAND_LATENCY_BUDGET_FAST_MS,
    [ZCL_COMMAND_LATENCY_FOREGROUND] = ZCL_COMMAND_LATENCY_BUDGET_FOREGROUND_MS,
    [ZCL_COMMAND_LATENCY_BACKGROUND] = ZCL_COMMAND_LATENCY_BUDGET_BACKGROUND_MS,
    [ZCL_COMMAND_LATENCY_PERSISTENT] = ZCL_COMMAND_LATENCY_BUDGET_PERSISTENT_MS,
};

int64_t zcl_command_latency_budget_ms(enum zcl_command_latency latency)
{
    size_t idx = (size_t)latency;
    if (idx >= sizeof(g_latency_budget_ms) / sizeof(g_latency_budget_ms[0]))
        return ZCL_COMMAND_LATENCY_BUDGET_PERSISTENT_MS;
    return g_latency_budget_ms[idx];
}
NAME_FN(zcl_command_cost_name, g_cost_names, enum zcl_command_cost)
NAME_FN(zcl_command_confirmation_name, g_confirmation_names,
        enum zcl_command_confirmation)
NAME_FN(zcl_command_status_name, g_status_names, enum zcl_command_status)

#undef NAME_FN

static bool copy_string(char *out, size_t out_size, const char *value)
{
    if (!out || out_size == 0)
        return false;
    int n = snprintf(out, out_size, "%s", value ? value : "");
    return n >= 0 && (size_t)n < out_size;
}

void zcl_command_reply_init(struct zcl_command_reply *reply,
                            const char *data_schema)
{
    if (!reply)
        return;
    memset(reply, 0, sizeof(*reply));
    reply->status = ZCL_COMMAND_STATUS_PASSED;
    reply->exit_code = ZCL_COMMAND_EXIT_OK;
    reply->data_schema = data_schema ? data_schema : "zcl.command.empty.v1";
    json_init(&reply->data);
    json_set_object(&reply->data);
}

void zcl_command_reply_free(struct zcl_command_reply *reply)
{
    if (!reply)
        return;
    json_free(&reply->data);
    memset(reply, 0, sizeof(*reply));
}

void zcl_command_reply_fail(struct zcl_command_reply *reply,
                            enum zcl_command_status status,
                            enum zcl_command_exit exit_code,
                            const char *code, const char *phase,
                            bool retryable, bool mutated,
                            const char *message, const char *evidence)
{
    if (!reply)
        return;
    reply->status = status;
    reply->exit_code = exit_code;
    reply->error.retryable = retryable;
    reply->error.mutated = mutated;
    (void)copy_string(reply->error.code, sizeof(reply->error.code), code);
    (void)copy_string(reply->error.phase, sizeof(reply->error.phase), phase);
    (void)copy_string(reply->error.message, sizeof(reply->error.message),
                      message);
    (void)copy_string(reply->error.evidence, sizeof(reply->error.evidence),
                      evidence);
}

bool zcl_command_reply_add_next(struct zcl_command_reply *reply,
                                const char *command, const char *input_json,
                                const char *reason)
{
    if (!reply || !command || !command[0] || !input_json || !input_json[0] ||
        reply->next_count >= ZCL_COMMAND_MAX_NEXT)
        return false;
    struct zcl_command_next *next = &reply->next[reply->next_count];
    if (!copy_string(next->command, sizeof(next->command), command) ||
        !copy_string(next->input_json, sizeof(next->input_json), input_json) ||
        !copy_string(next->reason, sizeof(next->reason), reason))
        return false;
    reply->next_count++;
    return true;
}

static bool path_valid(const char *path)
{
    if (!path || !path[0] || strlen(path) >= ZCL_COMMAND_MAX_PATH)
        return false;
    bool token_start = true;
    for (const unsigned char *p = (const unsigned char *)path; *p; p++) {
        if (*p == '.') {
            if (token_start)
                return false;
            token_start = true;
            continue;
        }
        if (token_start) {
            if (!(*p >= 'a' && *p <= 'z'))
                return false;
            token_start = false;
        } else if (!((*p >= 'a' && *p <= 'z') ||
                     (*p >= '0' && *p <= '9') || *p == '_' || *p == '-')) {
            return false;
        }
    }
    return !token_start;
}
#endif


static bool csv_token_equal(const char *csv, const char *value)
{
    if (!csv || !csv[0] || !value)
        return false;
    size_t value_len = strlen(value);
    const char *at = csv;
    while (*at) {
        const char *end = strchr(at, ',');
        size_t len = end ? (size_t)(end - at) : strlen(at);
        if (len == value_len && memcmp(at, value, len) == 0)
            return true;
        if (!end)
            break;
        at = end + 1;
    }
    return false;
}

#ifndef ZCL_HOTFORK_COMMAND_INPUT_CORE
static bool csv_valid_paths(const char *csv)
{
    if (!csv || !csv[0])
        return true;
    const char *at = csv;
    char token[ZCL_COMMAND_MAX_PATH];
    while (*at) {
        const char *end = strchr(at, ',');
        size_t len = end ? (size_t)(end - at) : strlen(at);
        if (len == 0 || len >= sizeof(token))
            return false;
        memcpy(token, at, len);
        token[len] = 0;
        if (!path_valid(token))
            return false;
        if (!end)
            break;
        at = end + 1;
    }
    return true;
}

static bool enum_values_valid(const struct zcl_command_spec *spec)
{
    return spec->layer <= ZCL_COMMAND_LAYER_CODE &&
           spec->effect <= ZCL_COMMAND_EFFECT_DESTRUCTIVE &&
           spec->risk <= ZCL_COMMAND_RISK_DEV_MUTATION &&
           spec->scope <= ZCL_COMMAND_SCOPE_OFFLINE_COPY &&
           spec->authority <= ZCL_COMMAND_AUTH_OWNER &&
           spec->availability <= ZCL_COMMAND_PLANNED &&
           spec->mode <= ZCL_COMMAND_MODE_STREAM &&
           spec->latency <= ZCL_COMMAND_LATENCY_PERSISTENT &&
           spec->cost <= ZCL_COMMAND_COST_STREAM &&
           spec->confirmation <= ZCL_COMMAND_CONFIRM_PLAN_COMMIT;
}

static bool command_is_branch(const struct zcl_command_spec *spec)
{
    return spec && spec->mode == ZCL_COMMAND_MODE_BRANCH;
}

bool zcl_command_registry_validate(const struct zcl_command_registry *registry,
                                   char *why, size_t why_size)
{
    if (why && why_size)
        why[0] = 0;
    if (!registry || !registry->commands || registry->count == 0) {
        if (why) snprintf(why, why_size, "empty registry");
        return false;
    }
    for (size_t i = 0; i < registry->count; i++) {
        const struct zcl_command_spec *spec = &registry->commands[i];
        if (!path_valid(spec->path) || !spec->summary || !spec->summary[0] ||
            !enum_values_valid(spec) || !csv_valid_paths(spec->aliases)) {
            if (why) snprintf(why, why_size, "malformed command at index %zu", i);
            return false;
        }
        if (spec->parent && spec->parent[0] && !path_valid(spec->parent)) {
            if (why) snprintf(why, why_size, "invalid parent for %s", spec->path);
            return false;
        }
        if (command_is_branch(spec)) {
            if (spec->handler || spec->availability != ZCL_COMMAND_READY) {
                if (why) snprintf(why, why_size,
                                  "branch %s must be ready without handler",
                                  spec->path);
                return false;
            }
        } else {
            if (!spec->input_schema || !spec->input_schema[0] ||
                !spec->output_schema || !spec->output_schema[0] ||
                !spec->example || !spec->example[0]) {
                if (why) snprintf(why, why_size,
                                  "leaf %s lacks schema/example", spec->path);
                return false;
            }
            if (spec->availability == ZCL_COMMAND_READY && !spec->handler) {
                if (why) snprintf(why, why_size,
                                  "ready leaf %s lacks handler", spec->path);
                return false;
            }
            if (spec->availability == ZCL_COMMAND_PLANNED && spec->handler) {
                if (why) snprintf(why, why_size,
                                  "planned leaf %s has handler", spec->path);
                return false;
            }
            if (spec->availability == ZCL_COMMAND_READY &&
                (!spec->semantics || !spec->semantics[0] ||
                 strcmp(spec->semantics, spec->summary) == 0)) {
                if (why) snprintf(why, why_size,
                                  "ready leaf %s lacks distinct semantics",
                                  spec->path);
                return false;
            }
        }
        if (spec->budget_bytes != 0 &&
            (spec->budget_bytes < 256 || spec->budget_bytes > 65536)) {
            if (why) snprintf(why, why_size,
                              "leaf %s budget_bytes out of range", spec->path);
            return false;
        }
        if (spec->availability != ZCL_COMMAND_READY &&
            (!spec->availability_reason || !spec->availability_reason[0])) {
            if (why) snprintf(why, why_size,
                              "non-ready %s lacks reason", spec->path);
            return false;
        }
        if (spec->effect == ZCL_COMMAND_EFFECT_READ &&
            spec->risk != ZCL_COMMAND_RISK_READ) {
            if (why) snprintf(why, why_size,
                              "read effect/risk conflict for %s", spec->path);
            return false;
        }
        const uint32_t known_traits =
            ZCL_COMMAND_TRAIT_DETERMINISTIC |
            ZCL_COMMAND_TRAIT_REVERSIBLE |
            ZCL_COMMAND_TRAIT_IDEMPOTENT |
            ZCL_COMMAND_TRAIT_DRY_RUN |
            ZCL_COMMAND_TRAIT_DEV_ONLY |
            ZCL_COMMAND_TRAIT_DISPLAY_ONLY;
        if ((spec->traits & ~known_traits) != 0) {
            if (why) snprintf(why, why_size,
                              "unknown command trait for %s", spec->path);
            return false;
        }
        if ((spec->traits & ZCL_COMMAND_TRAIT_DISPLAY_ONLY) != 0 &&
            (spec->effect != ZCL_COMMAND_EFFECT_MUTATE ||
             spec->risk != ZCL_COMMAND_RISK_APP_WRITE ||
             spec->confirmation != ZCL_COMMAND_CONFIRM_NONE ||
             spec->required_capabilities != ZCL_COMMAND_CAP_NONE)) {
            if (why) snprintf(why, why_size,
                              "display-only contract conflict for %s",
                              spec->path);
            return false;
        }
        for (size_t j = 0; j < i; j++) {
            const struct zcl_command_spec *other = &registry->commands[j];
            if (strcmp(spec->path, other->path) == 0 ||
                csv_token_equal(spec->aliases, other->path) ||
                csv_token_equal(other->aliases, spec->path)) {
                if (why) snprintf(why, why_size,
                                  "path/alias collision for %s", spec->path);
                return false;
            }
            const char *at = spec->aliases;
            while (at && *at) {
                const char *end = strchr(at, ',');
                size_t len = end ? (size_t)(end - at) : strlen(at);
                char token[ZCL_COMMAND_MAX_PATH];
                memcpy(token, at, len);
                token[len] = 0;
                if (csv_token_equal(other->aliases, token)) {
                    if (why) snprintf(why, why_size,
                                      "duplicate alias %s", token);
                    return false;
                }
                if (!end)
                    break;
                at = end + 1;
            }
        }
        if (spec->parent && spec->parent[0]) {
            bool found_parent = false;
            for (size_t j = 0; j < registry->count; j++) {
                if (strcmp(registry->commands[j].path, spec->parent) == 0 &&
                    command_is_branch(&registry->commands[j])) {
                    found_parent = true;
                    break;
                }
            }
            if (!found_parent) {
                if (why) snprintf(why, why_size,
                                  "missing branch parent %s for %s",
                                  spec->parent, spec->path);
                return false;
            }
        }
    }
    return true;
}

const struct zcl_command_spec *zcl_command_registry_find(
    const struct zcl_command_registry *registry, const char *path_or_alias,
    bool *was_alias)
{
    if (was_alias)
        *was_alias = false;
    if (!registry || !path_or_alias || !path_or_alias[0])
        return NULL;
    for (size_t i = 0; i < registry->count; i++) {
        if (strcmp(registry->commands[i].path, path_or_alias) == 0)
            return &registry->commands[i];
    }
    for (size_t i = 0; i < registry->count; i++) {
        if (csv_token_equal(registry->commands[i].aliases, path_or_alias)) {
            if (was_alias)
                *was_alias = true;
            return &registry->commands[i];
        }
    }
    return NULL;
}

const struct zcl_command_spec *zcl_command_registry_resolve_words(
    const struct zcl_command_registry *registry,
    const char *const *words, size_t word_count, size_t *consumed,
    bool *was_alias, char *invoked, size_t invoked_size)
{
    if (consumed)
        *consumed = 0;
    if (was_alias)
        *was_alias = false;
    if (invoked && invoked_size)
        invoked[0] = 0;
    if (!registry || !words || word_count == 0)
        return NULL;

    char candidate[ZCL_COMMAND_MAX_PATH] = {0};
    size_t pos = 0;
    const struct zcl_command_spec *best = NULL;
    size_t best_count = 0;
    bool best_alias = false;
    for (size_t i = 0; i < word_count; i++) {
        const char *word = words[i];
        if (!word || !word[0] || word[0] == '-' || strchr(word, '.') ||
            strchr(word, '/') || strchr(word, '\\'))
            break;
        int n = snprintf(candidate + pos, sizeof(candidate) - pos,
                         "%s%s", pos ? "." : "", word);
        if (n <= 0 || (size_t)n >= sizeof(candidate) - pos)
            break;
        pos += (size_t)n;
        bool alias = false;
        const struct zcl_command_spec *found =
            zcl_command_registry_find(registry, candidate, &alias);
        if (found) {
            best = found;
            best_count = i + 1;
            best_alias = alias;
            if (invoked && invoked_size)
                (void)copy_string(invoked, invoked_size, candidate);
        }
    }
    if (consumed)
        *consumed = best_count;
    if (was_alias)
        *was_alias = best_alias;
    return best;
}
#endif

/* ── Per-key input value bounds ──────────────────────────────────────────
 *
 * WHY THE DEFAULT IS 4096, AND WHAT IT PROTECTS. The default branch of
 * zcl_command_registry_input_validate() types every key the chain does not
 * name as a string and refuses one longer than ZCL_COMMAND_INPUT_STR_MAX.
 * That number is not protecting a parser (lib/json bounds nesting depth, not
 * string length), a log line (no dispatch path logs an input value), or the
 * reply frame (replies are built from handler output, never echoed input).
 * It is the "no input key is unbounded" floor: it caps how much a caller can
 * make the process hold and hash for ONE argument, and it keeps a typical
 * document inside the shared command frame. It is a property of the DEFAULT
 * — of not knowing what the key carries — not a property of any key.
 *
 * So it is exactly wrong for a key whose value is a hex-encoded wire object
 * that already has a published maximum. A package manifest is bounded by
 * VCS_PACKAGE_MANIFEST_MAX_WIRE_BYTES (1 MiB); hex doubles that to 2 MiB of
 * characters. Capping it at 4096 capped a publishable manifest at ~2 KB of
 * wire — roughly three files — so `zcode package publish` worked only for
 * toy packages. Raising the default instead would hand every other key the
 * same 2 MiB, which is the opposite of a bound.
 *
 * Each entry below is DERIVED from the constant that already governs that
 * key's wire, doubled for hex. This function is the single source of truth
 * for "how long may this key be": the validator calls it (it is not restated
 * inline anywhere) and zcl_command_registry_input_budget_bytes() calls it to
 * size the read frame, so validator and reader cannot drift apart. */
#define ZCL_COMMAND_INPUT_STR_MAX 4096u
/* `files` is an ARRAY key, so its bound is two numbers rather than one.
 * Defined here, consumed by the array branch of the validator and by the
 * budget sum — neither restates a literal. */
#define ZCL_COMMAND_INPUT_FILES_MAX_ITEMS 256u
#define ZCL_COMMAND_INPUT_FILES_PATH_MAX 1024u

size_t zcl_command_registry_input_str_max(const char *key)
{
    if (!key || !key[0])
        return ZCL_COMMAND_INPUT_STR_MAX;
    /* Hex of a canonical package-release envelope (zcode.package.publish.*). */
    if (strcmp(key, "release_hex") == 0)
        return 2u * (size_t)VCS_PACKAGE_RELEASE_MAX_WIRE_BYTES;
    /* Hex of a content.v2 package manifest — the key that made this whole
     * bound load-bearing: one entry per file, up to VCS_PACKAGE_MAX_FILES. */
    if (strcmp(key, "manifest_hex") == 0)
        return 2u * (size_t)VCS_PACKAGE_MANIFEST_MAX_WIRE_BYTES;
    /* Hex of a declarative build recipe (zcode.package.recipe wire). */
    if (strcmp(key, "recipe_hex") == 0)
        return 2u * (size_t)VCS_PACKAGE_RECIPE_MAX_WIRE_BYTES;
    /* Canonical hex of the bounded inline c23_corpus_checkpoint.v1 read.
     * The static verifier derives its wire and shard ceilings by querying
     * this same rule, so the transport can neither truncate an admitted
     * checkpoint nor silently widen the handler. */
    if (strcmp(key, "checkpoint") == 0)
        return ZCL_COMMAND_MAX_INPUT;
    /* Canonical hex of the bounded inline c23_corpus_shard.v1 read. */
    if (strcmp(key, "shard") == 0)
        return ZCL_COMMAND_MAX_INPUT;
    /* transaction_controller.c uses a 2,000,000-byte canonical transaction
     * buffer for create/sign. Hex doubles the wire size. */
    if (strcmp(key, "raw_hex") == 0)
        return 4000000u;
    return ZCL_COMMAND_INPUT_STR_MAX;
}

/* Bytes one JSON member costs at its bound: `"key":<value>,`. Strings add
 * two quotes; the trailing comma is charged to every member (one member
 * overpays by a byte, which is slack, not drift). */
static size_t input_member_budget(const char *key, size_t key_len)
{
    size_t value_max;
    if (key_len == 5 && memcmp(key, "files", 5) == 0)
        value_max = 2u + ZCL_COMMAND_INPUT_FILES_MAX_ITEMS *
                             (ZCL_COMMAND_INPUT_FILES_PATH_MAX + 3u);
    else if ((key_len == 7 && memcmp(key, "effects", 7) == 0) ||
             (key_len == 6 && memcmp(key, "inputs", 6) == 0) ||
             (key_len == 7 && memcmp(key, "outputs", 7) == 0) ||
             (key_len == 7 && memcmp(key, "prevtxs", 7) == 0))
        value_max = ZCL_COMMAND_MAX_INPUT;
    else
        value_max = 2u + zcl_command_registry_input_str_max(key);
    return key_len + 4u + value_max;
}

size_t zcl_command_registry_input_budget_bytes(
    const struct zcl_command_spec *spec)
{
    size_t total = 3; /* '{', '}', NUL */
    const char *csv = spec ? spec->input_keys : NULL;
    char token[128];
    while (csv && *csv) {
        const char *end = strchr(csv, ',');
        size_t len = end ? (size_t)(end - csv) : strlen(csv);
        if (len > 0 && len < sizeof(token)) {
            memcpy(token, csv, len);
            token[len] = 0;
            total += input_member_budget(token, len);
        }
        if (!end)
            break;
        csv = end + 1;
    }
    /* Floor, never ceiling: a leaf whose keys are all small keeps the frame
     * it has always had, so this change can only widen, never tighten. */
    return total < ZCL_COMMAND_MAX_INPUT ? ZCL_COMMAND_MAX_INPUT : total;
}

bool zcl_command_registry_input_validate(const struct zcl_command_spec *spec,
                                         const struct json_value *input,
                                         char *why, size_t why_size)
{
    if (why && why_size)
        why[0] = 0;
    if (!spec || !input || input->type != JSON_OBJ) {
        if (why) snprintf(why, why_size, "input must be one JSON object");
        return false;
    }
    if (strcmp(spec->input_schema, "zcl.command.empty_input.v1") == 0 &&
        input->num_children != 0) {
        if (why) snprintf(why, why_size, "command accepts no input keys");
        return false;
    }
    for (size_t i = 0; i < input->num_children; i++) {
        const char *key = input->keys[i];
        if (!key || !key[0] || !csv_token_equal(spec->input_keys, key)) {
            if (why) snprintf(why, why_size, "unknown input key '%s'",
                              key ? key : "");
            return false;
        }
        for (size_t j = 0; j < i; j++) {
            if (input->keys[j] && strcmp(input->keys[j], key) == 0) {
                if (why) snprintf(why, why_size, "duplicate input key '%s'", key);
                return false;
            }
        }
        const struct json_value *value = &input->children[i];
        bool type_ok = false;
        if (strcmp(key, "files") == 0) {
            type_ok = value->type == JSON_ARR &&
                      value->num_children <= ZCL_COMMAND_INPUT_FILES_MAX_ITEMS;
            for (size_t j = 0; type_ok && j < value->num_children; j++) {
                const struct json_value *item = &value->children[j];
                const char *text = json_get_str(item);
                type_ok = item->type == JSON_STR && text && text[0] &&
                          strlen(text) <= ZCL_COMMAND_INPUT_FILES_PATH_MAX;
            }
        } else if (strcmp(key, "verbose") == 0 ||
                   strcmp(key, "details") == 0 ||
                   strcmp(key, "confirm") == 0 ||
                   strcmp(key, "enabled") == 0 ||
                   strcmp(key, "relink_generation") == 0 ||
                   strcmp(key, "wait_for_edit") == 0 ||
                   strcmp(key, "all") == 0 ||
                   strcmp(key, "allow_high_fees") == 0) {
            /* `all` is app.shop.want.list's "include expired and cancelled
             * rows" flag — a bool in its declared schema; the default
             * string branch made it uninvokable from the shell. */
            type_ok = value->type == JSON_BOOL;
        } else if (strcmp(key, "effects") == 0) {
            /* vault.intent.plan owns the strict nested effect contract. The
             * transport must nevertheless admit the declared array shape;
             * treating an unruled key as a string made the command's own
             * documented multi-recipient example impossible to invoke. */
            type_ok = value->type == JSON_ARR &&
                      value->num_children >= 1u &&
                      value->num_children <= 50u;
        } else if (strcmp(key, "public_keys") == 0) {
            /* P2SH multisig composition accepts public material only. Keep
             * the transport shape aligned with the handler so the documented
             * JSON array reaches it instead of being rejected as a string. */
            type_ok = value->type == JSON_ARR &&
                      value->num_children >= 1u &&
                      value->num_children <= 16u;
            for (size_t j = 0; type_ok && j < value->num_children; j++) {
                const struct json_value *item = &value->children[j];
                const char *text = json_get_str(item);
                size_t len = text ? strlen(text) : 0;
                type_ok = item->type == JSON_STR &&
                          (len == 66u || len == 130u);
                for (size_t k = 0; type_ok && k < len; k++)
                    type_ok = isxdigit((unsigned char)text[k]) != 0;
            }
        } else if (strcmp(key, "inputs") == 0 ||
                   strcmp(key, "prevtxs") == 0) {
            type_ok = value->type == JSON_ARR &&
                      value->num_children <= 256u;
        } else if (strcmp(key, "read_only_verbs") == 0 ||
                   strcmp(key, "object_roots") == 0 ||
                   strcmp(key, "capability_roots") == 0 ||
                   strcmp(key, "service_roots") == 0 ||
                   strcmp(key, "portal_roots") == 0 ||
                   strcmp(key, "starting_roots") == 0) {
            /* Space manifest/service root sets, service verb sets, and
             * scout starting roots are bounded string arrays. The handlers
             * own the exact grammar (64-hex roots, uniqueness, the four
             * read-only verb names, the per-set caps); the transport only
             * admits the declared array-of-strings shape. Without this rule
             * the default branch demanded a string and every one of these
             * leaves was uninvokable from the shell. */
            type_ok = value->type == JSON_ARR && value->num_children <= 64u;
            for (size_t j = 0; type_ok && j < value->num_children; j++) {
                const struct json_value *item = &value->children[j];
                const char *text = json_get_str(item);
                type_ok = item->type == JSON_STR && text && text[0] &&
                          strlen(text) <= 64u;
            }
        } else if (strcmp(key, "outputs") == 0) {
            type_ok = value->type == JSON_OBJ &&
                      value->num_children <= 256u;
        } else if (strcmp(key, "seed") == 0) {
            type_ok = (value->type == JSON_INT && json_get_int(value) > 0) ||
                      (value->type == JSON_STR && json_get_str(value) &&
                       json_get_str(value)[0] && strlen(json_get_str(value)) <= 32);
        } else if (strcmp(key, "amount") == 0) {
            type_ok = value->type == JSON_INT || value->type == JSON_REAL ||
                      (value->type == JSON_STR && json_get_str(value) &&
                       json_get_str(value)[0] && strlen(json_get_str(value)) <= 64);
        } else if (strcmp(key, "units") == 0 ||
                   strcmp(key, "supply") == 0) {
            /* ZSLP amounts are indivisible base units. The backing RPC
             * parser (zslp_tx_rpc_units, zslp_transaction_rpc.c) takes only
             * an unsigned decimal string, and the write-handler leaf
             * (AWN_U64_STR, app_write_native_handlers.c) forwards strings
             * verbatim and renders a positive JSON_INT to its decimal
             * string — so both forms are valid here: the string form of the
             * app_features.def examples ("supply":"1000") and the int form
             * of the vault.def send-token example ("units":25). The string
             * rule mirrors the RPC parser: nonempty digits, nonzero, with a
             * coarse 20-char u64 bound (the RPC owns exact overflow). */
            const char *s = json_get_str(value);
            type_ok = value->type == JSON_INT && json_get_int(value) > 0;
            if (!type_ok && value->type == JSON_STR && s && s[0] &&
                strlen(s) <= 20) {
                bool nonzero = false;
                type_ok = true;
                for (const unsigned char *p = (const unsigned char *)s; *p;
                     p++) {
                    if (*p < '0' || *p > '9') { type_ok = false; break; }
                    if (*p != '0') nonzero = true;
                }
                type_ok = type_ok && nonzero;
            }
        } else if (strcmp(key, "decimals") == 0) {
            type_ok = value->type == JSON_INT && json_get_int(value) >= 0 &&
                      json_get_int(value) <= 8;
        } else if (strcmp(key, "required_signatures") == 0) {
            /* Multisig threshold; the handler additionally checks it does
             * not exceed the supplied public-key count. */
            type_ok = value->type == JSON_INT &&
                      json_get_int(value) >= 1 &&
                      json_get_int(value) <= 16;
        } else if (strcmp(key, "action_mask") == 0) {
            /* Seven local-sovereignty actions occupy bits 0..6. Keep this
             * transport validator aligned with the policy handler so the
             * leaf's exact 1..127 contract reaches plan/commit unchanged. */
            type_ok = value->type == JSON_INT && json_get_int(value) >= 1 &&
                      json_get_int(value) <= 127;
        } else if (strcmp(key, "cursor") == 0) {
            type_ok = (value->type == JSON_INT && json_get_int(value) >= 0) ||
                      (value->type == JSON_STR && json_get_str(value) &&
                       json_get_str(value)[0] && strlen(json_get_str(value)) <= 256);
        } else if (strcmp(key, "raw_offset") == 0) {
            /* Byte offset into core.chain.transaction.get raw mode. */
            type_ok = value->type == JSON_INT && json_get_int(value) >= 0;
        } else if (strcmp(key, "raw_bytes") == 0) {
            /* Keep the hex-doubled page inside the ordinary result budget. */
            type_ok = value->type == JSON_INT && json_get_int(value) >= 1 &&
                      json_get_int(value) <= 1024;
        } else if (strcmp(key, "slot") == 0) {
            /* app.transaction-types.micro-lab has exactly 100 stable,
             * one-based campaign slots.  The CLI types --slot=91 as an
             * integer; without this rule the default string branch makes the
             * documented native fast path uncallable before its handler. */
            type_ok = value->type == JSON_INT && json_get_int(value) >= 1 &&
                      json_get_int(value) <= 100;
        } else if (strcmp(key, "height") == 0 ||
                   strcmp(key, "start_height") == 0 ||
                   strcmp(key, "after") == 0 ||
                   strcmp(key, "after_epoch") == 0) {
            type_ok = value->type == JSON_INT && json_get_int(value) >= 0;
        } else if (strcmp(key, "day") == 0) {
            /* Civil day number (unix/86400) — the deterministic window
             * pin every zcode reward/badge/seed/fetch surface takes. */
            type_ok = value->type == JSON_INT && json_get_int(value) >= 0;
        } else if (strcmp(key, "now_unix") == 0 ||
                   strcmp(key, "now") == 0 ||
                   strcmp(key, "created_at") == 0 ||
                   strcmp(key, "expires") == 0 ||
                   strcmp(key, "expires_at") == 0 ||
                   strcmp(key, "issued_unix") == 0 ||
                   strcmp(key, "expires_unix") == 0) {
            /* Explicit Unix timestamps. now_unix is the deterministic
             * submission-window pin used by zcode.science; created_at and
             * expires_at are the ZPAY envelope bounds (and existing build
             * worker fields); issued_unix and expires_unix bound the
             * app.shop.want.post advertisement window; expires/now are the
             * zses:v1 invite window. Without this rule the default branch
             * demands a string while every handler reads JSON_INT, making
             * the declared commands uninvokable through the CLI. */
            type_ok = value->type == JSON_INT && json_get_int(value) >= 0;
        } else if (strcmp(key, "amount_zatoshi") == 0) {
            /* app.shop.want.post declared payment terms (uint64 in struct
             * shop_want_v1, app/models/include/models/shop_want.h). Without
             * this rule the default branch demands a string and rejects the
             * leaf's OWN declared example (`"amount_zatoshi":500000`), so
             * the leaf is uninvokable from the shell. Capped at the 21M-ZCL
             * supply so a nonsense amount is refused up front; the handler
             * owns the exact >0 rule as BAD_AMOUNT. */
            type_ok = value->type == JSON_INT && json_get_int(value) > 0 &&
                      json_get_int(value) <= 2100000000000000LL;
        } else if (strcmp(key, "nonce") == 0) {
            /* app.shop.want.post's replay nonce is a positive integer, but
             * app.auth.verify's nonce is an opaque server-issued STRING that
             * already passed the default branch. Admit both shapes and let
             * each handler own its strict rule (BAD_NONCE / the auth flow's
             * own refusal) so the same mistake reports the same code over
             * every transport. */
            type_ok = (value->type == JSON_INT && json_get_int(value) >= 1) ||
                      (value->type == JSON_STR && json_get_str(value) &&
                       json_get_str(value)[0] &&
                       strlen(json_get_str(value)) <=
                           zcl_command_registry_input_str_max(key));
        } else if (strcmp(key, "sequence") == 0 ||
                   strcmp(key, "not_before") == 0 ||
                   strcmp(key, "expiry") == 0 ||
                   strcmp(key, "observation_unix") == 0) {
            /* Space manifests, scout missions, and the zcode.network
             * publish/storage_ack records all carry positive integer
             * sequence/window fields; every declared example types them as
             * integers and every handler reads JSON_INT (mvspace_int,
             * scout_int). The default string branch made
             * metaverse.space.plan|commit and metaverse.space.scout.plan|run
             * uninvokable through the typed CLI: an integer failed here and
             * a numeric string passed here only to read as 0 in the handler
             * (json_get_int on a JSON_STR), which then refused with
             * BAD_MANIFEST/BAD_SCOUT_MISSION. */
            type_ok = value->type == JSON_INT && json_get_int(value) >= 1;
        } else if (strcmp(key, "maximum_depth") == 0) {
            /* Scout traversal bound: 0 is "the starting roots only". The
             * cap mirrors VCS_SPACE_SCOUT_DEPTH_MAX. */
            type_ok = value->type == JSON_INT && json_get_int(value) >= 0 &&
                      json_get_int(value) <= 8;
        } else if (strcmp(key, "maximum_spaces") == 0) {
            /* Cap mirrors VCS_SPACE_SCOUT_SPACES_MAX. */
            type_ok = value->type == JSON_INT && json_get_int(value) >= 1 &&
                      json_get_int(value) <= 32;
        } else if (strcmp(key, "maximum_portals") == 0) {
            /* Cap mirrors VCS_SPACE_SCOUT_PORTALS_MAX. */
            type_ok = value->type == JSON_INT && json_get_int(value) >= 1 &&
                      json_get_int(value) <= 64;
        } else if (strcmp(key, "maximum_bytes") == 0) {
            /* `maximum_bytes` is shared by two unrelated protocols. A source
             * package fetch must admit the complete carrier (the publication
             * contract caps it at 256 MiB), while space scouting keeps its
             * much smaller traversal budget. A key-global 8 MiB cap made the
             * documented zcode.package.fetch example uninvokable before its
             * handler or authenticated DHT route could run. */
            int64_t maximum =
                spec->path && strcmp(spec->path, "zcode.package.fetch") == 0
                    ? 256LL * 1024LL * 1024LL
                    : 8LL * 1024LL * 1024LL;
            type_ok = value->type == JSON_INT && json_get_int(value) >= 1 &&
                      json_get_int(value) <= maximum;
        } else if (strcmp(key, "deadline_ms") == 0) {
            /* Cap mirrors VCS_SPACE_SCOUT_DEADLINE_MS_MAX (60 s). */
            type_ok = value->type == JSON_INT && json_get_int(value) >= 1 &&
                      json_get_int(value) <= 60000;
        } else if (strcmp(key, "expires_in_seconds") == 0) {
            /* Owner-gated dev activation plan lifetime. The handler repeats
             * this exact bound; recognizing the integer here lets the typed
             * CLI reach that policy instead of misclassifying it as text. */
            type_ok = value->type == JSON_INT && json_get_int(value) >= 60 &&
                      json_get_int(value) <= 3600;
        } else if (strcmp(key, "challenge_block_height") == 0 ||
                   strcmp(key, "action_sequence") == 0 ||
                   strcmp(key, "result_sequence") == 0 ||
                   strcmp(key, "reproduction_sequence") == 0 ||
                   strcmp(key, "publisher_sequence") == 0 ||
                   strcmp(key, "max") == 0) {
            /* zcode.science int pins the same bug class as now_unix: the
             * handlers read them with json_get_int, so the default string
             * branch made every science leaf that takes one uninvokable
             * from the shell. All are positive in every handler (height
             * and sequences must be nonzero; max is a render cap the
             * handler clamps to its own bound). */
            type_ok = value->type == JSON_INT && json_get_int(value) >= 1;
        } else if (strcmp(key, "min-height") == 0) {
            /* net census height floor: a non-negative advertised height. */
            type_ok = value->type == JSON_INT && json_get_int(value) >= 0;
        } else if (strcmp(key, "seen-within") == 0) {
            /* net census recency window in seconds (0..1y). */
            type_ok = value->type == JSON_INT && json_get_int(value) >= 0 &&
                      json_get_int(value) <= 31536000;
        } else if (strcmp(key, "page") == 0) {
            /* net census zero-based page index. */
            type_ok = value->type == JSON_INT && json_get_int(value) >= 0 &&
                      json_get_int(value) <= 1000000;
        } else if (strcmp(key, "peer_id") == 0) {
            /* app.messaging.send p2p recipient: a connected peer's numeric id
             * as reported by core.network.peers.list. Without this rule the
             * default branch would demand a string and reject `--peer_id=3`,
             * which the CLI types as an integer. */
            type_ok = value->type == JSON_INT && json_get_int(value) >= 0;
        } else if (strcmp(key, "product_id") == 0 ||
                   strcmp(key, "purchase_id") == 0) {
            /* app.store.{order,pay,purchases,collect} row ids. The CLI types
             * a bare integer as JSON_INT and every one of those leaves'
             * declared examples uses one ("product_id":1). Without this rule
             * the default branch demands a string, and a numeric string then
             * fails the handler's json_get_int_or > 0 check — the leaf is
             * uninvokable from the shell either way. The handler owns the
             * real unknown-row refusal (UNKNOWN_PRODUCT / UNKNOWN_PURCHASE),
             * so the only rule here is positive-int. */
            type_ok = value->type == JSON_INT && json_get_int(value) > 0;
        } else if (strcmp(key, "locktime_blocks") == 0) {
            /* app.swap.{initiate,participate} lock DURATION in blocks from the
             * current tip. Range mirrors swap_locktime_to_absolute()
             * (app/controllers/src/swap_controller.c), which refuses anything
             * outside 1..1000000. */
            type_ok = value->type == JSON_INT && json_get_int(value) >= 1 &&
                      json_get_int(value) <= 1000000;
        } else if (strcmp(key, "price_per_mb_zat") == 0) {
            /* app.market.offer asking price per MB in ZATOSHIS (int64 in
             * struct file_offer, lib/net/include/net/file_market.h). Without
             * this rule the default branch demands a string and rejects the
             * leaf's OWN declared example (`price_per_mb_zat:1000`), so the
             * operator got INVALID_INPUT instead of the leaf's PLANNED
             * refusal and never learned why it is closed. Capped at the
             * 21M-ZCL supply so a nonsense price is refused up front. */
            type_ok = value->type == JSON_INT && json_get_int(value) >= 0 &&
                      json_get_int(value) <= 2100000000000000LL;
        } else if (strcmp(key, "chunk_start") == 0 ||
                   strcmp(key, "chunks_paid") == 0) {
            /* app.market.purchase.plan paid chunk range (uint32 in struct
             * market_purchase_request, services/file_market_purchase_internal.h).
             * Without this rule the default branch demands a string and
             * rejects the leaf's OWN declared example
             * (`"chunk_start":0,"chunks_paid":1`), so the leaf is uninvokable
             * from the shell; the RPC handler (rpc_zmarket_purchase_plan)
             * demands JSON_INT, so a string can never reach it either.
             * chunk_start=0 names the first chunk; chunks_paid must pay for
             * at least one. The service owns the exact in-offer range check. */
            type_ok = value->type == JSON_INT &&
                      json_get_int(value) >= (strcmp(key, "chunks_paid") == 0) &&
                      json_get_int(value) <= 4294967295LL;
        } else if (strcmp(key, "recipient_value_zat") == 0) {
            /* Aggregate metaverse liquidity planning uses exact zatoshi.
             * Keep the transport range aligned with the handler: positive,
             * and never above the complete ZCL money supply. */
            type_ok = value->type == JSON_INT && json_get_int(value) > 0 &&
                      json_get_int(value) <= 2100000000000000LL;
        } else if (strcmp(key, "maximum_fee_zat") == 0) {
            /* Zero is a meaningful caller-selected ceiling. The live intent
             * planner owns any stricter fee-policy decision. */
            type_ok = value->type == JSON_INT && json_get_int(value) >= 0 &&
                      json_get_int(value) <= 2100000000000000LL;
        } else if (strcmp(key, "concurrency") == 0) {
            /* Matches the vault intent's maximum structured effects count. */
            type_ok = value->type == JSON_INT && json_get_int(value) >= 1 &&
                      json_get_int(value) <= 50;
        } else if (strcmp(key, "price_zcl") == 0 ||
                   strcmp(key, "price_zatoshi") == 0) {
            /* app.store.list-product asking price, in whichever unit the key
             * names. Typed like `amount` (number or numeric string) and left
             * DELIBERATELY unrestricted beyond that: the handler owns the
             * unit rules and answers with MISSING_PRICE / PRICE_CONFLICT /
             * BAD_PRICE / PRICE_OUT_OF_RANGE, and a coarse range check here
             * would collapse all four into one INVALID_INPUT that tells the
             * merchant nothing about which one they hit. Without this rule
             * the default branch demands a string and rejects the leaf's own
             * declared example. */
            type_ok = value->type == JSON_INT || value->type == JSON_REAL ||
                      (value->type == JSON_STR && json_get_str(value) &&
                       json_get_str(value)[0] &&
                       strlen(json_get_str(value)) <= 64);
        } else if (strcmp(key, "tokens_per_purchase") == 0) {
            /* app.store.list-product tokens minted per purchase. Any
             * non-negative integer reaches the handler, which enforces the
             * real 1..10000 bound as BAD_TOKENS_PER_PURCHASE — so the same
             * mistake reports the same code over every transport. */
            type_ok = value->type == JSON_INT && json_get_int(value) >= 0;
        } else if (spec->path &&
                   strcmp(spec->path, "app.presentation.show") == 0 &&
                   strcmp(key, "items") == 0) {
            /* The renderer-neutral model repeats the exact item shape and
             * count validation. This coarse transport rule only makes its
             * bounded JSON array reachable through the typed CLI. Keep 64
             * aligned with ZCL_PRESENT_MODEL_ITEMS_MAX without making the
             * low-rank command kernel depend upward on lib/presentation. */
            type_ok = value->type == JSON_ARR && json_size(value) <= 64u;
        } else if (spec->path &&
                   strcmp(spec->path, "app.presentation.show") == 0 &&
                   strcmp(key, "actions") == 0) {
            /* Same low-rank mirror for ZCL_PRESENT_MODEL_ACTIONS_MAX. */
            type_ok = value->type == JSON_ARR && json_size(value) <= 4u;
        } else if (strcmp(key, "timeout_ms") == 0) {
            type_ok = value->type == JSON_INT && json_get_int(value) >= 1 &&
                      json_get_int(value) <= 300000;
        } else if (strcmp(key, "heartbeat_ms") == 0) {
            type_ok = value->type == JSON_INT && json_get_int(value) >= 100 &&
                      json_get_int(value) <= 60000;
        } else if (strcmp(key, "max_cpu_seconds") == 0) {
            /* ZCODE task/action CPU ceiling. The work-start and improve
             * handlers own the same closed 1..600 second range; keeping the
             * registry aligned makes their declared typed input reachable. */
            type_ok = value->type == JSON_INT && json_get_int(value) >= 1 &&
                      json_get_int(value) <= 600;
        } else if (strcmp(key, "verbosity") == 0) {
            type_ok = value->type == JSON_INT && json_get_int(value) >= 0 &&
                      json_get_int(value) <= 2;
        } else if (strcmp(key, "max_items") == 0) {
            type_ok = value->type == JSON_INT && json_get_int(value) >= 1 &&
                      json_get_int(value) <= 100;
        } else if (strcmp(key, "max_lines") == 0) {
            type_ok = value->type == JSON_INT && json_get_int(value) >= 1 &&
                      json_get_int(value) <= 1000;
        } else if (strcmp(key, "since_secs") == 0) {
            type_ok = value->type == JSON_INT && json_get_int(value) >= 0 &&
                      json_get_int(value) <= 31536000;
        } else if (strcmp(key, "since") == 0 ||
                   strcmp(key, "since_epoch") == 0) {
            /* ops.telemetry.watch's resume cursor and the feed epoch it was
             * minted under. Both are opaque non-negative counters the leaf
             * itself issued in a previous reply, so the only rule here is the
             * type: 0 is legal and meaningful (`since=0` is "I have nothing",
             * `since_epoch=0` is "I did not record one"). Without this rule
             * the default branch demands a STRING and the CLI's `--since=41`
             * — which types as an integer — is refused as INVALID_INPUT
             * before the handler ever runs, making the leaf uninvokable from
             * the shell exactly as zcode.package.publish.plan once was. */
            type_ok = value->type == JSON_INT && json_get_int(value) >= 0;
        } else if (strcmp(key, "epoch") == 0) {
            /* ZC23 epoch selectors (zcode.commons.epoch, the shadow epoch
             * pair, the schedule propose pair) are non-negative integer
             * epochs; every handler re-validates its own range. Without this
             * rule the default branch demands a STRING and the leaves are
             * uninvokable from the shell. */
            type_ok = value->type == JSON_INT && json_get_int(value) >= 0;
        } else if (strcmp(key, "cutoff_height") == 0 ||
                   strcmp(key, "cutoff_mtp") == 0 ||
                   strcmp(key, "epoch_capacity_atoms") == 0) {
            /* Simulation projections bind their result to an explicit,
             * positive caller-owned cutoff. Handlers re-check semantic
             * ranges; the registry only makes the typed CLI path reachable. */
            type_ok = value->type == JSON_INT && json_get_int(value) > 0;
        } else if (strcmp(key, "limit") == 0 || strcmp(key, "depth") == 0) {
            type_ok = value->type == JSON_INT && json_get_int(value) >= 1 &&
                      json_get_int(value) <= 1000000;
        } else if (strcmp(key, "watcher_id") == 0) {
            type_ok = value->type == JSON_INT && json_get_int(value) > 1;
        } else if (strcmp(key, "seconds") == 0) {
            type_ok = value->type == JSON_INT && json_get_int(value) >= 1 &&
                      json_get_int(value) <= 60;
        } else if (strcmp(key, "top_n") == 0) {
            type_ok = value->type == JSON_INT && json_get_int(value) >= 1 &&
                      json_get_int(value) <= 32;
        } else {
            /* Type and length decided in the same breath: the bound comes
             * from zcl_command_registry_input_str_max(), which is the ONLY
             * place a per-key string length is written down. */
            const char *text = json_get_str(value);
            type_ok = value->type == JSON_STR && text && text[0] &&
                      strlen(text) <= zcl_command_registry_input_str_max(key);
            if (type_ok && strcmp(key, "side") == 0)
                type_ok = strcmp(text, "input") == 0 ||
                          strcmp(text, "output") == 0;
            if (type_ok && strcmp(key, "view") == 0)
                type_ok = strcmp(text, "summary") == 0 ||
                          strcmp(text, "normal") == 0 ||
                          strcmp(text, "full") == 0;
        }
        if (!type_ok) {
            /* An over-long string is the one failure an operator cannot
             * diagnose from "invalid type or range" — the value looks
             * perfectly well-typed. Say the length and the bound, so the
             * refusal names the rule that fired. */
            const char *text = json_get_str(value);
            size_t str_max = zcl_command_registry_input_str_max(key);
            if (why && value->type == JSON_STR && text && strlen(text) > str_max)
                snprintf(why, why_size,
                         "input key '%s' is %zu characters, over its %zu limit",
                         key, strlen(text), str_max);
            else if (why)
                snprintf(why, why_size,
                         "invalid type or range for input key '%s'", key);
            return false;
        }
    }

    /* Required discovery inputs appear in every error path, so accepting `{}`
     * here would let a malformed next action false-green before failing on
     * invocation. `discover.help` deliberately shares the path-input schema
     * but makes path optional, so bind requiredness to the exact leaf until
     * required-key metadata is promoted into the catalog. */
    const char *required_key = NULL;
    if (strcmp(spec->path, "discover.search") == 0)
        required_key = "query";
    else if (strcmp(spec->path, "discover.describe") == 0 ||
             strcmp(spec->path, "discover.schema") == 0)
        required_key = "path";
    if (required_key) {
        const char *value = json_get_str(json_get(input, required_key));
        if (!value || !value[0]) {
            if (why)
                snprintf(why, why_size, "missing required input key '%s'",
                         required_key);
            return false;
        }
    }
    return true;
}

#ifndef ZCL_HOTFORK_COMMAND_INPUT_CORE
static void digest_text(struct sha256_ctx *sha, const char *value)
{
    static const unsigned char separator = 0;
    const char *text = value ? value : "";
    sha256_write(sha, (const unsigned char *)text, strlen(text));
    sha256_write(sha, &separator, 1);
}

void zcl_command_registry_digest(const struct zcl_command_registry *registry,
                                 char out[72])
{
    if (!out)
        return;
    struct sha256_ctx sha;
    unsigned char hash[SHA256_OUTPUT_SIZE];
    sha256_init(&sha);
    if (registry) {
        for (size_t i = 0; i < registry->count; i++) {
            const struct zcl_command_spec *spec = &registry->commands[i];
            digest_text(&sha, spec->path);
            digest_text(&sha, spec->parent);
            digest_text(&sha, spec->aliases);
            digest_text(&sha, spec->summary);
            digest_text(&sha, spec->tags);
            digest_text(&sha, spec->input_schema);
            digest_text(&sha, spec->output_schema);
            digest_text(&sha, spec->input_keys);
            digest_text(&sha, spec->positional_keys);
            unsigned char typed[] = {
                (unsigned char)spec->layer,
                (unsigned char)spec->effect,
                (unsigned char)spec->risk,
                (unsigned char)spec->scope,
                (unsigned char)spec->authority,
                (unsigned char)spec->availability,
                (unsigned char)spec->mode,
                (unsigned char)spec->latency,
                (unsigned char)spec->cost,
                (unsigned char)spec->confirmation,
            };
            sha256_write(&sha, typed, sizeof(typed));
        }
    }
    sha256_finalize(&sha, hash);
    memcpy(out, "sha256:", 7);
    for (size_t i = 0; i < sizeof(hash); i++)
        (void)snprintf(out + 7 + i * 2, 3, "%02x", hash[i]);
    out[71] = 0;
}

static bool push_string_array_csv(struct json_value *object, const char *key,
                                  const char *csv)
{
    struct json_value array;
    json_init(&array);
    json_set_array(&array);
    const char *at = csv;
    while (at && *at) {
        const char *end = strchr(at, ',');
        size_t len = end ? (size_t)(end - at) : strlen(at);
        char token[ZCL_COMMAND_MAX_PATH];
        if (len == 0 || len >= sizeof(token)) {
            json_free(&array);
            return false;
        }
        memcpy(token, at, len);
        token[len] = 0;
        struct json_value item;
        json_init(&item);
        json_set_str(&item, token);
        bool ok = json_push_back(&array, &item);
        json_free(&item);
        if (!ok) {
            json_free(&array);
            return false;
        }
        if (!end)
            break;
        at = end + 1;
    }
    bool ok = json_push_kv(object, key, &array);
    json_free(&array);
    return ok;
}

static bool push_child_summary(struct json_value *children,
                               const struct zcl_command_spec *spec)
{
    struct json_value child;
    json_init(&child);
    json_set_object(&child);
    bool ok = json_push_kv_str(&child, "path", spec->path) &&
              json_push_kv_str(&child, "summary", spec->summary) &&
              json_push_kv_str(&child, "risk",
                               zcl_command_risk_name(spec->risk)) &&
              json_push_kv_str(&child, "latency",
                               zcl_command_latency_name(spec->latency)) &&
              json_push_kv_str(&child, "availability",
                               zcl_command_availability_name(
                                   spec->availability)) &&
              json_push_back(children, &child);
    json_free(&child);
    return ok;
}

static size_t write_bounded_json(struct json_value *root, char *out,
                                 size_t out_size, size_t contract_budget)
{
    if (!root || !out || out_size == 0)
        return 0;
    size_t need = json_write(root, out, out_size);
    if (need >= out_size || need > contract_budget) {
        if (out_size)
            out[0] = 0;
        return 0;
    }
    return need;
}

size_t zcl_command_registry_menu_json(const struct zcl_command_registry *registry,
                                      const char *path, char *out,
                                      size_t out_size)
{
    const char *wanted = path && path[0] && strcmp(path, "root") != 0
        ? path : "";
    const struct zcl_command_spec *node = NULL;
    if (wanted[0]) {
        node = zcl_command_registry_find(registry, wanted, NULL);
        if (!node)
            return 0;
        if (!command_is_branch(node))
            return zcl_command_registry_describe_json(registry, wanted,
                                                       out, out_size);
    }

    char digest[72];
    zcl_command_registry_digest(registry, digest);
    struct json_value root, children;
    json_init(&root);
    json_init(&children);
    json_set_object(&root);
    json_set_array(&children);
    bool ok = json_push_kv_str(&root, "schema", "zcl.command_menu.v1") &&
              json_push_kv_str(&root, "path", wanted[0] ? wanted : "root") &&
              json_push_kv_str(&root, "summary",
                               node ? node->summary :
                               "Z23 sovereign command interface") &&
              json_push_kv_str(&root, "registry_digest", digest);
    for (size_t i = 0; ok && registry && i < registry->count; i++) {
        const char *parent = registry->commands[i].parent;
        if (strcmp(parent ? parent : "", wanted) == 0)
            ok = push_child_summary(&children, &registry->commands[i]);
    }
    ok = ok && json_push_kv(&root, "children", &children);
    if (children.num_children > 0) {
        const struct json_value *first = json_at(&children, 0);
        const char *next_path = json_get_str(json_get(first, "path"));
        struct json_value next, empty;
        json_init(&next);
        json_init(&empty);
        json_set_object(&next);
        json_set_object(&empty);
        ok = ok && json_push_kv_str(&next, "command", "discover.describe") &&
             json_push_kv_str(&empty, "path", next_path) &&
             json_push_kv(&next, "input", &empty) &&
             json_push_kv(&root, "next", &next);
        json_free(&empty);
        json_free(&next);
    }
    size_t result = ok
        ? write_bounded_json(&root, out, out_size,
                             wanted[0] ? ZCL_COMMAND_BRANCH_BUDGET
                                       : ZCL_COMMAND_ROOT_BUDGET)
        : 0;
    json_free(&children);
    json_free(&root);
    return result;
}

size_t zcl_command_registry_describe_json(
    const struct zcl_command_registry *registry, const char *path,
    char *out, size_t out_size)
{
    bool alias = false;
    const struct zcl_command_spec *spec =
        zcl_command_registry_find(registry, path, &alias);
    if (!spec)
        return 0;
    if (command_is_branch(spec))
        return zcl_command_registry_menu_json(registry, spec->path,
                                              out, out_size);

    char digest[72];
    zcl_command_registry_digest(registry, digest);
    struct json_value root, input, policy;
    json_init(&root);
    json_init(&input);
    json_init(&policy);
    json_set_object(&root);
    json_set_object(&input);
    json_set_object(&policy);
    /* OS-B2: measured latency for this leaf (process-lifetime; empty on a fresh
     * CLI process — see the ring's PROCESS-LIFETIME CAVEAT). */
    int64_t observed_p99_us = 0;
    uint32_t observed_samples = 0;
    (void)latency_ring_p99(registry, spec, &observed_p99_us, &observed_samples);
    bool ok = json_push_kv_str(&root, "schema", "zcl.command_spec.v1") &&
              json_push_kv_str(&root, "path", spec->path) &&
              json_push_kv_str(&root, "summary", spec->summary) &&
              json_push_kv_str(&root, "availability",
                               zcl_command_availability_name(
                                   spec->availability));
    if (spec->semantics && spec->semantics[0])
        ok = ok && json_push_kv_str(&root, "semantics", spec->semantics);
    if (spec->availability_reason && spec->availability_reason[0])
        ok = ok && json_push_kv_str(&root, "availability_reason",
                                    spec->availability_reason);
    ok = ok && json_push_kv_str(&root, "registry_digest", digest) &&
         json_push_kv_str(&input, "id", spec->input_schema) &&
         push_string_array_csv(&input, "allowed_keys", spec->input_keys) &&
         push_string_array_csv(&input, "positional_keys",
                               spec->positional_keys) &&
         json_push_kv(&root, "input_schema", &input) &&
         json_push_kv_str(&root, "output_schema", spec->output_schema) &&
         json_push_kv_str(&policy, "layer",
                          zcl_command_layer_name(spec->layer)) &&
         json_push_kv_str(&policy, "effect",
                          zcl_command_effect_name(spec->effect)) &&
         json_push_kv_str(&policy, "risk",
                          zcl_command_risk_name(spec->risk)) &&
         json_push_kv_str(&policy, "scope",
                          zcl_command_scope_name(spec->scope)) &&
         json_push_kv_str(&policy, "authority",
                          zcl_command_authority_name(spec->authority)) &&
         json_push_kv_str(&policy, "mode",
                          zcl_command_mode_name(spec->mode)) &&
         json_push_kv_str(&policy, "latency",
                          zcl_command_latency_name(spec->latency)) &&
         json_push_kv_str(&policy, "cost",
                          zcl_command_cost_name(spec->cost)) &&
         json_push_kv_str(&policy, "confirmation",
                          zcl_command_confirmation_name(spec->confirmation)) &&
         json_push_kv_bool(&policy, "deterministic",
                           (spec->traits & ZCL_COMMAND_TRAIT_DETERMINISTIC) != 0) &&
         json_push_kv_bool(&policy, "idempotent",
                           (spec->traits & ZCL_COMMAND_TRAIT_IDEMPOTENT) != 0) &&
         json_push_kv_bool(&policy, "display_only",
                           (spec->traits &
                            ZCL_COMMAND_TRAIT_DISPLAY_ONLY) != 0) &&
         json_push_kv_int(&policy, "allowed_lanes", spec->allowed_lanes) &&
         json_push_kv_int(&policy, "required_capabilities",
                          (int64_t)spec->required_capabilities) &&
         json_push_kv_int(&policy, "budget_bytes",
                          spec->budget_bytes > 0
                              ? spec->budget_bytes
                              : (int64_t)ZCL_COMMAND_RESULT_BUDGET) &&
         json_push_kv_int(&policy, "budget_ms",
                          zcl_command_latency_budget_ms(spec->latency)) &&
         json_push_kv_int(&policy, "observed_p99_us", observed_p99_us) &&
         json_push_kv_int(&policy, "observed_samples",
                          (int64_t)observed_samples) &&
         json_push_kv(&root, "policy", &policy) &&
         json_push_kv_str(&root, "example", spec->example);
    if (spec->aliases && spec->aliases[0])
        ok = ok && push_string_array_csv(&root, "aliases", spec->aliases);
    if (alias)
        ok = ok && json_push_kv_str(&root, "canonical_path", spec->path);
    size_t result = ok
        ? write_bounded_json(&root, out, out_size, ZCL_COMMAND_SPEC_BUDGET)
        : 0;
    json_free(&policy);
    json_free(&input);
    json_free(&root);
    return result;
}

static bool contains_folded(const char *haystack, const char *needle)
{
    if (!haystack || !needle || !needle[0])
        return false;
    size_t needle_len = strlen(needle);
    for (const unsigned char *h = (const unsigned char *)haystack; *h; h++) {
        size_t i = 0;
        while (i < needle_len && h[i] &&
               tolower(h[i]) == tolower((unsigned char)needle[i]))
            i++;
        if (i == needle_len)
            return true;
    }
    return false;
}

static bool normalize_query(const char *query, char out[129])
{
    if (!query)
        return false;
    size_t pos = 0;
    bool pending_space = false;
    for (const unsigned char *p = (const unsigned char *)query; *p; p++) {
        if (*p < 0x20 && !isspace(*p))
            return false;
        if (isspace(*p)) {
            if (pos)
                pending_space = true;
            continue;
        }
        if (*p >= 0x80 || pos + (pending_space ? 1U : 0U) + 1U >= 129)
            return false;
        if (pending_space)
            out[pos++] = ' ';
        pending_space = false;
        out[pos++] = (char)tolower(*p);
    }
    out[pos] = 0;
    return pos > 0;
}

static int command_match_score(const struct zcl_command_spec *spec,
                               const char *query, const char **reason)
{
    if (strcmp(spec->path, query) == 0) {
        *reason = "exact_path";
        return 1000;
    }
    if (csv_token_equal(spec->aliases, query)) {
        *reason = "exact_alias";
        return 900;
    }
    if (csv_token_equal(spec->tags, query)) {
        *reason = "exact_tag";
        return 700;
    }
    if (strncmp(spec->path, query, strlen(query)) == 0) {
        *reason = "path_prefix";
        return 650;
    }
    if (contains_folded(spec->path, query)) {
        *reason = "path";
        return 550;
    }
    if (contains_folded(spec->tags, query)) {
        *reason = "tag";
        return 450;
    }
    if (contains_folded(spec->summary, query)) {
        *reason = "summary";
        return 300;
    }
    /* Multi-word fallback: a space-separated query ("dev loop") that matched
     * nothing as a single string still matches a command when EVERY word
     * appears (folded) in its path, tags, or summary. This lets natural
     * multi-word queries reach dotted command paths ("dev.loop.status") —
     * where the literal "dev loop" is never a substring. Single-word queries
     * never enter this block (no space), so all scoring above is unchanged. */
    if (strchr(query, ' ')) {
        size_t words = 0, matched = 0;
        for (const char *p = query; *p;) {
            while (*p == ' ')
                p++;
            if (!*p)
                break;
            const char *start = p;
            while (*p && *p != ' ')
                p++;
            size_t wl = (size_t)(p - start);
            char word[129];
            if (wl == 0 || wl >= sizeof(word))
                return 0;
            memcpy(word, start, wl);
            word[wl] = 0;
            words++;
            if (contains_folded(spec->path, word) ||
                contains_folded(spec->tags, word) ||
                contains_folded(spec->summary, word))
                matched++;
        }
        if (words >= 2 && matched == words) {
            *reason = "terms";
            return 250;
        }
    }
    return 0;
}

struct search_hit {
    const struct zcl_command_spec *spec;
    const char *reason;
    int score;
};

static bool hit_before(const struct search_hit *a, const struct search_hit *b)
{
    return a->score > b->score ||
           (a->score == b->score && strcmp(a->spec->path, b->spec->path) < 0);
}

size_t zcl_command_registry_search_json(
    const struct zcl_command_registry *registry, const char *query,
    char *out, size_t out_size)
{
    char normalized[129];
    if (!registry || !normalize_query(query, normalized))
        return 0;
    struct search_hit hits[ZCL_COMMAND_SEARCH_LIMIT] = {0};
    size_t hit_count = 0, total = 0;
    for (size_t i = 0; i < registry->count; i++) {
        const char *reason = NULL;
        int score = command_match_score(&registry->commands[i], normalized,
                                        &reason);
        if (score == 0)
            continue;
        total++;
        struct search_hit candidate = {
            .spec = &registry->commands[i], .reason = reason, .score = score
        };
        size_t insert = hit_count;
        while (insert > 0 && hit_before(&candidate, &hits[insert - 1]))
            insert--;
        if (insert >= ZCL_COMMAND_SEARCH_LIMIT)
            continue;
        size_t end = hit_count < ZCL_COMMAND_SEARCH_LIMIT
            ? hit_count : ZCL_COMMAND_SEARCH_LIMIT - 1;
        while (end > insert) {
            hits[end] = hits[end - 1];
            end--;
        }
        hits[insert] = candidate;
        if (hit_count < ZCL_COMMAND_SEARCH_LIMIT)
            hit_count++;
    }

    char digest[72];
    zcl_command_registry_digest(registry, digest);
    struct json_value root, matches;
    json_init(&root);
    json_init(&matches);
    json_set_object(&root);
    json_set_array(&matches);
    bool ok = json_push_kv_str(&root, "schema", "zcl.command_search.v1") &&
              json_push_kv_str(&root, "query", normalized) &&
              json_push_kv_str(&root, "registry_digest", digest);
    for (size_t i = 0; ok && i < hit_count; i++) {
        struct json_value match;
        json_init(&match);
        json_set_object(&match);
        ok = json_push_kv_str(&match, "path", hits[i].spec->path) &&
             json_push_kv_str(&match, "reason", hits[i].reason) &&
             json_push_kv_str(&match, "risk",
                              zcl_command_risk_name(hits[i].spec->risk)) &&
             json_push_kv_str(&match, "latency",
                              zcl_command_latency_name(
                                  hits[i].spec->latency)) &&
             json_push_kv_str(&match, "availability",
                              zcl_command_availability_name(
                                  hits[i].spec->availability)) &&
             json_push_back(&matches, &match);
        json_free(&match);
    }
    ok = ok && json_push_kv(&root, "matches", &matches) &&
         json_push_kv_int(&root, "count", (int64_t)hit_count) &&
         json_push_kv_int(&root, "total_matches", (int64_t)total) &&
         json_push_kv_bool(&root, "truncated", total > hit_count);
    if (hit_count > 0) {
        struct json_value next, input;
        json_init(&next);
        json_init(&input);
        json_set_object(&next);
        json_set_object(&input);
        ok = ok && json_push_kv_str(&next, "command", "discover.describe") &&
             json_push_kv_str(&input, "path", hits[0].spec->path) &&
             json_push_kv(&next, "input", &input) &&
             json_push_kv(&root, "next", &next);
        json_free(&input);
        json_free(&next);
    }
    size_t result = ok
        ? write_bounded_json(&root, out, out_size, ZCL_COMMAND_LIST_BUDGET)
        : 0;
    json_free(&matches);
    json_free(&root);
    return result;
}

static bool lane_allowed(const struct zcl_command_spec *spec,
                         const struct zcl_command_context *context)
{
    if (!spec || spec->allowed_lanes == 0)
        return false;
    if (spec->allowed_lanes & ZCL_COMMAND_LANE_LOCAL)
        return true;
    const char *lane = context ? context->operator_lane : NULL;
    if (!lane || !lane[0])
        return false;
    if (strcmp(lane, "dev") == 0)
        return (spec->allowed_lanes & ZCL_COMMAND_LANE_DEV) != 0;
    if (strcmp(lane, "canonical") == 0 || strcmp(lane, "live") == 0)
        return (spec->allowed_lanes & ZCL_COMMAND_LANE_CANONICAL) != 0;
    if (strcmp(lane, "soak") == 0)
        return (spec->allowed_lanes & ZCL_COMMAND_LANE_SOAK) != 0;
    if (strcmp(lane, "offline-copy") == 0)
        return (spec->allowed_lanes & ZCL_COMMAND_LANE_OFFLINE_COPY) != 0;
    return false;
}

static bool reply_add_describe_next(struct zcl_command_reply *reply,
                                    const struct zcl_command_spec *spec,
                                    const char *reason)
{
    if (!reply || !spec || !spec->path)
        return false;
    if (strcmp(spec->path, "discover.describe") == 0)
        return zcl_command_reply_add_next(
            reply, "discover.help", "{}",
            "inspect the discovery surface and choose a valid leaf");
    char input[ZCL_COMMAND_MAX_PATH + 16];
    int n = snprintf(input, sizeof(input), "{\"path\":\"%s\"}",
                     spec->path);
    return n > 0 && (size_t)n < sizeof(input) &&
           zcl_command_reply_add_next(reply, "discover.describe", input,
                                      reason);
}

static bool push_next_array(struct json_value *root,
                            const struct zcl_command_reply *reply,
                            const struct zcl_command_registry *registry,
                            const struct zcl_command_spec *current_spec)
{
    struct json_value array;
    json_init(&array);
    json_set_array(&array);
    bool ok = true;
    for (size_t i = 0; ok && i < reply->next_count; i++) {
        struct json_value item, input;
        json_init(&item);
        json_init(&input);
        json_set_object(&item);
        if (!json_read(&input, reply->next[i].input_json,
                       strlen(reply->next[i].input_json)) ||
            input.type != JSON_OBJ) {
            json_free(&input);
            ok = false;
            break;
        }
        const struct zcl_command_spec *next_spec =
            zcl_command_registry_find(registry, reply->next[i].command, NULL);
        char why[160] = {0};
        if (!next_spec || command_is_branch(next_spec) ||
            (current_spec && strcmp(next_spec->path, current_spec->path) == 0) ||
            !zcl_command_registry_input_validate(next_spec, &input, why,
                                                 sizeof(why))) {
            json_free(&input);
            ok = false;
            break;
        }
        ok = json_push_kv_str(&item, "command", reply->next[i].command) &&
             json_push_kv(&item, "input", &input) &&
             json_push_kv_str(&item, "reason", reply->next[i].reason) &&
             json_push_back(&array, &item);
        json_free(&input);
        json_free(&item);
    }
    ok = ok && json_push_kv(root, "next", &array);
    json_free(&array);
    return ok;
}

static bool push_error(struct json_value *root,
                       const struct zcl_command_error *error)
{
    struct json_value object, blockers;
    json_init(&object);
    json_init(&blockers);
    json_set_object(&object);
    json_set_array(&blockers);
    bool ok = json_push_kv_str(&object, "code", error->code) &&
              json_push_kv_str(&object, "error_code", error->code) &&
              json_push_kv_str(&object, "message", error->message) &&
              json_push_kv_str(&object, "phase", error->phase) &&
              json_push_kv_str(&object, "current_state",
                               error->current_state[0]
                                   ? error->current_state
                                   : "REQUEST_FAILED") &&
              json_push_kv_bool(&object, "retryable", error->retryable) &&
              json_push_kv_bool(&object, "human_action_required",
                                error->human_action_required) &&
              json_push_kv_str(&object, "next_action",
                               error->next_action[0]
                                   ? error->next_action
                                   : "follow the first next command") &&
              json_push_kv_bool(&object, "mutated", error->mutated);
    if (error->evidence[0])
        ok = ok && json_push_kv_str(&object, "evidence", error->evidence);
    if (error->failure_id[0])
        ok = ok && json_push_kv_str(&object, "failure_id",
                                    error->failure_id);
    ok = ok && json_push_kv(&object, "blockers", &blockers) &&
         json_push_kv(root, "error", &object);
    json_free(&blockers);
    json_free(&object);
    return ok;
}

static size_t serialize_reply(const struct zcl_command_registry *registry,
                              const struct zcl_command_spec *spec,
                              struct zcl_command_reply *reply,
                              bool invoked_by_alias,
                              uint64_t request_sequence,
                              int64_t elapsed_us,
                              size_t budget_bytes,
                              bool agent_session_presented,
                              const struct agent_spend_policy_decision *policy,
                              char *out, size_t out_size)
{
    char request_id[48];
    (void)snprintf(request_id, sizeof(request_id), "local-%016llx",
                   (unsigned long long)request_sequence);
    struct json_value root;
    json_init(&root);
    json_set_object(&root);
    bool successful = reply->status == ZCL_COMMAND_STATUS_PASSED ||
                      reply->status == ZCL_COMMAND_STATUS_ACCEPTED;
    bool ok = json_push_kv_str(&root, "schema", "zcl.result.v1") &&
              json_push_kv_str(&root, "command", spec->path) &&
              json_push_kv_bool(&root, "ok", successful) &&
              json_push_kv_str(&root, "status",
                               zcl_command_status_name(reply->status)) &&
              json_push_kv_str(&root, "request_id", request_id) &&
              json_push_kv_int(&root, "elapsed_us",
                               elapsed_us < 0 ? 0 : elapsed_us);
    /* OS-B2: fold the per-command latency contract into the envelope beside the
     * unbudgeted microsecond `elapsed_us`. `budget_ms` derives purely from the
     * leaf's declared latency bucket; `budget_exceeded` flags an over-budget
     * dispatch (measured against elapsed_us at microsecond resolution). */
    int64_t budget_ms = zcl_command_latency_budget_ms(spec->latency);
    int64_t elapsed_ms = elapsed_us < 0 ? 0 : elapsed_us / 1000;
    bool budget_exceeded = elapsed_us > budget_ms * 1000;
    ok = ok && json_push_kv_int(&root, "budget_ms", budget_ms) &&
         json_push_kv_int(&root, "elapsed_ms", elapsed_ms) &&
         json_push_kv_bool(&root, "budget_exceeded", budget_exceeded);
    /* Per-invocation authority block: whether THIS dispatch ran bounded by an
     * agent grant or as the unbounded local operator. Without it, a spend by a
     * 0.001-ZCL grant and the same spend by the omnipotent operator serialize
     * to identical bytes, so a transcript cannot be audited for which one
     * happened, and the exemption is only implied by absence. Present on every
     * reply — the exemption is stated, not assumed. The grant id is always the
     * redacted form. */
    {
        struct json_value auth;
        json_init(&auth);
        json_set_object(&auth);
        (void)json_push_kv_str(&auth, "policy",
                               agent_session_presented ? "bounded" : "exempt");
        (void)json_push_kv_str(
            &auth, "agent_session",
            (agent_session_presented && policy && policy->evidence[0])
                ? policy->evidence
                : "none (local operator)");
        if (agent_session_presented && policy) {
            (void)json_push_kv_int(&auth, "debited_zat", policy->debited_zat);
            if (policy->debited_zat > 0)
                (void)json_push_kv_int(&auth, "window_remaining_zat",
                                       policy->window_remaining_zat);
        }
        ok = ok && json_push_kv(&root, "authority", &auth);
        json_free(&auth);
    }
    if (invoked_by_alias)
        ok = ok && json_push_kv_str(&root, "canonical_path", spec->path);
    if (successful) {
        ok = ok && json_push_kv_str(&root, "data_schema",
                                    reply->data_schema ? reply->data_schema :
                                    spec->output_schema) &&
             json_push_kv(&root, "data", &reply->data);
    } else {
        ok = ok && push_error(&root, &reply->error);
        /* No error may lack an escape action: if the handler left `next` empty,
         * point the caller at this command's contract so a bare failure always
         * carries a next step. */
        if (reply->next_count == 0) {
            (void)reply_add_describe_next(
                reply, spec,
                "inspect this command's contract and availability");
        }
    }
    ok = ok && push_next_array(&root, reply, registry, spec);
    size_t contract = successful
                          ? (spec->budget_bytes > 0
                                 ? (size_t)spec->budget_bytes
                                 : ZCL_COMMAND_RESULT_BUDGET)
                          : ZCL_COMMAND_ERROR_BUDGET;
    if (budget_bytes > 0 && budget_bytes < contract)
        contract = budget_bytes;
    size_t result = ok
        ? write_bounded_json(&root, out, out_size, contract)
        : 0;
    json_free(&root);
    return result;
}

size_t zcl_command_registry_execute_json(
    const struct zcl_command_registry *registry,
    const struct zcl_command_spec *spec,
    const struct zcl_command_context *context,
    const struct json_value *input,
    bool invoked_by_alias, const char *invoked_name,
    const char *view, size_t budget_bytes,
    size_t max_items, const char *cursor,
    char *out, size_t out_size, enum zcl_command_exit *exit_code)
{
    if (exit_code)
        *exit_code = ZCL_COMMAND_EXIT_INTERNAL;
    if (!registry || !spec || command_is_branch(spec) || !input ||
        input->type != JSON_OBJ)
        return 0;

    /* Consult the hot-swap override snapshot for this resolved leaf before
     * falling back to the immutable catalog handler column. When no snapshot
     * is published this is a single atomic load + NULL check (zero overhead).
     * When an override IS used, hold a ref on its snapshot across the handler
     * call so a hot-swap loader cannot dlclose the .so out from under us
     * (epoch/refcount drain — zcl_command_registry_all_retired_quiesced). */
    struct zcl_command_handler_snapshot *held = handler_snapshot_acquire();
    zcl_command_handler_fn override =
        held ? snapshot_lookup(held, spec->path) : NULL;
    zcl_command_handler_fn handler = override ? override : spec->handler;
    if (!override && held) {
        /* Builtin handler lives in the immutable binary — no ref needed. */
        handler_snapshot_release(held);
        held = NULL;
    }

    struct zcl_command_reply reply;
    zcl_command_reply_init(&reply, spec->output_schema);
    struct agent_spend_policy_decision policy = { 0 };
    int64_t started_us = platform_time_monotonic_us();
    if (spec->availability == ZCL_COMMAND_PLANNED) {
        zcl_command_reply_fail(&reply, ZCL_COMMAND_STATUS_BLOCKED,
                               ZCL_COMMAND_EXIT_BLOCKED, "COMMAND_PLANNED",
                               "dispatch", false, false,
                               "command is declared but not implemented",
                               spec->availability_reason);
        (void)reply_add_describe_next(
            &reply, spec, "inspect availability and replacement");
    } else if (!handler) {
        zcl_command_reply_fail(&reply, ZCL_COMMAND_STATUS_BLOCKED,
                               ZCL_COMMAND_EXIT_BLOCKED,
                               "COMMAND_COMPAT_ONLY", "dispatch", false,
                               false,
                               "canonical adapter is not executable yet",
                               spec->compat_target);
        (void)reply_add_describe_next(
            &reply, spec, "inspect the compatibility target");
    } else if (!lane_allowed(spec, context)) {
        zcl_command_reply_fail(&reply, ZCL_COMMAND_STATUS_BLOCKED,
                               ZCL_COMMAND_EXIT_DENIED, "LANE_DENIED",
                               "authorize", false, false,
                               "command is not allowed in this lane",
                               context && context->operator_lane
                                   ? context->operator_lane : "unknown");
        (void)reply_add_describe_next(
            &reply, spec, "inspect the declared lane scope");
    } else if (context && spec->authority > context->authority_ceiling) {
        /* Fail closed: the session's authority ceiling (derived once from its
         * role via the authz policy table) is below what this leaf requires.
         * Enforced BEFORE the capability check so an under-privileged role can
         * never reach a capped leaf even if it somehow held the bit. A NULL
         * context (local operator / in-process) bypasses this entirely. */
        zcl_command_reply_fail(&reply, ZCL_COMMAND_STATUS_BLOCKED,
                               ZCL_COMMAND_EXIT_DENIED, "AUTHORITY_DENIED",
                               "authorize", false, false,
                               "command authority exceeds the session ceiling",
                               zcl_command_authority_name(spec->authority));
        (void)reply_add_describe_next(
            &reply, spec, "inspect the required authority");
    } else if (context &&
               (spec->required_capabilities &
                ~context->granted_capabilities) != 0) {
        zcl_command_reply_fail(&reply, ZCL_COMMAND_STATUS_BLOCKED,
                               ZCL_COMMAND_EXIT_DENIED,
                               "CAPABILITY_DENIED", "authorize", false,
                               false, "required capability was not granted",
                               spec->path);
        (void)reply_add_describe_next(
            &reply, spec, "inspect required capabilities");
    } else {
        /* ── agent spend policy ───────────────────────────────────────────
         * A bounded agent session presented per-invocation
         * (docs/work/agent-spend-policy-design.md). Placed AFTER the lane,
         * authority and capability gates on purpose: this gate is the one
         * that WRITES (it debits the session's rolling window), so running it
         * ahead of the free refusals let a caller who could reach the gate
         * drain an agent's budget with commands that were then denied anyway.
         * Last check before the handler, first thing that costs anything.
         *
         * `committing` resolves the plan/commit gate the same way the handlers
         * do, so a plan-stage preview enforces the caps without spending the
         * window; only the confirmed invocation is debited. If the handler
         * then fails, the debit is released below — the window tracks money
         * that moved, not commands that were attempted. */
        const struct json_value *confirm_v = json_get(input, "confirm");
        bool committing =
            spec->confirmation != ZCL_COMMAND_CONFIRM_PLAN_COMMIT ||
            (confirm_v && json_get_bool(confirm_v));
        agent_spend_policy_evaluate(
            context ? context->agent_session : NULL, spec, input, committing,
            &policy);
        if (!policy.allowed) {
            zcl_command_reply_fail(&reply, ZCL_COMMAND_STATUS_BLOCKED,
                                   ZCL_COMMAND_EXIT_DENIED,
                                   policy.code[0] ? policy.code
                                                  : "POLICY_DENIED",
                                   "authorize", false, false,
                                   policy.detail[0]
                                       ? policy.detail
                                       : "the agent session's spend policy "
                                         "refused this command",
                                   /* the REDACTED grant id: a refusal says
                                    * which grant said no, it never re-prints
                                    * the bearer token into a transcript. */
                                   policy.evidence);
            (void)reply_add_describe_next(
                &reply, spec, "inspect the session's spend policy");
        } else {
            struct zcl_command_request request = {
                .spec = spec,
                .context = context,
                .input = input,
                .view = view && view[0] ? view : "normal",
                .budget_bytes = budget_bytes,
                .max_items = max_items,
                .cursor = cursor,
                .invoked_by_alias = invoked_by_alias,
                .invoked_name = invoked_name,
                .agent_policy_settled = true,
            };
            handler(&request, &reply);
            /* The debit paid for a spend. If the handler did not report a
             * mutation, no money moved (RPC unreachable, insufficient funds,
             * a sovereignty refusal), so the window gets it back. */
            if ((policy.debited_zat > 0 || policy.intent_debit_managed) &&
                !reply.error.mutated) {
                agent_spend_policy_release(
                    context ? context->agent_session : NULL, &policy);
                policy.debited_zat = 0;
            }
        }
    }

    bool status_ok = reply.status == ZCL_COMMAND_STATUS_PASSED ||
                     reply.status == ZCL_COMMAND_STATUS_ACCEPTED;
    if ((status_ok && reply.exit_code != ZCL_COMMAND_EXIT_OK) ||
        (!status_ok && reply.exit_code == ZCL_COMMAND_EXIT_OK) ||
        (status_ok && reply.error.code[0])) {
        zcl_command_reply_fail(&reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL,
                               "INTERNAL_CONTRACT", "serialize", false,
                               reply.error.mutated,
                               "handler returned an inconsistent result",
                               spec->path);
    }
    int64_t elapsed_us = platform_time_monotonic_us() - started_us;
    uint64_t sequence = atomic_fetch_add_explicit(&g_request_sequence, 1,
                                                   memory_order_relaxed);
    const struct zcl_command_registry *next_registry =
        context && context->registry ? context->registry : registry;
    /* OS-B2: record this dispatch's duration into the per-leaf latency ring.
     * `spec` was resolved against `registry` (the caller's array), so the ring
     * is keyed by its offset there; latency_ring_record bounds-checks and
     * no-ops if `spec` is not inside `registry->commands`. Recording is
     * unconditional — the PLANNED/COMPAT/denied fast-fail paths included — since a
     * leaf whose authorization check alone blows its budget is exactly the kind
     * of regression the ring should catch. */
    latency_ring_record(registry, spec, elapsed_us);
    size_t result = serialize_reply(next_registry, spec, &reply,
                                    invoked_by_alias, sequence, elapsed_us,
                                    budget_bytes,
                                    context && context->agent_session &&
                                        context->agent_session[0],
                                    &policy, out, out_size);
    if (result == 0) {
        static const char fallback[] =
            "{\"schema\":\"zcl.result.v1\",\"command\":\"internal\","
            "\"ok\":false,\"status\":\"failed\","
            "\"request_id\":\"local-overflow\",\"elapsed_us\":0,"
            "\"error\":{\"code\":\"RESPONSE_BUDGET_EXCEEDED\","
            "\"error_code\":\"RESPONSE_BUDGET_EXCEEDED\","
            "\"message\":\"bounded response could not be serialized\","
            "\"phase\":\"serialize\",\"current_state\":\"REQUEST_FAILED\","
            "\"retryable\":false,\"human_action_required\":true,"
            "\"next_action\":\"inspect the command contract and retry with bounded output\","
            "\"mutated\":false,\"blockers\":[]},\"next\":[]}";
        size_t len = sizeof(fallback) - 1;
        if (len < out_size && (budget_bytes == 0 || len <= budget_bytes)) {
            memcpy(out, fallback, len + 1);
            result = len;
            reply.exit_code = ZCL_COMMAND_EXIT_INTERNAL;
        }
    }
    if (exit_code)
        *exit_code = reply.exit_code;
    /* Release the override snapshot ref (NULL-safe) now the handler has run. */
    handler_snapshot_release(held);
    zcl_command_reply_free(&reply);
    return result;
}
#endif
