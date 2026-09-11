/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "kernel/command_registry.h"

#include "command_registry_internal.h"

#include "crypto/sha256.h"
#include "platform/time_compat.h"
#include "services/agent_spend_policy.h"  // lib-layer-ok:agent-spend-policy-gate
#include "util/log_macros.h"
#include "util/safe_alloc.h"

#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef ZCL_HOTFORK_COMMAND_INPUT_CORE
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
bool command_registry_latency_ring_p99(
    const struct zcl_command_registry *registry,
    const struct zcl_command_spec *spec, int64_t *p99_us, uint32_t *count)
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

static bool replace_preamble(const struct zcl_command_handler_override *overrides,
                             size_t count, char *why, size_t why_sz,
                             const struct zcl_command_registry **registry)
{
    if (why && why_sz)
        why[0] = '\0';
    if (!overrides || count == 0 || count > ZCL_COMMAND_HANDLER_OVERRIDE_MAX) {
        if (why && why_sz)
            snprintf(why, why_sz, "invalid override count: %zu", count);
        LOG_FAIL("kernel.command", "invalid override count: %zu", count);
    }
    *registry = atomic_load_explicit(&g_active_registry, memory_order_acquire);
    if (!*registry) {
        if (why && why_sz)
            snprintf(why, why_sz, "no active registry bound");
        LOG_FAIL("kernel.command", "no active registry bound for override batch");
    }
    return command_registry_replace_validate(*registry, overrides, count, why,
                                             why_sz);
}

/* Why a step taken under the write lock refused. handler_write_lock() is a
 * non-reentrant spinlock, and every LOG_* macro reaches zcl_log_emit_at(),
 * which takes the stdio stream lock to emit its line atomically — so no
 * step below it logs. The failing step records its reason here and
 * replace_report() emits the line, same text and same false, AFTER the
 * unlock. */
enum replace_fail {
    REPLACE_FAIL_NONE = 0,
    REPLACE_FAIL_ALLOC,
    REPLACE_FAIL_CAPACITY
};

static bool replace_report(enum replace_fail fail)
{
    if (fail == REPLACE_FAIL_ALLOC)
        LOG_FAIL("kernel.command", "override snapshot allocation failed");
    if (fail == REPLACE_FAIL_CAPACITY)
        LOG_FAIL("kernel.command", "override capacity exceeded (max %u)",
                 (unsigned)ZCL_COMMAND_HANDLER_OVERRIDE_MAX);
    return false;
}

static struct zcl_command_handler_snapshot *replace_clone(
    const struct zcl_command_handler_snapshot *old, uint32_t next_generation,
    char *why, size_t why_sz, enum replace_fail *fail)
{
    *fail = REPLACE_FAIL_NONE;
    struct zcl_command_handler_snapshot *next =
        zcl_malloc(sizeof(*next), "command handler override snapshot");
    if (!next) {
        if (why && why_sz)
            snprintf(why, why_sz, "snapshot allocation failed");
        *fail = REPLACE_FAIL_ALLOC;
        return NULL;
    }
    if (old)
        memcpy(next, old, sizeof(*next));
    else
        memset(next, 0, sizeof(*next));
    next->generation = next_generation;
    atomic_store_explicit(&next->refs, 0, memory_order_relaxed);
    next->published_prev = NULL;
    return next;
}

static bool replace_merge(struct zcl_command_handler_snapshot *next,
                          const struct zcl_command_handler_override *overrides,
                          size_t count, char *why, size_t why_sz,
                          enum replace_fail *fail)
{
    *fail = REPLACE_FAIL_NONE;
    for (size_t i = 0; i < count; i++) {
        const struct zcl_command_handler_override *ovr = &overrides[i];
        size_t idx = next->count;
        for (size_t k = 0; k < next->count; k++) {
            if (next->slots[k].path &&
                strcmp(next->slots[k].path, ovr->path) == 0) {
                idx = k;
                break;
            }
        }
        if (idx == next->count) {
            if (next->count >= ZCL_COMMAND_HANDLER_OVERRIDE_MAX) {
                if (why && why_sz)
                    snprintf(why, why_sz, "override capacity exceeded");
                *fail = REPLACE_FAIL_CAPACITY;
                return false;
            }
            next->count++;
        }
        next->slots[idx] = *ovr;
    }
    return true;
}

bool zcl_command_registry_replace_batch(
    uint32_t generation,
    const struct zcl_command_handler_override *overrides,
    size_t count, char *why, size_t why_sz, uint32_t *out_generation)
{
    const struct zcl_command_registry *registry = NULL;
    if (!replace_preamble(overrides, count, why, why_sz, &registry))
        return false;

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

    enum replace_fail fail = REPLACE_FAIL_NONE;
    struct zcl_command_handler_snapshot *next =
        replace_clone(old, next_generation, why, why_sz, &fail);
    if (!next) {
        handler_write_unlock();
        return replace_report(fail);
    }
    if (!replace_merge(next, overrides, count, why, why_sz, &fail)) {
        handler_write_unlock();
        free(next);
        return replace_report(fail);
    }

    next->published_prev =
        atomic_load_explicit(&g_published_head, memory_order_acquire);
    atomic_store_explicit(&g_published_head, next, memory_order_release);
    atomic_store_explicit(&g_active_handlers, next, memory_order_release);
    if (out_generation)
        *out_generation = next_generation;
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
    "instant", "fast", "foreground", "background", "persistent", "maintenance"
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
    [ZCL_COMMAND_LATENCY_MAINTENANCE] = ZCL_COMMAND_LATENCY_BUDGET_MAINTENANCE_MS,
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
    (void)command_registry_copy_string(reply->error.code,
                                       sizeof(reply->error.code), code);
    (void)command_registry_copy_string(reply->error.phase,
                                       sizeof(reply->error.phase), phase);
    (void)command_registry_copy_string(reply->error.message,
                                       sizeof(reply->error.message), message);
    (void)command_registry_copy_string(reply->error.evidence,
                                       sizeof(reply->error.evidence),
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
    if (!command_registry_copy_string(next->command, sizeof(next->command),
                                      command) ||
        !command_registry_copy_string(next->input_json,
                                      sizeof(next->input_json), input_json) ||
        !command_registry_copy_string(next->reason, sizeof(next->reason),
                                      reason))
        return false;
    reply->next_count++;
    return true;
}
#endif

#ifndef ZCL_HOTFORK_COMMAND_INPUT_CORE
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
        if (command_registry_csv_token_equal(registry->commands[i].aliases,
                                             path_or_alias)) {
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
        if (!command_registry_resolve_word_ok(word))
            break;
        if (!command_registry_resolve_append(candidate, sizeof(candidate), &pos,
                                            word))
            break;
        bool alias = false;
        const struct zcl_command_spec *found =
            zcl_command_registry_find(registry, candidate, &alias);
        if (found)
            command_registry_resolve_accept(found, alias, i + 1, &best,
                                            &best_count, &best_alias, invoked,
                                            invoked_size, candidate);
    }
    if (consumed)
        *consumed = best_count;
    if (was_alias)
        *was_alias = best_alias;
    return best;
}
#endif

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
        if (!command_registry_input_key_declared(spec, input, i, why, why_size))
            return false;
        bool type_ok = false;
        if (!command_registry_input_value_type_ok(spec, key,
                                                  &input->children[i],
                                                  &type_ok) ||
            !type_ok)
            return command_registry_input_type_why(key, &input->children[i],
                                                   why, why_size);
    }
    return command_registry_input_required_discovery(spec, input, why,
                                                     why_size);
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

static zcl_command_handler_fn execute_bind_handler(
    const struct zcl_command_spec *spec,
    struct zcl_command_handler_snapshot **held)
{
    *held = handler_snapshot_acquire();
    zcl_command_handler_fn override =
        *held ? snapshot_lookup(*held, spec->path) : NULL;
    if (!override && *held) {
        handler_snapshot_release(*held);
        *held = NULL;
    }
    return override ? override : spec->handler;
}

static void execute_check_contract(struct zcl_command_reply *reply,
                                   const struct zcl_command_spec *spec)
{
    bool status_ok = reply->status == ZCL_COMMAND_STATUS_PASSED ||
                     reply->status == ZCL_COMMAND_STATUS_ACCEPTED;
    if ((status_ok && reply->exit_code != ZCL_COMMAND_EXIT_OK) ||
        (!status_ok && reply->exit_code == ZCL_COMMAND_EXIT_OK) ||
        (status_ok && reply->error.code[0])) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "INTERNAL_CONTRACT",
                               "serialize", false, reply->error.mutated,
                               "handler returned an inconsistent result",
                               spec->path);
    }
}

static size_t execute_fallback(char *out, size_t out_size, size_t budget_bytes,
                               struct zcl_command_reply *reply)
{
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
        reply->exit_code = ZCL_COMMAND_EXIT_INTERNAL;
        return len;
    }
    return 0;
}

static bool execute_session_presented(const struct zcl_command_context *context)
{
    return context && context->agent_session && context->agent_session[0];
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
    if (!registry || !spec || command_registry_is_branch(spec) || !input ||
        input->type != JSON_OBJ)
        return 0;

    struct zcl_command_handler_snapshot *held = NULL;
    zcl_command_handler_fn handler = execute_bind_handler(spec, &held);
    struct zcl_command_reply reply;
    zcl_command_reply_init(&reply, spec->output_schema);
    struct agent_spend_policy_decision policy = {0};
    int64_t started_us = platform_time_monotonic_us();
    command_registry_execute_run(spec, context, input, handler,
                                 invoked_by_alias, invoked_name, view,
                                 budget_bytes, max_items, cursor, &reply,
                                 &policy);
    execute_check_contract(&reply, spec);
    int64_t elapsed_us = platform_time_monotonic_us() - started_us;
    uint64_t sequence = atomic_fetch_add_explicit(&g_request_sequence, 1,
                                                  memory_order_relaxed);
    const struct zcl_command_registry *next_registry =
        context && context->registry ? context->registry : registry;
    latency_ring_record(registry, spec, elapsed_us);
    size_t result = command_registry_serialize_reply(
        next_registry, spec, &reply, invoked_by_alias, sequence, elapsed_us,
        budget_bytes, execute_session_presented(context), &policy, out,
        out_size);
    if (result == 0)
        result = execute_fallback(out, out_size, budget_bytes, &reply);
    if (exit_code)
        *exit_code = reply.exit_code;
    handler_snapshot_release(held);
    zcl_command_reply_free(&reply);
    return result;
}
#endif
