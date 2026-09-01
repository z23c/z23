// one-result-type-ok:sampler-has-no-fallible-surface — E2 / E2b (one way out):
// this file owns nothing that can fail with a reason worth carrying. The two
// bool exports are pure queries, not operations: `_is_armed` is a classifier
// ("is the supervised child registered in THIS process") and `_source_at` is a
// bounds-checked read of a static table (false means "index past the end", a
// loop terminator, not an error). The tick itself cannot fail either — a
// provider that declines to fill is a normal, expected answer that the tick
// reports by publishing nothing and reporting NEITHER progress nor idle, which
// is a supervisor outcome rather than a returned error. `_register` returns
// void, `_sample_once` returns a count and `_records_published` a counter, so
// there is no surface here for struct zcl_result to improve.
/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * telemetry_watch_service — see services/telemetry_watch_service.h for the
 * contract, the sampled-domain policy and the supervision argument.
 *
 * SHAPE. One static source table, one tick, one diff per source. The table is
 * the ONLY place that says which domains are sampled; the tick walks it and
 * knows nothing else. Adding a domain to the feed is adding a row plus a fill
 * shim, and nothing in the tick, the ring or the command layer changes.
 *
 * THIS FILE NAMES NO TELEMETRY FIELD, and cannot: it hands a schema and two
 * snapshots to telemetry_watch_diff(), which reads the names out of the
 * domain's own descriptor table. It also writes no JSON and decides no health
 * — the record's verdict comes from telemetry_evaluate(), the single
 * evaluator. It is deliberately NOT named `*_fill.c` and defines no
 * `*_dump_state_fill`: it is a consumer of the sync provider, not a second
 * one.
 *
 * WHY THE FIRST SAMPLE IS A FULL RECORD. Each source's `prev` starts
 * zero-initialised, which in this layer means every leaf UNSET. The first real
 * sample therefore differs from it in every leaf that has any presence at all,
 * and the diff publishes a baseline record saying so. That is correct rather
 * than convenient: an agent at sequence 0 knows nothing, so from its cursor
 * everything IS new. No special case, no `have_prev` flag.
 */

#include "services/telemetry_watch_service.h"

#include "services/sync_telemetry.h"
#include "supervisors/domains.h"
#include "util/log_macros.h"
#include "util/supervisor.h"
#include "util/telemetry_render.h"
#include "util/telemetry_snapshots.h"
#include "util/telemetry_watch.h"

#include <stdatomic.h>
#include <string.h>

/* ── the source table ────────────────────────────────────────────────── */

/* One watched domain. `fill` NULL means declared-unsampled and `skip_reason`
 * then says why in one greppable token; the two are checked against each other
 * at registration so a row cannot be half-declared. */
struct twx_source {
    const char *domain;         /* the telemetry domain name */
    const char *canonical_path; /* the leaf a record points a reader at */
    bool (*fill)(void *snapshot);
    void *cur;
    void *prev;
    size_t snapshot_size;
    const struct telemetry_domain_schema *schema;
    const char *skip_reason;
};

/* The one provider that exists. A shim rather than a cast in the table so the
 * typed signature is checked by the compiler. */
static bool twx_fill_sync(void *snapshot)
{
    return sync_dump_state_fill((struct sync_snapshot *)snapshot);
}

/* Two snapshots per sampled domain, held statically: the sampler runs on the
 * supervisor's tick runner and must not allocate, and a `struct sync_snapshot`
 * is far too large to sit on that thread's stack twice per tick. */
static struct sync_snapshot g_sync_cur;
static struct sync_snapshot g_sync_prev;

/* Short static tokens, not prose: they travel in every reply, and the prose is
 * in the header and in engine/composition/commands/telemetry/watch.def. */
#define TWX_WHY_NO_PROVIDER "no_typed_snapshot_provider_wired_yet"
#define TWX_WHY_NODE_FREE "no_ambient_in_process_state_directory_scoped"

/* Every registered telemetry domain appears here, sampled or not. Enumerating
 * all eight is the point: a domain that fell out of the feed would otherwise
 * be invisible, and "the feed covers everything" is exactly the assumption a
 * reader makes when a reply lists only what it does cover. */
static struct twx_source g_sources[] = {
    { "runtime", "ops.telemetry.runtime", NULL, NULL, NULL, 0, NULL,
      TWX_WHY_NO_PROVIDER },
    { "sync", "ops.telemetry.sync.summary", twx_fill_sync, &g_sync_cur,
      &g_sync_prev, sizeof(struct sync_snapshot), &g_sync_schema, NULL },
    { "network", "ops.telemetry.network", NULL, NULL, NULL, 0, NULL,
      TWX_WHY_NO_PROVIDER },
    { "storage", "ops.telemetry.storage", NULL, NULL, NULL, 0, NULL,
      TWX_WHY_NO_PROVIDER },
    { "wallet", "ops.telemetry.wallet", NULL, NULL, NULL, 0, NULL,
      TWX_WHY_NO_PROVIDER },
    { "agents", "ops.telemetry.agents", NULL, NULL, NULL, 0, NULL,
      TWX_WHY_NO_PROVIDER },
    { "zcode", "ops.telemetry.zcode", NULL, NULL, NULL, 0, NULL,
      TWX_WHY_NO_PROVIDER },
    /* Declared unsampled for a reason that is structural and permanent, not a
     * missing provider: metaverse state is directory-scoped and node-free, so
     * there is no ambient in-process value a sampler could read. Its field
     * table carries zero watchable leaves to match. */
    { "metaverse", "metaverse.property.list", NULL, NULL, NULL, 0, NULL,
      TWX_WHY_NODE_FREE },
};

#define TWX_SOURCE_COUNT (sizeof(g_sources) / sizeof(g_sources[0]))

static _Atomic uint64_t g_records_published = 0;
static _Atomic uint64_t g_ticks = 0;
static _Atomic uint64_t g_fill_failures = 0;

/* ── one sample ──────────────────────────────────────────────────────── */

/* Sample one source. Returns false when the provider refused to fill — a real
 * fault, reported to the caller so the tick can withhold BOTH progress and
 * idle. `*published` is incremented when a record was written. */
static bool twx_sample_source(struct twx_source *src, size_t *published)
{
    if (!src->fill)
        return true; /* declared unsampled: not a fault, and not work either */

    memset(src->cur, 0, src->snapshot_size);
    if (!src->fill(src->cur)) {
        atomic_fetch_add(&g_fill_failures, 1);
        LOG_WARN("telemetry_watch",
                 "sample: provider for domain '%s' did not fill a snapshot",
                 src->domain);
        return false;
    }

    struct telemetry_watch_record rec;
    memset(&rec, 0, sizeof rec);
    if (telemetry_watch_diff(src->schema, src->prev, src->cur, &rec) == 0) {
        /* Nothing the node owns moved. Adopt the sample as the new baseline
         * anyway (it is identical where it matters) and publish nothing. */
        memcpy(src->prev, src->cur, src->snapshot_size);
        return true;
    }

    rec.captured_at = telemetry_now_unix();
    size_t n = strlen(src->canonical_path);
    if (n >= TELEMETRY_WATCH_PATH_MAX)
        n = TELEMETRY_WATCH_PATH_MAX - 1;
    memcpy(rec.canonical_path, src->canonical_path, n);
    rec.canonical_path[n] = '\0';

    /* Health is DERIVED, never authored here: the same evaluator the renderer
     * folds into `ops telemetry sync summary` judges this snapshot. */
    struct telemetry_domain_verdict verdict;
    memset(&verdict, 0, sizeof verdict);
    rec.health = telemetry_evaluate(src->schema, src->cur, &verdict)
                     ? verdict.state
                     : TELEMETRY_HEALTH_UNKNOWN;

    if (telemetry_watch_publish(&rec) != 0) {
        atomic_fetch_add(&g_records_published, 1);
        if (published)
            (*published)++;
    }
    memcpy(src->prev, src->cur, src->snapshot_size);
    return true;
}

size_t telemetry_watch_service_sample_once(void)
{
    telemetry_watch_init();
    size_t published = 0;
    for (size_t i = 0; i < TWX_SOURCE_COUNT; i++)
        (void)twx_sample_source(&g_sources[i], &published);
    return published;
}

uint64_t telemetry_watch_service_records_published(void)
{
    return atomic_load(&g_records_published);
}

size_t telemetry_watch_service_source_count(void)
{
    return TWX_SOURCE_COUNT;
}

bool telemetry_watch_service_source_at(size_t index, const char **domain,
                                       const char **canonical_path,
                                       const char **skip_reason)
{
    if (index >= TWX_SOURCE_COUNT)
        LOG_FAIL("telemetry_watch", "source_at: index %zu is out of range",
                 index);
    if (domain)
        *domain = g_sources[index].domain;
    if (canonical_path)
        *canonical_path = g_sources[index].canonical_path;
    if (skip_reason)
        *skip_reason = g_sources[index].skip_reason;
    return true;
}

void telemetry_watch_service_reset_baseline(void)
{
    for (size_t i = 0; i < TWX_SOURCE_COUNT; i++) {
        if (g_sources[i].prev)
            memset(g_sources[i].prev, 0, g_sources[i].snapshot_size);
    }
}

/* ── supervision ─────────────────────────────────────────────────────── */

static struct liveness_contract g_watch_contract;
static _Atomic supervisor_child_id g_watch_id = SUPERVISOR_INVALID_ID;

/* How long the sampler may go without EITHER publishing a record or declaring
 * itself idle before the supervisor calls it stuck. At a 5 s period this is
 * ~180 consecutive ticks that neither observed a change nor established there
 * was nothing to observe — which, given the tick below reports idle on every
 * healthy quiet pass, can only be a run of provider failures. */
#define TWX_MAX_QUIET_US ((int64_t)15 * 60 * 1000 * 1000)

static void twx_tick(struct liveness_contract *c)
{
    (void)c;
    supervisor_child_id id = atomic_load(&g_watch_id);
    atomic_fetch_add(&g_ticks, 1);

    telemetry_watch_init();
    size_t published = 0;
    bool all_filled = true;
    for (size_t i = 0; i < TWX_SOURCE_COUNT; i++) {
        if (!twx_sample_source(&g_sources[i], &published))
            all_filled = false;
    }

    if (published > 0) {
        /* A published record is the RESULT this service exists to produce. */
        supervisor_progress(id, (int64_t)atomic_load(&g_records_published));
    } else if (all_filled) {
        /* Every sampled provider answered and nothing moved. This is the one
         * state where "there was legitimately nothing to do" has been
         * POSITIVELY established — the snapshots were taken and compared — so
         * it is the only place an idle report is honest. */
        supervisor_progress_idle(id);
    }
    /* else: a provider refused to fill. Report NEITHER, so the quiet clock
     * keeps running and a run of failures becomes a NO_PROGRESS stall. A
     * failed sample looks exactly like a quiet node from the outside, and
     * that is precisely the confusion the detector exists to catch. */

    supervisor_tick(id);
}

void telemetry_watch_service_register(void)
{
    supervisor_domains_init();
    if (atomic_load(&g_watch_id) != SUPERVISOR_INVALID_ID)
        return;

    /* A half-declared row would sample nothing while claiming to be covered,
     * or claim a reason for a domain it does sample. Both are silent coverage
     * holes, so they are caught here rather than in a reply nobody reads. */
    for (size_t i = 0; i < TWX_SOURCE_COUNT; i++) {
        const struct twx_source *s = &g_sources[i];
        bool sampled = s->fill != NULL;
        if (sampled == (s->skip_reason != NULL) || (sampled && !s->schema)) {
            LOG_WARN("telemetry_watch",
                     "source '%s' is half-declared (fill=%s skip_reason=%s) — "
                     "it will not be sampled and its coverage is unstated",
                     s->domain, sampled ? "set" : "NULL",
                     s->skip_reason ? s->skip_reason : "NULL");
        }
    }

    telemetry_watch_init();
    liveness_contract_init(&g_watch_contract, "ops.telemetry_watch");
    atomic_store(&g_watch_contract.period_secs,
                 (int64_t)TELEMETRY_WATCH_PERIOD_SECS);
    atomic_store(&g_watch_contract.deadline_secs, (int64_t)0);
    g_watch_contract.on_tick = twx_tick;
    g_watch_contract.on_stall = NULL;
    supervisor_child_id id =
        supervisor_register_in_domain(g_op_sup, &g_watch_contract);
    atomic_store(&g_watch_id, id);
    if (id == SUPERVISOR_INVALID_ID) {
        LOG_WARN("telemetry_watch",
                 "supervisor register failed — the change feed will not be "
                 "sampled by the node and every poll will sample itself");
        return;
    }
    /* ARMED, not exempt: this service has a real result signal (records
     * published) AND a real idle signal (a sample taken that found nothing),
     * and the tick above reports exactly one of them on every healthy pass.
     * The only way the marker freezes without an idle report is a run of
     * provider failures, which is a fault and must be named. */
    supervisor_set_progress_max_quiet(id, TWX_MAX_QUIET_US);
}

bool telemetry_watch_service_is_armed(void)
{
    return atomic_load(&g_watch_id) != SUPERVISOR_INVALID_ID;
}
