/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * legacy_mirror_sync_parity_trend — bounded trend-history write for the
 * mirror's consensus-parity comparisons (see models/parity_sample.h). Split
 * out of legacy_mirror_sync_service.c to keep that file under the E1
 * file-size ceiling; shares g_lms via legacy_mirror_sync_internal.h exactly
 * like every other TU in this service.
 *
 * Called from lms_cache_comparison() for EVERY comparison outcome the
 * mirror's comparator can land in: a clean agreeing sample, a same-height
 * hash disagreement, an unreachable-oracle sample, and the "no common
 * height available yet" sample. This turns the mirror's ad-hoc
 * rpc-unreachable / hash-disagreement blockers (which only ever fire
 * transiently and can go unnoticed for days — see
 * engine/conditions/src/parity_slo_breach.c) into a trendable time series. */
// one-result-type-ok:best-effort-trend-write — lms_record_parity_sample is a
// best-effort, fire-and-forget history write (observational trend data,
// never a correctness dependency); failures are logged via LOG_WARN, not
// returned, matching every other best-effort persistence write in this
// codebase (e.g. network_monitor.c's nm_sample_once).

#include "legacy_mirror_sync_internal.h"

#include "config/runtime.h"
#include "models/parity_sample.h"
#include "platform/time_compat.h"
#include "util/log_macros.h"

#include <stdatomic.h>

/* Bounded retention for the parity_samples trend table. Every comparison
 * outcome writes one row; capped to the newest N so the table cannot grow
 * unbounded on a long-running node. 10k rows at the default 3s tick cadence
 * covers several hours of dense history — comfortably longer than the
 * parity_slo_breach detector's sustained-window thresholds. */
#define PARITY_SAMPLE_RETAIN_ROWS 10000

/* Best-effort trend write. A missing/unopened node.db (e.g. unit tests that
 * never wire the runtime db service) is a silent no-op — this is
 * observational history, never a correctness dependency. Callers write it
 * OUTSIDE g_lms.lock so a slow/busy DB write never blocks the hot
 * comparison path. */
void lms_record_parity_sample(int height, bool known, bool agree)
{
    struct node_db *ndb = app_runtime_node_db();
    if (!ndb || !ndb->open)
        return;

    struct db_parity_sample s = {
        .ts = (int64_t)platform_time_wall_unix(),
        .our_height = atomic_load(&g_lms.local_height),
        .oracle_height = atomic_load(&g_lms.legacy_height),
        .heights_equal_at = height,
        .hash_equal = (known && agree) ? 1 : 0,
        .oracle_reachable = atomic_load(&g_lms.reachable) ? 1 : 0,
    };
    if (!db_parity_sample_save(ndb, &s))
        LOG_WARN("legacy_mirror", "parity sample save failed");
    if (!db_parity_sample_prune(ndb, PARITY_SAMPLE_RETAIN_ROWS))
        LOG_WARN("legacy_mirror", "parity sample prune failed");
}
