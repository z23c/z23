/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * rewind_driver — implementation of the one generic "nearest self-verified
 * base -> rewind -> O(delta) re-derive" recovery driver. See
 * jobs/rewind_driver.h for the full contract.
 *
 * This TU owns NO storage and NO new mutation path: it is pure orchestration
 * over three existing primitives —
 *   - reducer_frontier_nearest_self_verified_base (sovereign base selection),
 *   - reducer_frontier_compute_hstar (the provable tip + served_floor), and
 *   - stage_rederive_range (THE universal, LCC-safe, served-floor-preserving
 *     re-derive primitive; NOT modified here).
 * The escalate-once fallback names a typed blocker rather than looping. */

#include "jobs/rewind_driver.h"

#include "reducer_frontier_rewind_bases.h"   /* nearest-self-verified selector */

#include "jobs/reducer_frontier.h"
#include "jobs/stage_rederive_range.h"
#include "services/sync_monitor.h"
#include "storage/progress_store.h"
#include "util/blocker.h"
#include "util/log_macros.h"
#include "validation/main_state.h"
#include "event/event.h"

#include <sqlite3.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* Build the driver-owned, namespaced escalation blocker id from a caller tag.
 * All driver escalations live under the "rewind_driver." namespace so the one
 * generic call site declares a single bounded pattern (blocker_remedy_bindings
 * "rewind_driver.*"). An empty tag still yields a valid id. */
static void build_blocker_id(char *buf, size_t buflen, const char *tag)
{
    snprintf(buf, buflen, "rewind_driver.%s",
             (tag && tag[0]) ? tag : "escalation");
}

/* Name a typed, escalatable dependency blocker for the un-healable case (LCC
 * refusal, or no reachable self-verified base). BLOCKER_DEPENDENCY +
 * retry_budget=-1 keeps it a retry-forever dependency (never a silent latch);
 * blocker_set is rate-limited/idempotent, so a persistent cause collapses to a
 * single named blocker rather than a retry storm — this is the "escalate ONCE"
 * contract. A committed (or no-op) recovery clears it via the caller. */
static void escalate_named_blocker(const char *blocker_id,
                                   const char *reason_text)
{
    /* blocker-id: rewind_driver.* */
    blocker_name_dependency(blocker_id, "rewind_driver", reason_text);
}

bool rewind_to_nearest_self_verified_base(int32_t at_or_below,
                                          const char *reason,
                                          const char *escalate_tag,
                                          struct rewind_driver_result *out)
{
    if (out) {
        memset(out, 0, sizeof(*out));
        out->base_height = -1;
        out->hstar = -1;
    }
    const char *why = reason ? reason : "rewind_driver";

    char blocker_id[BLOCKER_ID_MAX];
    build_blocker_id(blocker_id, sizeof(blocker_id), escalate_tag);

    sqlite3 *db = progress_store_db();
    if (!db) {
        LOG_WARN("rewind_driver",
                 "[rewind_driver] %s: progress db unavailable — cannot drive "
                 "recovery", why);
        return false;  // raw-return-ok:logged-above
    }
    /* ms is optional: stage_rederive_range re-creates created_outputs itself and
     * never dereferences a NULL ms (accepted for API symmetry). */
    struct main_state *ms = sync_monitor_main_state();

    /* H* + served_floor from the durable reducer authority. served_floor is
     * read for observability + the served-floor invariant: stage_rederive_range
     * NEVER deletes tip_finalize_log rows, so the publicly served floor survives
     * a rewind even below it (only the cursor is rewound and re-advances). */
    progress_store_tx_lock();
    int32_t hstar = -1;
    int32_t served_floor = -1;
    bool have_hstar = reducer_frontier_compute_hstar(db, &hstar, &served_floor);
    progress_store_tx_unlock();
    if (!have_hstar || hstar < 0) {
        LOG_WARN("rewind_driver",
                 "[rewind_driver] %s: H* recompute failed — cannot locate a "
                 "re-derive window", why);
        return false;  // raw-return-ok:logged-above
    }
    if (out)
        out->hstar = hstar;

    /* Ceiling for base selection: never above H* (nothing above the provable
     * tip is a rewind base), and never above the caller's divergence height. */
    int32_t ceiling = at_or_below < hstar ? at_or_below : hstar;

    struct reducer_frontier_rewind_base base;
    if (!reducer_frontier_nearest_self_verified_base(ceiling, &base)) {
        char reason_text[BLOCKER_REASON_MAX];
        snprintf(reason_text, sizeof(reason_text),
                 "%s: no self-verified rewind base at or below h=%d (H*=%d) — "
                 "deeper recovery / operator attention required",
                 why, (int)ceiling, (int)hstar);
        escalate_named_blocker(blocker_id, reason_text);
        event_emitf(EV_RECOVERY_ACTION, 0,
                    "action=rewind-driver-no-base reason=%s ceiling=%d hstar=%d",
                    why, (int)ceiling, (int)hstar);
        LOG_WARN("rewind_driver",
                 "[rewind_driver] %s: no self-verified base <= %d — escalated "
                 "(named blocker %s)", why, (int)ceiling,
                 blocker_id);
        if (out)
            out->escalated = true;
        return true;
    }

    if (out) {
        out->base_height = base.height;
        out->base_self_derived = base.self_derived;
        strncpy(out->base_kind, base.kind, sizeof(out->base_kind) - 1);
        out->base_kind[sizeof(out->base_kind) - 1] = '\0';
    }

    /* Base already at/above the provable tip: nothing to re-derive. Clear any
     * stale escalation blocker and report a clean no-op. */
    if (base.height >= hstar) {
        blocker_clear(blocker_id);
        LOG_INFO("rewind_driver",
                 "[rewind_driver] %s: nearest self-verified base %s@%d already "
                 "at/above H*=%d — no rewind needed", why, base.kind,
                 (int)base.height, (int)hstar);
        if (out)
            out->nothing = true;
        return true;
    }

    /* Preserve the self-verified base itself and re-derive the suffix strictly
     * above it. stage_rederive_range's from_height is the FIRST height whose
     * verdict/coin delta is removed; passing base instead would unwind the
     * trusted base and leave coins_applied_height unable to cover it. */
    int32_t rederive_from = base.height + 1;
    struct stage_rederive_range_result rr = {0};
    if (!stage_rederive_range(db, ms, (int)rederive_from, (int)hstar, &rr)) {
        LOG_WARN("rewind_driver",
                 "[rewind_driver] %s: stage_rederive_range [%d,%d] hit a store "
                 "error", why, (int)rederive_from, (int)hstar);
        return false;  // raw-return-ok:logged-above
    }

    if (rr.refused_no_inverse || !rr.ok) {
        char reason_text[BLOCKER_REASON_MAX];
        snprintf(reason_text, sizeof(reason_text),
                 "%s: re-derive [%d,%d] above base %s refused (%s) — needs "
                 "refold-from-anchor / operator", why, (int)rederive_from,
                 (int)hstar, base.kind,
                 rr.refused_no_inverse ? "LCC: applied height lacks inverse "
                                         "delta" : "rewind did not commit");
        escalate_named_blocker(blocker_id, reason_text);
        event_emitf(EV_RECOVERY_ACTION, 0,
                    "action=rewind-driver-refused reason=%s base=%s base_h=%d "
                    "hstar=%d lcc=%d", why, base.kind, (int)base.height,
                    (int)hstar, (int)rr.refused_no_inverse);
        LOG_WARN("rewind_driver",
                 "[rewind_driver] %s: re-derive from %s@%d refused_no_inverse=%d "
                 "ok=%d — escalated (named blocker %s)", why, base.kind,
                 (int)base.height, (int)rr.refused_no_inverse, (int)rr.ok,
                 blocker_id);
        if (out)
            out->escalated = true;
        return true;
    }

    /* Rewind committed: the stale suffix is scheduled for re-derivation from
     * on-disk bodies by the normal forward fold. Clear the escalation blocker. */
    blocker_clear(blocker_id);
    LOG_WARN("rewind_driver",
             "[rewind_driver] %s: re-derived [%d,%d] from self-verified base %s "
             "(self_derived=%d) rewound=%d cursors=%d coins_rewound=%d "
             "(served_floor=%d preserved) — forward fold re-derives",
             why, (int)rederive_from, (int)hstar, base.kind,
             (int)base.self_derived, (int)rr.rewound, rr.cursors_rewound,
             (int)rr.coins_rewound, (int)served_floor);
    event_emitf(EV_RECOVERY_ACTION, 0,
                "action=rewind-driver-rederive reason=%s base=%s base_h=%d "
                "hstar=%d rewound=%d coins_rewound=%d", why, base.kind,
                (int)base.height, (int)hstar, (int)rr.rewound,
                (int)rr.coins_rewound);
    if (out) {
        out->ok = true;
        out->rewound = rr.rewound;
        out->coins_rewound = rr.coins_rewound;
        out->cursors_rewound = rr.cursors_rewound;
    }
    return true;
}
