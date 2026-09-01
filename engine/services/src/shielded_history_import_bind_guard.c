/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * shielded_history_import_bind_guard — the fail-closed target-height guard for
 * the complete shielded-history import. The contract lives in
 * services/shielded_history_import_service.h; in short:
 *
 * The reducer's fold resumes at the TARGET datadir's coins authority
 * (fold_resume = coins_applied_height, so the frontier must BE the tree state
 * at fold_resume - 1 == the coins island root). This guard verifies that the
 * requested target height is that bind anchor. The import service separately
 * binds the SOURCE chainstate's persisted best-block hash to the exact target
 * header before its transaction opens. Both predicates are required: this
 * one prevents a height-mismatched frontier, while the exact hash bind prevents
 * future entries in the source's additive, unheighted nullifier set.
 *
 * The guard therefore REFUSES any bind whose tip_height does not match the
 * target's bind anchor, BEFORE the import transaction opens, so a refusal
 * commits nothing. A target with NO coins authority yet (fresh datadir —
 * shielded-first ordering) passes silently.
 *
 * PARTIALLY-FOLDED targets (2026-08-02, the replay-canary anchor track): a
 * node that seeded and then folded PAST the seed has coins_best ABOVE the
 * durable seed floor (reducer_seed_floor_height), and the chainstate cannot
 * hold the live resume anchor's root — the roots above the floor are the
 * fold's own computed rows. The import's job there is to supply history AT
 * AND BELOW the seed floor (the fold's rows cover everything above it, and
 * the shielded preflight guarantees the folded span consumed no spends), so
 * the correct bind is the seed floor, not the live coins_best. Rule: when a
 * seed floor is declared the bind must equal it; otherwise it must equal
 * the coins island root.
 *
 * Both callers share this one predicate: the -import-complete-shielded verb
 * (engine/entry/main.c, terminal-visible refusal with both heights + the remedy) and
 * shielded_history_import_from_chainstate itself (defense in depth — a
 * caller bypassing the verb cannot select a different target height). Split
 * out of shielded_history_import_service.c to keep that file under its
 * file-size ceiling.
 *
 * one-result-type-ok:owner-gated-boot-import — a pure bool predicate on the
 * same owner-gated boot/import surface as shielded_history_import_service.c
 * (which carries the same marker): the refusal reason travels via node.log
 * [shielded_import] (every refusal path LOG_RETURNs the exact heights) and
 * via *coins_best_out to the verb's terminal message; there is no
 * zcl_result-returning runtime surface to thread. */
// one-result-type-ok:owner-gated-boot-import

#include "services/shielded_history_import_service.h"

#include "jobs/reducer_frontier.h"
#include "util/log_macros.h"

#include <sqlite3.h>
#include <stdint.h>

#define SHI_BIND_GUARD_SUBSYS "shielded_import"

bool shielded_history_import_bind_guard_probe(sqlite3 *progress_db,
                                              int64_t tip_height,
                                              int32_t *coins_best_out)
{
    if (coins_best_out)
        *coins_best_out = -1;
    if (!progress_db || tip_height < 0)
        LOG_RETURN(false, SHI_BIND_GUARD_SUBSYS, "bind guard: invalid args");

    /* The bind anchor: the durable seed floor when declared (a partially-
     * folded target binds at its fold's START, not its live tip — see the
     * header), else the live coins island root. */
    int32_t seed_floor = -1;
    bool floor_found = false;
    if (!reducer_seed_floor_height_read(progress_db, &seed_floor,
                                        &floor_found))
        LOG_RETURN(false, SHI_BIND_GUARD_SUBSYS,
                   "bind guard: seed-floor read failed (progress.kv read "
                   "error) — refusing rather than guessing the bind anchor");

    int32_t coins_best = -1;
    uint8_t cb_hash[32];
    bool cb_hash_found = false, cb_found = false;
    if (!reducer_frontier_derive_coins_best(progress_db, &coins_best, cb_hash,
                                            &cb_hash_found, &cb_found))
        LOG_RETURN(false, SHI_BIND_GUARD_SUBSYS,
                   "bind guard: coins-best derive failed (progress.kv read "
                   "error) — refusing rather than guessing the fold-resume "
                   "anchor");
    if (!floor_found && !cb_found)
        return true;   /* no coins authority yet — fresh datadir, legal */
    int64_t anchor =
        floor_found ? (int64_t)seed_floor : (int64_t)coins_best;
    if (coins_best_out)
        *coins_best_out = (int32_t)anchor;
    if (tip_height == anchor)
        return true;
    LOG_RETURN(false, SHI_BIND_GUARD_SUBSYS,
               "bind guard REFUSAL: tip bind h=%lld != bind anchor h=%lld "
               "(%s) — importing would key the shielded frontier %lld "
               "block(s) off the resume point and the fold would hard-wedge "
               "at the first Sapling-commitment block above the island "
               "(hashFinalSaplingRoot mismatch). Refusing; nothing "
               "committed.",
               (long long)tip_height, (long long)anchor,
               floor_found ? "durable seed floor" : "coins island root",
               (long long)(tip_height - anchor));
}
