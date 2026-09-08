/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * rom_fetch_orphan_sweep — reclaim the disk an abandoned ROM download left
 * behind, without ever touching one that can still finish.
 *
 * An interrupted per-chunk ROM fetch deliberately leaves TWO files side by
 * side in `<datadir>/bundles/`: the staging file `<name>.part` and its durable
 * resume journal `<name>.part.journal` (core/modules/net/src/rom_fetch.c,
 * core/modules/net/include/net/rom_journal.h). That pair is the feature — a
 * restarted node re-fetches only the chunks the journal has not marked, so a
 * kill-9 halfway through a 20 GB bundle costs seconds, not hours.
 *
 * The cost of that feature is that nothing ever removed a pair whose download
 * will never be resumed: the operator picked a different bundle, the seeder
 * stopped offering that artifact, the node moved to a newer height. Those
 * pairs sat in the datadir forever. This sweep is the eviction policy.
 *
 * THE STALENESS RULE, exactly — a pair is removed only when BOTH hold:
 *
 *   1. ORPHANED: no currently-registered ROM artifact (rom_seed's read-only
 *      registry) carries the pair's target filename. A `.part` whose target
 *      nothing offers any more has nothing left to resume toward.
 *   2. STALE: the newer of the pair's two modification times is at least
 *      `horizon_sec` old. A download that is running right now touches its
 *      journal after every chunk, so a live transfer — including the one this
 *      boot may have just started — is never inside the sweep's reach.
 *
 * Requiring both is deliberately conservative. A false positive is not a
 * correctness bug (the journal header pins the manifest identity, so a
 * re-created download can never silently trust foreign bytes), but it does
 * cost the operator a full re-download, which is a real regression. Nothing is
 * removed that this sweep cannot positively identify as both unwanted and
 * idle.
 *
 * BOTH OR NEITHER. The two files of a pair are only ever removed together.
 * A lone `.part` with no journal sibling, or a lone journal with no `.part`,
 * is not a pair and is left exactly where it is — this sweep owns the pair
 * shape and nothing else.
 *
 * Scope: `<datadir>/bundles/` only, one bounded non-recursive pass, no
 * threads, no network, no state carried between calls. */

#ifndef ZCL_CONFIG_ROM_FETCH_ORPHAN_SWEEP_H
#define ZCL_CONFIG_ROM_FETCH_ORPHAN_SWEEP_H

#include <stdbool.h>
#include <stdint.h>

/* Six hours. Generous on purpose: the horizon's whole job is to keep a slow
 * or paused transfer out of the sweep's reach, and a stalled 20 GB fetch over
 * a thin link can legitimately go a long while between chunks. Disk is cheap;
 * a needless re-download is not. Override with
 * ZCL_ROM_FETCH_ORPHAN_HORIZON_SEC (engine/composition/flags.def). */
#define ROM_FETCH_ORPHAN_HORIZON_SEC_DEFAULT (6u * 60u * 60u)

/* Candidate pairs examined in one sweep. Matched to the ROM registry bound
 * (ROM_SEED_MAX_ARTIFACTS) — a datadir holding more in-progress downloads than
 * the node can register artifacts is pathological, so the cap is a runaway
 * stop, not a routine limit. When it fires the sweep says so in `capped`
 * rather than quietly reporting a short count. */
#define ROM_FETCH_ORPHAN_SWEEP_MAX_PAIRS 8u

/* What one sweep did. Counts, never a list: the log lines name each pair and
 * the reason, and the caller wants the totals. */
struct rom_fetch_orphan_sweep_result {
    uint32_t pairs_seen;      /* `.part` files that had a journal sibling    */
    uint32_t pairs_removed;   /* pairs unlinked — both files                 */
    uint32_t pairs_kept;      /* still registered, or younger than horizon   */
    uint32_t pairs_failed;    /* an unlink refused; reported, never hidden   */
    uint64_t bytes_reclaimed; /* `.part` + journal bytes of removed pairs    */
    bool     capped;          /* the bounded pass stopped early              */
};

/* Sweep `<datadir>/bundles/` once under the rule in this file's header.
 * `horizon_sec` is the staleness horizon in seconds; pass
 * rom_fetch_orphan_sweep_horizon_sec() for the configured default. Fills
 * `*out` (zeroed first) when `out` is non-NULL.
 *
 * Returns true when the pass completed — including the ordinary case of
 * finding nothing to do. Returns false only when the sweep could not run at
 * all (no datadir, unreadable bundles directory) or an unlink refused; the
 * caller treats that as information, not a boot failure. */
bool rom_fetch_orphan_sweep_run(const char *datadir, uint32_t horizon_sec,
                                struct rom_fetch_orphan_sweep_result *out);

/* The configured horizon: ZCL_ROM_FETCH_ORPHAN_HORIZON_SEC when it parses as
 * a positive integer, else ROM_FETCH_ORPHAN_HORIZON_SEC_DEFAULT. A malformed
 * or non-positive value is ignored (with a warning) rather than obeyed — an
 * operator typo must not shorten the horizon to zero and sweep a live
 * download. */
uint32_t rom_fetch_orphan_sweep_horizon_sec(void);

#endif /* ZCL_CONFIG_ROM_FETCH_ORPHAN_SWEEP_H */
