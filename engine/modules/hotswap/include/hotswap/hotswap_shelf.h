/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Hot-swap IMAGE COMMIT + the depth-1 rollback SHELF.
 *
 * Two things live here because they are one mechanism:
 *
 *   1. hotswap_commit_image() — the step that makes a freshly published module
 *      image the live one for its source, and decides which image (if any) may
 *      now be UNMAPPED. Retirement safety is decided here and nowhere else.
 *   2. The SHELF — the depth-1 retained predecessor image, so an operator can
 *      say "put back the module that was live before this one".
 *
 * ── WHY RETIREMENT IS DECIDED FROM THE REGISTRY GENERATION ────────────────
 *
 * A module swap is two steps that are NOT one atomic step:
 *
 *      (a) hotswap_module_publish()  -> the command registry publishes a new
 *          override snapshot and assigns it a generation, under the registry's
 *          own write lock.
 *      (b) the loader records "this handle is now live for this source" and
 *          hands the PREVIOUS handle to the retire path, which may dlclose it.
 *
 * Step (a) happens outside any loader lock, because it runs resident probe and
 * commit callbacks. So two activations of the SAME source can interleave with
 * (a) in one order and (b) in the other:
 *
 *      R: publish  -> generation 5, registry now dispatches into image R
 *      F: publish  -> generation 6, registry now dispatches into image F
 *      F: record   -> slot says image F is live, hands image OLD to retire
 *      R: record   -> slot says image R is live, hands image F to retire
 *      R: retire(image F) -> every RETIRED snapshot has drained, so the old
 *         quiescence test says "safe" and image F is unmapped — while the
 *         ACTIVE snapshot is generation 6, which dispatches into image F.
 *
 * That is a use-after-free of executable pages, and the drain test cannot see
 * it: drain only proves nothing is still INSIDE a retired snapshot, and the
 * ACTIVE snapshot is deliberately skipped (it is always live). The defect is
 * that (b) trusted the loader's own arrival order to say which image the
 * registry considers live. It does not; only the registry generation does.
 *
 * So the commit uses the generation the registry assigned as the ONE ordering
 * authority:
 *
 *   - a commit whose generation is newer than the slot's becomes live, and the
 *     slot's previous image is the retirement candidate;
 *   - a commit whose generation is NOT newer lost the race in the registry, so
 *     it never touches the slot or the shelf and offers ITSELF as the
 *     retirement candidate instead.
 *
 * ── AND NOTHING IS UNMAPPED WITHOUT A PROOF ───────────────────────────────
 *
 * Ordering alone is not enough, and an unmap must never rest on bookkeeping
 * being right. Every candidate must clear BOTH gates before it is unmapped:
 *
 *   DRAIN      no in-flight dispatch is still inside a retired snapshot
 *              (the resident's quiesced hook — unchanged).
 *   REFERENCE  no leaf the candidate published is still owned by the
 *              candidate's own generation in the live-leaf ownership table
 *              this file maintains. A leaf's owner is the HIGHEST generation
 *              that ever published it, which is exactly the merge rule the
 *              registry's snapshot uses, so the answer does not depend on the
 *              order the loader's threads arrive in.
 *
 * The REFERENCE gate also closes a defect that is not a race at all: a module
 * is admitted if every leaf it declares is on its allowlist row, NOT if it
 * declares all of them. A v2 that drops a leaf leaves v1's handler live in the
 * merged snapshot, and unmapping v1 would be a use-after-free on the next
 * dispatch of the dropped leaf. The reference gate refuses that unmap.
 *
 * ON DOUBT WE LEAK, ALWAYS. Anything unproven — an untracked leaf, a full
 * ownership table, an unconfirmed drain — keeps the mapping. A retained
 * mapping is ~121 KB plus one descriptor and is already NAMED by the
 * hotswap.retired_generation_undrained blocker with a reclaim retry; a
 * use-after-free in a consensus node is not recoverable. The leak is bounded
 * by one mapping per swap, and swaps are operator-initiated.
 *
 * ── WHAT IS SHELVED, AND WHY THAT AND NOTHING ELSE ────────────────────────
 * The shelf keeps the superseded SEALED IMAGE (a dup() of the memfd), never
 * the mapped handle:
 *   - it is cheap: ~121 KB of page cache per source, one descriptor;
 *   - F_SEAL_WRITE lives on the INODE, so a shelved image provably still is
 *     the bytes that were admitted — a shelf entry cannot rot into something
 *     else the way a path can;
 *   - holding the fd does NOT hold the code mapped, so the retirement decision
 *     above is completely unaffected. The dup() is taken BEFORE the original
 *     descriptor is handed to the retire path, so there is exactly one owner
 *     per descriptor.
 * Depth is 1 by construction (ZCL_HOTSWAP_SHELF_DEPTH): shelving a new image
 * close()s the outgoing one. Fixed table, no growth. Only the commit that WON
 * the generation race writes the shelf, so a shelf entry always names the
 * image the registry actually superseded.
 *
 * AN IMAGE IS THE ONLY THING SHELVED — a security property, not a
 * convenience. Only the real, dlopen-based activation path shelves anything.
 * hotswap_module_publish(), the pure always-compiled admit/probe/commit
 * gauntlet that any caller may drive with a module struct that never was a
 * file, never puts anything on the shelf, however many times it publishes.
 * Retaining such a struct instead would mean rollback could republish live
 * handlers from a pointer, with no bytes to re-hash, no ELF shape to re-probe,
 * no consensus pin to re-check, and — because those checks live on the loader
 * path — no dev-datadir confinement and no activation gate either. That is a
 * second door into activation, which is exactly the duplicate-system defect
 * this loader exists to avoid. So the shelf holds bytes, and bytes are the
 * only thing the gauntlet eats.
 *
 * ── WHAT ROLLBACK MEANS HERE — read this before assuming ──────────────────
 * hotswap_rollback() returns a source to its PREVIOUS MODULE, not to its
 * compiled-in baseline implementation. The command registry has no per-leaf
 * removal: zcl_command_registry_replace_batch() only overwrites or appends
 * override slots, and the sole clearing entry point wipes ALL overrides at
 * once and is test-only. So rollback works by REPUBLISHING the older module
 * over the same leaf paths. A source whose first swap is still live therefore
 * has nothing shelved and cannot be rolled back at all.
 *
 * ROLLBACK RE-ENTERS THE FULL ADMISSION GAUNTLET. It is not a "we already
 * checked this one" shortcut. The shelved image is dup()ed and pushed through
 * the same dev-datadir confinement, the same -hotswap-activate +
 * ZCL_HOTSWAP_ACTIVATE=1 gate, and the same shape probe, hash, dlopen, symbol,
 * consensus-pin, admit, probe-before-publish and one-batch-commit sequence a
 * forward swap runs. The gate is re-checked at the moment of the rollback,
 * never remembered from the original activation. The single stage that cannot
 * re-run is hotswap_path_is_acceptable(): a shelf image has no path. That
 * check is about where bytes came from, and these bytes passed it before they
 * were ever mapped — it is skipped knowingly, and skipped nowhere else.
 *
 * ⛔ OPERATOR-INITIATED ONLY — a stated precondition, not a style note.
 * Each successful rollback publishes a registry snapshot, and published
 * snapshots are DELIBERATELY never freed (lock-free dispatch readers hold
 * snapshot pointers optimistically, so reclaiming one would be a
 * use-after-free). The registry's own rationale rests on "writes are rare (hot
 * swaps)". Rollback is a toggle: call it twice and you are back where you
 * started, so anything that fires it automatically — a retry, a watchdog, a
 * health check, an "activation failed, put the old one back" handler — turns a
 * rare write into a loop, i.e. a memory leak with a clock on it. Wire it to an
 * operator command and to nothing else.
 */

#ifndef ZCL_HOTSWAP_SHELF_H
#define ZCL_HOTSWAP_SHELF_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>

#include "hotswap/hotswap_module.h"

#ifdef __cplusplus
extern "C" {
#endif

/* One retained predecessor per source TU. Not a tunable: the retire path owns
 * exactly one superseded image at a time, and a deeper shelf would need a
 * retention policy the loader does not have. */
#define ZCL_HOTSWAP_SHELF_DEPTH 1

struct hotswap_shelf_entry {
    char     source_tu[256];
    char     artifact_sha256[65];
    uint32_t generation;        /* registry generation the image had when live */
    time_t   retired_at;
    bool     present;
};

/* Fills up to `cap` entries; returns the number of sources that have a
 * shelved image (which may exceed `cap` — the return is the true count, not
 * the number written). `out` may be NULL when `cap` is 0, to count only.
 * Never blocks the dispatch path: dispatch is lock-free and never touches the
 * activation lock this reads under. */
size_t hotswap_shelf_list(struct hotswap_shelf_entry *out, size_t cap);

/* False if `source_tu` is unknown or has nothing shelved. */
bool hotswap_shelf_peek(const char *source_tu, struct hotswap_shelf_entry *out);

/* Put the shelved image back, through the full admission gauntlet.
 * On success the image that WAS live becomes the new shelf entry, so a second
 * call returns to where you started (rollback is a toggle).
 * On failure nothing changes and `report` carries the stage that refused.
 *
 * Requires exactly the authority a forward resident swap requires: the image
 * is re-admitted under the dev datadir it was admitted with, and the
 * -hotswap-activate + ZCL_HOTSWAP_ACTIVATE=1 gate is re-checked now, not
 * remembered from the original activation.
 *
 * Refuses at stage "shelf" when the source is unknown, has nothing shelved,
 * or already has a rollback in flight; the refusal populates `report` and
 * changes nothing.
 *
 * DEV-ONLY: without ZCL_DEV_BUILD this refuses at stage "release", exactly
 * like hotswap_activate(). */
bool hotswap_rollback(const char *source_tu,
                      const struct hotswap_publish_hooks *hooks,
                      struct hotswap_activate_report *report);

/* ── The commit step ──────────────────────────────────────────────────────
 *
 * Called once per SUCCESSFUL publish, by the activation gauntlet, after
 * hotswap_module_publish() has committed the batch and the registry has
 * assigned `generation`. It records the image against its source, maintains
 * the shelf, and applies the ordering + reference proof described at the top
 * of this file before anything is unmapped.
 *
 * `unmap` is how a mapping is released. The loader passes the dynamic-loader
 * release; a test passes its own observer. It is NEVER called for an image
 * that failed either gate.
 *
 * TAKES OWNERSHIP of `fd` on every path (the slot keeps it while the image is
 * live; the retire path closes it; a candidate retained for lack of proof
 * keeps it, matching its mapping).
 *
 * Returns true when this image became the live one for its source. It returns
 * false in the two cases where it did not, both of which the loader treats the
 * same way (the swap itself has already committed in the registry, so neither
 * is an activation failure):
 *   - the fixed slot table is full, so nothing was recorded and nothing was
 *     retired, and the caller's mapping is kept;
 *   - a NEWER generation for this source was already recorded, so this image
 *     lost the registry race and is itself the retirement candidate. */
typedef void (*hotswap_unmap_fn)(void *handle);

struct hotswap_commit_image {
    const char *source_tu;
    void       *handle;          /* the live mapping for this image */
    int         fd;              /* sealed image descriptor, or -1 */
    const struct zcl_hotswap_leaf *leaves;
    uint32_t    leaf_count;
    uint32_t    generation;      /* THE ordering authority: from the registry */
    const char *artifact_sha256;
    const char *resolved_datadir;
    hotswap_unmap_fn unmap;
    const struct hotswap_publish_hooks *hooks;   /* for `quiesced` only */
};

bool hotswap_commit_image(const struct hotswap_commit_image *req);

/* Commits that arrived after a NEWER generation for the same source had
 * already been recorded — i.e. the publish order and the loader's arrival
 * order disagreed. Zero on a quiet node. A concurrency test asserts this is
 * NON-zero before believing it produced the interleaving it set out to test:
 * a race test that never raced proves nothing. */
uint64_t hotswap_stale_commit_count(void);

/* Images that were NOT unmapped because a leaf they published is still owned
 * by their own generation, i.e. the live snapshot still dispatches into them.
 * Every one of these is a use-after-free that did not happen. */
uint64_t hotswap_reference_hold_count(void);

/* Attempt one reclaim pass over every mapping retained for lack of proof.
 * Same routine the hotswap.retired_generation_undrained blocker escape runs.
 * Returns true only when nothing is left retained. */
bool hotswap_reclaim_retained_now(void);

/* Test hook: drop every slot, shelf entry, pending retirement and leaf
 * ownership record, closing descriptors this module owns. Does NOT unmap
 * anything (the caller's images outlive it) and does not touch the blocker
 * registry (use blocker_reset_for_testing). */
void hotswap_activation_reset_for_testing(void);

#ifdef __cplusplus
}
#endif

#endif /* ZCL_HOTSWAP_SHELF_H */
