/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Hot-swap SHELF — the depth-1 retained predecessor image, per source TU.
 *
 * The loader could always roll FORWARD and it counted failed-swap unwinds, but
 * it could never be told "put back the module that was live before this one":
 * at commit the superseded module was handed to retire_handle(), which
 * dlclose()s the mapping and close()s its sealed image. The bytes were gone.
 *
 * WHAT IS RETAINED, AND WHY THAT AND NOTHING ELSE.
 * The shelf keeps the superseded SEALED IMAGE (a dup() of the memfd), never
 * the mapped handle:
 *   - it is cheap: ~121 KB of page cache per source, one descriptor;
 *   - F_SEAL_WRITE lives on the INODE, so a shelved image provably still is
 *     the bytes that were admitted — a shelf entry cannot rot into something
 *     else the way a path can;
 *   - holding the fd does NOT hold the code mapped, so the existing
 *     dlclose-after-drain reclamation is completely unaffected. The dup() is
 *     taken BEFORE the original descriptor is handed to retire_handle(), so
 *     there is exactly one owner per descriptor and retire's close() is
 *     unchanged.
 * Depth is 1 by construction (ZCL_HOTSWAP_SHELF_DEPTH): shelving a new image
 * close()s the outgoing one. Fixed table, no growth.
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
 * this loader exists to avoid. It would also dangle: for a module that DID
 * come from a .so, its struct lives in a mapping retire_handle() may dlclose.
 * So the shelf holds bytes, and bytes are the only thing the gauntlet eats.
 *
 * A CONSEQUENCE WORTH STATING: `artifact_sha256` on a shelf entry is never
 * empty and never inferred. Every image that can reach the shelf was hashed
 * from its own sealed descriptor by the loader before it was ever mapped, so
 * an entry always names exactly the bytes it holds — after a forward
 * supersede and after a rollback supersede alike.
 *
 * WHAT ROLLBACK MEANS HERE — read this before assuming.
 * hotswap_rollback() returns a source to its PREVIOUS MODULE, not to its
 * compiled-in baseline implementation. The command registry has no per-leaf
 * removal: zcl_command_registry_replace_batch() only overwrites or appends
 * override slots, and the sole clearing entry point wipes ALL overrides at
 * once and is test-only. So rollback works by REPUBLISHING the older module
 * over the same leaf paths. A source whose first swap is still live therefore
 * has nothing shelved and cannot be rolled back at all.
 *
 * ROLLBACK RE-ENTERS THE FULL ADMISSION GAUNTLET. It is not a "we already
 * checked this one" shortcut — a second door into module activation is exactly
 * the cloned-implementation defect this tree keeps paying for. The shelved
 * image is dup()ed and pushed through the same dev-datadir confinement, the
 * same -hotswap-activate + ZCL_HOTSWAP_ACTIVATE=1 gate, and the same shape
 * probe, hash, dlopen, symbol, consensus-pin, admit, probe-before-publish and
 * one-batch-commit sequence a forward swap runs. The gate is re-checked at
 * the moment of the rollback, never remembered from the original activation.
 * The single stage that cannot re-run is hotswap_path_is_acceptable(): a
 * shelf image has no path. That check is about where bytes came from, and
 * these bytes passed it before they were ever mapped — it is skipped
 * knowingly, not silently, and it is the only one.
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

#ifdef __cplusplus
}
#endif

#endif /* ZCL_HOTSWAP_SHELF_H */
