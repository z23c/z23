/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * rom_bundle_admission — receipt-gated registration of a consensus-state
 * bundle into the ROM-seed catalog (net/rom_seed.h), so any node holding a
 * two-builder-verified bundle + its independent replay receipt can become a
 * free-tier P2P recovery source for it, not just the single machine the
 * bundle was originally exported/verified on.
 *
 * net/rom_seed.h's own rom_seed_scan_datadir() / rom_seed_register() admit a
 * consensus-state-bundle-*.sqlite file purely on structural grounds (SQLite
 * magic bytes + size band) — that is intentional there: rom_seed is the
 * generic low-level registry/serve primitive and every fetcher independently
 * re-verifies content after download regardless of what a seeder claims
 * (docs/ROM_DELIVERY.md, "Trust model"). This module adds a STRICTER,
 * OPTIONAL admission gate on top of that primitive, specifically for bundles
 * placed in a "designated replica" directory a second disk / second node
 * feeds via tools/scripts/rom-bundle-replicate.sh: register the bundle into
 * the shared rom_seed catalog ONLY when an adjoining
 * consensus_state_replay_receipt.v1 file (config/consensus_state_replay_
 * receipt.h) self-verifies AND binds this exact bundle's whole-file SHA3-256
 * digest. Fail-closed: no receipt (missing, corrupt, or bound to a
 * different bundle) means the bundle is never registered, so it is never
 * offered or served — never a partial/best-effort admission. */

#ifndef ZCL_CONFIG_ROM_BUNDLE_ADMISSION_H
#define ZCL_CONFIG_ROM_BUNDLE_ADMISSION_H

#include <stddef.h>
#include <stdint.h>

struct rom_artifact;

enum rom_bundle_admission_result {
    ROM_BUNDLE_ADMIT_OK = 0,
    ROM_BUNDLE_ADMIT_ERR_ARGS,          /* NULL/empty dir or filename        */
    ROM_BUNDLE_ADMIT_ERR_NOT_BUNDLE,    /* filename doesn't classify as the  */
                                        /*   consensus-bundle artifact kind  */
    ROM_BUNDLE_ADMIT_ERR_HASH,          /* could not read/hash the bundle    */
    ROM_BUNDLE_ADMIT_ERR_NO_RECEIPT,    /* fail-closed: no verifying receipt */
    ROM_BUNDLE_ADMIT_ERR_REGISTER,      /* receipt verified but rom_seed's   */
                                        /*   own structural check refused    */
};

/* Register the consensus-state bundle named `filename` inside `dir` into the
 * shared rom_seed catalog, ONLY if `dir/consensus_state_replay_receipt.v1`
 * self-verifies and binds this exact bundle's SHA3-256 whole-file digest.
 * `filename` must be a bare basename (no path separators/traversal — the same
 * rule rom_seed_register enforces). On ROM_BUNDLE_ADMIT_OK the artifact is
 * registered exactly as if rom_seed_register() had admitted it directly (same
 * registry, same serve path), and `*out` (if non-NULL) is filled with the
 * registered artifact. Every other result leaves the catalog untouched. */
enum rom_bundle_admission_result rom_bundle_admission_register(
    const char *dir, const char *filename, struct rom_artifact *out);

/* Bounded scan of `dir`: admits every consensus-state-bundle-*.sqlite entry
 * whose adjoining receipt verifies (as rom_bundle_admission_register above);
 * silently (LOG_WARN-only) skips anything that fails the gate. Returns the
 * number of bundles admitted. Mirrors rom_seed_scan_datadir's scan bound
 * (ROM_SEED_MAX_ARTIFACTS / a fixed directory-entry ceiling). */
int rom_bundle_admission_scan(const char *dir);

/* Supervised, single-shot background scan of `dir` (spawned + joined exactly
 * like rom_seed_start_scan/rom_seed_stop_scan). Idempotent; a no-op if `dir`
 * is NULL/empty. Called from boot when -rombundlereplicadir=PATH is set. */
void rom_bundle_admission_start_scan(const char *dir);
void rom_bundle_admission_stop_scan(void);

#endif /* ZCL_CONFIG_ROM_BUNDLE_ADMISSION_H */
