/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * boot_header_seed_import — import a swarm-downloaded header-chain seed
 * (block_index.bin, ROM_ARTIFACT_HEADER_SEED) into the in-memory header index
 * at boot so a fresh instant-on node climbs pindex_best_header to the artifact
 * tip WITHOUT the serial ~4.7 GB P2P header crawl that otherwise gates the
 * checkpoint-bundle install.
 *
 * Trust model (consensus parity — calls only frozen verifiers, defines none):
 * the artifact arrived content-verified by rom_fetch (per-chunk + whole-file
 * SHA3). This importer reuses load_block_index_flat, which re-verifies the
 * embedded SHA3, runs the per-row PoW-target admission gate
 * (block_row_verify → CheckProofOfWork) with per-row quarantine of a failing
 * row, and reconciles persisted FAILED bits against the baked ROM checkpoint —
 * so a bad/forged artifact wastes bandwidth, it never poisons state. On top of
 * that, this importer forces HEADER-ONLY semantics on every imported row
 * (strips HAVE_DATA/HAVE_UNDO, clears stale file positions, clamps VALID level
 * to <= BLOCK_VALID_TREE): it NEVER trusts the seeder's persisted body/script
 * validity or data availability, so every block body is re-fetched and fully
 * re-validated (full Equihash) as the reducer folds forward from the installed
 * checkpoint. The final consensus bind stays exactly where it already is: the
 * install gate (consensus_state_checkpoint_header_ready) independently requires
 * the imported chain to own the baked checkpoint block hash before any bundle
 * installs. */

#ifndef ZCL_CONFIG_BOOT_HEADER_SEED_IMPORT_H
#define ZCL_CONFIG_BOOT_HEADER_SEED_IMPORT_H

#include <stdbool.h>

struct main_state;

/* Import a downloaded <datadir>/bundles/block_index.bin header seed into `ms`'s
 * block-index map. STRICT NO-OP (returns false) when: the artifact is absent,
 * seeding is opted out (ZCL_NO_BUNDLE_FETCH), the datadir is already sovereign
 * (bundle-installed marker), a header index is already populated (this only
 * seeds a fresh/near-empty map), or the root block_index.bin already exists
 * (the boot ladder consumed it). On a real import it moves the artifact to the
 * datadir root (so the rom_seed scan re-serves it and the flat loader finds
 * it), loads it via the shared verified flat loader, applies the header-only
 * clamp, publishes pindex_best_header, and names a typed blocker (never a fatal
 * abort — always fail-open to P2P IBD) when the load fails or the imported
 * chain does not own the baked checkpoint. Returns true iff headers landed. */
bool boot_header_seed_import_maybe(const char *datadir, struct main_state *ms);

#endif /* ZCL_CONFIG_BOOT_HEADER_SEED_IMPORT_H */
