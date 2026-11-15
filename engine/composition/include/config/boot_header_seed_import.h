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

/* What the header index the boot ladder already loaded says about the seed.
 * The fetch gate (boot_bundle_fetch.c) and the import below both decide from
 * this one verdict, so they cannot disagree. Only FRESH and STUB let the seed
 * land; every other verdict leaves the datadir exactly as it is. */
enum boot_header_seed_index_verdict {
    /* No <datadir>/block_index.bin and no local body or tip: a fresh node. */
    BOOT_HEADER_SEED_INDEX_FRESH = 0,
    /* A root block_index.bin is present but the loaded index is a replaceable
     * stub: 1..1024 rows, no row above genesis holds local body data
     * (BLOCK_HAVE_DATA / BLOCK_HAVE_UNDO), and the active tip is genesis or
     * absent. A first boot that stopped before the seed imported. */
    BOOT_HEADER_SEED_INDEX_STUB,
    /* A root block_index.bin is present but no index (or an empty one) was
     * loaded from it: nothing says it is a stub, so it is left alone. */
    BOOT_HEADER_SEED_INDEX_NOT_LOADED,
    /* More than 1024 rows: an already-synced or imported header index. */
    BOOT_HEADER_SEED_INDEX_POPULATED,
    /* A row above genesis holds this node's own body or undo data. */
    BOOT_HEADER_SEED_INDEX_BODY_DATA,
    /* The active chain tip is above genesis. */
    BOOT_HEADER_SEED_INDEX_TIP_ABOVE_GENESIS,
};

/* Classify the loaded header index `ms` (NULL means "not given") for a datadir
 * whose root block_index.bin is (`root_present`) or is not present. Reads the
 * row count first, so a populated multi-million-row index is never walked. */
enum boot_header_seed_index_verdict
boot_header_seed_index_verdict(const struct main_state *ms, bool root_present);

/* True iff the verdict lets the seed land (FRESH or STUB). */
bool boot_header_seed_index_verdict_allows(enum boot_header_seed_index_verdict v);

/* One fixed sentence naming why the verdict was reached (for the INFO lines). */
const char *
boot_header_seed_index_verdict_reason(enum boot_header_seed_index_verdict v);

/* Import a downloaded <datadir>/bundles/block_index.bin header seed into `ms`'s
 * block-index map. STRICT NO-OP (returns false) when: the artifact is absent,
 * seeding is opted out (ZCL_NO_BUNDLE_FETCH), the datadir is already sovereign
 * (bundle-installed marker), or the loaded index is anything but FRESH or STUB
 * (see boot_header_seed_index_verdict). On a real import it moves the artifact
 * to the datadir root (so the rom_seed scan re-serves it and the flat loader
 * finds it) — atomically replacing a STUB root file — loads it via the shared
 * verified flat loader, applies the header-only clamp, publishes
 * pindex_best_header, and names a typed blocker (never a fatal abort — always
 * fail-open to P2P IBD) when the load fails or the imported chain does not own
 * the baked checkpoint. Returns true iff headers landed. */
bool boot_header_seed_import_maybe(const char *datadir, struct main_state *ms);

#endif /* ZCL_CONFIG_BOOT_HEADER_SEED_IMPORT_H */
