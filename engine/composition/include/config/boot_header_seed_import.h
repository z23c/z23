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
 * installs.
 *
 * What a seed may contribute is only what a compiled block hash binds: a seed
 * whose chain does not own the baked checkpoint is discarded whole, and from
 * one that does only the anchor block's row and its ancestors are kept. The
 * anchor is the highest compiled block hash the seed provably owns: a baked
 * state rung above the checkpoint (the hash a fresh node's install at that
 * rung already binds its header chain to) whose row, found by that hash, has
 * the checkpoint row and every lower rung's hash on its chain and the
 * compiled rung chainwork as its derived chainwork; else the baked
 * checkpoint. A row above the anchor, or off the anchor block's chain, is
 * bound by no compiled hash (its stored hash is checked only against its own
 * target, so forging one needs no Equihash solution); such rows are removed
 * before anything is saved or published, and the headers above the anchor
 * arrive by P2P header sync with full validation.
 *
 * Crash safety: the seed is loaded IN PLACE from <datadir>/bundles. The root
 * <datadir>/block_index.bin — the file the next boot's ladder loads as this
 * node's own index — is only ever written by this node's own flat save of the
 * bound, clamped map, and only after the decision. A STUB root is removed
 * just before that save, so the save is the flat writer's full
 * tmp+fsync+rename and never an in-place rewrite that a kill could leave
 * half-written. A kill before the rename leaves no root (or the stub, when
 * the removal was not yet durable) and the seed in bundles/, so the next boot
 * runs the same decision on it again; a root that does not load
 * (NOT_LOADED) is never produced by this import and is still never seeded. */

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
 * (see boot_header_seed_index_verdict). On a real import it loads the artifact
 * in place via the shared verified flat loader, decides checkpoint ownership,
 * keeps only the rows the anchor (checkpoint or owned state rung) binds,
 * applies the header-only clamp, removes a STUB root and writes the bound map
 * as the root index with the flat writer's full tmp+fsync+rename (the
 * rom_seed scan re-serves that file), removes the artifact, then publishes
 * pindex_best_header. It names a typed blocker (never a fatal
 * abort — always fail-open to P2P IBD) when the load fails, the imported chain
 * does not own the baked checkpoint, or the bound index cannot be written.
 * Returns true iff headers landed. */
bool boot_header_seed_import_maybe(const char *datadir, struct main_state *ms);

#ifdef ZCL_TESTING
/* Test seam: simulate process death at one named point of the NEXT import.
 * The import returns false there and does no further file or memory work, so
 * a test can run the next boot over exactly the files a kill would leave. */
enum boot_header_seed_kill_point {
    BOOT_HEADER_SEED_KILL_NONE = 0,
    BOOT_HEADER_SEED_KILL_AFTER_LOAD,     /* seed rows loaded, nothing decided */
    BOOT_HEADER_SEED_KILL_AFTER_DECISION, /* owned seed bound and clamped */
    BOOT_HEADER_SEED_KILL_AFTER_ROOT_UNLINK, /* stub root removed, not saved */
    BOOT_HEADER_SEED_KILL_AFTER_SAVE,     /* root index written */
};
void boot_header_seed_import_test_kill_at(enum boot_header_seed_kill_point p);
#endif

#endif /* ZCL_CONFIG_BOOT_HEADER_SEED_IMPORT_H */
