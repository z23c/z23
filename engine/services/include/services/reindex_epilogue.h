/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * reindex_epilogue — derive ALL durable post-reindex state from the
 * just-replayed or verified-imported UTXO set in ONE ordered commit discipline
 * so the recovery path can never manufacture the coins_applied > hstar wedge.
 *
 * tenacity-roadmap item 3: -reindex-chainstate (the crash-only auto-recovery
 * verb) ends torn without this epilogue — boot_index_clear_coins_state DELETES the SHA3
 * commitment + coins_best cache but nothing recomputes them, coins_kv is never
 * reseeded, and the 8 reducer stage cursors + coins_applied_height keep their
 * STALE pre-reindex values. Stale cursors over a freshly-rebuilt coin set
 * manufacture the coins_applied > hstar coin-tear shape; with the never-give-up
 * unit that degrades into an infinite reindex loop. This epilogue closes it by
 * DERIVING every value from the replayed authoritative set. Snapshot import
 * uses the same epilogue so a verified local snapshot is a fast rebuild, not
 * a weaker second authority path. */

#ifndef ZCL_SERVICES_REINDEX_EPILOGUE_H
#define ZCL_SERVICES_REINDEX_EPILOGUE_H

#include <stdbool.h>
#include <stdint.h>

struct main_state;
struct node_db;

/* Run after a SUCCESSFUL full reindex replay (errors==0, coins flushed to the
 * `utxos` mirror, g_utxo_commitment_skip CLEARED by the caller). Derives, in
 * order: (1) reset+reseed coins_kv from the mirror + migration stamp;
 * (2) recompute the SHA3 commitment + count, stamp utxo_sha3 + coins_best_block
 * cache; (3) raise coins_applied_height to tip+1 FIRST, then clamp the
 * tip_finalize anchor + 8 stage cursors to the replayed tip via the
 * trusted-seed convention; (4) self-check H* == replayed tip; (5) require the
 * bounded shielded replay session at tip+1 and atomically publish Sprout,
 * Sapling, and nullifier completeness.
 *
 * Returns true iff all derivations land AND H* == tip. Best-effort-but-LOUD:
 * any failure logs, PAGES (EV_OPERATOR_NEEDED + typed reason), and returns
 * false so the caller leaves the reindex sentinel pending for a next-boot
 * retry — bounded by the existing auto-reindex attempt budget, never FATAL,
 * never a silent infinite loop.
 *
 * `datadir` locates <datadir>/node.db for the coins_kv reseed copy. */
bool reindex_epilogue_derive(struct main_state *ms, struct node_db *ndb,
                             const char *datadir);

/* Run after a verified snapshot import has populated node.db `utxos`.
 * This is the same authority-derivation epilogue used by full reindex, but the
 * source is a SHA3/anchor-verified snapshot rather than a genesis replay. */
bool reindex_epilogue_derive_imported_snapshot(struct node_db *ndb,
                                               const char *node_db_path,
                                               int height,
                                               const uint8_t hash[32]);

#endif /* ZCL_SERVICES_REINDEX_EPILOGUE_H */
