/* Copyright (c) 2009-2010 Satoshi Nakamoto
 * Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#ifndef ZCL_VALIDATION_CONNECT_BLOCK_H
#define ZCL_VALIDATION_CONNECT_BLOCK_H

#include "chain/chain.h"
#include "chain/chainparams.h"
#include "coins/coins_view.h"
#include "coins/undo.h"
#include "consensus/validation.h"
#include "primitives/block.h"
#include "sapling/incremental_merkle_tree.h"
#include <stdbool.h>

/* Set the Sapling commitment tree for connect_block to update and verify.
 * Must be called before connect_block. Set to NULL for just_check mode. */
void connect_block_set_sapling_tree(struct incremental_merkle_tree *tree);

/* ── Sapling-root parity enforcement (DEFAULT-OFF) ──────────────────────
 *
 * When false (the DEFAULT), connect_block keeps EXACTLY today's behavior:
 * post-Sapling-activation it rejects ONLY an all-zeros hashFinalSaplingRoot
 * ("bad-sapling-root-zeroed"). A wrong NON-ZERO root is still accepted —
 * a known latent leniency vs zclassicd (project_sapling_root_parity_hole).
 *
 * When true, connect_block ALSO runs the pure recompute predicate
 * sapling_root_matches() below and rejects ANY mismatch between the
 * block's hashFinalSaplingRoot and the locally-recomputed Sapling
 * commitment-tree root ("bad-sapling-root-mismatch"), matching zclassicd
 * (CheckBlock / ConnectBlock anchor check, which rejects ANY mismatch).
 *
 * ⚠ DO NOT enable on the live node (set the runtime flag, or flip this
 *   default) until a FULL-HISTORY REPLAY against the real chain confirms
 *   ZERO false-rejects. This is the h=478544 lesson (CLAUDE.md "Consensus
 *   rule: validate against the CHAIN, not the reference text"): a bounded
 *   predicate that looks tighter-is-better can false-reject a real,
 *   already-mined block and wedge forward sync. Parity tightening of a
 *   bounded predicate requires a real-chain replay FIRST. Default-off keeps
 *   default behavior byte-identical until that replay proves it safe.
 *
 * Set by the node from the -enforce-sapling-root argv flag (engine/entry/main.c).
 * Default false. _Atomic so a background validation thread can read it
 * without a lock. */
extern _Atomic _Bool g_enforce_sapling_root;

/* DEFAULT-OFF CHECKDATASIG_SIGOPS parity flag.
 * When true, connect_block ORs SCRIPT_VERIFY_CHECKDATASIG_SIGOPS into its
 * script verification flags, matching zclassicd ConnectBlock
 * (zclassic-cpp/src/main.cpp:2567). That bit makes OP_CHECKDATASIG /
 * OP_CHECKDATASIGVERIFY count toward the per-block MAX_BLOCK_SIGOPS ceiling.
 * Default false ⇒ connect_block's flags are byte-identical to today
 * (P2SH | CHECKLOCKTIMEVERIFY only).
 *
 * ⚠ This is a tightening (reject) predicate: setting the bit can only RAISE
 *   a block's counted sigop total, so a previously-accepted block could now
 *   exceed the cap. Do NOT flip the default or pass -enforce-checkdatasig-sigops
 *   on the live node until a FULL-HISTORY REPLAY against the real chain
 *   confirms ZERO false-rejects (the h=478544 lesson — see the
 *   g_enforce_sapling_root warning above).
 *
 * Set by the node from the -enforce-checkdatasig-sigops argv flag
 * (engine/entry/main.c). Default false. _Atomic so a background validation thread can
 * read it without a lock. */
extern _Atomic _Bool g_enforce_checkdatasig_sigops;

/* PURE recompute predicate. Given `pre_block_tree` — the Sapling
 * commitment-tree frontier as it stood AFTER the parent block and BEFORE
 * `block` — recompute the tree root that `block` should commit to (by
 * appending every Sapling output commitment in `block`, in order) and
 * compare it to `block`'s hashFinalSaplingRoot.
 *
 * Side-effect-free: operates on a value-copy of `pre_block_tree`, touches
 * no DB / no globals, and never mutates its inputs. Returns true iff the
 * recomputed root byte-equals the header root. `pre_block_tree` may be
 * NULL, in which case the predicate cannot recompute and returns true
 * (cannot-decide → do-not-reject), so it can never false-reject when the
 * caller has no frontier to fold from. */
_Bool sapling_root_matches(const struct block *block,
                           const struct incremental_merkle_tree *pre_block_tree);

/* Connect `block` at `pindex` against `view`, applying its inputs/outputs.
 * just_check — when true, run full validation (all script/proof/conservation
 *   checks and the coins-view updates against the scratch `view`) but commit
 *   NO persistent state: connect_block returns as soon as validation succeeds
 *   without writing the best-block/tip. Used for dry-run checks of a candidate
 *   before committing. When false, the block is connected for real and its
 *   state changes are applied. Returns false (with `state` populated) on any
 *   validation failure or internal error. */
bool connect_block(const struct block *block,
                   struct validation_state *state,
                   struct block_index *pindex,
                   struct coins_view_cache *view,
                   const struct chain_params *params,
                   bool just_check);

bool disconnect_block(const struct block *block,
                      struct validation_state *state,
                      struct block_index *pindex,
                      struct coins_view_cache *view,
                      const struct block_undo *blockundo);

#endif
