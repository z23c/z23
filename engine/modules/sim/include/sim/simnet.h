/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * simnet — deterministic, RAM-only single-node chain harness.
 *
 * The keystone the token / name / spend simulators build on: assemble a
 * block, drive it through the REAL consensus code (connect_block()), and
 * watch the in-memory UTXO state advance — with NO disk, NO real PoW, and
 * NO real funds.
 *
 *   assemble block  →  connect_block(&blk, &vs, &pindex, &view, &params,
 *                                    false)  →  coins_view advances in RAM
 *
 * How PoW / script validation is skipped WITHOUT touching consensus code:
 * simnet mints at heights covered by a synthetic checkpoint, so
 * connect_block sets expensive_checks=false (identical mechanism to
 * tests/harness/src/test_connect_block_self_write.c). We never modify a
 * consensus predicate — if a block is rejected, the harness fixed its own
 * block construction.
 *
 * State model (all in RAM, no sqlite):
 *   - `view`     : the live UTXO set (a coins_view_cache over a zeroed
 *                  backing view). This IS the chain state.
 *   - `tip`      : the current tip's block_index; `tip.hashBlock` is the
 *                  stable storage the next block's hashPrevBlock links to.
 *   - `params`   : a value-copy of chain_params_get() with a single
 *                  high-height checkpoint so every minted height is
 *                  "covered" (expensive_checks=false).
 *
 * Coinbase maturity: connect_block's real predicate is
 *   pindex->nHeight - coin.height >= COINBASE_MATURITY (100).
 * simnet_spend() honors it by minting the spending block at a height that
 * satisfies the predicate — see the note on simnet_spend below. Nothing at
 * the connect_block layer requires contiguous heights, so this is a
 * minimal, faithful way to produce a mature-coinbase spend through the real
 * validator.
 */

#ifndef ZCL_SIM_SIMNET_H
#define ZCL_SIM_SIMNET_H

#include "coins/coins_view.h"
#include "chain/chain.h"
#include "chain/chainparams.h"
#include "chain/checkpoints.h"
#include "core/uint256.h"

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct seed_tape seed_tape_t;

/* Forward decl — the optional in-sim Sapling note-commitment tree
 * (Sapling Lane C). Full type in sapling/incremental_merkle_tree.h; kept a
 * pointer here so transparent-only sims pull in nothing extra. */
struct incremental_merkle_tree;

struct simnet {
    struct coins_view_cache view;       /* the live in-RAM UTXO set    */
    struct coins_view       null_view;  /* zeroed backing (no disk)    */
    struct chain_params     params;     /* value copy + high checkpoint */
    struct checkpoint_entry cpentry;    /* params.checkpointData -> here */
    struct block_index      tip;        /* current tip; tip.hashBlock = stable tip hash */
    struct transaction     *mempool_txs; /* FIFO simulator mempool, owned */
    size_t mempool_count;
    size_t mempool_cap;
    uint32_t next_block_time;           /* deterministic virtual nTime for next mint */
    uint32_t last_block_time;           /* nTime of the current tip, 0 before first mint */
    seed_tape_t *clock_tape;            /* optional deterministic clock owner */
    int mempool_last_reject;            /* enum simnet_mempool_reject, kept int to avoid a header cycle */
    char mempool_last_detail[128];
    int  tip_height;
    bool initialized;

    /* ── Sapling Lane C (all default-off; NULL/false = today's behavior) ── */
    struct incremental_merkle_tree *sapling_tree; /* optional, owned; the live
                                                   * note-commitment tree. When
                                                   * set, every mint appends this
                                                   * block's shielded-output note
                                                   * commitments and stamps the
                                                   * header root from the REAL
                                                   * current tree root. NULL =
                                                   * Lane A empty-root stamp. */
    bool run_contextual_check;          /* when true, each mint also drives the
                                         * REAL contextual_check_block(is_ibd=
                                         * false) so Sapling Groth16 spend/output
                                         * proofs + binding sig are verified
                                         * through the production consensus path. */

    /* A minimal in-memory registry of every Sapling tree root this sim has
     * committed via a successful mint (simnet.c:sim_mint_block). Wired as
     * null_view's get_anchor vtable hook so connect_block's cross-block
     * "JoinSplit anchor requirements" check
     * (coins_view_cache_have_joinsplit_requirements) can resolve a LATER
     * block's spend anchor to an EARLIER block's committed root — a RAM-only,
     * this-sim-only analog of the real node's durable anchor_kv
     * (engine/jobs/utxo_apply_anchors.c). Grows by doubling; freed in
     * simnet_free. NULL/0 until the first Sapling-tree mint commits a root. */
    struct uint256 *sapling_anchor_history;
    size_t sapling_anchor_count;
    size_t sapling_anchor_cap;
};

/* Initialize a fresh, empty single-node harness. Places the synthetic base
 * tip just below the first mintable height (Sapling inactive there), wires
 * the coins view's best block to it, and installs the covering checkpoint.
 * Returns false (and logs) on OOM; on false the struct must not be used. */
bool simnet_init(struct simnet *s);

/* Release the harness's in-memory state (coins view). Idempotent. */
void simnet_free(struct simnet *s);

/* Bind an installed seed tape as the simulator clock owner. Successful mints
 * advance the tape by the target spacing so block nTime, GetAdjustedTime(),
 * and CLTV finality share one deterministic virtual clock. */
void simnet_use_seed_tape(struct simnet *s, seed_tape_t *tape);

/* Lower the Overwinter+Sapling activation heights to `height` on the sim's
 * LOCAL params value-copy ONLY (never chain_params_get() / the mainnet
 * definition in core/modules/chain/src/chainparams.c). After this call, blocks minted
 * at nHeight >= `height` are validated by the REAL connect_block with Sapling
 * active — the mint helpers set the header's hashFinalSaplingRoot to the empty
 * Sapling note-commitment tree root (the sim mints only transparent txs, so
 * the tree stays empty) so the post-activation root check passes unchanged.
 * Sim-local by construction: it does not touch any global consensus state, so
 * mainnet parity is preserved. No-op (logs) on an uninitialized sim or a
 * negative height. */
void simnet_activate_sapling_at(struct simnet *s, int height);

/* Mint a new block whose only transaction is a coinbase, driving it through
 * connect_block(). On success the tip advances by one and the coinbase's
 * single output is a spendable (maturing) coin in `view`. `out_cb_txid`, if
 * non-NULL, receives the coinbase txid. Returns false (and logs the reject
 * reason) if the real validator rejects the block. */
bool simnet_mint_coinbase(struct simnet *s, struct uint256 *out_cb_txid);

/* Mint a coinbase-only block whose single output pays `script` and `value`.
 * This is the funding primitive used by the simulator wallet toolkit. */
bool simnet_mint_coinbase_to(struct simnet *s, const struct script *script,
                             int64_t value, struct uint256 *out_cb_txid);

/* Mint a new block containing the harness coinbase followed by caller-built
 * transparent transactions. `txs[0..ntx)` may include OP_RETURN outputs and
 * spends against the live in-RAM coins view. On a valid request ownership of
 * each tx's allocated vin/vout arrays transfers to simnet; the caller must
 * keep any needed txids before calling. Returns false (and logs) if the real
 * validator rejects the block. */
bool simnet_mint_txs(struct simnet *s, struct transaction *txs, size_t ntx);

/* Mint empty coinbase blocks until the tip is at least `target_height`.
 * Heights are contiguous; asking for the current/past height is a no-op. */
bool simnet_mint_to_height(struct simnet *s, int target_height);

/* Mint a block that spends `in_txid`:`in_n` to one new output of
 * `out_value`, plus the block's own coinbase (vtx[0]). The block is minted
 * at a height that satisfies coinbase maturity for the spent coin, so a
 * freshly-minted coinbase can be spent through the REAL maturity predicate
 * without minting 100 filler blocks. On success the input coin is consumed
 * and the new output is present in `view`. `out_txid`, if non-NULL, receives
 * the spend tx's txid. Returns false (and logs) on rejection or if the input
 * coin is absent. `out_value` must be <= the spent output's value (the
 * difference is the fee). */
bool simnet_spend(struct simnet *s, const struct uint256 *in_txid,
                  uint32_t in_n, int64_t out_value, struct uint256 *out_txid);

/* Height of the current tip. */
int simnet_tip_height(const struct simnet *s);

/* Deterministic virtual block clock. `tip_time` is 0 before the first mint;
 * `next_block_time` advances by ZClassic's 150-second target spacing after
 * every minted block. */
uint32_t simnet_next_block_time(const struct simnet *s);

/* Copy the current tip hash into `out`. */
bool simnet_tip_hash(const struct simnet *s, struct uint256 *out);

/* True iff `txid` has at least one unspent output in the live UTXO set. */
bool simnet_coin_exists(struct simnet *s, const struct uint256 *txid);

/* Fetch the value of `txid`:`n` from the live UTXO set. Returns false (and
 * leaves *out_value untouched) if the coin or output index is absent/spent. */
bool simnet_coin_value(struct simnet *s, const struct uint256 *txid,
                       uint32_t n, int64_t *out_value);

#ifdef __cplusplus
}
#endif

#endif /* ZCL_SIM_SIMNET_H */
