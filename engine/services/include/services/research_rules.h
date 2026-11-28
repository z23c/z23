/* purpose: Resolve ballot-activated research rules on a candidate block's parent branch. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZCL_SERVICES_RESEARCH_RULES_H
#define ZCL_SERVICES_RESEARCH_RULES_H

#include "base/result.h"
#include "chain/chain.h"
#include "chain/chainparams.h"
#include "services/miner_signal_catalog_pin.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct block;

/* Rules this build can enforce. A pinned catalog entry activates a rule only
 * when its revision bytes equal the rule's published revision, byte for byte.
 * Unknown entries are tallied but enforce nothing. A locked-in or active
 * unknown entry makes resolution unavailable, naming its catalog slot. */
#define RESEARCH_RULE_BLOCK_CAP 0u
#define RESEARCH_RULE_DEPOSIT_FREEZE 1u
#define RESEARCH_RULE_COUNT 2u

/* Published rule revisions; see docs/work/BLOCK_SIZE_UPGRADE.md and
 * docs/work/SAPLING_DEPOSIT_UPGRADE.md. */
extern const uint8_t research_rule_revision[RESEARCH_RULE_COUNT][32];

/* Rules that govern the candidate block whose parent was resolved. */
struct research_rules_state {
    bool active[RESEARCH_RULE_COUNT];
};

/* The deployment one node enforces: its selected chain and the operator's
 * verified catalog pin. Composition boot installs it once, before any
 * consumer reads it, and it is immutable afterwards. Without a binding (every
 * ordinary network, and a research node started without a catalog) no rule
 * is ever active. */
struct research_rules_binding {
    const struct chain_params *params;
    const struct miner_signal_catalog_pin *pin;
};
/* Bind the Ironwood descriptor to a pin carrying the same genesis. Returns
 * false, and binds nothing, for any other chain, a pin bound to another
 * genesis, or a second call. The caller keeps both objects alive. */
bool research_rules_install(const struct chain_params *params,
                            const struct miner_signal_catalog_pin *pin);
const struct research_rules_binding *research_rules_binding(void);

/* The frozen deposit rule: every non-coinbase transaction keeps
 * value_balance >= 0. Withdrawals, migrations and miner rewards stay allowed.
 * Returns 0 when `block` obeys it, otherwise the 1-based position of its
 * first offending transaction. A NULL block, an empty one, or one without
 * a transaction array reports SIZE_MAX: fail closed. */
size_t research_rules_deposit_violation(const struct block *block);

/* Result codes of the resolvers below. The message explains the cause. */
enum research_rules_code {
    /* Null arguments, a binding that is not the Ironwood chain, or an index
     * ancestry that does not form one height per block. Nothing was decided. */
    RESEARCH_RULES_INVALID = -1,
    /* A window block body could not be read or authenticated, or an unknown
     * catalog rule is locked in or active. The caller
     * must hold the candidate and retry; it must neither reject the block as
     * invalid nor validate it under the inactive rules. */
    RESEARCH_RULES_UNAVAILABLE = -2
};

/* A block body is authenticated only when both hold: `block_get_hash(blk)`
 * equals `*bi->phashBlock`, and `domain_consensus_check_block_merkle_root`
 * accepts `blk`, which binds its transactions to the hashed header. A header
 * alone authenticates nothing: the ballots are in the coinbase.
 *
 * Ancestors between the window and the parent are not read: they are linked
 * by the index (`pprev`, one height per block), which this node sets only
 * from an authenticated header's hashPrevBlock. A caller that links index
 * entries by hand keeps that invariant itself.
 *
 * Supply the complete block for one ancestor. `out` is initialized by the
 * caller with block_init and owned by the caller. Return false when the body
 * is unavailable. */
typedef bool (*research_rules_read_fn)(void *ctx, const struct block_index *bi,
                                       struct block *out);

/* Decide which rules govern the candidate that extends `parent`.
 *
 * A NULL binding, or a NULL parent (the genesis block), leaves every rule
 * inactive and succeeds, so ordinary networks are unchanged. Each pin entry
 * whose revision is a known rule is scheduled independently: its votes are
 * the coinbase ballots of the authenticated blocks in the complete window on
 * the parent's own ancestry, its threshold is the catalog's, and it is active
 * exactly when the candidate height reaches the entry's activation height on
 * a branch that qualified. The decision is a pure function of the parent
 * ancestry, so replay, reorganization and restart agree.
 *
 * Unknown entries are tallied but enforce nothing; locked-in or active unknown
 * entries return RESEARCH_RULES_UNAVAILABLE naming the slot. Voting or expired
 * unknown entries change nothing. Window bodies are read only when a known
 * entry reaches activation or an unknown entry can first lock in, and the
 * ancestry is walked only then. On success
 * `*out` is written; on failure it is untouched. */
struct zcl_result research_rules_for_parent(const struct research_rules_binding *binding,
    const struct block_index *parent, research_rules_read_fn read, void *read_ctx,
    struct research_rules_state *out);

/* Forward-only twin for sweeps that already hold each block in order. It
 * reads nothing: the sweep supplies every block it connects. */
struct research_rules_tracker;
struct research_rules_tracker *research_rules_tracker_create(
    const struct research_rules_binding *binding);
void research_rules_tracker_destroy(struct research_rules_tracker *tracker);
/* Connect one block extending the block connected before it. A bound tracker
 * authenticates bodies only at heights [start - 1, start + window); outside
 * that range, or with no binding, it hashes nothing and checks ordering only.
 * A failed required authentication is `RESEARCH_RULES_UNAVAILABLE`.
 * The first connected block must lie at
 * or below the window parent; a sweep that starts higher cannot use the
 * tracker and resolves through research_rules_for_parent instead. A failure
 * leaves the tracker unchanged. */
struct zcl_result research_rules_tracker_connect(struct research_rules_tracker *tracker,
    const struct block_index *bi, const struct block *blk);
/* Rules for the candidate that extends the block connected last. Fails with
 * RESEARCH_RULES_INVALID before the first connection. */
struct zcl_result research_rules_tracker_state(const struct research_rules_tracker *tracker,
    struct research_rules_state *out);

#endif
