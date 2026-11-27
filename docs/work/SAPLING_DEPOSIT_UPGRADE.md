<!-- Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 -->

# Proposed Sapling deposit freeze

A migration may adopt this proposal independently of the block-size limit, Ironwood support or a proof-of-work change. Its purpose is to stop new net deposits into Sapling while allowing holders of existing Sprout and Sapling notes to withdraw. Here a deposit means a **net inflow per transaction**. A holder can still pay another Sapling address from existing shielded funds.

## Activation and value flow

Give this rule revision its own slot and activation height H in the [miner signaling catalog](MINER_SIGNALING.md). Once the rule qualifies on the candidate's parent branch, enforce it starting with block H. Preserve historical validation before H and on a deployment that omits the rule. On replay and branch changes, derive the decision from the candidate parent.

For each transaction, use the signed Sapling value balance. A negative balance moves value into Sapling, and a positive balance releases value from it. The proposed additional predicate is a comparison against zero after ordinary structural decoding and amount checks. It requires no extra proof verification, allocation or database lookup. For any newly supported transaction version, explicitly identify its Sapling balance when qualifying this proposal.

<!-- claim: symbol-present tx_structural_check_value_balance core/consensus/src/tx_structural.c # signed Sapling balance bounds and accounting -->

| Otherwise valid transaction | Result under this rule |
| --- | --- |
| Transparent or Sprout funds produce net Sapling inflow | Reject |
| Net Sapling inflow and a larger withdrawal in a separate transaction in the same block | Reject the block |
| Zero Sapling balance, including an internal transfer | Allow |
| Positive Sapling balance, including a partial withdrawal with Sapling change | Allow |
| Sprout exit to a transparent recipient, with no Sapling bundle | Allow |

Apply the predicate independently to every transaction, including coinbase when its version permits a Sapling bundle. If a network requires a coinbase deposit under another active rule, resolve that conflict in the deployment before scheduling the migration. Preserve all existing proof, anchor, nullifier, amount, fee and binding-signature checks. Mining and mempool admission should use the same next-block rule as block validation.

## Exit qualification

Start two isolated peers with spendable pre-activation notes in each pool. Pin the source block hash and independently replay its history. At H−1, H and H+1, exercise full withdrawals less fees, partial withdrawals with change, and one-zatoshi net deposits. For a Sprout-to-Sapling transaction that the new rule rejects, also demonstrate the holder's Sprout-to-transparent path. Check that wallet restart, rescan and restored spending keys can locate and spend each eligible note. Record recipient balances, fees, inclusion and double-spend rejection. Repeat across a reorganization that crosses the voting window and H.

When composing this rule with the [200,000-byte block limit](BLOCK_SIZE_UPGRADE.md), demonstrate spendable exit transactions under the cap on both peers. Include the coinbase, complete header and transaction count when checking block size. Keep the archived verification of an old spend and the construction of a new wallet withdrawal as separate pieces of evidence. A migration is ready for users only after both pools have a working withdrawal path.
