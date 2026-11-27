<!-- Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 -->

# Proposed 200,000-byte block limit

An opt-in network deployment may select this rule independently of proof of work, shielded pool rules and wallet migration. Its only consensus effect is an upper bound on the canonical serialized size of one complete block. The proposed limit is 200,000 bytes inclusive. The validation constants document a historical ceiling of 2,000,000 bytes. The block shape check bounds transaction count. Establish historical serialized-byte enforcement separately by auditing the reference node and every admission path before implementation. The default mining policy already targets 200,000 bytes.

<!-- claim: symbol-present domain_consensus_check_block_size_and_coinbase core/consensus/src/check_block.c # block shape entry point -->
<!-- claim: symbol-present MAX_BLOCK_SIZE core/modules/validation/include/validation/main_constants.h # historical ceiling -->
<!-- claim: symbol-present DEFAULT_BLOCK_MAX_SIZE core/modules/validation/include/validation/main_constants.h # default production policy -->

The [miner signaling guide](MINER_SIGNALING.md) describes the testnet ballot format and how to check lock-in.

## Rule

A deployment must publish its network identity, exact rule revision and activation trigger. For a fixed-height deployment it must specify H. For a signalled deployment it must bind the agreed signal resolver and its parameters. Resolve activation for the candidate block from its parent on the selected network. Starting with the first active block, count the canonical serialized header (including CompactSize solution length and solution), followed by the CompactSize transaction count and all canonical transaction bytes including shielded data. Accept equality. Exclude P2P framing and storage envelopes. Apply the existing historical rules at all earlier heights and on profiles that omit the proposal. Enforcing this restriction alone tightens the set of valid blocks and is a soft fork. A distinct fork network can adopt it as one of its rules.

Use one size predicate for received blocks, submitted blocks, local production and replay. A trusted cached length must refer to the exact validated serialization. Locally assembled blocks require canonical accounting, including CompactSize width changes. Abort locally on inability to compute a length. Keep that error distinct from a deterministically oversized block. Initial sync must enforce the active cap. Reorganizations must select the rules for each candidate parent and refresh next-block templates. Keep historical readers able to decode the original range.

## Observable behavior

For a deployment active from H, the following expectations refer only to the size rule. Each complete acceptance fixture also needs valid transactions, commitments and proof of work.

| Serialized bytes | H−1 | H | H+1 |
| ---: | --- | --- | --- |
| 199,999 | Pass | Pass | Pass |
| 200,000 | Pass | Pass | Pass |
| 200,001 | Pass | Reject | Reject |

Qualify the rule on two isolated peers. Compare canonical serialization with the length used by validation for all three boundaries. Check a block crossing a CompactSize threshold, a block with shielded data, and a block whose transaction bytes alone fit while the full header pushes it over. Run every boundary through peer acceptance and block submission. Compare initial sync, restart and reorg outcomes with full replay. Immediately before activation, the template RPC must report 200,000 for the next block and the miner must fit its generated coinbase and proof in that total. Verify the legacy profile still accepts an otherwise valid 200,001-byte block at the same height.

The cap bounds future block bytes. Estimate actual storage impact using historical block sizes and measure validation cost with identical blocks on the same host. Qualify ordinary Sprout and Sapling withdrawals under the selected cap when composing a migration that preserves shielded exits.
