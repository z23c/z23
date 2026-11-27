<!-- Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 -->

# Miner signaling on testnet and regtest

A pool can signal readiness for any subset of proposals in one voting round. Each proposal has its own rule revision, bit position and activation height. The status RPC counts accepted blocks on the branch selected by the node at its durable provable tip. Block share estimates hashpower over the voting window. The threshold is 95% of **all** blocks in that window, including silent blocks, rounded up to a whole block.

For example, a 20-block window requires 19 signals. With heights 1 through 20 reserved for voting and height 23 selected for activation, the tally becomes final for that branch after block 20. Blocks 21 and 22 provide lead time. A qualifying proposal first reports active **for block 23**, when its parent is block 22. A proposal with 18 signals expires independently. To compare competing branches, query nodes that have selected different tips.

<!-- claim: symbol-present miner_signal_phase_at engine/services/src/miner_signal_round.c # candidate height and tally -->
<!-- claim: symbol-present miner_signal_schedule_valid engine/services/src/miner_signal_round.c # minimum old-rule interval -->

## Reproduce the catalog

Pass the following JSON array as the positional parameters to the registered RPC method `getballotcatalog` on regtest. The fork identifier and two rule revisions below are disposable example values. For a deployment, operators must agree on the fork identity and what each revision implements before the window opens.

```json
[
  "1111111111111111111111111111111111111111111111111111111111111111",
  1,
  20,
  [
    ["0000000000000000000000000000000000000000000000000000000000000001", 23],
    ["0000000000000000000000000000000000000000000000000000000000000002", 24]
  ],
  0
]
```

The inputs are the fork identifier, start height, voting window, ordered list of rule revisions and activation heights, and selected slot. Sort revisions by their 32 raw bytes in ascending order. On regtest the example produces catalog digest `0daa0498aef76847abdfd5771aed663a241a0853aec641845f588325f5168100`. Selecting slot 1 gives the same digest. Changing any rule or height, the fork identity, or the network genesis changes the commitment for the whole ballot. The v1 encoding and SHA3-256 inputs are specified in the catalog service header.

<!-- claim: symbol-present rpc_getballotcatalog engine/controllers/src/blockchain_controller_ballot.c # catalog RPC -->
<!-- claim: symbol-present miner_signal_catalog_select engine/services/include/services/miner_signal_catalog.h # canonical byte encoding -->

## Signal and inspect the result

Call `createballotoutput` with the catalog digest and a 32-byte bitmap, both in hex. To signal readiness for both example proposals, use `03` followed by 31 zero bytes. To signal only for slot 0, use `01` followed by 31 zero bytes. Append the returned zero-value output as the last coinbase output before computing the transaction ID, Merkle root and proof of work. Keep unused bits zero.

Call `getballotstatus` with the same five parameters used for `getballotcatalog`. Read `parent_hash`, `parent_height`, `next_height`, `votes` and `phase_of_next_block` together. A bound query returns `schedule_source` equal to `supplied_catalog`. The six-argument diagnostic accepts a digest and schedule separately and labels that result `raw_parameters`. The RPC checks hash-bound validation evidence and block bodies at the durable provable tip. A missing body or changing chain can make the query fail. This version bounds RPC voting windows to 256 blocks.

<!-- claim: symbol-present rpc_createballotoutput engine/controllers/src/mining_controller.c # pool ballot construction -->
<!-- claim: symbol-present rpc_getballotstatus engine/controllers/src/blockchain_controller_ballot.c # next-block status -->

These RPCs report readiness for a supplied schedule. Enforcing a migration at its activation height requires a network profile with an agreed catalog and a reviewed consensus implementation for that rule. A block-size limit, a Sapling deposit restriction and a proof-of-work change can each use a separate proposal.

## Pin a catalog at startup

<!-- claim: symbol-present boot_ballot_catalog_load engine/composition/src/boot_ballot_catalog.c # selected-network catalog pin -->

To reuse the same catalog across restarts, store its four manifest fields as a JSON array in a file. Use the first four parameters from the regtest example above, omitting the final slot selector. Under the selected node datadir, put the file in the `ballots` directory and name it with the lowercase catalog digest followed by `.json`.

Set `testballotcatalog=0daa0498aef76847abdfd5771aed663a241a0853aec641845f588325f5168100` in that datadir's node configuration or pass `-testballotcatalog=0daa0498aef76847abdfd5771aed663a241a0853aec641845f588325f5168100` on the command line. The node derives the digest from the manifest and selected network genesis at startup. A mismatch fails startup. Once running, the node holds the verified catalog in memory.

Call `getballotstatus` with a single slot number, for example the JSON parameters `[0]`. A successful query reports `schedule_source` equal to `pinned_catalog`. The pin selects the local catalog used by this status query. It grants no authority to install a consensus rule.

## Request a voting block template

On a node with the catalog pinned, pass `[{"ballotslots":[0,1]}]` as the JSON parameters to `getblocktemplate` to signal for slots 0 and 1. The returned `coinbasetxn.data` already contains the final ballot output. Omitting the field preserves ordinary template behavior. Each requested slot must be distinct and the template height must fall inside the voting window.

The node checks that the complete template fits mining policy with the height-selected Equihash solution and a 100-byte coinbase scriptSig. A pool that makes further edits must preserve the intended vote, recompute the Merkle root, and check the final serialized size before solving the block.

<!-- claim: symbol-present miner_ballot_template_apply engine/services/src/miner_ballot_template.c # coinbase mutation and serialized size check -->
