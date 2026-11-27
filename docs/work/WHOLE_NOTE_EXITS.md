<!-- Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 -->

# Proposed whole-note legacy exits

This testnet design is separate from the [net Sapling deposit freeze](SAPLING_DEPOSIT_UPGRADE.md). Once activated, transactions using Sprout or Sapling may consume whole notes but cannot create funded notes in either legacy pool. Ordinary transparent and Ironwood-only transactions remain available. This design is not implemented or qualified for activation; mainnet activation is outside its scope.

## Consensus rules

Apply the following to every transaction with a Sapling spend or output or a Sprout JoinSplit, including attempts to deposit into either pool. Preserve existing structural, amount, proof, signature, anchor, nullifier and fee checks. Multiple notes from either or both legacy pools and ordinary transparent fee inputs are allowed. Ordinary conservation applies to the sum of all inputs and outputs; fees must be nonnegative and satisfy existing bounds. The transaction format must classify every pool it carries and reject unrecognized components.

* Require zero Sapling output descriptions, even purported zero outputs; this conservative rule does not assert that every output carries value. Sapling spend proofs and the binding signature establish the value released by all Sapling spends.
* For every Sprout JoinSplit require `vpub_old = 0` and openings proving both mandatory output commitments are zero-valued. Existing JoinSplit proofs and signatures remain mandatory. Per-JoinSplit enforcement excludes hidden intermediate change.
* Allow released value to fund transparent outputs, a net Ironwood deposit, and the fee. Disallow deposits into other shielded pools. For Ironwood, the verified signed `valueBalanceIronwood < 0` establishes a net deposit; retain its proof and binding-signature checks. Do not infer a positive individual output or receiver from an encrypted action. The wallet must construct the intended recipient and verify its readable received value separately. Normal transparent inputs or Ironwood spends may also fund the transaction, so consensus does not attribute particular units to a particular destination.

[ZIP 229](https://zips.z.cash/zip-0229) specifies Ironwood flags and its signed balance as spends minus outputs. Its action proofs enforce the enabled spend/output semantics; a transaction builder must set and validate the flags consistently with its construction. An Ironwood component with net outflow is not a permitted destination for legacy exits under this proposal. Unmodified version 6 has no JoinSplit fields: Sprout-to-Ironwood therefore needs a separately specified compatible transaction format or a two-step transparent exit and deposit. No format or proof compatibility is assumed.

<!-- claim: symbol-present tx_structural_check_value_balance core/consensus/src/tx_structural.c # Sapling balance checking -->

## Sprout zero-output witness

The current Sprout note commitment is SHA-256 of `b0 || a_pk || value_LE64 || rho || r`. The transaction exposes commitments but not their openings. A testnet-only versioned extension must authenticate exactly two canonical `(a_pk, rho, r)` openings per JoinSplit, with value fixed at zero, against the corresponding serialized commitments. Reject missing, malformed, swapped, mismatched openings and trailing data. Specify byte encoding, size limits, transaction ID, signature-hash domain and network separation before implementation; a sidecar or mempool-only rule cannot enforce this. Check that the existing prover produces compatible openings: output rho is derived by the JoinSplit construction, not independently sampled. Generate fresh randomness as required by the prover, never publish input openings or reuse input-note material.

The openings reveal dummy-note data and can increase transaction linkability. Public balances may also reveal a single spent note’s value when other flows are known. Commitment binding and existing proof soundness are both necessary; revealing openings does not replace proof verification. Independently review the construction and demonstrate a complete valid JoinSplit before activation.

<!-- claim: symbol-present sprout_note_cm core/modules/sapling/include/sapling/note.h # Sprout note commitment primitive -->

## Activation and evidence

Assign a separate testnet signaling identity and activation height. Derive activation from each candidate's parent branch; preserve pre-activation validation. Enforce the same next-block rule in mempool and mining, and revalidate or evict transactions when the tip changes. Replay and reorganization must recheck proofs, witnesses, signatures, nullifiers and balances. Specify network-specific transaction and signature domains to prevent cross-network replay.

Use two isolated testnet peers and independently replay the source history. At H−1, H and H+1, verify whole-note exits from each pool, mixed-pool and transparent-input transactions, fees, recipient balances, wallet restart and rescan. Include the mature-coinbase path under actual coinbase protection, complete block size, signaling-window and activation reorganizations, mempool reconsideration and double-spend rejection. Record source blocks, transaction bytes and IDs, fees and recipient readback; keep private note data private. Demonstrate construction and redemption, not only archived proof verification.

Reject Sapling outputs including zero outputs, partial exits with legacy change, internal legacy sends, deposits, positive `vpub_old`, either nonzero dummy, malformed or altered openings, invalid proofs or signatures, duplicate nullifiers, invalid fees, unsupported formats and forbidden shielded deposits. Check block validation and mempool behavior. Test both distinct Sprout commitments in one valid JoinSplit, including swapped openings and a hidden intermediate output.

## Commitment component vectors

A C23 driver compiled with Clang 20 called `sprout_note_cm` at source revision `0acb1facc`; its four results matched independently hashed preimages. Each field is 32 repetitions of the indicated byte. These fixed bytes are test vectors, not production randomness; this test does not establish a valid JoinSplit.

| `a_pk` | `rho` | `r` | Value | Commitment |
| --- | --- | --- | --- | --- |
| 11 | 22 | 33 | 0 | `9460dccaf2f2292fdaa24d67576d7b3cbd2efbfc2f658dbfa89f0877d590fac9` |
| 11 | 22 | 33 | 1 | `210bc07845a0f18d5e7fe0b688a5c5ad12d2b56f4cde85e684e071066cb18b59` |
| 44 | 55 | 66 | 0 | `d9f4ec0f762ecb4e042a93853f2c1da7f019536343759e3048cc664927642a9d` |
| 44 | 55 | 66 | 1 | `dccb57b84880d221e9f362d8f76a387b867a81881f323469fbbbfee6aef45ce9` |
