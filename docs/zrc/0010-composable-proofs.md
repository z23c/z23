<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# 0010: Composable proofs

| Field | Value |
|---|---|
| ZRC | 0010 |
| Title | Composable proofs |
| Status | draft |
| Owner | orchestrator |
| Created | 2026-09-05 |
| Supersedes | none |

## Problem

A push is admitted only when this box holds one whole-tree receipt for the
exact `(tip, base)` pair. The pre-push hook loads
`.cache/zcl-dev-proof/receipts/<tip>-<base>.receipt`
(`tools/dev/z23_git_hook.c:541-543`) and refuses any remote ref other than
`refs/heads/main` as `remote-ref-not-main`
(`tools/dev/z23_git_hook.c:606-609`). The receipt is one SHA3-256 seal over
ten content roots (`tools/dev/dev_proof_receipt.h:62-71`,
`tools/dev/dev_proof_receipt.c:249-266`). A Mac box and a Linux box that
each proved a disjoint subset cannot combine those proofs. A rebase that
does not change a group's inputs still misses the pair-keyed file.

The owner's directive, 2026-09-05, verbatim: proofs must be composable, we
must always use intelligent crypto, we must use caching and all the best
algorithms p2p.

ZRC 0007 gossipes CANDIDATE, PROOF_SET, and PUBLICATION and leaves open who
proves which group, how two hosts' rows union, and how the rows move on a
private plane. This ZRC answers those three.

## Design

### 1. Composable

A receipt becomes a signed Merkle root over **verdict leaves**. It is no
longer one opaque seal that a second box must re-create in full.

**Leaf key.** `(input-closure digest, toolchain class, group id)`.

**Leaf value.** `verdict` (`pass` or `fail`) + producer Ed25519 public key +
signature + `observed_unix` + `elapsed_ms` + the producer's log sequence and
previous log head (see §2).

**Input-closure digest.** SHA3-256 under domain `zcl.verdict.closure.v1`
over the host-neutral receipt roots that name *what was proved*, not *which
compiler proved it*:

- `source_root`, `source_cas_root`, `mutation_root`
- `changed_set_root`, `impact_policy_root`, `build_graph_root`
- `group id` (test catalog name, lint gate name, or TU path)
- the group's own input bytes: for a test group, the forward-closure file
  hashes already folded by `trc_compute_key`
  (`tests/harness/src/testcache.c:512-555`); for a TU, the source sha plus
  the include-set digest already used by `tu_result_cache.sh`

`compiler_root`, `flags_root`, and `environment_root` stay out of this
digest. They classify the producer, they do not identify the change.

The ten roots on the v1 body, in wire order
(`tools/dev/dev_proof_receipt.h:62-71` and the serialize list at
`tools/dev/dev_proof_receipt.c:154-160`), remain:

`source_root`, `source_cas_root`, `mutation_root`, `changed_set_root`,
`impact_policy_root`, `compiler_root`, `flags_root`, `environment_root`,
`build_graph_root`, `child_set_root`.

The Merkle tree is keyed by leaf key. The receipt seal stays SHA3-256 under
`zcl.dev_acceptance_receipt.v1` over the unsigned body
(`tools/dev/dev_proof_receipt.c:249-266`), then Ed25519 over domain
`zcl.dev_proof_receipt.v2` plus that whole sealed body
(`tools/dev/dev_proof_receipt.c:31-36`, `:270-278`), now covering the Merkle
root of the leaves this producer minted. A partial receipt is that root plus
inclusion proofs for the served leaves.

**Required closure for `(tip, base)`.** The leaf keys the impact plan
selects. `build_test_selector` (`tools/dev/dev_proof.c:3351-3407`) emits
every catalog group when `plan->closure_universal`, else the union of
`path_groups` and `closure_groups`. Lint gates and compile TUs join as
named groups. `test_log_account` requires
`groups_total == groups_ran + groups_cached + groups_gated` and zero
failed, skipped, and unobserved (`tools/dev/dev_proof.c:3432-3467`).
`groups_gated` is declined work; it does not cover a leaf.

**Admission by union.** A receiver admits `tip` against `base` when the
union of leaves from trusted producers covers every required leaf key.
Covered subtrees are never re-proven; uncovered keys are the only work.
The pair-keyed receipt file becomes a cache of that union, not the
authority.

**Toolchain class.** An equivalence class of the three toolchain roots
(`compiler_root`, `flags_root`, `environment_root`) after the policy-2
capsule capture (`tools/dev/dev_proof_receipt.h:33-38`,
`zcl_dev_proof_build_identity_v1_capture` at
`tools/dev/dev_proof.c:2180-2189`). Two classes are named at least:
`linux-gnu-c23` and `darwin-arm64-c23`. A Mac leaf and a Linux leaf
**compose** for a host-neutral group: either class's trusted `pass` covers
that group id. They do not compose for a host-specific group (Landlock /
seccomp, Darwin CodeDirectory, kqueue versus inotify). No host-predicate
table file exists under tools/dev/; the mechanism is the catalog's
per-group skip and fail-closed host branches. A leaf under the wrong class
is `receipt_toolchain_class_mismatch`.

**What still does not port, and the repair.** Policy 1 hashed the checkout
path into compiler/flags/build_graph and hashed literal `PATH` into the
environment root. Policy 2 already dropped `PATH` and rewrites the checkout
root to a virtual token before hashing the plan
(`tools/dev/dev_proof.c:2024-2039`, `:2082-2087`, `:2135-2143`). What still
disagrees across boxes is `proof_environment_root`
(`tools/dev/dev_proof.c:2144-2166`): it hashes the literal values of `CC`,
`CXX`, `CFLAGS`, `CPATH`, `SDKROOT`, and the other named variables, so two
boxes with one compiler at two absolute driver paths mint two environment
roots. The repair is a ticket that keys those three roots per **toolchain
class** (capsule content only), never per path.

The hook does not re-derive local roots fieldwise. It validates the stored
record: nonzero roots, matching seal, matching child receipts
(`tools/dev/z23_git_hook.c:561-580`). Hollow `compiler_root` is
`receipt_required_root_missing`; a flipped seal is `receipt_seal_mismatch`;
a different pair is `receipt_commit_or_base_mismatch`
(`tools/dev/dev_proof_receipt.c:346-398`).

### 2. Intelligent crypto

- **Content addressing.** Every closure digest and Merkle node is SHA3-256.
  Hits are exact. A different toolchain class is a different key.
- **Ed25519 per leaf or per batch.** Default: one signature per leaf, same
  as `zcl_dev_proof_signer_sign` (`tools/dev/dev_proof_signer.c:215-242`).
  Batch rule: one producer may sign the Merkle root of its own leaves; a
  leaf is covered only with an inclusion proof to that root. Distinct
  producers never share a batch. Batch verification is a speed-up, not a
  second trust rule, and does not change `signers.allow`.
- **Allowlist.** A leaf counts only when `zcl_dev_proof_signer_verify`
  accepts the key: this box, or a 64-hex line in `signers.allow`
  (`tools/dev/dev_proof_signer.c:26-27`, `:368-406`). Existing refusals:
  `receipt_unsigned`, `signature_invalid`, `signer_unknown`,
  `signer_key_unreadable` (`tools/dev/dev_proof_signer.h:39-42`).
- **Hash-chained per-producer logs.** Each producer appends
  `(seq, leaf_hash, prev_head)`. A second record with the same `seq` and a
  different hash, or two heads with the same `prev_head`, is
  `receipt_log_fork_detected`. A later `fail` is a new seq, not an edit.
- **Merkle inclusion proofs.** A peer may serve a subset of leaves plus
  sibling hashes. The receiver checks inclusion, then the union cover. It
  never infers a missing leaf is a pass.

New refusals, named, never a boolean:

- `receipt_leaf_unsigned` — a leaf has no signature.
- `receipt_leaf_signer_unknown` — the leaf key is not this box and is not
  in `signers.allow`.
- `receipt_closure_uncovered` — the union misses one or more required
  groups; the token is followed by the uncovered group ids.
- `receipt_toolchain_class_mismatch` — a leaf's class cannot cover that
  group id.
- `receipt_log_fork_detected` — the producer's log is not a single chain.

Absence is never a pass. A missing leaf is uncovered work or a named
refusal, never a cached skip.

### 3. Caching

The **verdict store** is the first-class object. The pair-keyed receipt
file is a projection of it. Record key = leaf key; value = leaf value from
§1 plus served-log bytes. Cached test verdicts are keyed by
`trc_compute_key` (`tests/harness/src/testcache.c:512-555`) from
`testcache_probe_group` (`tests/harness/src/testcache.c:710-712`). The
runner's `ZCL_TESTCACHE_STORE_ROOT` pin (`tools/dev/dev_proof.c:4342-4344`)
is lifted to the node's replicated table, still keyed by digest.

**Hits are exact.** A stale closure is a miss. `tu_result_cache.sh` keys a
TU on compiler identity, flags, and TU bytes plus an include-set digest
(`tools/lint/tu_result_cache.sh:53-74`, `:297-310`);
`tools/lint/check_windows_cross_syntax.sh:41-49` replays that cache into
the same log and rc paths. The warm generation
(`proof_build_identity_equal` at `tools/dev/dev_proof.c:2192-2198`,
`warm_donor_scan` at `:2607-2637`) is the same idea at generation grain.

**Eviction.** Drop by age (operator TTL) and when the closure is
superseded: a new `source_root` / `changed_set_root` / `impact_policy_root`
mints a new key. The TU cache already prunes old salt generations
(`tools/lint/tu_result_cache.sh:247-260`); the verdict store prunes by
superseded digest.

**Fleet facts.** Each box emits three signed rows on the private plane:
`proof_cache_hit_rate`, `proof_cache_bytes_served`,
`proof_cache_seconds_saved`. They are measurements, not admission. A zero
hit rate is a fact, not a proof of freshness.

### 4. Best algorithms p2p

Private verdict replication rides the **private plane** of ZRC 0009: paired
Noise mesh streams, refused as `stream_peer_unpaired` or
`stream_link_not_noise` (`engine/composition/src/mesh_stream.c:92-93`).
Public INV/GET/POST on the fleet board never carries a private leaf id.

Discovery reuses the board's INV/GET gossip
(`engine/composition/src/boot_fleet_board.c:322-388`): INV announces leaf
or batch ids this node holds; GET asks for ids it lacks; the answer is one
signed leaf or a Merkle-partial receipt per frame, on the stream, not on
the public board.

Store sync uses set reconciliation. Each side holds a compact sketch of its
leaf-id set (minisketch / IBLT-style): a small linear sketch of the xor of
ids, from which the symmetric difference is decoded when it is smaller than
the sketch capacity. At fleet scale that difference is the new leaves since
the last sync, so peers exchange those ids and then GET only the missing
bodies, instead of transferring the whole store.

Public verdicts for public repositories may ride the public board with the
same signatures. There is no central registry. ZRC 0007's three objects
stay the landing vocabulary; this ZRC only shapes, caches, and copies
PROOF_SET rows.

## Acceptance

1. A Mac leaf set and a Linux leaf set that together cover every required
   host-neutral group, plus each host-specific group in its own class, admit
   the `(tip, base)` pair. Neither set alone admits it if the other still
   holds an uncovered host-specific group.
2. One required group missing is refused as `receipt_closure_uncovered`
   followed by that group id. The other leaves are not re-run.
3. A leaf with a forged signature is refused as `signature_invalid` or
   `receipt_leaf_unsigned`. A leaf from a key not in `signers.allow` is
   `receipt_leaf_signer_unknown` (or `signer_unknown` at the receipt
   trailer).
4. A stored record whose closure digest does not equal the current
   host-neutral roots is a miss. It is never a hit.
5. A leaf under `darwin-arm64-c23` offered to cover a Linux-only group is
   `receipt_toolchain_class_mismatch`.
6. Two signed heads for one producer seq are `receipt_log_fork_detected`.
7. The three cache facts (hit rate, bytes served, seconds saved) are
   present as signed private-plane rows after a union admission.

## Out of scope

Consensus, the sealed core, on-chain anchoring, and paying for proofs.
Need, job, claim, and remote-receipt stay with ZRC 0007. This ZRC does not
pick a prover market or change what a gate checks.

## Landing

1. Leaf format + signer (reuse `signers.allow`, add the five new refusal
   tokens, Merkle inclusion). One lane.
2. Receiver union (cover check, `receipt_closure_uncovered`, toolchain
   class). One lane.
3. Replication on paired Noise streams with INV/GET of leaf ids. One lane.
4. Set reconciliation of the leaf-id set. One lane.

Each unit is at most one lane. The pair-keyed hook is fallback until stage
2; a missing store admits nothing.

## Discussion

Board rows carrying `zrc-0010`. The first experiment is the
receiver-admission probe proposed by the Mac worker on 2026-09-05: offer a
Linux-produced leaf set to a Mac receiver for a host-neutral tip, without
listing the Linux key in `signers.allow`. Predicted refusal order:
`signer_unknown` (or `receipt_leaf_signer_unknown`) first, because signer
identity is decided before structural claims
(`tools/dev/dev_proof_receipt.c:351-367`); then the toolchain roots, as
`receipt_toolchain_class_mismatch` or a cover miss, once the key is listed.
