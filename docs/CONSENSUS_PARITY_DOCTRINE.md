# Consensus-Parity Doctrine — z23 ⇔ zclassicd

**Status: inviolable. This is a safety boundary, not a preference.**

z23 is an independent C23 reimplementation of a ZClassic full node. It
shares one live chain with the canonical C++ daemon **zclassicd** (reference
source: a local `zclassic-cpp` checkout; live oracle node: `~/.zclassic`, RPC 8232).
For that to be safe, the two implementations must agree, **bit for bit**, on
which blocks and transactions are valid.

## The rule

> **z23 MUST accept exactly the blocks and transactions zclassicd
> accepts, and reject exactly those it rejects — at every height, forever.**

A change making z23 accept a block zclassicd rejects (or vice versa)
**forks the chain**: our nodes split from the network, exchanges and explorers
diverge, the "one chain" guarantee breaks. There is no opt-in, miner-signaled,
or "51%-gated" version of this that is acceptable — a fork is a fork regardless
of how its activation is dressed up.

## What IS consensus (must match zclassicd)

Changing **any** of these requires zclassicd to ship the identical rule
**first**, network-wide, before z23 may adopt it:

- **Equihash PoW** — (N,K) params and the per-epoch table. Resolved **only**
  from the static, height-keyed `EquihashUpgradeInfo[epoch]` (200,9 before the
  Bubbles fork at h=585,318; 192,7 at and after). Never from miner signaling or
  a dynamic per-height override.
- **Network-upgrade activation heights** — Overwinter/Sapling 476,969; Bubbles
  585,318; Bubbly/DiffAdj 585,322; Buttercup 707,000. Activation is
  `nHeight >= nActivationHeight`. No versionbits, BIP9/BIP8, or signaling.
- **Difficulty** — `powLimit`, averaging window (17), max adjust up/down
  (16/32), target spacing (150 pre-Buttercup, 75 post).
- **Block validity** — structure, size/weight, merkle/commitment roots, branch
  ids, sighash, sigops.
- **Transaction validity** — structural and contextual checks, script
  verification, value/fee rules, and all shielded-proof verification
  (Sprout/Sapling Groth16/PHGR13, JoinSplit Ed25519).
- **Subsidy / founders' reward** — halving schedule and amounts.
- **Genesis** — hash and branch-id constants.

## What is NOT consensus (we may differ freely)

Relay/mempool/propagation **policy** does not change which blocks are valid and
is *not* covered by this doctrine: mempool acceptance policy, fee estimation,
transaction-relay strategy (e.g. Dandelion BIP156 — relay-only privacy), P2P
service bits and inv types (unknown ones ignored by both sides), peer scoring,
RPC/native command surface, the explorer, wallet UX, sync strategy, storage layout, and
observability. Here z23 is free to be better than zclassicd.

## The enforced guards

| Layer | What | Where |
|---|---|---|
| **1. `check-consensus-parity` (lint gate E13)** | Forbids the *shape* of a divergence: forbidden mechanism tokens, plus registry-checked future-height literals and wall-clock reads | `./build/bin/z23-lint check-consensus-parity`; run by `make lint` / `make ci` / `make deploy` |
| **2. `test_consensus_parity` (test group)** | Pins the consensus *values* | `tests/harness/src/test_consensus_parity.c`; run by `make test_parallel` / `make ci` |
| **3. Runtime cross-check** | Compares live block hashes against zclassicd | `legacy_mirror` / `z23 ops mirror` / `z23 core consensus report` |

**Lint gate E13** fails if a **non-zclassicd consensus mechanism** appears in
the consensus source path — the `PATHS` array in
`./build/bin/z23-lint check-consensus-parity`: `core/params`, `core/chainparams`,
`core/consensus`, `core/modules/validation`, `core/modules/chain`, `core/modules/mining`, `engine/jobs`.
Every entry must exist on disk or the gate hard-fails rather than scanning
nothing. Banned token classes:
`versionbits`, `VersionBitsState`, `ComputeBlockVersion`, `ehUpgrade` /
`eh_upgrade`, `nSignalBit`, `vbits_`, `equihash_n_at` / `equihash_k_at`
(dynamic override getters), `BIP9`, `BIP8`. These guard the *mechanism* —
zclassicd has none of them; introducing one means activation or PoW params
would depend on something other than the fixed height schedule. False positive?
Mark the line `// consensus-parity-ok:<reason>`.

### Scan classes `HEIGHT` / `CLOCK` (E13 extension) — future-height literals and wall-clock reads

The forbidden-token scan above catches the *versionbits/BIP9* family by
name. It is blind to a bomb that never names any of those tokens: an
adversarial review once planted

```
if (n_height >= 3400000) halvings--;
```

two lines below a legitimate height gate in `core/consensus/src/subsidy.c` —
a bare integer comparison. Deterministic rebuild, full-chain replay, and
historical UTXO-root agreement all pass clean against it, because the
divergence only fires once the chain actually reaches the planted height.

E13 also scans the same `PATHS` for two more shapes:

- **`HEIGHT`** — an integer literal at or above the last baked mainnet
  checkpoint (3,100,000 — i.e. strictly in this codebase's future) sitting
  next to a relational operator (`>=`, `<=`, `==`, `<`, `>`) on a line that
  also mentions "height". This is the exact shape of the bomb above.
- **`CLOCK`** — a read of `time(NULL)`, `GetTime()`, `GetAdjustedTime()`,
  `gettimeofday()`, or `clock_gettime()` in the consensus surface: a
  non-deterministic, non-height-keyed input with no business deciding a
  consensus outcome on its own.

A hit in either class fails the gate unless it is registered in
**`tools/lint/FLAG_DAYS.txt`** — a machine-checked ledger, not the
`consensus-parity-ok:` comment. That comment is unchanged and still means
exactly what it meant before, for the forbidden-token class only; it is not
reused as a second escape for `HEIGHT`/`CLOCK`, on purpose — the registry
exists specifically so a hit can be cleared without editing (or even owning)
the flagged file. The registry keys on the exact
`(path:line, class, sha256-of-the-line)` triple, so ANY edit to a registered
line — the literal, the operator, unrelated whitespace, anything — turns
that row **stale** and fails the gate exactly like an unregistered site.
That is deliberate: a line-number drift from an unrelated refactor is a new
site needing a fresh, reviewed row, not a false alarm to silence.

`tools/lint/FLAG_DAYS.txt`'s own header documents the field format in
full. Its current entries are the authoritative, current list — this
document does not mirror a count that would just go stale; read the
registry itself. Every wall-clock site the scan finds in the tree today was
reviewed and is a known, non-divergent use: a progress-log speed metric, the
initial-block-download recency heuristic, the standard "block timestamp too
far in the future" check zclassicd also runs, and a miner's own candidate
block's timestamp — none of them decide whether a *received* block is valid
based on the local clock in a way zclassicd doesn't also do.

The gate also prints `FLAG_DAYS_REGISTRY_DIGEST: sha256:<hex>` on every run
— a whole-file digest of the registry, meant to be carried in a release
record so a weak node (or a human comparing two releases) can tell **that**
the registry moved between releases without diffing the file itself.

**What this does NOT do.** This is a visibility mechanism, not a lock. It
does not stop a hostile publisher who edits `FLAG_DAYS.txt` in the same
commit as a new bomb and writes a plausible-sounding rationale — nothing
textual can verify that a rationale is honest. What it buys is that the
edit is forced to be small, textual, and diffable, instead of invisible
inside six directories of C. It also does not catch:

- a future-height literal hidden behind a named constant
  (`#define FUTURE_HEIGHT 3400000; if (n_height >= FUTURE_HEIGHT)`);
- a C23 digit-separated literal (`3'400'000`) or a hex-encoded height
  (`0x33E140`);
- a height comparison whose variable isn't spelled with "height" anywhere on
  the same physical line — the co-occurrence check is same-line-only, chosen
  so the scanner doesn't also flag unrelated large-integer comparisons
  (byte-size ceilings, nanosecond timeouts) that happen to share a
  relational operator with a big number;
- a literal written across a `<<`/`>>` shift or a `->` member-access token
  touching it (the operator-adjacency check doesn't special-case those, on
  the theory that a false positive there costs one registry row, while a
  false negative costs the point of the gate);
- anything hidden behind indirection a textual scanner can't see through —
  a value computed at runtime and compared later, a function pointer, a
  macro expansion whose body lives on a different line.

It is a lint gate: cheap, mechanical, and blind to anything that isn't
matching text in the files it reads. Treat a clean run as "no *textually
obvious* new future-height or wall-clock dependency," never as a proof of
absence — the runtime cross-check (row 3 of the table above) and a human
reviewing every `FLAG_DAYS.txt` diff are still load-bearing.

**Test group** pins the consensus values (Equihash table, all activation
heights, protocol versions, pow constants, `powLimit`, genesis hash) to the
golden zclassicd numbers. To change a value you must change zclassicd first and
update this test in the same breath, deliberately.

## What the `core/` seal does not cover

`core/MANIFEST.sha3` (Gate #47, `check-core-seal`) freezes the *text* of the
consensus predicates. It does not freeze the arithmetic those predicates call.
Sealed code calls unsealed code on every block:

| Sealed caller | Unsealed callee | What it decides |
|---|---|---|
| `core/math/src/hash.c` | `core/modules/crypto/src/sha256.c` | block hash, txid, merkle root |
| `core/consensus/src/script_interp.c` | `core/modules/crypto/src/sha256.c` | `OP_SHA256` / `OP_HASH256` |
| `core/consensus/src/equihash.c` | `core/modules/crypto/src/blake2b_avx2.c` | Equihash PoW (height-selected N,K) |
| `core/` → `coins/coins.h` → `sapling/incremental_merkle_tree.h` | `core/modules/sapling/src/fr_avx512.c` | Sapling commitment-tree anchor, Groth16 verdicts |
| same closure, via `sapling/bn254.h` | `core/modules/sapling/src/bn254_accel.c` | Sprout Groth16 JoinSplit verdicts |

Editing any of those changes which blocks the node accepts without moving a
byte inside `core/`, so `check-core-seal` stays green. That is by design and
must stay that way: those files exist to get faster, and freezing them would
put the owner unseal ritual in front of every optimisation.

What covers them is **Gate #51 `check-accel-oracle-pinned`**. It recomputes,
from source, the include-closure of `core/` over `lib/*/src`, keeps the members
carrying a runtime ISA dispatch, and requires each one to be listed in
`tools/lint/accel_oracle_registry.txt` against a differential oracle that runs
in the test suite and proves it byte-identical to a portable reference. A new
accelerator, a new `#include` edge from `core/` that reaches one, a deleted
oracle, or an oracle that is compiled but not dispatched all fail the gate.

Practical rule: **an accelerated primitive under `core/` is a parity change
until an oracle says otherwise.** Write the oracle in the same commit as the
accelerator, drive the same inputs through every tier, and compare bytes — not
verdicts, not timings.

## Empirical oversize grandfather (live-behavior parity over text parity)

The doctrine target is **the behavior of the running network**, not the
reference TEXT — and there is one proven place where they diverge.

zclassicd's text enforces `serialized size > MAX_TX_SIZE_AFTER_SAPLING (102000)`
unconditionally in `CheckTransaction` (`src/consensus/consensus.h:27`, <!-- doc-path-ok: zclassicd (upstream C++) path -->
`src/main.cpp:1196-1200`). But the canonical chain contains **413 post-Sapling
txs above 102000** (heights 478,544..1,968,856; max 1,922,197 bytes). They were
legal when mined (the original Zcash-Sapling rule capped a tx at `MAX_BLOCK_SIZE`
= 2 MB); zclassicd later tightened the constant **without grandfathering**, so
running nodes accept that history only because validated blocks are never
re-checked — a from-genesis replay of zclassicd's own text false-rejects its own
chain: it FATALs at block 478,544 on tx `e3eeb123…` (125,811 bytes,
`bad-txns-oversize`), breaking every full-validation path (reindex, background
validation, verifying genesis sync). The 413-tx list is derived from a
complete frame-walk + per-height hash scan of the canonical chain (heights
0..3,143,532), `getblockhash`-compared and per-tx-drilled against live
zclassicd; H_LAST = 1,968,856.

The rule that is bit-for-bit equal to running-zclassicd behavior on every block
either node will ever **newly** validate:

- **In a block**: excuse exactly those 413 canonical txs, via a static
  `{txid, size}` allowlist (exact-match, txid recomputed from serialized bytes,
  hard `MAX_BLOCK_SIZE` structural ceiling). Everything else — including a fresh
  oversize tx in a fork block at an old height, which running zclassicd's
  `CheckTransaction` rejects — gets the strict 102000. A height window was
  rejected for exactly that reason: it would over-accept deep-reorg fork blocks.
- **Standalone (mempool/relay)**: strict 102000 always, matching
  `AcceptToMemoryPool → CheckTransaction`.
- The pre-Sapling contextual 100000 rule is untouched: the scan proved zero
  pre-Sapling txs exceed it (verified, not assumed).

Mechanics:

- `tools/data/oversize_grandfather_txids.txt` — committed provenance list
  (`height txid size`, 413 lines).
- `tools/scripts/gen_oversize_grandfather_table.sh` — regenerates the table,
  re-verifying EVERY entry against a live zclassicd (canonical-at-height +
  byte-exact size); `--fixture` emits the 478,544 KAT input.
- `core/consensus/src/oversize_grandfather_table.inc` — the generated static
  table (sorted, bsearch-able).
- `domain_consensus_tx_oversize_grandfathered()` + `enum domain_tx_check_context`
  in `core/consensus/src/tx_structural.c` +
  `core/consensus/include/domain/consensus/tx_structural.h` (the `domain/`
  include token is preserved by `-Icore/consensus/include`); consumed via
  `check_transaction_in_block()` (block paths) vs `check_transaction()`
  (mempool, strict).
- Golden pins: `test_consensus_parity` (count 413, max 1,922,197, first/last
  violations, size-exact semantics) + the 478,544 KATs in
  `test_domain_consensus_tx_structural` (real canonical tx accepted in-block,
  rejected as new, tamper-rejected).
- Fast lane: `make immutable-history-canaries` runs those real-history pins
  without a chain download. Treat it as the first check for any bounded
  consensus predicate change; the full real-history gates are still
  `make replay-canary-anchor` and `make replay-canary-genesis`.

This is **not** a consensus change ahead of zclassicd — it *restores* parity
with what every running zclassicd node actually does, and is exactly the static,
non-signaled, non-dynamic mechanism class gate E13 permits.

## Groth16 proof decode tightening (history evidence)

`core/modules/sapling/src/bls12_381.c` decodes Groth16 proof points as
zclassicd's librustzcash 06da3b9 does: a compressed infinity with any stray bit
is refused, an Fq coordinate equal to or above q is refused, and a proof point
A, B or C at infinity is refused (bellman `Proof::read`). This refuses
encodings Z23 used to accept, so it needed proof that no proof on the real
chain is now refused.

Method (2026-11-16, host z23-r1, read-only): the append-only zclassicd
`blk*.dat` block files (52 files) were copied to a private directory and every
block was parsed with Z23's own `block_deserialize`. Every Sapling spend proof,
Sapling output proof and Groth16 JoinSplit proof went through the fixed
`groth16_proof_read`. No datadir, node or service was touched.

| Item | Value |
|---|---|
| Blocks parsed (incl. forks) | 3,343,579, 0 parse failures |
| Canonical chain covered | heights 0..3,321,763, tip `00000e7a9106652d0f0d0e7e5844a8302591d113325e02f9ea1f9c852feb88df`, 3,321,764 blocks, 0 gaps, 5,328,626 txs |
| Coverage check | prev-hash chain walked from the tip to genesis with every ancestor present; that tip hash equals the zclassicd oracle's `getblockhash 3321763` |
| Sapling spend proofs decoded | 454,954, refused 0 |
| Sapling output proofs decoded | 1,066,109, refused 0 |
| Groth16 JoinSplit proofs decoded | 95,592, refused 0 |
| First / last height with a Groth16 proof | 476,970 / 3,321,753 (none below Sapling activation 476,969) |
| Fork blocks also scanned | 456,101 / 1,073,157 / 95,613 proofs, refused 0 |

The scan ran twice with identical results. Blocks above height 3,321,763 were
not in the copy (the oracle was 13 blocks ahead). This is a decoder-level scan
of every real proof, not a full-history node replay
(`make replay-canary-genesis`).

## PHGR13 proof decode tightening (history evidence)

`core/modules/sapling/src/bn254.c` decodes the eight points of a Sprout PHGR13
(BCTV14) JoinSplit proof as the Proof.hpp and Proof.cpp of zclassicd (src/zcash)
do on top of libsnark. It refuses encodings Z23 used to accept: a G1 or G2
lead byte other than `0x02`/`0x03` and `0x0a`/`0x0b` (including the lead bit
`0x04` with x = 0 that Z23 read as the point at infinity; zclassicd has no such
encoding), a coordinate equal to q, a G2 FE2IP integer at or above q^2 (the
quotient was truncated to 256 bits, so X + 2^256*q decoded like X: a second
byte string for the same valid proof), and a G2 point outside the order-r
subgroup. In the other direction, the Fq2 square root now returns the root
`t*u` when x^3 + b' is a non-residue of Fq. Reaching that case through the
verifier needs a subgroup point of that shape; none is known and finding one
is a search of about 2^254, so it is pinned at the field level only.

Method (2026-11-17, read-only): a differential harness linked
the Proof.cpp of zclassicd and libsnark (portable build, no `-DUSE_ASM` in the
verifier translation units) beside this file's `sprout_verify_phgr13`,
`bn_g1_decompress` and `bn_g2_decompress`, and compared verdicts case by case
over the append-only zclassicd `blk*.dat` copy (52 files). No datadir, node or
service was touched.

| Item | Value |
|---|---|
| Blocks parsed (incl. forks) | 3,343,579, 0 parse failures |
| PHGR13 JoinSplits found / distinct | 433,209 / 432,407 |
| Distinct mainnet proofs accepted by zclassicd | 432,407 |
| Of those refused by the fixed Z23 | 0 |
| Mutation and point-level cases (125 classes) | 51,390 |
| Total cases / Z23 verdicts differing from zclassicd | 483,797 / 0 |
| Same harness on the code before the fix | 9,849 differing, all Z23 accepting what zclassicd rejects |

`tests/harness/src/test_bn254_phgr13_parity.c` pins each rule at the point
level and `tests/harness/src/test_sprout_phgr13_kat.c` on the real height-241 proof. This is a
verifier-level comparison of every real proof, not a full-history node replay
(`make replay-canary-genesis`).

## PHGR13 verifier speed: the pairing engine

`core/modules/sapling/src/bn254.c` verifies Sprout PHGR13 JoinSplit proofs with its own BN254
pairing. The Miller loop, final exponentiation, G1/G2 decoders, the verifier's multi-scalar
multiplication and its G2 subgroup test now run on an *engine*
(`core/modules/sapling/src/bn254_engine.inc`, included twice: once over the portable
multiply and once over the inlined BMI2+ADX multiply of `mont_adx.h`, selected at run time
by `bn254_accel_cpu_has_adx()`). A mainnet proof verifies in about 2.7-3.0 ms on a desktop Skylake
core (i9-9900K) instead of 18-20 ms; on the 7950X3D server libsnark with its assembly field
multiply takes 14.0 ms and the previous C23 verifier took 18.1 ms (`docs/CRYPTO_PERF.md`).

**Contract: the same function, not a similar one.** The engine changes how values are computed, not
which values. Every Fq, Fq2, Fq6 and Fq12 element is canonical (fully reduced) after every
operation, as before. So for every input, including inputs no honest proof contains:

| Quantity | Relation to the previous implementation |
|---|---|
| Miller-loop value before the final exponentiation | the same Fq12 element: the same line formulas (`doubling_step`, `mixed_addition_step`), evaluated once per G2 point instead of once per pairing, and applied by a sparse multiply that equals the dense one |
| final exponentiation | the same Fq12 element: same exponent, same addition chain; Granger-Scott squarings equal the generic ones on the cyclotomic subgroup, which is where the easy part always lands |
| G1 / G2 decompression, Fq2 square root | the same accept set and the same points |
| IC multi-scalar multiplication | the same group element (Straus windows over per-key tables instead of 9 double-and-add loops) |
| five pairing checks | still five separate products, each `== 1` after its own final exponentiation; no random combination, no merged equations |
| G2 subgroup test | the same predicate `r*P == O`, decided by `psi(P) == [6u^2]P` (below) |

The verdict is a function of those values, so the accept and reject sets are identical to the
previous implementation's and therefore to zclassicd's. The one place the *method* differs from
what a reader would expect is the subgroup test, so its argument is written out:

*Claim.* For a point P of the twist E'(Fq2): `r*P = O` iff `psi(P) = [6u^2]P`, where `psi` is the
untwist-Frobenius-twist endomorphism (the same constants as the Miller loop's Frobenius step) and
`u = 4965661367192848881`.
*Proof.* The BN family has `q = 36u^4+36u^3+24u^2+6u+1`, `r = 36u^4+36u^3+18u^2+6u+1`, trace
`t = 6u^2+1 = q+1-r` (the test pins all three identities numerically). `psi` has degree `q` and
satisfies `psi^2 - t*psi + q = 0` (it is conjugate to Frobenius by the twist isomorphism), so for an
integer `m` the endomorphism `psi - [m]` has degree `m^2 - t*m + q`; at `m = 6u^2` that is
`q - 6u^2 = r`. An isogeny of degree `r` has at most `r` kernel points, so
`K = {P : psi(P) = [6u^2]P}` has `|K| <= r`. `G2 = E'(Fq2)[r]` is cyclic of order `r` (`r^2` does not
divide `#E'(Fq2) = r(2q-r)`) and `psi` acts on it as multiplication by `q mod r = q - r = 6u^2`, so
`G2` is inside `K`; hence `K = G2`. A point passes iff it lies in `G2`. QED. The test also checks
this on 100+ twist points per instance against the original `r*P` loop, including `[r]t`
(pure cofactor torsion), `[2q-r]t` (in G2) and `[r]t + g` (mixed), and every decoded proof of the
history gate below goes through it.

The line tables and Straus tables depend only on the verifying key. They are built once from the
first key a verification sees, in static storage, and published with a release store; every
verification compares the key it is handed with the snapshot, so a key edited in place (as
`test_bg_validation_reverify` does) or a second key is verified against private tables built from
that key, never stale ones.

**Evidence.**

| Check | Result |
|---|---|
| `test_bn254_engine_parity` (frozen pre-engine copy `bn254_legacy_reference.c` in the test tree) | tower, Miller loop, final exponentiation, pairing, decoders, subgroup test, MSM and verdicts equal on both engine instances; 16 threads verifying through one key |
| History gate (`phgr13_diff`: zclassicd's Proof.cpp over libsnark beside this verifier) | 483,797 cases (all 432,407 distinct mainnet PHGR13 proofs and 51,390 mutation and point-level cases): 0 verdicts differing from zclassicd for the candidate wrapper and 0 for the raw verifier, on the files of this change (3,343,579 blocks, 20 shards) |

Do not "simplify" the engine into a second, separately maintained pairing, and do not merge
the five checks into one random-coefficient product: the former forks the consensus function, the
latter changes it (a probabilistic acceptance rule instead of five exact ones).

## Parity guards on the connect path

`contextual_check_block()` must stay wired into the connect path: context-free
structural checks plus the staged proof gate alone miss the per-tx contextual
rules, which is the root cause behind 4 of the 5 divergences below. All 5 are
closed:

| # | Divergence | Landed at |
|---|---|---|
| 1 | CHECKDATASIG/CHECKDATASIGVERIFY undercounted as 0 sigops in the context-free structural count | `core/consensus/src/check_block.c:57` `DOMAIN_CONSENSUS_SIGOP_COUNT_FLAGS = SCRIPT_VERIFY_CHECKDATASIG_SIGOPS`, unconditional |
| 2 | Per-tx contextual rules (Overwinter expiry, NU version gating, per-tx finality, BIP34 `bad-cb-height`) unwired on connect | `contextual_check_block()` (`core/modules/validation/src/check_block.c:436`) called from `engine/jobs/src/script_validate_contextual.c:107`, IBD- and tip-window-gated (see `docs/agent/AGENT_TRAPS.md` for the gating rationale) |
| 3 | JoinSplit Ed25519 signature not verified on the block-connect path | `engine/jobs/src/proof_validate_stage.c` verifies it before the per-joinsplit zk-SNARK loop; failure tags `first_failure_proof_type="joinsplit_sig"` |
| 4 | Height-gated Sapling/Overwinter structural tx rules (version-group-id, version floors) unwired on connect | same wiring as #2 |
| 5 | Missing `bad-txns-coinbase-spend-has-transparent-outputs` rule | `engine/jobs/src/utxo_apply_delta.c:536` and `engine/jobs/src/utxo_apply_stage.c:498` |

**Nuance on #1 — two separate sites, two separate postures.** zclassicd sets
`SCRIPT_VERIFY_CHECKDATASIG_SIGOPS` in *both* `CheckBlock`
(`STANDARD_SCRIPT_VERIFY_FLAGS`) and `ConnectBlock`. c23's context-free
structural count (#1 above) matches unconditionally. The **`ConnectBlock`-analogue
reindex path** (`core/modules/validation/src/connect_block.c`) is a *separate*,
**DEFAULT-OFF** parity flag (`g_enforce_checkdatasig_sigops`,
`-enforce-checkdatasig-sigops`) — a tightening (reject) predicate gated on a
full-history replay confirming zero false-rejects first, per the
h=478544 doctrine above. **Do not flip its default without that replay.** (The
live reducer fold does its own sigop accounting and is unaffected by this
flag; only the boot-reindex path reads it.)

**Refuted candidates (do not re-investigate):** pow-diffadj operator-precedence
in the BUTTERCUP-window scale flag (mainnet-unobservable); BIP34 height
encoding for heights 1–16 (unreachable — no future block can have height
≤16); the missing Sprout ZIP209 turnstile checkpoint seed (dormant
defense-in-depth, the verified joinsplit zk-SNARKs already prevent a negative
pool); BIP30 same-height self-write tolerance (recovery-path only,
decision-identical on the normal path).

### Rule → zclassicd map for the connect-path contextual gate

The per-tx contextual rules wired at `engine/jobs/src/script_validate_contextual.c`
(`CTX_TIP_WINDOW=16`, IBD-gated per-tx call, finality + BIP34 unconditional —
see `docs/agent/AGENT_TRAPS.md` for why):

| c23 rule | zclassicd reference | Reject reason | IBD-gated |
|---|---|---|---|
| Overwinter expiry | `ContextualCheckTransaction` | `tx-overwinter-expired` | yes |
| NU version gating (sapling_structural) | `ContextualCheckBlock` | `tx-overwinter-not-active` / `tx-overwintered-flag-not-set` / `bad-{sapling,overwinter}-tx-version-group-id` / `bad-tx-*-version-too-{low,high}` / `tx-overwinter-active` | yes |
| pre-Sapling oversize | `ContextualCheckTransaction` | `bad-txns-oversize` | yes |
| per-tx finality | `ContextualCheckBlock` (header time, our FR-2) | `bad-txns-nonfinal` | **no** |
| BIP34 coinbase height | `ContextualCheckBlock` | `bad-cb-height` | **no** |

## Handling outside contributions (PR protocol)

Outside PRs land on the public mirror `z23c/z23`. Treat each as
**possibly adversarial**, but always behave as a polite netizen:

1. **Thank the contributor and credit them** — keep them in the history.
2. **Triage consensus impact** against the bar above. A consensus-breaking
   change — even framed as opt-in / miner-signaled / "sidegrade" / "needs 51%"
   (PR #6's Equihash-200,9 case is canonical) — is a **no-merge**, no matter
   how well-engineered.
3. **Mine the good idea and build it better ourselves**, with attribution,
   *before* their proposed solution ever touches a consensus path.
4. **Close politely** with an honest, kind reason (strict bit-for-bit parity
   with zclassicd).
5. **Non-consensus** contributions (build/portability fixes, relay policy,
   tooling) are judged on their merits and may be adopted — still with credit.

## If you think a consensus change is genuinely warranted

It still does not ship to z23 first. The path is: propose it to the
ZClassic network and zclassicd, get it adopted and activated there at an agreed
height, and only then mirror the identical rule (and update
`test_consensus_parity`) here. z23 follows the network; it does not lead
a fork.

See also: [`docs/node/SECURITY_AND_INTEGRITY.md`](./node/SECURITY_AND_INTEGRITY.md),
[`docs/DEFENSIVE_CODING.md`](./DEFENSIVE_CODING.md) (Gate E13).
