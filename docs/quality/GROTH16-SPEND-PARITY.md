# Groth16 SPEND-circuit differential parity — scoreboard (present tense)

The native pure-C23 Sapling **spend** circuit is being ported gadget-by-gadget
to match bellman's `Spend::synthesize` (pinned librustzcash commit
`06da3b9ac8f278e5d4ae13088cf0a4c03d2c13f5`). Pairing is all-or-nothing, so a
partial port yields **no** green Groth16 spend round-trip yet — the value landed
so far is a *proven-at-parity prefix*, guarded by a standing differential oracle.

This doc is the honest scoreboard: what is proven at parity vs the reference,
and what is pending.

## The gates (all under the `groth16_selfverify` test group)

| Lane | File | What it proves |
|------|------|----------------|
| H2 | `tests/harness/src/groth16_spend_oracle.c` | Native `nsk_to_nk` / `crh_ivk` / `ivk_to_pkd` / `compute_cm` / `compute_nf` == librustzcash, byte-for-byte, for one pinned KAT witness. |
| H3 | `core/modules/sapling/src/sapling_circuit.c` + `circuit_bits.c` + shape gate in `test_groth16_selfverify.c` | Ported spend sections **1..10** synthesize with per-section cumulative constraint counts equal to the reference trace; in-circuit `nk`/`rk` wires carry reference-correct points; §10's blake2s digest bits equal `CRH^ivk`; every §10 wire is bound (single-bit witness flips break the R1CS); synthesis deterministic. Single witness. |
| H4 | `tests/harness/src/groth16_spend_parity.c` | **Standing** differential parity oracle over a **corpus** of witnesses — generalizes H2+H3 and auto-tightens as H3 ports more sections. |
| **H5** | `tests/harness/src/groth16_spend_adversarial.c` | Adversarial + negative-control gate over the **active production proving path** (reference-oracle prover -> native C23 verifier) — the only lane that runs a real prove/verify round-trip and tries to break it. Requires `~/.zcash-params` (SKIPs cleanly when absent, same convention as the rest of the self-test block). |

Run: `make t-fast ONLY=groth16_selfverify` (H2/H3/H4 are params-free; no
`~/.zcash-params`, no proving key required — H5 needs real params and SKIPs
without them). `make t-fast ONLY=snark_kat` is the sibling KAT gate.

## H5 — acceptance bar per check category

H5 (`tests/harness/src/groth16_spend_adversarial.c`) is the only lane that drives
the ACTIVE production proving path end to end: the reference-oracle prover
(librustzcash) generates a real spend proof, the independent native C23
verifier (`sapling_check_spend`) accepts or rejects it, using real
`~/.zcash-params` proving/verifying keys. Every check below states the
acceptance bar it enforces — a differential vector without a stated bar is
not a gate, so this table is authoritative, not decorative:

| # | Category | Vector | Acceptance bar |
|---|----------|--------|-----------------|
| 1 | Self-test end-to-end | prove(native C23) for a freshly-built note/Merkle-witness/nullifier/signature bundle | `sapling_check_spend` MUST **accept** |
| 2 | Differential | native `sapling_compute_rk(ak,ar)` vs the `rk` the reference-oracle prover returned for the identical `(ak,ar)` | MUST be **byte-identical** (no FFI export for `rk` exists, see H2's doc comment, so this is the closest available cross-check of a public-input wire against ground truth) |
| 3 | Corrupted proof bytes | single-bit flip at 3 offsets across the 192-byte proof (A's flag byte, C's tail byte, inside B) | MUST be **rejected** |
| 4 | Corrupted witness | a valid proof from a *different* witness, replayed against the original statement's public inputs | MUST be **rejected** — this is exactly the attack the Groth16 pairing check exists to stop |
| 5 | Wrong public inputs | single-bit flip in `cv` / `anchor` / `nullifier` / `rk`, real proof held fixed | MUST be **rejected** |
| 6 | Corrupted signature/sighash | single-bit flip in `spend_auth_sig` or `sighash` | MUST be **rejected** (the RedJubjub gate, independent of the Groth16 check) |
| 7 | Truncated/bit-flipped proving key | `groth16_pk_read` (native C23 parser) on truncated (5 cut points, 0%..90%) or bit-flipped real `sapling-output.params` bytes, plus 0-byte/1-byte buffers | MUST return **false** (typed refusal) and MUST NOT crash |
| 8 | Determinism | `rk` / nullifier across two independent re-provings of the byte-identical witness | MUST be **byte-identical** (double-spend protection depends on the nullifier being reproducible) |
| 8 | Documented non-determinism | `cv` / the 192-byte proof across the same two re-provings | MUST **differ** (Groth16 ZK blinding + value-commitment re-randomization are intentional, OsRng-backed on this path) — asserted explicitly so a silent change either direction is caught; both independently-blinded proofs must still independently verify |
| 8 | Determinism | `groth16_pk_read` parsed twice from identical bytes; `sapling_spend_prover_native_status()` called twice | MUST be **structurally/byte-identical** (pure functions, no hidden state) |
| 9 | Zeroization | `memory_cleanse(cs.witness, cap_vars*sizeof(fr))` — the exact call `sapling_create_spend_proof` makes before `cs_free` | MUST leave the buffer **all-zero** (this is where the secret `ar`/`nsk` bit-decomposition wires live until this line runs) |
| 9 | Zeroization | `memory_cleanse(&wit, sizeof(wit))` over a `struct sapling_spend_witness` populated by `sapling_spend_parse_witness` | MUST leave the struct **all-zero** |

## What the H4 parity oracle proves (per witness, whole corpus)

For every witness in a deterministic corpus (index 0 = the pinned H2 KAT
witness; 1..N distinct canonical scalars):

- **(A) Section-boundary parity, auto-tightening.** Each recorded section's
  cumulative constraint count equals the pinned 28-entry reference trace table
  (`REF_SECTIONS[]` in `groth16_spend_parity.c`). The oracle diffs only the
  sections the native circuit *actually records* (`n_sections` from the traced
  synthesis), so when the H3 port advances from 9 sections to 10, 11, … the new
  section's boundary is validated against `REF_SECTIONS[i]` **with no edit to
  the oracle** — it tightens itself off the reference boundaries.
- **(B) Structural invariance.** An R1CS circuit's shape must not depend on the
  witness. Every corpus witness must produce a byte-identical section shape
  (constraints/vars/inputs per section) to witness 0 — a class of unsoundness
  the single-witness H2/H3 gates cannot see.
- **(C) Per-wire value parity vs the reference archive.** The in-circuit `nk`
  wire (`[nsk] ProofGenerationKeyGenerator`, section 7) is compared
  byte-for-byte to `librustzcash_nsk_to_nk` **for every witness** — the
  differential against ground truth, not just the KAT. The `ak` (section 1) and
  `rk` (section 4) wires are cross-checked against the native scalar derivations
  (the reference archive exports no `ak`/`rk` FFI: `ak` is a private circuit
  input, `rk = ak + [ar]G` is internal). The **256 `repr` bits** produced by
  sections 8 and 9 are checked bit-for-bit against the points' compressed
  encodings; because Jubjub compression is `y` with `x`'s low bit in the top
  bit, `repr` *is* the compressed encoding, so `repr(nk)` is diffed directly
  against librustzcash's own `nsk_to_nk` output.
- **(D) Determinism.** Re-synthesizing an identical witness yields a
  byte-identical witness vector.
- **(E) R1CS satisfaction — the coefficient-level check.** Every emitted
  constraint is evaluated against the honest witness and must satisfy
  `A*B == C` (`cs_is_satisfied`, mirroring bellman's
  `TestConstraintSystem::which_is_unsatisfied`). This is the **only** check that
  reads constraint *coefficients*: (A) reads counts and (C) reads a handful of
  wire values, and neither can see a wrong coefficient inside an
  otherwise-correctly-shaped constraint. Without (E), "proven at parity" would
  mean only that the right *number* of constraints exist — and a circuit whose
  own witness does not satisfy it produces proofs the network rejects.

On the first divergence in any category the oracle prints the offending
`(witness index, section name, expected vs actual)` — it flags, never hides.
A negative-control (corrupting a reference boundary) turns the gate RED with a
`FIRST DIVERGENCE` line, so the gate is not hollow.

### Mutation-tested, not assumed

Each category above is confirmed to fire by planting a defect and running the
gate. The three classes are complementary — no single check subsumes another:

| Planted defect | Counts (A) | Values (C) | Satisfaction (E) |
|---|---|---|---|
| One extra satisfiable constraint | **RED** | ok | ok |
| One-bit flip in a witness value (`gadget_edwards_add`) | ok | **RED** | **RED** |
| One-bit flip in a constraint **coefficient** (on-curve `d`; unpacking `-1`) | ok | ok | **RED** |
| `x`/`y` swapped in `EdwardsPoint::repr` | ok | **RED** | ok |

The coefficient row is the reason (E) exists: before it was added, a one-bit
coefficient flip in section 1's on-curve check passed the entire gate green
while making that constraint unsatisfiable by the honest witness.

Section 10 added two more columns to the H3 gate, and its mutation table shows
why neither is redundant. **(V)** is the digest-value differential against
`CRH^ivk`; **(B)** is the wire-binding probe (flip one section-10 wire 0↔1 and
require the R1CS to become unsatisfiable):

| Planted defect in the blake2s gadget | Counts | (V) value | (E) satisfaction | (B) binding |
|---|---|---|---|---|
| `CBIT_FR_CAPACITY` 254 → 200 (MultiEq flush schedule) | **RED** (24608) | — | — | — |
| `Is ^ Not` result view allocated instead of negated | **RED** (24840) | — | — | — |
| BLAKE2s rotation `R1` 16 → 15 | ok | **RED** | ok | ok |
| XOR constraint replaced by a vacuous `0*0=0` | ok | ok | ok | **RED** (0/256 digest wires bound) |

The last two rows are the point. A wrong rotation constant is free in constraint
terms, so counts and satisfaction both stay green and only (V) sees it. A
vacuous constraint keeps the count, the digest value *and* satisfaction green —
because all three only ever read the honest witness — and only (B) sees that a
prover could then choose its own `ivk`. Under-constraint, not over-constraint,
is the soundness-relevant failure mode here.

## Coverage — PROVEN vs PENDING

- **PROVEN at parity:** reference sections **1..10** — cumulative
  **24590 / 98777** constraints (~24.9%). ak on-curve/not-small-order, ar/nsk bit
  decompositions, the two fixed-base multiplications (`[ar]SpendAuthGenerator`,
  `[nsk]ProofGenerationKeyGenerator`), `rk = ak + [ar]G`, rk inputize, the
  strict `EdwardsPoint::repr` of ak and nk (§8/§9, 388 constraints per field
  element), and the in-circuit **blake2s for `ivk`** (§10, 21006 constraints) —
  all byte-identical to the reference trace across the whole corpus, with the
  `nk` wire and `repr(nk)` bits pinned to librustzcash, §10's 256 digest bits
  pinned to `CRH^ivk` (and its 251 truncated bits to the librustzcash `ivk` KAT
  vector), and every constraint satisfied by the honest witness.
- **PENDING (H3 port):** sections **11..28** — variable-base `pk_d` (§13), value
  commitment (§14), note-commitment Pedersen hash (§17), the 32-level Merkle
  path (§21, 44224 constraints), the twin blake2s for `nf` (§27, the same 21006
  gadget over the 256-bit nf preimage), and nullifier packing (§28).
  Target: **98777** constraints, **98638** aux, **8** inputs (7 public + ONE).
  The `98638` aux figure is independently corroborated by the trusted-setup
  proving key itself: bellman's private-input query length `pk.l_len` for
  `sapling-spend.params` is exactly 98638 (see the H1 baseline line).

The oracle re-reports this scoreboard (`parity coverage: N/28 sections,
C/98777 constraints`) on every run, so the number moves the moment H3 lands the
next section — no edit to H4 required. It also prints the **named** next
unimplemented section as a typed blocker line (currently
`11:witness g_d`), so the seam is legible, never a silent gap.

### The architectural fork at section 10 — resolved, not worked around

Sections 1..9 needed only two kinds of circuit bit: an ordinary allocated
boolean and a conditionally-allocated one. Section 10 (blake2s for `ivk`, and
its twin §27 for `nf` — together **42012 constraints, 42.5% of the whole
circuit**) is built on bellman's `Boolean` / `UInt32` / `multieq` stack, where a
bit is `Constant(bool) | Is(AllocatedBit) | Not(AllocatedBit)` and both constant
folding and negation cost **zero** constraints. `circuit_gadgets.h` represents
every wire as a bare `size_t` variable index and can express neither, so a
blake2s written against it misses 21006 by thousands and no amount of tuning
closes the gap.

That stack is now ported as its own module —
**`core/modules/sapling/include/sapling/circuit_bits.h`**
+ `core/modules/sapling/src/circuit_bits.c`: `struct cbit` (Boolean),
`struct cu32` (UInt32), `struct multieq` (MultiEq), and `gadget_blake2s`. Every
function carries its exact reference constraint cost in its doc comment. Three
numbers are load-bearing and mutation-tested:

- **`CBIT_FR_CAPACITY` = 254** (`Fr::CAPACITY` = NUM_BITS − 1). MultiEq packs
  successive 33/34-bit equalities at disjoint bit offsets and flushes when the
  next one will not fit, so this constant sets the flush schedule. Setting it to
  200 yields 24608 instead of 24590. (Setting it to 253 changes nothing — the
  straddled sums 235 and 268 fall the same side of both — so it is the
  *schedule*, not the literal, that is pinned.)
- **Negation is free.** Emitting a real constraint for the `Is ^ Not` result view
  instead of taking `Not(c)` yields 24840.
- **Constant folding is free.** For a 512-bit all-*allocated* preimage, the
  `all_constants` short-circuit inside `addmany` is never reached (every sum has
  at least one allocated operand), so that branch is exercised by an
  all-constant input only — bellman's `test_blake2s_constant_constraints`
  shape. The folding that *is* load-bearing here is in `cbit_xor`, which keeps
  round 0 cheaper than rounds 1..9 and the final `h ^ v[i]` free.

Why 21006 is the right target: bellman's own `test_blake2s_constraints` asserts
**21518** constraints for a 512-bit input, of which **512** are the caller's
`AllocatedBit::alloc` booleanity constraints — leaving **21006** for the hash,
exactly the reference spend trace's §10 delta. §27 reuses the gadget unchanged.

### Output circuit and native prover close-out

The **output** circuit now matches the production key: 5 public inputs, 7821
auxiliary variables, and 7827 constraints. Its gate derives cv/epk/cm from the
witness, checks every constraint, and pins deterministic synthesis. The
Groth16 FFT uses the canonical encoding of the published 2^32 root of unity;
using the upstream Montgomery limb literal as canonical had selected a
different QAP domain while still passing ordinary FFT round-trip tests.

## Honest self-test surface — the native prover names its own blocker

`sapling_spend_prover_native_status()` (core/modules/sapling/src/sapling_circuit.c) is the
production, params-free coverage probe: it runs a canonical (non-secret)
synthesis, reports `sections_ported / sections_total`,
`constraints_ported / constraints_total`, and `next_blocker`. It reports
`roundtrip_ready = true` only after the production native C23 self-test creates
a Spend proof, an Output proof, and a binding signature and the independent
consensus verifier accepts the complete bundle. Counts alone cannot promote
readiness. The operational send gate uses that same result and requires no Rust
backend.
