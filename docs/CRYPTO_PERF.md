# Crypto performance — the standing "beat Rust" invariant

**The invariant:** every C crypto primitive on the Z23 consensus path
must stay **at least as fast as its Rust/blst counterpart**, and may only ever
get **faster** — never regress. "Beat Rust" is a durable, gated property, not a
one-time push. This document is the standing contract; the mechanism is the
`check-crypto-perf` gate.

Consensus verify **logic is frozen** (see
[`CONSENSUS_PARITY_DOCTRINE.md`](./CONSENSUS_PARITY_DOCTRINE.md)). This whole
surface is **measurement + gating only** — it calls the production verify/hash
predicates and touches no validity predicate. **No Rust is linked into the
shipped binary** (the no-external-deps rule); the comparison is against pinned /
cited Rust numbers, never a live Rust link.

## The three pieces

| piece | path | role |
|---|---|---|
| Benchmark | `build/bin/z23 -bench-crypto-vs-rust` (`engine/entry/main.c`) — `make bench-crypto-vs-rust` | Times every consensus-path C primitive as a **median of N** ns/op, prints machine-readable `CRYPTOPERF <key> <ns> <ops/s>` lines, appends medians to `docs/bench-history.csv`. |
| Baseline | `tools/crypto_perf_baseline.csv` | Per primitive: `c_ns_baseline` (a **ceiling that may only shrink**), `rust_ns_baseline`, `gate_mode`, `rust_source`. |
| Gate | `tools/scripts/check_crypto_perf.sh` — `make check-crypto-perf` | Measures C live and enforces the ratchet + the ratio-vs-Rust rule below. |

The benchmark cannot go **hollow-fast**: every primitive is TEETH-checked
(valid → true, perturbed → false / avalanche / square-consistency) before any
number is recorded, and the same teeth run independently in the fast test pool
as the `crypto_perf_selftest` group (`tests/harness/src/test_crypto_perf_selftest.c`).
A no-op hash / always-true verify / operand-returning multiply fails there
before the gate can ratchet a broken primitive.

## The gate rules

Run `make check-crypto-perf` in a **quiet context** (it is deliberately **NOT**
in the default `make lint` aggregate — microbench timing flakes under CI load).
Margin default **20%** (`ZCL_CRYPTO_PERF_MARGIN`).

1. **RATCHET (always, hard).** `measured_c_ns <= c_ns_baseline * (1 + margin)`.
   The baseline is a **ceiling**; as we optimise we **shrink** it (never raise
   it). A self-regression beyond the margin **FAILS**. This is the core
   protection — our C crypto can only get faster.

2. **RATIO vs Rust.** `ratio = measured_c_ns / rust_ns_baseline`.
   - `gate_mode=beat` — we are ahead. **Hard-FAIL if `measured_c_ns >=
     rust_ns_baseline`** (we lost the lead). This is **flake-proof by
     construction**: a `beat` row is only valid when
     `rust_ns_baseline >= c_ns_baseline * (1 + margin)`, so any run that passes
     the ratchet is necessarily below Rust. The gate asserts that headroom
     (`FAIL_CONFIG` if a `beat` row is mis-pinned).
   - `gate_mode=behind` — we are behind (or only slimly ahead, kept in this
     bucket for flake safety). **No hard fail** (that would red main today);
     the gate prints a loud **`BEHIND RUST — optimize <primitive>`** line and
     relies on the ratchet for monotonic improvement toward parity. This is the
     target list for the crypto-beat-rust workflow.

## Current standing (baseline 2026-07-13, AMD Ryzen 9 7950X3D, pure-C23 `-v3`)

Median-of-5 × 120 ms, pinned slightly above max-observed for ratchet headroom.
Rust numbers are **CITED** published reference points (no Rust is linked); see
`tools/crypto_perf_baseline.csv` for the source of each.

| primitive | C ns/op | Rust ns/op | ratio | verdict |
|---|--:|--:|--:|---|
| equihash-200-9 verify | ~122k | 160k (zcashd C++ ref) | 0.72 | **BEAT** |
| secp256k1 ECDSA verify | ~49k | 90k (RustCrypto k256) | 0.55 | **BEAT** |
| BLAKE2b-512 (1 KiB) | ~0.85k | 1.1k (blake2b scalar) | 0.78 | **BEAT** |
| SHA256 (1 KiB) | ~0.47k | 0.68k (SHA-NI) | 0.70 | **BEAT** |
| SHA3-256 (1 KiB) | ~1.7k | 2.0k (keccak scalar) | 0.83 | behind* (slim) |
| BLS12-381 Fp mul | ~31 | 45 (blst asm) | 0.69 | **BEAT** |
| groth16 BLS12-381 output verify | ~7.7M | 3.0M (librustzcash) | 2.57 | behind |
| BLS12-381 Ate pairing | ~1.83M | 0.6M (blst) | 3.05 | behind |
| ed25519 verify | ~0.71M | 55k (ed25519-dalek) | 12.9 | behind (no base-point precompute, 16×16 field) |

\* `sha3-256` is marginally ahead but pinned `behind` so its hard-fail can't
flake near the boundary; optimise it past a 25% margin to promote it to `beat`.

**Where we beat Rust:** Equihash verify, ECDSA verify (vendored libsecp256k1 vs
RustCrypto), BLAKE2b (AVX2 path), SHA256 (SHA-NI path). **Optimize targets
(behind):** the pairing / Fp-mul / Groth16 elliptic-curve stack (blst
hand-asm) and ed25519. Groth16 being behind is
expected today and must NOT red main — the loud line keeps it visible.

### ed25519 verify — where the remaining 13× is

The verify equation `[S]B + [h](−A) == R` used to run as two independent
256-step cswap ladders. It is now ONE interleaved Straus double-scalar
multiply over 4-bit fixed windows, sharing the 256 doublings between both
terms — the same `mx_build_table`/`mx_digit` machinery the batch verifier
already used, so it is not new arithmetic, just the two-term case of code
that was already there and already tested. Measured on this host, same
build, immediately before and after the change: median **1496 µs → 710 µs,
a 2.11× speedup** (before: 5 runs, 1446–2197 µs; after: 9 runs, 662–813 µs;
each run is itself the harness's median of 5 × 120 ms samples, and the wide
tails are the live node competing for the machine).

The secret-scalar paths — key derivation and signing — deliberately did
**not** move to the windowed code. They keep the constant-time ladder,
because window indices are branched on and only verify's inputs (signature,
public key, message hash) are public.

That leaves ~13× against dalek, and it is not hiding in the scalar
multiplication any more. It is in two places this change did not touch:
there is no precomputed table for the fixed base point B, and the field is
still the TweetNaCl 16×16-limb schoolbook rather than 5×51 limbs. The field
is the larger of the two and it is shared with every other consumer of this
file, so it is a separate, more invasive change that needs its own
before/after — **`test_ed25519_differential` is the harness that will hold
it honest**, exactly as it did here.

### SHA256 ISA dispatch — runtime only, never compile-time

SHA-256 selects between a portable C transform and an Intel SHA-NI transform at
**runtime**, via CPUID plus a known-answer test against the portable reference
(`detect_sha_ni`). The hardware transform is emitted from the baseline
translation unit by a per-function `__attribute__((target("sha,sse4.1")))` —
the same shape `blake2b_avx2.c`, `keccak_x4.c` and `sha3_256_x4.c` use.

Two properties depend on that being a runtime decision, and a compile-time
guard breaks both:

* The shipped `-march=x86-64-v3` does **not** define `__SHA__`. A
  `#ifdef __SHA__` around the transform deletes it from every released binary
  while `/proc/cpuinfo` still reports `sha_ni` — silently, since the portable
  fallback stays correct, merely ~4× slower on every block hash, merkle root,
  txid and sighash. This was the state of the tree until the guard was removed.
* `tools/scripts/check_reproducible_build.sh` deliberately does not set
  `ZCL_NATIVE`, so the binary must be byte-identical across build hosts.
  Runtime dispatch keeps it so; compile-time selection would make the artifact
  depend on the builder's CPU.

Measured at the shipped `-march=x86-64-v3` on the baseline host, portable vs
SHA-NI within the same binary:

| workload | portable | SHA-NI | speedup |
|---|--:|--:|--:|
| SHA-256, 1 KiB | 1934.2 ns | 470.5 ns | 4.11× |
| double-SHA-256, 80 B (block hash) | 364.3 ns | 91.4 ns | 3.99× |
| double-SHA-256, 64 B (merkle combine) | 362.2 ns | 89.3 ns | 4.06× |

`ZCL_NATIVE=1` (`-march=native`) buys nothing further — 474.9 ns for the 1 KiB
case, i.e. within noise of the portable-march build — because the target
attribute, not the `-march`, is what emits the SHA-NI opcodes. The dispatch
stays a runtime decision precisely so the binary remains byte-identical across
build hosts for `tools/scripts/check_reproducible_build.sh`.

The `test_sha256_isa_parity` group is the differential oracle for the two
transforms and the standing regression guard: on a CPU that advertises SHA-NI
it FAILS if the node does not actually install SHA-NI, so a re-introduced
compile-time guard cannot go unnoticed again.

### The rest of the ISA inventory

The rule above is tree-wide, not a SHA-256 special case: `#ifdef __<ISA>__`
around a vector body deletes it from every shipped binary, because
`-march=x86-64-v3` defines `__AVX__/__AVX2__/__BMI__/__BMI2__/__FMA__` and
does **not** define `__SHA__`, `__AVX512*__`, `__ADX__`, `__AES__` or
`__PCLMUL__` — all of which the baseline host physically has. A per-function
`__attribute__((target(...)))` plus a runtime CPUID (**and** XCR0/XGETBV)
predicate is the only shape that ships.

Every accelerated path under `core/modules/crypto/src/` and `core/modules/sapling/src/` now
follows it. The audited inventory is `sha256.c`, `sha3_avx512.c`,
`keccak_avx512.c`, `sha3_256_x4.c`, `blake2b_avx2.c`, `fr_avx512.c`,
`bn254_accel.c` — every other file in those two directories has no
accelerated path at all (no `immintrin.h`, no `target(...)`, no CPUID), so
absent acceleration there is a perf opportunity, not this defect class.

Two dispatch decisions are deliberate and must not be read as bugs:
`keccak_avx512.c` is default **off** because single-stream Keccak-f measures
0.84–0.99× on Zen 4 (the cross-lane π gather dominates), while the
lane-parallel `sha3_256_x4.c` and `sha3_avx512.c` (`sha3_512_x4`) are default
**on** and measure ~1.7–2×. A measured loss left off is not a compiled-out
path.

One gap is known, still open, and needs its own job:

* **`blake2b_avx2.c` gates on CPUID alone.** `detect_features()` reads leaf-7
  EBX bits 5 and 16 with no XCR0 check, unlike every other ZMM entry point in
  the tree. On a kernel booted with AVX-512 state disabled, `g_has_avx512f`
  reads 1 and the 8-way compress would `SIGILL`. Practically unreachable on a
  supported Linux, but this is a live dispatch predicate on the Equihash
  verification path, so tightening it is a consensus-adjacent change and needs
  its own gate.

### Closed: the ADX overclaim (and the slowdown behind it)

`fr_avx512.c` and `bn254_accel.c` used to name a tier
`"BMI2+ADX (MULX+ADCX+ADOX)"` that built **no carry chains at all**. Every
`_addcarryx_u64` took a literal `0` carry-in and folded the carry with an
ordinary scalar add, so GCC lowered all of them to plain `ADC`; the shipped
object disassembled to `mulx=64, adcx=0, adox=0`. `target("bmi2,adx")` bought
MULX and nothing else.

It was also **slower than the portable C it displaced**, in all six measured
cases — so the tier cost speed *and* told the operator a false story about why.

The fix was to write the thing the name promised: a real CIOS dual carry chain
in inline asm (`core/modules/sapling/src/mont_adx.h`), ADCX on CF and ADOX on OF. Asm and
not intrinsics because C has no way to keep two carry chains in two flag bits —
that is *why* the intrinsic version degraded, and it will degrade again for the
next person who "simplifies" it back.

Measured with `taskset -c 8 build/bin/simd_bench --cpu=8 --reps=101` on the
baseline 7950X3D at 1-minute load 2.4-2.9, p90/median 1.00-1.02x on every row (the
old MULX column is from the same harness before the rewrite):

| workload | portable | old "ADX" (MULX only) | real ADCX/ADOX | old vs portable | new vs portable |
|---|--:|--:|--:|--:|--:|
| BN254 Fq (Sprout), latency | 23.26 ns | 28.32 ns | 22.51 ns | 0.82× | **1.03×** |
| BN254 Fq (Sprout), throughput | 18.05 ns | 22.37 ns | 15.59 ns | 0.81× | **1.16×** |
| BLS12-381 Fr, latency | 24.48 ns | 29.19 ns | 22.52 ns | 0.85× | **1.09×** |
| BLS12-381 Fr, throughput | 16.78 ns | 23.06 ns | 15.68 ns | 0.73× | **1.07×** |
| BLS12-381 Fp, latency | 42.32 ns | 54.83 ns | 33.60 ns | 0.78× | **1.26×** |
| BLS12-381 Fp, throughput | 38.16 ns | 52.95 ns | 27.75 ns | 0.72× | **1.38×** |

The decision rule applied here is the one the `keccak_avx512` deletion set: a
tier that is not measurably faster than portable does not get left switched off,
it gets deleted. The MULX-only bodies are gone — not disabled — and portable is
the only fallback. Had the rewrite failed to beat portable, the whole tier would
have been deleted instead, and that would also have been a ~1.2–1.4× win.

Bit-identity is proven three ways, because this is a consensus path: the
`bn254_accel` and `fr_accel` differential oracles (boundary vectors 0/1/p-1/p-2
and their cross products, plus 100k–200k random vectors per field, reduced into
`[0, p)`), `simd_bench`'s per-tier check (which exits 2 on divergence and whose
`--self-test` proves it can fail), and `make check-groth16-parity` on the frozen
corpus.

Two guards keep it closed. `test_fr_accel` is the Fr/Fp differential oracle that
did not exist before — only BN254 Fq had one, even though every Sapling proof
verifies through Fr and Fp. `test_mont_adx_honest` reads the **compiled bytes**
of the installed multiply and fails if the reported implementation string claims
ADCX/ADOX that the machine code does not contain; it is the check that would
have caught the original overclaim on day one, and it fails on the parent commit.

## Optimizing safely

Any optimization to a consensus crypto primitive must stay **bit-identical** to
the frozen verify logic. The differential parity oracle
(`tests/harness/differential/`, run with `make check-groth16-parity`) proves an
optimized implementation returns the exact same accept/reject verdict as the
frozen reference on adversarial inputs. It compiles
`core/modules/sapling/src/bls12_381.c` straight from source and replays a frozen corpus
of point encodings (canonical + non-canonical infinity, out-of-field x,
on-curve non-subgroup), malformed proofs, and crafted single/batch
verifications against `groth16_parity_golden.bin` +
`groth16_decode_corpus.bin`. A single verdict flip fails the gate.

Parity is defined **against our own frozen behavior**, not against
librustzcash: the corpus deliberately pins the quirks this chain accepts —
notably the BLS12-381 non-canonical infinity encoding (infinity flag set with
dirty trailing bytes), which librustzcash rejects and we ACCEPT. Never
"fix" a pinned quirk; that is a consensus break.

Flow: optimise → `make check-groth16-parity` → prove bit-identity via the
`crypto_perf_selftest` teeth → re-run `make check-crypto-perf` → **shrink** the
baseline in `tools/crypto_perf_baseline.csv` (and flip `behind`→`beat` once you
clear the margin). The ratchet then holds the new line forever.
`run_parity_oracle.sh record` re-freezes the golden and is legitimate ONLY
after a deliberate, full-history-replay-approved consensus change.

## Landed: fixed-base public-input scalar-mul

`vk_x = IC[0] + sum(input[i]*IC[i+1])` multiplies bases that are CONSTANT for
the life of a verifying key, yet the naive path paid a full 256-bit
double-and-add per non-zero input on every verify. `groth16_vk_build_combs()`
precomputes a windowed table per IC point once at param load
(`core/modules/sapling/src/params_init.c`), and each per-verify scalar-mul becomes 64
table lookups plus adds with zero doublings. Tables are read-only after the
build, so one VK stays shareable across verify threads.

Measured with `make bench-groth16-comb ITERS=40` (7950X3D, `-O2 -march=x86-64-v3`,
median of three runs — both paths timed in one process against the same key):

| circuit | inputs | naive | fixed-base | speedup |
|---|--:|--:|--:|--:|
| sapling OUTPUT verify | 5 | 6.98 ms | 4.93 ms | 1.41x (-29%) |
| sapling SPEND verify | 7 | 7.74 ms | 5.05 ms | 1.53x (-35%) |

Cost: 144 KiB of table per IC point — ≈3.0 MB resident for all three consensus
keys (SPEND 7 inputs, OUTPUT 5, sprout-groth16 9), built once in ~25 ms total
at param load. On allocation failure the naive path is kept: same verdicts,
original speed. The remaining verify time is the four Miller loops plus the
final exponentiation, which is where the next optimization has to go.

The `tools/crypto_perf_baseline.csv` ratchet still carries the pre-optimization
`groth16 output verify` number: shrinking it requires a `make
check-crypto-perf` run against a full build with real params, not this
micro-bench.
