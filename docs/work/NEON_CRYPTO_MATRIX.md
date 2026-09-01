<!-- Copyright 2026 Rhett Creighton - Apache License 2.0 -->

# NEON_CRYPTO_MATRIX — crypto acceleration across x86-64 and arm64

Status: work-document. Owner: the arm64/NEON crypto lane. It records, for
every crypto family in `core/modules/crypto/src/` and `core/modules/sapling/src/`, what the x86
tier is, what the arm64 tier is, how each tier is gated, which test group
proves bit-identity, and which bench times it — with the honest "no clean NEON
equivalent" markers where the ISA does not offer one.

Everything in here is re-derivable from the tree. Where a sentence could rot
(a lane landing under this document, a new tier), the sentence says what to run
to re-derive it. Do not paste derived counts into this file — the doc-count
lint gates exist precisely because prose copies of counts rot.

## 1. The contract every tier obeys

A tier is not "some intrinsics in a file". It ships only with all of:

1. **A runtime gate.** Never a compile-time `#ifdef` as the only gate — a
   binary built on a capable host runs on incapable hosts. The three gate
   shapes in use:
   - **CPU probe** — the audited CPUID/OSXSAVE/XCR0 predicate in
     `core/modules/crypto/include/crypto/simd_dispatch.h` (`simd_cpu_words_probe`,
     `simd_avx2_usable`, `simd_avx512f_usable`, `simd_avx512_dq_vl_usable`,
     `simd_avx512_ifma_usable`). x86 only, and only for instruction sets with
     XSAVE state the OS can refuse to save (that is what
     `make check-simd-os-support` polices, and its scan is deliberately
     x86-only: it matches the literal `target("avx` attribute text, because
     `target("sha")` / `target("sse4.2")` / `target("bmi2,adx")` have no OS
     state component beyond what 64-bit mode always enables).
   - **KAT gate** — run the vector implementation on fixed vectors, compare
     against the portable implementation, and stay scalar for the life of the
     process on a single divergent byte. Used where the instruction set needs
     no OS permission (SHA-NI's self-test, crc32c's self-test, and the NEON
     gate in `core/modules/crypto/src/blake2b_avx2.c`).
   - **Portable-only** — no second tier, so nothing to gate. The gate is then
     the functional KAT vectors that already pin the primitive.
2. **A differential oracle group** — an in-suite test that drives the same
   input through every installed tier and requires byte-identity with the
   portable path. The impl↔oracle pairs are pinned in
   `tools/lint/accel_oracle_registry.txt` and policed by
   `make check-accel-oracle-pinned`; adding a tier without an oracle row there
   is how a consensus divergence ships.
3. **A bench that verifies before it times** — `tools/simd_bench.c` captures
   each tier's digests, compares them against the generic tier
   (`parity_fail`), and only times a tier that is `available && verified`.
   It exits non-zero on any divergence, and `--self-test` plants a divergence
   to prove the comparator still fires.

Dispatch hooks are **narrowing, never widening**: a caller may request a tier,
and the dispatcher installs the widest tier the host can actually execute,
returning the tier installed. On arm64 there is no 8-way BLAKE2b tier, so a
request for the 8-way tier narrows to the 4-way one; the string reporter
(`equihash_blake2b_batch_implementation()`, `sha256_implementation()`,
`bn254_accel_implementation()`, …) always names what actually runs.

## 2. The matrix

The row order follows the dependency direction: primitives first, the things
built on them after. "x86 tier" / "arm64 tier" name the tier that runs **after
the lanes listed in §4 land**; where a cell says "none today", re-derive it
with the command in the cell rather than trusting the prose.

| Family (files) | x86-64 tier | x86 gate | arm64 tier | arm64 gate | Bit-identity proof | Bench |
|---|---|---|---|---|---|---|
| BLAKE2b, Equihash batch — `core/modules/crypto/src/blake2b_avx2.c` | AVX-512F 8-way + AVX2 4-way (`target("avx512f")`, `target("avx2")`) | `simd_cpu_words_probe` + `simd_avx2_usable` / `simd_avx512f_usable`, two-layer cap/use atomics | **NEON 4-way** (this lane) | **one-time KAT** — `blake2b_neon_kat()` drives four Equihash-shaped fixed vectors through the NEON compress and the portable sequential path; any divergent bit → scalar for the life of the process | `test_blake2b_batch_parity` (all tiers vs the sequential reference, both batch entry points, contiguous + strided + repeated indices, plus teeth) | `make bench-simd` — the Equihash BLAKE2b row; `CRYPTOPERF equihash-200-9` |
| BLAKE2b scalar — `core/modules/crypto/src/blake2b.c` | portable (the frozen reference) | n/a — single tier | identical portable file | n/a | the RFC 7693 vectors inside `test_crypto`; every batch-oracle leg above pins the vector tiers *to this file* | `CRYPTOPERF blake2b`; `tools/crypto_perf_baseline.csv` row `blake2b` |
| SHA-256 — `core/modules/crypto/src/sha256.c` | SHA-NI, `target("sha,sse4.1")` | CPUID leaf 7 EBX[29] **plus a KAT self-test** (`detect_sha_ni`) | FEAT_SHA256 (`vsha256hq`/`vsha256su*`) | macOS `hw.optional.arm.FEAT_SHA256` plus a one-time transform KAT; any mismatch stays portable | `test_sha256_isa_parity`, plus `test_arm_hw_tiers` for OS-advertised reachability | `make bench-simd` — the SHA-256 row; `CRYPTOPERF sha256`; CSV row `sha256` |
| SHA-3 / Keccak x4 — `core/modules/crypto/src/keccak_x4.c`, `keccak_x4_internal.h`, `sha3_avx512.c`, `sha3_256_x4.c` | AVX-512F+VL+DQ (`target("avx512f,avx512vl,avx512dq")`): `vprolq` rotations + `vpternlogd` theta/chi | `keccak_x4_available()` → `simd_host_has_avx512_dq_vl()`, plus per-call-site default-enable macros and `sha3_*_x4_select_impl` force hooks | verified NEON x4 lane, explicitly selectable; **AUTO is scalar on arm64** because the Apple-Silicon oracle measures NEON at about 0.55x scalar | macOS `hw.optional.arm.FEAT_SHA3`; forced-vector parity against the scalar reference before promotion | `test_sha3_256_x4`, `test_sha3_512_x4` assert parity and that AUTO refuses the slower arm64 tier | the two oracle groups print scalar-vs-NEON throughput; scalar remains the shipped arm64 winner |
| CRC32C — `platform/modules/util/src/crc32c.c` (not under `core/modules/crypto`, listed because it carries a hardware tier) | SSE4.2 `_mm_crc32_u64`, `target("sse4.2")` | `__builtin_cpu_supports("sse4.2")` under `pthread_once`, **plus a KAT** comparing `crc32c_hw` against the software table across a spread of lengths | FEAT_CRC32 (`crc32cx`) | macOS `hw.optional.arm.FEAT_CRC32` plus the same one-time hardware-vs-table KAT | `test_arm_hw_tiers` proves OS-advertised reachability and parity; `test_event_log` proves storage framing through active/software paths | inline in `test_event_log`; implementation is reported by `zcl_crc32c_impl_name()` |
| BN254 Fq Montgomery — `core/modules/sapling/src/bn254.c`, `bn254_accel.c`, `mont_adx.h` | BMI2+ADX inline asm (`MULX`+`ADCX`+`ADOX`), `target("bmi2,adx")` — the asm exists because the `_addcarry*` intrinsics collapse the two carry chains | CPUID leaf 7 EBX[8]/EBX[19], dispatch through `g_bn_fq_mont_mul` | **portable `unsigned __int128` CIOS** — see §3; **no clean NEON equivalent** (marker below) | none needed — portable is the fallback tier and the dispatch table just points at it | `test_bn254_accel`, plus `test_mont_adx_honest` (checks the implementation string against what is actually compiled) | `make bench-simd` — the BN254 Fq latency/throughput rows |
| BLS12-381 Fr / Fp Montgomery — `core/modules/sapling/src/fr.c`, `fr_avx512.c`, `mont_adx.h` | same BMI2+ADX tier; AVX-512 IFMA is *probed* (`simd_avx512_ifma_usable`) but deliberately unimplemented — the reporter string says so | CPUID leaf 7 EBX[8]/EBX[19] + IFMA probe, dispatch through `g_fr_mont_mul` / `g_fp_mont_mul` | portable `__int128` CIOS; **no clean NEON equivalent** (§3) | none needed | `test_fr_mont_parity`, `test_fr_accel`, `test_mont_adx_honest` | `make bench-simd` — the Fr and Fp latency/throughput rows; `CRYPTOPERF bls12-381-fp-mul` |
| Equihash verifier — `core/modules/crypto/src/equihash.c` | inherits the BLAKE2b batch tiers; no intrinsics of its own | inherits | inherits the NEON 4-way tier through the same two call sites | inherits the NEON KAT | `test_blake2b_batch_parity` is the oracle for the hashing; consensus-side pins in `test_equihash_blake2b_state_seal`, `test_domain_consensus_equihash` | the `simd_bench` Equihash row *is* the verifier's hash-generation cost |
| Equihash solver — `core/modules/crypto/src/equihash_solver.c` | portable C23 (bucket-based Wagner, fixed parameters) | n/a — single tier | identical | n/a | the equihash groups above | none — the solver has no bench primitive today |
| secp256k1 (vendored) — `vendor/lib/libsecp256k1*.a` | the linked archive; no in-tree source | n/a — vendored | the Darwin archive is built on the host by `tools/scripts/build_vendor.sh` with no field/scalar override, so upstream defaults apply: **`__int128` limb arithmetic, which is native on arm64 — no NEON needed, and upstream has no NEON path** | none — upstream's own constant-time portable/`__int128` code | upstream's own exhaustive/ct testing is disabled in the vendored build; the node pins it through `CRYPTOPERF secp256k1-ecdsa-verify` timing and the CSV ratchet row `secp256k1-ecdsa-verify` | `CRYPTOPERF secp256k1-ecdsa-verify` |
| ChaCha20-Poly1305 — `core/modules/crypto/src/chacha20poly1305.c` | SSE2 four-block word-sliced tier, explicitly selectable | mandatory x86-64 ABI plus a stable one-time portable-oracle KAT | NEON four-block word-sliced tier, explicitly selectable; **AUTO remains portable pending physical promotion evidence** | mandatory arm64 ABI plus the same stable one-time KAT; concurrent first callers converge and a divergent bit disables the vector tier | `test_chacha20_isa_parity`: RFC vector, every length 0..1024, randomized differential cases, in-place operation, exact caller-shaped opens, auth-before-output tamper teeth, AEAD caller boundaries, and counter-exhaustion refusal | `make bench-simd CHACHA_ONLY=1 REQUIRE_CHACHA_WINS=1 REPS=41` runs paired portable/vector seal **and open** rows for Sapling notes, Noise frames, and private-object chunks with p50/p90/p95/max. Run it in three separate physical-Mac processes; even three clean observations are a promotion candidate, not a sealed receipt or AUTO authority |
| AES-256 (FF1) — `core/modules/crypto/src/aes256.c` | portable — **no AES-NI tier even on x86** | n/a | portable. FEAT_AES exists on arm64 but a one-sided tier would break the parity posture | n/a | the `test_zip32_*` FF1 groups that consume it | none |
| Curve25519 / X25519 — `core/modules/crypto/src/curve25519.c`, `x25519_safe.c` | portable (TweetNaCl-style 16-limb) | n/a | portable | n/a | `test_ed25519_differential` and the note-encryption groups | `CRYPTOPERF ed25519-verify` is the nearest timed sibling |
| Ed25519 — `core/modules/crypto/src/ed25519.c` | portable | n/a | portable | n/a | `test_ed25519_differential` | `CRYPTOPERF ed25519-verify` |
| SHA-512 / SHA-1 / RIPEMD-160 — `core/modules/crypto/src/sha512.c`, `sha1.c`, `ripemd160.c` | portable — no tier on either arch | n/a | portable | n/a | the KAT vectors inside `test_crypto` | none |
| BLAKE2s / BLAKE3 — `core/modules/crypto/src/blake2s.c`, `blake3.c` | portable | n/a | portable | n/a | `test_blake3_kat` for BLAKE3; BLAKE2s via `test_crypto` | none |
| Sapling note encryption / PRF / FF1 — `core/modules/sapling/src/note_encryption.c`, `prf.c`, `ff1.c` | inherit the tiers of BLAKE2b, ChaCha20-Poly1305, Curve25519, SHA-256, AES-256 | inherit | inherit (including the NEON BLAKE2b tier on the KDF path) | inherit | the KDF/KAT groups (`test_note_encryption_*`, `test_sapling_kdf_*`, `test_zip32_*`) | none of their own |

## 3. The honest markers — where NEON is not the answer

These are the rows where "just add a NEON tier" is wrong, and saying so is the
point of this document.

- **BN254 / BLS12-381 field multiplication.** NEON has no 64×64→128 widening
  multiply: `umulh` is scalar-only and there is no 64-bit `umull` vector form.
  A vector Montgomery multiplier would have to be rewritten over 32-bit limbs
  with re-derived reduction constants — a new implementation to be proven, not
  a port of a proven one. The arm64 posture is therefore **portable C with
  `unsigned __int128` CIOS plus the compiler's auto-vectorization of the
  surrounding batch loops**, and the proof burden stays where it already is
  (`test_fr_mont_parity`, `test_bn254_accel`). The same reasoning is why x86
  uses ADX *inline asm* rather than intrinsics (`mont_adx.h` header comment:
  the two-carry-chain shape is not expressible in the portable intrinsics).
- **SHA-256.** The arm64 counterpart of SHA-NI is not NEON, it is FEAT_SHA256
  — `vsha256hq` collapses two rounds and `vsha256su0/1` the message schedule;
  a NEON-only SHA-256 would be *slower* than the extension and much slower
  than SHA-NI. The lane in flight should land the extension, not NEON.
- **secp256k1.** Upstream's field/scalar code over `__int128` limbs is already
  native-width on arm64, and upstream ships no NEON backend. There is nothing
  to accelerate honestly; the vendored archive's own constant-time code is the
  tier on both arches.
- **AES-256 / Curve25519 / Ed25519 / SHA-512 / SHA-1 / RIPEMD-160 /
  BLAKE2s / BLAKE3.** No SIMD tier exists on **either** arch.
  That is a parity decision as much as a priority one: a one-sided arm64 tier
  would make the two platforms diverge in timing but not in output, and the
  consensus contract only needs output parity. Any future tier here should
  land on both arches or neither.
- **Keccak x4.** NEON *can* express the x4 geometry (four instances across a
  register pair), but with no `vprolq` and no ternary-logic instruction every
  rho/theta/chi step expands into several baseline ops. Expect a modest win,
  not the AVX-512 ratio, and budget for a fresh oracle rather than a port.
- **The Equihash solver.** Its cost is bucket/cache behavior, not arithmetic
  width; SIMD does not map onto it cleanly on either arch.

## 4. Landed arm64 lanes and re-derivation

These paths are code, not promises. Re-derive each instead of trusting this
list, and keep measured-slower implementations available for proof without
making them the automatic default:

- **SHA-256 FEAT_SHA256** — `core/modules/crypto/src/sha256.c`. Re-derive:
  `git grep -n "vsha256hq\|__ARM_FEATURE_SHA" -- core/modules/crypto/src/sha256.c`.
- **CRC32C FEAT_CRC32** — `platform/modules/util/src/crc32c.c`. Re-derive:
  `git grep -n "crc32cx\|__ARM_FEATURE_CRC32" -- platform/modules/util/src/crc32c.c`.
- **SHA3/Keccak x4 NEON** — `core/modules/crypto/src/keccak_x4*.c`,
  `core/modules/crypto/src/sha3_*x4*.c`. Re-derive:
  `git grep -ln "arm_neon" -- core/modules/crypto/src`.
- **BLAKE2b NEON 4-way** — `core/modules/crypto/src/blake2b_avx2.c`.

The tree-wide re-derivation for "what arm64 SIMD exists at all" is:

```sh
git grep -ln "__aarch64__" -- core/modules/crypto core/modules/sapling platform/modules/util
git grep -ln "arm_neon"    -- core/modules/crypto core/modules/sapling platform/modules/util
```

and, for the x86 side, the set of files the OS-state gate holds to the
`target("avx…")` rule is derived with the gate's own scan:

```sh
git grep -l -E '__attribute__\(\(target\("avx' -- '*.c'
```

(`make check-simd-os-support` reports how many files it scanned and how many
violations it found, not the list.)

## 5. How to prove a tier (the checklist a new arm64 lane follows)

1. Put the tier beside the portable one in the same file the oracle already
   pins, or add the pair to `tools/lint/accel_oracle_registry.txt` and write
   the oracle. The oracle must include **teeth**: it has to demonstrate that a
   planted one-bit divergence is caught, or its pass proves nothing.
2. Gate it. On arm64 that is almost always the KAT shape — NEON is base ABI
   (no OS-state question), FEAT_* extensions are the ones that need a
   runtime-capability probe (AT_HWCAP or a compiler-provided macro checked at
   runtime), and a KAT on top costs one compress at startup and buys a
   guarantee no probe can give.
3. Wire the force/report hooks so `*_implementation()` and the select hook
   name the tier honestly, and make the select hook narrowing-only.
4. Add the primitive to `tools/simd_bench.c` with the verify-then-time shape,
   and only then quote a number.

## 6. How to read a bench row

`make simd_bench` (or `make bench-simd`) prints, per primitive, one row per
tier: availability, verification against the generic tier, then the timing.
A tier that is not installed on the host prints as unavailable and is skipped;
a tier whose digests diverge prints the first divergent byte pair and is never
timed. `--self-test` plants a divergence and requires the comparator to fire;
`--csv` emits the same rows in machine form. Because the Equihash row's unit
is "block headers" (512 BLAKE2b finalizations), its speedup factor is the
number to quote for the NEON tier.
