/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Ed25519 signatures (verify + sign) — pure C23 implementation.
 * Replaces libsodium crypto_sign_verify_detached. */

#ifndef ZCL_CRYPTO_ED25519_H
#define ZCL_CRYPTO_ED25519_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/* Verify an Ed25519 signature (RFC 8032 Ed25519, SHA-512 hash). Returns
 * true IFF the 64-byte `sig` is a valid signature by `pk` over `msg`.
 *
 * Consensus verify uses this for JoinSplit ed25519 signatures, where
 * exact agreement with zcashd is mandatory; keypair/sign were added
 * later for off-chain identity documents (contexts/wallet/modules/zid) and reuse the same
 * field/group/scalar arithmetic.
 * A true return certifies ALL of:
 *   - `pk` is not the all-zero identity point (rejected up front);
 *   - S (sig[32..63]) is canonical, i.e. S < L the group order — malleable
 *     high-S signatures are rejected BEFORE any point math (RFC 8032
 *     §5.1.7; a non-canonical S would otherwise split consensus);
 *   - `pk` decompresses to a valid curve point, and [S]B == R + [h]A where
 *     h = SHA-512(R || pk || msg) mod L, compared via a constant-time
 *     XOR-accumulate (no early-exit memcmp).
 * Any failed check returns false (it logs the reason; it never aborts).
 * `msg_len` may be 0. */
bool ed25519_verify(const uint8_t sig[64],
                    const uint8_t *msg, size_t msg_len,
                    const uint8_t pk[32]);

/* Verify n independent Ed25519 signatures at once.
 *
 * Returns EXACTLY
 *     ed25519_verify(sig[0], msg[0], len[0], pk[0]) && ... && (n-1)
 * — same verdict as the loop, on every input including adversarial ones,
 * never "true if most of them verify". A single bad signature anywhere in
 * the set makes the whole call false.
 *
 * Arrays are parallel and all of length n: `msgs[i]` (may be NULL when
 * `msg_lens[i]` is 0), `sigs[i]` (64 bytes), `pubkeys[i]` (32 bytes).
 *
 * n == 0 returns true — the empty conjunction, matching a zero-iteration
 * verify loop. A caller that requires at least one signature must check n
 * itself. n == 1 runs the same batch machinery (no special case) and is
 * still faster than `ed25519_verify`, because the combined path uses
 * windowed multiplication where the single path uses a bit-at-a-time
 * ladder.
 *
 * Speed comes from one shared multi-scalar multiplication (Straus, with
 * the doublings shared across the whole set) instead of n separate double
 * scalar multiplications, randomised with 128-bit scalars drawn from the
 * project CSPRNG. Exact agreement with the single path — including for
 * small-order/8-torsion-crafted public keys, where the naive random-scalar
 * batch equation would accept signatures that `ed25519_verify` rejects —
 * comes from a per-signature torsion screen; the construction and its
 * proof obligations are documented at the top of the batch section in
 * core/modules/crypto/src/ed25519.c.
 *
 * Failure modes are handled, not papered over: if the CSPRNG refuses (a
 * predictable randomiser is a forgery oracle) or the working buffer cannot
 * be allocated, the call falls back to n independent `ed25519_verify`
 * calls and returns the same verdict, more slowly.
 *
 * Pure scalar C23 — no intrinsics and no runtime CPU dispatch, so there is
 * one code path on every target. */
bool zcl_ed25519_verify_batch(const uint8_t *const *msgs,
                              const size_t *msg_lens,
                              const uint8_t *const *sigs,
                              const uint8_t *const *pubkeys,
                              size_t n);

/* Derive an Ed25519 keypair from a 32-byte seed (RFC 8032 §5.1.5):
 * h = SHA-512(seed); the secret scalar a is h[0..31] clamped
 * (a[0] &= 248, a[31] &= 127, a[31] |= 64); pk = [a]B, compressed.
 * `sk` receives a copy of the seed (the RFC 8032 "secret key" IS the
 * 32-byte seed); `pk` receives the 32-byte public key. */
void zcl_ed25519_keypair(uint8_t pk[32], uint8_t sk[32], const uint8_t seed[32]);

/* Sign `msg` (RFC 8032 §5.1.6, pure Ed25519 / SHA-512):
 *   r = SHA-512(prefix || M) mod L   (prefix = SHA-512(sk)[32..63])
 *   R = [r]B
 *   k = SHA-512(R || pk || M) mod L
 *   S = (r + k*a) mod L
 * `sk` is the 32-byte seed and `pk` the matching public key from
 * ed25519_keypair — pk is mixed into the k hash, so a mismatched pk
 * produces a signature that does not verify. `sig` receives R || S.
 * `msg_len` may be 0. The scalar path uses the same branch-free clamp
 * and cswap ladder as verify (no data-dependent table lookups). */
void zcl_ed25519_sign(uint8_t sig[64], const uint8_t *msg, size_t msg_len,
                      const uint8_t sk[32], const uint8_t pk[32]);

/* The symbols are zcl_-prefixed to avoid colliding with the vendored Tor
 * libtor.a, which exports its own ed25519_sign into the same binary (same
 * pattern as sha3_256 in crypto/sha3.h). Always use the macro names. */
#define ed25519_keypair zcl_ed25519_keypair
#define ed25519_sign zcl_ed25519_sign
#define ed25519_verify_batch zcl_ed25519_verify_batch

#endif
