<!-- Copyright 2026 Rhett Creighton - Apache License 2.0 -->

# Private-object grant and encryption order

## Intent

Prove that a sender can encrypt an exact private object before the receiver
issues the ciphertext-bound durable grant. The pre-encryption key context must
not depend on the future grant identifier; the final signed offer must still
bind both the grant identifier and ciphertext root.

## Environment

- Local time: `2026-08-29T19:39:55-04:00`
- UTC: `2026-08-29T23:39:55+00:00`
- CPU: AMD Ryzen 7 PRO 8840U with Radeon 780M Graphics
- Native compiler: GCC 16.1.1
- Windows cross-compiler: GCC 16.1.0 (`x86_64-w64-mingw32-gcc`)

## Method

The registered acceptance constructs a two-chunk plaintext and canonical
plaintext root, derives the key context while `grant_id` and `ciphertext_root`
are absent, encrypts both chunks, and derives the canonical ciphertext root.
It then derives and validates the exact durable grant, attaches the resulting
identifier and ciphertext root, derives the nonce-bound request identifier,
signs the offer, and checks the complete expected offer.

```bash
make -j"$(nproc)" t-fast ONLY=mesh_private_object_grant_pipeline
make -j"$(nproc)" t-fast ONLY=mesh_private_object_proto
make -j"$(nproc)" t-fast ONLY=mesh_private_object_crypto
```

## Result

The new pipeline group passed cold with one group run, zero failures, and zero
skips. The protocol and chunk-crypto regression groups also passed cold. The
key context is unchanged when the later grant identifier and ciphertext root
are attached. Altering either field is refused by exact expectation matching,
and altering the ciphertext root after signing invalidates the signature.

This removes the construction cycle; it does not issue remote authority.
Target-side capability plan/commit still requires a canonical private-object
template bound by `proposal.input_root`, atomic live-authority revalidation,
and an independently verified two-peer receipt.
