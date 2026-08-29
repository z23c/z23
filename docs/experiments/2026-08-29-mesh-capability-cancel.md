<!-- Copyright 2026 Rhett Creighton - Apache License 2.0 -->

# Signed mesh capability frames and durable transfer cancellation

## Intent

Add a bounded portable wire for the owner-mesh capability lifecycle and make
private-object cancellation survive process restart without revoking,
consuming, or widening the underlying grant.

## Environment

- Local time: `2026-08-29T19:17:40-04:00`
- UTC: `2026-08-29T23:17:40+00:00`
- CPU: AMD Ryzen 7 PRO 8840U w/ Radeon 780M Graphics
- Native compiler: GCC 16.1.1
- Windows cross-compiler: GCC 16.1.0 (`x86_64-w64-mingw32-gcc`)

## Method

The capability codec was registered as an exact test group. It exercises
canonical signed PROPOSAL, COMMIT, GRANT, REFUSAL, RENEW, CANCEL, and ACK
frames, exact lengths, closed capability and result vocabularies, bounded
resources, mandatory ambient-authority denials, signature tampering, reserved
bytes, and generation zero.

The private-object stage appends the existing canonical 80-byte transfer
CANCEL frame after its header and chunk bitmap. It accepts only the original
journal length or that length plus one complete CANCEL frame. Reopen refuses
torn, oversized, malformed, wrong-kind, zero-id, and wrong-transfer tails.
The receiver persists and flushes cancellation before clearing its active
slot or reporting terminal success.

```bash
make -j"$(nproc)" t-fast ONLY=mesh_capability_proto
make -j"$(nproc)" t-fast ONLY=mesh_private_object_stage
make -j"$(nproc)" t-fast ONLY=mesh_private_object_receiver
```

The three modified implementation units were also checked with native GCC and
MinGW using `-std=c2x -fsyntax-only -Wall -Wextra -Werror -pedantic`.

## Result

Each registered group ran cold with one group selected, zero failures, and
zero skips. Native and Windows cross-syntax checks passed for the signed codec,
stage journal, and receiver. Tests prove cancellation survives restart and a
fresh re-signed Noise-session offer with the same stable transfer identity;
the receiver emits no new requests after the terminal record. Grant
revocation separately survives database reopen and cannot be reversed by an
idempotent insertion.

This does not prove two-host negotiation or an operator capability service.
The codec grants no authority by itself. Target-side plan/commit, renewal,
remote revocation acknowledgement, network dispatch, plaintext publication,
and signed completion receipts remain open.
