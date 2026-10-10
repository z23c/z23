<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Fleet board authority recheck before delayed delivery

## Outcome

A private fleet board answer prepared at OPEN is sent only while the existing pairing, delegation window and read role remain authorized. The production tick reuses the OPEN authority predicate immediately before emitting the cached answer. Existing framing, limits, signatures and refusal reasons remain unchanged. Previously delivered bytes are outside this claim.

## Exact experiment

Source base: `9c60d6dfcf5421767fe7f3fdf3705d5b892efed2`.
Execution date: 2026-10-10 UTC (2026-10-09 America/Puerto_Rico).
Host CPU: AMD Ryzen 9 7950X3D. Test compiler: GCC 14.2.0; syntax tooling: Clang 18.1.3. All builds and tests used canonical `devbuild --wait` admission.

The registered `fleet_board` fixture opens a real stream over production Noise records and P2P queues with one byte of initial credit. The first service tick emits nothing. It then independently revokes the durable pairing, withdraws the read role, or expires the signed delegation before delivering a WINDOW frame. Each refused case requires CLOSE and an empty output queue after a second tick. The positive control compares the exact signed post bytes. Socket delivery, delegation lookup and clock are fixture seams; this is not a two-host route qualification.

| Variant | Observed result |
| --- | --- |
| Parent plus regression | Authorized control passes; all three withdrawn-authority cases emit DATA instead of CLOSE and fail. |
| Candidate | Registered group passes. |
| Mutation removing only the new recheck | Authorized control passes; the same three production-boundary failures recur. |
| Restored candidate | Registered group passes, with one group run, zero cached groups, failures, skips, environment omissions or load-flaky results. |

The initial required lint run passed 34 of 35 gates and refused stale generated capability inventory after the new test call graph. Canonical `make docs-capability-inventory` regeneration, its generated-file gate and the complete `lint-fast` run subsequently passed.

## Cost and evidence

Parent request queue: 65.432212872 s; execution: 441.865005904 s, including fresh dependency setup and compilation. Candidate queue: 164.306558322 s; execution: 65.710689865 s. Controlled mutation, restoration and first lint queue: 108.253920530 s; execution: 191.758607274 s. These phases differ in dependency and cache preparation; no performance improvement is inferred.

SHA-256 logs:
- Parent: `9bf695697c6963b4be4e8e40438ce712bdf1fa3cccad7d09f514acaaa42c7290`.
- Candidate: `73d23e1f24f11e262ca3a1cec4f4cef02a15e661ab86121117fd9adfe7ad80e1`.
- Mutation: `325cac2332e952165dcbca1986090679bfcf1d25592780975dde5b4c369c6882`.
- Restored: `474141be474e1f8ab1e97084e69ad3af6f8073d6950fa95036a19bf5ec014484`.
- Initial lint refusal: `27735d1f4bd9dcab830b6955510efe9d5f348302ed837229ea1872b9c5f03b41`.

## Remaining acceptance

Two consenting isolated nodes must carry the same native message and object identities in both directions, execute receiver-authorized bounded work, return verified receipts, recover after disconnect/restart without duplicate work, and enforce revocation. Existing boardmail RPC mocks and this socket-elided fixture do not establish that route.


## Current-base requalification

The candidate was fast-forwarded to `f57b6adc27b2160d4ded6ae388e731264d7e7245`; both board source and test preimages remained identical. Canonical inventory regeneration, the uncached registered `fleet_board` group and required `lint-fast` passed on this base. The group ran once with zero failures, cached groups, skips, environment omissions or load-flaky results. Queue: 97.414731511 s; execution: 144.544062877 s. Combined log SHA-256: `c219dd2f38c01692c1ef27e3b76a0706f4f956154a7458f4c361d637c853e009`. Earlier parent and mutation witnesses remain bound to their original `9c60` base.
