<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Forward secrecy for native tunnels

Status: design proposal, not an implemented or qualified protocol change.
Original source review: `0f9325278ade90be99ad5203ebbef865b5403996`.
Integration base: `f4c51e944b919e4869369bdb9969ad6ee8234377`.
Reviewed on 2026-10-15. This document authorizes no deployment, pairing,
credential rotation, core modification or production execution.

## Security objective and current boundary

A captured tunnel must remain confidential after later compromise of its
long-term pairing credential, provided its ephemeral secrets and traffic keys
were erased and the selected cryptographic assumptions remain valid.
This objective does not cover a compromised endpoint while it handles plaintext.

The current host tunnel uses a static 32-byte PSK with SHAKE256-Wrap records.
Its key schedule extracts from that PSK and the handshake transcript
(the session key schedule in
[`device_host_psk.c`](../../engine/services/src/device_host_psk.c)).
Fresh nonces distinguish sessions; they do not supply an ephemeral secret
unknown to an observer who later obtains the PSK. This outer profile has
**no forward secrecy**. Erasing one session's derived keys does not change
that conclusion while the PSK and recorded transcript can reconstruct them.

OpenSSH inside the tunnel is a separate cryptographic channel. The measured
Linux loopback sshd trial used `sntrup761x25519-sha512` key exchange and
classical Ed25519 host authentication. Do not infer the inner suite from an outer profile, or
infer post-quantum authentication from hybrid key exchange. Record the negotiated
SSH key exchange and host-key algorithm separately. A stronger outer channel
does not fix unpinned SSH host keys or grant remote shell authority.

## Prefer the existing hybrid Noise transport

The preferred migration is explicit pairing and target admission through the
existing native mesh transport, then reuse of
[`mesh_tunnel`](../../engine/composition/include/config/mesh_tunnel.h).
Its header describes bounded streams and a receiver-owned loopback target
allow table. That interface alone does not establish the negotiated transport
suite. Reuse requires separately verifying the session's Noise suite, peer
identity binding and runtime admission; none is inferred from the header.

Require the exact suite
`Noise_XXhfs_25519+MLKEM768_ChaChaPoly_SHA256`, already represented in
[`noise_handshake.h`](../../core/modules/noise/include/noise/noise_handshake.h).
It combines ephemeral X25519 with ephemeral ML-KEM-768 in the existing
handshake state machine. The current suite name and token layout are a
repository protocol; FIPS 203 standardizes ML-KEM, not this complete tunnel.
Do not create a second implementation of the KEM, DH, transcript or combiner.

The initiator's KEM encapsulation key is 1184 bytes and the responder's
ciphertext is 1088 bytes. Use the existing header constants and checked
message limits, not a second catalog of sizes. The KEM decapsulation key
must be generated afresh for every full handshake, never stored as the
pairing's long-term secret. X25519 ephemeral keys must also be fresh.

The existing `noise_hs_split` clears handshake secrets, including ephemeral
DH and KEM state; `noise_hs_cleanse` handles terminal cleanup. Integration
must destroy every copy on success, failure, cancellation and timeout.
Source-level clearing does not prove that compiler temporaries, registers,
swap or crash dumps contain no remnants. Independent implementation review
and a documented process-memory policy remain required.

Authenticate the remote static identity against the exact receiver-approved
pairing. XX completion without that comparison is not peer authorization.
The existing static X25519 identity and the inner Ed25519 SSH host identity
remain classical authentication mechanisms. This proposal targets hybrid
forward secrecy, not resistance to every active quantum attacker.

## Standalone alternative

First inspect and reuse the existing
[`device_channel`](../../engine/services/src/device_channel.c) boundary. It already
uses XXhfs with pinned local and peer X25519 identities, a purpose/profile-bound
prologue and a guest-stream interface. That source mechanism is not evidence
that the current static-PSK host tunnel uses it.

A direct host runtime that cannot use an established mesh session may adapt
the same existing XXhfs state machine to its bounded socket lifecycle.
That is a separate integration candidate, not permission to reinterpret
current PSK frames as Noise or to expose a new listener automatically.

Before implementation, freeze a versioned byte-level protocol contract and
independent vectors for its prologue, role ordering, messages and terminal
records. Bind the selected suite, protocol version, ordered peer identities,
target service, both ordered authorization identities and credential epochs.
Define canonical encoding and field bounds so both endpoints hash identical
bytes. Keep local authorization roots distinguishable when they differ.

Reusing the static-PSK pairing record does not create a pinned Noise identity.
Require explicit re-pairing into the existing identity model. If compatibility
requires PSK authentication in addition to the hybrid handshake, specify and
review an exact supported Noise PSK-modifier profile first; do not insert an
ad hoc concatenation, XOR or extra secret into the existing KDF. The current
XXhfs implementation must not be described as implementing such a modifier.

ML-KEM-768 with X25519 is preferred to a KEM-only new profile because it
reuses the existing hybrid implementation and retains a separate classical
key-agreement assumption. A KEM-only alternative needs its own named suite,
security analysis, vectors and explicit receiver policy. Neither alternative
is a silent downgrade or fallback path.

## Admission, erasure and downgrade rules

- Authenticate and confirm the full handshake before releasing application
  bytes or opening the approved loopback target. Disable early application data.
- Enforce the receiver's exact pairing, direction, target and current policy.
  A valid transcript never substitutes for a fresh authorization check.
- Select a minimum suite under local policy. Unknown versions, wrong pins,
  mismatched roles and unsupported suites fail closed. Never retry static PSK,
  classical-only Noise or plaintext after a required hybrid handshake fails.
- Bound pre-authentication connections, bytes, elapsed time, KEM operations
  and memory separately from authenticated sessions. Garbage connections
  must not consume authenticated-session quota indefinitely.
- Refuse entropy failure. Production entropy comes from the existing qualified
  host RNG; deterministic randomness is test-only.
- Preserve authenticated terminal records and truncation detection. Transport
  EOF, SSH exit, wrapper success and receiver cleanup are separate observations.
- Rekey traffic before existing counter limits. Symmetric rekey alone adds no
  fresh secret and does not promise recovery from current-state compromise.
  Establish a fresh full ephemeral handshake when new entropy is required.
- Do not persist ephemeral private keys, shared secrets or traffic keys in CAS,
  receipts, transcripts or retry objects. Public transcript hashes are evidence,
  not permission to retain session secrets.

## PSK rotation and migration

Until hybrid admission is qualified, describe legacy outer protection as
static PSK and keep the independently pinned inner SSH channel.

Rotate each peer's PSK using independent high-entropy randomness supplied
through the existing owner-private pairing lifecycle. Do not derive a replacement
only from a compromised old PSK or send it over a channel authenticated solely
by that compromised credential. Never publish secrets in the fleet wiki or mail.

Prepare the new credential epoch at both endpoints, verify the exact peer,
scope and expiration, then commit through existing pairing authority.
If an overlap is necessary, explicitly bound it to the named old and new
epochs with a deadline; it must not mean accepting any historical credential.
Revocation must stop new admissions and interrupt existing authority at the
existing guarded I/O boundary. Verify both endpoints and retire old secret
material according to that lifecycle. Rotation does not retroactively give
forward secrecy to recorded legacy sessions.

Migrate in this order:

1. Qualify the existing hybrid primitives and the exact adapter in isolated
   fixtures. Preserve the static-PSK suite as a separately named legacy profile.
2. Explicitly approve and pin Noise identities and target admission at both
   consenting endpoints; distribute the exact package through existing
   verification and reproduction authorities.
3. Exercise an isolated hybrid-required route. Record the negotiated outer
   suite and inner SSH algorithms; never infer them from configuration.
4. Promote the exact accepted version only through owner-controlled policy.
   Disable legacy admission for that pairing after both endpoints verify
   revocation and the new route's acceptance.
5. Rollback may restore a previously accepted binary but cannot lower a
   hybrid-required policy or revive a revoked credential. If the old binary
   cannot satisfy current policy, refuse instead of reconnecting insecurely.

No production `core/` changes are included. Any future change under that
sealed authority requires the repository's separate unseal/reseal procedure.

## Vectors, experiments and acceptance

Reuse the pinned NIST ACVP vectors in
[`mlkem768_vectors.h`](../../platform/modules/mlkem/tests/mlkem768_vectors.h)
and the deterministic transcript checks in
[`test_noise_xxhfs.c`](../../tests/harness/src/test_noise_xxhfs.c).
The former records its upstream commit and source JSON hashes. Retain those
identities; never regenerate expected outputs with the implementation being
tested and call that independent evidence.

| Obligation | Required experiment or witness |
| --- | --- |
| Primitive identity | Registered `mlkem` group against pinned ACVP inputs, including key validation and implicit rejection. |
| Exact hybrid transcript | Registered `noise_xxhfs_handshake` group, then independently generated adapter vectors containing public test seeds, ordered prologue bytes, every message, transcript hash and both directional keys. |
| Hybrid dependence | Change only KEM randomness, then only DH randomness; each must change the expected keys. Wrong KEM ciphertext must fail authenticated confirmation despite implicit-rejection decapsulation returning a secret. |
| Policy binding | Wrong identity, role, epoch, target, version and suite; mutate each binding independently and require refusal before target dial. |
| Downgrade refusal | Hybrid-required peer presented with legacy or classical-only capability, stripped negotiation and replayed old handshake. No silent fallback. |
| Secret lifecycle | Deterministic test hooks verify wiping on successful split and every terminal path; separately review compiler, process-memory and crash-dump exposure. |
| Receiver lifecycle | Preserve registered `device_host_psk`, `device_host_runtime` and `mesh_tunnel` obligations where applicable; add adapter-specific pre-auth limits, cancellation, truncation and revocation tests. |
| Two-host acceptance | Real shell, exact-byte transfers, authenticated closure, successful wrapper result, no residual processes, explicit backup behavior and both-end revocation. Fail if any layer reports failure. |
| Efficiency | At least 10 samples per arm, a recorded interleaved schedule, matched hosts/SSH/options/payload and terminal gates. Retain failures and retries; start no next receiver during the competing arm. Measure setup, steady transfer, memory and attributable CPU separately. |
| Portability | Native Linux and macOS compile and focused acceptance on exact artifacts; unsupported lifecycle or isolation capability remains unavailable. |

A unit test cannot prove forward secrecy against all attackers. Review the
complete protocol and key lifecycle independently before acceptance. New
adapter vectors, integration results, performance costs and platform coverage
are **NOTRUN** in this design. Retain exact source/base, compiler, CPU, timestamps,
commands and receipt hashes when those experiments execute.

## Primary references

- [NIST FIPS 203](https://csrc.nist.gov/pubs/fips/203/final), including its
  published errata notice: ML-KEM requirements, not tunnel certification.
- [NIST ACVP ML-KEM specification](https://pages.nist.gov/ACVP/draft-celi-acvp-ml-kem.html):
  validation inputs and implicit-rejection cases; pin a revision when importing vectors.
- [Noise Protocol Framework, revision 34](https://noiseprotocol.org/noise.html):
  transcript, key derivation and application responsibilities. Repository
  XXhfs integration still needs its own exact profile and review.

