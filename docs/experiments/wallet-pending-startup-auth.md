<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Pending wallet startup authentication

An encrypted wallet can require historical replay before services start. The
normal interactive unlock command is unavailable during that interval.

The Android app passes one endpoint of a private inherited local socket to
the node. A pending locked wallet requests a bounded versioned frame over the
socket. The node checks the socket and peer, unlocks through the existing
wallet lock implementation, arms the existing 3,600-second maximum timer,
and wipes the received secret. Cancellation, a malformed frame, an incorrect
secret, a closed socket, or an expired deadline leaves recovery pending.
The wallet is explicitly locked before normal services start.

Before replay and again inside its final publication transaction, the node
checks the durable Sapling keyset against unlocked memory and verifies derived
viewing identities. Publication must be admitted while the wallet is
authenticated and before the monotonic deadline under the wallet transition
lock. An admitted database commit may complete after that deadline.

On the pre-integration candidate, focused node tests passed three groups with
zero skips; the affected boot group also passed after unsupported-platform
descriptor cleanup. Android host authentication, wallet and operations tests
and an Android native build passed. These results do not establish full replay
or device startup: complete encrypted-wallet replay, memory use, cancellation
and startup on a phone remain to be measured on the integrated candidate.

A synthetic encrypted 20-key historical replay stopped at height 517448 when
replay reported a busy resource; its wallet remained pending. Startup now retries
only typed contention with a bounded, cancellable wait and rechecks the chain,
wallet identity and pending binding before accepting progress. A partially
completed chunk resumes at its first incomplete block. A completed step whose
final check is contended waits for revalidation before advancing.

Replay also reuses each output's decoded public ephemeral point across wallet
keys. Real encrypted-note fixtures cover empty, single and 20-key sets, sparse
keys, malformed points, and preserved note state. Focused replay and boot tests
passed 2/2 with zero skips (log SHA-256
`0a36af788f0468946fc1122f0d057f4828b33e2ddf3550e8aecd95a83db67f5a`);
the complexity gate passed (log SHA-256
`8c5c281b7b6079c076cb9af49a9fcaef290c4a432bcaf29cdfe230b7baa70412`).
The replay changes were reviewed independently. A separate synthetic
low-order point comparison passed; it is not a phone performance measurement.
A full encrypted synthetic replay reached wallet and node readiness with keys
preserved; interruption recovery and device behavior remain to be measured.

## Cancellation and continuation

An isolated Pixel run of the earlier build did not stop within 30 seconds
while loading the public block index and required forced termination. The
loader now observes shutdown during ancestry and row loading and discards
partial state. In a subsequent isolated Pixel component test, termination
completed in 1.05 seconds without forced termination and the synthetic keys
remained unchanged. This does not establish Android UI behavior.

Closing the received-app progress window retains the completed operation and
stops later build, open, and Keep steps. The release deployment target selects
its node-only build explicitly. Focused receive, receive UI, and block-index
loader tests passed all three groups with no skips; the complexity gate passed.
