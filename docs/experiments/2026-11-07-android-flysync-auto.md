<!-- Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 -->

# Android automatic snapshot startup

Date: 2026-11-07. Host: AMD Ryzen 9 7950X3D; GCC 14.2.0.
Base source: `964231b627689da0b0c064ef622966dd4e85d31d`, subsequently
published as `cabd41cbb184d7b7de02af3ee9dccd3bca7b1d72` with identical tree
`0bd995c5661e7dea18428755bc3d9ec9e110d0d7`.

## Behavior

Android starts its node with `-flysync-auto`, `-nolegacyimport` and
`-nolegacyutxoimport`. Automatic mode uses the existing node boot gate:
empty chain state enters the snapshot wait, an existing non-island chain
continues ordinary synchronization, and seeded or installed islands retain
their existing lifecycle. Explicit `-flysync` retains precedence and its
refusal to replace an existing non-island chain.

Android disables imports from an inherited legacy-node directory while
retaining its own persisted block index. The automatic flag alone does not
change the generic node's legacy-import settings. Snapshot validation,
compiled checkpoint authority, canonical cutover authorization and wallet
replay requirements remain enforced.

A recorded hold must be an exact eight-byte BLOB. Missing records mean no
prior hold; malformed records, unreadable storage and a missing progress
store refuse the hold decision. Refusal does not repair or delete records.

## Verification

The focused registered groups `flysync_island` and
`consensus_state_install_runtime` passed cold: two executed groups, zero
failures, cached groups, skips, unobserved legs or load-flaky results, in
2.2 seconds. They cover the real argument parser, fresh and existing chain
selection, explicit-mode precedence, seeded restart, own-index reload,
malformed hold rejection and the existing guarded installer.

Focused log SHA256:
`0f2edea4875fa7e490af51e8af279c7e0dd9527d71114c3ce2632d9f6f5c6da0`.

After extracting the fresh-start scenario into a separate test helper,
`flysync_island` passed cold again: one group in 2.7 seconds, with zero
failures, cached groups, skips, unobserved legs or load-flaky results.
The complexity check passed at cap 15 with no baseline pins.

Final focused log SHA256:
`6c384fa327f9131cbb054ea3920e1e1dec509b5bb42205946404d2dcb9d86ef4`.

The complete Android host suite passed with the installed Android SDK
configured, including launch, direct queries, setup, wallet view, send-flow
fixtures and memory-wipe assertions. DEX verification used the SDK tool;
no missing-tool skip was enabled. These are isolated synthetic fixtures.

App-suite log SHA256:
`336a7b8b06e5d33872f05ced1126d663dde97cac5e11a8005e442c2e1ae68c75`.

Tested code delta SHA256:
`5c1013538c986bafbc07f09a44b18fe40137811c282da54c6a140d724bfa4c3e`.

The initial run exposed overlapping progress-store fixtures and a missing
store in an offer-filter fixture. Each now owns its required store. Android
fixtures now supply the required wallet-readiness metadata and valid app
files path. Wallet-screen send-test recipes include their Bech32 dependency.
The original display, wipe, setup and save-intent assertions remain intact.

## Remaining qualification

Actual-device automatic startup, inherited-HOME boot isolation, snapshot
transfer latency, memory use and foreground survival require device evidence.
Host timing does not establish phone latency. Production snapshot commitments
and provider availability require their separate source-bound verification.
An existing wallet requires a guarded migration and verified scan coverage;
a fresh-chain automatic-startup result does not establish that migration.

## Late offer recovery

A late verified bundle after the initial wait left a fresh node with a sparse
header index that could not satisfy the existing installation binding. Recovery
now requires an unchanged durable genesis, a verified compiled checkpoint
bundle and the complete authenticated header window. Reducer entry stays held
until a restart; the seed transaction rechecks the genesis proof. A bounded
persistent counter limits repeated recovery boots.

Focused synthetic database and admission tests passed 2/2. An opt-in test using
a public full-history archive and verified bundle passed the recovery window,
durable seed and restart request in 41.0 seconds, with no skips. It does not
exercise the complete Android boot or prove migration of an existing wallet.

A device recovery run reached the verified seed while a chain-integrity remedy
also scheduled a background restore. The remedy and its worker now defer while
the startup recovery hold is active. Focused condition and reducer tests passed
2/2, including a modeled queued worker with unchanged chain and database state.
The full device restart and interrupted-install recovery remain separate checks.
