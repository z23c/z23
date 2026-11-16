<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Landing claim overlap

A linked worktree submitted a candidate touching a file already claimed by
another worktree. Claim acquisition refused overlap, but submit did not read
the claim ledger. The duplicate landing request was cancelled.

The submit guard compares the candidate's changed paths with the shared claim
ledger before qualification and again at enqueue. A live foreign overlap is
reported as `CLAIM_OVERLAP`; a matching existing queue row attaches before qualification,
without repeating its gates.
The final check holds the claim lock through queue insertion, acquiring the
queue lock second. The check is an enqueue snapshot: later claim acquisition
does not inspect the queue and is not prevented by an existing request.

The diagnostic baseline ran 58 scenarios: controls passed and the foreign
live-overlap scenario failed. Its diagnostic mode returned 3 by design; it is
not an acceptance receipt. Acceptance requires the focused normal-mode test
and the candidate gates.

The diagnostic log SHA-256 is
`20494975f75d7227e925a1d36ba65a0138f4563c811a40c662db074374783dde`.

The focused normal-mode run used
`make -j2 t-fast-exact ONLY=dev_land_shard_03 T_FAST_EXACT_ARGS=--no-cache`.
It ran 58 scenarios with zero failures and zero skips in 113.8 seconds. The
log SHA-256 is
`294fb1925a44818c2a1abab581efa91c9de7a06d76bc9d7bde9403b2a92ecf6f`.
At that point the native candidate and full gates had not run. Windows runtime verification
was not run.

The subsequent candidate `90484f466c47bd5166a0c778b033368c0f312683` full
verification selected 1,592 groups and reported two final failures, 17
self-skips and two load-flaky groups. The landing shard failure reported 14
Git launches where its existing assertion requires four. The consolidated
repair changes the source after that candidate; the earlier focused pass does
not verify the repaired bytes. Focused checks and full gates for the repair
remain pending.

The consolidated repair focused run selected both landing shards and the
command registry catalog. All three passed with zero skips in 178.2 seconds;
shard 02 failed its first attempt in the depfile timeout case and passed when
retried alone. Its existing marker assertion measured four Git launches. The
log SHA-256 is
`87f5e598d26d6de20373672c09005fb3a21476a8ae9b4838feb6f3daafe9b952`.
The subsequent Git compatibility repair changes the source again and requires
new verification.

The Git compatibility repair was checked with
`make -j2 t-fast-exact ONLY=dev_land_shard_02,dev_land_shard_03 T_FAST_EXACT_ARGS=--no-cache`.
Both groups passed with zero skips in 296.5 seconds. Shard 03 first failed its
concurrent-submit child-exit assertion and passed when retried alone; the
runner reported one load-flaky group. The cause of the first failure was not
established. The four-launch assertion and linked, nested and legacy Git
fixtures passed. The log SHA-256 is
`6d8d1069648a3a0f56dbf1cfc68dcc24f0ccdc02de9fa2dd646f0ed17746de32`.

Submit retries a confirmed claim-lock conflict against a five-second deadline,
using bounded nonblocking attempts. An unreadable lock or expired wait still
refuses the submission. Claim acquisition retains its nonblocking policy.
This repair changes the source after the focused results above and requires
new verification.

The bounded-lock repair was checked with
`make -j2 t-fast-exact ONLY=dev_land_shard_02,dev_land_shard_03 T_FAST_EXACT_ARGS=--no-cache`.
Both groups passed with zero skips in 1053.8 seconds. Shard 02 first failed
its depfile timeout case, and shard 03 first failed its cancellation-at-lint
completion assertion; both passed when retried alone. The runner reported two
load-flaky groups. The causes of the first failures were not established.
The four-launch, concurrent submit, linked and nested worktree, legacy Git,
and bounded claim-lock contention cases passed. The log SHA-256 is
`3809308f23ce1cfbf34e86097bfece14b183a706d0da3dfea184548ec95a9bf8`.

Integrated candidate `e77de20e1ca5b50768924d4c64995a78d694fd45` selected
108 groups from the fresh source closure. All passed with zero skips; five
passed on isolated retry after first-attempt failures. Full verification failed:
capability closure found an undeclared clock capability in the claim module,
and the real-clock deadline gate found three fixed-iteration polling sleeps in
the late-claim fixture. The full verification log SHA-256 is
`1c82078bf515c193c4c190ca86663b21c323886d4eb9767625b9a7e033b93009`.

The repair declares the clock capability and replaces fixture coordination
polling with FIFO handshakes. A bounded real-clock wait remains solely for
kernel child cleanup. The repaired fixture passed all 58 shard 03 scenarios,
with zero skips and no retries, in 89.7 seconds using
`make -j2 t-fast-exact ONLY=dev_land_shard_03 T_FAST_EXACT_ARGS=--no-cache`.
Its log SHA-256 is
`c281830ca6eb81c801433134e3ed033bfddbde336439a7ea01735f3c46796e76`.
The full real-clock deadline gate and complexity check passed. Capability
closure and native candidate gates remain pending. Windows runtime verification
was not run.
