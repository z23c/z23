<!-- Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 -->

# Android sync recovery

Date: 2026-10-28. Source base: `e4d4a6e9c900f3be2aaeaddb909025373b8410ba`,
with the runtime and test changes described below. Android target: arm64,
API 35, Android NDK r30. The resulting node binary's SHA-256 was
`7a53fa58698b49e4d953e58fdcd3fcd68769583756c5fd3f3948c5a80afd780c`.

The observed node stopped advancing while a validation stage held the progress
store lock and waited for the chain mutex. Concurrent intake or header
admission held the chain mutex and waited for the progress store. The intake
and header admission paths now release the chain mutex when the progress
store is busy. The contextual validation gate returns idle when the chain
mutex is busy and retries the same validation on a later step.
<!-- claim: symbol-present header_admit_lock_pair engine/jobs/src/header_admit_stage.c # nonblocking progress admission -->
<!-- claim: symbol-present script_validate_contextual_gate engine/jobs/src/script_validate_contextual.c # contextual validation gate -->

An unclean shutdown left a non-empty SQLite WAL that could contain committed
frames. Normal boot's
producer-evidence preflight requires a stable WAL-aware copy and previously
used a fixed temporary directory unavailable to the Android app. The preflight
now uses the platform temporary-directory facility, retains source-identity
checks, and refuses a temporary root that aliases the node data directory.
<!-- claim: symbol-present platform_temp_directory_create engine/composition/src/boot_mint_anchor_preflight.c # private temporary snapshot -->

An optional catchup drain budget limits elapsed time between complete stage
steps. It is active only when catchup is active and the environment setting is
present. A single step can exceed the budget; its validation and transaction
are not interrupted. Default behavior is unchanged when the setting is absent.
<!-- claim: symbol-present catchup_drain_budget_due engine/jobs/src/catchup_cadence.c # bounded catchup drain -->

## Focused checks

The following checks ran through the installed build admission rail on the
working candidate. The reducer intake and WAL preflight checks preceded the
later header-admission and elapsed-budget edits; their applicability to a
changed candidate requires the final landing gates.

| Check | Result |
| --- | --- |
| `ZCL_STRESS_TESTS=1 make -j4 t-fast-exact ONLY=reducer_block_ingest_gate` | 1 group passed, 0 skipped |
| `make -j4 t-fast-exact ONLY=mint_anchor_preflight` | 1 group passed, 0 skipped |
| `make -j4 t-fast-exact ONLY=script_validate_contextual_gate` | 1 group passed, 0 skipped |
| `make -j4 t-fast-exact ONLY=catchup_cadence,proof_validate_stage,script_validate_stage,utxo_apply_stage,body_persist_stage,tip_finalize_stage` | 6 groups passed, 0 skipped |
| `make -j4 t-fast-exact ONLY=header_admit_stage,tip_finalize_stage,catchup_cadence` | 3 groups passed, 0 skipped |
| `make -j4 ZCL_TARGET=android-arm64 z23` | Build and Android C23 ELF audit passed |

A non-author source review covered the changes. These checks do not establish
full-chain synchronization or a throughput improvement. The Android node
continued syncing after the earlier lock fix; the final candidate requires
separate on-device verification and exact-candidate landing proof.

The final focused union ran all ten groups listed above with
`ZCL_STRESS_TESTS=1`: 10 passed, 0 failed, 0 skipped. This verifies the combined
runtime changes; it does not replace the landing gates or on-device sync proof.

Set `ZCL_CATCHUP_DRAIN_BUDGET_MS=100` to yield catchup drains between completed
steps after 100 milliseconds. The accepted range is 1–60000 milliseconds.
An absent or invalid value leaves the existing drain behavior unchanged.

## GCC 16 qualification repairs

The landing build exposed unused volatile counters in two nonterminating
isolation fixtures. Constant infinite loops preserve their timeout behavior
without unused writes. It also exposed a database setup assertion that
incremented a pointer instead of the caller's failure count; the helper now
accumulates and returns the actual failures through that pointer.

On 2026-10-28, `make -j4 t-fast-exact
ONLY=reflex_runner,test_parity_lockin_turnstile ZCL_TEST_WERROR=1` passed both
groups with zero failures and zero skips under GCC 16. A non-author reviewed
both repairs. The full landing proof remains a separate requirement.

The receiver subsequently identified an unregistered drain-budget flag and a
bare temporary-directory fixture. Registering the flag and using the harness
temporary-directory helper passed `check-flag-registry`,
`check-no-bare-tmp-fixture`, and the exact `mint_anchor_preflight` group
(one passed, zero skipped), with non-author review.

## Mempool and finalization lock ordering

A later Pixel stall was a storage/main-state lock cycle: tip finalization held
the progress-store mutex while waiting for `cs_main`; transaction admission
held `cs_main` while its shielded-state lookup waited for the progress store.
Peer message processing stopped with the admission thread.

The boot-installed immutable backend guard now precedes `cs_main` for both
the tip snapshot and input-dependent admission. A busy main-state lock releases
the backend guard before retrying. Proof checks remain outside the guard;
input checks and insertion retain their atomic main-state boundary. Callers
must not already hold `cs_main` without the backend guard.

The two-thread regression exercises both guarded sections with the real
progress-store mutex and requires successful admission after release. Reversing
the lock order fails the regression; restoring the fix passes. The focused
`accept_to_mempool` and `tip_finalize_stage` groups passed with zero skips.
Independent review covered the guard, boot initialization, and failure exits.

The regression uses condition-variable handshakes rather than elapsed-time
polling. After that refactor, `accept_to_mempool`, `tip_finalize_stage`, and
`consensus_parity` passed together (three groups, zero skips). A controlled
main-lock-first mutation failed both guard-entry assertions; the restored
sealed source passed. The seal, mirror, complexity, file-size, registration,
and test-clock gates passed without raising baselines.

Full lint is not accepted: GCC 16.2 MinGW found eight existing Windows API
declaration failures outside this change. The first local run also lacked a
default compiler alias and linker required by two tooling checks. Publication
and device deployment remain pending the required full qualification.

## Bounded coin-set authority lookup

A near-tip thread sample found the message handler holding the progress-store
mutex while `coins_kv_is_proven_authority` counted the entire coin table. The
predicate requires only a nonempty set. Its SQLite path now requests one row;
the applied-height and migration-marker checks, RAM-overlay behavior, locking,
and refusal on read errors remain unchanged.

An 8,193-coin fixture measured SQLite cache hits plus misses for the actual
authority call: 121 page accesses with the old count predicate and 10 with the
bounded lookup. The standalone full count used 115 accesses. These are page
access measurements, not elapsed-time or phone-throughput claims. Measurement
date: 2026-10-28; compiler: GCC 16.2.1. The regression fails with the old
predicate and passes after restoring the fix. Empty sets, read errors, and
overlay tombstones/additions passed; overlay coverage ran in a fresh process
with `ZCL_FOLD_INRAM=1`.

The combined focused run passed four groups with zero skips:
`coins_kv_sovereign_gate`, `accept_to_mempool`, `tip_finalize_stage`, and
`consensus_parity`. Independent review covered both changes. A full-suite
attempt compiled the strict runner but was cancelled during fixture preparation
to include the bounded lookup; it produced no full-suite test verdict.

The subsequent full lint run passed the capability, seal, complexity,
registration, test-clock, compiler-environment, and standalone-tool checks.
It reported the same eight Windows declaration failures and one missing
kernel-store SQL annotation in the new helper. The annotation was corrected
and its focused gate passed. Full release qualification remains incomplete.
