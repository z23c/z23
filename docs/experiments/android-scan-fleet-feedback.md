<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Android scan and fleet feedback
Wallet and Scan lead the primary actions, before installed apps, in both home
layouts. Assistant and the existing app launchers remain available.


The scanner keeps looking until it reads a QR code, the owner cancels, the
activity stops it, or the camera fails. It no longer dismisses the screen
because 30 seconds passed. A visible hint names the action, and Cancel stays
available. Device errors and owner cancellation have distinct outcomes.

Fleet preview verifies the invitation signature and expiry without creating
keys, pinning an operator or joining. The app shows the phone name and complete
manager public key before enabling Join. The manager key must still be compared
with the issuing computer; a self-signature does not establish that trust.
Joining validates the invitation again.

The typed join reply is read after command warnings. The app saves its return
code privately and reloads it after restart, with a QR code and Copy code action.
It reports a failed save explicitly while retaining the new code in memory.
An incomplete reply preserves the prior receipt. Neither preview nor a signed
return code is presented as proof that the manager admitted the phone.

## Evidence

On 2026-11-04, `make -C apps/z23android test native` passed at
`56b6ad1ac684a74e3760e28e6d32f4e7ebf78e53`, with strict C23 host warnings and
Android NDK r30 arm64 compilation. Scan fixtures exercise success after 400
empty polls and cancellation at 450 polls. Those are simulated polls, not a
phone latency measurement. The QR sanitizer fixture passed 2000 iterations,
including all 489 pristine-frame controls.

The same source passed `make t-fast-exact ONLY=test_fleet_enrol`: one group ran
without skips or cached verdicts in 2.4 seconds. Preview fixtures cover valid,
forged, malformed and expired invitations, and no writes to absent or existing
fleet state. App fixtures cover receipt reload, refused replacement preserving
the old file, and malformed, oversized, symbolic-link and FIFO input.

The complexity gate passed, and independent source review accepted the flow.
Hardware scanning, physical taps, app restart and complete fleet admission
still require device evidence.

The home ordering change passed `make -C apps/z23android test-host native`

after independent source review. Physical layout remains part of device acceptance.

## Balance refresh presentation

The owner reported a brief unavailable balance before the amount appeared.
The exact reply responsible was not captured. Funds already waits for its first
summary; it now reserves the same balance row for `Loading…` and replaces it
only with a reported amount. A failed refresh retains an earlier amount only
when it was visible while locked or the wallet is unencrypted. It is labelled
last known, accompanied by the refresh failure and any existing scan warning,
and cannot be used to start Send or Make private. A later valid reply restores
the live display. An unlocked encrypted balance is not retained after failure.

On 2026-11-04, the host `make -C apps/z23android test-wallet` and
`make check-cyclomatic-complexity` passed under `DEVBUILD_CLASS=light`.
Fixtures cover initial loading to a reported zero, refresh failure and recovery,
locked and unlocked privacy, and an incomplete scan warning. An initial test
compile failed on a missing declaration; a subsequent privacy test exposed a
temporary view that was not wiped. Both were repaired before the passing run.
The updated APK has not been tested on a physical device.

## Sealed fleet machine review

A sealed machine code is verified against the recorded operator before its
name and manager key are shown. Connect imports the reviewed record and then
requests an outbound onion peer. The request reports a scheduled connection,
not a completed handshake or admission. Live connected status remains the
node fleet status result. Invitation and payment codes retain their own paths.

<!-- claim: symbol-present fleet_roster_preview tools/dev/fleet_enrol_store.c # advisory signed machine validation -->
<!-- claim: symbol-present zapp_fleet_connect_run apps/z23android/operations.c # import before scheduling a connection -->

Validation on 2026-11-04 UTC used GCC 14.2.0 and Clang 20.1.8 on an AMD
Ryzen 9 7950X3D, plus Android NDK r30 Clang 21.0.0 for the ARM64 app.
The full Android host suite and ARM64 native app build passed. The exact
`test_fleet_enrol`, `test_command_input_bounds`, and `test_native_api_contract`
groups passed: three executed, none cached, failed, skipped, or retried.
The command help budget and cyclomatic complexity checks passed without
raising limits or adding baseline exceptions. These checks cover machine
preview, read-only state handling, revocation revalidation, and refusal to
dial after a failed import. Physical camera decoding, edited-input timing,
activity recreation, and a live fleet handshake remain device acceptance
checks; host results do not establish them.

The landing KPI check exposed repeated roster-walk setup introduced by machine
preview. A shared query now supplies the same filters, visitor, scan output,
and read mode to the existing walk. The duplicate-candidate count returned
from 1849 to its committed floor of 1848 without changing the floor. On the
same toolchain, the KPI and complexity checks passed, followed by exact
`test_fleet_enrol` and `test_native_api_contract`: two groups executed, none
cached, failed, skipped, or retried. The complete admitted check took 267.51
seconds; maximum process RSS was 1298724 KiB, not aggregate job memory.

The expired-invitation fixture now uses the suite's fixed historical timestamp
instead of subtracting from the current clock inside an assertion. Its required
`FLEET_INVITE_EXPIRED` result is unchanged. The wall-clock assertion gate and
exact `test_fleet_enrol` group passed after this change, with one group executed
and no cached verdict, failure, skip, or retry.

An API 36 x86_64 emulator with ARM translation exercised the unchanged app
subtree using an emulator-only software-KeyMint fixture. Fresh setup displayed
24 words and accepted the three correct checks, but saving remained pending
with a child still in the app runtime before command execution. Confirmation,
Receive, and a final timeout were not established. A separate fresh test user
kept Scan open for 62 seconds and returned Home on Cancel; camera-service
connect and disconnect were also observed. Enter on invalid fleet text produced
a verification refusal without Connect. These observations do not prove QR
decoding, edited-input timing, hardware security, or physical-device behavior.

## Initial balance retry and read-only preview coverage

Without a previously validated summary or sealed balance, an answered but
invalid first summary keeps the balance row at `Loading…`. The app retries
twice at one-second intervals; a third invalid answer shows the existing
failure state. A verified summary supplies the amount, including zero.
A node that does not answer still shows its node availability state. A retry
already in flight or a reveal-triggered summary does not start a second read.

<!-- claim: symbol-present defer_initial_summary apps/z23android/wallet_screens.c # bounded initial summary retry -->
<!-- claim: symbol-present funds_schedule_refresh apps/z23android/wallet_screens.c # at most one summary per tick -->

The new loading assertion failed against the previous implementation. After
the fix, deterministic clock fixtures cover recovery to a reported zero,
persistent failure, a silent node followed by an invalid answer, a busy
asynchronous read, and a simultaneous reveal transition. Existing privacy,
stale-balance, scan-warning, and unknown-amount assertions remain in place.

On 2026-11-04 UTC, GCC 14.2.0 on an AMD Ryzen 9 7950X3D passed
`make -C apps/z23android test-wallet` and the complexity gate after the retry
decision was extracted into a helper. The complete admitted run took 70.25
seconds with maximum process RSS 67604 KiB; this is not aggregate job memory.

A full candidate proof exposed missing registry coverage for `fleet.preview`
and an incomplete command example in the Android README. The example now describes
the sealed code rather than suggesting a command invocation. The read-only
fixture signs a machine record in isolated state and verifies that preview
reaches the absent-anchor refusal, then checks absent, populated, foreign,
invalid, and WAL-backed datadirs. The isolation and wall-clock gates passed,
followed by exact `test_read_leaf_no_datadir_write` and `test_fleet_enrol`:
two groups ran with no cached verdict, failure, skip, or retry. Test wall time
was 75.4 seconds; the complete admitted check took 243.67 seconds with maximum
process RSS 1291504 KiB. The changed app has not yet been installed on a phone.

<!-- claim: symbol-present rlw_fleet_fixture tests/harness/src/test_read_leaf_no_datadir_write.c # signed preview no-write fixture -->

The combined candidate also passed the ARM64 native app build, KPI floor,
complexity, bound documentation claims, Markdown links, and inline path checks.
That admitted run took 172.90 seconds with maximum process RSS 698460 KiB.

## Direct scan review and explicit wallet check

Scanned invitations with an explicit join prefix retain that prefix through review,
so they go directly to invitation verification instead of trying machine
verification first. The parser and signature checks are unchanged. The code
is kept out of displayed scan text. This removes one request on that path;
device latency has not been measured.

After a failed wallet save, the existing check action is labelled
`Check wallet`. Its accompanying text tells the owner to retain a copy of
the recovery words and explains that checking closes the displayed words.
The existing wallet check and retry behavior is unchanged.

<!-- claim: symbol-present scan_payload apps/z23android/controller.c # preserve explicit invitation through review -->
<!-- claim: symbol-present wsu_give_up_write apps/z23android/wallet_setup.c # failed save returns to checking -->

On 2026-11-04 UTC, the scan and wallet-setup host suites and the ARM64 native
app build passed after these changes. The admitted run took 46.04 seconds
with maximum process RSS 77940 KiB. The installed phone app was inspected
separately: Wallet opened to Balance, Receive, Send, and History. That older
APK does not qualify the new source or establish the initial-frame timing.

## Dismiss scan outcome

A Home scan outcome has a Dismiss button. Dismiss clears that outcome without
changing the node notice or wallet state. The wallet wait message is shorter
while retaining the distinction between a running node and a stopped node.

<!-- claim: symbol-present set_outcome apps/z23android/shell.c # controls Home scan outcome visibility -->
<!-- claim: symbol-present silent_node_items apps/z23android/wallet_screens.c # distinguishes a running node -->

On 2026-11-04 UTC, the installed APK built from commit `209db27d0179`
retained the existing wallet. With the node stopped, Wallet showed its last
known balance and age; after Start it retained that amount with updating and
waiting status. Initial-frame flicker was not captured. The prior APK Stop
was observed to finish within 67 seconds; this is an upper bound for that
observation, not a measurement of the new APK shutdown latency.

On the same installed APK, an invalid fleet code displayed duplicate error
messages. The controller change keeps one error message; that change has not
been measured on the device. A Stop tap at 06:22:18 UTC showed Stopping at
06:22:37, and polling observed the node process gone at 06:22:50, about
32 seconds after the tap, without forced termination.

A warm phone node stopped between 128 and 129 seconds after the recorded Stop
request; a later restart stopped between 20 and 21 seconds. The runs had
different durations and conditions, and do not establish the cause. Android
logcat now reports only allowlisted completed shutdown stage names and decimal
durations, without forwarding the source line or its suffix. This does not
identify a stage that has not yet completed. The focused nodelog privacy and
filter tests and the complexity gate passed; no device result for the new
telemetry is claimed here.

On the landed Android build, a short-run Stop took between 40 and 41 seconds;
the completed fast-restart-persist stage accounted for 33,085 ms. The stage
contains projection catch-up, flat-file save, coverage binding and a passive
checkpoint, so the stage measurement alone does not identify the slow substep.
The Android log filter now reconstructs only those four fixed substep names and
their validated durations, plus the flat-save mode and byte count. Focused
nodelog tests cover producer-shaped lines and reject malformed or extra fields;
the complexity and hardening checks passed. Device measurements of these
substeps remain pending.

A later warm Stop took between 126 and 127 seconds. The preceding stage timings
completed, but the fast-restart completion line was not observed. Its 120-second
watchdog can exit after the durability point, so elapsed time alone cannot
identify the exit path. Android now emits fixed, reconstructed messages for the
fast-restart deadline and the watchdog forced-after-durable decision separately.
The focused nodelog tests and complexity and hardening checks passed; a device
observation of these messages remains pending.
A missing watchdog message does not rule out the watchdog path: process exit
may occur before the app drains the node console pipe.

On the landed ef115 Android build, one Stop reported projection catch-up at
16,585 ms, incremental flat save at 1,863 ms with 981,183 bytes rewritten,
flat bind at 29,787 ms and passive checkpoint at 1 ms. The completed
fast-restart-persist stage took 48,236 ms. The flat-save path alone does not
identify which coverage proof the bind used. The Android filter now also
reconstructs the producer’s validated bind row, checked-row, throughput and
thread counters. Focused nodelog tests cover the largest accepted counters and
malformed or overflowing inputs; complexity and hardening checks passed.
Device measurements of these counters remain pending.
