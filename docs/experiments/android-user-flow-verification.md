<!-- Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 -->

# Android user-flow verification

This checklist tracks observed behavior, not an overall pass. Run each case in
an isolated simulator package with throwaway data. Record source and APK hashes,
device geometry, action, expected and observed state, elapsed time, and the
result. Never record recovery words, keys, invitation tokens or private wallet
content. Keep production screen protection enabled. A timeout, forced recovery,
missing observation or test-only injection is recorded explicitly.

| Journey | Normal and failure checks | Cancel, relaunch and timing oracle | Host | Simulator | Physical |
|---|---|---|---|---|---|
| Install and update | Install, open, then update while preserving app data; verify identity and launch. Test denied or failed install without claiming an update. | Relaunch preserves intended data and does not start duplicate nodes. Record elapsed startup. | PARTIAL: signer guard fixture | PARTIAL: separate preview install and update | PARTIAL: separate preview install and update; old test signer unavailable |
| First launch and create | Fresh no-wallet state offers Create and Restore. Create with a throwaway seed; verify words, three checks, save and open Funds. Refused authentication and failed save give a useful next action. | Back while words are held does not discard them; after interruption check state without fabricating success. Observe each bounded wait and recovery. | PARTIAL: setup and launch-failure fixtures | PARTIAL: test-only 3159 create, save and restart; production-policy software-key refusal | PENDING |
| Restore and backup | Restore throwaway words with and without a start height; malformed words and invalid nonblank height must be explained. Check restoration and backup flow without publishing secret text. | Cancel form or relaunch during work; preserve uncertainty and never claim an unread wallet is empty. Record node pause/write/restart duration. | PARTIAL: setup and height fixtures | PARTIAL: 3159 restore; 363 form and injected failures | PARTIAL: preview form validation and Back |
| Unlock, relock and background | Request private balance and authenticate; refused or cancelled authentication leaves it hidden. Check screen protection and automatic relock. | Background, pause, resume and recreate during authentication and after reveal; private content must not remain visible. Record lock completion. | PARTIAL: device-key and wallet privacy fixtures | PENDING | PENDING |
| Node start, sync, stop and offline | Start from stopped, observe connection and sync, then stop; test an offline or nonanswering node and a blocked stop during payment. | Reopen or restart while starting/stopping; status must reflect the process and its answer. Record stop/start bounds and any recovery. | PENDING | PARTIAL: test-only 3159 restart passed | PENDING |
| Funds refresh and errors | Read a valid summary including zero; inject empty, malformed and silent answers with and without sealed cache. Check loading, bounded retry, unknown and last-known labels without synthetic zero. | Repeat Retry while a request is busy, navigate away and reopen; stale replies must not replace current state. Record retry intervals. | PARTIAL: focused wallet fixtures | PARTIAL: 57d fixture checks compact unavailable layout and Retry | PENDING |
| Receive and amount | Open latest address, explicitly request a new one, copy it, set a valid amount and reject malformed or out-of-range amounts. Verify the QR payload. | Back or recreate without making a new key. Tap actual soft keyboard GO and verify it sets the amount; measure visibility and response. | PARTIAL: amount model fixtures | PARTIAL: synthetic f4a soft GO rejects zero and accepts 1.25 | PENDING |
| Send and make private | Use a throwaway plan: address, amount, fee and exact review; refuse malformed input and authentication failure. No real payment is authorized by this checklist. | Cancel before commit; after an unknown commit outcome show History rather than blind retry. Test relaunch and idempotency with isolated fixtures. Record bounded waits. | PARTIAL: wallet-send fixtures | PARTIAL: synthetic refusal, review, cancel and unknown outcome | PENDING |
| History, memo and privacy | Open history, page, detail and memo; distinguish empty from unreadable and hidden private data. | Back and relaunch clear private screen content; failed reads remain retryable without inventing entries. Record slow-read behavior. | PARTIAL: wallet-screen fixtures | PENDING | PENDING |
| QR permission and scan | Test permission allowed, denied and Settings; scan a public plain-text code, invalid payment and fleet code. Verify classified destination and no automatic payment. | Cancel/Back during acquisition and verification, then retry; late results must not reopen a dismissed screen. Record whether camera and worker stop or finish. | PARTIAL: classification and camera-access fixtures | PARTIAL: test-only 3159 plain QR; f4a postdecode cancel | PENDING |
| Fleet enrollment | With an isolated manager and throwaway identity, review operator key, join, return receipt, admit, import and connect. Refuse expired, invalid or wrong-operator inputs. | Cancel at review and during verification; no admission before authorization. After relaunch reconcile receipts and prove onion handshake separately from a scheduled dial. | PENDING | PARTIAL: synthetic review, refusal, receipt and Copy | PENDING |
| Navigation and accessibility | Exercise Home, Apps, Settings and layouts at 1080x2160, density 540 and font scale 1.5. Check action bounds, scrolling, focus, tap feedback and visible errors. | Back, rotation, recreation, rapid taps and keyboard dismissal preserve the correct screen and prevent duplicate actions. Record any hidden or unreachable control. | PENDING | PARTIAL: 57d compact unavailable and 5d84 focused review fixtures at these dimensions | PENDING |

PARTIAL names only the observed slice; it does not qualify the whole row.
The 3159 simulator used a test-only derivative and software KeyMint. It does
not establish hardware-backed custody or physical-device behavior. Fleet
handshake, real-wallet soft keyboard GO, and all payment execution remain unproved.

Existing bounds to check include up to 180 seconds for setup node stop/start,
15 minutes for the wallet write, and two one-second retries for initial answered
invalid summaries. The camera acquisition loop has no automatic deadline; Cancel
must remain available. A fleet preview has a five-second command limit after
spawn; an unreturned spawn is a separate observation, not a proven five-second
end-to-end bound. Record other limits from the exact candidate rather than
assuming these bounds apply to every operation.

<!-- claim: symbol-present funds_schedule_refresh apps/z23android/wallet_screens.c # bounded summary retry -->

Proposed UX acceptance target, UNMEASURED: a tap gives visible feedback within
one second, and navigation or Cancel remains responsive during background
work. Chain sync and camera aiming may continue indefinitely, but their stop or
cancel action must remain available. Verification waits require an explicit
timeout and a recovery action; a missing measurement is not a pass.

A postdecode-only simulator fixture on candidate `f4a6639` showed the checking
state, stayed on Home after Cancel and delayed release in two observations,
and opened the review on a subsequent scan. It did not exercise the camera
or a real fleet. At 1080x2160, density 540 and font scale 1.5, Join was visible
while the manager key was clipped below it after scrolling; the later candidate
below changes that layout. A host Receive lifecycle fixture also checks that a stale reply
from a closed visit cannot replace the reopened screen; device behavior remains
pending.

A separate `f4a6639` simulator fixture exercised the actual soft keyboard GO:
zero showed validation, 1.25 showed the requested amount, and leaving and
reopening Receive removed that prior amount. Address and node responses were
synthetic. This is not a real-wallet, new-address call-count, or hardware
custody result.

The `5d84a664` postdecode fixture placed the complete manager identity and
comparison instruction above Join, with Cancel visible in a fixed footer, at
the stated simulator geometry. Checking, Cancel and delayed release returned Home without a late review; a
subsequent scan reopened review; background and resume preserved review. A real Join, receipt,
operator identity, camera path and onion handshake were not tested by it.

A synthetic fleet backend on `5d84a664` exercised a refused Join, a successful
receipt with image and Copy control, and a later refusal without a stale
receipt or Copy control. This did not enroll a real machine or establish a
camera decode, receipt QR pixel decode or network connection.

The optional update signer guard passed throwaway host checks for missing,
invalid, matching and mismatching signer inputs and a verifier that prints a
matching certificate before failing. The existing phone test package signing
key remains unavailable; these checks do not recover it.

Focused host fixtures passed setup, device key, wallet send and camera access.
These checks cover isolated paths and do not qualify complete journeys.

The `be6a224c` postdecode simulator replay retained Checking, Cancel and late
result suppression, then showed the complete identity before Join and a fixed
Cancel at the stated geometry. Synthetic refusal, receipt and Copy, followed
by another refusal without stale Copy, also passed. Camera decode and real fleet
enrollment were outside this fixture. The replay report SHA-256 is
`7fc6d14c6cb158ea4bcc1c1033fab5edcee309f331598925eb1680c6170219ea`.

A separate production-policy preview was installed and updated without moving
wallet data from existing packages. On the physical device, its first launch
and Restore form, validation guidance and Back were observed with no wallet
creation or node process. A single cold-launch observation was 213 ms; this
is not a latency distribution or hardware wallet qualification.

A `363bcaac` simulator fixture used the real Restore screen with a synthetic
restore backend. An oversized 30-digit height remained visible after two
refused taps with no restore dispatch. Injected numeric-field getText and setText lookup failures each blocked repeated
dispatch until Back and a fresh form; blank then
dispatched height zero to the fixture. At the tested phone geometry, both
controls remained reachable with one scroll while the keyboard was open. This
does not establish a real restore, direct NewGlobalRef failure, or hardware custody.
The report SHA-256 is `5041e9e2eea5fe22af0abffca4fedd167adc7c9f3f60a1def1ab97f1ba9e235a`.

A synthetic Send fixture rejected malformed input, showed a review, cancelled
without a commit, and showed a history action after an unknown commit result
without automatic retry. It did not submit a real payment.
