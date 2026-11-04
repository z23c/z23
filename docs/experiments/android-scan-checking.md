<!-- Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 -->

# Fleet scan checking state

After a fleet code is decoded, Scan shows `Code scanned. Checking…` while its
preview runs. Cancel returns from Scan without waiting for that preview. A
cancelled current or just-completed scan discards its own late fleet review and result; it does
not cancel a native command already in progress. The next action resets the
scan state.

<!-- claim: symbol-present zapp_controller_cancel_scan apps/z23android/controller.c # cancel active scan -->

On 2026-11-04 UTC, the existing host `test-scan` classification suite passed.
That suite does not exercise the checking state or Android navigation.

A simulator-only postdecode fixture held fleet preview until released. On the
baseline, Scan retained aiming guidance while held. On candidate `f4a6639`,
Scan showed the checking text; Cancel followed by release stayed on Home with
no late review in two observations. A second scan followed by release opened
the fixture review. This injected a public synthetic payload and preview; it
does not prove camera decoding or a real fleet connection. At 1080x2160,
density 540 and font scale 1.5, Join was visible while the manager key was
clipped below it after scrolling. The later candidate below changes that layout.

A later postdecode-only simulator fixture on candidate `5d84a664` at the same
geometry placed the complete fixture name, key and comparison instruction at
vertical bounds 220–1084, before Join at 1098–1264. Cancel remained visible at
1953–2119; checking, Cancel and delayed release returned Home without a late
review, and a subsequent scan reopened the review. Background
and resume returned to that review. The fixture did not perform a real Join,
prove camera decoding, or verify the receipt path. The fixture APK SHA-256 was
`e30dfa2e8d3a02543d2d8acae3918425742a0a383d393b2cd9dd77518d259f5d`.

A separate synthetic backend exercised Join refusal, success and a later
refusal. The first refusal showed its reason and Back returned Home. Success
showed a saved receipt image and Copy code; copying showed the one-minute
clipboard message. The later refusal showed no receipt or Copy control. The
fixture used public fake data and did not perform a real fleet join, camera
scan or QR pixel decode.
