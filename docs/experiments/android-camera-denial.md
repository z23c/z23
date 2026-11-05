<!-- Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 -->
# Camera denial recovery

The camera reports permission refusal separately from camera errors. A live scan
can show a choice to retry, paste a code or return, while a canceled scan cannot
reopen it. The host scan and camera-access tests passed, including a refused
busy request followed by an accepted request and stale-ticket cancellation.
The Android ARM64 application compiled; complexity and hardening checks passed.

On Android 15, the previously released application was denied camera permission
twice, then opened Settings. After allowing camera access and pressing Back
through Settings, Scan reopened; the camera became active, Cancel closed it,
and a later Scan and Back also closed it. This did not test QR decoding or
measure exact latency.

An isolated API 36 simulator with ARM translation exercised the application at
1080x2160, density 540 and font scale 1.5. The first denial showed Retry,
Paste and Back; Retry reopened the permission dialog, and a second denial showed
Settings, Paste and Back. Paste opened the protected editor and Cancel returned
Home. In landscape, Settings, Paste and Back were visible and Back returned
Home. A controlled synthetic late denial after Cancel did not reopen Scan; the
worker marked its denial and a new scan was accepted. This synthetic result did
not exercise an operating-system permission response.

A separate simulator fixture held a synthetic node-start request while Settings
was open. After a test-only camera grant and activity replacement, Scan showed
Retry disabled and Back enabled. When the fixture refused and completed, Retry
became enabled; tapping it reached a synthetic fleet QR review, and Cancel
returned Home. In another pass, Back from the fallback followed by activity
replacement left Home visible in the same process. The grant and node-start
outcome were synthetic. The lifecycle probe used file I/O and may affect timing;
these observations do not establish process-restart or physical Settings behavior.
