<!-- Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 -->

# Fleet scan checking state

After a fleet code is decoded, Scan shows `Code scanned. Checking…` while its
preview runs. Cancel returns from Scan without waiting for that preview. A
cancelled active scan discards its own late fleet review and result; it does
not cancel a native command already in progress. The next action resets the
scan state.

<!-- claim: symbol-present zapp_controller_cancel_scan apps/z23android/controller.c # cancel active scan -->

On 2026-11-04 UTC, the existing host `test-scan` classification suite passed.
That suite does not exercise the new checking state or Android navigation.
Delayed-preview simulator verification remains required.
