<!-- Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 -->

# Android setup recovery

A setup worker can fail to start before it changes wallet state. A retry of an
uncertain write now preserves that uncertainty and the held recovery words; a
failed confirmation or marker worker returns to marker retry without showing
words again. Concurrent primary setup jobs are refused. A typed restore height
must be a positive integer; the separate unknown-height action retains its
existing meaning. Invalid input stays on the form.

The focused `test-setup` host fixture passed with rejected and accepted launch
callbacks, duplicate launch refusal, confirmed-word cleanup, and height bounds
including `INT64_MAX`. Strict Android ARM64 C23 syntax checks passed for the UI.
These fixtures do not establish physical-device behavior.
