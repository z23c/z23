<!-- Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 -->

# Empty initial wallet summary

An empty successful summary is malformed. With no cached balance, it follows
the same two one-second retries as other answered malformed summaries. Three
empty answers show the existing failure; a valid zero is shown only after a
valid summary. Silent failures retain their existing behavior.

<!-- claim: symbol-present defer_initial_summary apps/z23android/wallet_screens.c # bounded initial summary retries -->

On 2026-11-04, the focused host wallet test failed at the new loading
assertion before the change and passed after it. Both synchronous and
asynchronous empty-to-zero paths were checked; the synchronous fixture also
checks exhaustion. This does not establish the cause of a phone observation.
