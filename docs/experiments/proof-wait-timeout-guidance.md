<!-- Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 -->

# Proof wait timeout guidance

A pending proof wait reports a timeout and offers the exact read-only status
route, preserving the root, local commit and remote base. Missing proof state
retains its existing response, and oversized routes remain omitted.

<!-- claim: symbol-present zcl_dev_proof_wait_conclude tools/command/native_dev_proof_command.c # proof wait status mapping -->

On 2026-11-14, `DEVBUILD_CLASS=normal devbuild --wait make t-fast
ONLY=impact_composition` passed one group with no failures or skips. The
complexity and file-size checks also passed. The focused tests cover escaped
roots, exact identities, missing state and oversized next-action inputs.
