<!-- Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 -->

# Retained history verification

A verified capability holds the private history root and its cooperating
exclusive lease while a consumer uses the archive. The consumer must keep the
namespace and bytes immutable; the lease does not prevent same-user writes.
Cancellation is checked during inventory and hashing. A cancelled acquisition
releases the transferred handles without removing the archive.

On the candidate based on `b7295f7d3a2eabd4793a91e799343e5adf63d9aa`,
`make t-fast-exact ONLY=wallet_history_capability,wallet_history_export` passed
both groups with no skips. After adding verified root and path association,
`make t-fast ONLY=wallet_history_capability` passed with no skips. Fixtures use
isolated temporary directories. These tests do not establish chain validity or
protection against a writer that ignores the lease.
