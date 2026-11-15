<!-- Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 -->

# Android recent-block status

The Home headline identifies the existing tip-proximity verdict as recent-block
sync. Node details state that this check does not verify full history. The
change does not add a history-verification status or alter the node, wallet,
cooling or sync predicates.

On 2026-11-15 the Android host suite passed on base
`728fa8846c4d9c391989fca361af047c349f3c8c` with
`DEVBUILD_CLASS=normal devbuild --wait make -C apps/z23android test-host`.
The suite covers current, behind, unknown, paused, gentle and preview states.
Log SHA-256:
`70af98a21cd979dd01107003ece2b12950c96ce4c5f25a01faed7ed5330b707a`.
Phone layout and dynamic history-status disclosure remain unverified.
