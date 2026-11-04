<!-- Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 -->

# Receive lifecycle test

The wallet screen fixture closes and reopens Receive while a new-address reply is in flight, before that reply returns. The reopened screen keeps its independently read address and does not show the old request amount or late address. Removing the reply epoch guard made this focused case fail; restoring the source made `make -C apps/z23android test-wallet` pass. This synchronous fixture checks stale-result isolation, not asynchronous memory cleansing.

