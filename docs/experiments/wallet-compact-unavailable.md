<!-- Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 -->

# Compact unavailable wallet

When an answered wallet summary fails with no displayable or cached balance,
Funds shows one unknown balance and a retry action rather than separate unknown
amount categories. The retry requests the summary again without inventing an
amount. Cached balances, known values, scan notices and silent-node guidance
retain their existing handling.

<!-- claim: symbol-present funds_unavailable_items apps/z23android/wallet_screens.c # compact unavailable wallet -->

A focused fixture failed against the prior screen because no retry button was
shown. After the change, the wallet screen tests passed with the retry, privacy,
amount and scan-notice assertions enabled. Physical layout remains to be checked.
