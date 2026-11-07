<!-- Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 -->
# Test group selector extra coverage

The selector contract checks that legacy plan expansion includes matching
non-shard groups as well as all declared shards. A full-suite attempt at
`30fd3338a8ccf35a02f002bbb5486d0161e18f8e` failed the expected-count
assertion after the package prepare budget group joined that family.

The fixture names the additional group explicitly while retaining the exact
count, uniqueness, and shard-membership assertions. Focused validation passed:
`make t-fast ONLY=test_group_selector` ran one group with zero failures
and zero skips on 2026-11-07.

<!-- claim: symbol-present test_umbrella_groups tests/harness/src/test_test_group_selector.c # selector umbrella contracts -->
