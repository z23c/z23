<!-- Copyright 2026 Rhett Creighton - Apache License 2.0 -->

# Main release-readiness repair — 2026-08-27

## Intention

Qualify the code that reached `origin/main` during the four-node rollout and
remove defects that would make the release evidence or deployment transaction
unreliable.

## Observations

- The AArch64 HexStr oracle did not exercise a short output buffer: its three
  generated sizes were exact-fit or larger, and truncating cases were skipped.
- Three 40 MB test wallets moved to the heap without checking allocation.
- A post-join clock read could label a successful Linux timed join as late if
  the caller was scheduled after its deadline.
- `tools/ship.sh` removed only the legacy `zclassic23` symlink, leaving the
  canonical `z23` target available for stale reuse after a header-only edit.
- The native macOS runbook described platform seams as absent even though its
  parent revision already provided them.
- `test_encoding.c` had no changed-file impact rule, so the pre-push selector
  refused the otherwise-green repair rather than silently choosing no test.

## Result

The encoding oracle now covers short odd and even buffers, verifies the exact
NUL position and untouched suffix, and pins overlap fallback behavior. Wallet
allocation failures produce a test failure rather than a null dereference. The
unproved post-join classification was removed while Linux timed-join behavior
remains covered. Shipping removes the canonical production target before the
release build. The macOS runbook now describes the implemented seams.
The encoding test maps to its own registered group for future focused gates.

Measured at `2026-08-27T15:10:26-04:00`
(`2026-08-27T19:10:26Z`):

```text
test_encoding         groups_failed=0 self_skips=0
test_rpc_safety       groups_failed=0 self_skips=0
test_thread_registry  groups_failed=0 self_skips=0
test_onion_directory  groups_failed=0 self_skips=0
test_zcode_swarm_net  groups_failed=0 self_skips=0
test_projection_consumer groups_failed=0 self_skips=0
test_mempool_projection  groups_failed=0 self_skips=0
test_wallet_projection   groups_failed=0 self_skips=0
test_test_group_selector groups_failed=0 self_skips=0
tools/ship.sh --selftest                         PASS
tools/ship_selftest.sh                           PASS
tools/lint/check_ship_remote_transaction.sh      PASS
make lint-fast                                   PASS
check_doc_accuracy                               PASS (157 gates)
check_doc_claims                                 PASS (143 claims)
check_markdown_links                             PASS (283 documents)
check_accel_oracle_pinned                        PASS (7 files)
check_zcode_package_registry                     PASS (10 packages)
agent_fast_ci plan for test_encoding.c            mapped, no unmapped code
```

The encoding test ran on x86-64 and therefore observed the scalar tier. Its
sentinel and overlap cases are shared source and compile on AArch64, but live
NEON execution remains an AArch64 acceptance requirement.
