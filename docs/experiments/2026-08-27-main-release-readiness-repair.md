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

## Tor dependency publication repair

At `2026-08-27T19:35:51Z`, Z23 main pinned Tor object `7d5e32fda9c78d…`,
but the configured public repository still advertised `8f4b01ff3ee6…` and
refused an exact-object fetch. A fresh clone therefore could not reproduce
main. The bounded reassembly implementation was committed and signed directly
in the public Tor repository as `00fd7a14aacacd487634b82fc6203e695da2de0d`;
Z23 now pins that reachable object.

The rebuilt `vendor/tor/libtor.a` exported both admission functions, and the
full embedded-Tor test observed the live implementation:

```text
test_dynhost_reassembly_cap  OK
test_tor                     groups_failed=0 self_skips=0
test_torn_index_blocks_tip   groups_failed=0 self_skips=0
```

The first complete lint run then rejected one runbook phrase that formatted a
system header as an in-repository path. The wording now distinguishes that
external header from tracked source paths.

## ARM hardware-tier portability repair

Review of the later ARMv8 SHA-256 and CRC-32C tier found that its target
attributes and CRC builtins were specific to Clang. GCC 14 and newer require
the AArch64 target feature forms `+sha2` and `+crc`; the portable Arm C
Language Extensions API supplies `__crc32cd`, `__crc32cw`, and `__crc32cb`.
The implementation now uses those shared spellings, which Clang also accepts.

CRC-32C observability now reports the ISA that actually produced the bytes:
`hardware-sse4.2` on x86 and `hardware-armv8-crc32` on AArch64. Runtime
selection remains OS-feature-gated and compared with the portable reference
before activation. The x86 host cannot prove ARM instruction execution, so a
GCC AArch64 build and live parity run remain required release evidence for an
AArch64 artifact.

## Worker-stack repair integration

A later mainline change moved five 256-entry build-action scan buffers from
worker stacks to checked heap storage. Each buffer is about 516 KiB, which can
exhaust a default macOS worker stack. Integration retained that repair while
removing an unnecessary receipt query and reducing the source to 799 lines.
The SIGILL crash-handler registration was integrated without growing its
already-baselined translation unit. `make check-file-size-ceiling` then passed
with the enforced application ceiling clean and the library drift count at
its existing 22/22 bound.
