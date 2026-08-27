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

The four-host release dry run then reached remote staging with no candidate,
where `set -u` aborted on the unset release identifier. Dry-run staging now
returns before resolving or mutating any remote release path and states the
operation it would perform. The real four-host command completed its CPU,
glibc, SSH, and service preflight and reached the final no-mutation report.

## Cross-platform integration review

Review of the Windows build lane found that default MSYS `ps` output was
parsed as though it contained PPID and command columns, and that its displayed
start time was too coarse to distinguish a reused PID. The lane now reads the
documented procfs PPID, process name, and kernel start tick and fails closed if
those authorities are unavailable.

The incoming Apple toolchain path also claimed the fixed
`linux-x86_64-v3` action while hashing absence markers for Linux ABI files. It
was removed: the existing action remains Linux-only and Apple capture fails
closed until a versioned Apple target can pin the selected SDK, compiler
resources, flags, and ABI files. The new four-way BLAKE2b tier now uses
platform-neutral labels in its differential oracle and the benchmark reports
the runtime implementation name. Live NEON execution still requires an
AArch64 host and is not claimed by this x86-64 run.

Measured at `2026-08-27T17:59:02-04:00`
(`2026-08-27T21:59:02Z`):

```text
test_blake2b_batch_parity groups_failed=0 self_skips=0
test_build_fabric groups_failed=0 self_skips=0
check-build-epoch-integrity PASS
check-test-registration PASS
check-file-purpose PASS
check-pipefail-status-pipe PASS
check-c23-only PASS
check-long-functions PASS (existing library warnings only)
check-file-size-ceiling PASS (existing 22/22 library drift only)
check-doc-accuracy PASS
check-markdown-links PASS
check-clang-portability SKIP (installed Clang 22, baseline Clang 20)
```

The subsequent pre-push gate exposed two stale test assumptions after the
Windows vendor and canonical-binary changes. The LevelDB provenance test now
accepts the platform-bound recipe form and separately requires both POSIX and
Windows source routes. The network-policy fixture now models the shipped
`zclassic23 -> z23` alias instead of creating only the legacy name.

```text
test_vendor_provenance PASS
build_vendor_offline_selftest PASS
repro_network_policy_selftest PASS builds=4
```

## Concurrent main integration safety repair

Review of the next concurrent `main` batch retained its datadir ownership,
bounded-WAL, exact publish-generation, and real rollback acceptance work while
removing four false or unsafe outcomes:

- block reads no longer attempt to validate or hex-dump a possibly dangling
  pointer; the caller now owns the copied datadir bytes for the worker lifetime;
- WAL maintenance records the effective SQLite result and exact TRUNCATE result,
  and hard file-reset errors fail instead of becoming success;
- the byte-cap scheduler no longer duplicates the DB service's periodic
  five-minute checkpoint on slow disks;
- a hot-swap image superseded between registry publication and ownership commit
  is retired and reported as refused, not counted as a successful rollback.

Rollback fixtures are Linux-only build prerequisites, with an explicit
non-Linux platform contract. Fresh focused execution rebuilt both missing
fixtures, reproduced byte-identical images, and passed the real loader path.

Measured at `2026-08-27T18:39:21-04:00`
(`2026-08-27T22:39:21Z`):

```text
test_db_maintenance groups_failed=0 self_skips=0
test_db_maintenance_port groups_failed=0 self_skips=0
test_hotswap_rollback groups_failed=0 self_skips=0
test_agent_spend_policy groups_failed=0 self_skips=0
test_catchup_lifecycle_service groups_failed=0 self_skips=0
test_disk_block_io groups_failed=0 self_skips=0
test_command_handler_snapshot groups_failed=0 self_skips=0
test_sqlite + wallet SQLite groups_failed=0 self_skips=0
```

## Final concurrent integration review

The next `main` batch added AArch64 SHA3 lanes and a wallet replay outcome.
Review found that the SHA3-512 oracle still forced the x86 selector on AArch64,
so it would compare scalar output with itself while production selected NEON.
The oracle now selects the target's real vector tier. Both SHA3 batch dispatch
surfaces publish their initialized function through atomic storage guarded by
`pthread_once`, removing concurrent first-use data races.

The replay outcome was volatile and keyed only by a public quote root, so it
could not safely authorize a durable `COMMITTED` to `PLANNED` custody-state
downgrade. That downgrade and its unused outcome ring were removed. Wallet buy
confirmation now uses the existing atomic `PLANNED` to `ARMING` claim before
key access or outbound gossip; a competing confirmation fails closed without
sending an accept. The Windows setup now defines its checkout placeholder, and
the LevelDB recipe retains the platform-bound form required by the stronger
provenance gate.

Measured at `2026-08-27T18:50:21-04:00`
(`2026-08-27T22:50:21Z`):

```text
test_sha3_512_x4 groups_failed=0 self_skips=0 (AVX-512 selected)
test_sha3_256_x4 groups_failed=0 self_skips=0 (AVX-512 selected)
test_yardsale_wallet groups_failed=0 self_skips=0
test_yardsale_app groups_failed=0 self_skips=0
check-vendor-provenance PASS
check-zcode-package-registry PASS (10 roots rederived)
```

Native NEON execution remains unclaimed by this x86-64 host; the corrected
oracle will select NEON on an eligible AArch64 test host.

The final Windows-native process-introspection commit changed the registered
platform package. Its content, release, lock, and signature fields were
re-derived from the combined tree before release.

```text
test_dev_platform groups_failed=0 self_skips=0
check-zcode-package-registry PASS (10 roots rederived)
check-vendor-provenance PASS
```

## Deployment and bundle boundary review

Review of the final concurrent batch found that Darwin named-file bundle
staging could publish a different inode than the descriptor that was sealed,
and its read-only reopen could retain an `O_RDWR` descriptor. The Darwin
extension was removed from this release; Linux retains its already-proven
anonymous-inode path.

The host-neutral ship observer now uses its platform executable helper at every
test site. An interrupted rename-before-directory-mode publication is repaired
by making a real, non-symlink release root read-only before re-verifying any
bytes and before selection.

Measured at `2026-08-27T19:06:11-04:00`
(`2026-08-27T23:06:11Z`):

```text
check-ship-remote-transaction PASS
test_consensus_state_snapshot_export groups_failed=0 self_skips=0
test_consensus_state_snapshot_install groups_failed=0 self_skips=0
check-zcode-package-registry PASS (10 roots rederived)
```

## Confined platform package acceptance

The platform package smoke test had begun requiring live process
introspection. That contract is invalid inside the bounded package builder:
Linux process information is optional there, and the package API documents
those probes as fallible. The portable package test now covers its deterministic
memory-observation seam; live process behavior remains covered by the dedicated
platform group. The platform package row was re-derived from the corrected
source.

Measured at `2026-08-27T19:41:14-04:00`
(`2026-08-27T23:41:14Z`):

```text
test_zcode_package_registry groups_failed=0 self_skips=0
test_zcode_swarm_net groups_failed=0 self_skips=0
test_dev_platform groups_failed=0 self_skips=0
check-zcode-package-registry PASS (10 roots rederived)
lint-fast PASS
```

## Windows portability integration

The concurrent Windows portability batch was integrated after repairing three
release blockers: the confined platform package retained only deterministic
probes, its exact package row was re-derived, and the socket compatibility
header became self-contained for POSIX consumers. Build and shell entry points
use Git's `text eol=lf` policy so Windows checkout configuration cannot add
carriage returns to executable scripts.

Measured at `2026-08-27T19:54:34-04:00`
(`2026-08-27T23:54:34Z`):

```text
test_dev_platform groups_failed=0 self_skips=0
test_zcode_package_registry groups_failed=0 self_skips=0
check-zcode-package-registry PASS (10 roots rederived)
lint-fast PASS
```
