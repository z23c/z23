<!-- Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 -->

# Canary sentinel durability

The replay canary used three whole-system `sync` calls while resetting its
sentinel and publishing a verdict. One isolated absent-oracle observation
spent 18.579368 seconds in those command spans out of 18.773395 seconds wall
time. It returned the expected BLOCKED verdict below the existing 30-second
requirement. This measures global flush coupling; it does not establish the
cause of an earlier timing failure or a performance improvement.

## Lifecycle

The existing development binary's `dev test canary_sentinel` command performs
checked, object-scoped persistence without starting a candidate node. Reset
durably removes the prior sentinel, clears only this run's numeric temporary
leaf, and publishes the start marker. Publication flushes the complete staged
file, renames it atomically, then flushes the retained directory. Other
writers' numeric temporary leaves remain untouched.

The POSIX handler retains a directory descriptor and accepts owner-owned
0755 directories when group and other users cannot write them. Publication
requires owned, regular, single-link staged files without group/other write
access. Safe fixed-leaf cleanup does not read or trust the old file's contents
or write bits; this permits removal of retained legacy 0664 sentinels and
markers. Symlinks and nonregular or multiply linked entries are refused.
A directory-local advisory lock covers each operation, not the replay interval.

Creation uses `umask go-w` in a subshell, preserving caller read restrictions:
umasks 0002 and 0022 produce 0644 sentinels and markers; 0077 produces 0600.
Relative verdict directories remain accepted without resolving their terminal
component before native no-follow validation. The group-specific host-needs
row builds the development tool independently of the candidate node.

A failed barrier never reports durable success. A namespace change followed
by directory-flush failure reports durability unknown; verdict invalidation
is best-effort, not a proven rollback. Both Makefile wrappers require a zero
harness exit as well as a fresh PASS sentinel. Native failures emit bounded
structured diagnostics to stderr before the script exits 2. The command does
not perform consensus, wallet, deployment or network operations.

## Qualification

The source baseline was `c90997a57a3a933555c7b6ce2fd0043bc7f74cfc`.
The repaired code tested on Linux was:

| Path | Git blob |
| --- | --- |
| `tools/command/native_dev_canary_sentinel.c` | `93c6cf372aa7d2e6e28def15ba3882da6ffc202a` |
| `engine/modules/kernel/src/command_registry_input_types.c` | `879aae76a29aea75f705d07467b6ea7432c4169e` |
| `tools/scripts/replay_canary.sh` | `a71b63e9a0c074eacdc2deeb871492ccfaf5b071` |
| `tests/harness/src/test_replay_canary_verdict.c` | `f2bc0f80808448b6756cdd11dafb21891996b486` |
| `Makefile` | `52e737d1d7f45b81c3a3be29d97b051973da4fb9` |
| `tools/dev/test_group_host_needs.def` | `96ab16b087b348f53ccb32b6678289e18da89f13` |

The first focused qualification failed, including its automatic isolated
retry. CLI normalization rejected the numeric timestamp before the handler,
and a new direct fixture passed a relative path to an absolute-path handler.
Retained fixtures also exposed legacy mode 0664 under umask 0002. The repairs
preserve the original assertions: only this leaf accepts integer or validated
decimal-string timestamps, the direct fixture resolves its existing directory
physically, and cleanup and creation distinguish old permissions from strict
new publication.

The repaired run used:

```sh
DEVBUILD_CLASS=normal ZCL_TOOLS_LINK_JOBS=14 devbuild --wait \
  ionice -c3 make -j28 t-fast ONLY=replay_canary_verdict
```

It passed one registered group with zero failures, skips, unobserved results
or load-flaky groups. The group reported 37.6 seconds wall time and a phase
receipt of 37,559 ms test body and 0 ms startup. End-to-end elapsed time was
141.758 seconds, including admission, build and wrapper overhead; admission
wait and build time were not separately measured. The interval was
2026-10-27T04:57:39.972Z through 2026-10-27T05:00:01.730Z.

The compiler was GCC 14.2.0, Ubuntu package 14.2.0-4ubuntu2~24.04.1. Hardware
was an AMD Ryzen 9 7950X3D 16-Core Processor, Linux 6.8.0-139-generic x86_64.
Native admission reserved 28 CPUs and 24 GiB; the command used idle I/O
priority. The built development executable SHA-256 was
`4996ba279ea4edf4e4ce70fd4f2bb489e8b1e7d5fe01ca1d9bba81a1a190f981`.

| Retained evidence | SHA-256 |
| --- | --- |
| Initial isolated global-sync trace | `df4b0aaf783aaf8664b3d3e00c0c459cf1c46359eefb78618fe47d500587d614` |
| First failed focused run, including automatic retry | `7fec31ca29ab603bcc5aeeeac0cc65b58a297e52aed05361e552286696d596a3` |
| Repaired focused run | `018ea74455af58786b266ebda191e135d0da1b6c34fd478f2d7209050e93a5c4` |

The passing group exercised actual native write/file-flush/rename/directory-
flush failures, unlink durability unknown, explicit 0664 publication refusal,
valid 0644 stages at each injected boundary, all three caller umasks, and
integer/string CLI typing. Real-script tests rejected global `sync` use and
native persistence refusal. Copies of both actual Makefile recipes rejected
nonzero-exit/fresh-PASS and zero-exit/no-PASS fixtures while accepting the
zero-exit/fresh-PASS control. Existing killed-run, stale-PASS, executable-
identity and absent-oracle 30-second assertions passed unchanged.

These results qualify isolated Linux fixtures, not live activation or node
health. macOS runtime qualification was not run. The existing POSIX canary
remains unsupported on Windows; its native command explicitly refuses there.
This note was updated after the focused run. Full lint and native exact
candidate proof remain pending; no live deployment was performed.

## Capability declaration correction

The first default native intake refused capability closure. Its full checker
output identified two blocking undeclared reaches: the new handler used
`CAP_FS_READ` and `CAP_FS_WRITE` without a module declaration. An exact
`CAP_FS_READ|CAP_FS_WRITE` row was added to the existing declaration file;
handler and test bytes were unchanged.

The read-only checker loads this declaration file directly. After the repair
it exited 0: 2,754 objects scanned, zero unclassified, undeclared,
overdeclared, missing-source-row or raw-syscall violations. Two declared-but-
unobserved rows remain at the existing coverage baseline, and twenty compiled-out
capability observations remain unobserved. This is not cross-platform proof.
The repaired declaration file blob was
`c7826820d164218abb5725559fa247b82d825804`.

The leading failure excerpt also mentioned one foreign object. That object
is the current `DEV_PACKAGE_VERIFY_GUI_STUB_OBJ` alias built from
`contexts/wallet/views/src/wallet_gui.c` with GUI macros explicitly undefined.
Its Makefile recipe, dependency file and DWARF source name agree. The
checker's filename-based source mapping does not recognize the alias; its
foreign count is informational and is not part of the blocking violation sum.
The object was retained, with no cleanup or gate waiver. The two missing
capability declarations caused the refusal.

The repaired checker log SHA-256 was `7a98c1630b87ed64c823c983b2d205e527b10740c05ebdfa6f60946dd83e075a`.

## Canonical proof and accessor consolidation

The corrected intake queued candidate `fd68a7e54e21410b9daeed90111d32359fde8cf5`.
Its native proof assembled `b7b8305becdbde2d69276227d8635493b899aaf0` on
`4ec8326118b381d4f1a5c35b937532ac62b2603a` and failed lint before test proof.
The retained gate bodies reported a missing purpose comment in the new handler
and 1,849 duplicate candidates against the fixed maximum of 1,848. The
intake had invoked the purpose checker in its default WARN mode; the canonical
Makefile target enforced RATCHET. Intake acceptance did not establish canonical
lint acceptance.

A fresh native inventory reproduction at the exact assembled source confirmed
1,849 candidates. It identified the new `canary_string` accessor as identical
to four existing static accessors. The repair deletes it and composes the
existing null-safe JSON accessors. An explicit directory type check preserves
missing or nonstring directory rejection during input validation; an empty
string retains the existing persistence refusal. Integer and string timestamp
validation and the existing fault assertions remain unchanged. A purpose line
was added inside the first copyright comment block.

On 2026-10-27, the repaired source based on `fd68a7e54e21410b9daeed90111d32359fde8cf5`
produced 1,847 duplicate candidates, below the unchanged 1,848 floor. This
absolute result qualifies the repaired source; the difference from the earlier
assembled source is not attributed wholly to accessor removal because their
bases differ. The structural batch generated the inventory twice: a subsequent
canonical KPI target regenerated its phony inventory prerequisite. Both scans
used the same pinned source and reported the same count. The retained final
inventory SHA-256 was `786c5fd50ae5480c9853d8d35f4f9890da4398d2732d79abd88f27de163bbb43`.
The canonical KPI checker passed all nine metrics, the purpose checker reported
zero RATCHET violations, and complexity, file-size and staged diff checks passed.
The structural log SHA-256 was `9cddf1cd2ba94966987360be3e2f746edda8d942f21d5403ba934d241b511cd1`.

The registered `replay_canary_verdict` focused run then passed one group with
zero failures, skips, unobserved groups or flaky retries. Reported group wall
time was 46.7 seconds; the phase receipt recorded 46,650 ms in the test body
and 0 ms startup. The new direct-handler and real-CLI directory validation
regression explicitly passed. The compiler, CPU and platform were the Linux
configuration recorded above. Handler blob `3e3f72d71582fe104ff18fe66fd018bb490a6111`
and test blob `9eee90bb21052d47054fd0bcf3ebceacbea4ebd4` remained unchanged
through qualification. The focused log SHA-256 was
`db2b249ed7c2e32b54bbddc99ebdcd7a0c7e7118dbbadc1d079350a72c3f8010`.
Earlier failures remain evidence; these results establish neither their timing
cause nor a performance improvement. Native exact candidate proof remains
pending, and no production activation or additional platform runtime was tested.

## Privileged-transition disposition

The successor candidate `dbf84f293bb54223f9d3720fd8e393ac65ef8644` was admitted
as native queue row 1280. Its lint proof reported that the new owner-mutating
`dev.test.canary_sentinel` leaf lacked a Law-7 disposition. The rule requires
an explicit review of every such leaf: privileged artifact installation must
bind an authority receipt; operations that install no privileged artifact must
record a factual exemption.
The final shard-07 real-tree checker assertion reported the same missing
disposition; it is a second observation of this policy omission, not a
separate canary runtime defect.

The canary command resets or publishes fixed replay-verdict evidence and its
marker in a validated owner directory. It installs no privileged artifact and
changes no running binary or canonical node. Its disposition therefore records
that limited effect; it neither bypasses authority-receipt verification for an
installation nor grants new execution or deployment authority. Handler and test
bytes are unchanged. The canonical `check-privileged-transition-receipt`
gate passed on 2026-10-27: all 150 owner-mutating leaves were dispositioned
(1 receipt, 149 exempt). Full donor byte, metadata and absence manifests
matched before and after the admitted check; no donor rebuild was needed.

Canonical gate log SHA-256: `c3d098945efe9d8d70fdf4332be53397b16503f797ad0787bc646c01782b33f4`.
