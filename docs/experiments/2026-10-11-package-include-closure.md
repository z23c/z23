<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Package include-directory closure

Recorded at 2026-10-11T04:35:57Z (local 2026-10-11T00:35:57-04:00).
Proposal base: `c0c1e97a2e2a40cb3b63710ecfb565ca83c5b406`.
Execution parent: `06f6567737e00c4588d590ca59b24e749c8a18c8`, tree
`972ca5eec0224334b45e45c39b3f37bc720c6921`, on receiver alias `node1`.
The affected production and test source files were byte-identical between
the two bases before applying the regression. This does not establish
whole-tree equality.

Version 4 separates argument construction and regression verification into
smaller helpers after version 3 failed the complexity and documentation-path
lint gates. Fresh parent, fixed, cutoff-mutation and restored runtime phases
independently qualify the refactored production and regression bytes recorded
below. Historical version-2 observations remain separate. This version-6
prose reconciliation changes no production or regression bytes; final full
lint remains **PENDING** at its documentation freeze.

A package recipe permits 256 include directories. The external package
verifier previously passed only its first eight directories to compilation
and preprocessing. A valid package could compile with different behavior
when a later directory supplied an optional header.

The verifier now holds the complete include argument storage in one checked
heap allocation per translation unit. Its three owners are dependency-plan
construction, library/test compilation, and program compilation. Each owner
releases storage after the last preprocessing, serialization, cache or compile
borrow, including failure paths. Argument construction rejects oversized
counts and truncated include, dependency, define or prefix-map formatting.

Compile-vector capacity includes all accepted directory, dependency and define
counts, the fixed operands and NULL, and the maximum architecture tokens that
fit the existing architecture buffer. Preprocessing vectors and cache-key
rendering use corresponding bounds. The static capacities are 466 compile
slots and 470 preprocessing slots; these are source bounds, not measurements.
No dependency archive, compiler identity or capsule acceptance policy changes.

The registered `zcode_verify` regression invokes the actual
`build/bin/zclassic23-package-verify-dev` subprocess with full package isolation.
The source returns 42 when `__has_include` finds its declared header, otherwise
17. Its linked test requires 42. Three cases cover a header in directory 8,
a header in directory 9, and a header in directory 256 with 64 defines.

The first two cases use canonical store manifests, recipes, chunks and signed
fixture releases. Signed attestation mode uses `--store` and `--key`, without
`--plan` or `--emit`. The test verifies the signed observation, exact roots,
`TEST_PASS`, actual test exit 0 and full isolation before fixture cleanup.
Attestation subprocess exit 0 means successful observation persistence and can
also accompany a failing package test.

The boundary case independently captures accepted fixture files into native
ZVCS CAS, materializes their verified bytes read-only, and recaptures the tree
to check its exact identity. It uses the canonical recipe file outside that
tree and candidate quick mode with fresh cold/warm emit and work paths, a shared
fresh object cache, and a dependency plan. This mode passes neither `--store`
nor `--key`. The test, rather than the candidate verifier, independently checks
the supplied source-root identity.

Boundary acceptance requires parsed `TEST_PASS` build receipts over exact
source, recipe and lock roots, full isolation, actual test exit 0, and emitted
archive bytes matching those receipts. Plans must contain all 256 ordered
include arguments, all 64 ordered define arguments, and the exact selected
header closure_value.h in directory inc255, its class, SHA3-256 and size.
Both cache sidecars must
pass the existing key verifier and independent object-byte hashing. The source
sidecar must match the plan's preprocessed hash and complete normalized argv,
with the two different output operands explicitly checked. Cold/warm archive
and object hashes must agree. Required cache counts are cold 0 hits/2 misses
and warm 2 hits/0 misses with positive reused bytes.

## Historical version-2 runtime qualification

Four admitted canonical jobs executed the version-2 regression: parent with
regression only, fixed candidate, original-cutoff mutation, and restored fixed
candidate. The mutation changes only the include-argument loop to
`i < recipe->include_dirs.count && i < 8u`. Its SHA256 is
`2bbd6d8e2f39c21e5d27ee852b13fe53ed8e459866a5d28200c53e1d9f6e05e2`.
Reverse application restored the exact fixed production hash before the final
job. Every phase ran one registered group, cached zero groups, and recorded
zero skips and zero unobserved environment legs.

| Case | Parent and cutoff mutation | Fixed and restored |
| --- | --- | --- |
| 8-directory signed fixture | Verified signed `TEST_PASS`, full isolation | Same passing control |
| 9-directory signed fixture | Verified signed `TEST_FAIL`, test ran, exit 1, full isolation | Verified signed `TEST_PASS`, test exit 0, full isolation |
| 256-directory/64-define candidate, cold and warm | Actual `TEST_FAIL`; complete-argument/header and passing-receipt checks failed | Actual `TEST_PASS`; complete plan, verified objects and archive, bound warm reuse passed |

The retained parent and mutation ninth-directory diagnostic reports signature
verification success, matching signer and source/recipe/release roots,
`test_ran=1`, and `exit=1`. Attestation identity:
`e4f6ee6e32a45a164086b3a46eb903625f612fc331094729c4dab3c49e86db9c`.
The fixed/restored ninth-directory passing attestation identity is
`1509c3f773e4f27a3bb5041b690e5ce1daeae3e8e06afe427e46d31b932e6d2c`.
All these attestation subprocesses exited 0. The failing observations reached
actual compilation, linking and test execution; usage, compiler or sandbox
refusal did not substitute for the witness.

Fixed and restored boundary runs passed every ordered 256-include/64-define,
selected-header, receipt/archive, sidecar/object, preprocessing/argv and
cold/warm byte-identity assertion described above. Both had cold 0 hits/2
misses and warm 2 hits/0 misses, with 2592 reused bytes. Parent and mutation
also reported those cache counts while their package tests failed. Cache hits
alone therefore do not establish passing test behavior.

The canonical commands were:

```sh
devbuild --wait make t-fast-exact ONLY=zcode_verify
devbuild --wait make t-fast-exact ONLY=zcode_verify T_FAST_EXACT_ARGS=--no-cache
```

The second command qualified restoration by running the actual group with
runner caching explicitly disabled; the fixture's separate warm object-cache
test remained enabled. Parent and mutation returned host command status 2
and group status 1; fixed and restored returned 0 for both. The implementation,
regression and mutation received independent source acceptance before their
execution. Version 3 independently reconciled the retained observations.

## Historical version-2 source and executable identities

The regression source remained unchanged through all four phases:
`ff345d47e4012423ff8ede4101392e258cfd1ee99fa7669cea88f7431965bf5a`.
Production source SHA256 values:

| Phase | SHA256 |
| --- | --- |
| Parent | `ad9361d7fb45c9859ce3c86eff222626ff47cd15b9e029af0b82a5f4eb1c2c7c` |
| Fixed and restored | `f4c73e6e97ac78f366a35e1d8276bf1c1edc566057e6e8ff6264958afb0ff049` |
| Cutoff mutation | `e4cbf31338a13f3fc11105eeb1c78dc02001d17988189002814977d095c191a4` |

Each phase recorded the effective verifier bytes separately:

| Phase | Verifier SHA256 |
| --- | --- |
| Parent | `232102fa909bb82f1dee7591944f634cf029097d38393b6d92e841998e39eaae` |
| Fixed | `0ec1d34871fd70ad1d65d9438680763ec16e969780cce155e3a5e8b573d04cac` |
| Cutoff mutation | `945150662a9e56e82efcb420fddd60c90de270462d16b6999dd00ed6adc8c0f9` |
| Restored | `92204d22640f9936d8d3a8aba5086cdb46959ca4ea2f767b3d856dfd0713934d` |

Fixed and restored verifier hashes differ. The results are bound to each
phase's recorded bytes; no verifier-binary reproduction claim is made.

## Retained evidence

SHA256 identities of complete canonical logs, native scheduler job records
and registered-suite verdicts:

| Phase | Record | SHA256 |
| --- | --- | --- |
| Parent | Log | `1b7fc64ee07e2995718a04da05a7f6ea996606e0de2ebdfbc008cfe0e8bbb0f9` |
| Parent | Native job | `099169a7e1224e16429b43ee8b84145ecf646f330d9f303cd553e3cb42efd9c1` |
| Parent | Verdict | `280cc8aadbb4905c299299d320a920d9d0ec748dbd027008f88e284be150323d` |
| Fixed | Log | `3a5e276450a20a5905b94e50bd4d84ad22c954fd65d5914aa2a870b50bb9016f` |
| Fixed | Native job | `4e4e21f6e6cd10a11e40d66be0522201eb689e8e6a944da53052720d946c052b` |
| Fixed | Verdict | `84e1f00250fe0052cd6a1832d3a0a2510d85dd64da7e31e01fd20fe30d249bf3` |
| Cutoff mutation | Log | `6e0e82e393e2818f40754eb458db80cd440a0b8421c31a756ba1dbce2f9c3424` |
| Cutoff mutation | Native job | `157830d63af7106982e6bcc115505e72ab6b0b608e69a74ceb4e823ff665d617` |
| Cutoff mutation | Verdict | `db744e741d52e96c03ce414b9560bad606b9287a955aabe155bc074d2db1250f` |
| Restored | Log | `80a9d9efcf5ea2bbd36501a79a16fb83b647befd5e23a399bc5990331d42bb78` |
| Restored | Native job | `b25cba4dcb8001fc73d4d9fc6d535a791e5fd1d058895f803d334c753f6496d8` |
| Restored | Verdict | `bf037b42dd6c8669046837c6f389556bd0e88a88186f749ee3325ed36d4a144a` |

The retained parent/mutation logs contain the runner's retry decision and
final alone-run body. A separate original pool-attempt body is not retained;
behavioral qualification relies on the final retained diagnostic. Fixture
cleanup removed raw CAS, signed attestations, plans, receipts and cache objects.
Their in-process verification assertions and runner diagnostics are retained,
but independent replay of those removed fixture objects is not claimed.

## Measured job resources and remaining gates

Native scheduler measurements cover each complete admitted command, including
any prerequisite build work. They are separate from individual package timing
or a comparative performance experiment.

| Phase | Native job PID | Queue seconds | Run wall seconds | CPU seconds | Peak MiB |
| --- | --- | --- | --- | --- | --- |
| Parent | 1851816 | 0 | 97 | 105 | 1211 |
| Fixed | 1928908 | 0 | 180 | 32 | 1166 |
| Cutoff mutation | 2025203 | 434 | 91 | 46 | 646 |
| Restored | 2986252 | 8 | 102 | 40 | 642 |

Across these four jobs, recorded queue time totals 442 seconds, run wall time
470 seconds and CPU time 223 seconds. Peak memory is per job, not an additive
total. Compiler versions and CPU model were not recorded in this retained
qualification packet. Model usage, subscription usage, actual charges and
complete workflow cost remain unknown. No performance or efficiency gain is
claimed.

Windows/macOS runtime acceptance, sanitizers and publication remain **NOTRUN**
for this slice. Program allocation cleanup awaits dedicated
executed coverage. A changed-header 42-to-43 cache invalidation experiment is
an explicit **NOTRUN** follow-up; these results do not qualify complete
byte-invalidation coverage or complete physical toolchain closure.

## Version-3 lint failure and version-4 candidate

Canonical full lint job 3677076 returned 2: 4 of 219 gates failed with caching
disabled. Six candidate functions exceeded complexity cap 15; the generated fixture
header path was incorrectly presented as a tracked path in the documentation;
the receiver's installed pre-commit guard did not match the tracked hook; and
the capability inventory needed canonical regeneration for the added
registered-test reachability. No complexity baseline or acceptance threshold
is raised. The hook and generated-inventory corrections have separate scope.

Retained SHA256 identities for that failed lint job:

| Record | SHA256 |
| --- | --- |
| Complete log | `65032a36d2a938808fbc0cb6230739a88205ca81d8e81dad96eefaf7f6052908` |
| Native scheduler job | `1da685b56c69b1e5ad69fa16c17070a23caf1329e303e8b6dbee8b81eddd4f9f` |
| Native lint gate report | `3c4fd97ed02737ac4e41275c71c12a80585c13a989d30148df9b4abfc766c31a` |

Its scheduler recorded queue 0 seconds, run wall 415 seconds, CPU 2496 seconds
and peak memory 3837 MiB. These additional resources are separate from the
four runtime jobs above; complete workflow cost and actual charges remain
unknown.

The version-4 production refactor separates platform arguments, compiler
options and declared recipe inputs while preserving their ordering, accepted
counts, formatting refusals, heap ownership and vector capacities. Regression
helpers separate recipe construction, accepted fixture population, sidecar
contents/object verification, shard enumeration and cache-count checks. Every
existing behavioral, root, byte, argv, isolation and reuse assertion remains.
The generated header is described by its directory and basename.

Refactored source SHA256 identities:

| File | SHA256 |
| --- | --- |
| tools/package_verify.c | `448071aed103489d0f16eb0594d0e4064812cc2e78ee06a595fdede044630862` |
| tests/harness/src/test_zcode_verify.c | `fc7daa30b8b2bd9b79c4f4e795fee9b4a50427e8465a7a33ce808796db48726d` |

Independent source review and fresh four-phase runtime acceptance now qualify
the refactored source identities. Final full lint and this prose reconciliation's
independent documentation review remain separate pending gates. Historical
version-2 receipts, patches and manifests are preserved without reinterpretation.

## Fresh refactored runtime qualification

All four fresh jobs ran the actual registered group through host admission:

```sh
devbuild --wait make t-fast-exact ONLY=zcode_verify T_FAST_EXACT_ARGS=--no-cache
```

Each recorded one group executed, zero cached, zero skips and zero unobserved
environment legs. Fresh parent uses unchanged original production SHA256
`ad9361d7fb45c9859ce3c86eff222626ff47cd15b9e029af0b82a5f4eb1c2c7c`
with the refactored regression; its production diff is empty. Fixed and restored
use production `448071aed103489d0f16eb0594d0e4064812cc2e78ee06a595fdede044630862`.
Mutation uses `73f45991e76900c345aa5659e1a48c5ce6c60a28660371445bde6276bdde8e08`;
patch SHA256 `2dc684cec3969c04d09ed5a4f2a0c4b11c6db232ed88fc1f1486e60aba804c51`
adds only the original eight-directory cutoff to the relocated include loop.

All four phases preserve regression SHA256
`fc7daa30b8b2bd9b79c4f4e795fee9b4a50427e8465a7a33ce808796db48726d`,
runtime documentation `cc12e91f80fea957a77778cd0a32035d66c62ac7161845f422b716261cde6849`,
and canonically generated capability inventory
`bbe1e953eb276140c5dbbbfc11e653332f1af4503cc2f99fca0ca87b7669f4a4`.
Before/after receiver measurements agree within each phase. This prose revision
is distinct from the recorded documentation bytes present during execution.

| Fresh case | Parent and actual cutoff mutation | Fixed and restored |
| --- | --- | --- |
| Signed 8-directory control | Verified `TEST_PASS`, full isolation | Same passing control |
| Signed 9-directory test | Verified `TEST_FAIL`, test ran, exit 1, full isolation | Verified `TEST_PASS`, test exit 0, full isolation |
| Candidate 256-directory/64-define cold/warm | Actual `TEST_FAIL`; passing-receipt, complete-plan/header and sidecar/object assertions fail | Actual `TEST_PASS`; every plan, receipt, sidecar, object, archive and byte-identity assertion passes |

The signed ninth-directory failure again verifies with matching signer and
package/recipe/release roots, `test_ran=1` and `exit=1`. The retained attestation
identities match the historical fixtures, but these are separately executed
fresh observations. Actual compilation, linking and test behavior distinguish
parent/mutation from fixed/restored; usage, missing compiler, isolation refusal
and timeout do not substitute. All attestation subprocesses returned 0, while
parent/mutation host commands returned 2 and their group returned 1.
Fixed/restored command and group statuses were 0.

Fixed and restored pass the independently checked immutable source tree, exact
receipt roots and passing actual tests under full isolation, all ordered
256 includes/64 defines, exact last-header class/hash/size, source preprocessing
and argv agreement, independent sidecar/object/archive verification and
cold/warm byte identity. Cold has 0 hits/2 misses/0 reused bytes; warm has
2 hits/0 misses/2592 reused bytes. Parent/mutation have the same cache counts
but fail their actual package tests and completeness assertions.

The receiver waited for the mutation job to terminate, reverse-checked and
reverse-applied the one-line mutation, and immediately verified exact fixed
production plus unchanged test/documentation/inventory bytes. Restoration
record SHA256:
`a471d6980d1542a127e39963138999dd17abd704b298ba29058cfccaa8bd69f6`.
The separate restored runtime then passed every assertion with group caching
disabled; structural reversal alone is not used as runtime proof.

| Fresh phase | Native PID | Queue s | Run wall s | CPU s | Peak MiB |
| --- | --- | --- | --- | --- | --- |
| Parent | 1284337 | 160 | 105 | 52 | 645 |
| Fixed | 1697574 | 0 | 81 | 30 | 646 |
| Cutoff mutation | 1768907 | 0 | 225 | 60 | 645 |
| Restored | 2117544 | 116 | 139 | 49 | 645 |

These four complete admitted commands total queue 276 seconds, run wall
550 seconds and CPU 191 seconds. They are separate from the earlier runtime
and failed-lint jobs, and from individual package-body measurements. Peak
memory is per job. No throughput, performance or cost improvement is inferred.
Model/subscription usage, actual charges and complete workflow cost remain
unknown.

## Fresh retained identities and proof limits

| Fresh phase | Record | SHA256 |
| --- | --- | --- |
| Parent | Complete log | `70c26b8caaf6471ecdddd4c2a00127311cb62382c49443f0451ccd01724c609e` |
| Parent | Native job | `da886462b5ae2447b171dc1e45aaa451663fff1096364c2c88a42d904fdf28dc` |
| Parent | Verdict | `e792081877a38313c3f6d99741fd777e1ff3a5a89edebaf01085a708b1839ef1` |
| Fixed | Complete log | `80af7b8d11e5e5b139fa80d3df6c3993fa402226a5d6e02283bc1ab8a4a3e339` |
| Fixed | Native job | `770b1716140519d4732c986e1e034975b9cf36c19cfb8696b456ff66fdd6f568` |
| Fixed | Verdict | `773fc76d3b1bcfb15500eec6847c33c2db7ee9dc5bc29a14009819247a90789d` |
| Cutoff mutation | Complete log | `a869451a7c53a0ba801ac208c9f5918217c669f58e7d41229970831071cdcb4e` |
| Cutoff mutation | Native job | `3f2e694838cd982668c830e3cb52a5ea1b8be01061f688cd7e34e80159c59a2e` |
| Cutoff mutation | Verdict | `ce940990215e3c9d8b111287251b69a12098237ce67d7f7a3d368ca029143ae7` |
| Restored | Complete log | `a92998ca5bb0a49c94c01063894efd8c57642737d1e6e5c0b1833401366f4cce` |
| Restored | Native job | `08cd6b11ced7a0197b0836b0ac990e19c2ec9e7fb175b0d165015c0ab83d2042` |
| Restored | Verdict | `935cf98bfa2920eb061dbab8a4f1b565646a05767229778bdf8962a1a0aa6cfd` |

Effective verifier and runner bytes are recorded per phase:

| Fresh phase | Executable | SHA256 |
| --- | --- | --- |
| Parent | Verifier | `9d482058e72bf460a85e8cdbfeca05e484ddf72f4735479e186e3e71a27df517` |
| Parent | Runner | `205247d85d6f039c06ee3d726cc7d1b750d56d88a6328757f045e78a1b33df7c` |
| Fixed | Verifier | `8e48178e2c19cda674ac7806fd748c6e3bc3407d3a00ede7b86e8d37e01e913f` |
| Fixed | Runner | `4f47d114dce52e0de70b1d61c034bb0940f0a21b7ddc9b6e1bff4cca8223714a` |
| Cutoff mutation | Verifier | `6187031df27e0dd78156c120c130db9e8442e476954d687b200393db3f713d6e` |
| Cutoff mutation | Runner | `682c8ec3420c3787312e7a978ccfe95dd0229f57c7d109b97ade8e6c95132a5c` |
| Restored | Verifier | `7730d76cd65c653b4363a824b3d51953b3743b17e72487817f8a1e5aaf80527d` |
| Restored | Runner | `037d9e432f941635bbbb3844363c5038213dfdc39331fc8a583db57f8500b1fc` |

Fixed/restored binaries differ; no binary reproduction claim is made.
Independent review verified the returned packet bytes and exact source
assertions, and accepted all four fresh runtime obligations. Review record
SHA256 identities:

| Fresh phase | Independent review SHA256 |
| --- | --- |
| Parent | `60c1de4ff15722067c5de7497a2190ce6ad6da905f2e53eeed6709dcf1f8efdb` |
| Fixed | `19c17ba5b90f2f3777d7c92dd1a371cebff8f459abbe927b62d314db03fc9752` |
| Cutoff mutation | `8c3cd3b044e3b4ea47cc44023316bde94e047ea624de617030f879af9e15ca13` |
| Restored | `d0a00b6db73c4c23301939da18f1fe38fb0de0e7c43bcbf1fa5b8f8cbc0e4bda` |

Source and executable measurements are receiver observations. Review of the
copied packet does not independently rehash remote executables. Parent and
mutation retain the retry decision and final alone-run body, not a separate
original pool-attempt body. Fixed/restored passing bodies are in their complete
logs. Raw CAS, signed attestations, plans, receipts, cache objects and capsules
were removed by unchanged fixture cleanup. Their in-process verification
assertions and diagnostics survive; independent replay of those raw objects
is unavailable.

Host context SHA256:
`d63f9d2ad166576c8f6876f6733d4499904da2bcd010d40811d3ba8f6750990b`.
It records AMD Ryzen 9 7950X3D 16-Core Processor, installed SSH-shell cc/gcc
resolution to GCC 14.2.0 and clang to Ubuntu Clang 20.1.8. The installed GCC
executable SHA256 is
`ce298ce0c8fbdaa4b43f6e0596e37d25a35a07b5c743cb26f11815b76fccf90d`;
installed Clang SHA256 is
`b1ca2b35b07cb5cb7db47247f329151ed22692a19de2763859b0867e6323e2fe`.
These installed/resolved identities do not establish consumed compiler bytes.
The fresh logs contain no echoed build compiler invocation. Source configuration
names the compiler paths and runtime diagnostics report compiler variants and
child-process counts, while cleaned capsules cannot supply further physical
toolchain closure.

Final full lint remains **PENDING** for this documentation freeze; its eventual
receipt belongs to separate additive evidence. This prose update changes no
C, test or inventory bytes; runtime claims remain bound to the recorded
executed tuples.
Other-platform package runtime, sanitizers, changed-header invalidation,
publication and complete physical toolchain closure remain unqualified.
