<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Evolving C23 factory qualification

Date: 2026-09-24T02:52:24-04:00 (2026-09-24T06:52:24+00:00).
Host: AMD Ryzen 7 PRO 8840U. Compiler: GCC 16.1.1 20260430, `-std=c23`.
Checkout base: `7a7bfe5823ea2b2684f1e45a564fc2a3cb3175ea`.
All packages, keys, stores, and reports were isolated under `test-tmp/`.
No resident node was running during the factory trials, so node-health
latency and synchronization effects are unobserved. A later isolated regtest
node did not reach RPC readiness: `svc.init_wallet` emitted slow at 30 s and
stuck telemetry at 60 and 90 s while a node build was in progress. It was
terminated after 111 s. This trial cannot attribute a node effect to factory
work and is retained as unavailable-observation evidence in
`test-tmp/factory-node-health-20260924/node.log`. The report's
`durable_hosting=unavailable_offline` is not a durability proof.

A second isolated regtest node reached `phase=serving`, `stage=ready`,
`rpc_bound=true`, height 0 in 12 s without a concurrent build. It used
`tools/scripts/isolated_node_env.sh` with ports 39580–39583 and the dead
`-connect=127.0.0.1:39999` sink. A fresh revision-1 factory run then passed
both stores in 4.338 s while the node remained ready. Ten sequential
`getblockcount` RPCs before the run answered in 7–9 ms (mean 8.0 ms); all
43 RPCs sampled during it answered in 7–11 ms (mean 9.09 ms). These are
client wall-clock samples on one host, not a controlled throughput study;
the height-0 node had no peer or chain-sync load. The baseline boot trace,
node log, RPC samples, and factory ledger are under
`test-tmp/factory-node-health-{baseline,load}-20260924/`. Their SHA-256
digests are recorded below. The first slow startup is not evidence of a
factory-induced regression.

| Isolated health artifact | SHA-256 |
| --- | --- |
| Boot trace | `a64171513054a1f758f4a2b1314fa4ab13dcbb158ca1e37bcf3745f653bc41d7` |
| Final boot status | `4dce2e222b00ac514209dfd6e49811c76a367ae11fdcf8b2c575533c6ffa018b` |
| Node log | `a53b8a585af3a7ba3d96285889801f4de09920ca5ae57a4b6de77f0aba05c76a` |
| Concurrent factory ledger | `6e9266247d24de7a69d33f950ce4345b67c31e4c6c34cc5da69b3db55ebd6b0d` |

`tools/dev/factory-evolving-fixture.sh` creates a C23 package with an
append-only value history. Revision N tests every prefix from 1 through N,
including the original tiny-lines behavior. The generator accepts N=1..100.
Three successive revisions and a separate revision-100 snapshot were exercised
through the real two-store `package-factory` path. The revision-100 snapshot
does not establish that all intermediate 4..99 transitions were accepted.
Revision 2 with value 2 replaced by 99 compiled cleanly; the package test
reported expected 3, got 100 and the factory refused it with `test-fail
(test exit 1)` at `add_commit_a`.

The pilot factory binary was SHA-256
`845dff78262c9d6a3d600bf47ce2ee48197688506a690a1bf8e46ff9145663e2`.
Its CLI and verifier binary SHA-256 values were
`8184917b0858297fa4856f8b6979869906e78725b869c461d7392970efbd7dea`
and `b17eda1cfc81431291a562be2e8ca8fb284da08a62f11a9108ac6fee7`.
The CLI and verifier came from a prior local build; their source commit was not
independently recovered. Exact executable bytes are preserved in the evidence
directory. The fresh-source build and qualification are recorded below.
The pilot fixture generator SHA-256 was
`935f5dadc90f54b5b3e81fb45ed47c0938f346b17ab3c0bb4dbb37b80cd74a4f`;
the committed generator uses portable `awk` in place of GNU `sed -i` and
reproduces the same revision-2 test bytes and mode.

Run the repeatable sequence from the repository root after building
`package-factory`, `z23`, `zclassic23-package-sign`, and
`zclassic23-package-verify`:

```bash
tools/dev/factory-evolving-qualification.sh \
  test-tmp/factory-qualification-new 3 build/bin
tools/dev/factory-evidence-audit.sh \
  test-tmp/factory-qualification-new/revision-2/report.json \
  test-tmp/factory-qualification-new/revision-2/pkg \
  test-tmp/factory-qualification-new/bin
tools/dev/factory-counterexamples.sh \
  test-tmp/factory-qualification-new worker \
  test-tmp/factory-worker-new
```

`factory-counterexamples.sh` accepts `wrong`, `interface`, `stale`, `contradictory`,
`partial`, `dependency`, `worker`, `publisher`, `duplicate`, `revoked`, and
`resource`. Each invocation requires a new output directory and checks its
expected failure or duplicate-dispatch result.

Pilot evidence is in `test-tmp/factory-qualification-pilot-20260924/`. The
ledger SHA-256 is
`6f18e85221192d69fcdf8b95d09ed364dbd77a15ffbf0fa630513bed48075afb`.
`verified`
below means the local package test passed and the factory reported successful
two-store reproduction. It is same-host proof, with one toolchain and a
self-screened admission; it is not independent operator acceptance. No case
was accepted by an operator.

| Case | Generated history source SHA-256 | Package root | Archive SHA3-256 | Factory | Wall s | CPU user+system s |
| --- | --- | --- | --- | --- | ---: | ---: |
| Revision 1 | `bb44fd76e90ed3901be8ca37d9f49f3d14ee9ff5239e2f5df6c93e43ae00479c` | `ae5a1e60d75e76390713a428cc91d1c0a5c26d3357f068206d28fcd3b3c295cf` | `66fa0097c390ab767740bf34d695519d1ad1acd13fd35cd8975fed5d31d2afdb` | reproduced both stores | 17.766 | 17.882 |
| Revision 2 | `b7623c59656795c7c9f2d53bcc00adf148ad90ad70073c3b6487766254d4bd85` | `6a6756b750b33e840a4f165f84558ac157578463d8664b350058e84f83e370ff` | `cddb295f76a91d76463cb73dae9c3e5bbfe9dacc78fa74a6883f52d855f26962` | reproduced both stores | 18.389 | 18.748 |
| Revision 3 | `bb6f3dd28feac8c7d697a2424a16b2f88629dfaebe20cca321146be2572b8846` | `49d9148921cb7c51424eed03191527de8b67f32ecf1d285f1cdf9082c47e4af8` | `c54d284e9b670198186e5831afd0111722e001d502de673f2890c7b2aa8d6007` | reproduced both stores | 20.110 | 19.591 |
| Wrong revision 2 | `f5bc2b15570a757a0d636ff44a662daeb66976df21cca73ba1f330cc94f2dbf6` | `54db8393b94bd72520ebaa39337bdc8b884abf4651dd45c2b53b02097a3dd7f9` | none | test refused | 4.488 | 4.440 |

Each successful store's installed `libtiny-lines.a` matched its peer byte for
byte. `ledger.tsv` carries each case's full report SHA-256 and both quick and
standard receipt ids; those receipt wires bind package, recipe, dependency,
toolchain, test verdict, and emitted artifact hashes.

Counts for those four cases: generated 4, buildable 4, locally previewed 4,
tested 4, locally verified 3, operator accepted 0. Aggregate factory wall time
was 60.753 s, user CPU 35.189 s, system CPU 25.472 s. Local preview here is
execution of the package test binary; no application UI was claimed.
The separate revision-100 package root was
`f424e549c260ef2206315d34ac62f7b5477bc63085517d7d802c69b2a73d5b01`;
its 100-prefix test and two-store factory run passed in 19.769 s. Its
generated history source SHA-256 was
`7f651ac07bd563b55fc63774582c0b79423a27d078e2b03e42376a673bdfc026`.
The installed archive SHA3-256 was
`287f2e0067aded8f6398d5e17625bf3d049379a4f43e4e586c3903ba54627c87`.

| Injection | Observed verdict | Exact evidence |
| --- | --- | --- |
| Compile-valid wrong value | Factory `test-fail`, no reproduction or admission | wrong-prefix-2 report, package root `54db8393...` |
| Public C23 function renamed | New package passed both stores; earlier client failed to compile | interface report, package root `c4046871...` |
| Dependency root introduced without installable dependency | `DEPENDENCY_LOCK: dependency-unresolved-root` at `add_plan_a` | `pilot-drift.report.json`, package root `1a7d6c12...` |
| Old report paired with revision 3 source | Audit refused package-root mismatch | Revision 2 report root `6a6756b7...`; revision 3 source root `49d91489...` |
| Receipt id contradicted in copied report | Audit refused differing quick receipt ids | revision-2 contradictory report |
| Build worker killed with signal 9 | Factory refused `build worker exit 137` | `pilot-deadworker.report.json` |
| Publisher process killed before publish commit | No report; rerun on same stores passed | `pilot-deadpublisher-recovery.report.json` |
| Same release dispatched again to same stores | Full duplicate run passed in 11.265 s; four object-cache hits, zero misses | `pilot-duplicate.report.json` |
| Publisher key changed to mode 000 | Factory refused `Permission denied` at sign | `pilot-revoked.report.json` |
| 16 MiB virtual-memory limit | Factory refused CLI output allocation | `fixed-resource.report.json` |
| Report copied without its receipt stores | Audit refused unavailable quick receipt | partial report |

The pilot package and report roots for its original injection set are in
test-tmp/factory-qualification-pilot-20260924/faults.tsv (SHA-256
`dffc27a16eadff58984d733b66a420b471929d54821367c82fb7dbecc60cae7a`).
Publisher death produced no report; the recovery report is a distinct object.

The initial memory-limit trial returned an invalid report because the failure
path logged an allocation error but passed uninitialized text into the step
report. `pf_cli` now sets the explanatory error before each early return. The
same 16 MiB trial returned a parseable failed report with
`zcode package publish plan: CLI output allocation`. No gate was weakened.

The interface counterexample renamed the public `history_prefix` function to
`history_prefix_v2` in the header, source, and current tests. The factory's
two-store report was successful, while the previously accepted client failed
to compile under `-std=c23 -Wall -Wextra -Werror -pedantic` because the old
declaration was absent. The new source SHA-256 was
`db52c7385ceb59db123a345c582d4eee8a5b9613e5533bb971ee223b32667cb2`,
package root `c4046871117d6e378f361495342166b2bcfbfdb21e8d0932e484c79092e1fbe1`,
installed archive SHA3-256
`002248d5c62898d48f72037c172c671905cad1c1a646e79b9d7393d27464dd9c`,
and replay report SHA-256
`95d6ae9bcd9d8b8642e5aecafaf268a8d438feb0a6e83a4b0cc6444cfbaa41f4`.
The report proves its own exact package; it does not claim compatibility with
older clients. This is a required additional acceptance check for an evolving
application.

For pilot revision 2, `add_commit_a`, `reproduce_build_a`, `add_commit_b`, and
`reproduce_build_b` consumed 13.825 s of the 18.389 s wall result. Duplicate
dispatch consumed another 11.265 s on the same exact release even with cache
hits. These timings were under concurrent node builds. Offline `storage_ack`
returned a disclosed DHT refusal in both stores; no hosting claim followed.

## Fresh-source repetition and sequential limit

The final worktree build passed `make -j8 z23 zclassic23-package-verify
tools/package-factory`. Fresh executable SHA-256 values were
`e59a8c7c42e0fedfaa41e7ad0f4ba12bda179aa90572b2254cbb453ea578c1ca`
(factory), `c6a35cc16b824533b1b1259480c6e598ec53a760ba8916fc852c8b44b036daf1`
(node CLI), and
`72b1a6a4487a5b7cb10e53fe0286121855c6811e03e4bbfa2ced1d0902620672`
(confined verifier). `tools/package_factory.c` SHA-256 was
`d461fac20da928e7fe1ac2669e46aed4d73a8985ec06102db29b409761a095cc`.
The fresh ledger is
test-tmp/factory-qualification-fresh-20260924/ledger.tsv (SHA-256
`936534f108e78b9b67d7f5b916eda03f1c86be45708d11e1d725bbc8ad3b87d7`).
Its report roots and receipt ids are in that ledger; fresh fault report roots
are in `faults.tsv` beside it (SHA-256
`880739a5120276b907eb5bc068e3223b030ffbdbe5f86cceda077699721f3c61`).

The four fresh cases again counted 4 generated, 4 buildable, 4 previewed,
4 tested, 3 locally verified, and 0 operator accepted. Wall seconds were
4.383, 4.343, 4.425, and 1.208 for revisions 1, 2, 3, and the wrong revision
2; total wall 14.359 s, user CPU 7.585 s, system CPU 4.723 s. Source roots,
package roots, receipt ids, and archive SHA3-256 values matched the pilot.
Fresh revision 2 spent 3.411 of its 4.343 s in the four store build and
reproduction steps. A repeated exact release still ran the full factory:
its second report recorded 2.499 s and eight object-cache hits.

One evolving fixture directory was then generated, compiled, and tested at
every revision 1..100. All 100 local tests passed, each checking every
previous prefix. Its ledger is
test-tmp/factory-local-100-20260924/ledger.tsv (SHA-256
`735136385ed05acfd914acf8362a558c121231aa9962fd3f010c6ae93fd0ce27`).
Those are local build/test verdicts, not 100 factory admissions. The final
revision separately passed the fresh two-store factory in 6.051 s while
full lint was active. Its report SHA-256 was
`0dca4253b44f07864819b57885dc2b6e3ea935aaa100119ac9c562ba7f142a92`;
the package and archive roots are above.

Using the same publisher key and the same two stores, revision 1 was
published, installed, tested, and reproduced. Revision 2 was refused at
`publish_commit_a` with `PUBLISH_FREQUENCY_LIMIT`: the key's ISO-week tier
allowance was exhausted. The two report SHA-256 values were
`3ccb4b990cc29a6653461c909ac4649495104da75799e356654f072d42092d4e`
and `629bc7d7f2334f224f5bcdad5c34dbd73a770ebf145c6c0c61cf04a1a6fe7445`.
The first archive remained byte-identical in both stores at SHA3-256
`66fa0097c390ab767740bf34d695519d1ad1acd13fd35cd8975fed5d31d2afdb`;
revision 2 was installed in neither store. This proves preservation of the
previously accepted artifact after the refused change. It also establishes
that the present full factory path cannot accept a rapid same-publisher
sequence of 100 releases.

Throughput and acceptance blockers, ranked by the observed effect:

1. The weekly publisher limit stops the second same-publisher release.
   The Commons policy owner is `contexts/commons/modules/vcs/src/package_policy.c`.
2. Two-store confined build and same-host reproduction consumed 3.411 s of
   the 4.343 s fresh revision-2 run. The factory and package-verifier owners
   control this path.
3. Duplicate dispatch still consumed 2.499 s on the second exact release.
   The factory journey owner controls this path.
4. Current-version tests accepted an interface-incompatible package. The
   Commons acceptance owner needs a prior-client compatibility check where a
   release claims to preserve earlier application behavior.

The highest-leverage product fix is an exact-root local candidate journey
through the existing prepare, build, test, preview, and reproduce authorities,
with publication as a separate final action under the unchanged frequency
gate. That permits rapid revisions and exact local acceptance without
misrepresenting each intermediate edit as a publicly released version.

## Real application boundary

The native `dev app list` command returned blog, social, and yardsale.
`dev app describe blog` reported `authority=definition-only` and
`contained=[runtime_authority,publication,deployment]`; that catalog alone
does not preview or accept a running application. SkyCombat is the repository
application with a separate C23 binary target. On this checkout,
`make -j8 game-check` failed under `-Werror=unused-but-set-variable` at
`apps/skycombat/src/models/test_multiplayer_complete.c:85` (`frame`). That
source file's SHA-256 is
`9a60fc7e6b560a1c875c33a6319fe414e5ca888ce587610bc9b6ba9aa4e82280`.
The registered `make -j8 t-fast ONLY=skycombat_models` group passed 1/1,
with 13 model assertions and no skipped tests; its test body took 22 ms.
Neither command connected the evolving package candidate to SkyCombat, so
there is no real-app preview or local application acceptance in this report.

## Physical-host reproduction and SkyCombat package trial

The operator selected SkyCombat as the real application and authorized the
existing development SSH hosts. Peer A and Peer B each executed a bounded
read command on the other with host
keys pinned to this operator's existing trusted keys. A fixture object sent
from Peer A to Peer B retained SHA-256
`917d9fda1ca2d18fbc3567b61b797aac677a5d01375e65ff1ea9719bc194f048`;
an object sent in the reverse direction retained SHA-256
`b365b2ed53000da5b431d09a8e761c355dea67882cd3a91e0136729327f4f35d`.
The route receipt SHA-256 is
`174e689fd6644e2e4fd7986e902a7acee19d911a33c6b54d002f5e70acfc26cc`.
Only inert qualification objects crossed during route preflight.

The two hosts then received the exact revision-2 Commons store objects and
the same frozen verifier executable, SHA-256
`72b1a6a4487a5b7cb10e53fe0286121855c6811e03e4bbfa2ced1d0902620672`.
Both ran full Landlock/seccomp confinement, built and tested package root
`6a6756b750b33e840a4f165f84558ac157578463d8664b350058e84f83e370ff`,
and independently emitted identical 503-byte build reports, SHA-256
`f1cd97d744247ea3f861460c556ae0d1555e1473089e4912d1695861811fdd9b`.
Their archives were byte-identical, SHA3-256
`3c4c1d1c2f44f9181110c1b74a5557e692051fe3920e8e42c68b3c4a0cd35186`.
Peer A rebuilt against Peer B's report and the verifier returned
`reproduction=MATCH outputs=3` in 0.813 s. Initial independent builds took
0.909 and 1.182 s wall time. Both hosts reported GCC 14.2.0; Peer A reported
Clang 20.1.8 and Peer B Clang 18.1.3. The local publisher recorded GCC
16.1.1 and emitted archive SHA3-256
`cddb295f76a91d76463cb73dae9c3e5bbfe9dacc78fa74a6883f52d855f26962`;
the current local Clang reports 22.1.6.
Reproducing against that local report refused with `output-hash-mismatch`
(exit 6). The differing toolchain cohort is observed; the full cause of the
archive byte difference was not isolated. The physical-host match is
independent reproduction for these two receiving hosts, not operator acceptance
or a proof that the original GCC 16 release reproduces there. The isolated
remote work directories were removed after collecting reports and archives.
Both archives have normalized member ownership and timestamps; the local
`gcc_0_0.o` and `gcc_0_1.o` members are 1264 and 1320 bytes, versus 1280
and 1336 bytes on both receivers. Disassembly of `gcc_0_0.o` shows
`endbr64` on the receiving hosts and none locally. The receivers'
`/usr/bin/cc` predefined `__CET__=3`; the local compiler defined no
`__CET__`. This identifies one concrete generated-code difference, not
every byte difference or a portable compiler fix.

`tools/dev/skycombat-factory-qualification.sh NEW_OUTPUT_DIR` copies the
real SkyCombat aircraft source and header byte-for-byte into an isolated
package. A C23 test linked with `-lm` passed and printed
`flight=60.000 boost=110.000 wrap=-999.000`. The original app source
SHA-256 is
`db757c6e927f880b6fd921ba6f673a9b7c77e172823510709c272c3574bbbc06`.
The factory prepared package root
`9a2c62d39213dd36a2e05ca064ac011d100ff429f92eecedd2f2682307495acc`
with recipe root
`d40194f24db81b34b3400fab47c9cdce6541d8a92fb4a46ff69d295168437fba`,
then refused install at `add_commit_a` with
`BUILD_NOT_INSTALLABLE: verdict build-fail`. The report SHA-256 is
`9051af5e1bd10b6b92e85ba0f734f8ac0221c85c47e0476735f9f7fabc173c20`.
The native `zcode package recipe` result reported
`allowed_system_libraries=[]`. The package verifier's first bounded
linker error named `aircraft_update`;
a direct link of the same package without `-lm` named its unresolved
`sinf` and `cosf` calls. The recipe has no `libm` declaration even though
the verifier supports an allowlisted `libm` recipe entry.
`contexts/commons/modules/vcs/src/package_prepare_schema.c` closes package
metadata without a system-library field, and
`contexts/commons/modules/vcs/src/package_prepare.c` never adds a library to
its derived recipe.
The release-critical fix is to carry a bounded, author-declared `libm`
choice into the exact recipe and prove the SkyCombat build and wrong-behavior
gates under confinement. This is the current exact-root app factory blocker.
The test is a model observation,
not a window preview; no SkyCombat candidate was published or accepted.

The isolated control replay is
`tools/dev/skycombat-libm-control.sh FACTORY_EVIDENCE_DIR NEW_OUTPUT_DIR`.
It uses the repository's canonical recipe parser, adds only its frozen
allowlisted `libm` id, serializes the result, and binds recipe root
`681deda25b57cad2ceca6771ce5fb201b17b0ce32e576f58e4e0279fd68047b9`
to the unchanged SkyCombat source root
`9a2c62d39213dd36a2e05ca064ac011d100ff429f92eecedd2f2682307495acc`.
The separate verifier completed its full standard profile under
Landlock/seccomp with `result=test-pass outputs=4 isolation=full` in
1.717 s wall time. Its build-report SHA-256 was
`7311775fc2f9b3d72f998a7f5a427d0e80f91b0fa0e881eadc4cbbad053ae556`;
the dependency-plan SHA-256 was
`8619dca78782673cff52bb1e860167b936174edfd6420f832d306754742b2dce`.
The replay then changed one copied boost expression from 50 to 0. The
compile-valid source SHA-256 became
`ca7526b327dcbbc3d1f18cc902911728717bf5a32d50f810aa61c5a5e18c5a0b`,
with new package root
`9abb3e1ee4a1daaa3b9a65eebeea728aba6dfe89ae76238a70cedbc52e66994d`.
Its local model test exited 1, and the confined standard verifier refused
the same recipe with `zbuild-package-standard-refused=1` (exit 6) in
1.459 s. This establishes that the bounded library declaration reaches
the behavior gate. Neither control recipe entered the publisher's canonical
release, either Commons store, a running game preview, or operator acceptance.

## Two-host SkyCombat control replay

The exact control source was transferred to two consenting development hosts
through the previously qualified bidirectional routes. The input tar SHA-256
was `5cce0dba16b3ee6bb1db7461a78767a8a4453ffa9db41dc7299c17a96ae251b6`;
each receiver checked that digest before extracting it. It contains the
unchanged and wrong-behavior package directories, canonical `libm` recipe
SHA-256 `29f58718561e2683eed540e2de5c79a6a5320cfabfd5f597d5d0cb69cfb94276`,
frozen verifier SHA-256
`72b1a6a4487a5b7cb10e53fe0286121855c6811e03e4bbfa2ced1d0902620672`,
and `tools/dev/fixtures/skycombat/remote_run.sh` SHA-256
`f61bbabe15dd2ba0771bef07a248ef0fd27c5abc4a351bcb99e9c8771e162703`.
The input is assembled from the output of
`tools/dev/skycombat-factory-qualification.sh`, followed by
`tools/dev/skycombat-libm-control.sh`; the frozen runner checks the recipe
and verifier bytes before it runs. On each receiver the bounded command was
`cd ISOLATED_DIR && tar -xf bundle.tar && ./run.sh`. No node or canonical
datadir was used; the isolated receiver directories were deleted afterward.

Both receivers reported GCC 14.2.0 on AMD Ryzen 9 7950X3D and full
Landlock/seccomp filesystem, network, and rlimit confinement. Each independently
passed the unchanged package root
`9a2c62d39213dd36a2e05ca064ac011d100ff429f92eecedd2f2682307495acc`
with `result=test-pass outputs=4 isolation=full`, and refused the
compile-valid boost regression root
`9abb3e1ee4a1daaa3b9a65eebeea728aba6dfe89ae76238a70cedbc52e66994d`
with `zbuild-package-standard-refused=1` (exit 6). The wrong run printed
`flight=60.000 boost=60.000 wrap=-999.000` and failed its declared model test.
Good/wrong wall seconds were 1.574/1.488 on Peer A and 1.563/1.376 on
Peer B. The frozen output manifest SHA-256 is
`ee2d09a8c60111bf69e581137417c8817f3f830b62933006e4633c32f794038a`.
All five emitted files matched byte for byte: build-report SHA-256
`e212bc6060500af3487034533db06444f0ce5909549667d54e158f6367da0f05`
and archive SHA-256
`8c1017874fcb6f7e1b8fc11496d0357955cbc8a75a0fac354296a428843195ed`;
the three public headers matched as recorded in the output manifest.
The returned Peer A/B evidence tar SHA-256 values were
`e0e0363f3f7028aa3766f37028e5042a92dfe2ff07a34a5a5c03ca285f2d4374`
and `775e9774090428eb76a9d0b02241859ff589a8567a44d98bf62db45e1b91fedd`.
Their stdout differs by the isolated emit path and performance counters.

The local GCC 16 archive SHA-256 was
`a928777a5ad75537bf99e5dfbe034fac3b3b2ab5c5fb75160d589c8196933176`,
so these two receiving hosts establish a GCC 14 cohort match, not
publisher-to-receiver byte identity. Candidate mode rejects
`--reproduce-against`; the exact emitted file comparison is independent
reproduction evidence but not a formal Commons reproduction receipt. The
verifier reported `source_bytes=unknown`; no byte-volume cost is inferred.
This replay did not observe a running game window, publication, local operator
acceptance, or resident-node health on the receiving hosts.

## Current-main integration replay

At 2026-09-24T05:44:32-04:00 (2026-09-24T09:44:32Z), the qualification
branch integrated reviewed `origin/main` commit
`3bde5b5b1fcb70887be701f8fb67b432b9e8f59c` into signed source commit
`78d9a087f0576052ef7425fb79e7f2104fcc146a`. The same fixture and
adversarial scripts were then exercised against the integrated source. The
commands below use isolated directories under `test-tmp/`:

```bash
make -j8 z23 zclassic23-package-verify tools/package-factory CC=gcc
make -j8 t-fast-exact ONLY=test_dev_land T_FAST_EXACT_ARGS=--no-cache CC=gcc
make -j8 t-fast-exact ONLY=test_zcode_dev_objects T_FAST_EXACT_ARGS=--no-cache CC=gcc
make -j8 t-fast-exact ONLY=test_fastobj_carrier T_FAST_EXACT_ARGS=--no-cache CC=gcc
make -j8 t-fast-exact ONLY=test_resident_launch_contract T_FAST_EXACT_ARGS=--no-cache CC=gcc
tools/dev/factory-evolving-qualification.sh test-tmp/factory-merge-20260924 3 build/bin
tools/dev/skycombat-factory-qualification.sh test-tmp/skycombat-factory-merged-20260924
tools/dev/skycombat-libm-control.sh test-tmp/skycombat-factory-merged-20260924 test-tmp/skycombat-libm-merged-20260924
make check-architecture-tree CC=gcc
make -j8 lint CC=gcc
```

All four focused test groups passed without skip or failure. The resident
launch test measured 20 headless `ztasks` edit-to-visible-behavior samples:
p50 1,198,089 us and p95 1,310,311 us. Its three injected behavior, crash,
and interface failures retained accepted state and undo history. This is not
a SkyCombat window preview. The current-main factory replay again produced
three good roots and one compile-valid wrong root: generated 4, buildable 4,
locally previewed 4, tested 4, locally verified 3, operator accepted 0.
Good-case factory wall seconds were 4.716, 5.011, and 4.974; the refused
wrong case took 1.399 s. Eleven separate fault scripts completed with their
expected observations: refused changes, an interface regression that the
factory admitted, or duplicate work. The cases were `wrong`, `interface`,
`stale`, `contradictory`, `partial`, `dependency`, `worker`, `publisher`,
`duplicate`, `revoked`, and `resource`. Architecture placement passed and
full lint passed 212/212 gates in 429.644 s wall time. No gate was relaxed.

| Integrated evidence artifact | SHA-256 |
| --- | --- |
| Factory ledger, including exact source, package, recipe, report and receipt roots | `71803b85f3fb974780ef9c30c45d8740a83330e15965f5d1503d820619349498` |
| `test_dev_land` log | `2aa0d0b61102f63ba0037e670ce76ec52cc7699d22f55b631efa7b4e263d35d0` |
| `test_zcode_dev_objects` log | `433377f8e490af0a4a557b5a263ab17e7a5fe1a52bb306840b52d6aa73e7a5` |
| `test_fastobj_carrier` log | `e13fe5764742afda4d8abcbd392204fa065e2a0d982b485f0c10d3662e4ec1f2` |
| `test_resident_launch_contract` log | `96fe4a5e2f5f79daa7ce03fe277a66e330e63d07f211925b3b2c7f46a48bfe1c` |
| Full lint log | `1b3efe3eded25258b661797bc16bcde5862611c53dd4d682160eb65029d7bad2` |
| Built `z23` executable | `d548a1a01096d943c42207a0639e2d79c2a359789360631465d79b52f4cf47b7` |
| Built package verifier | `d9ffca3e11b41786718f123854af008d65195cae71c55a7d13b93c81868d64a4` |

Current-main `dev land attach` now binds a signed local Git landing intent
to its target, proof digest, and bundle. Its code at
`tools/command/native_dev_land.c:5691` explicitly describes that intent as
separate from Commons publication. The canonical Commons publication store
entry point is `zcode_publication_store_accepted` in
`contexts/commons/services/src/zcode_lane_service.c:461`; the local land
path does not call it. Therefore passing the Git landing test is evidence
for local signed Git intent only. It does not promote any SkyCombat package
to canonical Commons publication, remote receipt, or operator acceptance.

## One-worker 100-transition factory replay

On 2026-09-24, source commit `b0f686aa2182f72f90306d22b182c3cfad01e746`
ran every revision 1..100 through the real two-store factory in order,
using one invoking worker and one shared object cache. Fixture generator
SHA-256: `917d9fda1ca2d18fbc3567b61b797aac677a5d01375e65ff1ea9719bc194f048`.
The host was an AMD Ryzen 7 PRO 8840U with GCC 16.1.1 20260430 under
`-std=c23`. No node or other local build ran during this timing sequence;
node-health impact is unobserved for it. The host's `devbuild` scheduler was
unavailable, so this was bounded by one invoking worker, not a scheduler slot.

Run: `tools/dev/factory-evolving-qualification.sh test-tmp/factory-100-real-20260924 100 build/bin`.
For each N=1..100, run `tools/dev/factory-evidence-audit.sh
test-tmp/factory-100-real-20260924/revision-N/report.json
test-tmp/factory-100-real-20260924/revision-N/pkg
test-tmp/factory-100-real-20260924/bin` with N replaced by its integer.
The audit passed 100/100: recomputed package and recipe roots matched
reports, quick and standard receipt ids and bytes matched across stores,
and both stores reported reproduction. Each C23 test exercised every
previous history prefix.

The 101 cases, including the expected wrong-prefix-2 refusal, counted
generated 101, buildable 101, local model preview 101, tested 101,
locally verified 100, operator accepted 0. The 100 good factory calls
totalled 439.897 s wall, 241.802 s user CPU and 140.755 s system CPU;
wall median was 4.242 s, p95 5.245 s, range 3.910–5.461 s.
No running application UI was previewed by this fixture.

| Artifact | SHA-256 or package root |
| --- | --- |
| 100-transition ledger with every source, package, recipe, report and receipt root | `cd3be86187b2131cab7a590aad35423baeaacb8dad139fbadd78ba04b22c669b` |
| Independent source/receipt audit log | `12ca158d4e9c0e5b491a501501745ecda02b623f4dc1a8548e87b9e7ad861941` |
| Frozen executable digest manifest | `7cc2ecf21a76add3c1e1069ead3822f2a0da063251e10f50721ba622ded419b2` |
| Final good source SHA-256 | `7f651ac07bd563b55fc63774582c0b79423a27d078e2b03e42376a673bdfc026` |
| Final good package root | `f424e549c260ef2206315d34ac62f7b5477bc63085517d7d802c69b2a73d5b01` |
| Final good report SHA-256 | `3e791e645f9e5f2578c2e1d57e7742420885e000faee9df09320500c61b30c5d` |

The 100 revisions used separate store pairs. They prove sequential source
evolution and local factory qualification of each version, with earlier
behavior checked. They do not prove 100 successive publications or accepted
versions in one store. The unchanged frequency gate still refuses a second
same-key weekly release in the shared-store trial above.

A further revision-100 wrong case changed the second value to 99. It
compiled cleanly under C23 and `-Werror`; the test printed `history prefix
2: expected 3, got 100` and exited 1. The factory refused package root
`de712089753ccea3dbebf4d942c99813ccbd0588e77a9d3617f4f4ffcb6c594a`
at `add_commit_a` with `BUILD_NOT_INSTALLABLE: verdict test-fail`.
Source SHA-256: `297b05ce53f3c5ff713bf7b3d012bf67878b9fd8460be870c19c01af400306de`;
refused report SHA-256: `cbcae72ffad5981e08867bbc21b43614922822a8225ff13d1e04223adc347187`.
The exact compiler, test, and factory outputs are retained under
`test-tmp/factory-100-wrong-final-20260924/`.

The same checkout's `make -j4 game-check CC=gcc` failed before linking
SkyCombat. GCC reported `apps/skycombat/src/models/test_multiplayer_complete.c:85:9:
error: variable 'frame' set but not used [-Werror=unused-but-set-variable=]`.
Build-log SHA-256: `fc8a7101af4dd9edc3fac616bf38d4eca594856458e31d21fcdcfd68aea0f0fd`.
No game binary was built, so the available X display did not provide a
window preview. The SkyCombat source owner needs a clean C23 game build;
the Commons recipe owner needs the bounded `libm` declaration demonstrated
by the isolated control before exact SkyCombat preview and acceptance.

## Physical-host revision-100 reproduction

Peer A and Peer B each passed a bounded SSH command and received the exact
input tar SHA-256 `f1750ba73455ed1869fa16b9506f5c49978648f910cd0cdbd7b6a55f7cdc9ffc`.
Each returned the same tar byte for byte before execution. The frozen
runner SHA-256 was `d97435cce4b3df5f9997f72baf1d845fa9066dcb219765b140bc7f1e541494d3`;
its stripped verifier SHA-256 was
`cc5c695bff576470771dfa9d0d556a1d0d635863d2f772ed96ef5a46187bd9c9`.
The input manifest SHA-256 was
`5e0bb0e458309c44f325d7d9c4b6d96747f689015c631ddb746e736906b12a07`.
Only frozen source, recipe and verifier inputs crossed to isolated temporary
workspaces. Both peers checked every input SHA-256 before invoking the
standard verifier with full Landlock/seccomp isolation.
The returned evidence is retained under
`test-tmp/factory-100-remote-20260924/`.

Both peers ran GCC 14.2.0 on AMD Ryzen 9 7950X3D. Each passed the final
good package root `f424e549c260ef2206315d34ac62f7b5477bc63085517d7d802c69b2a73d5b01`
with `result=test-pass outputs=3 isolation=full` and refused the
compile-valid wrong root
`de712089753ccea3dbebf4d942c99813ccbd0588e77a9d3617f4f4ffcb6c594a`
with exit 6. Good/wrong wall seconds were 0.874/0.689 on Peer A and
0.758/0.665 on Peer B. Their four good emitted files matched byte for byte:
output manifest SHA-256
`6f3782b8d9a676de5f30b5355cb1857c5c5f4c23f0e5a0243ebb26c29f512397`,
candidate build-report SHA-256
`85e9ccbc2e8af2061ab8fdb592f0f58d530bab98418474e68ee2980378148598`,
and archive SHA-256
`3f6122b9c0216b26f5b860a3fec7c0d7cbaddd000e80641cee66c6d683dba9ab`.
The returned Peer A and B result tar SHA-256 values were
`ddcfb20946ff392039df865e022d9af5da6aa26889343ed6cac8f02e63f7f381`
and `29f5d898f87f51a6453a7c3b53f54f9eabe56f8b059503467938d43604b2b3e5`.

Peer B then received the exact local store objects and Peer A's build
report. Its store-mode verifier returned `reproduction=MATCH outputs=3`
against that report and all three installed outputs matched Peer A's bytes.
The formal stdout SHA-256 was
`aaa8dcc4ce302838f84db0443a8ec73e6db688b82c2e70ad88403e70f9400570`.
The store-mode build-report SHA-256 was
`c2def8a96f56e6da608fb42aad8a0276ef9c4008e64a613d0e84505031429f79`:
it differs from the candidate report in recorded compilation flags, so
the claim is a formal output-set match, not identical report bytes.
The local GCC 16 publisher archive SHA-256 was
`70822fdb7db6949f08edf00758b60e951813c0c0e22138de05cca9eeb8a5e5e5`.
Publisher-to-peer byte identity is not established across that toolchain
boundary. No remote operator accepted or ran the library in an application.

## Isolated-node load observation

The 20-revision run used the frozen harness copy
`test-tmp/factory-node-health-20b-20260924/harness-run.sh` SHA-256
`05ca57213ecdd7117b320a2d76c9ea0d0f3ca49a14dd2879d1492f9d915ee522`
ran `tools/dev/factory-evolving-qualification.sh` for 20 revisions while
the guarded `isolated_node_env.sh` rail owned a throwaway regtest node.
The node used a private `/tmp` datadir, 39xxx ports, and a dead P2P sink.
It reached height-0 RPC readiness on attempt 17. No production datadir or
node was touched. The factory produced 20 good two-store verdicts and one
expected wrong-case refusal; good-case factory wall was 114.334 s and
user-plus-system CPU was 96.599 s. The node process was still alive after
the run. The factory ledger SHA-256 was
`9866abc8b88a8be46415c5b2789099dccea182fd0db8c6648d5a20855672b2f5`.

| RPC phase | Samples | Unavailable | Mean ms | p50 ms | p95 ms | Maximum ms |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Before factory | 100 | 0 | 10.800 | 11 | 12 | 13 |
| During factory | 553 | 0 | 11.501 | 11 | 14 | 21 |
| After factory | 1 | 0 | 12.000 | 12 | 12 | 12 |

Raw RPC sample SHA-256:
`0832a2b17a52eff527ad33327597e10e9c5eece78cd707ae961334fe26714506`.
The node log SHA-256 was
`4cb7ea5d1eb04eb9077f0f4de9867fd77b6bd0993e6244875722e7389ba6cf17`.
It contains 40 ERROR lines, including 12 before the factory's
2026-09-24T10:36:49+00:00 start. The pre-existing messages include
`catchup: final commit missing tip hash` and
`catchup: aborting (failed=1, restore_ok=1, indexed=0)` at height 0.
All sampled RPCs stayed available, but this was a disconnected height-0
node with an unhealthy catchup projection. The trial does not establish
chain-sync safety or a causal effect of factory load on those errors. The
recorded p95 rose from 12 to 14 ms under load; ordering, warmup, and
background work were not controlled enough to attribute that difference.
An earlier exploratory run under
`test-tmp/factory-node-health-20-20260924/` used the prior harness version;
the 20-revision run above used the frozen source named here. The tracked
harness subsequently gained an optional explicit port-base argument (SHA-256
`7572e3683f29f963fd61802e7d1b4e8ad816d3902e33e2a95d7f6598e22de7bc`).
Its one-revision smoke at port 39720 passed with the node alive after the
factory returned. That smoke does not replace the 20-revision load evidence.

## Real-package throughput sweep

`tools/dev/factory-throughput-qualification.sh` copied the existing
`z23/textstat` C23 package into isolated candidate roots. Eight cumulative
revisions added counts for digits, tabs, ASCII letters, high bytes, carriage
returns, spaces, NUL bytes, and newlines. Every revision retained the
package's earlier tests, added a direct assertion for its new operation,
and ran a separate C23 preview consumer that printed the new result. Added
source, header, and test lines were counted against the preceding revision.
Baseline lines and repeated dispatches were excluded from unique LOC. Each
factory job used two independent local stores and recorded source, package,
and report roots. Same-host factory success is a two-store proof, not a DEV
or release acceptance decision.

The initial exact-harness sweep is in
`test-tmp/factory-throughput-v3-c{1,2,4,8,16}-20260924/`.
Harness SHA-256:
`636be2167ad529e4c7e2c683e9c2aeb05fd574aea5ccac2de1f9277093c8f3be`.
C23 rusage helper SHA-256:
`e8299b12e6121a507b55537bca37ac404ed1a56d19cc6be5c4d9cb93c5ad94f7`.
Each output directory has executable hashes, compiler and CPU identity,
checkout SHA/status, UTC and local times, per-job reports, and a ledger.
The helper uses `wait4` to account for waited child CPU, maximum RSS, and
filesystem input/output block counts. These are block operations, not bytes.

| Concurrent jobs | Distinct edits | Repeated attempts | Two-store good / jobs | Generated → buildable → previewed → tested LOC | DEV / full accepted LOC | Batch wall s | Factory CPU s | Largest step mean ms |
| ---: | ---: | ---: | ---: | --- | ---: | ---: | ---: | --- |
| 1 | 1 | 0 | 1/1 | 14 → 14 → 14 → 14 | 0 / 0 | 3.360 | 2.957 | add-commit A 670 |
| 2 | 2 | 0 | 2/2 | 27 → 27 → 27 → 27 | 0 / 0 | 3.701 | 6.280 | add-commit A 715 |
| 4 | 4 | 0 | 4/4 | 53 → 53 → 53 → 53 | 0 / 0 | 4.109 | 13.744 | reproduce-build A 786 |
| 8 | 8 | 0 | 8/8 | 105 → 105 → 105 → 105 | 0 / 0 | 5.012 | 34.574 | add-commit B 952 |
| 16 | 8 | 8 | 14/16 | 105 → 105 → 105 → 105 | 0 / 0 | 7.742 | 96.225 | add-commit A 1560 |

The 16-way batch exhausted distinct work in this eight-edit workload: eight
attempts repeated existing source roots, factory CPU rose to 96.225 s, and
two attempts failed in `reproduce_build_a`. Both were exact
`fast cache CORRUPTION: existing entry ... differs from the freshly compile`
refusals (jobs 10 and 14); they were not reclassified as accepted.
The shared fast-object cache publishes an object and sidecar in separate
steps. Independent workers can see a pair while another worker writes it.
A per-key read/write lock was added in `tools/package_verify.c` while
retaining the byte-identity checks. The same 16-way dispatch then passed
16/16 with eight duplicate attempts in 8.260 s. Its ledger SHA-256 was
`e0676d6c2e9ed605cc10e6d003c12c572047a66e447265a672c034a2851f4fc7`;
the rebuilt verifier SHA-256 was
`bf33ff2f6bcc3ebc3dab11f9d3940b78803c1b2c134a344438ea06e53acd359e`.
This resolves the observed refusal in one rerun; it is not a statistical
reliability bound.

The largest factory step was add-commit on four batch widths and
reproduce-build on the four-way batch. Direct C23 compile and preview were
each below 60 ms per candidate through eight-way concurrency; factory wall
was 3.25–5.15 s per candidate. The two-store add-commit and reproduction
path is the measured wall-time owner. No production node was present during
this sweep. The earlier height-0 isolated-node probe above is a separate,
narrower observation.

### End-to-end timing after the cache repair

The final repeat used harness SHA-256
`d848eb083500342c4a324116d7b9296d1a43213f0a089e2f078c528c4a4368d7`.
`test-tmp/factory-throughput-v5-c{1,2,4,8,16}-20260924/` records both the
dispatch window and full harness wall time, including binary copying,
signer setup, candidate generation, compilation, preview, testing, factory
proof, and report aggregation. All jobs passed. The harness still generates
these deliberately small edits automatically; these service rates cannot be
extrapolated to human feature design or 10,000–100,000 accepted LOC per day.

| Concurrency | Distinct / attempted | Funnel LOC generated → buildable → previewed → tested → DEV accepted → full accepted | End-to-end s | Distinct edits/h | Factory CPU s | Largest step mean ms |
| ---: | ---: | --- | ---: | ---: | ---: | --- |
| 1 | 1/1 | 14 → 14 → 14 → 14 → 0 → 0 | 4.176 | 862 | 2.994 | add-commit A 703 |
| 2 | 2/2 | 27 → 27 → 27 → 27 → 0 → 0 | 4.396 | 1,638 | 6.301 | add-commit A 706 |
| 4 | 4/4 | 53 → 53 → 53 → 53 → 0 → 0 | 4.952 | 2,908 | 13.698 | add-commit A 774 |
| 8 | 8/8 | 105 → 105 → 105 → 105 → 0 → 0 | 6.034 | 4,773 | 34.176 | add-commit B 946 |
| 16 | 8/16 | 105 → 105 → 105 → 105 → 0 → 0 | 9.628 | 2,991 | 104.409 | add-commit B 1,606 |

The dispatch delay summed across jobs was 1.4, 2.8, 4.7, 10.9, and 23.7 ms
at widths 1, 2, 4, 8, and 16. There was no admission queue in this local
run: those figures measure fork-to-worker-start delay, while queue wait was
zero by construction. At width 16, maximum per-job RSS was 162,816 KiB,
and the verifier family reported 256 filesystem input and 85,424 output
block operations across attempts. The same width completed only eight
distinct edits, used 3.1 times the factory CPU of width 8, and reduced
distinct end-to-end throughput by 37%. This is workload and host contention,
not evidence of a universal machine saturation point. The ledger SHA-256
values by width 1/2/4/8/16 are
`f65ada900e7e38207be3fba36b50456f4b34529566c42a7bebc78e11fc06f8ba`,
`12fec4b186812171086c1f7125ebb028292a24e45da9dbc4a20bf9b0eb4cb7a5`,
`40e1b55fbc4a9937f440937b2a8d17c027f6381126a75e4da81f634f0ace5a8d`,
`d85b68d14c6a34d49eaedff4b1727cc6ba7043abf8e651db56cae7ff420fcefe`,
and `02dd83f150ac519b6cca014d96506527f3186c475d960f92491e758ff68280ee`.

### Node effect at width 16

The corrected node-health harness SHA-256 was
`c4ffbdc063128735c910fcd2e63e809277cafad7bc1b52cdf8896b9cbcc223cc`.
An initial attempt refused to run the factory because the new script lacked
its executable bit (`factory_exit=126`); it is preserved under
`test-tmp/factory-node-health-throughput-c16-20260924/` and is not a load
result. The fresh run under
`test-tmp/factory-node-health-throughput-c16b-20260924/` used a throwaway
regtest datadir and port base 39780. The node reached height-0 RPC readiness
on attempt 13, the factory passed 16/16, and the node remained alive.

| RPC phase | Samples | Unavailable | Mean ms | p50 ms | p95 ms | Maximum ms |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Before factory | 100 | 0 | 9.170 | 9 | 11 | 12 |
| During factory | 41 | 0 | 19.512 | 18 | 34 | 44 |
| After factory | 1 | 0 | 9.000 | 9 | 9 | 9 |

Raw RPC SHA-256 was
`81a61626ec1ad58237cb6bc35099c4accdfc97661410fbf7c1121be49794e5b5`;
node-log SHA-256 was
`2896aafb8aae081c6bb9af568532c8b2e77634f719a301bf50d2e9640c99f5c8`;
factory-ledger SHA-256 was
`72d587f59bf90ef86d5cab8fb370dc1e0601d3a3a62d32f17a3d78ee407d351c`.
Twelve of fourteen node ERROR lines preceded the factory start at
2026-09-24T11:05:54+00:00. The pre-existing errors include failed catchup
and missing tip metadata. RPC remained available, but p95 rose from 11 to
34 ms under load. This isolated, disconnected height-0 node cannot establish
chain-sync or production-node safety; the timing association is not a
controlled causal estimate.

### Ranked blockers and next fix

1. The factory's two sequential add-commit and reproduction paths consume
   most candidate wall time. At width 8, add-commit averaged about 1.9 s
   across stores and reproduction about 1.7 s. Owner: the Commons package
   factory and verifier implementation. Profile these steps internally
   before changing their proof contract.
2. Duplicate exact-root dispatch consumed eight of sixteen width-16 slots.
   The current local harness has only eight useful revisions, so the extra
   eight are measured waste. Owner: the existing Commons task/queue authority.
3. The node RPC p95 reached 34 ms at width 16, compared with 11 ms before
   load. Owner: the package admission and host resource policy; height-0
   evidence does not set a production threshold.
4. SkyCombat's canonical libm declaration and game build remain blocked as
   recorded above. Owner: the application package and build recipe. No
   SkyCombat LOC entered either acceptance count.

The highest-leverage next fix is exact-root admission in the existing queue:
deduplicate pending candidate/recipe roots before dispatch and budget active
package proofs against node headroom. In this measured width-16 batch, it
would remove eight repeated factory attempts before consuming CPU. The
post-fix cache lock preserves the byte-identity gate when distinct workers
still share an object key. The current data do not prove the proposed
admission policy's throughput or node-health result; that requires a fresh
width sweep with more than sixteen distinct useful edits and a healthy node.

### Current timing source after lint correction

Full lint found that the first C23 rusage helper used a direct clock outside
the platform layer. The helper now records only waited-child rusage; the
shell harness measures wall time around it. Its explicit source purpose and
regenerated capability inventory closed the other two full-lint failures.
The corrected helper SHA-256 is
`4aaade25997e453e18687643b238f21a1b9b956209171fa85a3a1c86b1d130ea`;
the corrected harness SHA-256 is
`3198e7cd05662bb2a7c6f425a9b5942d625474f9b43b2b7159c0130fafcdb2e1`.
The repeat under `test-tmp/factory-throughput-v6-c{1,2,4,8,16}-20260924/`
passed all 31 factory jobs. Its own end-to-end clock includes candidate
generation and report aggregation.

| Concurrency | Distinct / attempted | Funnel LOC generated → buildable → previewed → tested → DEV accepted → full accepted | End-to-end s | Distinct edits/h | Factory CPU s | Largest step mean ms |
| ---: | ---: | --- | ---: | ---: | ---: | --- |
| 1 | 1/1 | 14 → 14 → 14 → 14 → 0 → 0 | 4.900 | 735 | 2.985 | add-commit B 778 |
| 2 | 2/2 | 27 → 27 → 27 → 27 → 0 → 0 | 5.727 | 1,257 | 6.254 | add-commit A 894 |
| 4 | 4/4 | 53 → 53 → 53 → 53 → 0 → 0 | 6.237 | 2,309 | 13.701 | add-commit A 947 |
| 8 | 8/8 | 105 → 105 → 105 → 105 → 0 → 0 | 7.305 | 3,942 | 32.903 | add-commit A 1,098 |
| 16 | 8/16 | 105 → 105 → 105 → 105 → 0 → 0 | 10.748 | 2,679 | 99.215 | reproduce-build A 1,719 |

Width 8 again had the highest distinct service rate. At width 16, maximum
per-job RSS was 162,696 KiB, with 256 filesystem input and 57,808 output
block operations across the sixteen factory attempts. Total fork-to-worker
dispatch delay was 21.0 ms; there was no queued admission. The five ledger
SHA-256 values in width order were
`6ec091d8838f6759ca50b9bb6584305b77ecd9b2d56f81f11c79b3bfe34e4239`,
`f6ef945fbbb89f984020b0d1bda1abee7ddc657b5d38043ad14c7e26a37e5e7c`,
`a2756ee0943d0eb76a585e7dd1114a548c2c44d029441c977f343a017ccdc677`,
`08438dda6368852d6a3ff592fcde303dbabe4ae1f0a64c681fec903b3434075b`,
and `0c0c85f06b196e6779c9926674f96978affe0c384f201d8b8afac06befdc4b38`.
This source revision did not alter the candidate or factory logic. The
differences between the two five-width timing sweeps are observations under
different host activity, not a causal performance change.

## Fast feedback integration counterexample

After merging upstream commit `c9e2298920238e5b05a00991e185cf37a91fbb13`,
`make ff CC=gcc` refused during its compile rung in 2.682 s. The parent
`Makefile` supplies a 64-character all-zero `BUILD_COMPILER_ID` when the
`ff` target selects no compile epoch. The new fast-path forwarding condition
accepted that value by shape and passed it to nested Make. The nested epoch
session independently derived
`09027de7fdfe4d038af6dc0731d75c200adf2b01842479022a977ce39d61eef6`
and refused the mismatch. This was a real fail-closed counterexample, not a
compiler failure. The original command log SHA-256 was
`35e5201bd5cf94fd311349aacc61fc7d9c40f6c20faf3e66eb73d65bcc8bfbf2`.

`tools/agent_fast_ci.sh` now forwards only a nonzero 64-digit fingerprint;
when the parent selected no epoch, nested Make derives and verifies its own.
The corrected source SHA-256 is
`f6aefa7188dd6294c8eff8135593712730c09487c9c5f6a5b54ff6863a9c163e`.
The identical `make ff CC=gcc` command then passed. Its measured rungs were
44.447 s compile, 950.794 s source-wide tests, and 13.998 s lint-fast.
The runner reported 1,166 groups run, 0 cached, 9 gated, 0 failed,
19 self-skips, 0 environment-unobserved, and 1 load-flaky classification.
These are fast development feedback results, not release acceptance. The
passing command log SHA-256 was
`6301e0c1253993d12757e87cfa78175f2bfa519bbca70f02dbfdd0504448b210`.

For the full candidate-to-DEV-feedback path, the 950.794-second source-wide
test rung is the largest measured wall-time blocker, far exceeding the
3–9-second per-batch factory work above. Owner: the registered fast test
runner and its exact receipt cache. The single highest-leverage speed fix is
to reuse test observations only when their complete source, toolchain,
fixture, and policy inputs are proven identical, while preserving every
required group and fail-closed invalidation. Its attainable gain remains
unmeasured here. The exact-root queue admission fix above remains the
highest-leverage package-dispatch fix; neither proposal changes DEV evidence
into release qualification.
