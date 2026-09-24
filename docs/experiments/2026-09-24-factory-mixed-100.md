<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# One hundred cumulative mixed C23 package revisions

Date: 2026-09-24. Checkout: `bdcfd74d36fbfab109fae428817508063ab134ac`.
Host: AMD Ryzen 7 PRO 8840U; GCC 16.1.1 20260430, strict `-std=c23`.
The run used the real two-store package factory in isolated directories. No
resident node was running on the benchmark host. Its node-health effect was
therefore not observed; the separate isolated-node load experiment bounds only
height-0 RPC responsiveness under combined proof and package load.

The original 100-revision value-history corpus remains unchanged. This new
corpus adds one value-source line at each revision and introduces four
cumulative milestones in the real tiny-lines C23 package:

| Revision | Change | Preserved behavior checked |
| ---: | --- | --- |
| 25 | Add bounded range-sum API | All prior prefix sums and every valid range |
| 50 | Reuse range API in prefix implementation | Same prefix and range tests |
| 75 | Add text/JSON terminal client and bounded formatter | Every earlier formatted count and invalid-buffer refusal |
| 90 | Reject noncanonical decimal input in the client | Earlier valid outputs; whitespace/sign/overflow refusal |

The accepted source progression never removes the original prefix API.
Revision 90 corrects the earlier client's acceptance of a leading space:
revision 89 returns success for `history-cli ' 75'`, while revision 90 returns
exit 2. The correction retains all valid decimal results. Separate
compile-valid candidates change prefix value 2 to 99 or change the UI label
from `sum` to `total`; both fail tests and the factory gate.

## Reproduce and bind the result

```bash
make -j8 z23 zclassic23-package-sign zclassic23-package-verify \
  tools/package-factory build/bin/jsonq
tools/dev/factory-evolving-qualification.sh \
  test-tmp/factory-mixed-replay 100 build/bin factory-mixed-fixture.sh
bash tools/dev/factory-mixed-loc.sh \
  test-tmp/factory-mixed-replay test-tmp/factory-mixed-replay/loc.tsv
bash tools/dev/factory-mixed-stages.sh \
  test-tmp/factory-mixed-replay test-tmp/factory-mixed-replay/stages.tsv
```

The runner SHA-256 is
`26a6a5efd452495266f284e19569b8ed5ae9601ae74760972348970966af4936`;
the mixed generator SHA-256 is
`4b174f152db8c90725e736ac74b309e3f43be448b72902b0036d89b16e907223`.
It also calls the unchanged base generator at SHA-256
`917d9fda1ca2d18fbc3567b61b797aac677a5d01375e65ff1ea9719bc194f048`.
The frozen run's ledger SHA-256 is
`7fc17ab494d13240eb17e5b23f8dd61226c49de4591093653d4d6e86115c006c`.
The 102-row audit summary SHA-256 is
`00d8f663cb9a5a765a5092720c9e3c230f8de65a9c0a9fbe935641e42828bd59`:
all 100 normal package roots and matching two-store quick/standard receipt
bytes were rechecked against the package trees; both failed candidates were
refused. A receipt hash binds its stated evidence, not arbitrary correctness.
The runner's original default-generator path also passed a focused two-revision
regression and refused its wrong-prefix candidate; that ledger SHA-256 is
`e468377cf7cbe8e4ccdc0cad2e8744bb1fc8b44dc354312f108d0eb0440020e5`.

| Final revision evidence | SHA-256 or exact root |
| --- | --- |
| `src/history.c` | `aa68289413d3cd13fd7c752c9aa6521027856bcf08423622115feb1c751d885b` |
| `include/history.h` | `7f65da05b66fea1323010821658d2decb0554360c102b28bbb6b6e555b76dd8f` |
| `examples/history_cli.c` | `df7d5be683eca5d940bf959afd070786a37b2e7ad601d11dc654dc4246ed3ed9` |
| Package root | `654b455776cf1ac7996c052c9e260477ae9e574266084f2975e04fa0ce61dc82` |
| Factory report | `d7163905b7b4744bd463d25c5bd7bba256efea81a7d268aafd5f010ec4811745` |
| Quick receipt ID | `f2e1dae32dcb0c844c945dbed35b6dbf5a101551885d70284e21ff880ba8bd19` |
| Standard receipt ID | `3abd2e8755e48d83fda079177a7ed4e6b8c42d3ae06b4fa67b785da48a8d69db` |
| Final terminal executable | `064f971d618fd2f0877104e4de4f25beb87b1a47610b24bc18f7d1583d342266` |

Each revision used a fresh isolated publisher and two stores. Its cumulative
source and tests preserve earlier behavior, but these results do **not** prove
100 same-publisher releases or persistent installed-state migration. The
same-store control in the original experiment shows that the second immediate
release is refused by the current weekly publisher policy. This benchmark
does not weaken that gate.

## Funnel and cost

The source-LOC ledger SHA-256 is
`f886cfb0563e2ccf1802562024929c85e63937d22cfed37d0e211e7aaeee230d`.
It counts package source/header/example additions and removals, excluding
generated tests. Across 100 revisions there were 206 added and 5 removed
source lines. Revision 1 includes 19 scaffold/data lines; revisions 25, 50,
75 and 90 add 11, 2, 60 and 19 lines, respectively. These are measured
source changes, not a claim of 206 independent features.

| Stage | Revisions | Added source LOC |
| --- | ---: | ---: |
| Generated | 100 | 206 |
| Buildable | 100 | 206 |
| Previewed | 100 | 206 |
| Tested | 100 | 206 |
| Two-store verified | 100 | 206 |
| DEV accepted | 0 | 0 |
| Fully accepted | 0 | 0 |

For revisions 1–74, `previewed` is a local test-binary fallback. Revisions
75–100 compiled and ran the terminal client, checking exact text and JSON
bytes. The final client's 101 text and 101 JSON outputs for counts 0–100
passed; their preview ledger SHA-256 is
`5c49521e247e079c1663a6d2ea65383c3553b6f20f378b6ed5eac804ba498684`.
The separate final-state C23 audit passed 101 prefix cases, 5,151 ranges,
202 render cases, 101 parser cases and five invalid cases. Its log SHA-256 is
`482b72a7fa58bb4bd9feda9f063e1397a913a37d2e04092cafe53841357aa371`.

The 100 normal factory calls summed to 497.373 s wall, 302.616 s user CPU
and 185.570 s system CPU. Factory latency was p50 4.186 s, p95 4.548 s,
p99 30.467 s, maximum 30.511 s. Revisions 91–93 each took about 30 s;
all four expensive factory steps rose together, and this run did not capture
enough host telemetry to establish why. Start and final-ledger timestamps
span about 519 s, or roughly 694 locally verified changes/hour. This is not
DEV or release acceptance throughput. The stage ledger SHA-256 is
`6de4e8ddcf22bdfb586dc53b9a8c05696f529e6ddea71d1302390fd941c2bb4c`:
the two `add_commit` plus two `reproduce_build` steps consumed 396.966 s,
79.8% of summed factory wall. Aggregate RAM and I/O bandwidth were not
sampled in this serial run; the distinct-candidate concurrency experiment
reports per-job peak RSS and filesystem block counts separately.

The wrong-prefix candidate built and ran but failed its sum test. The wrong
UI candidate built, rendered `count=75 total=2850`, failed the exact preview
and test, and was refused as `BUILD_NOT_INSTALLABLE: verdict test-fail`.
Their report SHA-256 values are
`538d46cce3170207a1e3b00b8a63ed97885c3cf6e41b92cf60ce83392245b830`
and `53d9ad632a70af29b85535e840821e269aa4876a403fcf2835138030177d14cd`.
Neither was verified or accepted.

The largest measured factory component remains two-store commit and
reproduction. The larger end-to-end publication blocker is exact proof
supersession when `main` advances; that owner has the three seq36 superseded
pairs. The next performance repair is eligible exact-input-closure proof reuse
across Git-base movement, retaining all mandatory publication evidence and
independent remote observation. SkyCombat's canonical recipe and owner verdict
remain separate release prerequisites.
