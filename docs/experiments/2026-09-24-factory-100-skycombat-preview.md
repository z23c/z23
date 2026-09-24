<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# One hundred cumulative C23 revisions and SkyCombat control

Date: 2026-09-24. Checkout: `255990bfdc48e0c7e6f966aa2e8d6e678b25ca40`.
Local host: AMD Ryzen 7 PRO 8840U; GCC 16.1.1 20260430, `-std=c23`.
All generated packages, publisher keys, stores, reports, and game runtime
directories were isolated under `test-tmp/`. The checkout did not publish or
accept any package for an operator. The factory's offline hosting status was
`unavailable_offline` throughout.

## Evolving corpus

`tools/dev/factory-evolving-fixture.sh` generated 100 cumulative revisions of
the real tiny-lines C23 package. Each new revision adds one value-history
source line and tests every preceding prefix. The initial behavior remains
under test at every revision. This is a data/compute progression; it does not
represent 100 independently designed application features. Every revision
compiled, ran its local test binary, and passed the real two-store package
factory. Source transitions 2–100 each added one line and removed none.
Revision 100 has 112 history-source lines, 6 public-header lines, and 411
test-source lines. The test code is excluded from the useful-source count.

```bash
make -j8 z23 zclassic23-package-sign zclassic23-package-verify \
  tools/package-factory build/bin/jsonq
tools/dev/factory-evolving-qualification.sh \
  test-tmp/factory-100-current-20260924 100 build/bin
tools/dev/factory-evidence-audit.sh \
  test-tmp/factory-100-current-20260924/revision-100/report.json \
  test-tmp/factory-100-current-20260924/revision-100/pkg \
  test-tmp/factory-100-current-20260924/bin
```

| Evidence | SHA-256 or exact root |
| --- | --- |
| Generator | `917d9fda1ca2d18fbc3567b61b797aac677a5d01375e65ff1ea9719bc194f048` |
| Serial harness | `1e807daa387a792ae23246b7a2ae29a8d4242e385966da475482f1b9942090d4` |
| Factory executable | `e59a8c7c42e0fedfaa41e7ad0f4ba12bda179aa90572b2254cbb453ea578c1ca` |
| Serial ledger | `ae507d015981df5aae89ef7db81fd9b0b4382d95a48f9929030929a4e2ed3bc3` |
| Revision 100 history source | `7f651ac07bd563b55fc63774582c0b79423a27d078e2b03e42376a673bdfc026` |
| Revision 100 package root | `f424e549c260ef2206315d34ac62f7b5477bc63085517d7d802c69b2a73d5b01` |
| Revision 100 report | `cf2c28f9a602a6b07b8d518e6eb161e74f5998125befd5945db509b79f726d5b` |
| Revision 100 quick receipt | `22120dfa425d5955a2db0410f473621cf83adb0c0a63c7c7cb8e76052a1b40c6` |
| Revision 100 standard receipt | `abe7f89d29f83392d5e9b0c5e3716c0061e45a883cbb7f9728acef2d2b7fa60e` |

The serial run's 100 factory calls totaled 520.184 s wall, 292.081 s user
CPU, and 186.172 s system CPU. The whole harness took 534.725 s. Factory
latency was p50 4.153 s, p95 5.500 s, maximum 28.420 s. Revisions 80–82
took 19.906, 28.420, and 28.267 s; host samples did not establish a cause.
The four `add_commit` and `reproduce_build` steps across two stores totaled
398.963 s, 76.7% of summed factory wall. There was no local resident node
during this serial run; its node-health effect is unobserved.

| Candidate stage | Normal revisions | Compile-valid wrong revision 2 |
| --- | ---: | ---: |
| Generated | 100 | 1 |
| Buildable | 100 | 1 |
| Local test-binary previewed | 100 | 1 |
| Tested | 100 | 1 |
| Two-store locally verified | 100 | 0 |
| DEV accepted | 0 | 0 |
| Fully accepted | 0 | 0 |

The wrong revision compiled but changed value 2 to 99. Its local test failed,
and the factory refused it. The factory runs used a fresh isolated publisher
and pair of stores per revision. They do not establish 100 successive
same-publisher releases: the existing weekly publisher limit refused the
second release in the prior same-store trial. No DEV fast-lane result is
promoted to release qualification.

### Same-publisher state preservation control

`tools/dev/factory-same-store-lineage.sh` replayed revisions 1 and 2 in the
same two isolated stores with one publisher key. It explicitly tried publisher
sequences 1 and 2 for revision 2. The script SHA-256 is
`6df7fadc890c57dfb88b1a9fbbac929fcbe8882dc6c110bc33f756242ec2fa69`;
the three-case ledger SHA-256 is
`9e08d11197127dbf942aec152b0af950ef9e40f2cddfb5134f1f777fc5d32c09`.
GCC 16.1.1 ran it on AMD Ryzen 7 PRO 8840U on
`2026-09-24T19:08:58+00:00`.

```bash
tools/dev/factory-same-store-lineage.sh \
  test-tmp/factory-100-current-20260924 \
  test-tmp/same-store-lineage-new
```

| Candidate | Sequence | Factory exit | Wall s | Verdict |
| --- | ---: | ---: | ---: | --- |
| Revision 1 | 1 | 0 | 3.784 | Admitted in both isolated stores |
| Revision 2 | 1 | 1 | 0.088 | Refused `publisher-equivocation` |
| Revision 2 | 2 | 1 | 0.149 | Refused `PUBLISH_FREQUENCY_LIMIT` |

Revision 1's package root was
`ae5a1e60d75e76390713a428cc91d1c0a5c26d3357f068206d28fcd3b3c295cf`.
The installed file manifest in each store retained SHA-256
`eeef6d647c40b65ca2d7f146880403d975b9e855074833a8b04eee3f01586623`
before and after both refused revision-2 attempts. Revision 1 admission is
not human acceptance. This control proves the earlier artifact survived two
refusals; it also shows why the 100 isolated-publisher results cannot be
reported as 100 successive same-publisher releases. A legitimate fast DEV
lane or policy-respecting longer-term release schedule needs separate
qualification; neither refusal is a reason to weaken the release gate.

## Adversarial verdicts

The eleven current fault scripts returned their expected verdicts. The
original fault ledger SHA-256 is
`ee58642fd77047c8152d511358606d8e477a6dd35b99d1c67ff5b63dc3a0e517`.
It records one incorrect report binding, corrected below. `wrong` was compile-valid
but failed its behavioral test. `interface` passed the new package factory
while an old C23 client failed to compile against the renamed public API;
this executable counterexample disproves any inferred backward-compatibility
claim. Dependency drift, stale source/report pairing, contradictory receipt,
partial receipt observation, killed worker, revoked publisher key, and 16 MiB
resource limit were refused. Publisher death before commit produced no report.
Retries after worker and publisher death on the same isolated stores passed
and retained the revision-2 package root
`6a6756b750b33e840a4f165f84558ac157578463d8664b350058e84f83e370ff`.
A duplicate exact dispatch passed but consumed another 5.995 s of wall time.

```bash
for mode in wrong interface stale contradictory partial dependency worker \
  publisher duplicate revoked resource; do
  tools/dev/factory-counterexamples.sh \
    test-tmp/factory-100-current-20260924 "$mode" \
    "test-tmp/factory100-faults-$mode-new"
done
```

### Fault evidence binding correction

The original `contradictory` ledger row names the untouched report SHA-256
`c4fab579b40bb1dae61d065adcb3a74225ef5a2f3d5018a53aacf06e222f35b2`.
The audit actually consumed `altered.json` at SHA-256
`a9c76df7fecad2287ec02d4e5b35cf5e509410ce25bfe52f12a2aa8c640c4164`.
The top-level verdict log names that altered root and says `REFUSE quick receipt
ids differ`. The original ledger is retained unchanged. The new auditor
refuses it with `ledger binding mismatch: contradictory`; the negative-control
stderr SHA-256 is
`b6cc3c4b6e0b352f4ce279c70b1c3e718baa82207a924a98e96fdc80f814b26c`.

The reproducible runner now records the evaluated report, complete package
file-manifest digest, verdict log, duplicate second report, and worker or
publisher recovery report for every mode. It reran all eleven modes with their
expected outcomes, including same-store recovery after both deaths:

```bash
tools/dev/factory-fault-matrix.sh \
  test-tmp/factory-100-current-20260924 \
  test-tmp/factory-fault-matrix-new
```

The runner SHA-256 is
`95a1ffad5da9adc754eea0496b5904df5f89ebd52980fa686e4c595ce83b78d4`;
the auditor SHA-256 is
`d699ce26bf660a14996c70555c71ce3f69ea94b47e7140e29645b67364382394`.
The fresh run's ledger SHA-256 is
`d244684c67dc3d4dea641e914b733b5e89aac71cb91b11e9318082a1415a37ee`;
its source/report/log evidence matrix SHA-256 is
`7d55b8eb5e5da3cf991c3334b227f4ca222ca59598f0507ff8a11a839b9c72b3`.
The publisher-death evaluated report is explicitly `unavailable`; the recovery
report is a separate root. The refusal verdicts are unchanged by this
correction.

Dedicated feature, refactor, and UI progressions were not run as part of the
100-revision data/compute corpus. One-publisher 100-release progression,
owner acceptance, and node synchronization under package load remain unrun or
unobserved; their throughput and safety cannot be inferred from these ledgers.

## Real SkyCombat app and independent verifier control

`make -j8 game` built `build/bin/z23-skycombat` at SHA-256
`9a7a46565f2414bd8ccb5c9ee6ebb7c60b951ea690177f958123993091e4082c`.
An isolated Xvfb run opened the 1920×1080 game window, rendered the city,
aircraft and HUD, and logged five aircraft before the deliberate 12 s timeout.
The visually inspected full-frame PNG SHA-256 is
`38fd50456fb394a84df18956cc2d13cc56daf55163f0caa560f82a1b309873e4`.
This is a local application preview; the game owner has not recorded an
acceptance verdict. At the measurement checkout, `make -j8 game-check` failed on a pre-existing
`frame` set-but-unused diagnostic in
`apps/skycombat/src/models/test_multiplayer_complete.c` under `-Werror`.

The canonical SkyCombat aircraft package source SHA-256 is
`db757c6e927f880b6fd921ba6f673a9b7c77e172823510709c272c3574bbbc06`;
package root is
`9a2c62d39213dd36a2e05ca064ac011d100ff429f92eecedd2f2682307495acc`.
Its local C23 flight test passed, but the canonical factory recipe root
`d40194f24db81b34b3400fab47c9cdce6541d8a92fb4a46ff69d295168437fba`
was refused as `BUILD_NOT_INSTALLABLE` because it lacks libm. A separate
allowlisted-libm recipe root
`681deda25b57cad2ceca6771ce5fb201b17b0ce32e576f58e4e0279fd68047b9`
passed full confined verification locally. A compile-valid wrong-boost source
SHA-256 `ca7526b327dcbbc3d1f18cc902911728717bf5a32d50f810aa61c5a5e18c5a0b`
failed its local test and the confined verifier. The control recipe did not
change the canonical package or grant publication authority.

One consenting development peer independently checked the exact 24-file
input manifest, ran the good and wrong packages in the confined verifier,
and returned five hash-verified outputs. Bundle SHA-256 was
`2909b4f13b502cd34fd8acccab21a8042fbe100138a4ad246f2f14b9119ee2d1`;
returned evidence tar SHA-256 was
`52d062505ccfbef369941aedd6c4af807e40572d538074dffb137fcaf65ec0e2`.
The good build-report SHA-256 was
`e212bc6060500af3487034533db06444f0ce5909549667d54e158f6367da0f05`;
the wrong source was refused. The remote compiler was GCC 14.2.0, so its
artifact bytes are compared only within that compiler cohort. Bounded SSH
command and exact-object transfers were verified in both directions between
the local machine and the participating peer. Direct peer-to-peer DNS was
unavailable, so the second development peer did not participate in this
dispatch. The participating peer's typed node status remained identical in
before, eight during, and after samples; it was already blocked by
`review_required_bootstrap_trust`. This observation does not establish
chain-sync safety under load. The node-health sample ledger SHA-256 is
`0af0ebfa4882fd1aaf41a66693a011c6e28e70f411c539717e0d3543b9c379d6`.

## Bottleneck and next change

The largest measured serial wall-time component is two-store commit and
reproduction (398.963/520.184 s). Its exact ledger root and the canonical
SkyCombat libm refusal were sent to the Commons factory owner through native
agent mail sequence 318. The single highest-leverage performance change is
to reduce redundant exact-object work across the two store admissions and
reproduction steps while preserving each store's independent verification.
No acceptance or isolation gate may be relaxed to obtain a faster result.
The SkyCombat recipe fix and game-check diagnostic are release blockers
independent of this throughput optimization.

## Distinct-candidate concurrency and cache race

`tools/dev/factory-evolving-throughput.sh` schedules the same 32 cumulative
source revisions at widths 1, 2, 4, 8, 16, and 32. Every revision contributes
one useful history-source LOC, so its generated, buildable, previewed, tested,
and locally verified LOC counts equal its distinct-candidate stage counts.
All 32 jobs are considered ready at batch start; queue wait is the time from
that common ready instant to each job's actual start. Each job records compile,
preview, test, two-store proof, CPU, peak RSS, and filesystem block counts.
Peak RSS is per job, not a measurement of aggregate resident memory. No
resident node was running on the local benchmark host.

```bash
for width in 1 2 4 8 16 32; do
  tools/dev/factory-evolving-throughput.sh \
    test-tmp/factory-100-current-20260924 \
    "test-tmp/factory100-width${width}-new" "$width" build/bin
done
```

An initial width-2 run with verifier SHA-256
`68297cbc6a0e1b4606cf51b704adab76486a706fba777158444656fb801f3152`
verified 31/32 candidates in 90.590 s. Revision 2 had built and passed its
local test, but its standard-profile reproduction refused a same-key fast
object cache entry as `CORRUPTION`. The failed report SHA-256 is
`1bb9353e707c0a51a587f439fcefe5e873e7d301d975c271c45ad7c0700aad4a`.
The existing sidecar belonged to revision 1, package root
`ae5a1e60d75e76390713a428cc91d1c0a5c26d3357f068206d28fcd3b3c295cf`;
revision 2 used package root
`6a6756b750b33e840a4f165f84558ac157578463d8664b350058e84f83e370ff`.
Their unchanged test translation unit had one valid compile-action cache key.
Both writers missed before either completed. The second writer compared
whole sidecar bytes, including the legitimate different package root, and
reported a false corruption. The failure was fail-closed and no admission
followed. The initial width-2 ledger SHA-256 is
`ce0658c07f4db78f03d5ae2ff1fca2b2715784896857b40e7df0e8ac96dd53f0`.

The verifier now checks both sidecars against the same derived compile key,
their committed object SHA3 values against the newly compiled object, and
the stored object bytes and length. An altered object or malformed sidecar
still refuses. Rebuilt verifier SHA-256 is
`299a12b6df5b420883d6e933b9448c63a00d346eeb976bb85cd8105de1bbe09a`.
The width-2 rerun verified 32/32 in 86.591 s; its ledger SHA-256 is
`224a46a8f069ef728534ed4826a404bf5a82b8fb1afe818f0ed97dd7ae433102`.
This fixes an observed false refusal; it does not relax the object or
independent-reproduction gate.

The fixed-verifier harness SHA-256 is
`de55a219e3ad3b0c37796bbf8114ec63e0acfb316eb971a5d8a0548165cce58a`.
The sorted source-root set SHA-256 was
`1151bc975f2405398b05c2a36ea9087d610635e6521747b8dc65c67bcfc9f9e7`
in every run. Each row below has 32 generated, 32 buildable, 32 locally
previewed, 32 tested, 32 two-store verified, 0 DEV-accepted, and 0 fully
accepted useful source LOC. Proof and CPU columns sum across jobs; queue
wait is the mean per job. `changes/hour` is local verification throughput,
not DEV or release acceptance throughput.

| Width | Wall s | Changes/hour | Mean queue s | Compile sum s | Proof sum s | CPU sum s | Peak job RSS MiB | Ledger SHA-256 |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| 1 | 130.689 | 881 | 62.722 | 2.236 | 127.794 | 117.921 | 132.2 | `7cebc8bfd080e58338a4b88536aebea5cf3673ce315cd7c212b4f151db66f704` |
| 2 | 86.591 | 1,330 | 44.383 | 2.257 | 169.624 | 122.184 | 132.2 | `224a46a8f069ef728534ed4826a404bf5a82b8fb1afe818f0ed97dd7ae433102` |
| 4 | 83.446 | 1,381 | 20.330 | 4.387 | 325.859 | 353.294 | 132.0 | `c938f2910863d29bff74dfd2fe5d6f8e414d65a8be357a899871cdd383f81335` |
| 8 | 90.749 | 1,269 | 44.357 | 13.122 | 703.867 | 822.806 | 131.9 | `d7261e289ed9728eb3f8751b32a4978bd90b4ecb1a500df6bc73490a1f3c2172` |
| 8 repeat | 35.360 | 3,258 | 8.941 | 3.142 | 274.009 | 287.261 | 132.1 | `c7ba5dab573ba9e4a148f0e6eea54ec3076073bc3f2bed43e9d9e33d4afc2851` |
| 16 | 17.887 | 6,440 | 4.223 | 4.605 | 277.251 | 237.154 | 132.2 | `4fe513b621ef773c0d278b20e087cd541f7bff6c37dfdff549092fd61b8c78a8` |
| 16 repeat | 96.970 | 1,188 | 24.037 | 23.701 | 1498.060 | 1320.800 | 132.2 | `dca69e66dca1ac942787277e73312156e378853ce11bb09d3147d65da320d47e` |
| 32 | 22.213 | 5,186 | 0.004 | 10.201 | 683.503 | 329.220 | 132.0 | `42e95bce7531248f1a6387fd56cb0d35f45a57551a2dd95c4aa7c2f897d6ecd1` |

Preview plus test time summed 0.109–1.171 s across a batch; each run's
`summary.tsv` and `ledger.tsv` carry the exact values and raw filesystem
block counts. Aggregate RAM and disk bandwidth were not measured. The
width-16 repeat used 1320.800 CPU s against 237.154 CPU s in the first run,
and its proof sum rose from 277.251 to 1498.060 s. Width 8 also varied by
2.6× in wall time. Host contention or thermal behavior was not isolated, so
these runs establish a reachable peak, not a stable saturation point or a
production changes/day rate. No operator-accepted LOC were produced.

The existing `tools/dev/c23-cache-adversarial.sh` stopped at its first
cache-counter assertion on this checkout: its zsha256 fixture's translation
units were conservatively bypassed by the current assembler-input closure
rule, yielding zero hits and zero misses. That run did not test the changed
cache path. On copied warm caches from the actual tiny-lines width-2 run,
altering every cached object byte caused a factory refusal with `fast cache
CORRUPTION`; altering each sidecar schema caused a refusal with `sidecar
schema is not zcl.fastobj.sidecar.v1`. The two failed report SHA-256 values
were `d5030e979be9b435495ff7caca4764dd7ab12ece14d96f46c7ead8db016077d0`
and `8a10cff5fce4b846650c6d06302f328bb63e634b2d1e44ba2538ae7ef3fb1974`.
The tamper ledger SHA-256 is
`a7e8d87667112a3fefe977020e1572c1dfb4b54dfe9efd03dd0c29cf770de818`.
These are exact negative controls for the final verifier SHA-256
`a3fed28174de47a489e2d7abc3f4f6d273364fe35da76cd9c101d0ab09f3ce43`.
The final verifier also passed a fresh width-2 run: 32/32 distinct sources
locally verified in 79.345 s (1,451.9/hour). Its ledger SHA-256 is
`96cd3370ed167e7ca99b347c08b6458257bee437d5964c8d20215a0ee7de338b`.
Revision 2's independently audited report SHA-256 is
`9ad0317cd4651861af99417aa1b1b4f18ce5994e62b11dc16370231ae6d18a4f`;
its package root remains
`6a6756b750b33e840a4f165f84558ac157578463d8664b350058e84f83e370ff`.

## Exact landed SkyCombat follow-up

The separate game-check repair entered the native land queue as candidate
`b326f50899fa23928563b42d894c00d7e595c9f9`. Three full exact proofs
were superseded by changes to `origin/main`; none was publication evidence:

| Superseded source | Proof base |
| --- | --- |
| `5963dc2cd4df17a09afed8373b9f13eb07d3bbec` | `45e27159a20fdd708c39d440632237dac7f56070` |
| `97d2b1cc3290d7ecd164206b9c5b714f76778c87` | `e6344acced2cd3778f0c8c1c086ceecb3a40d326` |
| `0c2ad8174f318e6da13e110fd51e41daafb8deff` | `df8e379e4b85cbd5045b9382f2549ca899c70fe0` |

Queue sequence 32 proved successor
`b1f19c9b136377a25d5581c9ac5c8d40ba5f94fd` against
`b1a00ce5177365ffd8f545d7221732b69a7d84a4`. It stopped at
`PUBLICATION_INTENT_REQUIRED`; after the exact signed intent was attached,
the receiver independently fetched and verified the remote fast-forward,
source tree `43757ffe2663bdb9eaae46a6d7f6f677882efaef`, and signer
`6481aceda6665ada45d96fa0508d0d89002503c4910fb96342d8f26306570226`.
The verified remote tip is the successor commit above.

An isolated worktree detached at that exact commit ran:

```bash
make -j8 game-check
make -j8 game
sha256sum build/bin/z23-skycombat
```

`game-check` compiled 71 game and 5 raylib translation units with exit 0 in
11.559 s (22.797 s user CPU, 2.929 s system CPU); its captured log SHA-256
was `d6cff351fdaace993b6ed3bd82edd7747fa73a568ecece3e4ab707f5faf69488`.
`make game` exited 0 in 2.262 s after the object build. The executable
SHA-256 was
`9a7a46565f2414bd8ccb5c9ee6ebb7c60b951ea690177f958123993091e4082c`,
identical to the earlier visually inspected Xvfb preview. The previous frame
therefore binds to the exact landed executable bytes. Game-check and Git
publication are code gates; the current owner has not recorded a visual or
behavior acceptance verdict, and the canonical aircraft package recipe still
refuses missing `libm`. DEV-accepted and fully accepted counts remain zero.

Native agent mail sequence 353 requested the owner's exact preview verdict;
sequence 354 gave the land owner the three superseded proof pairs. A
serialized publication window spanning proof through remote receipt is the
highest-leverage measured end-to-end throughput repair. It must preserve the
current-base check, all proof gates, signed intent, and independent remote
observation. The two-store commit and reproduction cost remains the largest
measured per-candidate factory component.
