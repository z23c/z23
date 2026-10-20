<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Onion publication diagnostics: 2026-10-20

## Purpose and original focused source

The isolated onion acceptance test previously reported a 90-second window
without descriptor publication. The cause of that observation remains unknown.
This change improves the retained publication-log diagnostics without changing readiness,
the 90-second observation window, or the 60-second acceptance criterion.

The reviewed change modifies only the diagnostic test source
`tests/harness/src/test_onion_bootstrap.c`. Its preimage SHA256 is
`cb8bfe1e21332410713a07c65ab136f2b78b874ede120619e543c8fcb03e4105`;
the resulting source SHA256 is
`537ff6433db246bf26e18e3bf1d90d9bb20158eafa92f41a4aaa3db9de710715`.
The original reviewed patch SHA256 is
`9a4a800e86151c96ad2e83726bc4435c0a1d6e68843dcfe00a08e01594408dd2`.
The execution base was signed commit
`d5be3f3d53fe266a43e9bc7f0fa3b5e766c1aab0`; the diagnostic change was
uncommitted during these focused observations.

<!-- claim: file-present tests/harness/src/test_onion_bootstrap.c -->

## Method and results

Observed platform: Linux, AMD Ryzen 9 7950X3D. Installed Clang 18.1.3 was
observed; the compiler that produced the focused runner was not independently
established from the quiet build log. Date: 2026-10-20.

Both focused runs used the registered exact runner, cold execution, two
workers, a two-CPU quota and a 2 GiB memory limit. Real-network execution used
an explicit owned receipt directory and a disposable test datadir.

| Check | Observed result |
| --- | --- |
| Canonical complexity | PASS; 86,847 functions, 3,888 exact pins, cap 15; no pin change |
| Hermetic `onion_bootstrap_slice` | Diagnostic local reader OK; 1 cold group; 0 failures/skips/UNOBSERVED/load-flaky |
| Real `onion_bootstrap` | PASS; descriptor publication observed; readiness 15,001 ms; 18.7 s group wall |
| Real-run accounting | 1 cold group; 0 failures/skips/UNOBSERVED/load-flaky; no automatic retry observed |
| Real-run resource counters | Peak 203,362,304 bytes; 0 limit-hit/OOM/OOM-kill events |

The real receipt was written at 2026-10-20T17:14:42Z with verdict PASS and
reason `under_60s`. Its runner SHA256 was
`32cf36c80bb6efff520458b0aab3da95c9be55fac32551a905299f95f2caac3d`.
Receipt-file SHA256:
`be0af3152b2c42e9b3b28c4f9f53deeabd4cd27582add9257f3302ea18ecbe04`.
Full network-output SHA256:
`fe8820b9157d274c6730ef8f470c49b36a071e7867ec468bad0e465d9e4b7f07`.
The full output and resource records are retained in the local qualification
handoff; operational paths are not published here.

## Reproduction and limits

Run through host admission with `ZCL_STRESS_TESTS=1`:

```sh
make -j2 t-fast-exact ONLY=onion_bootstrap_slice \
  T_FAST_EXACT_ARGS='--no-cache --jobs=2'
```

The separate real-network observation uses `ONLY=onion_bootstrap` with an
explicit owned `ZCL_ONION_RECEIPT_DIR`. It needs outbound Tor connectivity;
its readiness assertions and observation budget remain unchanged.

The fresh success does not diagnose the earlier missing publication, establish
a reliability rate, or prove another platform. These focused observations are
not full candidate qualification, landing, or deployment evidence.

## Additive integration after the focused observations

A native qualification request for the original source stopped before gates
with a rebase conflict; nothing was queued. The public base had advanced to
`6edd5c28c9f6aee675890f72fa2a0cbf316d7cff`, which already retained bounded
head/tail notice windows, warning/error counters, fixed diagnostic categories,
and their local fixtures. Those landed behaviors are preserved by the
additive integration; no inherited qualifier or runner changes are included.

The additive reviewed patch SHA256 is
`e62c3a84f9878c047b34704c4a50e6831b2d3f0f4aca3f7b4ea9fb3b1c6d0996`.
Its preimage SHA256 is
`838c4f13e24c77b3d122ad21d1ff61024920b8cb3013ca24e9d11591ad7d45ba`;
its resulting diagnostic source SHA256 is
`e544bb00594f8c7331729a70785e0681148b58a41f7de2ff76d69304f31364db`.
The original `537ff643` source observations above are historical and do not
qualify this merged reader. The merged `e544bb00` source subsequently passed
canonical complexity (86,837 functions, 3,888 exact pins, cap 15) and the
stress-enabled hermetic slice: diagnostic local reader OK, one cold group,
zero failures/skips/UNOBSERVED/load-flaky, two workers. Peak memory was
677,646,336 bytes with zero limit-hit, OOM, or OOM-kill events.

The merged hermetic output SHA256 is
`cbf4788546ab59902cb091083cfb5083d1ff0c33cdc5b7f7c4e6f51647407dc8`.
Documentation checks passed before this result paragraph was added. Native
candidate qualification has not run for the merged reader. No standalone
network observation was repeated for this integration; the earlier successful
network receipt cannot qualify the materially merged source.
