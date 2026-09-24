<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Factory work beside an isolated regtest node

Date: 2026-09-24. Source checkout:
`9b2be1f4e7431dcbe03c61ca7ca2cbb7f562c8a7`. Local host: AMD Ryzen 7
PRO 8840U, GCC 16.1.1 20260430. The isolated node, temporary package stores,
and workload output lived in scratch datadirs. A separate exact land proof was
also running on this host, so this is a **combined-load observation**. It does
not isolate the factory's causal share of latency.

```bash
make -j8 zcl-rpc
tools/dev/factory-node-health-qualification.sh \
  test-tmp/factory-node-health-4-ready-20260924 4 39880 evolving
```

The harness SHA-256 is
`c4ffbdc063128735c910fcd2e63e809277cafad7bc1b52cdf8896b9cbcc223cc`.
The first invocation found `zcl-rpc` missing before starting a node or
factory. Building that local tool and rerunning in a fresh output directory
gave `ready=1`, `factory_exit=0`, and `node_alive=1`. Four cumulative normal
C23 revisions each generated, compiled, ran the local binary, tested, and
passed the real two-store factory. The compile-valid wrong-prefix revision
built and ran, failed its behavior test, and was not factory-verified.
DEV-accepted and fully accepted counts remain zero.

| Stage | Normal useful revisions | Wrong behavior |
| --- | ---: | ---: |
| Generated | 4 | 1 |
| Buildable | 4 | 1 |
| Local test-binary previewed | 4 | 1 |
| Tested | 4 | 1 |
| Two-store verified | 4 | 0 |
| DEV accepted | 0 | 0 |
| Fully accepted | 0 | 0 |

The four normal factory calls took 51.889, 46.640, 48.376, and 42.010 s;
their summed wall time was 188.915 s, user CPU 94.813 s, system CPU
68.256 s. The wrong revision took 1.397 s and was refused. This is much slower
than the earlier unloaded 100-revision median factory call of 4.153 s, but
the simultaneous full land proof and changing host load prevent attributing
the difference to one process. The exact factory ledger SHA-256 is
`e67d9680a864afa23f28ffb151a628b8fad244c04e2ab6b7a8ff4be9383bd23c`.

| RPC phase | Samples | Successful height-0 replies | Mean ms | p50 ms | p95 ms | p99 ms | Maximum ms |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Before factory | 100 | 100 | 27.890 | 10 | 119 | 195 | 311 |
| During factory | 539 | 539 | 131.102 | 123 | 213 | 299 | 390 |
| After factory | 1 | 1 | 10.000 | 10 | 10 | 10 | 10 |

The RPC sample ledger SHA-256 is
`57256925dac46087b33febecadc2961908b76a277b542b027fe9889f3f3e3d0d`.
The during-load sampler stopped when the factory completed, below its
600-sample cap; it did not silently exhaust its observation window.

The node log SHA-256 is
`b3e230b0f645e88665fcb91873ab519a4c95265e4ba585be794688dd9cec8809`.
It first records `catchup: final commit missing tip hash` and a catchup abort
at `2026-09-24T20:19:51Z`, before the factory workload. The same pair recurs
in the log. Successful height-0 RPC responses
and a live node process therefore **do not establish healthy synchronization**.
This fresh-regtest catchup behavior needs an independent node-owner diagnosis;
the observation does not show that package load caused it. The host had no
observed chain advancement during this run. Aggregate resident memory and I/O
bandwidth were not sampled by this harness.
