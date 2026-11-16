<!-- Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 -->
# Native fleet test cache selection

`dev.fleet.job` accepts `no_cache:true` only for a test start. The receiver
constructs the fixed `T_FAST_EXACT_ARGS=--no-cache` make argument; absent or
false keeps the prior command. A peer request carries the boolean to the
receiver, whose input validation must accept it before any job is started.
An older receiver that rejects the unknown input refuses rather than silently
running a cached request. Fleet job results are observations, not native proof
receipts.

The source-level local job and SSH transport fixtures check the constructed
arguments and input refusals. They do not prove that a remote receiver ran a
cold group. Focused tests and a real receiver run remain pending.

A real local receiver check requires three jobs against the same isolated
`ZCL_TESTCACHE_STORE_ROOT` with `ZCL_TEST_CACHE=1`: seed a passing `hex_codec`
result, confirm a default job reports a cached hit, then request
`no_cache:true` and confirm that group ran cold. Start each from a clean
committed checkout with the candidate `z23-dev`:

```sh
ZCL_TEST_CACHE=1 ZCL_TESTCACHE_STORE_ROOT="$cache_dir" build/bin/z23-dev dev fleet job --operation=start --task=test --group=hex_codec --cwd="$PWD" --expected_head="$(git rev-parse HEAD)" --json
```

Wait for each returned job ID before the next start. For the third start add
`--no_cache=true`; inspect each job log and verdict for the expected cache
state. These three jobs are NOT RUN. A local receiver uses no `peer`; remote
routing additionally requires an authorized SSH peer and candidate receiver
binary. Neither observation is a proof receipt.
