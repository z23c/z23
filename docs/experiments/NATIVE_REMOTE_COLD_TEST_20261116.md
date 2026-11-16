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
cold group. The command_registry_catalog and native_api_contract groups passed on
`18ed76ed778fbf7043fd178ab3a436c5105fc783`; dev_job passed on test-only repair
`1a13ff234f7b2d3a81aac95b06407cbebaa67f4b` in 19.784 seconds.

A real local receiver check requires three jobs against the same isolated
`ZCL_TESTCACHE_STORE_ROOT` with `ZCL_TEST_CACHE=1`: seed a passing `hex_codec`
result, confirm a default job reports a cached hit, then request
`no_cache:true` and confirm that group ran cold. Start each from a clean
committed checkout with the candidate `z23-dev`:

```sh
cache_dir=$(mktemp -d "${TMPDIR:-/tmp}/z23-fleet-cache.XXXXXXXX")
: "${cache_dir:?could not create private cache}"
ZCL_TEST_CACHE=1 ZCL_TESTCACHE_STORE_ROOT="$cache_dir" build/bin/z23-dev dev fleet job --operation=start --task=test --group=hex_codec --cwd="$PWD" --expected_head="$(git rev-parse HEAD)" --json
```

Wait for each returned job ID before the next start. For the third start add
`--no_cache=true`; inspect each job log and verdict for the expected cache
state. Preserve the job logs, then retire only this caller-owned cache after
all three jobs are terminal and no process holds it. A local receiver uses no
`peer`; remote
routing additionally requires an authorized SSH peer and candidate receiver
binary. Neither observation is a proof receipt.

On 2026-11-16 the real local receiver ran those three jobs from clean commit
`1a13ff234f7b2d3a81aac95b06407cbebaa67f4b` with binary SHA-256
`9d7d62529665e53670552ea8a3ffca9bb53cd90870320383b3a5e05263d7baf3`.
All returned zero with no failures, skips, environment-unobserved or load-flaky
cases; each reported toolkey `43e314c64cc4`.

| Job | Result | Groups run | Groups cached | Log SHA-256 |
| --- | --- | ---: | ---: | --- |
| `j6afb472d-178df1-1` | cold, stored 1 | 1 | 0 | `3009c9ee1ca1ebe969f9bdef2afb4385f4b0bbeacc364cd04eec58b20936a9d1` |
| `j6afb4793-17cfee-1` | cached | 0 | 1 | `7c73d2ff5cc6cb7c439ca2245bac6e0171d09234efebdf4c33a4e219d48647c4` |
| `j6afb47e9-1873a7-1` | no_cache, cold | 1 | 0 | `e6dd423fb794e6973831646f07fd0bd47d83c41353786c77d7500e2a8d1390ec` |

The SSH forwarding fixture is mocked; no live remote receiver was exercised.
