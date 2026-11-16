<!-- Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 -->
# Native fleet test cache selection

`dev.fleet.job` accepts `no_cache:true` only for a test start. The receiver
constructs the fixed `T_FAST_EXACT_ARGS=--no-cache` make argument; absent or
false keeps the prior command. A peer request carries the boolean to the
receiver, whose input validation must accept it before any job is started.
An older receiver that rejects the unknown input refuses rather than silently
running a cached request. Fleet job results are observations, not native proof
receipts.

After the complexity refactor, the complexity gate passed without baseline
changes. On commit `c055837140e926186e00809d11a2bc34f2215460`, the focused
`dev_job`, `command_registry_catalog` and `native_api_contract` groups passed
cold with zero failures, skips, environment-unobserved or load-flaky cases.
The focused log SHA-256 is
`38f85a04f6a98afc4ff9b4ce38fde8b305c1d82544877fda531f2f93f5dd2aca`.

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
`peer`; remote routing additionally requires an authorized SSH peer and
candidate receiver binary. Neither observation is a proof receipt.

On 2026-11-16 the real local receiver ran those three jobs from clean commit
`c055837140e926186e00809d11a2bc34f2215460` with binary SHA-256
`62a86c1a2ccf80545caeeb236e29c9c17fbb22feaedc56f6d3bbf1aa21509d3f`.
All returned zero with no failures, skips, environment-unobserved or load-flaky
cases; each reported toolkey `43e314c64cc4`.

| Job | Result | Groups run | Groups cached | Log SHA-256 |
| --- | --- | ---: | ---: | --- |
| `j6afb4c22-214afb-1` | cold, stored 1 | 1 | 0 | `660a784c3bf2c99a3f6c4f03be9e6a3c29a4a2d1eb3c0d5dce74b8ffd2b84c46` |
| `j6afb4c68-21efe8-1` | cached | 0 | 1 | `d94f9fb83318f82f9f67cdb876e76c8c4b2e125f39cdcadd3a3495d30ace88bc` |
| `j6afb4cae-22066b-1` | no_cache, cold | 1 | 0 | `9aea55f21eed7d91aafcb9172bb416de9172057d7f320318bdb4e5c51c4a606d` |

The SSH forwarding fixture is mocked; no live remote receiver was exercised.
