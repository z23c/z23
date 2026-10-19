<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Plugin package transfer acceptance — 2026-10-15

## Claim

The registered `plugin_package` group composes the existing plugin packer,
content.v2 swarm transfer, ordinary package checkout, and plugin store.
Publisher and receiver have separate temporary stores. The publisher serves
actual manifest and chunk DATA frames; no receiver chunk is injected directly.
The receiver fetch is bounded to 16 KiB and must reach COMPLETE with nonzero
verified fetched bytes before checkout.

Each of two generations passes these observations:

- The package is publicly serveable under its own signed package release.
- Checkout reconstructs four members into an absent destination; reuse of
  that destination refuses.
- Publisher-side plugin acceptance does not authorize the receiver. The first
  install refuses without the receiver's own pinned-key file.
- Receiver-local acceptance permits installation of the exact signed generation,
  whose executable SHA3-512 matches the checked-out bytes.
- Repeated install reports already present. The first install leaves current
  absent; a second generation leaves the explicitly selected first unchanged.
- Altering the checked-out image refuses with `PLUGIN_ERR_EXE_HASH`, including
  when that generation was already installed, and preserves current.

The signing material is outside the explicit four-member carrier. Its members
are LICENSE, demo, demo.plugin.json and demo.plugin.sig. Package publisher
signatures and plugin publisher signatures are independent.

## Evidence

Source baseline: `c4f778d24989c73005feaae111c28a53e76bcf14`, integrated into
the isolated lane at `58659c1ab8216433745b55fdfd63c8f0d52b74c6`.
Run on R1 through `devbuild --wait`:

```sh
env VENDOR_CC=gcc devbuild --wait make t-fast-exact \
  ONLY=plugin_package,plugin_store,zcode_swarm_complete
```

```text
SUITE VERDICT mode=cold groups_total=1331 groups_ran=3 groups_cached=0 groups_gated=1328 groups_failed=0 self_skips=0 env_unobserved=0 load_flaky=0 toolkey=83d57dfdeb13
ALL TESTS PASSED — 0/3 groups failed, 0 skipped (2.0s wall, 28 workers) [--exact filtered]
```

Raw log: `build/scratch/gateway-mailbox/plugin-package-focused.log`.
Two earlier failed runs are retained beside it: `plugin-package-first.log`
used an invalid package name; `plugin-package-second.log` attempted two
package publishers in one namespace. Those were fixture construction errors,
not production regressions. Both were corrected without changing production.

## Limits

This is an in-process integration test with fixture peer handles. It does not
qualify network authentication, a live fleet route, the full publisher CLI
recipe, platform execution, sandbox confinement, or performance. The image
contains inert test bytes and is never executed. No remote installation
endpoint or new production behavior is introduced. Live rollout and explicit
activation remain separately authorized operations.

## Published-base integration

After landing attempt 593 published
`7056818c3c15e8b92d01545247c523e2b1c02aeb`, the same three focused groups
passed again with zero failures or skips (2.6 s wall). Raw evidence is retained
in `build/scratch/gateway-mailbox/plugin-main-focused.log`.
The integrated design keeps the approved hub ordering, supplies the checkout
datadir, and explicitly distinguishes the account-local plugin pinned-key store
from that datadir. No production plugin implementation changed.
