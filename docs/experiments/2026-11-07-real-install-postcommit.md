<!-- Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 -->
# Real checkpoint install interruption

The opt-in snapshot-install fixture creates an isolated mainnet genesis datadir
with a synthetic watch-only record and scan floor zero. It copies the public
history into a private `wallet-history`, invokes the terminal installer through
`app_init`, and pauses at the existing test-only hook immediately after the
real activation commit. The parent kills that process and a fresh child checks
reconciliation, the durable generation and binding, the pending wallet fence,
the recovered marker, and the synthetic record. It does not exercise normal
wallet replay or establish READY.

The inputs are a public 519831552-byte H3309900 consensus bundle, its matching
public history, a private scratch directory with room for an independent copy,
and the local verification parameters. The normal fixture does not read them
unless all four variables are set. Partial configuration fails the fixture.

```sh
DEVBUILD_CLASS=normal \
ZCL_TEST_REAL_INSTALL_BUNDLE=/path/to/public-bundle.sqlite \
ZCL_TEST_REAL_INSTALL_HISTORY=/path/to/public-history \
ZCL_TEST_REAL_INSTALL_SCRATCH=/path/to/private-scratch \
ZCL_TEST_REAL_INSTALL_PARAMS=/path/to/verification-parameters \
  devbuild --wait --project z23 make t-fast-exact ONLY=snapshot_install_recovery
```

The command above uses the environment-based class selector. On hosts whose
`devbuild` supports `--class`, use `devbuild --wait --project z23 --class normal`
instead of the environment-based prefix.

The opt-in bounds setup and recovery children to 600 seconds each and the
installer to 1800 seconds. It reports progress during the wait; the normal
runner silence limit remains unchanged.

On 2026-11-07, the real-artifact fixture passed in 538.2 seconds on an AMD
Ryzen 9 7950X3D using GCC 14.2.0, with one group run and no skips. The
activation hook witnessed the committed H3309900 binding before SIGKILL; a
fresh process recovered the marker and preserved the pending fence, generation,
binding, floor and synthetic watch-only record. This observation used base
`60958bd181c6e6702f74c4d5c745d0b4dcc72546` and fixture header SHA-256
`0e6288a9a78cb0ed096a435f599f74ecb843b797bd2f6c50fe9d75b4bd3fef64`.
The supplied bundle had separately verified SHA-256
`2cb5e694d0c9b336935f6411aa0b0dae082b3e08a1dc1d214a464fd43e528a00`;
the later fixture checks a private copy against that digest before installation.
That earlier run set the canonical deployment override inside the isolated
installer child; it does not prove the no-override boundary. The current
fixture clears any inherited override before starting either child.

A second run on the same date, CPU and compiler passed in 329.9 seconds with
one group and no skips. It used base
`e52241041bd5aab9b39b49e1157ef28fb9e4b5b0` and fixture header SHA-256
`062abc744973d2780b32661002a7c2c090d0e770219094ffb0c07eccbde79dd0`.
The private bundle copy passed the size and SHA-256 checks above, and both
boot children cleared the canonical override. After the committed activation,
SIGKILL and fresh-process recovery, the pending fence, generation, binding,
scan floor and synthetic record remained intact; the marker was restored.
This run does not establish completion of wallet replay or READY.
