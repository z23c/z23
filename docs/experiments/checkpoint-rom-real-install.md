<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Real checkpoint bundle install

On 2026-11-13, an opt-in isolated fixture tested the native terminal install
using the compiled checkpoint at height 3056758. The public bundle SHA-256 was
`6bc3bf5152e5cd38deadc344d563478696d3800f4417e564119319196447ae83`;
the public flat index SHA-256 was
`68cda2bf810cc1583be5258816a3852948e625f99e2108e3b6bb104a41f733da`.
The fixture verified the source and private copies before installation.

The negative case rejected a wrong header, then the terminal installer refused
an empty header substrate; no install stamp was present. The positive case
validated the real checkpoint header with the frozen verifier and installed the
bundle. Its recorded authority was `CHECKPOINT_ROM`, with the compiled height,
block hash and UTXO root; its stamp generation and live coins generation were
both 1. The opt-in test group passed with no skips in 178.9 seconds. Peak RSS for
the admitted run was 1,810,824 KiB; total elapsed time was 3:26.78.

An earlier negative experiment failed its assertion: the public flat index
already contained the complete hash-bound checkpoint header and solution. The
installer independently validated that header and installed the bundle. The
corrected negative case used an empty header substrate. Neither experiment
changed a phone or a canonical datadir.

On 2026-11-14, the real-checkpoint fixture was run with the separately supplied
block input absent and the explicit flat-index header fallback enabled. The
fixture verified the bundle and index against the pinned SHA-256 values above,
reconstructed the complete checkpoint header from the index and round-tripped
it through a zero-transaction serialization carrier. The carrier is not a
consensus-valid block. The wrong-nonce header was refused; the unmodified header
passed the frozen Equihash verifier. The empty header substrate was refused,
and the validated substrate installed under the compiled checkpoint authority.
The focused group passed with no skips in 191.6 seconds.

A separate negative run supplied an invalid block path while enabling the
fallback. It failed before launching an installer, including on the automatic
retry; an explicitly supplied invalid path did not select the fallback. These
results qualify isolated checkpoint authority checks and installation only;
they do not establish interrupted download, wallet-history recovery or device
behavior.

## Interrupted transfer followed by checkpoint installation

On 2026-11-14, an isolated fixture transferred the same SHA-256-pinned
checkpoint bundle using the verified ROM chunk protocol. The first download
process was killed after two of 62 chunks were durably journaled. A fresh
process resumed; server accounting confirmed that neither retained chunk was
requested again and each of the 60 missing chunks was requested once. The
resumed file matched the original bundle SHA-256 and was passed directly to
the real installer in the same private fixture directory. The transfer
manifest was derived from the fixture bytes and supplied no installation
authority.

The installer refused the empty-header substrate and accepted the separately
validated checkpoint header under compiled checkpoint authority. The isolated
focused group passed with no skips in 198.8 seconds; the ordinary ROM and
snapshot recovery groups also passed with no skips. This test does not exercise
an interrupted installation, existing-wallet history recovery or a device.
