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
