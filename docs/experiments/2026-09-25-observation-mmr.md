<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Signed observation history checkpoint pilot

A checkpoint states that one issuer appended ordered observation roots to its
own log. It commits to the leaf count, occupied MMR peaks, predecessor
checkpoint root, observation time, and issuer key. Its 1,168-byte canonical
wire is a 1,104-byte domain-separated SHA3-256 signed body followed by one
Ed25519 signature. Each appended root produces a domain-separated leaf hash
that binds its log index; each carry produces a height-bound parent hash.
Each extension supplies 1–64 exact roots. Genesis verification replays the
first batch from the empty log and requires a zero predecessor root.
Subsequent verification starts from the exact locally verified predecessor
and all intervening roots, checks both signatures against the expected
issuer, recomputes every peak, and refuses missing, extra, zero, reordered,
or changed roots. A fork produces two independently verifiable heads and
neither is silently selected. Clients retain both heads and investigate the
conflict.

The checkpoint authenticates an issuer's claim about log history. It does not
validate the underlying observations, source, artifacts, policy, freshness,
independent trust domains, or acceptance. A newly encountered checkpoint
without a previously verified predecessor needs replay from genesis or a
separately trusted anchor before it can support synchronization. The bounded
codec is a pilot building block; peer transport and receiver-side acceptance
remain separate work.

## Local qualification

On 2026-09-25 UTC, GCC 16.1.1 on an AMD Ryzen 7 PRO 8840U, the registered
`zcode_dev_objects` group passed 1/1 with zero skips from base commit
`48c4e8ca4a151f7c7c4ba049f3a49e6233ac173d`:

```sh
make CC=gcc -j2 t-fast ONLY=zcode_dev_objects
```

The complete log SHA-256 is
`be3f02c49e02734cd83c21b4635a12229b376522cb6ca74551e1f1c99bbcd0f9`.
The selected group body took 11,048 ms. The focused test printed
`MMR_VERIFY_PROBE checks=64 cpu_us=134329 wire_bytes=1168 roots_bytes=64`:
2.099 ms of process CPU per two-root extension verification in that run.
This measures signature and peak verification in the local process. It does
not measure network transfer or prove the correctness of any logged
observation. The cold prerequisite build took about 32 minutes at `-j2`,
including a quarantined incomplete dev object epoch from an interrupted
earlier run.

The exact tested source SHA-256 values were:

| File | SHA-256 |
| --- | --- |
| `zcode_observation_mmr.h` | `eed2ba18359b502f1c95f2bf649a8f66dd3a31b7c243f1e1c2057fe383e6ce0e` |
| `zcode_observation_mmr.c` | `cffe34d7e693596d287aa1b872249c8bd64ac317a5468de84d807dcd3b68cf03` |
| `test_zcode_dev_objects.c` | `be8fd22d96331894d719647d021f66ec0e67234bbd9b5e56bba333e6d3079eec` |
