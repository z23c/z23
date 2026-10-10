<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Generated Tor provenance and source identity

## Contract

The untracked `vendor/tor/.provenance` is generated evidence about selected
archives and their producer. It is not a compiler source input. Source identity
excludes this exact untracked receipt while retaining it in dirty-path
observations. A tracked receipt remains an input. Other untracked files,
tracked Tor source, headers and selected archive bytes remain inputs.

The Tor provenance writer, archive authentication and readiness checks are
unchanged. Receipt exclusion does not establish equal source identities when
archives or other inputs differ, nor does it establish reproducible Tor builds
or complete toolchain closure. Filesystem mutation tokens remain local epoch
observations; they are not required to match between independent roots.

## Production-boundary experiment

The registered `source_identity_authority` group creates two valid outer Git
repositories with initialized nested Tor repositories. Their source, header and
selected archive bytes match; generated receipt bytes differ. The test invokes
the production `tools/dev/source-identity.sh` through both its native helper and
fallback path, checks equal source hashes, and checks that source, header,
archive, additional untracked source and unrelated `.provenance` changes alter
the hash. It also checks dirty-path visibility and tracked receipt sensitivity.
Every captured hash must be canonical, and capture failures propagate before
comparison. The native helper must exist, execute and retain its exact bytes.
Synthetic archives exercise inventory authority, not archive usability.

On 2026-10-10, exact base `24b3cb52acd800732d504f182a4351a9365aafc4` with the
corrected test and unchanged production script failed the receipt-only
comparison: `25b768841ae1abd07842c52c39fa20ce5e72464e6b9a1d4f85d6fa25ff89dc63`
versus `9cf5457d667adf6cac0af0e933b6dfbca3b29e3c5cd8c4f17724f8407ce3ccd0`.
The canonical runner's standalone retry reproduced the failure. With the
narrow exclusion and identical test bytes, all 12 cases passed. Each run
selected one registered group with zero skips.

The test SHA256 was
`e133a84c2bf541b455963f3dbb47d8c35a39d3ba91584a65881a2b4575022dd8` on both
sides. The native helper SHA256 before and after the passing run was
`93aba98ce0a90afd678cb68204cc34614dcd1c107934af85f51e44f6af22e0b0`.
The parent and fixed execution traces recorded actual helper launches.
The fixed log SHA256 is
`e1a4236be4cc82c639dcddc5ed30b0b04cd00e10c72c38f234bfd326fac0752b`; its raw
execution trace SHA256 is
`660d3b9d28cc2a2990c20cf9aa259d736e22442664c85dccb26860518cc61fb2`.

The admitted Linux x86_64 runs used GCC 14.2.0 and Clang 18.1.3 on an AMD
Ryzen 9 7950X3D. Environment receipt time was `2026-10-10T20:05:55Z`, also
`2026-10-10T16:05:55-04:00`. These are correctness observations, not a
performance benchmark. An earlier diagnostic fixture lacked an outer commit;
its failed dirty-path check was preserved and superseded by the corrected
same-test pair, without weakening the dirty-path assertion.

The registered `clientversion_format`, `consensus_state_producer_receipt`,
`vcs_core` and `make_lint_gates` impact groups also passed with zero skips.
`check-vcs-no-sha1` passed its authority lint, batch inventory selftest, source
identity selftest and sovereign source identity selftest. The admitted job
exited zero; its log SHA256 is
`fe35ca064478bb218fcbd9cdbab560298e6c1975f6e4c23f5cee35ec0db2ceea`.
