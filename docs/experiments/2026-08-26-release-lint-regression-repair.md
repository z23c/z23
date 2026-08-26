<!-- Copyright 2026 Rhett Creighton - Apache License 2.0 -->

# Release lint regression repair

## Observation

Release qualification of source `549b7d6cd` stopped before building or
deploying because six full-lint gates failed. The failures were a stale shell
baseline row, a source file without a derivable purpose, an orphaned root
header, generated API-reference drift, three nonexistent documentation paths,
and Git-version-dependent UTC spelling in the fleet source audit.

## Repair

The stale baseline row was removed. The block-index binding file now states its
purpose. CLI lane defaults moved under the existing configuration include
surface. The API reference was regenerated from the command catalogs, and the
hot-swap document names paths that exist. Fleet source dates normalize the
strict UTC `Z` suffix to `+00:00` at the shared audit boundary while preserving
other ISO-8601 offsets.

## Evidence

On 2026-08-26, each previously failing gate passed independently. The fleet
source fixture proved both UTC spellings produce the same value. The registered
`test_importblockindex_cli_dispatch` group passed with zero skips after the
header move. No node was restarted and no production datadir was modified by
this experiment.

## Incoming hot-swap intersection

The subsequent main integration added a pre-mount ELF symbol check. Review
found that concurrent invocations shared mutable scratch filenames, symbol
versions were discarded, and an absent shipped-artifact path skipped the check
while the summary could still claim success. Each run now owns a private
temporary directory, default ELF versions expose both their exact version and
unversioned alias while non-default versions remain exact-only, and an absent
artifact fails the row. The symbol-version self-test, one real module check
against `zclassic23-dev`, shell syntax checks, and `make lint-fast` passed.

## Shielded KAT fixture intersection

The complete release suite then found one failure in
`test_sprout_groth16_kat`: direct proof verification passed, but contextual
verification returned `shielded-verify-unavailable`. The test predated the
fail-closed rule requiring the complete verification-key set to be published
and had injected only its independently decoded Sprout key. The fixture now
installs the compiled, hash-pinned verification set first and then overrides
only its Sprout member. This changes test setup, not a consensus predicate.
