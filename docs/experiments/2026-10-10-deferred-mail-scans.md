<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Deferred mail scans during fleet brief assembly

## Intended behavior

Fleet brief assembly drains every available mail page. Intermediate pages do
not need to rescan all streams for the global sequence maximum. The internal
brief drain defers that scan, then replays the apparent final page through the
ordinary mail handler. This preserves the public handler's scan-before-page
ordering when a writer appends concurrently. Public mail pulls and evidence
drains continue to use the ordinary handler.

An append during final-page replay can create another page. The optimization
does not promise one global scan per drain under arbitrary concurrent growth.

## Observed qualification

Source base: `f57b6adc27b2160d4ded6ae388e731264d7e7245`.
Five-file candidate patch SHA256:
`16bdc23c4d180a9014f857fdc8b6eae15cc994e2d5d786a150a4a5b0c98bc2c7`.
Host: arm64 Mac16,10, Apple M4; Apple Clang 17.0.0
(`clang-1700.3.19.1`), target `arm64-apple-darwin25.0.0`.
Run metadata began at `2026-10-10T02:41:09Z`, local
`2026-10-09T19:41:09-0700`.

The canonical uncached `devagent_mail` group passed. The fleet caller fixture
uses two 70-row streams, a third populated stream, and an empty stream. It
checks projection, complete stream cursor tokens, an older-timestamp append,
resume, public pull shape, and mail evidence through the actual handlers.
The corrected `fleet_steer` group passed with four global stream scans for
the initial drain and eight for the resumed brief's two drains. The public
single-page control retains four scans; evidence retains scans per page.

An actual-caller mutation replaces only the brief-drain handler selection with
the ordinary handler. It compiled and ran the registered fleet group, failing
at `initial_scans != 4` with observed value **64**. The fixture's preceding
projection checks completed. Subsequent scan-count assertions are skipped by
the harness after this failure and are not claimed as mutation-run controls.
Restoring the exact candidate produced a green uncached fleet group. All five
candidate source hashes matched after restoration.

| Evidence | SHA256 |
| --- | --- |
| Mail group | `a0f1baf6fc63ca6e2e21cd375255cba0c65e7e7d2828ecc68e99cd07b39c360c` |
| Fleet group | `f7edab4ed40a20a5247f82d9ace0abbffb574073e4ce350aa5a6918df605caa0` |
| Caller mutation | `e8bacf10f165d8d17d5f02270573b80984796b7be1f6d4891f534f4ae6ddfe8f` |
| Restored fleet group | `abe455b60d76dd4873412dab1e0708f34aa23a3db0c9dc9df8aecb68fed2d3ca` |

Each successful group reports one group run, zero cached, zero failures,
zero self-skips and zero environment-unobserved outcomes. These are functional
and scan-count observations, not a latency benchmark or measured dollar saving.

## Cost and evidence limits

The first fleet run aborted during fixture setup because the inbox seeding
helper creates only one directory level. Moving the existing empty-stream
setup before seeding creates the required isolated parent hierarchy. No
production logic or acceptance threshold changed in that repair. The initial
failure, source reviews, repair, reruns and mutation work all count toward
complete task cost; this was not first-pass qualification.

Linux qualification used base `22a52e06e1fa28e71887bf006defdb98c983d362`,
whose five affected preimages match the original base. On an AMD Ryzen 9
7950X3D with GCC 14.2.0, the two registered groups passed uncached: two run,
zero failures, zero self-skips and zero environment-unobserved outcomes.
The runner reported 18.5 seconds of test wall time; this is not a matched
performance comparison. Run metadata began at `2026-10-10T03:05:16Z`
(host local `2026-10-10T03:05:16+00:00`). Inventory generation,
`lint-preflight` and `lint-fast` passed. Exact-pair publication proof remains
a separate gate. This experiment establishes neither fleet-wide latency nor
provider billing savings. Concurrent append coverage in the mail group and
public-handler equivalence constrain the optimization's correctness claim.
