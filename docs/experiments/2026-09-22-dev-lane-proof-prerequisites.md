<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Development lane proof prerequisites

Observed on 2026-09-22T20:00:57-04:00 / 2026-09-23T00:00:57+00:00.
Host: Linux, AMD Ryzen 7 PRO 8840U. Compiler: Clang 22.1.6.
Source baseline: `2a34603373e96bbe2d9dcf809253aff3eca2b0d0`.

## Failure

A lane created with `z23-dev dev lane new` from the baseline rejected the
exact signed-commit proof for `985f0e3bacdf3957a7988b5fe035ab085c611cf6`
against that baseline before source testing. The first attempt recorded
`proof_generation_dependency_unavailable:vendor/tor/.provenance`; after that
file was supplied from an archive built at the same pinned Tor source commit,
the second attempt recorded
`proof_generation_dependency_unavailable:vendor/tor/Makefile`. The refusal
paths are preserved under the lane's `.cache/zcl-dev-proof/attempts/` tree.

## Correction

Lane creation now copies the Tor provenance and Makefile alongside its static
archives. It also carries the SQLite amalgamation, lint and fleet-observation
tools, and both reducer lifecycle fixtures required by the proof generation
input set. Copied files retain distinct inodes so rebuilding in a lane cannot
modify the donor. Missing-dependency guidance names the owning build targets.

The lane fixture exercises all 16 copied paths, checks independent inodes,
and verifies that the second creation reuses the existing lane. This change
does not alter proof thresholds or treat a copied artifact as proof.

## Focused validation

On 2026-09-22T20:15:33-04:00 / 2026-09-23T00:15:33+00:00,
`make -j1 t-fast ONLY=dev_lane` passed the one selected group cold:
one run, zero failures, zero skips, 637 ms measured test-body time.
The earlier `make -j4 t-fast ONLY=dev_lane` build was interrupted to
remove contention from an unrelated exact publication proof; it produced
no test verdict. The interrupted transcript remains at
`/tmp/z23-prime-fix-test.log` on the test host.

After integrating `68cee428bf62121257b1207c745ee4c742afcad0` on
2026-09-22 local time (UTC-04:00) / 2026-09-23 UTC, the same focused target
passed 1/1 groups with zero failures and zero skips. The measured test body
was 434 ms. The transcript is `/tmp/z23-lane-68-test.log` on the test host.
This verifies the rebased fixture, not a full exact publication proof.

## Current-main continuation

The landing queue rebased the original candidate onto
`78c81207386e8c40e76e52337f7e6c48ac12ca22` and stopped in prebuild.
`check-cyclomatic-complexity` measured `dln_plant_deps` at 16, above the
cap of 15. The failed attempt remains the queue's sequence 4 result and the
log remains in the landing state. The successor fixture writes the same 16
paths from its existing verification list, removing the duplicated chain.
The standalone complexity gate then passed with 56,803 functions scanned and
4,136 exact baseline pins. `make -j8 t-fast ONLY=dev_lane` then passed its
one selected group with zero failures and zero skips; measured test-body time
was 425 ms. The transcript is `/tmp/z23-lane-78-test.log` on the test host.
This is focused fixture evidence, not an exact publication receipt.
