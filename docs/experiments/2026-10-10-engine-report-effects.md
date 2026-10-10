<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Report-only engine-unit outcomes

A report task with a measured unchanged worktree ends as `REPORTED`, exits 0,
and records no gate pass. Report edits fail before running an unrelated gate.
Malformed file envelopes and incomplete Git status refuse; an unknown changed
count remains null in the compatibility receipt and -1 in the canonical receipt.

Linux qualification used exact base
`024b4b95dfb967fa2353cfa22475c1412b011cb0`, production SHA256
`762776dcda92be7ac696bdc73fc1e7fe01f94e6fc2824b8384df37c292d0d979`,
and final test SHA256
`b333f3147af32ee0e34e8506921416a682952fd4747acd1195485bc93178e353`.
The registered `engine` group passed uncached on 2026-10-10T06:23:28Z:
one group ran, zero failed, zero self-skips and zero unobserved environments.
`make -j8 t-fast-exact ONLY=engine` took 68.03 seconds wall, 9.67 user and
5.12 system seconds, including compilation; the test phase took 18.3 seconds.
GNU time observed maximum RSS was 1,027,644 KiB, not aggregate tree memory.
Admission waited 2.172906811 seconds at eight CPU tokens and 8 GiB RAM.

Earlier tests were bound to v2 test SHA256
`d08060fd24badbd1740dace25edad53dc2132029c6d58f11c7ea78b7f54f744b`.
Removing refusal precedence reached the malformed-report failure. Restoring the
exact parent reached the clean-report failure. Both also failed an existing
empty-directory oracle because fixture Git initialization ran too early.
Restored v2 failed that same oracle. The final test-only repair defers checked
Git initialization until the positive contract case, preserving the oracle.
The report fixtures and production code are unchanged by that repair; those
negative observations are v2 evidence, not fresh v3 mutation runs.

The three earlier phases took 180.24, 84.72 and 28.42 wall seconds. Compiler
warnings in those logs remain observed limitations; this is not an all-clean
portability or release proof. Fixture replies made no provider calls. Model
billing and earlier orchestration repair costs are unknown. Current-main
integration, generated inventory and agent-verify remain pending.

The earlier proof manifest records GCC 14.2.0 on Linux x86-64 and an AMD Ryzen
9 7950X3D 16-Core Processor. These are recorded host/tool observations, not a
portability comparison.

## Pending report-text qualification

The follow-up proposal requires nonblank decoded report text, records blank
reports as `FAIL(NO-CHANGE)` with report-specific retry feedback, and stops a
`FAIL(REPORT-EDITED)` result after its first turn. Report CLI invocations also
require a supported structured decoder and a zero child exit status. Parsed
usage observations survive a nonzero report child exit. Edit CLI exit policy
is unchanged.

The blank-reply fixture and four-round edited-report fixture reuse the existing
report-effect test setup. Follow-up execution is `NOTRUN`; the earlier v5
qualification does not qualify these source changes. Structured report decoder
integration and CLI fixtures remain pending independent decoder review.

The existing fixture now includes a local scripted Claude result with synthetic
usage fields and exit status 23, plus an unsupported GLM report-format case.
Assertions require one refused invocation with retained tokens and cost, and
preflight refusal without any invocation, respectively. Compatibility cost
adoption precedes dispatch-failure handling so the failed child does not lose
its reported charge. These added cases remain `NOTRUN` pending decoder
integration. No provider is invoked by these fixtures.

## Integrated qualification

The coherent decoder and caller run used broker
`1339114-77888773-1791616932539007518`. Complexity, long-function, capability
inventory, and lint-fast gates passed. The six registered groups ran; five
passed, while the engine group exposed two fixture assertions that inspected
stderr through a stdout-only capture. Exit status, refusal verdict, invocation
counts, artifact absence, and retained usage were correct. Failure evidence
is preserved in `build/engine-unit-report-effect-v10/failure-groups.log`.

The fixture now selects the existing `zcl_spawn_capture_binary_merged` primitive
for refusal diagnostics. Existing callers retain stdout-only capture. Final
focused qualification used broker `1437067-77921434-1791617259071243785`:
`ONLY=engine` passed 1/1 groups with zero skips; capability inventory generation,
complexity, and lint-fast passed. Decoder source and the other five passing
groups were unchanged during the capture repair; those five groups were not
rerun. This is scoped qualification evidence, not a new complete matrix run.
Only owned complexity pins decreased: `append_unit_receipt` 27 to 25 and
`main` 152 to 148. Unrelated baseline entries were preserved.

## Production-boundary mutation receipts

Broker `1540664-77967373-1791617718457889787` tested two temporary mutations of
`tools/engine_unit.c` using the registered engine group. Permitting positive
CLI child exit status failed the existing assertion `nonzero report child
refuses once despite valid nonblank output`. Moving cost adoption after the
failed-dispatch exit failed `failed report child retains observed tokens and
cost`. Both mutants compiled and produced nonzero focused-group results; an
unrelated failure was not accepted as a witness.

The original file was restored between mutants and on the session exit.
Original and restored SHA-256 were both
`81d786ccc767419adeddb90b29b49134c843676d875dac033a6219bf55601119`.
The restored registered engine group passed. Exact mutant patches, hashes,
assertion witnesses, logs, and statuses are retained under
`build/engine-unit-report-effect-mutations/`. No provider call was made.
