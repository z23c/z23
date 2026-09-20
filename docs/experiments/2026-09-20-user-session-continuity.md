<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# User-session continuity acceptance

## Scope and baseline

The user outcome is interruption and restart of one coding task, recovery of
its objective, constraints and saved work, and completion of that same task.
The existing `story.focus` command reads canonical ZCODE task and context
objects. No additional session store or worker scheduler is required.

Baseline checkout: `93d61f73b8f5b6b7b493eadd3273053ddb41f50a`.
Observed upstream: `7db0ea1de6d1fd034e0720dc840a897742737cf4`.
The preceding worker-accounting repair is present in upstream ancestry as
`5818dba99`; its separate extraction and earlier checkout remain preserved.

At 2026-09-19T23:35:37-04:00 / 2026-09-20T03:35:37Z, the host reported
AMD Ryzen 7 PRO 8840U and GCC 16.1.1 20260430. These are environment
observations, not performance measurements.

## Read-only review

Child identity: `/root/session_edge_review`. Requested configuration:
`gpt-6-astra`, reasoning effort `low`. The child reported that runtime model
identity and token usage were not exposed; both remain unavailable. No Muse
identity or zero-usage inference is made.

The review found existing clean-process focus handoff acceptance in
`tests/harness/src/test_zcode_package_dev_focus.c`. It also identified that
the public focus response omits write-scope paths and saved candidate identity.
The proposed regression requires both from the same persisted coding task.
The original-workspace source-root refusal remains an invariant: candidate
edits occur in a separate workspace and do not justify weakening this check.

## Failure and correction

The initial regression added assertions to the existing registered
`zcode_package_dev` workflow. Its first run used:

```sh
make -j4 t-fast ONLY=zcode_package_dev
```

The run failed at `test_zcode_package_dev.c:1202` because `story.focus`
omitted `allowed_write_scopes`. One group ran, one failed, and none skipped.
Local logs: `/tmp/z23-session-resume-red.log` and
`test-tmp/test_parallel_2085551_689.log`.

The correction reuses the task's exact write-scope object, bounds its load,
parses it and verifies its root before rendering paths and `write_scope_root`.
Missing or altered scope bytes return `STORY_SCOPE_UNAVAILABLE`. Saved
`candidate_root` and `candidate_source_root` come from the existing verified
work-status projection. They identify saved objects, not a claim that a
particular filesystem workspace is ready to execute.

## Same-task restart acceptance

The final fixture executes a fresh process after the candidate and its build
and application evidence are saved. That process recovers the exact goal,
permitted paths, changed-file and patch-byte limits, and candidate roots,
then performs the first non-idempotent acceptance of that same task. The
parent repeats acceptance through the existing idempotent path. No model
provider or worker scheduler participates in this fixture.

The fixture also checks missing and corrupted scope objects, an empty
candidate identity before any saved candidate, and the existing refusal of
changed original-workspace source. The registered workflow completed its ten
admissible tasks and refused its two out-of-scope tasks. The successor run
passed one group with zero skips, test-body time 21,929 ms, in
`/tmp/z23-session-resume-successor.log`. Earlier green runs preceded the
successor-completion assertion and establish only their narrower checks.

All 32 fast lint gates passed. The complexity ratchet passed after helper
extraction; the focus handler's baseline decreased from 57 to 56. These are
correctness observations, not speedup or product comparison claims.

The clean-process extension is exercised on Linux. Windows subprocess
continuity is not claimed; its assertion is guarded explicitly. No canonical
datadir, production service or wallet state is used.

## Publication

Non-author child `/root/session_edge_review` independently ran the registered
command at 2026-09-19T23:44:17-04:00 / 2026-09-20T03:44:17Z: one uncached
group, zero failures or skips, test-body time 21,987 ms. The tracked diff's
SHA-256 before and after was
`840f245ce2b33e267ecdb410fa3a065416769d456561f136687c7828b833a568`.
The test executable SHA-256 was
`d2ca4b66e498d82535e8f83c8f9fe75a185b2f5bb941f489358cb74e00102a11`.
The log `/tmp/z23-session-independent.log` had SHA-256
`15265f3945af88fbad4113f65259ffbb9253a22f242dc382433ec44bd006d541`.
Final source review found no blocker. This verifies the local proposal;
integration requires its own exact-source gates.

Mandatory exact-source publication proof and observed remote publication
remain outstanding. The earlier local main integration backlog is preserved
separately from this session-recovery proposal.
