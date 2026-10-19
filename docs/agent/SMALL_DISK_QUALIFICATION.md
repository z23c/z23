<!-- Copyright 2026 Z23 contributors. Licensed under Apache-2.0. -->

# Qualifying on a small disk

Admit each validation job from measured headroom rather than discovering its
peak by exhausting the filesystem. The decision is local and private; publish
the gate result, not host capacity or load figures.

## Admission formula

For every filesystem the job writes, require:

```text
available >= protected reserve + credible peak growth + stopping margin
```

Derive peak growth from the same target, toolchain, cache state, temporary
location, log retention, and concurrency. Do not count a memory filesystem as
disk headroom, and do not count one mount twice through a different path.
Recheck immediately before launch and between bounded stages.

Prefer the smallest required sequence:

1. Route changed files with `z23 code tests <path>`.
2. Run the focused registered group with `make t-fast-exact ONLY=<group>`.
3. Run relevant sanitizer and architecture checks.
4. Run `make lint-fast` during iteration.
5. Run the repository-required full `make lint` and exact proof only at the
   final candidate tip through the applicable admitted build route.

Reuse exact receipts and compatible cached inputs. Do not rerun an unchanged
failure or delete warm objects needed by the next gate merely to report more
free space. When cleanup is due, remove only inactive, regenerable outputs
whose users, Git state, mounts, symlinks, and protected contents were checked;
measure the actual filesystem change afterward.

## Stop and report honestly

Stop before crossing the protected reserve. Record the exact completed stage
as **PASS** or **FAIL** and every unexecuted gate as **NOT RUN**. A focused
test, sanitizer witness, compatible receiver receipt, and full lint are
different evidence scopes.

Keep private all credentials, keys, wallet material, machine paths, private
endpoints, personal data, and host load or capacity figures. A public wiki
lesson may explain the admission method without disclosing the machine that
used it.
