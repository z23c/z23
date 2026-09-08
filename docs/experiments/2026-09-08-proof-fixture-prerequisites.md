<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Prepare declared proof fixtures before generation capture

The native proof for commit `a5c1d961d58406d77a8b761d2191d04ac9c97eed`
against base `f7ec11759f3fad1d80ccde386c32196a44f08f83`, requested from
the performance integration worktree, failed after 340826 ms during
original-plan preparation and generation setup. The required Linux artifact
`build/hotswap/zcl_rollback_fixture_a.so` was absent. Preparation requested
only `make dev-bin`; generation materialization required both rollback images.

Preparation now requests the two existing rollback-image targets in the same
Make invocation as `dev-bin` on Linux. Other platforms retain their existing
prerequisites. This builds the declared artifacts without compiling the full
test runner. Generation materialization still refuses missing dependencies.

The registered `impact_composition` fixture defines the rollback artifacts as
separate Make targets. After removing them, it requires generation copying to
refuse, then requires preparation to restore both artifacts before copying
succeeds. Its marker files test prerequisite scheduling and materialization;
they do not establish native module admission.

`git diff --check` and the canonical cyclomatic-complexity gate passed. The
fixed registered group passed with no skips in 105.9 seconds. Restoring only
the prior `dev-bin` preparation argv reproduced the regression: the group
failed at `ic_original_plan_recovers_fixtures`, including the runner's
automatic isolated retry, with no skips in 254.5 seconds. The fixed source
was restored byte-for-byte afterward. Final registered validation after
correcting the affected flag-registry source pointer passed with one group,
zero cache hits, zero failures, and zero skips in 228.3 seconds. The
flag-registry gate verified all 1146 first-use pointers. These runs were not
controlled performance comparisons. No publication or successful end-to-end
proof is claimed.

Validation host: Linux, AMD Ryzen 7 PRO 8840U, GCC 16.1.1 20260430;
recorded at `2026-09-08T03:01:24-04:00` / `2026-09-08T07:01:24+00:00`.
`make worktree-prime SRC="$DONOR_ROOT"` completed, with `DONOR_ROOT`
resolved to the performance integration worktree,
including the pinned embedded Tor build. The isolated registered command is:

```bash
nice -n 10 make -j4 t-fast-exact ONLY=impact_composition \
  T_FAST_EXACT_ARGS=--no-cache
```
