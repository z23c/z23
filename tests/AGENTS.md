<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# tests/

`harness/src/` contains test implementations; filenames do not necessarily name registered groups. `harness/include/test/` holds shared helpers, and `fixtures/` holds local fixtures (`blocks`, `fleet_observations`, `riscv-tests`).

For focused editing, use `make t-list` to discover registered groups and inspect
the test's registration and shard table to find its owner. In `g_dlx_shard_cases`
in `harness/src/test_dev_land.c`, `dlx_case_precheck` has owner `1u`.
For ordinary native fleet slices, the land queue runs committed-candidate proof.
Run `make agent-verify ONLY=@changed` when an explicit task or another applicable
workflow requires it. Focused tests provide feedback, not exhaustive proof.

Rules:
- Use `make t-fast ONLY=<group>` (substring) or `make t-fast-exact ONLY=<group>` (exact). For `test_dev_land_precheck.c`, run `make t-fast-exact ONLY=dev_land_shard_02`. Never run `test_zcl` directly.
- For an expected failure, `make t-fast-exact ONLY=<group> T_FAST_EXACT_ARGS=--diagnostic-once` runs once and produces no acceptance proof.
- A test file that exists proves nothing; zero groups run is a failure.
- Assertion macros jump to `_test_next`, a function-scoped C label. Do not duplicate that label when adding a test block; use a separate helper function or combine related assertions under one test. `TEST_END` also defines the label.
- Never weaken an assertion, threshold or fail-closed refusal to pass.
- Use local fixtures and isolated datadirs; never a live node or wallet.
- Some tests pin exact documentation sentences: `git grep -n "<sentence>" tests` before rewording a doc.
- Add an impact rule when no existing pattern covers a new test file: `cognition/controllers/include/controllers/agent_impact_rules.def`.

Commands: `make t-list`, `make t-fast ONLY=<group>`, `make -j8 agent-verify ONLY=<g,g>`.
