<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# tests/

`harness/src/test_<group>.c` is registered test group `<group>`; `harness/include/test/` holds shared helpers; `fixtures/` holds local fixtures (`blocks`, `fleet_observations`, `riscv-tests`).

Rules:
- Run groups only through `make t-fast ONLY=<group>` (substring) or `make t-fast-exact ONLY=<group>`; never run `test_zcl` directly.
- A test file that exists proves nothing; zero groups run is a failure.
- Never weaken an assertion, threshold or fail-closed refusal to pass.
- Use local fixtures and isolated datadirs; never a live node or wallet.
- Some tests pin exact documentation sentences: `git grep -n "<sentence>" tests` before rewording a doc.
- Add an impact rule when no existing pattern covers a new test file: `cognition/controllers/include/controllers/agent_impact_rules.def`.

Commands: `make t-list`, `make t-fast ONLY=<group>`, `make -j"$(getconf _NPROCESSORS_ONLN)" agent-verify ONLY=<g,g>`.
