<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# cognition/

Software-understanding machinery: `modules/` (`codeindex`, `ontology`, `retrieval`, `science`, `session`, `fleetfacts`, `territory`, `kpi`, `fingerprint`), plus `controllers/`, `models/`, `services/`.

Entry files: `modules/codeindex/` (navigator behind `z23 code ...`), `controllers/include/controllers/agent_impact_rules.def` (changed file to focused test group rules).

Rules:
- A new source file or test needs an impact rule in `agent_impact_rules.def` when no existing pattern covers it.
- The source universe is defined once in `modules/codeindex/include/codeindex/source_roots.def`; change it there only.
- Derived indexes (`.codeindex/`) are caches; delete freely, never commit.

Tests: `make t-fast ONLY=codeindex`, `make t-fast ONLY=code_firsthour`; for a wider change `make -j"$(getconf _NPROCESSORS_ONLN)" agent-verify ONLY=@changed` (committed changes; or ONLY=<g,g>).
