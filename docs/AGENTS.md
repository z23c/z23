<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# docs/

Manuals and plans. Index: `README.md`. Procedure: `DEVELOPING.md` (open one section, never the whole file). Ownership map: `CODEBASE_MAP.md`. Fleet: `FLEET.md`, `work/AGENT_FLEET.md`, `agent/`. Current work order: `work/FORWARD_PLAN.md`.

Generated, never hand-edit (regenerate with the canonical target):
- `API_REFERENCE.md` from `API_REFERENCE.md.in` and the command `.def` files: `make docs-api-reference`.
- `CAPABILITY_INVENTORY.jsonl`: `make docs-capability-inventory`.
Both are excluded from search by the root `.ignore`; open them by path.

Rules:
- A prose assertion about code carries a claim marker (syntax in `docs/DEFENSIVE_CODING.md`); `tools/lint/check_doc_claims.sh` fails when it stops holding. Move the marker with the text.
- Relative links must resolve (`check-markdown-links`); inline code paths must exist (`check_doc_inline_paths`).
- Entry documents avoid positive-reliance phrasing; keep wording factual and current.
- No private host names, home paths, ssh aliases or ledgers.

Check: `make lint-fast`.
