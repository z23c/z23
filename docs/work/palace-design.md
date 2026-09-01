# The Palace — the legibility + invariant layer for fast LLM development

**One binary. One chain. One way to do each thing — an LLM learns WHERE a
thing lives, WHAT it does, and WHAT it breaks in near-zero tokens, because
the layout is indexed and the beauty is lint-enforced.**

Four properties, each a lookup rather than a guess:

| Property | Mechanism |
|---|---|
| Location predicts content | 7 shape folders (the Event shape has none), lint-enforced by `tools/lint/framework_shape_check.sh` + `tools/lint/check_framework_filename_suffix.sh`; shapes canonical in `cognition/modules/codeindex/src/codeindex_group.c` (`k_app_shapes[]`) |
| Navigation is O(1) indexed | `cognition/modules/codeindex/` SQLite index + the `code` command branch (`engine/composition/commands/code.def`, `tools/command/native_code_command.c`) answer where-is/what-calls/what's-in-file without grep |
| Impact is a lookup | `cognition/controllers/src/agent_impact_rules.c` (`agent_impact_apply_shared_rules`) maps a changed path → focused test groups, shared by native `agentimpact` and `make fast-ci` |
| Content self-describes | every indexed file carries a `purpose` string, derived from the first substantive line of its top-of-file block comment (`ci_file_purpose()`, `cognition/modules/codeindex/src/codeindex_scan.c`); `code file`/`code group`/`code map` render it |

## Self-description

**Rule:** a file's purpose is the first substantive line of its top-of-file
block comment (an optional leading `<stem> — ` / `<stem>: ` / `<stem> - `
prefix is stripped). A file whose leading comment is genuinely not a purpose
may override with an explicit `/* purpose: ... */` first line.

`ci_file_purpose()` extracts it during the existing scan pass (no second
parse, no schema migration); `codeindex_build.c` stores it in `f.purpose`;
`code file`/`code group`/`code map` render it.

## Unified namespace view — `code room <path>`

Joins the four namespaces above for one path in a single bounded JSON
response: `shape` (from the group path), `purpose` (`finfo.purpose`),
`group` + `neighbors` (`codeindex_files_in_group()`), `tests[]`
(`agent_impact_apply_shared_rules`), and `commands[]` (resolved via the
handler-symbol join where available; `null` with a stated reason otherwise —
never a wrong guess). `code map` remains the floor plan (grouped/categorized
counts); `code room` is the single-room detail.

## The lint gates that keep it decay-proof

Each follows the shape-gate ladder (`ZCL_LINT_MODE` WARN → RATCHET
(shrink-only baseline) → HARD):

- **`check-file-purpose`** (`tools/lint/check_file_purpose.sh`) — every
  indexed `.c`/`.h` must yield a non-empty derivable purpose.
- **`check-group-purpose`** (`tools/lint/check_group_purpose.sh`) — every
  group node (`ci_group_emit_all`) must have a non-empty purpose; the group
  list is finite (~35 `lib/<mod>` + fixed roots), so this gate runs HARD.
- **`check-no-orphan-placement`** (`tools/lint/check_no_orphan_placement.sh`)
  — no new source file may land in the catch-all `root` group; every file
  must resolve to a known `lib/<mod>`/`app/<shape>`/`core`/`config`/`domain`/
  `adapters`/`ports`/`tools` group.

Each gate is planted-and-asserted in `test_make_lint_gates` per
`docs/FRAMEWORK.md` §5's gate-testing convention.

## No physical reorg

The palace is a legibility + invariant layer, not a file-move. The 8-shape
location structure is already enforced (`docs/FRAMEWORK.md` §9); a tree-wide
move would churn includes/depfiles and touch the consensus boot path for
near-zero additional legibility gain once purpose data and `code room` exist.
If a boot-monolith split ever happens, it happens on the architecture axis
under copy-prove, not as part of this layer.

Nothing here changes consensus, the reducer, the fact log, or any runtime
path — this is derived, read-only, recomputed-never-repaired, the same
posture as `cognition/modules/codeindex/` and `contexts/commons/modules/vcs/`.
