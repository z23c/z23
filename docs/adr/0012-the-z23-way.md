# ADR-0012: The Z23 way

- **Status:** Accepted 2026-10-22.
- **Deciders:** Project maintainer.

---

## Context

On 2026-10-22 two land queues were frozen and deploys sat 144 commits behind
`main`. A lane that held a valid receipt could push `main` directly, so the
queue was not the only road. Generated files caused the most churn: the
capability inventory alone changed 202 times in 10 days, and every refresh
raced every other landing. Tooling commits had also grown into a large share
of `main` with no measure of whether they helped.

The project needs one road to `main`, one place the queue lives, one inner
loop, and a budget for work about the work.

## Decision

| Topic | Decision |
| --- | --- |
| Route to main | `build/bin/z23-dev dev land submit --worktree=<lane>` on the land host. Only the land driver pushes `main`; the native pre-push hook (`tools/dev/z23_git_hook.c`, installed by `make install-hooks`) refuses every other `main` push. |
| Queue host | The land host runs the single land queue and its resident driver (`z23-land-step.timer`). |
| Generated docs | Not tracked (wave 2). Built into `build/gen/` by make targets; gates recompute them and nothing compares against a stored copy. |
| Inner loop | `make check ONLY=<exact ids>` (renamed from `agent-verify`, which stays one release as an alias). `ONLY=` is exact; substring matching uses `MATCH=`. |
| Full lint | Once per landed tree, in the land proof. Lane lint is optional feedback. |
| Work order | `docs/work/FORWARD_PLAN.md#now`, at most 7 ranked items, product first. Claims go through the native `dev.agent` registry; `cards.jsonl` holds volunteer slices linking to NOW items. |
| Command spelling | `build/bin/z23-dev dev ...` for dev leaves; `z23 ...` for node leaves. |
| Lab code home | `cognition/`. `tools/` holds only build-time programs and gates. |
| Test placement | `tests/<room>/` mirrors the source room. |
| Meta budget | KPI `meta_share_7d`, target at most 30% of `main` commits; queue enforcement only if it stays over target for 2 weeks. Tooling commits cite the KPI they move, before and after. |
| New tables | A new `.def` must delete at least 2 hand-kept lists. |

## Consequences

For every agent (Claude, Codex, humans):

- Land through `dev land submit`; never push `main`. A refused push is the
  hook working, not a fault to route around.
- Do not commit regenerated docs expecting them to be compared later; run
  the make targets and read `build/gen/`. Until wave 2 lands, the landing
  proof still folds the generated paths it knows about.
- Use `make check ONLY=<exact ids>` while editing, and run the full lint
  once, in the land proof, rather than before every commit. Lane lint is
  feedback, not a gate.
- Take work from the NOW list, claim it through the `dev.agent` registry,
  and link volunteer slices from `cards.jsonl` to a NOW item.
- Put lab code under `cognition/` and tests under the room they test.
- A tooling commit states the `meta_share_7d` effect it expects and what it
  measured. A new `.def` table ships with the deletion of at least two
  hand-kept lists it replaces.
- The legacy bash lander, its queue binary and its unit are removed; the
  native driver is the only lander.

Enforcement of the meta budget stays advisory unless the share remains over
target for two consecutive weeks.
