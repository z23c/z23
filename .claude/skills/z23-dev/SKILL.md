---
name: z23-dev
description: Use when developing Z23 as a maintainer or fleet member, understanding its architecture, or making a source change. Points to the canonical contract and the section of the developer manual to read, instead of importing it.
---

Public volunteers use `.github/CONTRIBUTING.md` and the `z23-work` skill, not
this one.

Read [`AGENTS.md`](../../../AGENTS.md) and [`docs/THE_Z23_WAY.md`](../../../docs/THE_Z23_WAY.md) first. The developer manual
[`docs/dev/DEVELOPING.md`](../../../docs/dev/DEVELOPING.md) is large; read only the
section for your step, with `grep -n '^## ' docs/dev/DEVELOPING.md` to find it:

| Step | Section |
| --- | --- |
| Fresh machine | `0. First hour on a clean machine` |
| Find the right code | `1. Orient`, `2. Inspect exact context` |
| Edit | `3. Edit within ownership boundaries` |
| Feedback and tests | `4. Receive fast local feedback`, `5. Build and focused proof` |
| Integrate and push | `6. Integrate and push a coherent slice` |
| Fleet policy, hosts, priorities | `Maintainer hosts`, `Fleet entry and policy ownership`, `The normal loop` |

This compatibility skill holds no project doctrine; edit the canonical
documents instead.
