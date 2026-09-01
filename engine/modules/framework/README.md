# engine/modules/framework/

Framework primitives used by the eight `app/` shapes.

This directory is intentionally small. It contains C runtime primitives that are
already real, not a placeholder DSL. Primitive data structures live in
`platform/modules/util`; do not add framework headers whose only purpose is to re-export
them.

| File | Purpose |
|---|---|
| `include/framework/condition.h` + `src/condition.c` | Condition registry and engine: `{detect, remedy, witness}` structs with polling, backoff, witnessed recovery, and operator escalation. |

Do not add macro-only scaffold here. The canonical form is a plain struct plus
registration function that can be grepped, stepped through, and linted. See
[`docs/FRAMEWORK.md`](../../../docs/FRAMEWORK.md) for the architecture and its
§9 debt board for active debt.
