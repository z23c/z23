# Telemetry contract

The stable shape of `ops.telemetry.*`. This page is the contract; it carries no
live values and no incident history.

## What an agent needs to know

Everything is reachable from `discover help`:

```
z23 discover help ops.telemetry
z23 discover help ops.telemetry.sync
z23 discover describe ops.telemetry.sync.stages
z23 ops telemetry sync stages
z23 ops telemetry watch --since=<sequence>
```

`ops state` and `ops statecatalog` remain as raw-debug surfaces over the same
underlying subsystems. New work should use the typed nested commands; machine
replies always return the canonical path even when an alias was invoked.

## The four layers

| Layer | Owns | Never does |
|---|---|---|
| Field table `<domain>_fields.def` | every field name, unit, tier, health rule, meaning | contain code |
| Provider `<domain>_dump_state_fill` | filling a typed snapshot struct | write JSON, decide health |
| Render `platform/modules/util/src/telemetry_render.c` | JSON, views, health, completeness | know any domain |
| Controller | pick a snapshot and a view | name a field |

A field's name token is written **once**, in the field table. The snapshot
struct, the JSON key, the ontology path and the leaf id are all expansions of
that one token, so they cannot drift apart.

Row grammar: `platform/modules/util/include/util/telemetry_field_table.h`.
API: `platform/modules/util/include/util/telemetry_render.h`.
Domain list (frozen): `platform/modules/util/include/util/telemetry_domains.def`.

## Health is derived, never authored

A field row declares a rule (`TFR_*`), a threshold, and a severity
(`platform/modules/util/include/util/telemetry_field_table.h:18-34`).
The render layer calls `telemetry_field_evaluate()` for each leaf and folds
the resulting health levels into one enum
(`platform/modules/util/src/telemetry_render.c:417-442`):

```
ok < unknown < degraded < unhealthy
```

The `ops state` handler has an annotation branch for a true JSON boolean
`explain` and a returned `state` for a covered subsystem. That branch calls
`telemetry_ontology_annotate()` (`tools/command/native_command.c:604-611`),
which uses the same evaluator
(`platform/modules/util/src/telemetry_ontology.c:598-604`).
Current input validation prevents that branch from being reached: `explain`
falls through to the non-empty string rule
(`engine/modules/kernel/src/command_registry_input_types.c:411-420,539`);
it is absent from the boolean key lists
(`engine/modules/kernel/src/command_registry_input_types.c:67-77`;
`engine/modules/kernel/src/command_registry_devagent_input.c:185-194,352-364`).
The CLI converts `explain=true` to a JSON boolean before validation, which
rejects it as `INVALID_INPUT`
(`tools/command/native_command.c:2446-2448,4205-4216,4286-4291`).
A valid string does not satisfy `json_get_bool()`
(`platform/modules/json/src/json.c`), so the covered-subsystem handler
reports `meaning_available` instead of annotating
(`tools/command/native_command.c:613-619`).
`ops debug meaning` routes questions and reads the static ontology through
`telemetry_ontology_json`; it does not evaluate a supplied field value
(`tools/command/native_command.c:1092-1097,1132-1155`).

`unknown` outranks `ok` deliberately: a reply full of unreadable leaves must
never claim health. It sits below `degraded` because "could not judge" must not
shout louder than "judged, and broken".

The view tier filters **rendering only, never evaluation**, so `--view=summary`
cannot report `ok` while a full-tier field is critical.

## Unknown is never silent

Four independent mechanisms, strongest first:

1. Rendering is table-driven. Every field in the table is emitted; a provider
   cannot omit one, only set its presence.
2. `TELEMETRY_UNSET == 0`, so a zero-initialised snapshot starts with every
   field unset and a forgotten field renders as a counted `provider_defect`
   rather than a plausible zero.
3. An unavailable field renders its key with `null` plus a static reason token,
   so it is judged `unknown` rather than skipped.
4. `completeness` states the totals: `present`, `unavailable`,
   `not_applicable`, `truncated`, `unset`.

A leaf with no provider at all ships `PLANNED` and fails closed with exit 3,
naming what is missing. It never returns an empty object.

## Schemas and versioning

Every leaf declares `zcl.telemetry.<domain>.<leaf>.v1`. Adding a field or a
group is backward compatible and does not bump the version. Removing or
retyping a field does — publish `.v2` and keep `.v1` until callers move.

## `watch`

`watch` is the registry's only `STREAM`-mode leaf and it is a **cursor poll**,
not a long-lived connection: one call returns the bounded batch of changes
recorded after `since` and exits; the agent re-invokes with the last sequence
it saw. Each record carries `sequence`, `captured_at`, `canonical_path`,
`changed_fields`, `health`, `dropped_count`.

A resume that falls behind the ring returns a non-empty batch with the gap
flagged — a missed window and a quiet period must never look alike. The
sequence is not persisted across restart; an epoch value lets an agent tell a
restart from a stall.

## Enforcement

| Gate | Holds |
|---|---|
| `check-telemetry-ontology` | the row-content check rejects an empty `means`; for the eight judged rules it also rejects an empty `next`, including when both `implies` and `next` are empty. Empty `implies` with non-empty `next` passes this check; it does not validate the unit or rule column (`tools/lint/check_telemetry_ontology.sh:485-509`; current rules: `platform/modules/util/include/util/telemetry_ontology.h:59-69`). Table-driven domains receive structural checks (`tools/lint/check_telemetry_ontology.sh:629-672`); scanned fill-provider files fail on calls matching `json_push_kv_(int\|str\|bool\|dbl\|uint)` (`tools/lint/check_telemetry_ontology.sh:675-718`). |
| `check-dumper-never-blocks` | no blocking lock or unbounded scan in a dumper **or** a collector |
| `check-command-contract` | every leaf states its source and freshness |
| `check-command-availability-truthful` | a leaf that cannot answer is `PLANNED`, not silently empty |
| `check-describe-budget` | every `discover describe` document fits its byte budget |
| `check-file-size-ceiling` / `check-long-functions` | 1500-line hard file limit (800-line target), 500-line functions |
