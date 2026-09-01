# Model Layer

`engine/models/` is the ActiveRecord-style persistence boundary for app-owned and
node-projection data.

## Goals

- keep SQL out of controllers when the data is really a model
- make validation and callback behavior consistent across records
- keep CRUD code predictable for humans and LLM-assisted maintenance
- centralize SQLite statement patterns behind shared macros instead of
  hand-rolling them in every file

## Standard File Shape

Follow this order in model source files:

1. `DEFINE_MODEL_CALLBACKS(model_name)`
2. optional normalization hooks like `*_before_save`
3. optional `DEFINE_MODEL_BEFORE_SAVE_READY(...)`
4. `validate_*` function using `validates_*` helpers
5. save methods
6. row readers / deserializers
7. find / list / count / exists helpers
8. delete / update helpers

## Macro Guide

The shared macros live in [activerecord.h](include/models/activerecord.h).

Use these by default:

- `AR_BEGIN_SAVE` / `AR_FINISH_SAVE`
  Use when saving through a cached prepared statement.
  Parameters:
  `cbs`: model callbacks.
  `model_name`: short validation log label.
  `record`: model pointer.
  `validate_fn`: model validation function.
- `AR_ADHOC_SAVE`
  Use when the save query is prepared locally in the function.
  Parameters:
  `ndb`: `struct node_db *`.
  `stmt`: local `sqlite3_stmt *`.
  `sql`: fixed SQL string.
  `cbs`: model callbacks.
  `model_name`: short validation log label.
  `record`: model pointer.
  `validate_fn`: model validation function.
  `bind_code`: one or more `AR_BIND_*` calls.
- `AR_QUERY_ONE_BOOL`
  Use for `_find()` / `_find_by_*()` functions that load one row or return `false`.
  Parameters:
  `ndb`, `stmt`, `sql`: query setup.
  `bind_code`: binds lookup params.
  `row_code`: deserializes the current row into the output record.
- `AR_QUERY_EXISTS`
  Use for `_exists()` helpers.
  Parameters:
  `ndb`, `stmt`, `sql`: query setup.
  `bind_code`: binds lookup params.
- `AR_QUERY_LIST`
  Use for list/read functions that fill an output array.
  Parameters:
  `ndb`, `stmt`, `sql`: query setup.
  `out`: output array.
  `max`: max rows to emit.
  `bind_code`: binds query params like `LIMIT`, `OFFSET`, or filters.
  `row_code`: fills `out[count]`.
- `AR_QUERY_COUNT_SQL`
  Use for simple `COUNT(*)` queries with no bind params.
- `AR_QUERY_INT64_SQL`
  Use for simple aggregate int64 queries with no bind params.
- `AR_EXEC_BOOL`
  Use for simple `UPDATE` / `DELETE` statements where `SQLITE_DONE` is enough.
  Parameters:
  `ndb`, `stmt`, `sql`: statement setup.
  `bind_code`: binds statement params.
- `AR_EXEC_CHANGED_BOOL`
  Use for `UPDATE` / `DELETE` where at least one changed row is required.
  Same parameters as `AR_EXEC_BOOL`.
- `AR_ADHOC_DESTROY`
  Use for local prepared delete statements that should run destroy callbacks.
  Parameters:
  `ndb`, `stmt`, `sql`: delete statement setup.
  `cbs`: model callbacks.
  `record`: model pointer being deleted.
  `bind_code`: binds delete key params.
- `AR_CACHED_DESTROY`
  Use for cached delete statements that should run destroy callbacks.
  Parameters:
  `stmt`: cached prepared delete statement.
  `cbs`: model callbacks.
  `record`: model pointer being deleted.
  `bind_code`: binds delete key params.

## Example Call Shapes

```c
sqlite3_stmt *s = NULL;
AR_ADHOC_SAVE(ndb, s,
    "INSERT OR REPLACE INTO table_name(a,b) VALUES(?,?)",
    cbs, "model_name", rec, validate_model_name,
    AR_BIND_INT(s, 1, rec->a);
    AR_BIND_TEXT(s, 2, rec->b));
```

```c
sqlite3_stmt *s = NULL;
AR_QUERY_ONE_BOOL(ndb, s,
    "SELECT col1,col2 FROM table_name WHERE id=?",
    AR_BIND_INT(s, 1, id),
    row_to_model_name(s, out));
```

```c
sqlite3_stmt *s = NULL;
AR_QUERY_LIST(ndb, s,
    "SELECT col1,col2 FROM table_name ORDER BY id DESC LIMIT ? OFFSET ?",
    out, max,
    AR_BIND_INT(s, 1, (int)max);
    AR_BIND_INT(s, 2, (int)offset),
    row_to_model_name(s, &out[count]));
```

```c
sqlite3_stmt *s = NULL;
AR_ADHOC_DESTROY(ndb, s,
    "DELETE FROM table_name WHERE id=?",
    cbs, rec,
    AR_BIND_INT(s, 1, rec->id));
```

## Design Rules

- prefer model APIs over controller-owned SQL
- use prepared statements and bind values, not interpolated SQL
- use whitelist logic for any dynamic SQL fragment that cannot be bound
- keep model callbacks for normalization, not business workflow
- keep service-layer orchestration out of models
- keep controllers thin: validate input, call services/models, format response

## When Not To Add A Macro

Do not add a macro just to hide one line of code. Add one only when:

- the pattern already exists in multiple files
- the macro makes the lifecycle more obvious, not less
- the call site becomes shorter and more uniform after the change
- the semantics stay narrow and predictable

If a helper needs branching, ownership, or multi-step workflow logic, prefer a
small static function over another macro.
