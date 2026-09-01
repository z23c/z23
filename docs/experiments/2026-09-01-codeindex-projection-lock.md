<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Code-index projection lock verification

## Intention

Keep retrieval projection verification on one exact SQLite snapshot without
recursively acquiring the code-index store's non-recursive mutex.

## Counterexample

Incoming commit `8d291c3c60432c7993b4007dd0aea9f139d325ad` acquired the
store mutex in `ci_store_retrieval_projection_is_valid()`, then called both
`ci_store_meta_get()` and `ci_store_retrieval_projection_root()`. Each callee
acquired the same mutex again. The root function also acquired the mutex before
calling `ci_store_meta_get()`. A retrieval view therefore could not reach its
first logical projection comparison.

## Change

The metadata reader and projection root now have lock-held internal forms.
Both public operations acquire the mutex once, inspect metadata and all
retrieval tables within that one snapshot, then release it. Malformed derived
rows still report an invalid generation so the retrieval opener can rebuild
from exact source.

## Evidence

Observed locally at `2026-09-01T12:03:39-04:00`
(`2026-09-01T16:03:39+00:00`):

```text
make -j16 t-fast ONLY=codeindex_projection_integrity
groups_total=1068 groups_ran=1 groups_failed=0 self_skips=0
test_body_ms=41
```

The group passed 20 assertions covering independent equal projections,
physical row reordering, seven logical poison forms, rejection, and exact
deterministic rebuild.
