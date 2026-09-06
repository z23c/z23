# Flags

Every runtime, build, and test flag this tree reads out of its process
environment lives in one closed catalog: `engine/composition/flags.def`. A
flag whose name is not a row there is not a flag — `make check-flag-registry`
refuses a `getenv("ZCL_...")` call or a shell/Makefile `${ZCL_...}` /
`$ZCL_...` read whose name is missing from the catalog, and refuses a row the
catalog still carries once nothing in the tree reads it any more. The set can
only shrink on purpose.

## Why one file

Before this catalog existed, adding an environment-variable override was
free: write `getenv("ZCL_WHATEVER")` and it worked, with no record anywhere
of what it did, who added it, or whether anything still needed it. The gate
turns that into a two-step operation — add the read, add the row, in the
same commit — so the set of flags is always a fact the tree can state, not
an archaeology project.

## The four kinds

Each row's `kind_` says how the flag is consumed:

- `env_runtime` — read via `getenv()` from compiled C at run time.
- `env_build` — read by a build or dev-tooling shell script (not a test,
  not a Makefile assignment).
- `env_test` — read by test-harness C, or a script under a `tests/` path.
- `make_var` — read inside the Makefile itself: a variable a caller can
  override with `make VAR=... target` or an exported shell variable of the
  same name.

## Expiry

A row's `expires_` field is either `-` (never expires) or a `YYYY-MM-DD`
date. The gate compares that date against HEAD's own commit date (`git log
-1 --format=%cs`), never the wall clock, so the check is reproducible from
history alone. Once a flag's date has passed, the gate fails until the flag
and its row are removed together, or someone deliberately pushes the date
out because the flag still earns its keep.

## Adding or removing a flag

Adding one: in the same commit, add the `getenv()` / `${...}` read and a new
row in `engine/composition/flags.def` naming its kind, default (or `-`),
expiry (or `-`), and one plain sentence saying what decision it makes.

Removing one: delete the read site and its row together. A row with no
remaining read site fails the gate — the registry can shrink, but never
silently grow orphaned rows.

## Undocumented rows

The catalog's first sweep of the tree found many flags with no comment or
doc explaining them. Those rows carry `undocumented; first use <path>:<line>`
instead of an invented reason, so the debt is greppable:
`git grep -n 'undocumented; first use' engine/composition/flags.def`. Fixing
one is welcome any time — replace the placeholder with a real sentence once
you know why the flag exists.

## The gate

`make check-flag-registry` (part of the full `make lint` umbrella, not
`lint-fast`) parses the catalog and scans every git-tracked `*.c`, `*.h`,
`*.sh`, and `Makefile` for reads. It fails closed on a hollow scan (zero
files, or zero reads) rather than reporting a false "clean". See
`tools/lint/lintc/gate_flag_registry.c` for the implementation and
`tools/lint/check_lint_gate_wiring.sh` for how every lint gate, including
this one, stays wired into both `Makefile` and `tools/lint/run_lint.sh`.
