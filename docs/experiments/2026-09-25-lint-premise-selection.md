<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Base-relative lint premise selection: dry run over real main commits

Date: 2026-09-25. Host: Linux 6.8, Landlock ABI 4, x86_64-w64-mingw32-gcc
and clang on PATH. Tool: `z23-lint select --dry` (slices 1 and 2 of the
premise-selection design: the premise core and the Landlocked
`z23-lint unit-exec` runner). Nothing here is authority. No gate reads
these rows, no verdict is inherited, and no premise root is persisted.

## What one row claims

For each translation unit of `check-windows-cross-syntax` and
`check-clang-portability`, `select --dry` prints the candidate's premise
root (`action_root`), the same fold over the verified base (`base_root`),
`would_inherit`, and the first reason the two differ. The premise is:

- the gate code, the selection engine and policy files, the toolchain pin,
  and the text of the Makefile variables the gate reads (plus every
  variable those reference);
- the root of the path set, so an added, removed or renamed path (every
  "does this header exist" lookup) flips every unit;
- the over-approximate textual include closure of the unit (every include
  or embed directive, ignoring `#if`, each name resolved to every tracked
  path it could name under any `-I` order);
- the unit's own rows in the gate's baselines.

The base is verified before any row can say `would_inherit=true`.
`git ls-remote` of the canonical remote names the `main` tip. `git fetch`
copies that tip's recent history into an empty private store; index-pack
there re-derives every object id, so a planted object in the persistent
store fails the copy. The base must be an ancestor of that tip. Base file
bytes come only from the private store and are hashed with SHA3-256. Git
object ids stay opaque locators handed to Git, which is the same recipe dev
land's remote observation uses (`tools/dev/dev_git_tree.c`). Without
Landlock, or with `--no-landlock`, every row reads
`would_inherit=false`.

## Method

Each commit was checked out as a detached worktree and measured against
its first parent:

```bash
git worktree add --detach "$SCRATCH/wt_$C" "$C"
z23-lint select --dry --base="$(git rev-parse "$C~1")" \
  --root="$SCRATCH/wt_$C" --objects="$PWD" --scratch="$SCRATCH"
```

The unit lists are each gate's own: the cross-syntax gate's
`make ZCL_TARGET=windows-x86_64 print-node-c23-srcs` `.c` paths, and the
clang-portability gate's coverage oracle, which its scan must equal. One
run took 19–22 s wall. That covers the `make` unit listing (about 7 s),
the private-store fetch (about 4 s), and hashing and closure over 2,339
units.

## Results

| Commit | Change | cross-syntax would inherit | clang-portability would inherit | Fresh units and reason |
|---|---|---:|---:|---|
| `2159242a84` | `codeindex_inventory_evidence.c` plus a lint baseline row | 2338 / 2339 | 2336 / 2337 | `codeindex_inventory_evidence.c` in both gates: `closure-changed` on itself |
| `c472356ff2` | `tools/dev/dev_proof_observation.c` | 2339 / 2339 | 2337 / 2338 | `dev_proof_observation.c` (clang only; the file is not in the Windows node set) |
| `a21195c8d6` | `dev_proof_observation.{c,h}` plus a test file | 2339 / 2339 | 2337 / 2338 | `dev_proof_observation.c`, the only unit in either set that includes the changed header |

For a narrow edit, both per-TU gates would recompile one unit out of about
2,340. The edited baseline file in `2159242a84`
(`cyclomatic_complexity_baseline.txt`) belongs to neither gate, so it
flipped nothing.

## Limits of this measurement

- The toolchain pin (`tools/dev/toolchain.pin`) does not exist yet. Its
  absence is a hashed state, so a compiler upgrade between base and
  candidate is not yet part of any premise. Until the pin slice lands, these
  counts describe what selection would skip, not what it could safely skip.
- A new or deleted file anywhere outside the pruned directories flips every
  unit through the path-set root. The three commits above only modified
  existing files.
- Units are not run here. That `unit-exec` holds a real compile to its
  premise is proven by the `lint_selection` test group: a computed premise
  compiles under the Landlock domain, while a premise missing one header
  fails with `PREMISE_INCOMPLETE`.
- Trust in the base still rests on Git's SHA-1 object ids, as dev land's
  own remote observation does. No z23 code computes SHA-1, and every root
  here is SHA3-256 over bytes.
