<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Match capability declarations to compiled entry points

The composed proof at `d6943d5f1` reported six capability declaration
violations. The three affected source files and their declarations were
unchanged from `f7ec11759`. Inspection of the proof generation's objects
confirmed the existing external references:

| Source | Classified references | Exact declaration |
| --- | --- | --- |
| `wallet_gui.c` | `fopen`, `fgets`, `__fprintf_chk`, `webkit_web_view_load_uri`, `sqlite3_busy_timeout` | `FS_READ`, `FS_WRITE`, `NETWORK`, `CLOCK` |
| `wallet_gui_bot.c` | `webkit_web_view_run_javascript` | `PROCESS` |
| `native_dev_train_shared.c` | Internal platform and spawn calls; harmless external libc calls | `NONE` |

Only these three declaration rows changed. No source capability, symbol
classification, enforcement threshold, or platform override changed.

On Linux, the unchanged capability gate scanned the proposal worktree's
existing complete epoch
`2ec8d82c200e4c4fab57e674a5166feba435b7f518ae0b70b7ee5d69c146fd49`:
2275 objects, 1083 classified symbols, and 1196 module rows. It reported zero
unclassified, undeclared, or overdeclared references. Its 15 selftests passed.
The two declared-but-unobserved rows and one compiled-out clock declaration
remain explicit; their thresholds were not changed. No rebuild was needed.

GUI reach depends on both `HAVE_GTK` and `HAVE_WEBKIT`. With neither defined,
the existing guard detector reports the omitted GUI reach as unobserved.
With only one defined, its conservative conjunction handling can report an
overdeclaration. This change does not claim that configuration was tested or
alter the guard detector to suppress it.

Recorded at `2026-09-08T03:47:23-04:00` /
`2026-09-08T07:47:23+00:00`. This focused closure result is not a completed
composed publication proof.
