<!-- Copyright 2026 Rhett Creighton - Apache License 2.0 -->

# Windows filesystem boundary acceptance

## Intent

Keep native Windows package traversal usable without following reparse points,
and keep the authority-bearing consensus store inert until SQLite can bind its
main database, WAL, SHM, journal, and migration operations to a retained
directory capability. Correct Windows state-root and registry checks that did
not exercise the behavior their targets named.

## Environment

- Local time: `2026-08-29T18:11:22-04:00`
- UTC: `2026-08-29T22:11:22Z`
- CPU: AMD Ryzen 7 PRO 8840U with Radeon 780M Graphics
- Native compiler: `gcc (GCC) 16.1.1 20260430`
- Cross-compiler: `x86_64-w64-mingw32-gcc (GCC) 16.1.0`

## Method

The Windows package scanner was changed from pathname enumeration to one
retained root handle. Every child is enumerated with `NtQueryDirectoryFile`,
opened relative to its retained parent with `NtCreateFile` and
`FILE_OPEN_REPARSE_POINT`, classified from that handle, and read from that same
handle. Reparse points and non-disk special objects are refused. File identity,
size, modification time, and change time are compared before and after reads.

The Windows consensus store was reviewed from its first operation. Legacy
migration ran before directory validation and used pathname-based SQLite,
unlink, and rename operations. The later directory comparison did not bind
SQLite's separate main/WAL/SHM opens. The Windows entry therefore again refuses
before migration or mutation. Its acceptance fixture carries a real
`progress.kv` sentinel and proves its identity, metadata, and bytes are
unchanged while every `consensus.db` and `consensus.db.tmp` family member stays
absent.

The Windows state-root override now enters through `GetEnvironmentVariableW`
and converts explicitly to UTF-8. The fixture uses a Unicode override, creates
pre-existing permissive `z23/dev` directories, verifies their repair to the
owner-private contract, and removes the complete fixture. ACL repair first
proves a real, non-reparse directory owned by the current SID.

Focused commands:

```bash
make build/tests/windows/package_prepare.exe
make build/tests/windows/progress_store_refusal.exe
make build/tests/windows/state_root.exe
wine build/tests/windows/package_prepare.exe
wine build/tests/windows/progress_store_refusal.exe
wine build/tests/windows/state_root.exe
make zcode-package-registry-check
make -j4 t-fast ONLY=mesh_route
make -j4 t-fast ONLY=mesh_status_wire
make -j4 t-fast ONLY=zcode_package_registry
make -j4 t-fast ONLY=progress_store
make -j4 t-fast ONLY=consensus_db_migrate
make -j4 t-fast ONLY=consensus_db_flip
```

The four changed production translation units also passed MinGW C2x syntax
checking with `-Wall -Wextra -Werror -pedantic`.

## Result

The package acceptance passed under Wine, including a real file-reparse-point
refusal. The progress-store and state-root executables cross-linked under the
strict Windows catalog; Wine returned the documented exit 77 because it could
not prove the native current-SID/private-DACL contract. This is an honest
runtime refusal, not Windows runtime evidence.

All six registered native groups passed with one group run, zero failures, and
zero self-skips. The registry executable ran and rederived 10 roots and the
exact dependency DAG. Native Windows consensus-store operation remains
unavailable. Enabling it requires a retained-directory SQLite VFS whose
`xOpen`, `xDelete`, `xAccess`, and `xFullPathname` behavior is capability-bound,
including WAL, SHM, journal, temporary files, and legacy migration.
