<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Worker path portability and proof prerequisites

Observed on 2026-09-19T18:56:11-04:00 / 2026-09-19T22:56:11+00:00.
Host: Linux, AMD Ryzen 7 PRO 8840U. Host compiler: GCC 16.1.1 20260430.
Windows cross compiler: x86_64-w64-mingw32-gcc 16.1.0.
Source baseline: `a6c62003efd8aa6add52e1d6e8f5caca10a9bc3c`.

## Failure and correction

The exact publication proof rejected three Windows translation units for
unavailable POSIX calls: candidate restoration used `fsync` and `lstat`,
worktree cleanup used `lstat`, and receiver inspection used `lstat`, `S_ISLNK`
and `realpath`. The Windows worker-confinement acceptance executable also
failed `-Werror` because its volatile CPU-loop counter was never read.

Candidate restoration now uses the existing platform file-sync and regular-file
metadata contracts. Cleanup distinguishes a missing path from unreadable
metadata and retains the latter as present. Windows receiver inspection uses
handle-observed regular-file size and modification time and refuses reparse
points; Windows has no POSIX executable bit. Its root resolver uses the existing
canonical-directory contract. POSIX root resolution and indexed file checks
retain their previous behavior. The confinement workload reads its counter
after the loop without removing the CPU load.

## Measured validation

```bash
make -j8 check-windows-cross-syntax build/tests/windows/devagent_worker_confine.exe
```

The command exited zero. Cross-syntax compiled 2,333 translation units, all
clean, with zero skipped headers, zero baselined files and zero new failures.
The worker-confinement executable cross-linked with `-Wall -Wextra -Werror
-pedantic`. These are compilation results, not Windows runtime qualification.
Focused Linux behavior tests passed after integrating the incoming status
changes described below. The complete publication proof remains required.
`make docs-capability-inventory` regenerated the derived source evidence;
`tools/lint/check_capability_inventory_generated.sh` then passed with 1,500
capabilities and 1,149 registered roots resolved.

The submitting checkout also had Tor archives recorded against an older
submodule commit. An explicit `ZCL_TOR_JOBS=8 make tor-full` rebuilt from the
pinned `f4e28103c0eb9016e0b500d02486b7a59d20ee5d`; the provenance self-test,
archive hashes, source commit and compiler identity checks passed afterward.
No provenance record was edited to attest unchanged stale archives.

## Native worker attempt

The existing queue accepted `portable-proof-prerequisites`, and its resident
worker claimed and executed one job in an isolated checkout. Worker status
reported `executing` with a live process identity. The attempt was refused
before testing when reported usage exceeded its explicit 500,000-token cap:
526,860 input plus 2,799 output tokens, 36,752 ms executor wall time. No source
changes remained, and the executor recorded the workspace clean at its pinned
base. The subsequent repair was made locally and is not attributed to a
successful worker candidate. No successful worker-to-publication cycle follows
from this experiment. The next worker-budget investigation must inspect actual
usage events before increasing the cap or resubmitting the job.

## Integration and status refusal coverage

The incoming `f44c2ab81bf7287adf22682c6bc4c078eeb1f7c7` adds read-only worker
status, queue capacity observations and candidate reports. Review found that
its worker status classified every failed queue `stat` as measured emptiness
and did not detect read errors. The integration limits measured absence to
`ENOENT`, rejects nonregular ledgers, verifies complete JSON rows and valid
job names/attempts, and discards partial observations on parse or stream
failure. Queue-path truncation is also refused. The regression covers a
self-referential symlink, a directory, malformed JSON, an incomplete final
line, a traversal name, and an invalid attempt type. Counts and job identity
remain unknown in those cases.

```bash
make -j8 t-fast-exact ONLY=test_devagent_worker,test_devagent_queue,test_devagent_mail,test_devagent_receive,test_devagent_muse_run,test_fleet_steer,test_host_gc,test_dev_ci
```

On 2026-09-19T19:05:37-04:00 / 2026-09-19T23:05:37+00:00, all eight groups
ran and passed with zero cached groups, zero failures and zero skips. The
runner measured 22,362 ms test-body wall time. This is focused fixture
acceptance, not proof of a completed distributed worker/publication journey.

After extracting the bounded ledger reader to meet the complexity limit,
the worker-focused test command passed again. The final `make -j8 lint-fast
check-windows-cross-syntax` passed all 32 fast gates and compiled all 2,335
Windows translation units cleanly, with zero skips or baselines. The separate
Windows acceptance build cross-linked 72 programs; no Windows runtime result
is claimed. These checks completed before 2026-09-19T19:12:54-04:00 /
2026-09-19T23:12:54+00:00. Exact signed-commit publication proof remains pending.
