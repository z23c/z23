<!-- Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 -->

# Landing status during foreground proof

A foreground landing driver retains its drive lock while individual steps
release their step lock. A free step lock therefore does not establish that
no driver is active.

Status observes both locks without creating or retaining them. The owner and
lease fields retain their step-lock meaning. When the step lock is free and
the drive lock is held, the receiver-driver field reports an active drive and
the suggested action is to observe status. This observation does not identify
an exact proof worker or establish proof completion. An unreadable drive lock
reports unknown rather than an absent drain.

<!-- claim: symbol-present dl_driver_observed tools/command/native_dev_land.c -->

The registered landing regression uses an isolated queue and a real child-held
drive lock. It checks active-driver status while the step lock is free, refusal
of a competing scoped drive, unchanged queue bytes, and restored absent-drain
behavior after releasing the child.

<!-- claim: symbol-present dlx_adopt_drive_held tests/harness/src/test_dev_land_adopt_push.c -->

Run the focused group with:

~~~sh
make t-fast ONLY=dev_land
~~~

## Observed qualification

On 2026-10-27, the fixed implementation passed the broad dev_land selection:
six executed registered groups, zero failed, skipped or flaky groups. The
third shard passed and its drain-adoption scenario reported zero failures.

The RED experiment retained the same regression and replaced only the
production implementation with its exact baseline bytes. It selected
dev_land_shard_03, which owns the changed scenario. The first attempt and
the runner's automatic isolated retry both failed because status reported
drain_absent while a child held the drive lock. The final make exit was 2:
one group failed, with zero skips or flaky results. The narrower RED selection
does not establish a whole-suite comparison.

The production candidate was restored and its blob verified after the RED
runner ended. An interrupted SSH transport was recorded separately; the
original remote runner survived and its terminal status supplied the verdict.

These runtime results identify regression blob
03569c79a1de7212768fe7afdeb44d35312d885a. A later mechanical extraction
moved the complete child process branch into a helper to satisfy the
complexity cap. The production implementation is unchanged. The revised
regression blob d417df8bb66adc98b28c8979762cf8b33b993819 has passed the
complexity gate; its runtime acceptance remains pending the exact native
landing proof. The historical runtime results do not qualify those new
regression bytes.

Evidence identities:

- Baseline: 1c8192c9bafa275beb56562e3936234ce4029d06.
- Baseline production blob: 2634ce7fc3d505050b62ced6715950c674425dfc.
- Fixed production blob: 3bfa8633d15900905ca747a56a271cc1f4824fcc.
- Regression blob: 03569c79a1de7212768fe7afdeb44d35312d885a.
- GREEN log SHA256:
  e4f4d9fccf7807184c694de183e2d64c952515deb5610d36151e05a52709ae62.
- RED log SHA256:
  d0f8b5eab386d98557aa13f6976ea1aa2878b4e373d8c5dd715f286b9d84857c.
