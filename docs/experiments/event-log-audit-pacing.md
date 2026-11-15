<!-- Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 -->

# Event-log audit thermal pacing

The receipt-prefix audit uses the existing gentle and pause thermal policy.
It still verifies the entire vouched prefix or reports an incomplete audit;
integrity failures retain their existing failure handling.

A synthetic regression on 2026-11-15 failed before the change because the
audit callback did not mark gentle pacing or enter an idle gap. The runner
retried the failed group once with the same result. Red log SHA-256:
`696f0d6316b68c6a9c99182b7113200a62a6b507a03b9a4fc7da9b1de5a3e91e`.

The focused storage-pacing and event-log groups passed after the change, with
zero skips. Tests cover normal and gentle callbacks, pause and resume, shutdown
at gentle nap entry, and the existing intact-prefix and corrupt-prefix audit
cases. They do not establish phone CPU or thermal improvement. Log SHA-256:
`bff4b88448a7f957562e2fbd1c1617d592a7cabec006a707dd17c76348e1a172`.

Source base: `80549bd17122eccc6e18a1c84a48b00af5b191f5`. Reproduce on a
maintainer host with
`DEVBUILD_CLASS=normal devbuild --wait make t-fast-exact ONLY=storage_pacing,event_log`.
