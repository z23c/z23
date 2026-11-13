<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Progress store busy status retry

The status journey directs a read-only retry when the progress store is busy,
while retaining the owner-review requirement and unhealthy node verdict. Other
review-required blockers retain their inspection guidance.

Focused reproduction: `devbuild --wait make t-fast ONLY=command_registry_catalog`.
2026-11-13: PASS, one group, zero failures or skips. The fixture checks both
the busy and bootstrap-trust cases. Runtime qualification
on a phone remains unmeasured; the installed phone source identity is unknown.
