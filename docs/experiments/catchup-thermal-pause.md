<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Catchup pause and resume

On 2026-11-13, a focused local fixture exercised projection catchup with the
node pace set to pause. Entry while paused left the projection unchanged. A
pause during the walk committed only its completed prefix; resuming with a
keyed wallet produced the same projection and integrity receipt as an
uninterrupted walk. A paused walk with no indexed rows left its cursor and
outcome unchanged. `make t-fast-exact ONLY=node_db_catchup_service` passed the
fixture. With the production change removed, all three pause assertions failed.
Witness-bearing pause/resume equivalence remains unmeasured by this fixture.
