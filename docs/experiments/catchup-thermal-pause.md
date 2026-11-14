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

On 2026-11-14, an isolated worker fixture exercised background projection
at gentle pace. With a writer holding the database queue, the worker queued
an owed turbo-mode restore and the fixture observed the original synchronous
setting and a dropped index restored after the writer released. Two gentle
iterations left a behind projection cursor unchanged, invoked shielded
verification, and advanced the quiescent marker passed to `supervisor_progress`. After normal pace
returned, catchup indexed four blocks and advanced the durable cursor. The
`node_db_projection_heal` focused group passed without skips. This observes
verification invocation, not its result, and does not measure a full
supervisor deadline. Device performance for this change was not measured.
The worker fixture used source base `d63558cc4a941f30660aaf343de81e9b1e51ee29`
and an uncommitted test and implementation diff with SHA-256
`479af4a0dc6cbfcecea543e38645fc64d9dc9d6d9ab863f1b9b5932c36aada98`.
