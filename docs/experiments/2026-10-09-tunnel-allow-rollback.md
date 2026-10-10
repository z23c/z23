<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Failed tunnel grant persistence

A refused allow operation must leave the in-memory authorization set equal
to its last persisted state. The production allow path snapshots the affected
row and count under the tunnel lock, restores both if persistence fails, and
clears a newly allocated row. Deny and revocation behavior is unchanged.

Proposal base: `ad1e0d543f1eed924accc4408ac22384e7f13583`.
Three-file patch SHA256:
`dc82997ebc674f1ad5a534a633dbf302f1aeb121b3e5a49220aed80ec006dcbe`.

The registered `mesh_tunnel` regression owns a paired peer and a loopback
target. A private directory at the staging-file path forces grant persistence
to fail. The next production OPEN must close with
`tunnel_target_not_allowed`, create no stream, and make no target connection.
The test also checks the prior row and persisted bytes, failed update
restoration, and ordinary addition and update after removing the collision.

From 2026-10-10T00:06:17Z to 2026-10-10T00:09:36Z, Apple M4 with Apple
Clang 17.0.0 executed exact compatible
base `c76d49aa24f63b565ac77c6f95996d14f4c659fe` plus the patch.
The three source preimages equal the proposal base. Five focused structural
gates passed. Parent production with the new regression failed at its actual
OPEN assertion; the candidate passed; disabling production rollback failed at
the same assertion; restoring the candidate passed. Each phase used the
canonical registered runner with one uncached group and no self-skips.
The qualification README SHA256 is
`6ddf723d6ee886d8ea41ce1a9364a2997944038dd3c4d888b45c3a2b7f1b7eb5`;
its retained SHA256SUMS verifies phase logs, source hashes and restoration.

This is bounded Mac rollback evidence. It does not establish Linux runtime,
sanitizer coverage, live revocation, reconnect recovery or fleet connectivity.
Current-base publication requires the native signed commit/base proof with
full mandatory lint and affected tests; those receipts determine admission.
