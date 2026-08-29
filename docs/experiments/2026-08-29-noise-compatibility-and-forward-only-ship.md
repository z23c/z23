# Noise naming compatibility and forward-only shipping

Date: 2026-08-29T19:43:05Z

## Intent

Adopt the canonical Noise transport name without silently disabling existing
nodes or breaking version-one diagnostic consumers. Prevent deployment
rollback from starting an older binary after a forward database migration.

## Result

- `-v2transport` and `-nov2transport` remain deprecated aliases;
  `-noisetransport` takes precedence when both spellings are present.
- Version-one machine, connman, telemetry, and application-protocol documents
  retain their original keys or tokens while also exposing canonical Noise
  names where the schema permits aliases.
- Local shipping refuses persistent-schema changes because its deployment
  transaction cannot yet disarm rollback.
- Remote forward-only shipping leaves the candidate installed after a failed
  qualification and never enters the outer rollback path.
- Persistent-schema classification covers the database version, migration
  implementation, internal contract, and orchestration files.

## Evidence

The following commands passed from the same worktree with GCC 16.1.1:

```text
make -j16
make -j16 t-fast ONLY=cli_argv_strict
make -j16 t-fast ONLY=telemetry_network
make -j16 t-fast ONLY=syncdiag_rpc
make -j16 t-fast ONLY=mesh_status_wire
make -j16 t-fast ONLY=noise_transport_parity
make -j16 t-fast ONLY=hotswap_module
make -j16 t-fast ONLY=source_bundle_fetch
make -j16 t-fast ONLY=source_bundle_publish
make lint-fast
bash -n tools/ship.sh
tools/lint/check_ship_remote_transaction.sh
```

All selected groups reported `groups_failed=0` and `self_skips=0`. The public
binary build reported `c23-node: PASS`. The shipping check remains hermetic;
it does not touch a running service.
