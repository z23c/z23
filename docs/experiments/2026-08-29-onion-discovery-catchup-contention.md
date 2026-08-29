<!-- Copyright 2026 Rhett Creighton - Apache License 2.0 -->

# Onion discovery and projection catch-up contention

## Intention

Keep periodic onion-peer discovery from performing schema and index work while
the node database projection catch-up owns a bulk write transaction.

## Production observation

Observed at `2026-08-29T05:05:00Z` on the maintainer's third hosted node. The
canonical service was active with zero restarts, 25 handshaked peers, a ready
onion service, and the validated chain at height 3,232,741. The node database
projection was about 1,050 rows behind and its catch-up worker was parked after
eight aborted passes.

The logs recorded one failed `BEGIN IMMEDIATE` renewal followed by seven more
`database is locked` failures. The same windows recorded index rebuild failures
and periodic `blog.onion_discovery_wallet` and
`blog.onion_discovery_chain` runtime reopens. Those read-only pollers used the
full runtime open, which may run schema and index preparation.

## Change

Both pollers now use `node_db_open_existing_runtime()`. That path refuses a
missing or mismatched database and does not create, migrate, or prepare the full
statement catalog. The wallet query also uses the caller's bounded row limit so
every allocated raw transaction row is visited and released.

## Repeated evidence

Host: AMD Ryzen 7 PRO 8840U; compiler: GCC 16.1.1 20260430; local time:
`2026-08-29T01:08:36-04:00`; UTC: `2026-08-29T05:08:36+00:00`.

- `make -j16 t-fast ONLY=blog`: 1/1 group passed, zero skips.
- `make -j16 t-fast ONLY=zdir`: 3/3 groups passed, zero skips.
- `make -j16 t-fast ONLY=sqlite`: 3/3 groups passed, zero skips.
- `make -j16 t-fast ONLY=overlay_parse_parity`: 1/1 group passed, zero skips;
  272,004 differential inputs compared.
- `make lint-fast`: 21/21 gates passed.

The blog regression verifies that discovery against a missing database leaves
`node.db`, `node.db-wal`, and `node.db-shm` absent. Live acceptance still
requires an owner-approved release deployment and observation beyond two onion
poll intervals; this source-level result does not claim that deployment.
