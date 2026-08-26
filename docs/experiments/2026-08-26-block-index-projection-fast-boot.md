<!-- Copyright 2026 Rhett Creighton - Apache License 2.0 -->

# Bound block-index projection startup

## Question

Can a node avoid rereading every block-index projection row after a clean
restart without trusting an unbound cache or weakening corruption recovery?

## Baseline

Node 3 uses an Intel Xeon E3-1241 v3, 16 GB RAM, spinning-disk persistent
storage, and GCC 14.2.0. On 2026-08-26T09:04:44-04:00
(2026-08-26T13:04:44Z), its verified flat loader completed in six seconds and
the projection top-up then visited the full 3,232,513-row index. The recorded
`block_index_load` phase took 1,970,196 ms. Tip restoration followed at
2026-08-26T09:37:32-04:00 (2026-08-26T13:37:32Z). The system service entered
its running state at 2026-08-26T09:38:45-04:00, forty minutes after process
start.

## Method

Projection header replacements and status patches now add their hash to a
transactional dirty set in the same transaction as the row and consumer
cursor. After all writers have stopped, graceful shutdown catches the
projection up, atomically saves the embedded-SHA3 flat index, then binds the
flat payload digest, size, row count, and covered event offset while clearing
the dirty set in one projection transaction.

Boot admits the bounded path only when the already-verified flat identity
matches that binding exactly. It then visits only dirty hashes. A missing,
legacy, stale, malformed, truncated, or mismatched identity retains the
existing full scan. A dirty hash with a missing or malformed projection row
fails closed.

Registered acceptance on 2026-08-26 covered seven `block_index_` groups with
zero failures and zero skips. The end-to-end top-up fixture measured zero rows
for a clean bound restart, one row for one status delta, and the full two-row
projection after replacing the flat file without a matching bind.

## Result and next measurement

The C23 implementation proves bounded work and fail-safe fallback in isolated
fixtures. It has not yet been promoted to a production node, so no live
post-change startup-time claim is made.

After a release candidate completes deployment qualification, perform one
graceful stop on a consenting spinning-disk node to mint the binding, then
restart the same immutable binary. Record compiler, CPU, binary SHA3, flat row
count, dirty row count, `block_index_load` duration, time to public P2P listen,
and time to synchronized serving. Acceptance requires
`projection top-up source=bound-delta rows=0` on the unchanged restart; any
binding mismatch must report `source=full` and preserve current behavior.
