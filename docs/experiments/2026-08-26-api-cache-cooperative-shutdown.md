<!-- Copyright 2026 Rhett Creighton - Apache License 2.0 -->

# Cooperative API-cache shutdown

## Question

Can a slow-host node stop cleanly while a background API refresh is scanning
the transparent UTXO set, without publishing a partial result?

## Observed failure

On node 3, a full HODL-wave SQLite scan outlived the frontend shutdown stage.
The cache worker had no cancellation boundary, so the frontend stage watchdog
forced process exit after 15 seconds. The next boot could not use the clean
shutdown path.

## Method

Only background HODL and deep-stat refreshes install a SQLite progress handler.
The handler reads the cache worker's atomic run flag and interrupts the query
after shutdown clears that flag. Foreground API queries keep their existing
behavior. The HODL scanner now requires a terminal `SQLITE_DONE`; an interrupt
or other step error rejects the snapshot instead of returning accumulated rows.

## Isolated evidence

On 2026-08-26, the registered API test interrupted a real 5,000-row in-memory
UTXO scan through the production progress callback and observed
`UTXO index scan interrupted`, never `ok`. The registered `test_api` and
`test_models` groups each passed with zero skips, and `make lint-fast` passed.

## Live acceptance

The isolated test proves cancellation and fail-closed result handling. It does
not prove production shutdown latency. Release acceptance requires a graceful
stop while node 3 is performing its initial API refresh, no frontend stage
watchdog escalation, and a subsequent start from the clean-shutdown path.
