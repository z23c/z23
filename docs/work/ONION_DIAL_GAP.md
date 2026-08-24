# Onion dial gap — descriptor-gated rendezvous

Status: CODE-CORRECTED and isolated acceptance green on 2026-08-24. Fleet
acceptance remains HOLD until the referee observes `MESH=4/4` twice at the
unchanged thresholds. Owner: embedded-Tor hidden-service loop (`vendor/tor`
fork + `lib/net/src/onion_stream.c`) and its bounded pair probe.

## Root cause

The regression window reduced to an integration omission plus a probe race:

1. Application-side descriptor readiness was on main, but Tor commit
   `8f4b01ff3` (successful HSDir upload accounting, bounded upload retry, and
   exact INTRODUCE1/RENDEZVOUS1/RENDEZVOUS2 milestones) remained only on the
   node2 Tor lane. The root Git link still selected `7971a5e72`, so both
   descriptor success and rendezvous progress were silent.
2. The strict probe launched B with `-addnode=<A.onion>` as soon as A wrote
   its hostname. A cold public-Tor bootstrap can expose the hostname long
   before HSDirs confirm the descriptor. B therefore spent its bounded
   circuit attempts waiting for an unpublished service. One captured failure
   fetched the descriptor at the end of the second attempt and died at
   `INTRODUCE1_NOT_SEEN`.
3. The probe inferred circuit readiness from a buffered node log. One real
   connection reached P2P framing while the ledger still reported
   `CIRCUIT_NOT_READY`.

## Correction

- The root now pins Tor `8f4b01ff3`, which names successful descriptor upload,
  INTRODUCE1, RENDEZVOUS1, and RENDEZVOUS2 and retries failed upload rounds
  with the existing bounded 5--300 second backoff.
- `core network onion status` exposes the existing monotonic outbound-stream
  counters, including dial, circuit-ready, bridge, byte, answer, timeout, and
  teardown totals. Acceptance no longer depends on a log flush.
- The pair probe boots A and B in parallel without a peer target. It waits for
  A's confirmed descriptor upload and B's Tor readiness, then triggers exactly
  one operator-authorized `addnode onetry`. The 150-second readiness and pair
  allowances and the two-attempt/120-second circuit budget are unchanged.
- `PAIRED` now requires descriptor upload, client readiness, INTRODUCE1,
  RENDEZVOUS1, circuit ready, nonzero P2P framing bytes, and a live peer count.

## What "strong always" requires (the loop, end to end)

publish descriptor → upload observed → client INTRODUCE1 → RENDEZVOUS1 →
circuit ready → P2P framing flows. Every stage must be observable by
log line or counter, retried within the existing budgets, and asserted
by the pair-probe ledger. Acceptance for the fleet milestone stays:
15 consecutive PAIRED cycles + observed descriptor upload + MESH=4/4
twice separated.

## Acceptance evidence

On 2026-08-24, `tools/scripts/onion_pair_watch.sh` produced 15 consecutive
`PAIRED` records from fresh throwaway datadirs at one source identity. Every
record had all declared booleans true. Pair completion ranged from 38 to 146
seconds; the 146-second cold-bootstrap case reached descriptor/client
readiness at 141 seconds and then paired in five seconds. The hermetic checker
validated all 15 JSONL records, and focused `syncdiag_rpc`, `onion_bridge`,
`onion_stream`, and Tor integration groups passed.

The contemporaneous local-mode fleet referee remained `MESH=2/4`: node1 and
node2 completed VERSION/VERACK, while node3 and node4 were absent. That is a
fleet convergence blocker, not grounds to weaken the onion or height gates.
Probe telemetry stays host-local; the scripts live in `tools/scripts/` and do
not commit, push, deploy, or touch canonical datadirs.
