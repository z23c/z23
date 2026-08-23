# Onion dial gap — local repro and root cause

Status: CORRECTED 2026-08-23 after fresh probes on current main
(`12de13d32`+). Supersedes the earlier "dials are never issued" claim,
which was true of the then-checked-out binary and false of current main.
Owner: embedded-Tor hidden-service loop (`vendor/tor` fork +
`lib/net/src/onion_stream.c` / `connman_dialer.c`). Referee evidence:
[`deploy/devfleet/mesh.status`](../deploy/devfleet/mesh.status).

## Verified current behavior (two fresh isolated nodes, strict probe)

1. Node A boots with `-tor -onion-persist`; hostname file appears (~8 s
   historically; 20–45 s observed on current main — slower).
2. B dials `-addnode=<A.onion>:<port>` and DOES log
   `Connecting to onion addnode …` — the dynhost bridge dial attempt
   exists (`64c4446a7`, hardened by `385a32bf9`).
3. Failure is downstream of the attempt, in BOTH halves of the
   hidden-service loop:
   - CLIENT half: B's tor log shows ZERO `intro`/`rendezvous` events —
     the dynhost client stream never builds a circuit.
   - SERVICE half: A's tor log shows ZERO descriptor-upload lines — the
     service publishes its hostname file but never (visibly) uploads its
     descriptor to HSDirs, so even a healthy client could not intro.
4. An older locally-built binary paired at `PAIRED_AT=5s` under the same
   probe → there is a REGRESSION WINDOW between that build and current
   main, or a flaky publish path that older timing masked. Not yet
   bisected; bisection is assigned.

## What "strong always" requires (the loop, end to end)

publish descriptor → upload observed → client INTRODUCE1 → RENDEZVOUS1 →
circuit ready → P2P framing flows. Every stage must be observable by
log line or counter, retried within the existing budgets, and asserted
by the pair-probe ledger. Acceptance for the fleet milestone stays:
15 consecutive PAIRED cycles + observed descriptor upload + MESH=4/4
twice separated.

## Probe artifacts

Probe scripts live outside the tree (`/tmp/opencode`, ephemeral by
policy); node3 owns promoting them into `tools/scripts/` as the always-
on ledger. Re-run cost: under two minutes on any checkout with
`make tor-full` done.
