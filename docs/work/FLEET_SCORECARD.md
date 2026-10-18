<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Fleet A+ scorecard

The owner adopted these thirteen goals on 2026-10-16. Together with the P0 safety rules in AGENTS.md they set the fleet's priority order.

A+ means a live probe passes and keeps passing with nobody babysitting it. Each goal has an A+ bar, an owner and its subgoals. Live status lives in the fleet wiki page with slug fleet-goals, not in this repo; this page holds the targets.

| # | Goal | A+ bar | Owner(s) |
|---|------|--------|----------|
| 1 | Quantum-secure tunnel | every directed pair of fleet hosts; at least 150 MiB/s; access renews itself | claude-r1-lead |
| 2 | Post-quantum release signing | hybrid Ed25519+SLH-DSA; k-of-n hosts; nobody signs by hand | claude-r1-lead |
| 3 | Remote shell | z23 shell @any on every fleet machine; full commands; per-lead keys and audit | claude-rhett2 (Linux native), astra-mac (Mac) |
| 4 | Wiki | written anywhere, readable everywhere in 10 s; pinned pages never expire | claude-r1-lead (list, find, pinning), claude-laptop (curation) |
| 5 | Plugins + binary swarm | publish once; every host fetches from peers, checks pin and hash, installs atomically | oauth D1, r1 D2/D4, rhett2 D3/D5 |
| 6 | Seamless updates | a landing upgrades every host automatically and rolls back on failure | claude-r1-lead |
| 7 | MCP harness | MCP on every agent; warm code lookup under 50 ms; tokens down at least 50 %, measured | claude-rhett2 (mcp serve), claude-r1-lead (code.packet, capsule) |
| 8 | Telemetry | all 5 hosts in vitals in under 1 s; node-independent; signed history | claude-r1-lead, oauth |
| 9 | Landing throughput | at least 3 trains a day; zero proof failures a pre-submit check could catch | every lead (full make lint before submit) |
| 10 | Node health | every canonical node alive with logs advancing; receivers healthy | claude-r1-lead, claude-rhett2 |
| 11 | Zero spend | 0 ZCL; every fleet feature works without a fee | everyone |
| 12 | Mac parity | Darwin build, confinement and hub pairing equal to Linux | astra-mac |
| 13 | Agent productivity | every lead busy on its own lane; review never the bottleneck | claude-rhett2 (fleet lead), claude-laptop (review triage) |

## Subgoals that unlock the most

- Pinned identity (zero-spend trust) unblocks goals 3, 4 (sync at 0 ZCL), 5 (D3) and 11.
- Confined shell repairs (process-group custody, bounded writes, W^X) unblock goal 3.
- wiki list/find paging and non-expiring pinned pages unblock goal 4.
- Bounded delegated tasks through the tiered funnel (Haiku or Luna extracts, Sonnet or Sol implements, a non-author of any model reviews) carry task-level token receipts. Counting implementation, rejected packets, repair and review lets goal 7 measure tokens per accepted landed change across model mixes. The model a task requested is not evidence of the model that ran.

## Using this scorecard

Agents tie claims and READY posts to a goal number. The live copy is the fleet wiki page with slug fleet-goals (read it with fleet.wiki.read; MCP: z23_run). Update the owner column when lanes change.
