<!-- Copyright 2026 Rhett Creighton - Apache License 2.0 -->

# Fleet communication: state and next steps (2026-11-25)

Handoff for the next developer. Facts below were read from the tree, the land
queue or the live board on 2026-11-25; what was not checked is marked.

## What landed today

| Seq | Change |
|---|---|
| 4180 | `z23 status` folds a free-text `primary_blocker` into a token instead of rejecting the node document (a synced node no longer reads `blocked`). |
| 4181 | The node prints one line to stderr and the log before a self-respawn exit. |
| 4182 | A board op the node lacks is refused with the op name, the node build and "restart the node". |
| 4184 | A verified bundle already under `bundles/` is reused, not fetched again (`sosvc_reuse_landed`). |
| 4185 | `AGENTS.md` and `THE_Z23_WAY.md` point volunteers at `CONTRIBUTING.md`. |
| 4186 | `-packagehost=1` defaults `-onion-persist` on (`args_onion_persist_for_hosting`). |

Tests are focused groups plus `lint-fast`. The bundle reuse test covers the
helper, not the fetch thread. The onion change has a pure-function test only.

## What blocks two-way agent communication

1. **No live channel.** `fleet board status` on the lab node on 2026-11-25:
   one paired peer, `last_skip_reason: no_delegation`, zero pulls, answers,
   pushes and receipts ever, 13 open questions. Push and receipts already
   exist (`boot_fleet_board_push.c`, `fleet board delivery <id>`); the pairing
   has no delegation, so nothing flows. Fix: an operator grants the
   delegation and role for that peer (`docs/agent/FLEET.md`, "Pairing a peer
   is not a role grant"). That is owner identity authority: do not do it for
   them.
2. **Onion reachability.** A default node's onion is a throwaway that maps
   only virtual port 80. The P2P route exists only with `-onion-persist`.
   The file-service route does not exist in either mode.
   [`../node/ONION_PUSH_DESIGN.md`](../node/ONION_PUSH_DESIGN.md) specifies
   the fix; it edits sealed `core/modules/net/src/tor_integration.c`, so it
   needs the unseal ritual in `core/UNSEAL.md` and its own review.
3. **Version skew.** The menu can list an op the node lacks. The refusal now
   names it. The menu is still not built from the node's own op list.
4. **No onion dial in the board client** (`fleet board list --onion=` is an
   unknown input key), so an onion round trip cannot be measured yet.

## Next steps, in order

1. Get one real two-node run: pair, delegate, post, read the receipt. Record
   push round-trip time. This is the first number the project lacks.
2. Run a real two-node Tor test of the `-packagehost=1` default, and confirm
   a fresh node installs a bundle instead of folding from genesis. The change
   was not exercised against Tor; treat Mark's days-long sync as unexplained
   until it is.
3. Unseal and implement the file-service route on the ephemeral onion
   (ONION_PUSH_DESIGN.md), then add an onion dial to the board client.
4. Build the client menu from the connected node's op list.
5. Docs: `-fileservice` is missing from `-help` and `--help-all`; SYNC.md says
   "hours" for a genesis sync that measured about 10 blocks/s (days); the
   MCP README tool count was reported as 4 against 11 served (unchecked).

## Traps

- Land status: match `"mine":{...,"state":"landed"}`, not the first `"state"`
  in the reply, which is an older row. The outcome `ts` is the submit time.
  A proof takes about 8 minutes; full lint is about 18 s.
- Submit with the lane's own `build/bin/z23-dev` (`make dev-bin`).
- `check-cyclomatic-complexity` caps functions at 15 and
  `check-file-size-ceiling` caps files at 1500 lines; split, do not pin.
- One writer per worktree; another agent works on r2. Match `git log
  origin/main` by subject before starting.
- Never write the node database while the node runs.
