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
   one paired peer, `last_skip_reason: no_delegation` (the peer's delegation is not in the DHT table the lane reads; this does not prove none was anchored), zero pulls, answers,
   pushes and receipts ever, 13 open questions. Push and receipts already
   exist (`boot_fleet_board_push.c`, `fleet board delivery <id>`); with no
   delegation in view, nothing flows. First find out why: the lane reads
   delegations from the DHT routing table, so a peer that is not currently a
   contact reads as `no_delegation` even if one was anchored. Check whether
   the peer is connected and in the table. If none was ever anchored, an
   operator grants the delegation and role (`docs/agent/FLEET.md`, "Pairing a
   peer is not a role grant"); anchoring costs coins and is owner identity
   authority: do not do it for them. A roster (`fleet admit`) avoids both.
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

## Starter tasks (small, checked in the tree on 2026-11-25)

Each is one lane, one writer, one focused test group. Start with
`build/bin/z23-dev code guide <path>`, edit, run `make t-fast-exact
ONLY=<group>` and `make lint-fast` through `devbuild --wait`, then submit.
Match `git log origin/main` by subject first. The larger catalog is
[`C23_TASK_CATALOG.md`](C23_TASK_CATALOG.md).

1. ~~Test the respawn exit line.~~ Done (seq 4203). `boot_loop_guard_note_shutdown_intent`
   (`engine/composition/src/boot_loop_guard.c`) now prints a line for a
   self-respawn; nothing asserts it. Add a case to `test_boot_flight_recorder`
   that sets the tip-watchdog respawn flag and checks the stderr text.
2. **Test the bundle reuse in the fetch thread.** `sosvc_reuse_landed`
   (`engine/composition/src/state_offer_service.c`) has a helper test only.
   Add a group case where `sosvc_fetch_main` finds a verified landed file and
   makes no network call. Group: `test_state_offer`.
3. **List every flag in `-help`.** `-fileservice` was missing from `-help`
   until today. Diff the known-flag table in `engine/composition/src/args.c`
   against `print_usage_all` and add the missing lines; then add a lint that
   fails when a parsed flag has no help line. A rough grep on 2026-11-25 found
   about 74 of 127 parsed flags absent from the help text (Mark reported 88 of
   143). Many are likely hidden on purpose: decide which are public first, and
   write each line from the code, never from a guess.
4. **`code impact` speed: not reproduced on main.** On a current dev build it
   took 0.14 s on a wallet file and on `args.c` (budget 250 ms). The 5 s and
   28 s reports came from an older binary or a cold index. If it is slow for
   you, check the build age and run `code index` status before touching the
   handler; record the time on a current build.
5. **Build the board menu from the node's ops.** The client menu says ready
   for ops the running node lacks; the refusal now names the op. Ask the node
   for its op list once and filter the menu. Files: `tools/command/
   native_fleet_board_command.c`, `engine/composition/src/
   boot_fleet_board_rpc.c`. Group: `test_fleet_board`.
6. ~~Status for an unknown blocker.~~ Done (seq 4201, sync_state folded too). `status_brief_native_handler.c` now
   folds free text to a token. Add the same fold for `sync_state` (it still
   rejects the whole document on a non-token) with a test beside
   `test_status_brief_free_text_blocker_folds_to_token`.
7. **One contract.** `AGENTS.md`, `CONTRIBUTING.md`, `THE_Z23_WAY.md` and
   `DEVELOPING.md` repeat rules and sometimes disagree. Write a list of every
   rule that appears twice and where; do not delete anything in the same
   change.

Out of scope for a first change: anything under `core/`, custody, a
datadir, the delegation grant for the lab pairing, and the onion file route
(needs the unseal ritual).


## Live probe and the structural limit (2026-11-25)

One `fleet board post note --scope=fleet --ttl=600` from the lab node, then
`fleet board status` twice about 40 s apart: `push_out.queued` was 2 and
every other push counter 0. `queued` is a cumulative counter, not queue
depth: the posts were taken and drained, and the fan-out found nothing to
push to. One sample on one node; not a latency measurement.

Why nothing left, from `boot_fleet_board_push_fanout.c` (header comment):
- Push rides only the paired `board` service. A fan-out post goes to a paired
  peer with a live session that the answering half would serve; a peer with no
  session is "left to the pull" and counted nowhere.
- A peer on the fleet roster with no pairing row (the free path) is **never
  pushed to**. It pulls every 15 s over `board.roster`
  (`FLEET_BOARD_FLEET_PULL_INTERVAL_S`). Such cases only show as
  `push_fanout_roster_unpushed`.

So the fastest path needs a pairing, which needs a held delegation, and the
free path is capped at one pull interval. **This is the design item for fast
swarm communication** (specified in [`../node/ROSTER_PUSH_DESIGN.md`](../node/ROSTER_PUSH_DESIGN.md)): push over a roster stream (a `board.roster.push`
service with the same OPEN-carried payload and receipt), judged by
`fleet_board_roster_standing` and the session proof, so a roster member is
pushed to without a pairing. It touches admission and the receiving half's
proof of the pusher (`push_inbox_*` proves a pusher only through pairing
rows today), so it needs its own design note and a non-author review first.
Cheaper steps before it: lower the roster pull interval for peers that just
answered, and add a counter for "no live session" in the fan-out (the file
decision above is deliberate; the missing piece is visibility).

The lab MCP server answered `fleet.board.delivery` as `UNKNOWN_COMMAND`, so the
build behind it may predate the receipt reader; confirm which build the lab
node runs before judging receipts.

## Update: the wake landed (2026-11-25 evening)

While this handoff was written, another agent landed `board.wake`
(19a371e617) and shortened the pull interval to 5 s (efbd046c20). The same-second
wake runs on the 100 ms lane tick (f9d9eefe62). The "capped at one 15 s pull"
statements above describe the earlier state.

Roster push is the receipt path: a connected roster peer with no working
pairing row is offered one `board.rpush` OPEN (the name `board.roster.push`
does not fit the 16-byte service-name limit) carrying the post and a PUSH-side
roster proof, and the receiver answers with the paired push receipt. The
paired `push_opened` counter does not move. The pull remains the repair. A
peer the OPEN did not take is still `push_fanout_roster_unpushed`.

A fan-out post that found no live paired or roster session is
`push_out.fanout_no_session`, once. What is still missing for a swarm is a
measured round trip. This note does not claim a latency.
Check `git log origin/main --oneline -- engine/composition/src/boot_fleet_board*`
before starting any fleet-board work: several agents write here.
