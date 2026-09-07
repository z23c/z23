# App event sync — one dapp's signed events between two nodes

A dapp on z23 writes `AppEvent` rows: immutable, chained, signed by the
author's wallet key, and verified where they are stored
(`engine/models/src/app_event.c`). Until now every event a box held had been
written by that box. A SaaS that only ever serves what one machine wrote is
not replicated — it is single-homed with extra steps.

This is the pull that makes a topic's events cross.

## What it is

Three pieces, each with one job:

| Piece | Where | Job |
|---|---|---|
| the wire | `engine/modules/appsync/` | the PULL request, the answer's length-framed rows, and a per-row decode that hands every row to the App platform's own verifier |
| the ends | `engine/services/src/app_event_sync.c` | answer a pull out of this node's table; verify an answer and store what verified |
| the surface | `z23 dev app sync` | what this node holds, the frontier it would ask with, and the named refusal when there is no session |

The shape is the fleet ledger's on purpose. `engine/modules/fleetledger` is
the one node-to-node replication in this tree that is already proven, so
this reuses its discipline rather than inventing a second one:

- **Pull only.** Nothing is pushed and nothing is volunteered. A node that
  never asks never learns, so serving is never a way to reach a box that did
  not want to be reached.
- **Bounded.** One answer carries at most `ZCL_APP_SYNC_BATCH_MAX` rows and
  at most `ZCL_APP_SYNC_ANSWER_MAX` bytes. A peer with more to say is asked
  again from the new frontier.
- **Verify first.** Every row is checked with
  `zcl_app_signed_event_v1_verify()` under the HOST's scope. This module has
  no second opinion about what a valid event is.
- **Stop on the first bad row.** The refusal names the rule and the row
  index. Rows after it are not looked at.
- **Never merge.** An event is stored or refused. Forks are retained by the
  model, which is where fork policy already lives.

The row on the wire IS the App platform's canonical signed frame, so a row
that crossed is byte-identical to the one the author signed. The two-node
test in `tests/harness/src/test_app_event_sync.c` compares exactly that.

## Scope is host policy, and it arrives from above

`struct zcl_app_event_scope_v1` — app id, topic, chain id, and the topic's
byte budget — is compiled from the App's own `apps/<id>/app.def` and the
selected chain's genesis. It is never derived from a row. An event cannot
widen the app, topic, chain or size it is allowed to be by claiming one.

## The cursor on the wire is an event id

`app_events.receive_cursor` is a per-node `AUTOINCREMENT`: cursor 7 on one
box and cursor 7 on another name different rows. So a pull carries the
asker's frontier EVENT ID — the one name two boxes mean the same thing by —
and the answering node resolves it against its own arrival order. A peer
that does not hold that event answers from the start of the topic; every
save is idempotent by event id, so re-offering rows the asker already holds
costs bandwidth and stores nothing.

## The command

    z23 dev app sync <app_id> <topic> [--peer=<name>]

Without a peer it reports what this node holds for that topic and the
frontier a pull would carry:

    {"app_id":"social","topic":"social.events.v1","max_event_bytes":65536,
     "pulled":0,"verified":0,"refused":0,"held":3,"frontier":"<event id hex>",
     "batch_max":16}

With `--peer` it refuses, by name, as `NO_SESSION`: a one-shot process
launched from a checkout holds no paired Noise session, so it could not
prove who answered. See "What this does not do yet".

An unknown App or a topic the App does not declare is `UNKNOWN_TOPIC`. A
relative or absent datadir is `DATADIR_UNAVAILABLE`. Every refusal names the
rule; none of them stores anything.

## What this does not do yet

Said here rather than implied by silence:

- **No transport.** There is no `appsync` mesh stream service. The pull
  takes a peer as a name plus one function that turns a request into a
  bounded answer, so a paired session drops straight in — but nothing wires
  one today, and `dev app sync --peer=` therefore always refuses.
- **No anti-entropy loop.** Nothing runs on a timer. This is pull on
  command; the fleet ledger's 15-second lane has no counterpart here.
- **Arrival-order only, so a late joiner can keep a hole.** The answer walks
  the ANSWERER's arrival order. An event that reached the peer BEFORE the
  asker's frontier event did is behind that frontier and will not be offered
  again. Two nodes that pull each other from empty converge; a node that
  joins mid-history and then advances its frontier can be left with a gap.
  Closing that needs the inventory/get exchange
  (`docs/work/LLM-C23-APP-PLATFORM-CHECKLIST.md`) — offer ids, ask for the
  missing ones — which this build does not have.
- **No topic policy inside the node.** The byte budget for a topic is read
  from the checkout's `app.def`, so the scope can only be compiled where a
  checkout is. A node with no checkout has no way to say what a topic's
  limits are, which is why the surface is a `dev` leaf and not a node lane.

## Refusal tokens

`zcl_app_sync_status_label()` names every one, and they are what the
operator surfaces print:

| Token | Means |
|---|---|
| `appsync_argument` | a NULL, or a field over its bound |
| `appsync_malformed` | the bytes are not a frame of this version |
| `appsync_version` | a wire version this build does not speak |
| `appsync_row_too_large` | one row is over the wire's row bound |
| `appsync_batch_full` | the answer is at its row or byte bound |
| `appsync_scope` | the row is not in the asked-for app and topic |
| `appsync_sig_invalid` | the App platform refused the signature |
| `appsync_no_peer` | no peer named, or no session to ask over |
| `appsync_store_refused` | a verified row the local table would not keep |
