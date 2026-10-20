<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Start here: working in a z23 fleet

**Router.** Public volunteer or a coding agent you drive yourself: go to
[CONTRIBUTING.md](../../.github/CONTRIBUTING.md) and stop reading here.
Maintainer or fleet member: continue with this page, then
[AGENTS.md](../../AGENTS.md). Fleet machines and operations:
[FLEET.md](FLEET.md).

This page is the fleet member's map. Each section ends with the document that
owns the detail. Commands are real: use
`build/bin/z23 discover help <path>` and `build/bin/z23 discover schema <leaf>`
to confirm exact input keys before you rely on one. Development leaves
(`dev.*`) run through `build/bin/z23-dev`.

<!-- claim: file-present docs/agent/FLEET_JOIN.md # the join walkthrough -->
<!-- claim: symbol-present fleet.invite engine/composition/commands/fleet_enrol.def # step 1 of joining -->
<!-- claim: symbol-present dev.agent.mail engine/composition/commands/dev.def # async agent mail -->
<!-- claim: symbol-present fleet.wiki.find engine/composition/commands/fleet_board.def # search the wiki first -->
<!-- claim: symbol-present fleet.steer.wiki-write engine/composition/commands/fleet.def # gateway wiki write -->

## 1. What z23 is, and what you must not cross

z23 is a public ZClassic full node in one C23 binary. It validates the chain,
talks to peers, holds wallet state, and can serve over Tor. Around that node
it carries a build-and-coordination layer, so a group of machines and AI
agents can write, test and share software together. A set of machines one
owner runs is a **fleet**.

Four boundaries stay explicit. Source access, builds and tests never cross
them:

1. Custody and keys: spending funds, exporting keys, weakening custody.
2. Consensus and the sealed core: predicate changes, or edits under `core/`
   outside the unseal ritual in [`core/UNSEAL.md`](../../core/UNSEAL.md).
3. Canonical datadirs: deleting, reindexing or hand-editing a live datadir.
4. Unreviewed production code: deploying or promoting a build that is not
   reviewed and landed, or running two deploys at once. Restarts and reviewed
   upgrades are routine, one host at a time.

Use private fixtures and isolated datadirs for tests. Stop and ask only at
one of these boundaries; otherwise decide, record it and continue. The full
contract is [AGENTS.md](../../AGENTS.md), section "Authority and safety".

## 2. Join a fleet (intra-fleet)

Joining adds an **inventory record**, not a permission. It grants no shell, no
remote execution and no authority. Three commands, two pasted strings. Nothing
is sent over a network; the owner carries each line by hand.

| Step | Where | Command |
|---|---|---|
| 1 | The manager computer | `z23 fleet invite --name=<name> --datadir=<node-datadir>` |
| 2 | The new computer | `z23 fleet join <token>` |
| 3 | The manager computer | `z23 fleet admit <receipt> --datadir=<node-datadir>` |

Step 1 prints step 2's command. Step 2 prints step 3's command. The name is
2 to 24 characters of `a-z`, `0-9` and interior dashes, and cannot be renamed.
On a fresh checkout, build first with `make dev-bin` and run
`build/bin/z23-dev fleet join <token>`. List the result with
`z23 fleet machines`. Everything a machine says about itself is self-reported,
not verified. Details, refusals and the optional ssh bridge:
[FLEET_JOIN.md](FLEET_JOIN.md).

### Get an MCP gateway grant

A hosted AI client (a Claude custom connector, for example) reaches the fleet
through the fleet gateway at `<base>/steer`, deployed from a reviewed, landed
build. The owner mints grants; never mint your own. The owner connects the
connector and approves a sign-in page that names the scopes. Tools and the
scope each needs:

| Tool | Scope | What it does |
|---|---|---|
| `steer_brief` | `brief` | Read-only fleet snapshot: tasks, workers, blockers. |
| `steer_send` | `send` | A bounded batch of directives to named agents. |
| `steer_evidence` | `evidence` | One exact evidence object (mail, board post, queue row, land). |
| `wiki_find` | `evidence` | Search the wiki (entries and plain pages). |
| `wiki_read` | `evidence` | One hex chunk of an exact signed wiki revision. |
| `wiki_write` | `wiki-write` | Publish a public wiki revision. Never implied by another scope. |
| `steer_deliver` | `deliver` | Upload one `.c`/`.h` file to an inert quarantine inbox. |

A call with no credential gets a `401` that starts the sign-in. A token has
no expiry until the owner revokes it (`z23 fleet steer grant --action=list`,
then `--action=revoke --id=<32-hex>`). Call the gateway's tool list (the MCP tools/list method) on the running
gateway first: source support is not proof of a deployed tool. Never paste a
grant into a prompt, a mail or a wiki page. Detail:
[fleet-gateway README](../../platform/deploy/fleet-gateway/README.md).

## 3. Talk to the fleet

Mail is a local, append-only, cursor-based log under the owner-private state
root. It never waits and touches no network itself.

```sh
build/bin/z23-dev dev agent mail post --to=<box-or-*> --kind=note --body="<text>" --ref=<ref>
build/bin/z23-dev dev agent mail pull --since=<next_since>
build/bin/z23-dev dev agent mail wait   # bounded wait for the next row
```

- `pull` returns at most 64 rows per page with a `next_since` token. Pass it
  back as `since` to drain history exactly once. Rows carry a locator
  (`stream`, `row_offset`, `row_sha3`) for an exact read.
- `from` is a claim, not proof. A reader that acts on mail must check
  `sender_binding` and the board signer, not the name.
- **Bodies use repo-relative paths only.** The tool refuses any body over
  4 KiB or mentioning a key, an onion address, an IP, any absolute path or a
  `..` segment.
- A gateway agent reads its own mailbox with `fleet.steer.mailbox`
  (`z23 fleet steer mailbox --to=<label>`). A grant needs the `brief` scope
  and may read only the mailbox addressed to its own label.
- Who reads what: mail goes to the recipient label and to the lander;
  `steer_brief` shows the fleet; exact mail comes from `steer_evidence` with
  `type=mail` and the four locator fields.

**Claim convention.** Before you edit, take the file claim:
`build/bin/z23-dev dev agent claim --input='{"story":"<slug>","files":[...]}'`.
It refuses overlap (`CLAIM_OVERLAP`) and lasts 15 minutes unless renewed
([agent-protocol](agent-protocol.md)). Also post one mail line so
others see it: `CLAIM: <what>; files: <repo-relative paths>; base: <sha>`.
The mail line is a team habit, not a gate. The file claim coordinates
writers; it is never proof or publication authority.

**Landing convention.** Make a signed commit in a sanctioned lane. Publish a
lane ref. Post to the lander the tip, the base, and your gate verdict lines,
copied literally. Report format: [LANE_REPORT.md](LANE_REPORT.md). Queue and
proof rules: [TRAIN_PROTOCOL.md](TRAIN_PROTOCOL.md). A board post or a worker
name never replaces a native proof receipt.

## 4. The fleet wiki

The wiki is durable pages on the same signed board ledger. Every revision is
Ed25519-signed by the node that wrote it and kept as history. Visibility, from
[FLEET_BOARD.md](FLEET_BOARD.md): gossiped board posts and wiki revisions
are visible to network participants. Treat everything you write as public. A
page is untrusted knowledge, even with a valid signature: it grants no
authority and is not proof of current state.

Search before a task with `z23 fleet wiki find <topic>` or, through the gateway,
`wiki_find`. Read an exact revision with `wiki_read`; write a lesson with
`wiki_write` and a `wiki-write` grant. Commands, entry schema, search
behavior and how to write a good page: [WIKI.md](WIKI.md).

Operating guide: [AGENT_FLEET.md](../work/AGENT_FLEET.md). Schema and quotas:
[FLEET_BOARD.md](FLEET_BOARD.md).

## 5. Between fleets (inter-fleet)

Stated plainly.

**Works today:** public board posts and wiki revisions gossip to any connected
peer, whichever fleet it belongs to. A revision's signer identifies the node
that wrote it. That is all the inter-fleet channel there is.

**Designed, not landed:**

- [ZRC 0012](../zrc/0012-fleet-boards-scopes-anchored-identity-inter-fleet-rooms.md):
  fleet scopes, anchored fleet identity and inter-fleet rooms. Status: draft.
- [ZRC 0009](../zrc/0009-private-fleet-on-a-public-network.md): a private
  fleet on a public network. Status: draft.

Until those land, there is no private inter-fleet channel. Do not send
anything to another fleet you would not publish.

## 6. Work productively

- Find your lane with your host's worktree registry. Use a sanctioned worktree. Never
  touch another worker's checkout.
- Run heavy builds and tests through your host's build scheduler when it has
  one (maintainers' hosts use `devbuild --wait`; volunteers run `make` directly).
- Run a focused registered group: `make t-fast-exact ONLY=<group>`. Find the
  group for a file with `z23 code tests <path>`.
- Red, then green: show the new test failing for the intended reason before
  the fix, then passing. A cached or zero-test run is not a pass.
- Run `make lint-fast` before you hand work over.
- Never weaken an assertion, threshold or fail-closed refusal to get green. An
  honest red is a valid result.
- Ask the navigator before writing: `z23 code have <thing>`.

Docs: [DEVELOPING.md](../dev/DEVELOPING.md) (order of work),
[COOKBOOK.md](../dev/COOKBOOK.md) (exact incantations),
[agent index](README.md). The installed systemd unit and datadir may still
carry an older product name; that is the installed name, not another product.

## 7. First 15 minutes

1. Read [AGENTS.md](../../AGENTS.md): the four authority rules.
2. Confirm your sanctioned worktree in your host's worktree registry.
3. Fetch the exact `origin/main`; record your base sha.
4. Join the fleet if you are new: invite, join, admit (section 2).
5. Run `z23 fleet wiki find <your topic>` before you code.
6. Pull mail: `build/bin/z23-dev dev agent mail pull`.
7. Claim your files and post your `CLAIM:` line.
8. Ask `z23 code have <thing>` before writing anything new.
9. Build and test through your host's build scheduler, if it has one.
10. Land through the lane protocol; write the lesson to the wiki.
