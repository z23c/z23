<!-- GENERATED FILE — DO NOT EDIT BY HAND.
     Source of truth: config/commands/*.def
     Template (editorial prose): docs/API_REFERENCE.md.in
     Generator: tools/gen_api_reference.c
     Regenerate: make docs-api-reference
     Gate: tools/lint/check_api_reference_generated.sh (check-api-reference-generated) -->
# API_REFERENCE.md — the native command tree, leaf by leaf

This is a **reference table**, not a spec. For the grammar, envelope shapes,
budgets, and migration status, read
[`docs/NATIVE_COMMAND_INTERFACE.md`](./NATIVE_COMMAND_INTERFACE.md) first —
that document is the frozen contract; this one enumerates every leaf the
contract currently declares. For additional native aliases and operator
contracts (`agentops`, `agentdiagnose`, `servicecatalog`, and the ZNAM/ZMSG/
Market/ZSWP methods), see [`docs/AGENT_API.md`](./AGENT_API.md).

The command tree supports the shared mission: people and AI create verifiable
public work through the same API, while no caller, balance, package index, or UI
owns the world they build in. Start with `discover search <goal>`, inspect the
selected leaf with `discover schema <leaf>`, and trust the availability column:
`ready` is implemented, `planned` fails closed, and neither label grants truth
or ownership authority. The ZCODE creation path and its free-access guarantees
are defined in
[`docs/work/ZC23_LIVING_COMMONS.md`](./work/ZC23_LIVING_COMMONS.md).

For the shortest executable route, run `z23 zcode guide`. It points to
the ready leaves for finding, inspecting, creating, improving, evidencing,
accepting, publishing and verifying work. Commands that inspect pre-genesis
Living Commons state require an explicit isolated scratch workspace; `.` and
live/canonical datadirs are rejected rather than guessed.

## Source of truth

**This page is generated. Do not edit it by hand.**

Every table below is emitted by
[`tools/gen_api_reference.c`](../tools/gen_api_reference.c) directly from the
declarative `.def` files under [`config/commands/`](../config/commands/) — the
same files [`config/src/command_catalog.c`](../config/src/command_catalog.c)
expands into the immutable `g_catalog_commands[]` table
([`lib/kernel/src/command_registry.c`](../lib/kernel/src/command_registry.c)).
The generator is a second consumer of the identical X-macro grammar, so the C
preprocessor — not a hand-rolled parser — reads the catalog. A leaf added,
promoted, or re-scheduled in a `.def` file shows up here the moment the page is
regenerated, and never before or after.

Editorial prose (this section, the legend, the envelope summary, and the proof
table at the end) lives in the template
[`docs/API_REFERENCE.md.in`](./API_REFERENCE.md.in) and is copied through
verbatim; everything derived from the catalog replaces a
`<!-- ZCL-GEN:… -->` marker.

```bash
make docs-api-reference      # regenerate this page from config/commands/*.def
make lint                    # check-api-reference-generated fails on any drift
```

The drift gate is
[`tools/lint/check_api_reference_generated.sh`](../tools/lint/check_api_reference_generated.sh):
it regenerates into a temporary file and fails if the checked-in page differs.
Editing this page instead of the `.def` file it came from is therefore a lint
failure, not a silent lie.

To confirm any row against a running binary:

```bash
z23 discover help [path]        # branch menu — immediate children only
z23 discover describe <path>    # one leaf's full spec
z23 discover search <text>      # ≤5 ranked matches
z23 discover schema <path> --side=input|output
```

## What the catalog currently declares

| Catalog fact | Count |
|---|---|
| Registry entries (branches + leaves) | 713 |
| Top-level roots | 12 |
| Branches | 165 |
| Leaves (dispatchable command paths) | 548 |
| … `ready` (live handler in this build) | 495 |
| … `compat` (metadata only, names a fallback) | 25 |
| … `planned` (fail-closed BLOCKED, exit 3) | 28 |
| … dev-gated 🔧 (`ready` only in `z23-dev`) | 24 |
| Leaves with `effect=mutate` | 185 |
| Leaves with `effect=destructive` | 4 |
| Leaves requiring **owner** authority | 112 |

Per source file:

| `.def` file | Entries | Branches | Leaves |
|---|---|---|---|
| `config/commands/root.def` | 10 | 5 | 5 |
| `config/commands/core.def` | 120 | 29 | 91 |
| `config/commands/apps.def` | 16 | 3 | 13 |
| `config/commands/app_features.def` | 71 | 19 | 52 |
| `config/commands/store.def` | 18 | 0 | 18 |
| `config/commands/ops.def` | 47 | 9 | 38 |
| `config/commands/dev.def` | 55 | 13 | 42 |
| `config/commands/code.def` | 17 | 2 | 15 |
| `config/commands/accounts.def` | 11 | 2 | 9 |
| `config/commands/vault.def` | 24 | 4 | 20 |
| `config/commands/zcode.def` | 218 | 51 | 167 |
| `config/commands/zcode_science.def` | 25 | 7 | 18 |
| `config/commands/metaverse.def` | 30 | 7 | 23 |
| `config/commands/yardsale.def` | 7 | 2 | 5 |
| `config/commands/zses.def` | 4 | 2 | 2 |
| `config/commands/telemetry/root.def` | 6 | 2 | 4 |
| `config/commands/telemetry/watch.def` | 1 | 0 | 1 |
| `config/commands/telemetry/runtime.def` | 4 | 1 | 3 |
| `config/commands/telemetry/sync.def` | 4 | 1 | 3 |
| `config/commands/telemetry/network.def` | 5 | 1 | 4 |
| `config/commands/telemetry/storage.def` | 5 | 1 | 4 |
| `config/commands/telemetry/wallet.def` | 3 | 1 | 2 |
| `config/commands/telemetry/agents.def` | 4 | 1 | 3 |
| `config/commands/telemetry/zcode.def` | 4 | 1 | 3 |
| `config/commands/telemetry/metaverse.def` | 4 | 1 | 3 |


## Column legend

| Column | Meaning |
|---|---|
| **Command** | the leaf's dotted path written as CLI words (`core chain block get`), plus any declared aliases |
| **Avail** | `ready` (dispatches now) · `compat` (metadata only; NULL handler, names a `→` fallback) · `planned` (fail-closed BLOCKED, exit 3, no handler) · 🔧 = dev-gated |
| **Policy** | `effect / risk / authority`, then a non-`sync` mode and any confirmation ritual, then `· latency/cost` — the `zcl_command_*` enums, see `docs/NATIVE_COMMAND_INTERFACE.md` §13 |
| **Input keys** | the leaf's allowed input keys; **bold** = `positional_keys`, the key(s) the handler requires |
| **Output schema** | the leaf's `output_schema` id |
| **Example** | the invocation the `.def` entry declares as its canonical example |
| **Summary** | the leaf's one-line `summary`; for a non-`ready` leaf, its `availability_reason` follows in italics |

A `ready` leaf always has a live handler in this build; a `planned` leaf always
fails closed with `COMMAND_PLANNED` (exit 3) and no handler — never a silent
stub. Both invariants are proven for the *whole* catalog by
`test_command_registry_catalog.c` (`test_catalog_wellformed`,
`test_ready_leaves_bound`, `test_planned_fail_closed`), not asserted here.

**Dev-gated leaves** (🔧) are declared via `ZCL_COMMAND_DEV_READ` /
`ZCL_COMMAND_DEV_COMMAND`. In a `ZCL_DEV_BUILD` binary (`z23-dev`) they
are `ready` with a real handler; in a release build they are honest `compat`
stubs whose `availability_reason` and `compat_target` tell you to run the same
command against `z23-dev` instead. This page always renders the
**release** view, so it describes the binary an operator actually ships.
[`tools/lint/check_release_no_dev_symbols.sh`](../tools/lint/check_release_no_dev_symbols.sh)
proves via `nm` that the release binary links none of the dev executors, so the
distinction is structural, not a convention.

**Never RPC/REST-bound**: everything under `dev.*` is checkout-local by design
(see [`config/commands/README.md`](../config/commands/README.md): "No `lib/`
source may include App, controller, service, or development handler headers").
Almost every `ready` leaf under `core.*` and `ops.*` dispatches through
`zcl_native_bridge_command` — a direct call into either a native handler body
(`app/controllers/src/*_native_handlers.c`) or the backing JSON-RPC method,
through the command bridge.

## Roots

The root order below is a wire contract, not a presentation choice.

| Root | CLI | Kind | Avail | Summary |
|---|---|---|---|---|
| `status` | `status` | leaf | ready | Node and wallet readiness with one next action |
| `core` | `core` | branch | ready | Consensus-bound node capabilities |
| `app` | `app` | branch | ready | Capability-scoped sovereign applications |
| `dev` | `dev` | branch | ready | Native edit, proof, and publication loop |
| `ops` | `ops` | branch | ready | Node diagnostics |
| `discover` | `discover` | branch | ready | Search and describe the command registry |
| `code` | `code` | branch | ready | Hierarchical source-code navigator |
| `vault` | `vault` | branch | ready | What this node owns, and what may act on it |
| `zcode` | `zcode` | branch | ready | Create, verify and preserve public C23 work together |
| `metaverse` | `metaverse` | branch | ready | Sovereign digital property: catalog, rights, receipts |
| `yardsale` | `yardsale` | branch | ready | For-sale-by-owner signed ads, settled bilaterally |
| `zses` | `zses` | branch | ready | Session invites |


## The tree, leaf by leaf

Sections follow catalog declaration order. A branch appears only when it owns
at least one direct leaf; a branch that exists purely to nest other branches is
represented by its children's sections.

### `status` — Node and wallet readiness with one next action

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `status` | ready | read / read / operator · fast/low | none | `zcl.status_journey.v1` | `z23 status` | Node and wallet readiness with one next action |

### `core` — Consensus-bound node capabilities

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `core status` | ready | read / read / public · fast/low | none | `zcl.core_status.v2` | `z23 core status` | Consensus node status: height, sync, health |
| `core status brief` | ready | read / read / public · fast/low | none | `zcl.core_status_brief.v1` | `z23 core status brief` | Flat lean status: hstar, gap, blocker, conditions, peers, rss (full field list: docs/NATIVE_COMMAND_INTERFACE.md CLI UX contract) |

#### `core.wallet.security` — Encryption-at-rest and runtime key custody

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `core wallet security status` | ready | read / read / operator · fast/low | none | `zcl.wallet_security.v1` | `z23 core wallet security status` | Report wallet encryption and lock state |
| `core wallet security encrypt` | ready | mutate / wallet / **owner** · foreground/moderate | `passphrase` | `zcl.wallet_security.v1` | `z23 core wallet security encrypt --input=-` | Encrypt every wallet secret at rest, then lock |
| `core wallet security unlock` | ready | mutate / wallet / **owner** · foreground/moderate | `passphrase`, `timeout_seconds` | `zcl.wallet_security.v1` | `z23 core wallet security unlock --input=-` | Unlock wallet keys for a bounded interval |
| `core wallet security lock` | ready | mutate / wallet / **owner** · fast/low | none | `zcl.wallet_security.v1` | `z23 core wallet security lock` | Lock the wallet and scrub resident keys |

#### `core.chain` — Blocks, transactions, and mempool

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `core chain tip` | ready | read / read / public · fast/low | none | `zcl.chain_tip.v1` | `z23 core chain tip` | Active chain tip in one call |

#### `core.chain.block` — Block by height or hash

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `core chain block get` | ready | read / read / public · fast/low | **`height`**, `hash`, `verbosity` | `zcl.block.v1` | `z23 core chain block get --height=478544` | Get one block by height or hash |

#### `core.chain.transaction` — Transaction by id

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `core chain transaction get` | ready | read / read / public · fast/low | **`txid`**, `verbose`, `raw_offset`, `raw_bytes` | `zcl.transaction.v1` | `z23 core chain transaction get --txid=<hex>` | Get one transaction by id |

#### `core.chain.mempool` — Mempool state

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `core chain mempool status` | ready | read / read / public · fast/low | none | `zcl.mempool_status.v1` | `z23 core chain mempool status` | Mempool size, bytes, and fee summary |
| `core chain mempool list` | ready | read / read / public · fast/low | none | `zcl.mempool_list.v1` | `z23 core chain mempool list` | List mempool transaction ids |

#### `core.chain.wait` — Block until a chain condition holds

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `core chain wait height` | planned | read / read / operator · persistent/low | **`height`**, `timeout_ms` | `zcl.wait_result.v1` | `z23 core chain wait height --height=3200000` | Wait until the tip reaches a target height — *blocking wait proxy is deferred to the Wave 2.2 job protocol* |
| `core chain wait blocker` | planned | read / read / operator · persistent/low | **`blocker`**, `timeout_ms` | `zcl.wait_result.v1` | `z23 core chain wait blocker` | Wait until a named blocker is raised or cleared — *blocking wait proxy is deferred to the Wave 2.2 job protocol* |
| `core chain wait halt` | planned | read / read / operator · persistent/low | `timeout_ms` | `zcl.wait_result.v1` | `z23 core chain wait halt` | Wait until the node halts on a named blocker — *blocking wait proxy is deferred to the Wave 2.2 job protocol* |

#### `core.sync` — Sync phase and validation progress

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `core sync status` | ready | read / read / public · fast/low | none | `zcl.sync_status.v1` | `z23 core sync status` | Sync phase and header/block gap |
| `core sync validation` | ready | read / read / public · fast/low | none | `zcl.validation_status.v1` | `z23 core sync validation` | Background validation progress |
| `core sync blockers` | ready | read / read / public · fast/low | none | `zcl.blockers.v1` | `z23 core sync blockers` | Active named sync blockers |
| `core sync diagnose` | ready | read / read / operator · fast/moderate | none | `zcl.syncdiag.v1` | `z23 core sync diagnose` | Diagnose why sync is not advancing |
| `core sync frontier offline` | ready | read / read / operator · fast/low | `datadir` | `zcl.core_sync_frontier_offline.v1` | `z23 core sync frontier offline --input='{"datadir":"/home/you/.zclassic-c23"}'` | H* (reducer frontier) of a STOPPED/COPIED datadir |

#### `core.anchor` — Generic ZANC digest-anchor composition and inspection

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `core anchor compose` | ready | read / read / public · instant/tiny | **`digest`**, `hash_type`, `label` | `zcl.core_anchor_compose.v1` | `z23 core anchor compose --digest=<64hex> --label=release@1` | Compose one canonical generic ZANC digest anchor |
| `core anchor inspect` | ready | read / read / public · instant/tiny | **`op_return_hex`** | `zcl.core_anchor_inspect.v1` | `z23 core anchor inspect <op_return_hex>` | Strictly decode one canonical ZANC OP_RETURN |

#### `core.epoch` — Epoch anchors: commit the overlay catalog digest on-chain

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `core epoch status` | ready | read / read / operator · fast/low | `datadir` | `zcl.core_epoch_status.v1` | `z23 core epoch status` | Catalog digest, epoch position, and anchor presence |
| `core epoch anchor` | ready | mutate / wallet / operator · foreground/moderate | `datadir` | `zcl.core_epoch_anchor.v1` | `z23 core epoch anchor` | Anchor the current catalog digest on-chain (spends a fee) |
| `core epoch verify` | ready | read / read / operator · fast/low | `height`, `datadir` | `zcl.core_epoch_verify.v1` | `z23 core epoch verify` | Check the current epoch's anchor against the live digest |

#### `core.consensus` — Consensus reports, integrity, and mutation

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `core consensus report` | ready | read / read / public · fast/low | none | `zcl.consensus_report.v1` | `z23 core consensus report` | Consensus parity and rule report |
| `core consensus integrity` | ready | read / read / public · foreground/moderate | none | `zcl.data_integrity.v1` | `z23 core consensus integrity` | SHA3 over consensus tables |
| `core consensus mmb` | ready | read / read / public · fast/low | none | `zcl.mmb.v1` | `z23 core consensus mmb` | Merkle Mountain Belt commitment state |

#### `core.consensus.utxo` — UTXO set commitment and audit

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `core consensus utxo commitment` | ready | read / read / public · foreground/moderate | none | `zcl.utxo_commitment.v1` | `z23 core consensus utxo commitment` | SHA3 commitment over the UTXO set |
| `core consensus utxo audit` | ready | read / read / operator · foreground/moderate | none | `zcl.utxo_audit.v1` | `z23 core consensus utxo audit` | Audit the UTXO set for drift |

#### `core.consensus.block` — Invalidate or reconsider a block

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `core consensus block invalidate` | planned | destructive / core-recovery / **owner**, plan-commit · foreground/moderate | **`hash`** | `zcl.block_mutation.v1` | `z23 core consensus block invalidate --hash=<hash>` | Mark a block invalid and reorg away from it — *chain-mutation confirmation handshake is a Wave 2.2 deliverable* |
| `core consensus block reconsider` | planned | mutate / core-recovery / **owner**, plan-commit · foreground/moderate | **`hash`** | `zcl.block_mutation.v1` | `z23 core consensus block reconsider --hash=<hash>` | Clear an invalid mark and reconsider a block — *chain-mutation confirmation handshake is a Wave 2.2 deliverable* |

#### `core.network` — Peers and onion transport

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `core network status` | ready | read / read / public · fast/low | none | `zcl.network_status.v1` | `z23 core network status` | Network info and connections |
| `core network chain_view` | ready | read / read / public · fast/low | none | `zcl.network_chain_view.v1` | `z23 core network chain_view` | Reachable-network chain view: modal tip, max height, our delta, forks |
| `core network census` | ready | read / read / public · fast/low | `ua-contains`, `min-height`, `seen-within`, `page`, `limit` | `zcl.network_census.v1` | `z23 core network census --ua-contains=MagicBean --limit=25` | Paginated list of every node the crawler has seen |
| `core network node` | ready | read / read / public · fast/low | **`target`** | `zcl.network_node.v1` | `z23 core network node 1.2.3.4:8033` | Everything known about one node (census row, history, edges) |
| `core network versions` | ready | read / read / public · fast/low | none | `zcl.network_versions.v1` | `z23 core network versions` | User-agent / version distribution across the census |
| `core network graph` | ready | read / read / public · fast/low | none | `zcl.network_graph.v1` | `z23 core network graph` | Topology stats: node/edge counts and top-advertised endpoints |

#### `core.network.peers` — Connected peers

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `core network peers list` | ready | read / read / public · fast/low | none | `zcl.peers.v1` | `z23 core network peers list` | List connected peers |
| `core network peers incidents` | ready | read / read / operator · fast/low | none | `zcl.peer_incidents.v2` | `z23 core network peers incidents` | Recent peer misbehavior incidents |
| `core network peers latency` | ready | read / read / public · fast/low | none | `zcl.peer_latency.v1` | `z23 core network peers latency` | Round-trip latency for every peer |
| `core network peers add` | ready | mutate / core-recovery / operator · fast/low | **`address`** | `zcl.peer_add.v1` | `z23 core network peers add --address=<ip:port\|v3.onion>` | Add an outbound peer connection |

#### `core.network.onion` — Embedded onion service

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `core network onion status` | ready | read / read / public · fast/low | none | `zcl.onion_status.v1` | `z23 core network onion status` | Onion address, port map, bootstrap, and handshake stages |
| `core network onion health` | ready | read / read / operator · fast/low | none | `zcl.onion_health.v1` | `z23 core network onion health` | Onion reachability health |

#### `core.wallet` — Keys, balance, and transactions

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `core wallet status` | ready | read / read / operator · fast/low | none | `zcl.wallet_status.v1` | `z23 core wallet status` | Wallet summary and key counts |
| `core wallet balance` | ready | read / read / operator · fast/low | none | `zcl.wallet_balance.v1` | `z23 core wallet balance` | Confirmed and total balance |
| `core wallet restore` | ready | mutate / wallet / **owner**, plan-commit · foreground/moderate | **`from`**, `datadir`, `password`, `confirm` | `zcl.wallet_restore.v1` | `z23 core wallet restore --from=<backup.sqlite>` | Restore a wallet backup into a datadir |
| `core wallet rescan-witnesses` | ready | mutate / wallet / **owner**, job · background/high | none | `zcl.wallet_rescan_witnesses.v1` | `z23 core wallet rescan-witnesses` | Rebuild Sapling witnesses for unspent notes |
| `core wallet audit` | ready | read / read / operator · foreground/moderate | none | `zcl.wallet_audit.v1` | `z23 core wallet audit` | Audit wallet key/UTXO consistency |
| `core wallet rescan` | ready | mutate / wallet / **owner** · background/high | `start_height` | `zcl.wallet_rescan.v2` | `z23 core wallet rescan` | Rescan the chain for wallet transactions |
| `core wallet replay` | planned | mutate / wallet / **owner**, job · background/high | none | `zcl.wallet_replay.v1` | `z23 core wallet replay` | Replay wallet state from chain — *wallet replay job binding is a Wave 2.2 deliverable* |

#### `core.wallet.address` — Transparent addresses

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `core wallet address new` | ready | mutate / wallet / **owner** · fast/low | none | `zcl.wallet_address.v1` | `z23 core wallet address new` | Derive and persist a new transparent address |
| `core wallet address public-key` | ready | read / read / operator · fast/low | **`address`** | `zcl.wallet_public_key.v1` | `z23 core wallet address public-key --address=<addr>` | Get a wallet-owned address's public key |
| `core wallet address list` | ready | read / read / operator · fast/low | none | `zcl.wallet_addresses.v1` | `z23 core wallet address list` | List transparent addresses |
| `core wallet address import` | ready | mutate / wallet / **owner** · fast/low | **`address`** | `zcl.wallet_address.v1` | `z23 core wallet address import --address=<addr>` | Import a watch-only address |
| `core wallet address export-key` | ready | mutate / wallet / **owner**, plan-commit · fast/low | **`address`**, `confirm` | `zcl.wallet_privkey.v1` | `z23 core wallet address export-key --address=<addr>` | Export the private key for an address |
| `core wallet address label` | ready | mutate / app-write / operator · fast/low | **`address`**, `label` | `zcl.wallet_label.v1` | `z23 core wallet address label --input='{"address":"t1...","label":"friends"}'` | Set or clear the label on an address |
| `core wallet address by-label` | ready | read / read / operator · fast/low | **`label`** | `zcl.wallet_by_label.v1` | `z23 core wallet address by-label friends` | List addresses carrying a given label |

#### `core.wallet.utxo` — Spendable outputs

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `core wallet utxo list` | ready | read / read / operator · fast/low | none | `zcl.wallet_utxos.v1` | `z23 core wallet utxo list` | List spendable UTXOs |

#### `core.wallet.transaction` — Wallet transactions

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `core wallet transaction list` | ready | read / read / operator · fast/low | none | `zcl.wallet_tx_list.v1` | `z23 core wallet transaction list` | List recent wallet transactions |
| `core wallet transaction get` | ready | read / read / operator · fast/low | **`txid`** | `zcl.wallet_tx.v1` | `z23 core wallet transaction get --txid=<hex>` | Get one wallet transaction by id |
| `core wallet transaction send` | ready | mutate / wallet / **owner**, plan-commit · foreground/moderate | `wallet_scope`, `address`, `amount`, `idempotency_key`, `confirm` | `zcl.wallet_send.v1` | `z23 core wallet transaction send --input='<obj>'` | Build, sign, and broadcast a payment |

#### `core.wallet.transaction.multisig` — Transparent P2SH multisig composition

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `core wallet transaction multisig compose` | ready | read / read / operator · fast/low | `required_signatures`, `public_keys` | `zcl.wallet_multisig_composition.v1` | `z23 core wallet transaction multisig compose --input='<obj>'` | Compose a P2SH multisig address and redeem script |

#### `core.wallet.transaction.raw` — Raw transparent transaction composition

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `core wallet transaction raw create` | ready | mutate / wallet / **owner** · fast/low | **`inputs`**, **`outputs`**, `op_return_hex` | `zcl.wallet_raw_create.v1` | `z23 core wallet transaction raw create --input='<obj>'` | Create an unsigned raw transaction |
| `core wallet transaction raw sign` | ready | mutate / wallet / **owner** · foreground/moderate | **`raw_hex`**, `prevtxs` | `zcl.wallet_raw_sign.v1` | `z23 core wallet transaction raw sign --input='<obj>'` | Sign a raw transaction with wallet keys |
| `core wallet transaction raw broadcast` | ready | mutate / wallet / **owner**, plan-commit · foreground/moderate | **`raw_hex`**, `allow_high_fees`, `confirm` | `zcl.wallet_raw_broadcast.v1` | `z23 core wallet transaction raw broadcast --input='<obj>'` | Validate and broadcast a signed raw transaction |

#### `core.wallet.shielded` — Sapling shielded addresses and notes

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `core wallet shielded address` | ready | mutate / wallet / **owner** · fast/low | none | `zcl.shielded_address.v1` | `z23 core wallet shielded address` | Derive a new shielded address |
| `core wallet shielded balance` | ready | read / read / operator · fast/low | **`address`** | `zcl.shielded_balance.v1` | `z23 core wallet shielded balance --address=<zaddr>` | Shielded balance for one address |
| `core wallet shielded notes` | ready | read / read / operator · fast/low | none | `zcl.shielded_notes.v1` | `z23 core wallet shielded notes` | List spendable shielded notes |
| `core wallet shielded send` | ready | mutate / wallet / **owner**, plan-commit · foreground/high | `wallet_scope`, `from`, `to`, `amount`, `memo`, `memo_hex`, `idempotency_key`, `confirm` | `zcl.shielded_send.v1` | `z23 core wallet shielded send --input='{"wallet_scope":"dev","from":"zs1..","to":"zs1..","amount":"0.01000000"}'` | Send a shielded payment |

#### `core.wallet.backup` — Wallet backup

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `core wallet backup status` | ready | read / read / operator · fast/low | none | `zcl.wallet_backup_status.v1` | `z23 core wallet backup status` | Wallet backup freshness |
| `core wallet backup now` | ready | mutate / wallet / **owner**, plan-commit · fast/low | `confirm`, `password` | `zcl.wallet_backup.v1` | `z23 core wallet backup now` | Take a wallet backup now |
| `core wallet backup decrypt` | ready | mutate / wallet / **owner**, plan-commit · foreground/low | **`from`**, `to`, `password`, `confirm` | `zcl.wallet_backup_decrypt.v1` | `z23 core wallet backup decrypt --input='{"from":"~/wallet_backups/wallet_backup_1.sqlite.enc","to":"/tmp/wb.sqlite"}'` | Decrypt an encrypted wallet backup file |

#### `core.wallet.recovery` — Recovery phrase (the twelve words)

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `core wallet recovery status` | ready | read / read / **owner** · foreground/moderate | `datadir` | `zcl.wallet_recovery_status.v1` | `z23 core wallet recovery status` | Can this wallet be rebuilt from its words |
| `core wallet recovery restore` | ready | mutate / wallet / **owner**, plan-commit · foreground/moderate | `phrase`, `datadir`, `confirm` | `zcl.wallet_recovery_restore.v1` | `z23 core wallet recovery restore --input='{"datadir":"/tmp/recovered"}'` | Rebuild a wallet from its recovery phrase |

#### `core.storage` — Raw node storage

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `core storage stats` | ready | read / read / operator · fast/low | none | `zcl.db_stats.v1` | `z23 core storage stats` | Database size and table stats |
| `core storage integrity` | planned | read / read / operator · foreground/moderate | none | `zcl.storage_integrity.v1` | `z23 core storage integrity` | Verify raw storage integrity — *a distinct storage-integrity handler is a Wave 2.2 deliverable* |
| `core storage query` | ready | read / read / operator · fast/moderate | **`sql`**, `limit` | `zcl.storage_query.v1` | `z23 core storage query --sql='SELECT ...'` | Run one SELECT-only query over node.db |
| `core storage query offline` | ready | read / read / operator · fast/moderate | `datadir`, `sql`, `limit` | `zcl.storage_query.v1` | `z23 core storage query offline --input='{"datadir":"/home/you/.zclassic-c23","sql":"SELECT ..."}'` | Run one SELECT-only query over a STOPPED/COPIED datadir's node.db |

#### `core.mining` — Mining info and benchmarks

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `core mining status` | ready | read / read / public · fast/low | none | `zcl.mining_status.v1` | `z23 core mining status` | Mining info and difficulty |
| `core mining benchmark` | ready | read / read / operator · foreground/moderate | none | `zcl.mining_benchmark.v1` | `z23 core mining benchmark` | Run an Equihash solver benchmark |

#### `core.node` — Local node lifecycle

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `core node bootstatus` | ready | read / read / operator · fast/low | `datadir` | `zcl.core_bootstatus.v1` | `z23 core node bootstatus -datadir=/home/you/.zclassic-c23` | Pre-RPC boot status |
| `core node bootwait` | ready | read / read / operator · foreground/low | `datadir`, `timeout_ms`, `heartbeat_ms` | `zcl.core_bootstatus.v1` | `z23 core node bootwait -datadir=/home/you/.zclassic-c23 --timeout_ms=120000` | Wait for boot to serve |

#### `core.identity` — Sovereign identities: resolve and anchor master keys

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `core identity resolve` | ready | read / read / public · fast/low | **`pubkey`**, `name`, `datadir` | `zcl.core_identity_resolve.v1` | `z23 core identity resolve --pubkey=<64hex>` | Resolve one master key by pubkey or ZNAM name |
| `core identity anchor` | ready | mutate / wallet / **owner**, plan-commit · foreground/moderate | **`wallet_scope`**, `pubkey`, `idempotency_key`, `plan_id`, `confirm`, `datadir` | `zcl.core_identity_anchor.v2` | `z23 core identity anchor --input='{"wallet_scope":"dev","pubkey":"<64hex>","idempotency_key":"zid-anchor-1"}'` | Anchor a master key on-chain (spends a fee) |
| `core identity rotate` | ready | mutate / wallet / **owner**, plan-commit · foreground/moderate | **`wallet_scope`**, `pubkey`, `new_pubkey`, `idempotency_key`, `plan_id`, `confirm`, `datadir` | `zcl.core_identity_anchor.v2` | `z23 core identity rotate --input='{"wallet_scope":"dev","pubkey":"<64hex>","new_pubkey":"<64hex>","idempotency_key":"zid-rotate-1"}'` | Rotate an anchored master key to a successor (spends a fee) |
| `core identity revoke` | ready | mutate / wallet / **owner**, plan-commit · foreground/moderate | **`wallet_scope`**, `pubkey`, `idempotency_key`, `plan_id`, `confirm`, `datadir` | `zcl.core_identity_anchor.v2` | `z23 core identity revoke --input='{"wallet_scope":"dev","pubkey":"<64hex>","idempotency_key":"zid-revoke-1"}'` | Retire an anchored master key with no successor (spends a fee) |
| `core identity list` | ready | read / read / public · fast/low | `limit`, `offset`, `datadir` | `zcl.core_identity_index.v1` | `z23 core identity list --limit=25` | Page the anchored identities, newest anchor first |

#### `core.zdir` — On-chain node directory: announce and retire onion hostnames

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `core zdir guide` | ready | read / read / public · instant/tiny | none | `zcl.core_zdir_guide.v1` | `z23 core zdir guide` | How to find Z23 nodes from the chain, without seed IPs |
| `core zdir list` | ready | read / read / public · fast/low | `datadir` | `zcl.core_zdir_list.v1` | `z23 core zdir list` | Active onion hostnames folded from confirmed ZDIR records |
| `core zdir register` | ready | mutate / wallet / **owner**, plan-commit · foreground/moderate | **`wallet_scope`**, `hostname`, `pubkey`, `idempotency_key`, `plan_id`, `confirm`, `datadir` | `zcl.core_zdir_register.v2` | `z23 core zdir register --input='{"wallet_scope":"dev","hostname":"<56base32>.onion","idempotency_key":"zdir-register-1"}'` | Announce a v3 onion hostname on-chain as a node (spends a fee) |
| `core zdir deregister` | ready | mutate / wallet / **owner**, plan-commit · foreground/moderate | **`wallet_scope`**, `hostname`, `idempotency_key`, `plan_id`, `confirm`, `datadir` | `zcl.core_zdir_register.v2` | `z23 core zdir deregister --input='{"wallet_scope":"dev","hostname":"<56base32>.onion","idempotency_key":"zdir-deregister-1"}'` | Retire an onion hostname from the on-chain directory (spends a fee) |

### `app` — Capability-scoped sovereign applications

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `app list` | ready | read / read / public · fast/low | none | `zcl.app_index.v1` | `z23 app list` | List installed App manifests |
| `app inspect` | ready | read / read / public · fast/low | **`app_id`** | `zcl.app_manifest_summary.v1` | `z23 app inspect social` | Inspect one App manifest and bindings |
| `app protocols` (aliases: `appprotocols`) | compat → `z23 appprotocols` | read / read / public · fast/low | none | `zcl.app_protocols.v1` | `z23 app protocols` | List App protocol contracts — *native adapter is not executable yet; use the compatibility target* |

#### `app.transaction-types` — Discover every semantic ZCL transaction shape and its safe workflow

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `app transaction-types list` | ready | read / read / public · instant/tiny | none | `zcl.transaction_types.index.v2` | `z23 app transaction-types list` | List base, overlay, composite, process-only, contained, and planned transaction types |
| `app transaction-types show` | ready | read / read / public · instant/tiny | **`type`** | `zcl.transaction_type.v2` | `z23 app transaction-types show --type=znam_register` | Inspect one semantic ZCL transaction type and its safe workflow |
| `app transaction-types guide` | ready | read / read / public · instant/tiny | **`type`** | `zcl.transaction_type_guide.v1` | `z23 app transaction-types guide --type=znam_register` | Get one AI-ready transaction workflow with exact command contracts |
| `app transaction-types command` | ready | read / read / public · instant/tiny | **`path`** | `zcl.transaction_command.v1` | `z23 app transaction-types command core.wallet.transaction.send` | Reverse-map one native command to every transaction workflow it can serve |
| `app transaction-types wire` | ready | read / read / public · instant/tiny | none | `zcl.transaction_wire_catalog.v1` | `z23 app transaction-types wire` | List every consensus transaction wire era and script-processing bucket |
| `app transaction-types micro-lab` | ready | read / read / public · instant/tiny | **`slot`** | `zcl.transaction_micro_lab.v1` | `z23 app transaction-types micro-lab --slot=1` | Inspect the checked 100-transaction micro-lab campaign or one numbered slot |

#### `app.service` — Token-gated services declared in the service catalog

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `app service list` | ready | read / read / public · instant/tiny | none | `zcl.service_binding_index.v1` | `z23 app service list` | List declared services and their catalog identity |
| `app service inspect` | ready | read / read / public · instant/tiny | **`service`** | `zcl.service_binding.v1` | `z23 app service inspect reference` | Inspect one service binding: namespaces, token gate, isolation |
| `app service access` | ready | read / read / public · fast/low | **`service`**, `address`, `datadir`, `tip_height` | `zcl.service_access_verdict.v1` | `z23 app service access reference` | Evaluate one service's token gate and explain the verdict |
| `app service status` | ready | read / read / public · instant/tiny | **`service`** | `zcl.service_lifecycle.v1` | `z23 app service status` | Show each declared service's runtime lifecycle state |

#### `app.names` — Names

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `app names resolve` | ready | read / read / public · fast/low | **`name`** | `zcl.app_name_record.v1` | `z23 app names resolve alice` | Resolve a ZCL Name to its target |
| `app names list` | ready | read / read / public · fast/low | none | `zcl.app_name_index.v1` | `z23 app names list` | List registered ZCL Names |
| `app names register` | ready | mutate / app-write / **owner**, plan-commit · foreground/moderate | **`wallet_scope`**, `name`, `type`, `value`, `idempotency_key`, `plan_id`, `confirm` | `zcl.app_name_txresult.v1` | `z23 app names register --input='{"wallet_scope":"dev","name":"alice","type":"zaddr","value":"zs1..","idempotency_key":"name-register-1"}'` | Register a ZCL Name on-chain |
| `app names update` | ready | mutate / app-write / **owner**, plan-commit · foreground/moderate | **`wallet_scope`**, `name`, `type`, `value`, `idempotency_key`, `plan_id`, `confirm` | `zcl.app_name_txresult.v1` | `z23 app names update --input='{"wallet_scope":"dev","name":"alice","type":"zaddr","value":"zs1..","idempotency_key":"name-update-1"}'` | Replace a ZCL Name's primary target |
| `app names transfer` | ready | mutate / app-write / **owner**, plan-commit · foreground/moderate | **`wallet_scope`**, `name`, `new_owner`, `idempotency_key`, `plan_id`, `confirm` | `zcl.app_name_txresult.v1` | `z23 app names transfer --input='{"wallet_scope":"dev","name":"alice","new_owner":"t1..","idempotency_key":"name-transfer-1"}'` | Transfer ZCL Name ownership |
| `app names renew` | ready | mutate / app-write / **owner**, plan-commit · foreground/moderate | **`wallet_scope`**, `name`, `idempotency_key`, `plan_id`, `confirm` | `zcl.app_name_txresult.v1` | `z23 app names renew --input='{"wallet_scope":"dev","name":"alice","idempotency_key":"name-renew-1"}'` | Renew a ZCL Name registration term |
| `app names set-record` | ready | mutate / app-write / **owner**, plan-commit · foreground/moderate | **`wallet_scope`**, `name`, `type`, `value`, `idempotency_key`, `plan_id`, `confirm` | `zcl.app_name_txresult.v1` | `z23 app names set-record --input='{"wallet_scope":"dev","name":"alice","type":"btc","value":"bc1..","idempotency_key":"name-record-1"}'` | Set a multi-coin address record |
| `app names set-text` | ready | mutate / app-write / **owner**, plan-commit · foreground/moderate | **`wallet_scope`**, `name`, `key`, `value`, `idempotency_key`, `plan_id`, `confirm` | `zcl.app_name_txresult.v1` | `z23 app names set-text --input='{"wallet_scope":"dev","name":"alice","key":"url","value":"https://..","idempotency_key":"name-text-1"}'` | Set a text record on a ZCL Name |

#### `app.tokens` — Tokens

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `app tokens list` | ready | read / read / public · fast/low | none | `zcl.app_token_index.v1` | `z23 app tokens list` | List ZSLP tokens on the network |
| `app tokens create` | ready | mutate / wallet / **owner**, plan-commit · foreground/moderate | **`wallet_scope`**, `ticker`, `name`, `decimals`, `supply`, `idempotency_key`, `plan_id`, `confirm` | `zcl.app_token_txresult.v1` | `z23 app tokens create --input='{"wallet_scope":"dev","ticker":"DEMO","name":"Demo Token","decimals":0,"supply":"1000","idempotency_key":"demo-genesis-1"}'` | Create a ZSLP token |
| `app tokens send` | ready | mutate / wallet / **owner**, plan-commit · foreground/moderate | **`wallet_scope`**, `token_id`, `to`, `units`, `idempotency_key`, `plan_id`, `confirm` | `zcl.app_token_txresult.v1` | `z23 app tokens send --input='{"wallet_scope":"dev","token_id":"<64-hex>","to":"t1...","units":"25","idempotency_key":"token-send-1"}'` | Send ZSLP token units |
| `app tokens mint` | ready | mutate / wallet / **owner**, plan-commit · foreground/moderate | **`wallet_scope`**, `token_id`, `to`, `units`, `idempotency_key`, `plan_id`, `confirm` | `zcl.app_token_txresult.v1` | `z23 app tokens mint --input='{"wallet_scope":"dev","token_id":"<64-hex>","to":"t1...","units":"100","idempotency_key":"token-mint-1"}'` | Mint ZSLP token units |
| `app tokens burn` | ready | mutate / wallet / **owner**, plan-commit · foreground/moderate | **`wallet_scope`**, `token_id`, `units`, `idempotency_key`, `plan_id`, `confirm` | `zcl.app_token_txresult.v1` | `z23 app tokens burn --input='{"wallet_scope":"dev","token_id":"<64-hex>","units":"10","idempotency_key":"token-burn-1"}'` | Burn ZSLP token units |

#### `app.messaging` — Messaging

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `app messaging inbox` | ready | read / read / **owner** · fast/low | none | `zcl.app_message_index.v1` | `z23 app messaging inbox` | List inbox messages |
| `app messaging send` | ready | mutate / app-write / **owner**, plan-commit · foreground/moderate | `message`, `channel`, `peer_id`, `to`, `from_address`, `reply_to`, `confirm` | `zcl.app_message_send_result.v1` | `z23 app messaging send --input='{"channel":"p2p","peer_id":1,"message":"hi","confirm":true}'` | Send a message |
| `app messaging send-named` | planned | mutate / app-write / **owner**, plan-commit · foreground/moderate | **`name`**, `message`, `confirm` | `zcl.app_message_send_result.v1` | `z23 app messaging send-named --input='{"name":"alice","message":"hi"}'` | Send a message to a ZCL Name — *needs an outbound delivery path before it can be exposed natively: rpc_msg_send_named (messaging_controller.c) resolves the name, calls zmsg_store_add + db_zmsg_save, and answers status=queued, but nothing in the tree ever drains that store onto a peer socket — no writer sends MSG_ZMSG for a stored message, so the queue has no consumer and the message is never delivered. Use app messaging send with an explicit peer_id, whose write to the peer socket is real* |
| `app messaging read` | ready | mutate / app-write / **owner** · fast/low | **`msg_id`** | `zcl.app_message_read_result.v1` | `z23 app messaging read --input='{"msg_id":"<64hex>"}'` | Mark a message read |

#### `app.market` — Market

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `app market list` | ready | read / read / public · fast/low | `profile` | `zcl.app_market_index.v1` | `z23 app market list` | List files on the ZCL Market |
| `app market status` | ready | read / read / operator · fast/low | none | `zcl.app_market_status.v1` | `z23 app market status` | ZCL Market status |
| `app market offer` | ready | mutate / app-write / **owner**, plan-commit · foreground/moderate | `filepath`, `price_per_mb_zat`, `confirm` | `zcl.app_market_offer_result.v1` | `z23 app market offer --input='{"filepath":"/data/f","price_per_mb_zat":1000}'` | Announce a file for sale |
| `app market buy` | planned | mutate / wallet / **owner**, plan-commit · foreground/moderate | `wallet_scope`, **`root_hash`**, `confirm` | `zcl.app_market_buy_result.v1` | `z23 app market buy --input='{"root_hash":"<64hex>"}'` | Buy and download a market file — *the explicit app.market.purchase plan, commit, status, and retrieve commands implement the complete reviewed workflow; the optional one-shot coordinator still needs an owner-review-preserving design. The legacy zmarket_buy placeholder refuses without starting a session* |

#### `app.market.content` — Seller content

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `app market content list` | ready | read / read / **owner** · fast/low | none | `zcl.market_contents.index.v1` | `z23 app market content list` | List owner-registered paid content |
| `app market content register` | ready | mutate / app-write / **owner** · foreground/moderate | **`offer_id`**, `content_path` | `zcl.market_content.v1` | `z23 app market content register --input='{"offer_id":"<64hex>","content_path":"/private/file"}'` | Bind private seller bytes to a signed offer |

#### `app.market.purchase` — Buyer purchase

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `app market purchase guide` | ready | read / read / public · instant/tiny | none | `zcl.app_market_purchase_guide.v1` | `z23 app market purchase guide` | Show the paid-file purchase workflow |
| `app market purchase plan` | ready | mutate / wallet / **owner** · foreground/moderate | **`wallet_scope`**, **`offer_id`**, **`source_address`**, **`chunk_start`**, **`chunks_paid`**, **`idempotency_key`** | `zcl.market_purchase.v1` | `printf '%s' '{"wallet_scope":"dev","offer_id":"<64hex>","source_address":"<owned-address>","chunk_start":0,"chunks_paid":1,"idempotency_key":"lab-001"}' \| z23 app market purchase plan --input=-` | Reserve one exact paid chunk range |
| `app market purchase commit` | ready | mutate / wallet / **owner**, idempotency · foreground/high | **`wallet_scope`**, **`plan_id`**, **`confirm`** | `zcl.market_purchase.v1` | `z23 app market purchase commit --input='{"wallet_scope":"dev","plan_id":"<64hex>","confirm":true}'` | Commit one exact reserved market payment |
| `app market purchase status` | ready | read / read / **owner** · fast/low | **`plan_id`** | `zcl.market_purchase.v1` | `z23 app market purchase status --input='{"plan_id":"<64hex>"}'` | Read one durable market purchase state |
| `app market purchase retrieve` | ready | mutate / app-write / **owner** · foreground/high | **`plan_id`**, **`destination_path`** | `zcl.market_purchase.v1` | `printf '%s' '{"plan_id":"<64hex>","destination_path":"/private/output.bin"}' \| z23 app market purchase retrieve --input=-` | Retrieve and atomically publish a paid file |

#### `app.market.moderation` — Moderation

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `app market moderation guide` | ready | read / read / public · instant/tiny | none | `zcl.app_market_moderation_guide.v1` | `z23 app market moderation guide` | Show the marketplace moderation boundary |
| `app market moderation status` | ready | read / read / operator · fast/low | none | `zcl.market_moderation_status.v1` | `z23 app market moderation status` | Show this node's market moderation posture |

#### `app.market.moderation.profile` — Profiles

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `app market moderation profile show` | ready | read / read / operator · fast/low | **`profile`** | `zcl.market_moderation_profile.v1` | `z23 app market moderation profile show --input='{"profile":"open-view"}'` | Describe one immutable moderation profile |
| `app market moderation profile set` | ready | mutate / app-write / **owner**, plan-commit · fast/low | **`profile`**, **`mode`**, `plan_token` | `zcl.market_moderation_profile_set.v1` | `z23 app market moderation profile set --input='{"profile":"open-view","mode":"plan"}'` | Set this node's listing-visibility profile |

#### `app.market.moderation.review` — Review marks

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `app market moderation review set` | ready | mutate / app-write / **owner** · fast/low | **`offer_id`**, **`review_state`** | `zcl.market_review_set.v1` | `z23 app market moderation review set --input='{"offer_id":"<64hex>","review_state":"reviewed_ok"}'` | Mark one offer's local review_state |

#### `app.store` — Store

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `app store list-product` | ready | mutate / app-write / **owner** · fast/low | `datadir`, `name`, `description`, `price_zcl`, `price_zatoshi`, `token_id`, `tokens_per_purchase`, `content_path`, `content_type`, `content_filename` | `zcl.app_store_product.v1` | `z23 app store list-product --input='{"name":"Field guide","token_id":"GUIDE","price_zcl":0.25,"content_path":"/srv/guide.pdf"}'` | List a product for sale in the store |
| `app store products` | ready | read / read / operator · fast/low | `datadir` | `zcl.app_store_products.v1` | `z23 app store products` | List the store's active products |
| `app store catalog` | ready | read / read / operator · fast/low | none | `zcl.store_catalog.v1` | `z23 app store catalog` | List what the store sells |
| `app store order` | ready | mutate / app-write / **owner** · foreground/moderate | `product_id`, `customer_address`, `output_path`, `payment_kind` | `zcl.store_order.v1` | `z23 app store order --input='{"product_id":1,"customer_address":"t1...","output_path":"/tmp/bought.bin"}'` | Place an order for a product |
| `app store pay` | ready | mutate / wallet / **owner**, plan-commit · foreground/high | `purchase_id`, `from_address`, `confirm` | `zcl.store_pay.v1` | `z23 app store pay --input='{"purchase_id":1,"from_address":"t1...","confirm":true}'` | Pay a placed order |
| `app store purchases` | ready | read / read / operator · fast/low | **`purchase_id`** | `zcl.store_purchases.v1` | `z23 app store purchases` | Show purchases and what is still owed |
| `app store collect` | ready | mutate / app-write / **owner** · foreground/moderate | **`purchase_id`**, `output_path` | `zcl.store_collect.v1` | `z23 app store collect --input='{"purchase_id":1,"output_path":"/tmp/bought.bin"}'` | Download a purchase you paid for |

#### `app.shop` — Shop

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `app shop init` | ready | mutate / app-write / **owner**, plan-commit · foreground/moderate | `confirm`, `input`, `datadir` | `zcl.shop_init.v1` | `z23 app shop init --input='{"confirm":true,"input":"/data/products.json"}'` | Initialize a live private shop |
| `app shop status` | ready | read / read / operator · fast/low | `datadir` | `zcl.shop_status.v1` | `z23 app shop status` | Show this node's shop posture |
| `app shop reputation` | ready | read / read / operator · fast/low | **`publisher`**, `datadir`, `now_unix` | `zcl.shop_reputation.v1` | `z23 app shop reputation --input='{"publisher":"02ab..."}'` | Show the provable evidence for a publisher |

#### `app.shop.want` — Buyer wants

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `app shop want post` | ready | mutate / app-write / **owner**, plan-commit · foreground/moderate | **`buyer_secret`**, **`amount_zatoshi`**, **`criteria`**, `spec_hash`, **`expires_unix`**, `nonce`, `issued_unix`, `now_unix`, `datadir`, `confirm` | `zcl.shop_want_post.v1` | `z23 app shop want post --input='{"buyer_secret":"ab01...","amount_zatoshi":500000,"criteria":"a CSV of every ZCL block hash 0..100, sha3-verified","expires_unix":1780000000,"confirm":true}'` | Post a buyer want |
| `app shop want list` | ready | read / read / operator · fast/low | `datadir`, `now_unix`, `profile`, `all` | `zcl.shop_want_list.v1` | `z23 app shop want list` | Browse this node's want board |
| `app shop want status` | ready | read / read / operator · fast/low | **`want_id`**, `datadir`, `now_unix`, `profile` | `zcl.shop_want_status.v1` | `z23 app shop want status --input='{"want_id":"ab01..."}'` | Show one want in full |
| `app shop want cancel` | ready | mutate / app-write / **owner**, plan-commit · foreground/moderate | **`want_id`**, **`buyer_secret`**, `datadir`, `now_unix`, `confirm` | `zcl.shop_want_cancel.v1` | `z23 app shop want cancel --input='{"want_id":"ab01...","buyer_secret":"ab01...","confirm":true}'` | Cancel a want you posted |
| `app shop want review` | ready | mutate / app-write / **owner**, plan-commit · foreground/moderate | **`want_id`**, **`review_state`**, `datadir`, `confirm` | `zcl.shop_want_review.v1` | `z23 app shop want review --input='{"want_id":"ab01...","review_state":"reviewed_ok","confirm":true}'` | Set the local review mark on a want |

#### `app.shop.want.fulfill` — Fulfillments

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `app shop want fulfill post` | ready | mutate / app-write / **owner**, plan-commit · foreground/moderate | **`want_id`**, **`seller_secret`**, **`artifact_root`**, **`content_root`**, `build_receipt_id`, `fuzz_receipt_id`, `bench_receipt_id`, **`expires_unix`**, **`nonce`**, **`issued_unix`**, `now_unix`, `datadir`, `confirm` | `zcl.shop_fulfill_post.v1` | `z23 app shop want fulfill post --input='{"want_id":"ab01...","seller_secret":"cd02...","artifact_root":"ef03...","content_root":"1204...","expires_unix":1780003600,"nonce":7,"issued_unix":1780000000}'` | Post a signed fulfillment claim |
| `app shop want fulfill list` | ready | read / read / operator · fast/moderate | **`want_id`**, `datadir`, `now_unix`, `all`, `profile` | `zcl.shop_fulfill_list.v1` | `z23 app shop want fulfill list --input='{"want_id":"ab01..."}'` | Compare fulfillment evidence for one want |
| `app shop want fulfill status` | ready | read / read / operator · fast/moderate | **`fulfill_id`**, `datadir`, `now_unix`, `profile` | `zcl.shop_fulfill_status.v1` | `z23 app shop want fulfill status --input='{"fulfill_id":"ab01..."}'` | Re-verify one fulfillment claim |
| `app shop want fulfill withdraw` | ready | mutate / app-write / **owner**, plan-commit · foreground/moderate | **`fulfill_id`**, **`seller_secret`**, `datadir`, `now_unix`, `confirm` | `zcl.shop_fulfill_withdraw.v1` | `z23 app shop want fulfill withdraw --input='{"fulfill_id":"ab01...","seller_secret":"cd02...","confirm":true}'` | Withdraw a fulfillment you signed |
| `app shop want fulfill review` | ready | mutate / app-write / **owner**, plan-commit · foreground/low | **`fulfill_id`**, **`review_state`**, `datadir`, `confirm` | `zcl.shop_fulfill_review.v1` | `z23 app shop want fulfill review --input='{"fulfill_id":"ab01...","review_state":"reviewed_ok"}'` | Set this node's fulfillment curation mark |

#### `app.swap` — Swaps

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `app swap chains` | ready | read / read / operator · fast/low | none | `zcl.app_swap_chains.v1` | `z23 app swap chains` | List supported atomic-swap chains |
| `app swap list` | ready | read / read / operator · fast/low | **`state`** | `zcl.app_swap_index.v1` | `z23 app swap list --input='{"state":"pending"}'` | List atomic-swap contracts |
| `app swap initiate` | ready | mutate / wallet / **owner**, plan-commit · foreground/moderate | `wallet_scope`, `my_address`, `counter_address`, `amount`, `locktime_blocks`, `chain`, `confirm` | `zcl.app_swap_contract.v1` | `z23 app swap initiate --input='{"my_address":"t1..","counter_address":"t1..","amount":1,"locktime_blocks":20,"confirm":true}'` | Initiate an atomic swap |
| `app swap participate` | ready | mutate / wallet / **owner**, plan-commit · foreground/moderate | `wallet_scope`, `my_address`, `counter_address`, `amount`, `locktime_blocks`, `secret_hash`, `chain`, `confirm` | `zcl.app_swap_contract.v1` | `z23 app swap participate --input='{"my_address":"t1..","counter_address":"t1..","amount":1,"locktime_blocks":10,"secret_hash":"<64hex>","confirm":true}'` | Participate in an atomic swap |

#### `app.qr` — QR

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `app qr show` | ready | mutate / app-write / operator, display-only · fast/low | **`payload`**, `title`, `output`, `page` | `zcl.app_qr_show.v1` | `z23 app qr show 'zclassic:t1...?amount=0.01'` | Show a payload as a native QR window |

#### `app.presentation` — Native presentation

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `app presentation show` | ready | mutate / app-write / operator, display-only · fast/low | **`kind`**, **`request_id`**, **`title`**, `summary`, `exact_root`, `items`, `actions`, `output`, `page` | `zcl.app_presentation_show.v1` | `z23 app presentation show --input='<bounded-model>'` | Show a bounded renderer-neutral model in a native C23 window |
| `app presentation status` | ready | mutate / app-write / operator, display-only · fast/low | `output`, `page` | `zcl.app_presentation_status.v1` | `z23 app presentation status` | Show canonical node facts in a native C23 status card |
| `app presentation corpus` | ready | mutate / app-write / operator, display-only · fast/low | `output`, `page` | `zcl.app_presentation_corpus.v1` | `z23 app presentation corpus` | Show the canonical C23 corpus lower bound in a native status card |
| `app presentation code-change` | ready | mutate / app-write / operator, display-only · fast/low | **`workspace`**, **`before_root`**, **`candidate_root`**, **`path`**, **`requested_behavior`**, **`before_behavior`**, **`after_behavior`**, `output`, `page` | `zcl.app_presentation_code_change.v1` | `z23 app presentation code-change --input='<exact-roots-and-summaries>'` | Show an exact ZVCS-backed C code change in a native window |
| `app presentation development` | ready | mutate / app-write / operator, display-only · fast/low | `workspace`, `receipt_id`, `output`, `page` | `zcl.app_presentation_development.v1` | `z23 app presentation development` | Show the latest exact local development consequence in native C23 |
| `app presentation reproduction` | ready | mutate / app-write / operator, display-only · fast/low | **`action_id`**, `output`, `page` | `zcl.app_presentation_reproduction.v1` | `z23 app presentation reproduction --input='{"action_id":"<64hex>"}'` | Show live independent-reproduction progress in one native window |
| `app presentation publication-confirm` | ready | mutate / app-write / operator, display-only · foreground/moderate | `release_hex`, `manifest_hex`, `recipe_hex`, `dir`, `datadir`, `output`, `page` | `zcl.app_presentation_publication_confirm.v1` | `z23 app presentation publication-confirm --input='{"release_hex":"..","manifest_hex":"..","recipe_hex":"..","dir":"/tmp/pkg"}'` | Ask for an exact local package-commit decision in native C23 |
| `app presentation release-confirm` | ready | mutate / app-write / operator, display-only · fast/low | `workspace`, `work`, `datadir`, `output`, `page` | `zcl.app_presentation_release_confirm.v1` | `z23-dev app presentation release-confirm --input='{"workspace":".","work":"latest"}'` | Ask for one exact proven-candidate decision in native C23 |
| `app presentation publication-status` | ready | mutate / app-write / operator, display-only · fast/low | **`package_root`**, **`transport_root`**, **`confirmation_identity`**, `output`, `page` | `zcl.app_presentation_publication_status.v1` | `z23 app presentation publication-status --input='{"package_root":"<64hex>","transport_root":"<64hex>","confirmation_identity":"<64hex>"}'` | Show exact package publication progress in native C23 |

#### `app.blog` — Blog

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `app blog anchor` | ready | mutate / app-write / **owner**, plan-commit · foreground/moderate | **`wallet_scope`**, `name`, `event_id`, `idempotency_key`, `plan_id`, `confirm` | `zcl.app_blog_anchor.v1` | `z23 app blog anchor --input='{"wallet_scope":"dev","name":"alice","event_id":"<64-hex>","idempotency_key":"blog-alice-1"}'` | Anchor a signed Blog event on-chain |

#### `app.payments.zpay` — ZPAY

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `app payments zpay compose` | ready | read / read / public · instant/tiny | **`network`**, **`message_type`**, **`created_at`**, **`expires_at`**, **`nonce`**, **`request_id`**, **`invoice_digest`**, **`asset`**, **`amount_commitment`**, `reply_ref` | `zcl.app_zpay_memo.v1` | `z23 app payments zpay compose --input='<obj>'` | Compose an anonymous canonical ZPAY Sapling memo |
| `app payments zpay inspect` | ready | read / read / public · instant/tiny | **`memo_hex`**, **`network`**, **`now_unix`** | `zcl.app_zpay_envelope.v1` | `z23 app payments zpay inspect --input='<obj>'` | Decode, authenticate, and policy-check one ZPAY Sapling memo |

#### `app.auth` — Public-key challenge/response login

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `app auth challenge` | ready | mutate / app-write / public · fast/low | `server`, **`address`** | `zcl.auth_challenge.v1` | `z23 app auth challenge --input='{"address":"t1..."}'` | Issue a single-use login challenge to sign |
| `app auth verify` | ready | mutate / app-write / public · fast/low | `server`, `address`, `nonce`, `signature`, `pubkey` | `zcl.auth_session.v1` | `z23 app auth verify --input='{"address":"t1...","nonce":"..","signature":".."}'` | Verify a signed challenge and mint a session |

#### `app.account` — Principal (multi-user) administration

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `app account list` | ready | read / read / operator · fast/low | none | `zcl.account_index.v1` | `z23 app account list` | List principals (public projection) |
| `app account show` | ready | read / read / operator · fast/low | **`address`** | `zcl.account.v1` | `z23 app account show t1...` | Show one principal by address |
| `app account whoami` | ready | read / read / public · fast/low | **`address`** | `zcl.account.v1` | `z23 app account whoami t1...` | Resolve one address to its role/caps |
| `app account add` | ready | mutate / app-write / **owner** · fast/low | **`address`**, `pubkey`, `role`, `key_kind` | `zcl.account.v1` | `z23 app account add --input='{"address":"t1...","pubkey":"..","role":"operator"}'` | Register or update a principal with a role |
| `app account role` | ready | mutate / app-write / **owner** · fast/low | **`address`**, `role` | `zcl.account.v1` | `z23 app account role --input='{"address":"t1...","role":"owner"}'` | Set a principal's role |
| `app account suspend` | ready | mutate / app-write / **owner** · fast/low | **`address`** | `zcl.account.v1` | `z23 app account suspend t1...` | Suspend a principal |
| `app account unsuspend` | ready | mutate / app-write / **owner** · fast/low | **`address`** | `zcl.account.v1` | `z23 app account unsuspend t1...` | Reactivate a suspended principal |

### `dev` — Native edit, proof, and publication loop

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `dev status` | ready | read / read / operator · instant/low | none | `zcl.dev_cycle.v1` | `z23 dev status` | Read the latest native cycle verdict |
| `dev begin` | compat 🔧 → `z23-dev dev begin` | mutate / dev-mutation / **owner** · fast/low | `root`, `mode` | `zcl.dev_begin.v1` | `z23-dev dev begin` | Start or reattach to the warm C23 development service — *warm watcher ownership requires the dev-only executor* |
| `dev drive` | compat 🔧 → `z23-dev dev drive` | read / read / operator · persistent/low | `after_epoch`, `timeout_ms`, `wait_for_edit` | `zcl.dev_drive.v1` | `z23-dev dev drive` | Wait for feedback and return one compact next action — *bounded warm-service driving requires the dev binary* |
| `dev ff` | ready | read / read / operator · instant/low | none | `zcl.dev_ff.v1` | `z23 dev ff` | Fail-fast ladder: compile, test, lint |
| `dev verify-change` | compat 🔧 → `make dev-bin, then z23-dev dev verify-change` | read / read / **owner** · background/high | none | `zcl.dev_verify_change.v1` | `z23-dev dev verify-change` | Compile affected code and run mapped focused proofs with compact output — *changed-scope verification requires the dev-only process executor* |

#### `dev.publication` — Inspect asynchronous proven-source publication

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `dev publication status` | ready | read / read / operator · fast/low | **`job_root`** | `zcl.dev_publication_status.v1` | `z23-dev dev publication status --input='{"job_root":"<64-lowercase-hex>"}'` | Show one durable proof-to-publication job |
| `dev publication advance` | compat 🔧 → `z23-dev dev publication status` | mutate / dev-mutation / **owner** · background/moderate | **`job_root`**, `datadir`, `workspace`, `action_id`, `details` | `zcl.dev_publication_advance.v1` | `z23-dev dev publication advance --input='{"job_root":"<64-lowercase-hex>"}'` | Advance one proven-source job to its next durable blocker — *publication scheduling receipts require a dev checkout* |
| `dev publication collect` | compat 🔧 → `z23-dev dev publication status` | mutate / dev-mutation / **owner** · foreground/moderate | **`job_root`** | `zcl.dev_publication_collect.v1` | `z23-dev dev publication collect --input='{"job_root":"<64-lowercase-hex>"}'` | Bind independent storage and source-reproduction evidence — *publication evidence collection requires the dev-only ZVCS receipt writer* |

#### `dev.publication.mirror` — Record optional non-authoritative mirror evidence

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `dev publication mirror record` | compat 🔧 → `z23-dev dev publication mirror record` | mutate / dev-mutation / **owner** · fast/low | **`job_root`**, `git_oid` | `zcl.dev_publication_mirror_record.v1` | `z23-dev dev publication mirror record --input='{"job_root":"<64-lowercase-hex>","git_oid":"<optional-40-or-64-lowercase-hex>"}'` | Record optional declared GitHub mirror evidence — *optional mirror receipts require a dev checkout* |

#### `dev.core` — Core boundary and proof lanes

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `dev core boundary` | ready | read / read / public · instant/tiny | none | `zcl.core_app_boundary.v1` | `z23 dev core boundary` | Show the enforced Core/App ownership law |
| `dev core proof` | planned | read / read / **owner** · background/high | `files` | `zcl.dev_core_proof.v1` | `z23 dev core proof` | Run mandatory Core parity proof lanes — *native proof job extraction is not complete* |

#### `dev.app` — Build capability-scoped C Apps

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `dev app list` | ready | read / read / operator · fast/low | none | `zcl.dev_app_index.v1` | `z23 dev app list` | List checkout App manifests |
| `dev app describe` | ready | read / read / operator · fast/low | **`app_id`** | `zcl.dev_app.v1` | `z23 dev app describe social` | Describe an App manifest and its proofs |
| `dev app plan` | ready | read / read / operator · instant/tiny | **`app_id`**, **`resource`** | `zcl.dev_app_plan.v1` | `z23 dev app plan social posts` | Plan one conventional App resource slice |
| `dev app scaffold` | planned | mutate / dev-mutation / **owner** · foreground/moderate | **`app_id`**, **`resource`** | `zcl.dev_app_scaffold.v1` | `z23 dev app scaffold social posts` | Materialize a conventional App resource slice — *native bounded file materializer is not implemented* |
| `dev app simulate` | ready | read / read / operator · fast/moderate | **`app_id`**, `scenario`, `seed` | `zcl.dev_app_sim.v1` | `z23 dev app simulate social --seed=0x534f4349414c0001` | Run deterministic App network scenarios |
| `dev app inspect` | planned | read / read / operator · fast/low | **`app_id`** | `zcl.dev_app_inspect.v1` | `z23 dev app inspect social` | Inspect a resident App generation — *public App ABI is not connected to resident generations yet* |
| `dev app publish` | planned | mutate / dev-mutation / **owner**, job, idempotency · foreground/high | **`app_id`**, `idempotency_key` | `zcl.dev_app_publish.v1` | `z23 dev app publish social --idempotency-key=<key>` | Atomically publish a proven App generation — *App ABI generation publication is not wired yet* |

#### `dev.change` — Classify and apply changes

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `dev change plan` | ready | read / read / operator · instant/tiny | `files` | `zcl.dev_plan.v1` | `z23 dev change plan --input='{"files":["apps/social/app.def"]}'` | Classify files and select the smallest proof |
| `dev change apply` (aliases: `dev.change.cycle`) | compat 🔧 → `z23-dev dev change cycle` | mutate / dev-mutation / **owner**, job · foreground/high | `files` | `zcl.dev_cycle.v1` | `z23 dev change apply --input='{"files":["apps/social/app.def"]}'` | Contained publication entrypoint: returns RUNTIME_PUBLICATION_CONTAINED — *change application requires the dev-only process/activation executor* |

#### `dev.loop` — Persistent save-to-verdict loop

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `dev loop ensure` (aliases: `dev.loop.watch`) | compat 🔧 → `z23-dev dev loop ensure --input='{"mode":"auto"}'` | mutate / dev-mutation / **owner** · fast/low | `root`, `mode` | `zcl.dev_loop_status.v1` | `z23 dev loop ensure --input='{"root":".","mode":"verify"}'` | Ensure one resident watcher; auto publishes only stateless islands — *watcher ownership requires the dev-only executor* |
| `dev loop status` (aliases: `dev.loop.heartbeat`) | compat 🔧 → `z23-dev dev loop heartbeat` | read / read / operator · instant/low | none | `zcl.dev_loop_status.v1` | `z23 dev loop status` | Read watcher identity, epoch, and latest verdict — *watcher state is available through the dev binary* |
| `dev loop wait` | compat 🔧 → `z23-dev dev loop wait` | read / read / operator · persistent/low | `after_epoch`, `timeout_ms` | `zcl.dev_cycle.v1` | `z23 dev loop wait --input='{"after_epoch":41}'` | Wait for one verdict after a cycle epoch — *bounded verdict waiting is available through the dev binary* |
| `dev loop events` | compat 🔧 → `z23-dev dev loop events --format=jsonl` | read / read / operator · persistent/stream | `after`, `heartbeat_ms` | `zcl.dev_loop_event.v1` | `z23-dev dev loop events --after=41 --format=jsonl` | Stream resumable source and cycle events — *resumable event subscription is available through the dev binary* |
| `dev loop stop` | compat 🔧 → `z23-dev dev loop stop` | mutate / dev-mutation / **owner** · fast/low | **`watcher_id`** | `zcl.dev_loop_status.v1` | `z23 dev loop stop <watcher-id>` | Stop one identified native watcher — *watcher shutdown requires the dev-only executor* |

#### `dev.test` — Focused proof selection

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `dev test plan` | ready | read / read / operator · instant/tiny | `files` | `zcl.dev_test_plan.v1` | `z23 dev test plan --input='{"files":[]}'` | Map changed files to mandatory proof groups |
| `dev test run` (aliases: `dev.test.focused`) | compat 🔧 → `z23-dev dev test focused` | read / read / **owner** · background/high | **`group`** | `zcl.dev_focused_test.v1` | `z23 dev test run hotswap_simnet` | Run one exact prebuilt focused test group — *focused tests require the dev-only process executor* |
| `dev test story` | compat 🔧 → `z23-dev dev test story` | read / read / **owner** · instant/tiny | **`owner`** | `zcl.vault_intent_decision_story.v1` | `z23-dev dev test story --input='{"owner":"transaction_intent"}'` | Run one exact owner-bound fail-fast behavior story — *behavior stories require the dev-only frozen fixture registry* |
| `dev test sim` | compat 🔧 → `z23-dev dev test sim` | read / read / **owner** · fast/moderate | `app_id` | `zcl.dev_sim.v1` | `z23 dev test sim` | Run the generic hot-swap network proof — *the simulation runner requires the dev-only process executor* |
| `dev test replay` | planned | read / read / **owner** · foreground/moderate | **`seed`**, `scenario` | `zcl.dev_test_replay.v1` | `z23 dev test replay 1234` | Replay one deterministic failure seed — *generic seed replay registry is not implemented* |

#### `dev.generation` — Generation provenance

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `dev generation current` | compat 🔧 → `z23-dev dev generation current` | read / read / operator · instant/low | none | `zcl.dev_generation_status.v1` | `z23 dev generation current` | Show current and last-good generations — *generation state is available through the dev binary* |
| `dev generation history` | compat 🔧 → `z23-dev dev generation history` | read / read / operator · fast/low | `cursor`, `max_items` | `zcl.dev_generation_history.v1` | `z23 dev generation history` | Page accepted and rejected generations — *generation history is available through the dev binary* |
| `dev generation activate` | compat 🔧 → `make dev-bin, then z23-dev dev generation activate` | mutate / dev-mutation / **owner**, job, plan-commit · foreground/high | `idempotency_key`, `expires_in_seconds`, `intent_id`, `effect_digest`, `candidate_sha256`, `source_id_sha256`, `source_mutation_sha256`, `source_cas_sha3`, `expected_current_generation`, `expires_unix`, `confirm` | `zcl.dev_generation_activate.v1` | `z23-dev dev generation activate --input='{"idempotency_key":"upgrade-001"}'` | Stage, preflight, and activate one exact dev generation — *generation activation requires the dev-only process executor* |
| `dev generation rollback` | planned | destructive / dev-mutation / **owner**, job, plan-commit · foreground/high | `intent_id`, `effect_digest` | `zcl.dev_generation_rollback.v1` | `z23 dev generation rollback --input='<intent>'` | Restore verified last-good in the dev lane — *native activation engine is not implemented* |
| `dev generation compact` | planned | destructive / dev-mutation / **owner**, job, plan-commit · foreground/moderate | `intent_id`, `effect_digest` | `zcl.dev_generation_compact.v1` | `z23 dev generation compact --input='<intent>'` | Compact unleased old generations — *native lease-aware compaction is not implemented* |

#### `dev.diagnose` — Failure capsule lookup

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `dev diagnose latest` | compat 🔧 → `z23-dev dev diagnose latest` | read / read / operator · instant/low | none | `zcl.dev_failure_latest_result.v1` | `z23 dev diagnose latest` | Read the latest compiler failure — *failure capsules are available through the dev binary* |
| `dev diagnose show` | compat 🔧 → `z23-dev dev diagnose show <failure-id>` | read / read / operator · fast/low | **`failure_id`** | `zcl.dev_failure_show.v1` | `z23-dev dev diagnose show <failure-id>` | Show one compiler failure record — *durable failure artifacts are available through the dev binary* |

#### `dev.vcs` — One-command source+binary revert

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `dev vcs revert` | compat 🔧 → `z23-dev dev vcs revert <to> [--relink-generation]` | mutate / dev-mutation / **owner** · foreground/high | **`to`**, `relink_generation` | `zcl.dev_vcs_revert.v1` | `z23 dev vcs revert --input='{"to":"<64-hex commit id>","relink_generation":true}'` | Restore the checkout to a prior ZVCS commit; generation relinking is currently contained — *one-command source+binary revert requires a dev build* |

#### `dev.vcs.seal` — Owner-run ZVCS unseal-token ritual

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `dev vcs seal grant` | compat 🔧 → `z23-dev dev vcs seal grant --input='{"reason":"...","confirm":true}'` | mutate / dev-mutation / **owner** · fast/low | **`reason`**, `confirm` | `zcl.dev_vcs_seal_grant.v1` | `z23 dev vcs seal grant --input='{"reason":"post-baseline app/jobs edits reviewed","confirm":true}'` | Mint a one-shot ZVCS unseal token authorizing the CURRENT worktree's sealed content for the next green-cycle anchor — *granting a ZVCS unseal token requires a dev build* |

#### `dev.hotswap` — Tier-1 command-leaf hot-swap

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `dev hotswap apply` | compat 🔧 → `z23-dev dev hotswap apply --input='{"so_path":"...","probe_leaf":"..."}'` | mutate / dev-mutation / **owner** · fast/moderate | **`so_path`**, `probe_leaf` | `zcl.dev_hotswap.v1` | `z23-dev dev hotswap apply --input='{"so_path":"/tmp/gen.so","probe_leaf":"core.status"}'` | Live module hot-swap: forwards to the resident dev node; verify-only unless -hotswap-activate + ZCL_HOTSWAP_ACTIVATE=1 on the dev datadir (canonical refused) — *in-process hot-swap requires a dev build* |
| `dev hotswap probe` | compat 🔧 → `z23-dev dev hotswap probe --input='{"so_path":"...","probe_leaf":"..."}'` | read / read / **owner** · fast/low | **`so_path`**, `probe_leaf` | `zcl.dev_hotswap.v1` | `z23-dev dev hotswap probe --input='{"so_path":"/tmp/gen.so","probe_leaf":"core.status"}'` | Verify-only in-process: dlopen + ABI-validate + self_test of a module .so; never commits — *resident hot-swap probing requires a dev build* |

#### `dev.test.background` — Background proof freshness

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `dev test background status` | planned | read / read / operator · instant/low | none | `zcl.dev_background_quality.v1` | `z23 dev test background status` | Read lint, sanitizer, replay, and reproducibility freshness — *native background-quality projection is not implemented* |

### `ops` — Node diagnostics

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `ops health` | ready | read / read / public · fast/low | none | `zcl.health.v1` | `z23 ops health` | Health rollup |
| `ops diagnose` | ready | read / read / operator · fast/moderate | none | `zcl.ops_diagnose.v1` | `z23 ops diagnose` | Operator diagnosis |
| `ops lanes` | ready | read / read / operator · fast/low | none | `zcl.ops_lanes.v1` | `z23 ops lanes` | Lanes |
| `ops logs` | ready | read / read / operator · fast/low | **`pattern`**, `since_secs`, `max_lines`, `level` | `zcl.ops_logs.v1` | `z23 ops logs --pattern='blocker'` | Log regex tail |
| `ops timeline` | ready | read / read / operator · fast/low | none | `zcl.ops_timeline.v1` | `z23 ops timeline` | Events |
| `ops metrics` | ready | read / read / operator · fast/low | none | `zcl.ops_metrics.v1` | `z23 ops metrics` | Metrics |
| `ops state` | ready | read / read / operator · fast/low | **`subsystem`**, `key`, `explain` | `zcl.ops_state.v1` | `z23 ops state --subsystem=reducer_frontier` | Subsystem state |
| `ops statecatalog` | ready | read / read / operator · fast/low | `subsystem`, `limit`, `page` | `zcl.ops_statecatalog.v1` | `z23 ops statecatalog` | State subsystem catalog |
| `ops selftest` | ready | read / read / operator · fast/low | none | `zcl.ops_selftest.v1` | `z23 ops selftest` | Self-test |

#### `ops.jobs` — Job lifecycle

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `ops jobs list` | planned | read / read / operator · fast/low | none | `zcl.jobs.v1` | `z23 ops jobs list` | List asynchronous jobs — *the native job registry is a Wave 2.2 deliverable* |

#### `ops.debug` — Diagnostics

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `ops debug explain` (aliases: `explain`, `ops.explain`) | ready | read / read / operator · fast/low | **`topic`** | `zcl.ops_explain.v1` | `z23 explain sync` | Explain a subsystem in plain prose |
| `ops debug meaning` (aliases: `meaning`, `ops.meaning`) | ready | read / read / operator · fast/low | `subsystem`, `name`, `question` | `zcl.ops_meaning.v1` | `z23 meaning --name=pre_handshake_disconnects` | What a telemetry field means, and which report answers a question |
| `ops debug profile` (aliases: `profile`, `ops.profile`) | ready | read / read / operator · foreground/moderate | **`seconds`**, `top_n` | `zcl.ops_profile.v1` | `z23 profile 3` | Sample thread CPU + stage rates |
| `ops debug producer` (aliases: `ops.producer.status`) | ready | read / read / operator · fast/low | **`datadir`** | `zcl.ops_producer_status.v1` | `z23 ops producer status -datadir=/home/you/.zclassic-c23-mint` | Read a producer datadir's fold progress + receipt |
| `ops debug rom` (aliases: `ops.rom`) | ready | read / read / operator · fast/low | none | `zcl.rom_compile.v1` | `z23 ops rom` | ROM compilation fold progress |
| `ops debug backtrace` | ready | read / read / operator · fast/low | none | `zcl.ops_debug_backtrace.v1` | `z23 ops debug backtrace` | Dump every thread's backtrace |
| `ops debug bundle` | ready | read / read / operator · fast/low | none | `zcl.ops_debug_bundle.v1` | `z23 ops debug bundle` | Write one-shot debug bundle JSON |

#### `ops.debug.dash` — Operator rollup dashboards

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `ops debug dash kpi` (aliases: `kpi`, `ops.kpi`) | ready | read / read / operator · fast/moderate | none | `zcl.ops_kpi.v1` | `z23 kpi` | One-shot subsystem KPI dashboard |
| `ops debug dash snapshot` (aliases: `ops.snapshot`) | ready | read / read / operator · fast/low | none | `zcl.operator_snapshot.v3` | `z23 ops snapshot` | Operator snapshot payload |
| `ops debug dash summary` (aliases: `ops.summary`) | ready | read / read / operator · fast/low | none | `zcl.operator_summary.v1` | `z23 ops summary` | Fail-closed operator summary |
| `ops debug dash milestone` (aliases: `milestone`, `ops.milestone`) | ready | read / read / operator · fast/low | none | `zcl.milestone.v1` | `z23 milestone` | Version milestone progress |
| `ops debug dash mirror` (aliases: `ops.mirror`) | ready | read / read / operator · fast/low | none | `zcl.mirror_status.v2` | `z23 ops mirror` | zclassicd mirror lockstep |
| `ops debug dash selfheal` (aliases: `selfheal`, `ops.selfheal`) | ready | read / read / operator · fast/low | none | `zcl.self_heal_stats.v1` | `z23 ops selfheal` | Self-heal recovery counters |

#### `ops.debug.rom_seed` — ROM-seed policy

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `ops debug rom_seed status` | ready | read / read / public · fast/low | none | `zcl.rom_seed_status.v1` | `z23 ops debug rom_seed status` | ROM-seed policy + live counters |
| `ops debug rom_seed enable` | ready | mutate / app-write / **owner** · fast/low | none | `zcl.rom_seed_status.v1` | `z23 ops debug rom_seed enable` | Enable ROM-seed serving |
| `ops debug rom_seed disable` | ready | mutate / app-write / **owner** · fast/low | none | `zcl.rom_seed_status.v1` | `z23 ops debug rom_seed disable` | Disable ROM-seed serving |
| `ops debug rom_seed artifacts` | ready | read / read / public · fast/low | none | `zcl.rom_seed_artifacts.v1` | `z23 ops debug rom_seed artifacts` | List served ROM artifacts + seed stats |
| `ops debug rom_seed publish` | ready | mutate / app-write / **owner** · fast/low | none | `zcl.rom_seed_publish.v1` | `z23 ops debug rom_seed publish` | Publish this node's starter artifacts to the swarm |

#### `ops.debug.rom_fetch` — ROM-fetch engine

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `ops debug rom_fetch status` | ready | read / read / public · fast/low | none | `zcl.rom_fetch_status.v1` | `z23 ops debug rom_fetch status` | ROM-fetch engine status |
| `ops debug rom_fetch bundle` | ready | mutate / app-write / **owner** · background/moderate | `peer`, `port`, `root`, `whole_sha3`, `size`, `filename`, `out_dir` | `zcl.rom_fetch_bundle.result.v1` | `z23 ops debug rom_fetch bundle --input='{"peer":"203.0.113.7","root":"<64hex>","whole_sha3":"<64hex>","size":"538507264"}'` | Fetch + verify a ROM artifact from a peer |

#### `ops.mesh` — Mesh

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `ops mesh join` | ready | mutate / core-recovery / operator · foreground/low | **`endpoint`**, `address` | `zcl.ops_mesh_join_status.v1` | `z23 ops mesh join --endpoint=<host:port>` | Join a peer from a verified session invite |
| `ops mesh join_status` | ready | read / read / operator · fast/low | **`endpoint`**, `address` | `zcl.ops_mesh_join_status.v1` | `z23 ops mesh join_status --endpoint=<host:port>` | Report whether a mesh join has peered |

#### `ops.postmortem` — Postmortems

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `ops postmortem list` | ready | read / read / operator · fast/low | none | `zcl.postmortem_list.v1` | `z23 ops postmortem list` | List captured postmortems |
| `ops postmortem replay` | planned | read / read / operator · foreground/moderate | **`id`** | `zcl.postmortem_replay.v1` | `z23 ops postmortem replay <id>` | Replay one captured postmortem — *postmortem replay argument mapping is a Wave 2.2 deliverable* |

#### `ops.config` — Runtime config

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `ops config show` | planned | read / read / operator · fast/low | none | `zcl.ops_config.v1` | `z23 ops config show` | Show effective runtime configuration — *an effective-config reader is a Wave 2.2 deliverable* |
| `ops config reload` | planned | mutate / core-recovery / operator · fast/low | none | `zcl.ops_config_reload.v1` | `z23 ops config reload` | Reload runtime configuration — *config-reload binding is a Wave 2.2 deliverable* |

#### `ops.recovery` — Recovery ops

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `ops recovery status` | ready | read / read / operator · fast/low | none | `zcl.recovery_status.v1` | `z23 ops recovery status` | Refold and recovery progress |
| `ops recovery rebuild` | planned | destructive / core-recovery / **owner**, job, plan-commit · background/high | `depth` | `zcl.recovery_rebuild.v1` | `z23 ops recovery rebuild --depth=100` | Rebuild recent chain state — *recovery rebuild plan/commit handshake is a Wave 2.2 deliverable* |

#### `ops.telemetry` — Canonical typed telemetry tree

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `ops telemetry summary` | ready | read / read / operator · fast/low | none | `zcl.telemetry.summary.v1` | `z23 ops telemetry summary` | Whole-node telemetry rollup — start here |
| `ops telemetry health` | ready | read / read / operator · fast/low | none | `zcl.telemetry.health.v1` | `z23 ops telemetry health` | Health state per domain |
| `ops telemetry watch` | ready | read / read / operator, stream · fast/stream | **`since`**, `since_epoch`, `limit` | `zcl.telemetry.change.v1` | `z23 ops telemetry watch --since=41` | Resumable telemetry change feed |

#### `ops.telemetry.alerts` — Fired telemetry rules

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `ops telemetry alerts active` | ready | read / read / operator · fast/low | none | `zcl.telemetry.alerts.v1` | `z23 ops telemetry alerts active` | Every telemetry rule that is failing right now |
| `ops telemetry alerts history` | planned | read / read / operator · fast/low | `limit` | `zcl.telemetry.alerts.v1` | `z23 ops telemetry alerts history --limit=20` | Previously fired telemetry rules — *the telemetry alert feed is not built yet* |

#### `ops.telemetry.runtime` — Supervisor tree, services and host resources

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `ops telemetry runtime services` | ready | read / read / operator · fast/low | none | `zcl.telemetry.runtime.services.v1` | `z23 ops telemetry runtime services` | Registered services and their liveness |
| `ops telemetry runtime threads` | ready | read / read / operator · fast/low | none | `zcl.telemetry.runtime.threads.v1` | `z23 ops telemetry runtime threads` | Threads and their supervision state |
| `ops telemetry runtime resources` | ready | read / read / operator · fast/low | none | `zcl.telemetry.runtime.resources.v1` | `z23 ops telemetry runtime resources` | Host resources this process holds |

#### `ops.telemetry.sync` — Reducer frontier, stages and catch-up posture

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `ops telemetry sync summary` | ready | read / read / operator · fast/low | none | `zcl.telemetry.sync.summary.v1` | `z23 ops telemetry sync summary` | Sync posture and the current bottleneck |
| `ops telemetry sync stages` | ready | read / read / operator · fast/low | none | `zcl.telemetry.sync.stages.v1` | `z23 ops telemetry sync stages` | Every reducer stage cursor |
| `ops telemetry sync stage` | ready | read / read / operator · fast/low | **`stage`** | `zcl.telemetry.sync.stage.v1` | `z23 ops telemetry sync stage --stage=body_persist` | One reducer stage in full detail |

#### `ops.telemetry.network` — Peers, transport, onion and address pool

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `ops telemetry network summary` | ready | read / read / operator · fast/low | none | `zcl.telemetry.network.v1` | `z23 ops telemetry network summary` | Connectivity posture |
| `ops telemetry network peers` | ready | read / read / operator · fast/low | none | `zcl.telemetry.network.v1` | `z23 ops telemetry network peers` | Peer aggregate |
| `ops telemetry network tor` | ready | read / read / operator · fast/low | none | `zcl.telemetry.network.v1` | `z23 ops telemetry network tor` | Onion service state |
| `ops telemetry network transport` | ready | read / read / operator · fast/low | none | `zcl.telemetry.network.v1` | `z23 ops telemetry network transport` | Wire transport posture |

#### `ops.telemetry.storage` — Databases, indexes, cache and disk

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `ops telemetry storage summary` | ready | read / read / operator · fast/low | none | `zcl.telemetry.storage.summary.v1` | `z23 ops telemetry storage summary` | Storage posture |
| `ops telemetry storage database` | ready | read / read / operator · fast/low | none | `zcl.telemetry.storage.database.v1` | `z23 ops telemetry storage database` | Database handles and block-index integrity |
| `ops telemetry storage disk` | ready | read / read / operator · fast/low | none | `zcl.telemetry.storage.disk.v1` | `z23 ops telemetry storage disk` | Disk headroom |
| `ops telemetry storage cache` | planned | read / read / operator · fast/low | none | `zcl.telemetry.storage.cache.v1` | `z23 ops telemetry storage cache` | Cache occupancy and hit rates — *no storage cache publishes occupancy, hit ratio or eviction counts: coins_ram keeps no hit/miss counters and SQLite's page-cache counters need sqlite3_db_status() on a live handle, which would block the reply behind the reducer's write transaction* |

#### `ops.telemetry.wallet` — Wallet projection and key-handling posture

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `ops telemetry wallet summary` | ready | read / read / operator · fast/low | none | `zcl.telemetry.wallet.summary.v1` | `z23 ops telemetry wallet summary` | Wallet projection posture |
| `ops telemetry wallet security` | ready | read / read / operator · fast/low | none | `zcl.telemetry.wallet.security.v1` | `z23 ops telemetry wallet security` | Key-handling safety posture |

#### `ops.telemetry.agents` — Agent sessions, grants and activity

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `ops telemetry agents sessions` | ready | read / read / operator · foreground/low | none | `zcl.telemetry.agents.sessions.v1` | `z23 ops telemetry agents sessions` | Agent session population |
| `ops telemetry agents grants` | ready | read / read / operator · foreground/low | none | `zcl.telemetry.agents.grants.v1` | `z23 ops telemetry agents grants` | What the usable grants permit |
| `ops telemetry agents activity` | ready | read / read / operator · foreground/low | none | `zcl.telemetry.agents.activity.v1` | `z23 ops telemetry agents activity` | Recorded agent activity |

#### `ops.telemetry.zcode` — Package store, swarm and installs

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `ops telemetry zcode summary` | ready | read / read / operator · fast/low | none | `zcl.telemetry.zcode.summary.v1` | `z23 ops telemetry zcode summary` | ZCODE store posture |
| `ops telemetry zcode swarm` | planned | read / read / operator · fast/low | none | `zcl.telemetry.zcode.swarm.v1` | `z23 ops telemetry zcode swarm` | Swarm participation — *peer count, advertisements and verified bytes live only inside vcs_swarm_engine and every accessor takes its mutex blocking, which a telemetry collector must not do; needs a trylock or lock-free stats accessor on the engine first. Meanwhile whether the engine is running at all is in ops telemetry zcode summary* |
| `ops telemetry zcode installs` | planned | read / read / operator · fast/low | none | `zcl.telemetry.zcode.installs.v1` | `z23 ops telemetry zcode installs` | Install generations — *install state is on-disk only: package_lifecycle_active answers for one NAME and there is no enumeration and no in-process index, so listing installs means a directory walk of datadir/zcode/installed plus a generation-log read each, which a telemetry collector must not do; needs an installed-package index first* |

#### `ops.telemetry.metaverse` — Property catalog, market and confined services

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `ops telemetry metaverse properties` | ready | read / read / operator · instant/tiny | none | `zcl.telemetry.metaverse.properties.v1` | `z23 ops telemetry metaverse properties` | Which kinds of digital property this build can project, and which it cannot |
| `ops telemetry metaverse market` | planned | read / read / operator · fast/low | none | `zcl.telemetry.metaverse.market.v1` | `z23 ops telemetry metaverse market` | Property market activity — *no property market subsystem exists in this build* |
| `ops telemetry metaverse services` | planned | read / read / operator · fast/low | none | `zcl.telemetry.metaverse.services.v1` | `z23 ops telemetry metaverse services` | Confined broker services — *the confined agent broker keeps its state in an operator-named directory, not in this process; use `metaverse agent status --dir=DIR`* |

### `discover` — Search and describe the command registry

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `discover help` (aliases: `help`, `dev.help`) | ready | read / read / public · instant/tiny | **`path`** | `zcl.discovery_document.v1` | `z23 discover help dev.app` | Show one branch or leaf without loading the whole tree |
| `discover search` (aliases: `search`, `dev.search`, `dev.diagnose.search`) | ready | read / read / public · instant/tiny | **`query`** | `zcl.command_search.v1` | `z23 discover search 'ABI mismatch'` | Rank at most five commands by local deterministic intent search |
| `discover describe` | ready | read / read / public · instant/tiny | **`path`** | `zcl.command_spec.v1` | `z23 discover describe dev.app.simulate` | Describe one leaf's schemas, safety, authority, and availability |
| `discover schema` | ready | read / read / public · instant/tiny | **`path`**, `side` | `zcl.command_schema.v1` | `z23 discover schema dev.app.simulate --side=input` | Return the compact input or output schema contract for one leaf |

### `code` — Hierarchical source-code navigator

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `code guide` | ready | read / read / public · instant/tiny | none | `zcl.code_guide.v1` | `z23 code guide` | How to edit and prove a change in this checkout |
| `code group` | ready | read / read / public · foreground/tiny | **`group`** | `zcl.code_group.v1` | `z23 code group app/services` | Top source groups, or one group's subgroups and files |
| `code map` | ready | read / read / public · foreground/tiny | none | `zcl.code_map.v1` | `z23 code map` | Map the tree: root groups and app shapes with file counts |
| `code tests` | ready | read / read / public · fast/tiny | **`path`** | `zcl.code_tests.v1` | `z23 code tests lib/net/src/download.c` | Which focused test group a change to one file routes to |
| `code room` | ready | read / read / public · fast/tiny | **`path`** | `zcl.code_room.v1` | `z23 code room app/jobs/src/utxo_apply_stage.c` | Compose shape, purpose, neighbors and test route for one path |
| `code file` | ready | read / read / public · fast/tiny | **`path`** | `zcl.code_file.v1` | `z23 code file lib/vcs/src/vcs_index.c` | One file's symbol table and in-tree include dependencies |
| `code sym` | ready | read / read / public · fast/tiny | **`name`** | `zcl.code_symbol.v1` | `z23 code sym codeindex_open` | One symbol's card: kind, signature, def/decl, doc, guard |
| `code capsule` | ready | read / read / public · fast/tiny | **`name`** | `zcl.code_capsule.v1` | `z23 code capsule sovereignty_guard_allow` | Compose one symbol's identity, call graph, includes and commands |
| `code change-plan` | ready | read / read / public · fast/tiny | **`name`**, `symbol`, `intent`, `patch` | `zcl.code_change_plan.v1` | `z23 code change-plan codeindex_open` | Turn a symbol, intent, or patch into an edit and proof plan |
| `code refs` | ready | read / read / public · fast/tiny | **`name`**, `limit` | `zcl.code_refs.v1` | `z23 code refs zcl_malloc` | List call sites and references to one symbol |
| `code impact` | ready | read / read / public · fast/tiny | **`path`** | `zcl.code_impact.v1` | `z23 code impact lib/util/include/util/safe_alloc.h` | The reverse-dependency blast radius of one changed file |
| `code find` | ready | read / read / public · fast/tiny | **`text`**, `limit` | `zcl.code_find.v1` | `z23 code find hotswap` | Rank N symbols by name, with a one-line context per hit |

#### `code.provenance` — Attribute output back to the code that produced it

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `code provenance merkle` | ready | read / read / public · fast/tiny | **`path`** | `zcl.code_merkle.v1` | `z23 code provenance merkle lib/net` | Give the SHA3 Merkle root of the tree or a subtree |
| `code provenance facts` | ready | read / read / public · background/moderate | **`key`**, `store` | `zcl.code_facts.v1` | `z23 code provenance facts coins_applied_height` | Census the durable named slots and name the ones with several writers |
| `code provenance emitter` | ready | read / read / public · foreground/moderate | **`text`** | `zcl.code_emitter.v1` | `z23 code provenance emitter 'address_index.below_snapshot_seed'` | Resolve emitted text to its emitting code |

### `vault` — What this node owns, and what may act on it

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `vault list` | ready | read / read / operator · fast/low | **`class`** | `zcl.vault_list.v1` | `z23 vault list` | One row per asset class: everything this node owns |
| `vault show` | ready | read / read / operator · fast/low | **`class`**, `limit` | `zcl.vault_show.v1` | `z23 vault show transparent` | Itemize the holdings inside one asset class |
| `vault encumbered` | ready | read / read / operator · fast/low | **`class`**, `limit` | `zcl.vault_encumbered.v1` | `z23 vault encumbered` | What is owned but not free to move, and what would release it |
| `vault routes` | ready | read / read / public · instant/tiny | **`class`** | `zcl.vault_routes.v1` | `z23 vault routes` | Which existing path owns the spend for each asset class |
| `vault send` | ready | mutate / wallet / **owner**, plan-commit · foreground/moderate | `wallet_scope`, `address`, `amount`, `idempotency_key`, `confirm` | `zcl.wallet_send.v1` | `z23 vault send --input='{"address":"t1..","amount":1.5}'` | Spend transparent ZCL by dispatching to the wallet's own send |
| `vault send-shielded` | ready | mutate / wallet / **owner**, plan-commit · foreground/high | `wallet_scope`, `from`, `to`, `amount`, `memo`, `memo_hex`, `idempotency_key`, `confirm` | `zcl.shielded_send.v1` | `z23 vault send-shielded --input='{"wallet_scope":"dev","from":"zs1..","to":"zs1..","amount":"1.00000000"}'` | Spend shielded ZCL by dispatching to the wallet's own shielded send |
| `vault send-token` | ready | mutate / wallet / **owner**, plan-commit · foreground/moderate | **`token_id`**, `to`, `units`, `confirm` | `zcl.app_token_txresult.v1` | `z23 vault send-token --input='{"token_id":"<64-hex>","to":"t1...","units":25}'` | Send ZSLP units through the token command that owns the transaction |

#### `vault.intent` — Exact, expiring, durably idempotent transaction intents

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `vault intent issue` | ready | mutate / wallet / **owner** · foreground/moderate | `asset`, **`amount`** | `zcl.vault_intent_issue.v1` | `z23 vault intent issue --input='{"asset":"ZCL","amount":"0.01"}'` | Create a fresh transparent ZCL payment request |
| `vault intent plan` | ready | mutate / wallet / **owner** · background/high | **`wallet_scope`**, `route`, `from`, **`effects`**, **`idempotency_key`** | `zcl.vault_intent_plan.v1` | `printf '%s' '{"wallet_scope":"dev","route":"transparent","idempotency_key":"payment-001","effects":[{"asset":"ZCL","to":"t1...","amount":"0.01"}]}' \| z23 vault intent plan --input=-` | Persist an exact encrypted transaction plan |
| `vault intent fanout-plan` | ready | mutate / wallet / **owner** · background/high | **`wallet_scope`**, **`recipient_value_zat`**, **`maximum_fee_zat`**, **`concurrency`**, **`idempotency_key`** | `zcl.vault_intent_fanout_plan.v1` | `z23 vault intent fanout-plan --input='{"wallet_scope":"dev","recipient_value_zat":1000,"maximum_fee_zat":10000,"concurrency":10,"idempotency_key":"parallel-lab-001"}'` | Prepare private self-custody outputs for parallel transactions |
| `vault intent commit` | ready | mutate / wallet / **owner**, idempotency · foreground/high | **`wallet_scope`**, **`plan_id`**, **`confirm`** | `zcl.vault_intent_commit.v1` | `z23 vault intent commit --input='{"wallet_scope":"dev","plan_id":"<64hex>","confirm":true}'` | Commit one exact durable plan without double-paying |
| `vault intent submit` | ready | mutate / wallet / **owner**, idempotency · instant/low | **`wallet_scope`**, **`plan_id`**, **`confirm`** | `zcl.vault_intent_submit.v1` | `z23 vault intent submit --input='{"wallet_scope":"dev","plan_id":"<64hex>","confirm":true}'` | Queue an exact durable plan and return immediately |
| `vault intent cancel` | ready | mutate / wallet / **owner**, idempotency · instant/low | **`wallet_scope`**, **`plan_id`**, **`confirm`** | `zcl.vault_intent_cancel.v1` | `z23 vault intent cancel --input='{"wallet_scope":"dev","plan_id":"<64hex>","confirm":true}'` | Cancel an unclaimed durable transaction plan |
| `vault intent status` | ready | read / read / operator · fast/low | **`plan_id`** | `zcl.vault_intent_status.v1` | `z23 vault intent status --input='{"plan_id":"<64hex>"}'` | Read one transaction intent's chain-aware state |
| `vault intent list` | ready | read / read / operator · fast/low | none | `zcl.vault_intent_list.v1` | `z23 vault intent list` | List the newest durable transaction intents |

#### `vault.session` — Scoped, revocable spend-authority grants for agents

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `vault session create` | ready | mutate / wallet / **owner**, plan-commit · foreground/moderate | `account`, **`wallet_scope`**, `max_per_tx`, `max_per_window`, `reserve_floor`, `window_seconds`, `allowlist`, `expires_in`, `confirm` | `zcl.vault_session_create.v1` | `z23 vault session create --input='{"account":"t1..","wallet_scope":"dev","max_per_tx":"0.02","max_per_window":"0.02","reserve_floor":"0.08","window_seconds":"86400"}'` | Mint a scoped agent spend session; returns the token once |
| `vault session list` | ready | read / read / operator · fast/low | `account` | `zcl.vault_session_list.v1` | `z23 vault session list --input='{"account":"t1.."}'` | List agent spend sessions; the token is always redacted |
| `vault session revoke` | ready | mutate / wallet / **owner**, plan-commit · foreground/moderate | `session_id`, `confirm` | `zcl.vault_session_revoke.v1` | `z23 vault session revoke --input='{"session_id":"<32hex>","confirm":true}'` | Revoke an agent spend session by its full token |

#### `vault.swap` — Release funds locked in an atomic-swap contract

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `vault swap redeem` | ready | mutate / wallet / **owner**, plan-commit · foreground/moderate | `swap_id`, `secret`, `funding_txid`, `vout`, `confirm` | `zcl.vault_swap_settle.v1` | `z23 vault swap redeem --input='{"swap_id":"..","secret":"<64hex>"}'` | Claim a funded swap HTLC by dispatching the node's swap_redeem |
| `vault swap refund` | ready | mutate / wallet / **owner**, plan-commit · foreground/moderate | `swap_id`, `funding_txid`, `vout`, `confirm` | `zcl.vault_swap_settle.v1` | `z23 vault swap refund --input='{"swap_id":".."}'` | Reclaim an expired swap HTLC by dispatching the node's swap_refund |

### `zcode` — Create, verify and preserve public C23 work together

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `zcode guide` | ready | read / read / public · instant/tiny | none | `zcl.zcode_guide.v1` | `z23 zcode guide` | Tell Z23 what you want C23 to do |

#### `zcode.project` — C23 projects

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `zcode project inspect` | ready | read / read / operator · fast/moderate | **`workspace`**, `name`, `semver`, `license` | `zcl.zcode_project_inspect.v1` | `z23-dev zcode project inspect --input='{"workspace":"."}'` | Inspect one C23 project |
| `zcode project init plan` | ready | read / read / operator · fast/moderate | **`workspace`**, `name`, `semver`, `license` | `zcl.zcode_project_init_plan.v1` | `z23-dev zcode project init plan --input='{"workspace":"."}'` | Plan C23 project initialization |
| `zcode project init commit` | ready | mutate / app-write / operator, plan-commit · fast/moderate | **`workspace`**, `name`, `semver`, `license`, **`plan_id`**, **`confirm`** | `zcl.zcode_project_init_commit.v1` | `z23-dev zcode project init commit --input='{"workspace":".","plan_id":"<plan from init plan>","confirm":true}'` | Initialize one C23 project |
| `zcode project status` | ready | read / read / operator · fast/moderate | **`workspace`**, `name`, `semver`, `license` | `zcl.zcode_project_status.v1` | `z23-dev zcode project status --input='{"workspace":"."}'` | Show C23 project readiness |

#### `zcode.work` — Proven C23 work

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `zcode work context` | ready | read / read / public · instant/tiny | none | `zcl.zcode_work_context.v1` | `z23 zcode work context` | Show goal-context selection readiness |
| `zcode work preflight` | ready | read / read / operator · fast/low | `workspace`, `work`, `datadir` | `zcl.zcode_work_preflight.v1` | `z23 zcode work preflight --input='{"workspace":".","work":"latest"}'` | Check Codex adapter readiness before a model request |
| `zcode work start` | ready | mutate / app-write / operator · foreground/moderate | **`workspace`**, **`goal`**, `profile`, `context_symbol`, `max_cpu_seconds`, `datadir`, `details` | `zcl.zcode_work_start.v1` | `z23-dev zcode work start --input='{"workspace":".","goal":"Make the parser reject overflowing lengths","profile":"standard"}'` | Start reuse-first C23 work |
| `zcode work toolchain` | ready | read / read / operator · foreground/moderate | none | `zcl.zcode_toolchain_show.v1` | `z23 zcode work toolchain` | Show this node's C23 compile toolchain capsule |
| `zcode work status` | ready | read / read / operator · fast/low | `workspace`, `work`, `datadir`, `details` | `zcl.zcode_work_status.v1` | `z23-dev zcode work status --input='{"work":"latest"}'` | Show one human-first work status |
| `zcode work show` | ready | read / read / operator · fast/low | `workspace`, `work`, `datadir`, `details` | `zcl.zcode_work_status.v1` | `z23-dev zcode work show --input='{"work":"latest"}'` | Show one human-first work result |
| `zcode work run` | ready | mutate / app-write / operator · foreground/moderate | `workspace`, `work`, `adapter`, `datadir`, `details` | `zcl.zcode_work_run.v1` | `z23-dev zcode work run --input='{"work":"latest","adapter":"manual"}'` | Run one contained adapter handoff |
| `zcode work accept` | ready | mutate / app-write / operator · foreground/moderate | `workspace`, `work`, `datadir`, `confirmation_identity`, `details` | `zcl.zcode_work_accept.v1` | `z23-dev zcode work accept --input='{"work":"latest"}'` | Accept one exact proven candidate |
| `zcode work review` | ready | mutate / app-write / operator · foreground/moderate | `workspace`, `work`, `adapter`, **`verdict`**, **`findings`** | `zcl.zcode_work_review.v1` | `z23-dev zcode work review --input='{"work":"latest","adapter":"manual","verdict":"approve","findings":"No blocking findings."}'` | Review one exact candidate |

#### `zcode.passport` — Signed C23 module Passports

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `zcode passport status` | ready | read / read / public · instant/tiny | none | `zcl.zcode_passport_status.v1` | `z23 zcode passport status` | Show signed module Passport readiness |
| `zcode passport plan` | ready | read / read / public · instant/tiny | **`stable_api_root`**, **`recipe_root`**, **`toolchain_root`**, **`tests_root`**, **`license_root`**, **`semantic_fingerprint_root`**, **`workspace_lineage_root`**, **`source_assignment_root`**, **`quality_profiles_root`**, **`signer_pubkey`**, `workspace`, `publication_job_root` | `zcl.zcode_passport_plan.v1` | `z23 zcode passport plan --input='<exact evidence roots and signer_pubkey>'` | Plan an offline-signed C23 module Passport |
| `zcode passport commit` | ready | read / read / public · instant/tiny | **`stable_api_root`**, **`recipe_root`**, **`toolchain_root`**, **`tests_root`**, **`license_root`**, **`semantic_fingerprint_root`**, **`workspace_lineage_root`**, **`source_assignment_root`**, **`quality_profiles_root`**, **`signer_pubkey`**, **`signature`**, `workspace`, `publication_job_root` | `zcl.zcode_passport_commit.v1` | `z23 zcode passport commit --input='<same roots, signer_pubkey, external signature>'` | Materialize an externally signed C23 module Passport |
| `zcode passport verify` | ready | read / read / public · instant/tiny | **`passport`** | `zcl.zcode_passport_verify.v1` | `z23 zcode passport verify --passport=<lowercase-hex-wire>` | Verify one signed C23 module Passport |

#### `zcode.workspace` — Exact C23 workspace evidence bindings

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `zcode workspace status` | ready | read / read / public · instant/tiny | none | `zcl.zcode_workspace_status.v1` | `z23 zcode workspace status` | Show Passport-bound workspace readiness |
| `zcode workspace plan` | ready | read / read / public · instant/tiny | **`passport`**, **`module_release_root`**, **`sequence`**, `predecessor_release_root` | `zcl.zcode_workspace_plan.v1` | `z23 zcode workspace plan --input='<passport, release root, sequence>'` | Plan one Passport-bound workspace entry |
| `zcode workspace verify` | ready | read / read / public · instant/tiny | **`passport`**, **`module_release_root`**, **`sequence`**, `predecessor_release_root`, **`binding_root`** | `zcl.zcode_workspace_verify.v1` | `z23 zcode workspace verify --input='<plan input plus binding_root>'` | Verify one Passport-bound workspace entry |
| `zcode workspace show` | ready | read / read / public · instant/tiny | **`passport`**, **`module_release_root`**, **`sequence`**, `predecessor_release_root`, **`binding_root`** | `zcl.zcode_workspace_verify.v1` | `z23 zcode workspace show --input='<verified binding input>'` | Show one verified Passport-bound workspace entry |

#### `zcode.workspace.source` — Git-free source

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `zcode workspace source capture` | ready | mutate / app-write / operator · foreground/high | **`workspace`** | `zcl.zcode_source_capture.v1` | `z23 zcode workspace source capture --input='{"workspace":"/src/project"}'` | Capture one exact source tree into ZVCS |

#### `zcode.workspace.source.bundle` — Compressed ZVCS transport

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `zcode workspace source bundle create` | ready | mutate / app-write / operator · foreground/high | **`workspace`**, **`source_root`**, **`output`** | `zcl.zcode_source_bundle_create.v1` | `z23 zcode workspace source bundle create --input='{"workspace":"/src","source_root":"<64hex>","output":"/tmp/source.zvsb"}'` | Create a compressed bundle from one captured ZVCS tree |
| `zcode workspace source bundle verify` | ready | read / read / public · foreground/high | **`bundle`**, **`source_root`** | `zcl.zcode_source_bundle_verify.v1` | `z23 zcode workspace source bundle verify --input='{"bundle":"/tmp/source.zvsb","source_root":"<64hex>"}'` | Verify and rederive a compressed ZVCS source bundle |
| `zcode workspace source bundle import` | ready | mutate / app-write / operator · foreground/high | **`bundle`**, **`source_root`**, **`workspace`** | `zcl.zcode_source_bundle_import.v1` | `z23 zcode workspace source bundle import --input='{"bundle":"/tmp/source.zvsb","source_root":"<64hex>","workspace":"/tmp/zvcs-scratch"}'` | Import a verified source bundle into the existing ZVCS CAS |
| `zcode workspace source bundle checkout` | ready | mutate / app-write / operator · foreground/high | **`bundle`**, **`source_root`**, **`workspace`**, **`destination`** | `zcl.zcode_source_bundle_checkout.v1` | `z23 zcode workspace source bundle checkout --input='{"bundle":"/tmp/source.zvsb","source_root":"<64hex>","workspace":"/tmp/zvcs-scratch","destination":"/tmp/source-scratch"}'` | Reconstruct an exact source tree without Git |

#### `zcode.workspace.source.package` — P2P source carrier reconstruction

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `zcode workspace source package checkout` | ready | mutate / app-write / operator · foreground/high | **`datadir`**, **`package_root`**, **`source_root`**, **`accepted_work_root`**, **`workspace`**, **`destination`** | `zcl.zcode_source_package_checkout.v1` | `z23 zcode workspace source package checkout --input='{"datadir":"/tmp/zclassic23-node","package_root":"<64hex>","source_root":"<64hex>","accepted_work_root":"<64hex>","workspace":"/tmp/zvcs-scratch","destination":"/tmp/source-scratch"}'` | Reconstruct an exact source carrier from the P2P store |

#### `zcode.workspace.manifest` — Externally signed C23 workspace manifests

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `zcode workspace manifest plan` | ready | read / read / public · instant/tiny | **`passport`**, **`module_release_root`**, **`sequence`**, `predecessor_release_root`, **`workspace_sequence`**, `predecessor_workspace_root`, **`signer_root`**, `workspace`, `publication_job_root` | `zcl.zcode_workspace_manifest_plan.v1` | `z23 zcode workspace manifest plan --input='<verified Passport binding and signer public key>'` | Plan one externally signed workspace manifest |
| `zcode workspace manifest commit` | ready | read / read / public · instant/tiny | **`passport`**, **`module_release_root`**, **`sequence`**, `predecessor_release_root`, **`workspace_sequence`**, `predecessor_workspace_root`, **`signer_root`**, **`signature`**, `workspace`, `publication_job_root` | `zcl.zcode_workspace_manifest_commit.v1` | `z23 zcode workspace manifest commit --input='<same plan plus external signature>'` | Verify one externally signed workspace manifest |

#### `zcode.commons` — Read-only ZC23 Living Commons projection

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `zcode commons backlog` | ready | read / read / public · instant/tiny | **`workspace`**, **`cutoff_height`**, **`cutoff_mtp`** | `zcl.zcode_commons_backlog.v2` | `z23 zcode commons backlog --input='{"workspace":"/tmp/zclassic23-zcode-scratch","cutoff_height":1,"cutoff_mtp":1}'` | Show the simulation-only claim backlog |
| `zcode commons status` | ready | read / read / operator · fast/low | **`workspace`**, `expected_network_genesis_root`, `expected_zc23_policy_root`, `expected_epoch`, `expected_award_atoms`, `active_height`, `active_mtp`, `anchor_opening_height`, `anchor_opening_hash`, `anchor_maturity_height`, `anchor_maturity_hash`, `now_unix` | `zcl.zcode_commons_status.v1` | `z23 zcode commons status --input='{"workspace":"/tmp/zclassic23-zcode-scratch"}'` | Show Living Commons status |
| `zcode commons epoch` | ready | read / read / operator · fast/low | **`workspace`**, **`epoch`** | `zcl.zcode_commons_epoch.v1` | `z23 zcode commons epoch --input='{"workspace":"/tmp/zclassic23-zcode-scratch","epoch":1}'` | Show one creation epoch |
| `zcode commons lineage` | ready | read / read / operator · fast/low | **`workspace`**, **`package_root`** | `zcl.zcode_commons_lineage.v1` | `z23 zcode commons lineage --input='{"workspace":"/tmp/zclassic23-zcode-scratch","package_root":"<64hex>"}'` | Show package continuity lineage |
| `zcode commons verify` | ready | read / read / operator · fast/low | **`workspace`** | `zcl.zcode_commons_verify.v1` | `z23 zcode commons verify --input='{"workspace":"/tmp/zclassic23-zcode-scratch"}'` | Verify Living Commons integrity |
| `zcode commons rebuild` | ready | read / read / operator · fast/low | **`workspace`** | `zcl.zcode_commons_rebuild.v1` | `z23 zcode commons rebuild --input='{"workspace":"/tmp/zclassic23-zcode-scratch"}'` | Rebuild Living Commons projection |

#### `zcode.commons.creation` — Creation-attribution inspection

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `zcode commons creation show` | ready | read / read / operator · fast/low | **`workspace`**, **`root`** | `zcl.zcode_commons_creation_show.v1` | `z23 zcode commons creation show --input='{"workspace":"/tmp/zclassic23-zcode-scratch","root":"<64hex>"}'` | Show one creation attribution |

#### `zcode.commons.claim` — Signed simulation-only creation claims

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `zcode commons claim plan` | ready | read / read / operator · instant/tiny | **`workspace`**, **`claim`** | `zcl.zcode_commons_claim.v2` | `z23 zcode commons claim plan --input='{"workspace":"/tmp/zclassic23-zcode-scratch","claim":"<signed-claim-hex>"}'` | Validate one externally signed creation claim |
| `zcode commons claim commit` | ready | mutate / app-write / operator, plan-commit · fast/low | **`workspace`**, **`claim`** | `zcl.zcode_commons_claim.v2` | `z23 zcode commons claim commit --input='{"workspace":"/tmp/zclassic23-zcode-scratch","claim":"<signed-claim-hex>"}'` | Store one externally signed creation claim |
| `zcode commons claim show` | ready | read / read / operator · instant/tiny | **`workspace`**, **`root`** | `zcl.zcode_commons_claim.v2` | `z23 zcode commons claim show --input='{"workspace":"/tmp/zclassic23-zcode-scratch","root":"<claim-root>"}'` | Show one exact signed creation claim |

#### `zcode.commons.shadow` — Read-only pre-genesis shadow-epoch proof

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `zcode commons shadow plan` | ready | read / read / operator · fast/low | **`workspace`**, **`score_receipt_root`**, **`policy_candidate_root`**, **`reproduction_request_root`**, **`reproduction_proof_set_root`**, **`epoch`**, **`now_unix`** | `zcl.zcode_commons_shadow.v1` | `z23 zcode commons shadow plan --input='{"workspace":"/tmp/zclassic23-zcode-scratch","score_receipt_root":"<64hex>","policy_candidate_root":"<64hex>","reproduction_request_root":"<64hex>","reproduction_proof_set_root":"<64hex>","epoch":1,"now_unix":1}'` | Explain whether the first shadow epoch can be proven |
| `zcode commons shadow status` | ready | read / read / operator · fast/low | **`workspace`**, `expected_network_genesis_root`, `expected_zc23_policy_root`, `expected_epoch`, `expected_award_atoms`, `active_height`, `active_mtp`, `anchor_opening_height`, `anchor_opening_hash`, `anchor_maturity_height`, `anchor_maturity_hash`, `now_unix` | `zcl.zcode_commons_shadow_status.v1` | `z23 zcode commons shadow status --input='{"workspace":"/tmp/zclassic23-zcode-scratch"}'` | Show scratch shadow accounting status |
| `zcode commons shadow verify` | ready | read / read / operator · fast/low | **`workspace`** | `zcl.zcode_commons_shadow_verify.v1` | `z23 zcode commons shadow verify --input='{"workspace":"/tmp/zclassic23-zcode-scratch"}'` | Verify scratch shadow accounting structure |

#### `zcode.commons.shadow.attribution` — Scratch-only creation-attribution simulation

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `zcode commons shadow attribution plan` | ready | read / read / operator · fast/low | **`workspace`**, **`score_receipt_root`**, **`policy_candidate_root`**, **`reproduction_request_root`**, **`reproduction_proof_set_root`**, **`contributor_binding_root`**, **`epoch`**, **`now_unix`** | `zcl.zcode_commons_shadow_attribution.v1` | `z23 zcode commons shadow attribution plan --input='{...}'` | Plan one creation-backed shadow attribution |
| `zcode commons shadow attribution commit` | ready | mutate / app-write / operator, plan-commit · fast/low | **`workspace`**, **`score_receipt_root`**, **`policy_candidate_root`**, **`reproduction_request_root`**, **`reproduction_proof_set_root`**, **`contributor_binding_root`**, **`epoch`**, **`now_unix`** | `zcl.zcode_commons_shadow_attribution.v1` | `z23 zcode commons shadow attribution commit --input='{...}'` | Store one verified shadow attribution in scratch CAS |

#### `zcode.commons.shadow.epoch` — Scratch-only epoch-accounting simulation

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `zcode commons shadow epoch plan` | ready | read / read / operator · fast/low | **`workspace`**, **`policy_candidate_root`**, **`attribution_root`**, **`fixture_branch_root`**, **`previous_epoch_creation_root`**, **`now_unix`** | `zcl.zcode_commons_shadow_epoch.v1` | `z23 zcode commons shadow epoch plan --input='{...}'` | Plan exact shadow epoch accounting |
| `zcode commons shadow epoch commit` | ready | mutate / app-write / operator, plan-commit · fast/low | **`workspace`**, **`policy_candidate_root`**, **`attribution_root`**, **`fixture_branch_root`**, **`previous_epoch_creation_root`**, **`now_unix`** | `zcl.zcode_commons_shadow_epoch.v1` | `z23 zcode commons shadow epoch commit --input='{...}'` | Store one verified shadow epoch in scratch CAS |

#### `zcode.commons.shadow.protocol` — Four linked protocol shadow simulations

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `zcode commons shadow protocol verify` | ready | read / read / operator · fast/low | **`workspace`**, **`policy_candidate_root`**, **`epoch_0_root`**, **`epoch_1_root`**, **`epoch_2_root`**, **`epoch_3_root`**, **`branch_0_root`**, **`branch_1_root`**, **`branch_2_root`**, **`branch_3_root`**, **`now_unix`** | `zcl.zcode_commons_shadow_protocol.v1` | `z23 zcode commons shadow protocol verify --input='{...}'` | Verify four linked protocol shadow simulations |

#### `zcode.commons.schedule.propose` — Evidence-scheduled epoch emission proposals

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `zcode commons schedule propose plan` | ready | read / read / operator · fast/low | **`workspace`**, **`epoch`**, **`previous_proposal_root`** | `zcl.zcode_commons_schedule_propose.v1` | `z23 zcode commons schedule propose plan --input='{...}'` | Plan one Proof-of-Participation epoch proposal |
| `zcode commons schedule propose commit` | ready | mutate / app-write / operator, plan-commit · fast/low | **`workspace`**, **`epoch`**, **`previous_proposal_root`** | `zcl.zcode_commons_schedule_propose.v1` | `z23 zcode commons schedule propose commit --input='{...}'` | Store one epoch schedule proposal in scratch CAS |

#### `zcode.commons.schedule.claim` — Signed-claim epoch selection proposals

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `zcode commons schedule claim plan` | ready | read / read / operator · fast/low | **`workspace`**, **`epoch`**, **`cutoff_height`**, **`cutoff_mtp`**, **`epoch_capacity_atoms`**, **`previous_epoch_root`**, **`network_genesis_root`**, **`moderation_policy_root`**, **`qualification_predicates_root`**, **`backlog_algorithm_root`** | `zcl.zcode_commons_claim_epoch_plan.v2` | `z23 zcode commons schedule claim plan --input='{...}'` | Plan one signed-claim epoch selection |
| `zcode commons schedule claim commit` | ready | mutate / app-write / operator, plan-commit · fast/low | **`workspace`**, **`epoch`**, **`cutoff_height`**, **`cutoff_mtp`**, **`epoch_capacity_atoms`**, **`previous_epoch_root`**, **`network_genesis_root`**, **`moderation_policy_root`**, **`qualification_predicates_root`**, **`backlog_algorithm_root`** | `zcl.zcode_commons_claim_epoch_plan.v2` | `z23 zcode commons schedule claim commit --input='{...}'` | Store one signed-claim epoch proposal |
| `zcode commons schedule claim verify` | ready | read / read / operator · fast/low | **`workspace`**, **`proposal_root`**, **`network_genesis_root`**, **`moderation_policy_root`**, **`qualification_predicates_root`**, **`backlog_algorithm_root`** | `zcl.zcode_commons_claim_epoch_verify.v2` | `z23 zcode commons schedule claim verify --input='{...}'` | Reconstruct one signed-claim epoch proposal |
| `zcode commons schedule claim show` | ready | read / read / operator · instant/tiny | **`workspace`**, **`root`** | `zcl.zcode_commons_claim_epoch_show.v2` | `z23 zcode commons schedule claim show --input='{"workspace":"/tmp/zclassic23-zcode-scratch","root":"<proposal-root>"}'` | Show one exact signed-claim epoch proposal |

#### `zcode.commons.reproduction` — Portable simulation-only reproduction challenges

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `zcode commons reproduction challenge plan` | ready | read / read / operator · fast/low | **`workspace`**, **`request_hex`**, **`now_unix`** | `zcl.zcode_reproduction_challenge.v1` | `z23 zcode commons reproduction challenge plan --input='{"workspace":"/tmp/zclassic23-zcode-scratch","request_hex":"<hex>","now_unix":1}'` | Validate a portable reproduction challenge |
| `zcode commons reproduction challenge commit` | ready | mutate / app-write / operator, plan-commit · fast/low | **`workspace`**, **`request_hex`**, **`now_unix`** | `zcl.zcode_reproduction_challenge.v1` | `z23 zcode commons reproduction challenge commit --input='{...}'` | Store a portable reproduction challenge in scratch CAS |

#### `zcode.commons.economics` — Simulation-only v2 evidence economics

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `zcode commons economics status` | ready | read / read / public · instant/tiny | none | `zcl.zcode_commons_economics_status.v2` | `z23 zcode commons economics status` | Show simulation-only v2 evidence economics |

#### `zcode.commons.corpus` — Verified C23 corpus lower-bound projection

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `zcode commons corpus show` | ready | read / read / public · instant/tiny | **`root`** | `zcl.zcode_commons_corpus_show.v1` | `z23 zcode commons corpus show --root=<64-hex>` | Show one exact C23 corpus object |
| `zcode commons corpus verify` | ready | read / read / public · instant/low | `checkpoint` | `zcl.zcode_commons_corpus_verify.v1` | `z23 zcode commons corpus verify --checkpoint=<lowercase-hex-wire>` | Verify one bounded C23 corpus checkpoint |
| `zcode commons corpus status` | ready | read / read / public · instant/tiny | none | `zcl.zcode_commons_corpus_status.v1` | `z23 zcode commons corpus status` | Show the verified C23 corpus lower bound |

#### `zcode.commons.corpus.shard` — Bounded C23 corpus shard verification

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `zcode commons corpus shard verify` | ready | read / read / public · instant/low | `shard` | `zcl.zcode_commons_corpus_shard_verify.v1` | `z23 zcode commons corpus shard verify --shard=<lowercase-hex-wire>` | Verify one bounded C23 corpus shard |
| `zcode commons corpus shard page` | ready | read / read / public · instant/low | **`shard`**, `cursor`, `limit` | `zcl.zcode_commons_corpus_shard_page.v1` | `z23 zcode commons corpus shard page --input='{"shard":"<lowercase-hex-wire>","limit":256}'` | Read one stable-root page from a bounded C23 corpus shard |

#### `zcode.commons.impact` — Locally rendered productivity evidence

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `zcode commons impact verify` | ready | read / read / public · instant/tiny | `receipt` | `zcl.zcode_commons_impact_verify.v1` | `z23 zcode commons impact verify --receipt=<lowercase-hex-wire>` | Verify one signed productivity receipt |
| `zcode commons impact status` | ready | read / read / public · instant/tiny | none | `zcl.zcode_commons_impact_status.v1` | `z23 zcode commons impact status` | Show whether a productivity basis is shareable |
| `zcode commons impact share` | ready | read / read / public · instant/tiny | none | `zcl.zcode_commons_impact_share.v1` | `z23 zcode commons impact share` | Render a locally shareable productivity statement |

#### `zcode.moderation` — Decentralized Family Commons moderation

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `zcode moderation status` | ready | read / read / public · instant/tiny | none | `zcl.zcode_moderation_status.v1` | `z23 zcode moderation status` | Show Family moderation activation status |

#### `zcode.moderation.policy` — Immutable family policy profiles

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `zcode moderation policy list` | ready | read / read / public · instant/tiny | none | `zcl.zcode_moderation_policy_list.v1` | `z23 zcode moderation policy list` | List immutable Family Commons policies |
| `zcode moderation policy show` | ready | read / read / public · instant/tiny | **`profile`** | `zcl.zcode_moderation_policy_show.v1` | `z23 zcode moderation policy show --input='{"profile":"family-c23.v1"}'` | Show one immutable Family Commons policy |

#### `zcode.moderation.service` — Moderation service roster

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `zcode moderation service status` | ready | read / read / public · instant/tiny | none | `zcl.zcode_moderation_service_status.v1` | `z23 zcode moderation service status` | Show moderation service roster readiness |

#### `zcode.patronage` — Simulated patronage

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `zcode patronage show` | ready | read / read / operator · fast/low | **`workspace`**, **`root`**, **`expected_network_genesis_root`**, **`now_unix`** | `zcl.zcode_patronage_show.v1` | `z23 zcode patronage show --input='{"workspace":"/tmp/zclassic23-zcode-scratch","root":"<64hex>","expected_network_genesis_root":"<64hex>","now_unix":1}'` | Show and reverify one patronage offer or simulated funding receipt |
| `zcode patronage list` | ready | read / read / operator · fast/low | **`workspace`**, **`expected_network_genesis_root`**, **`now_unix`** | `zcl.zcode_patronage_list.v1` | `z23 zcode patronage list --input='{"workspace":"/tmp/zclassic23-zcode-scratch","expected_network_genesis_root":"<64hex>","now_unix":1}'` | List patronage objects |

#### `zcode.patronage.offer` — Signed patronage offers

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `zcode patronage offer plan` | ready | read / read / operator · fast/low | **`workspace`**, **`intent_hex`**, **`expected_network_genesis_root`**, **`now_unix`** | `zcl.zcode_patronage_offer.v1` | `z23 zcode patronage offer plan --input='{"workspace":"/tmp/zclassic23-zcode-scratch","intent_hex":"<hex>","expected_network_genesis_root":"<64hex>","now_unix":1}'` | Validate a signed simulation-only patronage offer |
| `zcode patronage offer commit` | ready | mutate / app-write / operator, plan-commit · fast/low | **`workspace`**, **`intent_hex`**, **`expected_network_genesis_root`**, **`now_unix`** | `zcl.zcode_patronage_offer.v1` | `z23 zcode patronage offer commit --input='{...}'` | Verify and store a signed simulation-only patronage offer |

#### `zcode.patronage.fund` — Fully simulated funding receipts

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `zcode patronage fund plan` | ready | read / read / operator · fast/low | **`workspace`**, **`funding_hex`**, **`expected_network_genesis_root`**, **`now_unix`** | `zcl.zcode_patronage_funding.v1` | `z23 zcode patronage fund plan --input='{"workspace":"/tmp/zclassic23-zcode-scratch","funding_hex":"<hex>","expected_network_genesis_root":"<64hex>","now_unix":1}'` | Validate a fully simulated funding receipt |
| `zcode patronage fund commit` | ready | mutate / app-write / operator, plan-commit · fast/low | **`workspace`**, **`funding_hex`**, **`expected_network_genesis_root`**, **`now_unix`** | `zcl.zcode_patronage_funding.v1` | `z23 zcode patronage fund commit --input='{...}'` | Verify and store a fully simulated funding receipt |

#### `zcode.continuity` — Package continuity

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `zcode continuity plan` | ready | read / read / operator · fast/low | **`workspace`**, **`policy_hex`**, **`expected_network_genesis_root`**, **`now_unix`** | `zcl.zcode_continuity_policy.view.v1` | `z23 zcode continuity plan --input='{"workspace":"/tmp/zclassic23-zcode-scratch","policy_hex":"<hex>","expected_network_genesis_root":"<64hex>","now_unix":1}'` | Validate a signed simulation-only continuity policy |
| `zcode continuity commit` | ready | mutate / app-write / operator, plan-commit · fast/low | **`workspace`**, **`policy_hex`**, **`expected_network_genesis_root`**, **`now_unix`** | `zcl.zcode_continuity_policy.view.v1` | `z23 zcode continuity commit --input='{...}'` | Verify and store a signed simulation-only continuity policy |
| `zcode continuity status` | ready | read / read / operator · fast/low | **`workspace`**, **`root`**, **`expected_network_genesis_root`**, **`now_unix`** | `zcl.zcode_continuity_policy.view.v1` | `z23 zcode continuity status --input='{"workspace":"/tmp/zclassic23-zcode-scratch","root":"<64hex>","expected_network_genesis_root":"<64hex>","now_unix":1}'` | Show and reverify one package continuity policy |

#### `zcode.patronage.settle` — Proof-conditioned simulated settlement

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `zcode patronage settle plan` | ready | read / read / operator · fast/low | **`workspace`**, **`settlement_hex`**, **`expected_network_genesis_root`**, **`expected_zc23_policy_root`**, **`expected_epoch`**, **`expected_award_atoms`**, **`active_height`**, **`active_mtp`**, **`anchor_opening_height`**, **`anchor_opening_hash`**, **`anchor_maturity_height`**, **`anchor_maturity_hash`**, **`now_unix`** | `zcl.zcode_patronage_settle.v1` | `z23 zcode patronage settle plan --input='{"workspace":"/tmp/zclassic23-zcode-scratch","settlement_hex":"<hex>","expected_network_genesis_root":"<64hex>","expected_zc23_policy_root":"<64hex>","expected_epoch":"1","expected_award_atoms":"500000000","active_height":"200","active_mtp":"1650","anchor_opening_height":"100","anchor_opening_hash":"<64hex>","anchor_maturity_height":"200","anchor_maturity_hash":"<64hex>","now_unix":1700}'` | Validate a proof-conditioned simulated settlement |
| `zcode patronage settle commit` | ready | mutate / app-write / operator, plan-commit · fast/low | **`workspace`**, **`settlement_hex`**, **`expected_network_genesis_root`**, **`expected_zc23_policy_root`**, **`expected_epoch`**, **`expected_award_atoms`**, **`active_height`**, **`active_mtp`**, **`anchor_opening_height`**, **`anchor_opening_hash`**, **`anchor_maturity_height`**, **`anchor_maturity_hash`**, **`now_unix`** | `zcl.zcode_patronage_settle.v1` | `z23 zcode patronage settle commit --input='{...}'` | Verify and store a proof-conditioned simulated settlement |

#### `zcode.patronage.refund` — Expiry-conditioned simulated refunds

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `zcode patronage refund plan` | ready | read / read / operator · fast/low | **`workspace`**, **`settlement_hex`**, **`expected_network_genesis_root`**, **`active_height`**, **`active_mtp`**, **`now_unix`** | `zcl.zcode_patronage_refund.v1` | `z23 zcode patronage refund plan --input='{"workspace":"/tmp/zclassic23-zcode-scratch","settlement_hex":"<hex>","expected_network_genesis_root":"<64hex>","active_height":"200","active_mtp":"2200","now_unix":2100}'` | Validate an expiry-conditioned simulated refund |
| `zcode patronage refund commit` | ready | mutate / app-write / operator, plan-commit · fast/low | **`workspace`**, **`settlement_hex`**, **`expected_network_genesis_root`**, **`active_height`**, **`active_mtp`**, **`now_unix`** | `zcl.zcode_patronage_refund.v1` | `z23 zcode patronage refund commit --input='{...}'` | Verify and store an expiry-conditioned simulated refund |

#### `zcode.package.dev` — Agentic development

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `zcode package dev prepare` | ready | read / read / operator · foreground/moderate | **`dir`**, **`publisher_pubkey`**, **`publisher_sequence`**, `reward_address`, `chain_id` | `zcl.zcode_package_dev_prepare.v1` | `z23 zcode package dev prepare --input='{"dir":"lib/base","publisher_pubkey":"<66hex>","publisher_sequence":1}'` | Derive canonical release inputs from a local package tree |
| `zcode package dev seal` | ready | read / read / operator · fast/low | **`release_body_hex`**, **`signature_hex`** | `zcl.zcode_package_dev_seal.v1` | `z23 zcode package dev seal --input='{"release_body_hex":"<hex>","signature_hex":"<128hex>"}'` | Verify and attach an offline development signature |
| `zcode package dev create` (aliases: `zcode.create`) | ready | mutate / app-write / operator · foreground/moderate | **`mode`**, `release_hex`, `manifest_hex`, `recipe_hex`, `dir`, `day`, `datadir` | `zcl.zcode_create.v1` | `z23 zcode create --input='{"mode":"plan","release_hex":"..","manifest_hex":"..","recipe_hex":"..","dir":"/tmp/pkg"}'` | Create package |
| `zcode package dev use` (aliases: `zcode.use`) | ready | mutate / app-write / operator · foreground/moderate | `name_or_root`, `plan_id`, `now_unix`, `datadir` | `zcl.zcode_use.v1` | `z23 zcode use --input='{"name_or_root":"<64hex>"}'` | Use dependency |
| `zcode package dev improve` (aliases: `zcode.improve`) | ready | mutate / app-write / operator · foreground/moderate | **`workspace`**, `candidate_workspace`, `datadir`, `mode`, `planned_task_root`, `planned_context_root`, `candidate_source_sha256`, `source_root`, `dependency_lock_root`, **`dependency_lock_hex`**, `write_scope_root`, **`write_scope_csv`**, `acceptance_tests_root`, **`acceptance_recipe_hex`**, **`model_policy_root`**, **`goal`**, **`proof_policy_hex`**, `action_kind`, `fixed_input_path`, `fixed_input_relpath`, `preprocessed_path`, `patch_root`, `candidate_source_root`, `adapter_policy_root`, `author_pubkey`, `candidate_sequence`, `candidate_created_unix`, `profile`, **`expires_unix`**, `max_changed_files`, `max_patch_bytes`, `max_context_bytes`, `max_cpu_seconds`, `max_memory_bytes`, `max_output_bytes`, `context_symbol`, `remote_peer` | `zcl.zcode_improve.v1` | `z23 zcode improve --input='{"mode":"plan","workspace":"/src/project","dependency_lock_hex":"<canonical wire hex>","write_scope_csv":"src,include","acceptance_recipe_hex":"<canonical wire hex>","model_policy_root":"<64hex>","goal":"fix seeded bug","proof_policy_hex":"<wire hex>","context_symbol":"buggy_function","expires_unix":123}'` | Improve code candidate |
| `zcode package dev evidence` (aliases: `zcode.evidence`) | ready | mutate / app-write / operator · foreground/moderate | **`workspace`**, `datadir`, **`action_id`** | `zcl.zcode_evidence.v1` | `z23 zcode evidence --input='{"workspace":"/src/project","action_id":"<64hex>"}'` | Evaluate candidate evidence |
| `zcode package dev accept` (aliases: `zcode.accept`) | ready | mutate / app-write / operator · foreground/moderate | **`workspace`**, **`action_id`**, **`lane`**, `datadir` | `zcl.zcode_accept.v1` | `z23 zcode accept --input='{"workspace":"/src/project","action_id":"<64hex>","lane":"CANDIDATE"}'` | Record candidate proof readiness |
| `zcode package dev lane` (aliases: `zcode.lane`) | ready | read / read / operator · foreground/low | **`workspace`**, **`source_root`**, `datadir` | `zcl.zcode_lane.v1` | `z23 zcode lane --input='{"workspace":"/src/project","source_root":"<64hex>","datadir":"/tmp/zclassic23-lane"}'` | Inspect source lane |
| `zcode package dev promotion-guide` | ready | read / read / public · instant/tiny | none | `zcl.zcode_lane_guide.v1` | `z23 zcode package dev promotion-guide` | Show signed lane workflow readiness |
| `zcode package dev tasks` (aliases: `zcode.tasks`) | ready | read / read / operator · foreground/low | **`workspace`**, `task_root`, `source_root`, `author`, `state`, `limit` | `zcl.zcode_tasks.v1` | `z23 zcode tasks --input='{"workspace":"/src/project"}'` | List local dev tasks |

#### `zcode.package.dev.score` — Evidence-derived signed ZC23 Score receipts

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `zcode package dev score plan` | ready | read / read / operator · fast/low | **`workspace`**, **`task_hex`**, **`candidate_hex`**, **`proof_policy_hex`**, **`proof_set_hex`**, **`proven_lane_hex`**, **`package_root`**, **`release_root`**, **`recipe_root`**, **`dependency_lock_root`**, **`api_capsule_root`** | `zcl.zcode_score_plan.v1` | `z23 zcode package dev score plan --input='{...}'` | Derive an unsigned ZC23 Score receipt |
| `zcode package dev score commit` | ready | mutate / app-write / operator · fast/low | **`workspace`**, **`receipt_hex`** | `zcl.zcode_score_commit.v1` | `z23 zcode package dev score commit --input='{"workspace":"/tmp/zclassic23-zcode-scratch","receipt_hex":"<hex>"}'` | Verify and store one signed ZC23 Score receipt |
| `zcode package dev score show` | ready | read / read / operator · fast/low | **`workspace`**, **`root`** | `zcl.zcode_score_show.v1` | `z23 zcode package dev score show --input='{"workspace":"/tmp/zclassic23-zcode-scratch","root":"<64hex>"}'` | Show and reverify one ZC23 Score receipt |

#### `zcode.package.dev.publish` — Publish an explicitly human-accepted work

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `zcode package dev publish plan` (aliases: `zcode.publish.plan`) | ready | read / read / operator · foreground/moderate | **`workspace`**, **`datadir`**, `acceptance_datadir`, **`source_root`**, **`publisher_pubkey`**, `name`, `semver`, `license`, `reward_address`, `znam`, `task_root`, `lane_receipt_root`, `publisher_sequence`, `parent_release_root`, `package_mapping_root`, `publication_job_root` | `zcl.zcode_publish_plan.v1` | `z23 zcode publish plan --input='{"workspace":"/src/project","datadir":"/tmp/zcode-dev","source_root":"<64hex>","publisher_pubkey":"<66hex>"}'` | Prepare a PROVEN work for offline release signing |
| `zcode package dev publish commit` (aliases: `zcode.publish`) | ready | mutate / app-write / operator · foreground/moderate | **`workspace`**, **`datadir`**, `acceptance_datadir`, **`source_root`**, **`release_hex`**, `task_root`, `lane_receipt_root`, `day`, `package_mapping_root`, `publication_job_root` | `zcl.zcode_publish_commit.v1` | `z23 zcode publish --input='{"workspace":"/src/project","datadir":"/tmp/zcode-dev","source_root":"<64hex>","release_hex":"<hex>"}'` | Publish one offline-signed PROVEN-work release |

#### `zcode.package` — Locally committed packages

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `zcode package guide` | ready | read / read / public · instant/tiny | none | `zcl.zcode_package_guide.v1` | `z23 zcode package guide` | Show the exact package workflow and authority boundaries |
| `zcode package search` | ready | read / read / operator · fast/low | `publisher`, `name_prefix`, `license`, `keyword`, `limit`, `datadir` | `zcl.zcode_package_search.v1` | `z23 zcode package search --input='{"keyword":"ring"}'` | Search locally committed packages |
| `zcode package library` | ready | read / read / operator · fast/low | `limit`, `datadir` | `zcl.zcode_package_library.v1` | `z23 zcode package library` | List complete packages this node can seed |
| `zcode package show` | ready | read / read / operator · fast/low | **`root`**, `datadir` | `zcl.zcode_package_show.v1` | `z23 zcode package show --input='{"root":"<64hex>"}'` | Release record and manifest summary for one package root |
| `zcode package recipe` | ready | read / read / operator · fast/low | **`root`**, `datadir` | `zcl.zcode_package_recipe.v1` | `z23 zcode package recipe --input='{"root":"<64hex>"}'` | Declarative build recipe for one package root |
| `zcode package verify` | ready | read / read / operator · fast/low | **`root`**, `datadir` | `zcl.zcode_package_verify.v1` | `z23 zcode package verify --input='{"root":"<64hex>"}'` | Verifier attestation quorum for one package root |
| `zcode package resolve` | ready | read / read / operator · fast/low | **`name`**, `datadir` | `zcl.zcode_package_resolve.v1` | `z23 zcode package resolve --input='{"name":"ringbuffer"}'` | Resolve a ZNAM package name to its release |
| `zcode package fetch` | ready | mutate / app-write / operator · foreground/moderate | `root`, `name`, `day`, `datadir`, `namespace`, `maximum_bytes` | `zcl.zcode_package_fetch.v1` | `z23 zcode package fetch --input='{"name":"<local-library-name>"}'` | Fetch a package from the authenticated swarm |
| `zcode package source reproduce` | ready | mutate / app-write / operator, plan-commit · foreground/high | **`mode`**, **`root`**, `namespace`, `sequence`, `not_before`, `expiry`, `plan_token`, `datadir` | `zcl.zcode_source_reproduce.v1` | `z23 zcode package source reproduce --input='{"mode":"plan","root":"<64hex>"}'` | Fetch, reconstruct, and attest one exact source package |
| `zcode package peers` | ready | read / read / operator · fast/low | **`root`**, `datadir` | `zcl.zcode_package_peers.v1` | `z23 zcode package peers --input='{"root":"<64hex>"}'` | Live swarm peers, local possession, pin, and transfer snapshot |
| `zcode package offered` | ready | read / read / operator · fast/low | `datadir` | `zcl.zcode_package_offered.v1` | `z23 zcode package offered` | Roots peers have ANNOUNCEd this session that this node can fetch |
| `zcode package pin` | ready | mutate / app-write / operator, plan-commit · foreground/moderate | **`root`**, **`mode`**, `plan_token`, `datadir` | `zcl.zcode_package_pin.v1` | `z23 zcode package pin --input='{"root":"<64hex>","mode":"plan"}'` | Pin a tracked package (PINS pool, never evicted) |
| `zcode package unpin` | ready | mutate / app-write / operator, plan-commit · foreground/moderate | **`root`**, **`mode`**, `plan_token`, `datadir` | `zcl.zcode_package_unpin.v1` | `z23 zcode package unpin --input='{"root":"<64hex>","mode":"plan"}'` | Release an operator pin |
| `zcode package checkout` | ready | mutate / app-write / operator · foreground/moderate | **`root`**, **`destination`**, `datadir` | `zcl.zcode_package_checkout.v1` | `z23 zcode package checkout --input='{"root":"<64hex>","destination":"/tmp/package-source"}'` | Reconstruct one verified package tree without executing it |
| `zcode package rollback` | ready | mutate / app-write / operator · fast/low | **`name`**, `now_unix`, `datadir` | `zcl.zcode_package_rollback.v1` | `z23 zcode package rollback --input='{"name":"alice/ringbuffer"}'` | Re-activate the previous installed generation |

#### `zcode.package.publish` — Commit a signed release into the local store (plan, then commit)

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `zcode package publish plan` | ready | read / read / operator · foreground/moderate | `release_hex`, `manifest_hex`, `recipe_hex`, `dir`, `datadir` | `zcl.zcode_publish_plan.v1` | `z23 zcode package publish plan --input='{"release_hex":"..","manifest_hex":"..","recipe_hex":"..","dir":"/tmp/pkg"}'` | Validate a candidate release without persisting anything |
| `zcode package publish commit` | ready | mutate / app-write / operator · foreground/moderate | `release_hex`, `manifest_hex`, `recipe_hex`, `dir`, `day`, `datadir` | `zcl.zcode_publish_commit.v1` | `z23 zcode package publish commit --input='{"release_hex":"..","manifest_hex":"..","recipe_hex":"..","dir":"/tmp/pkg"}'` | Re-validate and persist a candidate release into the local store |

#### `zcode.contributor` — Contributor identities

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `zcode contributor show` | ready | read / read / operator · fast/low | **`pubkey`**, `day`, `datadir` | `zcl.zcode_contributor_show.v1` | `z23 zcode contributor show --input='{"pubkey":"<66hex>"}'` | Contributor profile for one publisher pubkey |
| `zcode contributor packages` | ready | read / read / operator · fast/low | **`pubkey`**, `datadir` | `zcl.zcode_contributor_packages.v1` | `z23 zcode contributor packages --input='{"pubkey":"<66hex>"}'` | Published releases of one contributor key |
| `zcode contributor badges` | ready | read / read / operator · fast/low | **`pubkey`**, `limit`, `offset`, `datadir` | `zcl.zcode_contributor_badges.v1` | `z23 zcode contributor badges --input='{"pubkey":"<66hex>"}'` | Earned ZCODE Badges of one contributor (permanent evidence) |

#### `zcode.reward` — Legacy contribution rewards

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `zcode reward score` | ready | read / read / operator · foreground/moderate | **`root`**, `datadir` | `zcl.zcode_reward_score.v1` | `z23 zcode reward score --input='{"root":"<64hex>"}'` | Deterministic contribution score breakdown for one release root |
| `zcode reward eligible` | ready | read / read / operator · foreground/moderate | **`root`**, `datadir` | `zcl.zcode_reward_eligible.v1` | `z23 zcode reward eligible --input='{"root":"<64hex>"}'` | Reward eligibility gate list for one release root |
| `zcode reward queue` | ready | read / read / operator · fast/low | `state`, `limit`, `offset`, `datadir` | `zcl.zcode_reward_queue.v1` | `z23 zcode reward queue --input='{"state":"queued"}'` | Inspect the daily reward settlement queue |
| `zcode reward plan` | ready | mutate / app-write / operator, plan-commit · foreground/moderate | **`day`**, `datadir` | `zcl.zcode_reward_plan.v1` | `z23 zcode reward plan --input='{"day":20500}'` | Assemble one settlement window batch (SIMULATED) |
| `zcode reward commit` | ready | mutate / app-write / operator · foreground/moderate | **`plan_id`**, `datadir` | `zcl.zcode_reward_commit.v1` | `z23 zcode reward commit --input='{"plan_id":"<64hex>"}'` | Settle a planned batch (SIMULATED, idempotent) |
| `zcode reward receipt` | ready | read / read / operator · fast/low | **`plan_id`**, `datadir` | `zcl.zcode_reward_receipt.v1` | `z23 zcode reward receipt --input='{"plan_id":"<64hex>"}'` | Durable receipt for a settled batch (SIMULATED) |

#### `zcode.leaderboard` — Evidence rankings

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `zcode leaderboard daily` | ready | read / read / operator · fast/low | `category`, `day`, `limit`, `offset`, `breakdown`, `datadir` | `zcl.zcode_leaderboard.v1` | `z23 zcode leaderboard daily --input='{"day":20500,"category":"security-fixes"}'` | Daily ZCODE Ranking (earned score, never balances) |
| `zcode leaderboard weekly` | ready | read / read / operator · fast/low | `category`, `day`, `limit`, `offset`, `breakdown`, `datadir` | `zcl.zcode_leaderboard.v1` | `z23 zcode leaderboard weekly --input='{"day":20500}'` | Weekly ZCODE Ranking (ISO-8601 week, earned score) |
| `zcode leaderboard monthly` | ready | read / read / operator · fast/low | `category`, `day`, `limit`, `offset`, `breakdown`, `datadir` | `zcl.zcode_leaderboard.v1` | `z23 zcode leaderboard monthly --input='{"day":20500}'` | Monthly ZCODE Ranking (calendar month, earned score) |
| `zcode leaderboard all` | ready | read / read / operator · fast/low | `category`, `limit`, `offset`, `breakdown`, `datadir` | `zcl.zcode_leaderboard.v1` | `z23 zcode leaderboard all --input='{}'` | All-time ZCODE Ranking (earned score) |

#### `zcode.badge` — Evidence badges

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `zcode badge eligible` | ready | read / read / operator · fast/low | **`pubkey`**, `day`, `datadir` | `zcl.zcode_badge_eligible.v1` | `z23 zcode badge eligible --input='{"pubkey":"<66hex>","day":20500}'` | Which ZCODE Badges a contributor qualifies for right now |
| `zcode badge plan` | ready | mutate / app-write / operator · foreground/moderate | **`pubkey`**, `day`, `datadir` | `zcl.zcode_badge_plan.v1` | `z23 zcode badge plan --input='{"pubkey":"<66hex>","day":20500}'` | Assemble one dedup-checked badge issuance batch (SIMULATED) |
| `zcode badge issue` | ready | mutate / app-write / operator · foreground/moderate | **`plan_id`**, **`issuer_secret`**, `datadir` | `zcl.zcode_badge_issue.v1` | `z23 zcode badge issue --input='{"plan_id":"<64hex>","issuer_secret":"<64hex>"}'` | Issue a planned badge batch (SIMULATED, idempotent) |

#### `zcode.seed` — Local seeding facts

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `zcode seed status` | ready | read / read / operator · fast/low | `pubkey`, `day`, `datadir` | `zcl.zcode_seed_status.v1` | `z23 zcode seed status --input='{"pubkey":"<66hex>"}'` | Local serving facts, tier, and allowances per contributor key |
| `zcode seed ratio` | ready | read / read / operator · fast/low | `pubkey`, `datadir` | `zcl.zcode_seed_ratio.v1` | `z23 zcode seed ratio --input='{"pubkey":"<66hex>"}'` | The local verified-bytes ratio and exactly how it is computed |

#### `zcode.storage` — Content-addressed storage

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `zcode storage status` | ready | read / read / operator · fast/low | `datadir` | `zcl.zcode_storage_status.v1` | `z23 zcode storage status --input='{}'` | Store quota pools plus the pin-allowance policy view |

#### `zcode.release` — Release records

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `zcode release sign` | ready | mutate / app-write / operator · fast/low | `name`, `version`, `root`, `seed_file`, `seq`, `expiry`, `datadir` | `zcl.zcode_release_sign.v1` | `z23 zcode release sign --input='{"name":"demo","version":"0.1","root":"<64hex>","seed_file":"/path/seed.hex"}'` | Sign a release record with a master seed |
| `zcode release verify` | ready | read / read / public · fast/low | `doc`, `file`, `proof`, `root`, `anchored`, `datadir` | `zcl.zcode_release_verify.v1` | `z23 zcode release verify --input='{"doc":"<hex>"}'` | Verify a signed release record (optionally its batch inclusion) |
| `zcode release anchor` | ready | mutate / wallet / operator · foreground/moderate | `tip`, `domain`, `datadir` | `zcl.zcode_release_anchor.v1` | `z23 zcode release anchor --input='{}'` | Anchor the release batch's domain root on-chain |
| `zcode release prove` | ready | read / read / operator · fast/low | **`name`**, **`version`**, `domain`, `datadir` | `zcl.zcode_release_prove.v1` | `z23 zcode release prove --input='{"name":"demo","version":"0.1"}'` | Emit the domain-batch inclusion proof for one release |

#### `zcode.domain` — Anchor domains

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `zcode domain list` | ready | read / read / operator · fast/low | `datadir` | `zcl.zcode_domain_list.v1` | `z23 zcode domain list --input='{}'` | List the anchor domains stored in this datadir |
| `zcode domain status` | ready | read / read / operator · fast/low | `domain`, `datadir` | `zcl.zcode_domain_status.v1` | `z23 zcode domain status --input='{"domain":"zcode"}'` | Show one anchor domain's stored root, leaves, and anchor |

#### `zcode.proof` — Proof verification

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `zcode proof walk` | ready | read / read / public · foreground/low | `doc`, `doc_file`, `proof`, `root`, `tx`, `header`, `headers`, `merkle_branch`, `merkle_index`, `now`, `datadir` | `zcl.zcode_proof_walk.v1` | `z23 zcode proof walk --input='{"doc":"<hex>","proof":"<hex>","root":"<64hex>","tx":"<hex>","header":"<hex>","merkle_index":1,"merkle_branch":"<64hex>"}'` | Walk a record's proof chain down to proof-of-work, rung by rung |

#### `zcode.network` — Package DHT

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `zcode network delegate` | ready | mutate / app-write / operator · foreground/moderate | **`seed_file`**, `sequence`, `now`, `expiry`, `datadir` | `zcl.zcode_network_delegate.v1` | `z23 zcode network delegate --input='{"seed_file":"/path/master.hex"}'` | Provision this node's DHT delegation |
| `zcode network status` | ready | read / read / operator · fast/low | none | `zcl.zcode_network_status.v1` | `z23 zcode network status` | Inspect DHT status |
| `zcode network peers` | ready | read / read / operator · fast/low | `limit`, `offset` | `zcl.zcode_network_peers.v1` | `z23 zcode network peers --input='{"limit":16}'` | List DHT contacts |
| `zcode network find begin` | ready | read / read / operator · fast/low | **`node_id`** | `zcl.zcode_network_find_begin.v1` | `z23 zcode network find begin --input='{"node_id":"<64hex>"}'` | Admit a DHT lookup |
| `zcode network find poll` | ready | read / read / operator · fast/low | **`lookup_id`**, **`owner_token`** | `zcl.zcode_network_find_poll.v1` | `z23 zcode network find poll --input='{"lookup_id":"<32hex>","owner_token":"<32hex>"}'` | Poll a DHT lookup |
| `zcode network find cancel` | ready | read / read / operator · fast/low | **`lookup_id`**, **`owner_token`** | `zcl.zcode_network_find_cancel.v1` | `z23 zcode network find cancel --input='{"lookup_id":"<32hex>","owner_token":"<32hex>"}'` | Cancel a DHT lookup |
| `zcode network find` | ready | read / read / operator · foreground/moderate | **`node_id`** | `zcl.zcode_network_find.v1` | `z23 zcode network find --input='{"node_id":"<64hex>"}'` | Find closest DHT nodes |
| `zcode network records begin` | ready | read / read / operator · fast/low | **`kind`**, **`namespace`**, `semantic_root`, `transport_root`, `include_evidence_wires` | `zcl.zcode_network_records_begin.v1` | `z23 zcode network records begin --input='{"kind":"provider","namespace":"science","transport_root":"<64hex>"}'` | Admit iterative record discovery |
| `zcode network records poll` | ready | read / read / operator · fast/low | **`lookup_id`**, **`owner_token`** | `zcl.zcode_network_records_poll.v1` | `z23 zcode network records poll --input='{"lookup_id":"<32hex>","owner_token":"<32hex>"}'` | Poll iterative record discovery |
| `zcode network records cancel` | ready | read / read / operator · fast/low | **`lookup_id`**, **`owner_token`** | `zcl.zcode_network_records_cancel.v1` | `z23 zcode network records cancel --input='{"lookup_id":"<32hex>","owner_token":"<32hex>"}'` | Cancel iterative record discovery |
| `zcode network records` | ready | read / read / operator · foreground/moderate | **`kind`**, **`namespace`**, `semantic_root`, `transport_root`, `include_evidence_wires` | `zcl.zcode_network_records.v1` | `z23 zcode network records --input='{"kind":"pointer","namespace":"science.study","semantic_root":"<64hex>"}'` | Discover signed DHT records |
| `zcode network providers` | ready | read / read / operator · foreground/moderate | **`namespace`**, **`transport_root`** | `zcl.zcode_network_providers.v1` | `z23 zcode network providers --input='{"namespace":"science","transport_root":"<64hex>"}'` | List provider hints |
| `zcode network publish` | ready | mutate / app-write / operator, plan-commit · fast/low | **`mode`**, **`kind`**, **`namespace`**, `semantic_root`, **`transport_root`**, `owner_group`, **`sequence`**, **`not_before`**, **`expiry`**, `plan_token` | `zcl.zcode_network_publish.v1` | `z23 zcode network publish --input='{"mode":"plan","kind":"provider","namespace":"science","transport_root":"<64hex>","sequence":1,"not_before":1,"expiry":2}'` | Publish a signed DHT record |
| `zcode network storage_ack` | ready | mutate / app-write / operator, plan-commit · foreground/high | **`mode`**, **`namespace`**, `semantic_root`, **`transport_root`**, `owner_group`, **`sequence`**, **`not_before`**, **`expiry`**, `plan_token` | `zcl.zcode_network_storage_ack.v1` | `z23 zcode network storage_ack --input='{"mode":"plan","namespace":"science","transport_root":"<64hex>","sequence":1,"not_before":1,"expiry":2}'` | Publish a possession-backed storage ACK |
| `zcode network policy list` | ready | read / read / operator · fast/low | `datadir` | `zcl.zcode_network_policy_list.v1` | `z23 zcode network policy list` | Inspect local policy summary |
| `zcode network policy mutate` | ready | mutate / app-write / operator, plan-commit · fast/low | **`mode`**, **`operation`**, `source`, `effect`, `scope`, `action_mask`, `value`, `rule_id`, `enabled`, `plan_token`, `datadir` | `zcl.zcode_network_policy_mutate.v1` | `z23 zcode network policy mutate --input='{"mode":"plan","operation":"advisory","enabled":true}'` | Plan or commit local policy |
| `zcode network replication` | ready | read / read / operator · foreground/moderate | **`namespace`**, **`transport_root`** | `zcl.zcode_network_replication.v1` | `z23 zcode network replication --input='{"namespace":"science","transport_root":"<64hex>"}'` | Inspect declared replication |

#### `zcode.desc` — Onion descriptors

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `zcode desc publish` | ready | mutate / app-write / operator · fast/low | **`onion`**, `intros`, `seed_file`, `seq`, `not_before`, `expiry`, `now`, `datadir` | `zcl.zcode_desc_publish.v1` | `z23 zcode desc publish --input='{"onion":"<56base32>.onion","seed_file":"/path/seed.hex","intros":"<56base32>.onion:<64hex>","seq":"1"}'` | Publish a signed onion-service descriptor |
| `zcode desc verify` | ready | read / read / public · fast/low | `doc`, `file`, **`pubkey`**, `now` | `zcl.zcode_desc_verify.v1` | `z23 zcode desc verify --input='{"doc":"<hex>","pubkey":"<64hex>"}'` | Check a descriptor's signature against a master key you supply |
| `zcode desc resolve` | ready | read / read / public · fast/low | **`pubkey`**, `now`, `datadir` | `zcl.zcode_desc_resolve.v1` | `z23 zcode desc resolve --input='{"pubkey":"<64hex>"}'` | Look up an identity's current descriptor by its blinded record key |

#### `zcode.endpoint` — Signed node addresses

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `zcode endpoint publish` | ready | mutate / app-write / operator · fast/low | `onion`, `onion_port`, `ipv4`, `ipv4_port`, `ipv6`, `ipv6_port`, `services`, `height`, **`seed_file`**, `seq`, `not_before`, `expiry`, `now`, `datadir` | `zcl.zcode_endpoint_publish.v1` | `z23 zcode endpoint publish --input='{"onion":"<56base32>.onion","onion_port":"8033","seed_file":"/path/seed.hex","seq":"1","height":3196556}'` | Publish this node's signed endpoint record |
| `zcode endpoint accept` | ready | mutate / app-write / operator · fast/low | **`doc`**, `file`, `now`, `datadir` | `zcl.zcode_endpoint_accept.v1` | `z23 zcode endpoint accept --input='{"doc":"<hex>"}'` | Verify a peer's endpoint record against the chain and file it |
| `zcode endpoint verify` | ready | read / read / public · fast/low | **`doc`**, `file`, `now`, `datadir` | `zcl.zcode_endpoint_verify.v1` | `z23 zcode endpoint verify --input='{"doc":"<hex>"}'` | Check an endpoint record against the chain without storing it |
| `zcode endpoint resolve` | ready | read / read / public · fast/low | **`pubkey`**, `now`, `datadir` | `zcl.zcode_endpoint_resolve.v1` | `z23 zcode endpoint resolve --input='{"pubkey":"<64hex>"}'` | Look up a filed endpoint record by its blinded record key |
| `zcode endpoint list` | ready | read / read / public · fast/low | `now`, `datadir` | `zcl.zcode_endpoint_list.v1` | `z23 zcode endpoint list` | Show every filed endpoint record and whether the node will use it |

#### `zcode.package.add` — Install a package: plan then commit

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `zcode package add plan` | ready | mutate / app-write / operator · foreground/moderate | **`name_or_root`**, `now_unix`, `datadir`, `cursor`, `max_items` | `zcl.zcode_add_plan.v1` | `z23 zcode package add plan --input='{"name_or_root":"ringbuffer"}'` | Resolve, dependency-lock, and report what installing would do |
| `zcode package add commit` | ready | mutate / app-write / operator · background/high | **`plan_id`**, `now_unix`, `datadir`, `cursor`, `max_items` | `zcl.zcode_add_commit.v1` | `z23 zcode package add commit --input='{"plan_id":"<64hex>"}'` | Execute a plan: verify, build+test confined, install, activate, pin |

#### `zcode.science` — Scientific evidence

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `zcode science rebuild` | ready | mutate / app-write / operator · foreground/moderate | `now_unix`, `datadir`, `workspace` | `zcl.zcode_science_rebuild.v1` | `z23 zcode.science.rebuild --input='{"now_unix":1500}'` | Rebuild the science projection from the CAS |
| `zcode science publish` | ready | mutate / app-write / operator · foreground/moderate | **`root`**, `datadir`, `workspace` | `zcl.zcode_science_publish.v1` | `z23 zcode.science.publish --input='{"root":"<64hex>"}'` | Publish a science object to the swarm as a blob |
| `zcode science fetch` | ready | mutate / app-write / operator · foreground/moderate | `root`, `blob_root`, `datadir`, `workspace`, `now_unix`, `cancel` | `zcl.zcode_science_fetch.v1` | `z23 zcode.science.fetch --input='{"root":"<science-root-64hex>"}'` | Fetch and admit a blob-carried science object |

#### `zcode.science.study` — Preregistered study lifecycle

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `zcode science study plan` | ready | mutate / app-write / operator, plan-commit · foreground/low | **`wire_hex`**, `now_unix`, `datadir`, `workspace` | `zcl.zcode_science_plan.v1` | `z23 zcode.science.study.plan --input='{"wire_hex":"<844hex>"}'` | Plan a study submission |
| `zcode science study commit` | ready | mutate / app-write / operator, plan-commit · foreground/moderate | **`wire_hex`**, **`confirm`**, `now_unix`, `datadir`, `workspace` | `zcl.zcode_science_commit.v1` | `z23 zcode.science.study.commit --input='{"wire_hex":"<844hex>","confirm":true}'` | Commit a planned study |
| `zcode science study show` | ready | read / read / operator · fast/low | **`study_root`**, `datadir` | `zcl.zcode_science_study.v1` | `z23 zcode.science.study.show --input='{"study_root":"<64hex>"}'` | Show one study |
| `zcode science study list` | ready | read / read / operator · fast/low | `datadir`, `max` | `zcl.zcode_science_studies.v1` | `z23 zcode.science.study.list --input='{"max":32}'` | List studies |

#### `zcode.science.work` — Benchmark results and reproductions

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `zcode science work plan` | ready | mutate / app-write / operator, plan-commit · foreground/moderate | **`wire_hex`**, `method_hex`, `profile_hex`, `action_kind`, `action_sequence`, `action_source_cas_sha3`, `action_input_root_sha3`, `action_toolchain_capsule_sha3`, `now_unix`, `datadir`, `workspace` | `zcl.zcode_science_plan.v1` | `z23 zcode.science.work.plan --input='{"wire_hex":"<726hex>","method_hex":"<242hex>","profile_hex":"<444hex>"}'` | Plan benchmark evidence |
| `zcode science work commit` | ready | mutate / app-write / operator, plan-commit · foreground/moderate | **`wire_hex`**, **`confirm`**, `action_kind`, `action_sequence`, `action_source_cas_sha3`, `action_input_root_sha3`, `action_toolchain_capsule_sha3`, `now_unix`, `datadir`, `workspace` | `zcl.zcode_science_commit.v1` | `z23 zcode.science.work.commit --input='{"wire_hex":"<726hex>","confirm":true}'` | Commit planned benchmark evidence |
| `zcode science work execute` | ready | mutate / app-write / operator, plan-commit · foreground/moderate | `study_root`, `task_root`, `candidate_root`, `method_root`, `original_result_root`, `action_kind`, `action_sequence`, `result_sequence`, `reproduction_sequence`, **`challenge_block_height`**, **`challenge_block_hash`**, `reproducer_pubkey`, `confirm`, `now_unix`, `datadir`, `workspace` | `zcl.zcode_science_execute.v1` | `z23 zcode.science.work.execute --input='{"study_root":"<64hex>","task_root":"<64hex>","candidate_root":"<64hex>","method_root":"<64hex>","challenge_block_height":3200000,"challenge_block_hash":"<64hex>","confirm":true}'` | Execute a confined benchmark or reproduction |
| `zcode science work status` | ready | read / read / operator · fast/low | **`root`**, `datadir` | `zcl.zcode_science_work.v1` | `z23 zcode.science.work.status --input='{"root":"<64hex>"}'` | Show evidence status |
| `zcode science work receipt` | ready | read / read / operator · fast/low | **`root`**, `datadir`, `workspace` | `zcl.zcode_science_work.v1` | `z23 zcode.science.work.receipt --input='{"root":"<64hex>"}'` | Show evidence receipt |

#### `zcode.science.review` — Findings reviews

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `zcode science review submit` | ready | mutate / app-write / operator, plan-commit · foreground/moderate | **`wire_hex`**, `confirm`, `now_unix`, `datadir`, `workspace` | `zcl.zcode_science_review.v1` | `z23 zcode.science.review.submit --input='{"wire_hex":"<438hex>","confirm":true}'` | Submit a findings review |

#### `zcode.science.vote` — Curation votes

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `zcode science vote submit` | ready | mutate / app-write / operator, plan-commit · foreground/moderate | **`wire_hex`**, `confirm`, `network_genesis_root`, `voter_zid_root`, `signer_pubkey`, `now_unix`, `datadir`, `workspace` | `zcl.zcode_science_vote.v1` | `z23 zcode.science.vote.submit --input='{"wire_hex":"<438hex>","confirm":true,"network_genesis_root":"<64hex>","voter_zid_root":"<64hex>","signer_pubkey":"<64hex>"}'` | Submit a curation vote |

#### `zcode.science.findings` — Findings lifecycle

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `zcode science findings plan` | ready | mutate / app-write / operator, plan-commit · foreground/low | **`wire_hex`**, `now_unix`, `datadir`, `workspace` | `zcl.zcode_science_plan.v1` | `z23 zcode.science.findings.plan --input='{"wire_hex":"<634hex>"}'` | Plan a findings submission |
| `zcode science findings commit` | ready | mutate / app-write / operator, plan-commit · foreground/moderate | **`wire_hex`**, **`confirm`**, `now_unix`, `datadir`, `workspace` | `zcl.zcode_science_commit.v1` | `z23 zcode.science.findings.commit --input='{"wire_hex":"<634hex>","confirm":true}'` | Commit planned findings |

#### `zcode.science.rank` — Local discovery ranking

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `zcode science discover` | ready | read / read / operator · foreground/moderate | `search`, `category`, `hardware`, `network_genesis_root`, `now_unix`, `max`, `datadir`, `workspace` | `zcl.zcode_science_discover.v1` | `z23 zcode.science.discover --input='{"category":"active","max":16}'` | Search and rank study properties |
| `zcode science rank snapshot` | ready | read / read / operator · fast/low | **`workspace`**, `network_genesis_root`, `now_unix` | `zcl.zcode_science_rank_snapshot.v1` | `z23 zcode.science.rank.snapshot --input='{"workspace":"/path/to/workspace"}'` | Discovery graph snapshot |

### `metaverse` — Sovereign digital property: catalog, rights, receipts

#### `metaverse.agent` — Confined agents acting under a scoped grant

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `metaverse agent status` | ready | read / read / operator · instant/tiny | **`dir`** | `zcl.metaverse_agent_status.v1` | `z23 metaverse agent status --dir=/tmp/mv-broker` | What confinement the agent broker actually achieved |
| `metaverse agent money` | ready | read / read / operator · fast/moderate | **`dir`** | `zcl.metaverse_agent_money.v1` | `z23 metaverse agent money --dir=/tmp/mv-broker` | Identity-bound dev/prod custody, never an implied zero |
| `metaverse agent liquidity` | ready | read / read / operator · fast/moderate | **`dir`**, **`wallet_scope`**, **`recipient_value_zat`**, **`maximum_fee_zat`**, **`concurrency`** | `zcl.metaverse_agent_liquidity.v1` | `z23 metaverse agent liquidity --input='{"dir":"/private/broker","wallet_scope":"dev","recipient_value_zat":1000,"maximum_fee_zat":10000,"concurrency":10}'` | Plan parallel transaction liquidity without moving funds |
| `metaverse agent audit` | ready | read / read / operator · fast/low | **`dir`**, `limit` | `zcl.metaverse_agent_audit.v1` | `z23 metaverse agent audit --dir=/tmp/mv-broker` | Every action the confined agent took, and whether the log is intact |

#### `metaverse.property` — What property exists, who controls it, and how we know

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `metaverse property list` | ready | read / read / operator · fast/moderate | **`kind`**, `limit`, `datadir` | `zcl.metaverse_property_list.v1` | `z23 metaverse property list` | Every property this datadir holds, one row per kind scanned |
| `metaverse property show` | ready | read / read / operator · fast/low | **`property_id`**, `datadir` | `zcl.metaverse_property_show.v1` | `z23 metaverse property show content:<64hex>` | One property: its roots, controller, status, and evidence grade |

#### `metaverse.space` — Signed sovereign spaces and generic typed services

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `metaverse space plan` | ready | read / read / operator · fast/low | **`kind`**, `protocol_root`, `read_only_verbs`, `object_roots`, `capability_roots`, `sequence`, `not_before`, `expiry`, `name`, `description`, `service_roots`, `portal_roots`, `admission_root`, `datadir` | `zcl.metaverse_space_plan.v1` | `z23 metaverse space plan --input='{"kind":"service_descriptor","protocol_root":"<64hex>","read_only_verbs":["discover"]}'` | Plan one signed space manifest or typed service descriptor |
| `metaverse space commit` | ready | mutate / app-write / operator, plan-commit · fast/low | **`kind`**, `protocol_root`, `read_only_verbs`, `object_roots`, `capability_roots`, `sequence`, `not_before`, `expiry`, `name`, `description`, `service_roots`, `portal_roots`, `admission_root`, **`plan_token`**, **`confirm`**, `datadir`, `workspace` | `zcl.metaverse_space_commit.v1` | `z23 metaverse space commit --input='{"kind":"service_descriptor","protocol_root":"<64hex>","read_only_verbs":["discover"],"plan_token":"<64hex>","confirm":true}'` | Commit one exactly planned space object to local CAS |
| `metaverse space show` | ready | read / read / operator · fast/low | **`root`**, `workspace`, `datadir` | `zcl.metaverse_space_show.v1` | `z23 metaverse space show <64hex>` | Re-derive one local space object and its evidence grade |
| `metaverse space status` | ready | read / read / operator · fast/low | `root`, `kind`, `workspace`, `datadir` | `zcl.metaverse_space_status.v1` | `z23 metaverse space status --input='{"root":"<64hex>","kind":"space_manifest"}'` | Explain whether this node can publish, discover, or scout a Space |
| `metaverse space publish` | ready | mutate / app-write / operator · foreground/moderate | **`root`**, `workspace`, `datadir` | `zcl.metaverse_space_publish.v1` | `z23 metaverse space publish <64hex>` | Publish one local space object through the existing signed DHT |
| `metaverse space discover` | ready | mutate / app-write / operator · foreground/moderate | **`root`**, `kind`, `workspace`, `datadir` | `zcl.metaverse_space_discover.v1` | `z23 metaverse space discover <64hex> --kind=space_manifest` | Discover one exact space root under local admission policy |

#### `metaverse.space.scout` — Bounded read-only space missions and signed local evidence

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `metaverse space scout plan` | ready | read / read / operator · fast/low | `starting_roots`, `observation_unix`, `maximum_depth`, `maximum_spaces`, `maximum_portals`, `maximum_bytes`, `deadline_ms`, `datadir` | `zcl.metaverse_space_scout_plan.v1` | `z23 metaverse space scout plan --input='<mission-json>'` | Plan one bounded read-only traversal of sovereign spaces |
| `metaverse space scout run` | ready | mutate / app-write / operator, plan-commit · foreground/moderate | `starting_roots`, `observation_unix`, `maximum_depth`, `maximum_spaces`, `maximum_portals`, `maximum_bytes`, `deadline_ms`, `plan_token`, `confirm`, `workspace`, `datadir` | `zcl.metaverse_space_scout_run.v1` | `z23 metaverse space scout run --input='<confirmed-mission-json>'` | Run one exactly planned bounded read-only space scout mission |
| `metaverse space scout show` | ready | read / read / operator · fast/low | **`root`**, `workspace`, `datadir` | `zcl.metaverse_space_scout_show.v1` | `z23 metaverse space scout show <attestation-root>` | Show one signed local scout attestation and its canonical evidence map |

#### `metaverse.build` — Content-addressed C23 build jobs, actions, and receipts

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `metaverse build plan` | ready | mutate / app-write / operator · fast/low | **`source_sha256`**, **`source_cas_sha3`**, **`toolchain_sha3`**, **`input_root_sha3`**, **`flags_sha3`**, **`environment_sha3`**, **`profile`**, `datadir` | `zcl.build_plan.v1` | `z23 metaverse build plan --input='{"source_sha256":"<64hex>","source_cas_sha3":"<64hex>","toolchain_sha3":"<64hex>","input_root_sha3":"<64hex>","flags_sha3":"<64hex>","environment_sha3":"<64hex>","profile":"dev"}'` | Persist one immutable preprocessed C23 compile action |
| `metaverse build submit` | ready | mutate / app-write / operator · fast/low | **`job_id`**, `datadir` | `zcl.build_job.v1` | `z23 metaverse build submit <job_id>` | Queue every action in one planned build |
| `metaverse build status` | ready | read / read / operator · fast/low | **`job_id`**, `datadir` | `zcl.build_status.v1` | `z23 metaverse build status <job_id>` | Read one durable build and its ordered actions |
| `metaverse build cancel` | ready | mutate / app-write / operator · fast/low | **`job_id`**, `datadir` | `zcl.build_job.v1` | `z23 metaverse build cancel <job_id>` | Cancel one non-completed build |
| `metaverse build receipt` | ready | read / read / operator · fast/tiny | **`receipt_id`**, `datadir` | `zcl.build_receipt.v1` | `z23 metaverse build receipt <receipt_id>` | Read one signed worker build receipt |

#### `metaverse.build.worker` — Opt-in compile workers and their approved signing keys

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `metaverse build worker list` | ready | read / read / operator · fast/low | `datadir` | `zcl.build_worker_list.v1` | `z23 metaverse build worker list` | List build workers and current trust state |
| `metaverse build worker approve` | ready | mutate / app-write / operator · fast/low | **`worker_id`**, **`signer_pubkey`**, `capabilities`, `expires_at`, `datadir` | `zcl.build_worker.v1` | `z23 metaverse build worker approve <worker_id> --signer_pubkey=<64hex>` | Approve one Ed25519 build-receipt signer |
| `metaverse build worker revoke` | ready | mutate / app-write / operator · fast/low | **`worker_id`**, `datadir` | `zcl.build_worker.v1` | `z23 metaverse build worker revoke <worker_id>` | Revoke one build-receipt signer without deleting evidence |

### `yardsale` — For-sale-by-owner signed ads, settled bilaterally

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `yardsale guide` | ready | read / read / public · instant/tiny | none | `zcl.yardsale_guide.v1` | `z23 yardsale guide` | Pay ZCL and sell a 1/1 collectible |
| `yardsale buy` | ready | mutate / wallet / **owner**, plan-commit · foreground/moderate | **`ad_root`**, `confirm`, `now_unix` | `zcl.yardsale_buy.v1` | `z23 yardsale.buy --input='{"ad_root":"<64hex>","confirm":true}'` | Buy a live sign with wallet funds |

#### `yardsale.seller` — Seller profile: arm, disarm, status

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `yardsale seller arm` | ready | mutate / wallet / **owner**, plan-commit · foreground/moderate | **`token_txid`**, **`token_vout`**, **`ad_root`**, `confirm`, `now_unix` | `zcl.yardsale_seller_arm.v1` | `z23 yardsale.seller.arm --input='{"token_txid":"<64hex>","token_vout":1,"ad_root":"<64hex>","confirm":true}'` | Arm the seller profile from the wallet |
| `yardsale seller disarm` | ready | mutate / app-write / **owner** · foreground/low | none | `zcl.yardsale_seller_disarm.v1` | `z23 yardsale.seller.disarm` | Disarm the seller profile |
| `yardsale seller status` | ready | read / read / operator · fast/low | `now_unix` | `zcl.yardsale_seller_status.v1` | `z23 yardsale.seller.status` | Seller profile status |

### `zses` — Session invites

#### `zses.invite` — Invite

| Command | Avail | Policy | Input keys (**required**) | Output schema | Example | Summary |
|---|---|---|---|---|---|---|
| `zses invite create` | ready | read / read / public · fast/low | `endpoint`, `expires`, `capability_tag`, `capability-tag`, `posture`, `port` | `zcl.zses_invite.v1` | `z23 zses invite create` | Create a signed zses:v1 session invite |
| `zses invite accept` | ready | read / read / public · fast/low | **`invite`**, `now` | `zcl.zses_invite_accept.v1` | `z23 zses invite accept --invite=<json>` | Verify and accept a signed zses:v1 invite |


## Aliases

Every alias resolves through the same grammar as its canonical path
(`test_native_api_contract.c::test_root_and_discover_aliases_resolve`).

| Alias | Resolves to |
|---|---|
| `help` | `discover.help` |
| `dev.help` | `discover.help` |
| `search` | `discover.search` |
| `dev.search` | `discover.search` |
| `dev.diagnose.search` | `discover.search` |
| `appprotocols` | `app.protocols` |
| `explain` | `ops.debug.explain` |
| `ops.explain` | `ops.debug.explain` |
| `meaning` | `ops.debug.meaning` |
| `ops.meaning` | `ops.debug.meaning` |
| `profile` | `ops.debug.profile` |
| `ops.profile` | `ops.debug.profile` |
| `ops.producer.status` | `ops.debug.producer` |
| `ops.rom` | `ops.debug.rom` |
| `kpi` | `ops.debug.dash.kpi` |
| `ops.kpi` | `ops.debug.dash.kpi` |
| `ops.snapshot` | `ops.debug.dash.snapshot` |
| `ops.summary` | `ops.debug.dash.summary` |
| `milestone` | `ops.debug.dash.milestone` |
| `ops.milestone` | `ops.debug.dash.milestone` |
| `ops.mirror` | `ops.debug.dash.mirror` |
| `selfheal` | `ops.debug.dash.selfheal` |
| `ops.selfheal` | `ops.debug.dash.selfheal` |
| `dev.change.cycle` | `dev.change.apply` |
| `dev.loop.watch` | `dev.loop.ensure` |
| `dev.loop.heartbeat` | `dev.loop.status` |
| `dev.test.focused` | `dev.test.run` |
| `zcode.create` | `zcode.package.dev.create` |
| `zcode.use` | `zcode.package.dev.use` |
| `zcode.improve` | `zcode.package.dev.improve` |
| `zcode.evidence` | `zcode.package.dev.evidence` |
| `zcode.accept` | `zcode.package.dev.accept` |
| `zcode.lane` | `zcode.package.dev.lane` |
| `zcode.tasks` | `zcode.package.dev.tasks` |
| `zcode.publish.plan` | `zcode.package.dev.publish.plan` |
| `zcode.publish` | `zcode.package.dev.publish.commit` |


## Shared output schemas

Output schema ids carried by more than one leaf — the places where two commands
promise the same document shape.

| Output schema | Leaves |
|---|---|
| `zcl.wallet_security.v1` | `core.wallet.security.status`, `core.wallet.security.encrypt`, `core.wallet.security.unlock`, `core.wallet.security.lock` |
| `zcl.wait_result.v1` | `core.chain.wait.height`, `core.chain.wait.blocker`, `core.chain.wait.halt` |
| `zcl.block_mutation.v1` | `core.consensus.block.invalidate`, `core.consensus.block.reconsider` |
| `zcl.wallet_address.v1` | `core.wallet.address.new`, `core.wallet.address.import` |
| `zcl.wallet_send.v1` | `core.wallet.transaction.send`, `vault.send` |
| `zcl.shielded_send.v1` | `core.wallet.shielded.send`, `vault.send-shielded` |
| `zcl.storage_query.v1` | `core.storage.query`, `core.storage.query.offline` |
| `zcl.core_bootstatus.v1` | `core.node.bootstatus`, `core.node.bootwait` |
| `zcl.core_identity_anchor.v2` | `core.identity.anchor`, `core.identity.rotate`, `core.identity.revoke` |
| `zcl.core_zdir_register.v2` | `core.zdir.register`, `core.zdir.deregister` |
| `zcl.app_name_txresult.v1` | `app.names.register`, `app.names.update`, `app.names.transfer`, `app.names.renew`, `app.names.set-record`, `app.names.set-text` |
| `zcl.app_token_txresult.v1` | `app.tokens.create`, `app.tokens.send`, `app.tokens.mint`, `app.tokens.burn`, `vault.send-token` |
| `zcl.app_message_send_result.v1` | `app.messaging.send`, `app.messaging.send-named` |
| `zcl.market_purchase.v1` | `app.market.purchase.plan`, `app.market.purchase.commit`, `app.market.purchase.status`, `app.market.purchase.retrieve` |
| `zcl.app_swap_contract.v1` | `app.swap.initiate`, `app.swap.participate` |
| `zcl.rom_seed_status.v1` | `ops.debug.rom_seed.status`, `ops.debug.rom_seed.enable`, `ops.debug.rom_seed.disable` |
| `zcl.ops_mesh_join_status.v1` | `ops.mesh.join`, `ops.mesh.join_status` |
| `zcl.dev_cycle.v1` | `dev.status`, `dev.change.apply`, `dev.loop.wait` |
| `zcl.dev_hotswap.v1` | `dev.hotswap.apply`, `dev.hotswap.probe` |
| `zcl.dev_loop_status.v1` | `dev.loop.ensure`, `dev.loop.status`, `dev.loop.stop` |
| `zcl.account.v1` | `app.account.show`, `app.account.whoami`, `app.account.add`, `app.account.role`, `app.account.suspend`, `app.account.unsuspend` |
| `zcl.vault_swap_settle.v1` | `vault.swap.redeem`, `vault.swap.refund` |
| `zcl.zcode_workspace_verify.v1` | `zcode.workspace.verify`, `zcode.workspace.show` |
| `zcl.zcode_work_status.v1` | `zcode.work.status`, `zcode.work.show` |
| `zcl.zcode_commons_claim.v2` | `zcode.commons.claim.plan`, `zcode.commons.claim.commit`, `zcode.commons.claim.show` |
| `zcl.zcode_reproduction_challenge.v1` | `zcode.commons.reproduction.challenge.plan`, `zcode.commons.reproduction.challenge.commit` |
| `zcl.zcode_commons_shadow_attribution.v1` | `zcode.commons.shadow.attribution.plan`, `zcode.commons.shadow.attribution.commit` |
| `zcl.zcode_commons_shadow_epoch.v1` | `zcode.commons.shadow.epoch.plan`, `zcode.commons.shadow.epoch.commit` |
| `zcl.zcode_commons_schedule_propose.v1` | `zcode.commons.schedule.propose.plan`, `zcode.commons.schedule.propose.commit` |
| `zcl.zcode_commons_claim_epoch_plan.v2` | `zcode.commons.schedule.claim.plan`, `zcode.commons.schedule.claim.commit` |
| `zcl.zcode_patronage_offer.v1` | `zcode.patronage.offer.plan`, `zcode.patronage.offer.commit` |
| `zcl.zcode_patronage_funding.v1` | `zcode.patronage.fund.plan`, `zcode.patronage.fund.commit` |
| `zcl.zcode_continuity_policy.view.v1` | `zcode.continuity.plan`, `zcode.continuity.commit`, `zcode.continuity.status` |
| `zcl.zcode_patronage_settle.v1` | `zcode.patronage.settle.plan`, `zcode.patronage.settle.commit` |
| `zcl.zcode_patronage_refund.v1` | `zcode.patronage.refund.plan`, `zcode.patronage.refund.commit` |
| `zcl.zcode_publish_plan.v1` | `zcode.package.dev.publish.plan`, `zcode.package.publish.plan` |
| `zcl.zcode_publish_commit.v1` | `zcode.package.dev.publish.commit`, `zcode.package.publish.commit` |
| `zcl.zcode_leaderboard.v1` | `zcode.leaderboard.daily`, `zcode.leaderboard.weekly`, `zcode.leaderboard.monthly`, `zcode.leaderboard.all` |
| `zcl.zcode_science_plan.v1` | `zcode.science.study.plan`, `zcode.science.findings.plan`, `zcode.science.work.plan` |
| `zcl.zcode_science_commit.v1` | `zcode.science.study.commit`, `zcode.science.findings.commit`, `zcode.science.work.commit` |
| `zcl.zcode_science_work.v1` | `zcode.science.work.status`, `zcode.science.work.receipt` |
| `zcl.build_job.v1` | `metaverse.build.submit`, `metaverse.build.cancel` |
| `zcl.build_worker.v1` | `metaverse.build.worker.approve`, `metaverse.build.worker.revoke` |
| `zcl.telemetry.alerts.v1` | `ops.telemetry.alerts.active`, `ops.telemetry.alerts.history` |
| `zcl.telemetry.network.v1` | `ops.telemetry.network.summary`, `ops.telemetry.network.peers`, `ops.telemetry.network.tor`, `ops.telemetry.network.transport` |


## Envelope shapes (quick reference)

Full spec: `docs/NATIVE_COMMAND_INTERFACE.md` §8–§9. Summary only:

| Schema | When | Key fields |
|---|---|---|
| `zcl.command_menu.v1` | `discover help <branch>` / invoking a branch | `path`, `summary`, `registry_digest`, `children[]` (each: `path`,`summary`,`risk`,`latency`,`availability` — nothing else) |
| `zcl.command_spec.v1` | `discover describe <leaf>` | `availability`(+`availability_reason` if non-ready), `input_schema{id,allowed_keys,positional_keys}`, `output_schema`, `policy{layer,effect,risk,scope,authority,mode,latency,cost,confirmation,...}`, `example` |
| `zcl.command_search.v1` | `discover search <text>` | `matches[]` (≤5: `path`,`reason`,`risk`,`latency`,`availability`), `total_matches`, `truncated` |
| `zcl.result.v1` | executing any leaf | `ok`, `status` (`passed`\|`accepted`\|`blocked`\|`failed`), `data_schema`+`data` on success, `error{code,message,phase,retryable,mutated,blockers}` on failure, `next[]` |

Exit codes: `0` passed/accepted · `1` failed · `2` invalid input/unknown
command · `3` blocked by a named precondition (includes every `planned`
leaf) · `4` auth/capability denied · `5` transiently unavailable · `6`
internal contract failure.

## Where this is proven, not just documented

| Invariant | Test |
|---|---|
| This page matches `config/commands/*.def` byte for byte | `tools/lint/check_api_reference_generated.sh` (lint gate `check-api-reference-generated`) |
| Catalog well-formed, every leaf has schemas/example, ready⇒handler, planned⇒no handler | `test_command_registry_catalog.c::test_catalog_wellformed`, `test_ready_leaves_bound`, `test_planned_fail_closed` |
| Root menu stays in budget; branch menus stay shallow | `test_command_registry_catalog.c::test_root_menu_budget`, `test_branch_menus_shallow` |
| **Every** branch menu lists only its own immediate children, fixed 5-field shape | `test_native_api_contract.c::test_every_branch_menu_lists_only_own_children` |
| **Every** leaf's dotted path resolves 1:1 through its space-separated CLI words | `test_native_api_contract.c::test_every_leaf_dot_path_resolves_from_cli_words` |
| Declared aliases resolve through the same grammar | `test_native_api_contract.c::test_root_and_discover_aliases_resolve` |
| Search returns ≤5 ranked matches | `test_command_registry_catalog.c::test_search_bounded` |
| Missing required input fails closed with a structured `zcl.result.v1` error, not a silent pass | `test_command_registry_catalog.c::test_ops_state_requires_subsystem`; `test_native_api_contract.c::test_missing_required_input_fails_closed_structured` |
| `dev.*` leaves are release-`compat`, never falsely `ready` | `test_command_registry_catalog.c::test_dev_branch_leaves`, `test_dev_vcs_revert_release_stub`, `test_dev_vcs_seal_grant_release_stub` |
| Every bridged `ready` leaf has exactly one dispatch binding (body fn XOR direct RPC) | `test_command_registry_catalog.c` bridge-binding coverage |
| Release binary links no dev-mutation executor symbols | `tools/lint/check_release_no_dev_symbols.sh` |
