<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Z23 Architecture Diagrams

Use this page to trace startup, peer communication, block validation, and
transactions (transfers of value). A **wallet** holds keys and tracks payments;
**HTTP** (Hypertext Transfer Protocol) carries the web requests shown below.
You need the source checkout to follow the symbols and a Mermaid-compatible
viewer to render the diagrams. For a first node build, read
[GETTING_STARTED.md](../node/GETTING_STARTED.md).

1. Render a diagram in your Mermaid-compatible viewer.
2. Follow its arrows through the named functions, stages, and events.
3. Read the owning source before treating a branch as an operating procedure.

These are subsystem sketches; an arrow groups related work rather than
promising that every startup or synchronization path takes that branch.

| Reference | Use it for |
| --- | --- |
| This page | Current subsystem flow and source entry points |
| [FRAMEWORK.md](./FRAMEWORK.md) | Canonical architecture and current/target status |
| [Sovereignty ADR](../adr/0001-personal-sovereignty-stack.md) | Architecture rationale |

In the diagrams, `EV_*` names are observable events, not commands. A
**reducer** advances chain state through stages; a **tip** is the end of the
active chain. A **datadir** is the node's data directory. SQLite is the
embedded database used by the node; a coins **view** supplies reads and a
**cache** keeps coins in memory. **UTXO** means unspent transaction output.
A **snapshot** saves state for later import.

---

## Boot Sequence

**CLI** means command-line interface. **P2P** means peer-to-peer networking;
**RPC** means remote procedure call, served over HTTP. **Tor** carries onion
services, addressed by `.onion` names. `pthread` denotes a native thread.
The **activation controller** coordinates chain activation; `connman`
manages peer connections.
**SHA3-256** is the hash used to check snapshot bytes. Ports below are
defaults; `-port=` and `-rpcport=` override them. A full-Tor build starts Tor
by default without `-tor`. `-no-tor` disables it on non-serving lanes; network-
serving lanes refuse that option. A stub-Tor build refuses `-tor` unless the
non-serving development lane uses `-allow-tor-stub-dev`, which does not run Tor.
Startup opens `coins_view_sqlite` on the shared `node.db` connection, then
binds `coins_view_kv` as the read view beneath the coins cache, backed by
`coins_kv` in `progress.kv`.

```mermaid
flowchart TD
    START([z23 with node options]) --> PARSE[Parse CLI flags<br/>-datadir=, -port=, -tor]
    PARSE --> ACTIVATION[Activation Controller<br/>state = ACTIVATION_BOOT_PENDING]

    ACTIVATION --> DB_OPEN[Open storage<br/>node.db + consensus.db]
    DB_OPEN -->|EV_BOOT_DB_OPEN| UTXO_CHECK{UTXO snapshot<br/>available?}

    UTXO_CHECK -->|yes| UTXO_IMPORT[Import UTXO snapshot<br/>SHA3-256 verify]
    UTXO_CHECK -->|no| COINS
    UTXO_IMPORT -->|EV_BOOT_UTXO_IMPORT| COINS
    COINS[Open coins_view_sqlite<br/>bind coins_view_kv + cache] --> BLOCK_INDEX

    BLOCK_INDEX[Load block index<br/>flat file + SQLite] -->|EV_BOOT_BLOCK_INDEX| CHAIN_VALIDATE

    CHAIN_VALIDATE[Chain state validator<br/>coins vs index agreement]
    CHAIN_VALIDATE -->|BOOT_OK| ACTIVATE
    CHAIN_VALIDATE -->|BOOT_RECOVER_REIMPORT| RECOVERY{Recovery policy<br/>allows?}
    CHAIN_VALIDATE -->|BOOT_RECOVER_WIPE_WAIT| RECOVERY
    CHAIN_VALIDATE -->|BOOT_RECOVER_RESET_CHAIN| RECOVERY

    RECOVERY -->|allow| UTXO_RECOVERY[UTXO recovery service<br/>wipe/reimport/rebuild]
    RECOVERY -->|refuse| FAIL([Boot failed<br/>EV_BOOT_VALIDATION_FAILED])
    UTXO_RECOVERY --> ACTIVATE

    ACTIVATE[Activate best chain<br/>find canonical tip] -->|EV_BOOT_ACTIVATE| SERVICES

    SERVICES[Start services]
    SERVICES --> P2P[P2P connman<br/>port 8033]
    SERVICES --> RPC[RPC httpserver<br/>port 18232]
    SERVICES --> TOR{Full Tor linked<br/>and no -no-tor?}
    SERVICES --> WALLET[Wallet sync]
    SERVICES --> BG_VAL{Background validation<br/>enabled?}

    TOR -->|yes| TOR_BOOT[Bootstrap Tor<br/>generate .onion]
    TOR -->|no| READY
    TOR_BOOT --> READY

    BG_VAL -->|yes| BG_START[Background validation<br/>pthread]
    BG_VAL -->|no| READY

    P2P --> READY
    RPC --> READY
    WALLET --> READY
    BG_START --> READY

    READY([EV_NODE_READY<br/>Services started])
```

---

## P2P Network Flow

**VERSION/VERACK** exchange protocol information and acknowledge the peer.
**Headers** hold block metadata; full blocks also contain transactions.
**DNS** (Domain Name System) resolves hostnames; **IP** (Internet Protocol)
addresses locate peers. **Mainnet** is the public chain, rather than testnet.
`getheaders`, `getdata`, and `inv` are wire messages requesting headers,
requesting objects, and announcing objects. **FlyClient** checks sampled
headers using **MMB** (Merkle Mountain Belt) inclusion proofs and **PoW**
(proof of work). A snapshot **manifest** describes transferred chunks;
**chainwork** measures accumulated work, and **finality** constrains snapshot
height. **Delta sync** downloads blocks after the snapshot. **Relay** forwards
announcements; a **token bucket** meters bytes. Ban scores use a configurable
threshold, whose default is 100.

```mermaid
flowchart TD
    subgraph Discovery
        SEEDS[Hardcoded .onion seeds<br/>no mainnet DNS seeder is used]
        DIRECTORY[Fetch /directory.json<br/>from .onion peers]
        ADDNODE[Manual addnode]
    end

    SEEDS --> CONNECT
    DIRECTORY --> CONNECT
    ADDNODE --> CONNECT

    CONNECT[TCP connect<br/>port 8033] -->|EV_TCP_CONNECTED| HANDSHAKE

    subgraph Handshake
        HANDSHAKE[Send VERSION] --> VERSION_ACK[Recv VERSION]
        VERSION_ACK -->|EV_PEER_VERSION| VERACK[Exchange VERACK]
        VERACK --> ACTIVE[Peer state: ACTIVE]
    end

    ACTIVE --> SYNC_CHECK{Node at tip?}

    SYNC_CHECK -->|no| SYNC
    SYNC_CHECK -->|yes| RELAY

    subgraph Sync["Initial Sync"]
        direction TB
        SYNC[getheaders] --> HEADERS[Download headers<br/>EV_HEADERS_RECEIVED]
        HEADERS --> FLYCLIENT{FlyClient<br/>available?}
        FLYCLIENT -->|yes| FC_VERIFY[50 random samples<br/>MMB inclusion proofs<br/>PoW verify]
        FLYCLIENT -->|no| FULL_HEADERS[Full header chain]
        FC_VERIFY --> SNAPSHOT{Strict v2 snapshot peer<br/>available?}
        FULL_HEADERS --> GETBLOCKS
        SNAPSHOT -->|yes| SNAP_RECV[Validate v2 manifest<br/>chunk SHA3 + UTXO SHA3<br/>finality + chainwork]
        SNAPSHOT -->|no| GETBLOCKS
        SNAP_RECV --> DELTA[Delta sync<br/>blocks from snapshot to tip]
        GETBLOCKS[getdata blocks] --> DELTA
    end

    subgraph Relay["Steady State"]
        direction TB
        RELAY[Listen for inv] --> INV_CHECK{Have it?}
        INV_CHECK -->|no| GETDATA[getdata]
        INV_CHECK -->|yes| DROP[Drop]
        GETDATA --> PROCESS[Process block/tx]
        PROCESS --> ANNOUNCE[Relay to other peers<br/>inv]
    end

    subgraph Bandwidth["Bandwidth Control"]
        BUCKET[Token bucket<br/>download + upload]
        BUCKET -->|budget exceeded| THROTTLE[Skip peer this cycle<br/>EV_PEER_THROTTLED]
        BUCKET -->|budget ok| ALLOW[recv/send proceeds]
    end

    subgraph Scoring["Peer Scoring"]
        MISBEHAVE[Misbehavior detected] -->|EV_PEER_MISBEHAVE| SCORE{Score >= threshold?}
        SCORE -->|yes| BAN[Ban peer<br/>EV_PEER_BANNED]
        SCORE -->|no| CONTINUE[Continue]
    end
```

---

## Block Validation Pipeline

**Merkle root** is the block's commitment to its transactions. Transparent
**scripts** authorize spends with **ECDSA** signatures on secp256k1.
**Sapling** and **Sprout** are shielded transaction systems; **Groth16** is
the Sapling proof system. The **turnstile** checks shielded pool balances.
A **reorganization** switches to a winning branch by unwinding old changes;
a **side chain** is a branch outside the active chain. A **checkpoint**
compares state with a compiled commitment. A **flush**
persists cached changes. The staged reducer path and the `connect_block`
detail below are conceptual views, not two successive validation passes.

```mermaid
flowchart TD
    RECEIVE[Block received<br/>from P2P or RPC] --> INGEST[reducer_ingest_block]

    INGEST --> CHECK_BLOCK[check_block<br/>structure validation]

    subgraph Structural["Structure Checks"]
        CHECK_BLOCK --> HEADER_CHECK[Header validation<br/>PoW, timestamp, difficulty]
        HEADER_CHECK --> MERKLE[Merkle root<br/>verify]
        MERKLE --> TX_BASIC[Transaction structure<br/>version, size, format]
    end

    TX_BASIC -->|EV_BLOCK_CHECK_PASSED| HEADER_ADMIT[header_admit stage<br/>candidate fact]

    HEADER_ADMIT --> VALIDATE_HEADERS[validate_headers stage<br/>contextual header checks]
    VALIDATE_HEADERS --> BODY_FETCH[body_fetch stage<br/>request missing bodies]
    BODY_FETCH --> BODY_PERSIST[body_persist stage<br/>store block bytes]
    BODY_PERSIST --> SCRIPT_VALIDATE[script_validate stage<br/>transparent scripts]
    SCRIPT_VALIDATE --> PROOF_VALIDATE[proof_validate stage<br/>shielded proofs]
    PROOF_VALIDATE --> UTXO_APPLY[utxo_apply stage<br/>same-txn UTXO delta]
    UTXO_APPLY --> TIP_FINALIZE[tip_finalize stage<br/>publish reducer tip]

    TIP_FINALIZE --> BEST_CHECK{New block extends<br/>best chain?}
    BEST_CHECK -->|no, but more work| REORG
    BEST_CHECK -->|no| DONE_SIDE([Stored as<br/>side chain])
    BEST_CHECK -->|yes| CONNECT

    subgraph Reorg["Reorganization"]
        REORG[EV_REORG_START] --> UNWIND[Reducer unwind<br/>inverse UTXO deltas]
        UNWIND -->|fail| REORG_FAIL([typed blocker<br/>manual intervention])
        UNWIND -->|ok| RECONNECT[Apply winning branch<br/>from fork point]
    end

    RECONNECT --> CONNECT

    subgraph Connection["connect_block"]
        CONNECT[EV_BLOCK_CONNECT_START] --> INPUTS[Check inputs exist<br/>in UTXO set]
        INPUTS -->|EV_TX_INPUTS_CHECKED| SCRIPTS[Verify scripts<br/>ECDSA secp256k1]
        SCRIPTS -->|EV_SCRIPT_VERIFIED| SAPLING{Sapling<br/>txs?}
        SAPLING -->|yes| GROTH16[Verify Groth16<br/>spend + output proofs]
        SAPLING -->|no| TURNSTILE
        GROTH16 --> TURNSTILE[Turnstile check<br/>sprout + sapling pools]
        TURNSTILE -->|EV_TURNSTILE_CHECK| UTXO_UPDATE[Update UTXO set<br/>spend inputs, create outputs]
        UTXO_UPDATE --> CHECKPOINT{UTXO checkpoint<br/>height?}
        CHECKPOINT -->|yes| VERIFY_CP[Verify UTXO commitment<br/>against hardcoded hash]
        CHECKPOINT -->|no| FLUSH_CHECK
        VERIFY_CP -->|pass| FLUSH_CHECK
        VERIFY_CP -->|fail| REJECT([EV_UTXO_CHECKPOINT_FAIL<br/>block rejected])
    end

    FLUSH_CHECK{Flush needed?} -->|yes| FLUSH[Flush coins to SQLite<br/>EV_COINS_FLUSH]
    FLUSH_CHECK -->|no| TIP_UPDATE
    FLUSH --> TIP_UPDATE

    TIP_UPDATE[Publish reducer tip<br/>EV_TIP_UPDATED] --> NOTIFY[Notify wallet,<br/>mempool, subscribers]
    NOTIFY -->|EV_BLOCK_CONNECT_DONE| DONE([Block connected])

    CHECK_BLOCK -->|fail| REJECT_BLOCK([EV_BLOCK_REJECTED<br/>dos score assigned])
```

---

## Wallet Transaction Lifecycle

The **mempool** holds accepted transactions awaiting a block. **Coin
selection** chooses inputs; a **t-address** is transparent and a **z-address**
is shielded. A **zk-SNARK** is a shielded proof, and an **IVK** (incoming
viewing key) allows trial decryption of received notes. **Confirmation**
count tracks block inclusion; **maturity** controls when an output can be
spent. `z_sendmany` is an RPC method, called as `z23 z_sendmany ...`.

```mermaid
flowchart TD
    subgraph Create["Transaction Creation"]
        USER[User: z23 z_sendmany<br/>from, recipients] --> SELECT[Coin selection<br/>descending-value candidates]
        SELECT --> TRANSPARENT{Shielded address<br/>involved?}
        TRANSPARENT -->|t-addr to t-addr| BUILD_T[Build transparent tx<br/>inputs, outputs, change]
        TRANSPARENT -->|involves z-addr| BUILD_S[Build Sapling tx<br/>spend proofs, output proofs]
        BUILD_T --> SIGN_T[Sign inputs<br/>ECDSA secp256k1]
        BUILD_S --> SIGN_S[Create zk-SNARK proofs<br/>Groth16 spend + output]
        SIGN_T --> BROADCAST
        SIGN_S --> BROADCAST
    end

    BROADCAST[Broadcast to mempool<br/>+ relay to peers]

    subgraph Mempool["Mempool"]
        BROADCAST --> MEMPOOL_CHECK[Validate tx<br/>inputs, scripts, proofs]
        MEMPOOL_CHECK -->|valid| ACCEPT_MP[EV_TX_ACCEPTED<br/>added to mempool]
        MEMPOOL_CHECK -->|invalid| REJECT_MP[EV_TX_REJECTED]
        ACCEPT_MP --> RELAY_INV[Relay inv to peers]
        ACCEPT_MP --> WAIT[Wait for block<br/>inclusion]
    end

    subgraph Mining["Block Inclusion"]
        WAIT --> MINED[Miner includes tx<br/>in block template]
        MINED --> BLOCK_CONNECT[Block connected<br/>at height H]
    end

    subgraph Confirmation["Wallet Tracking"]
        BLOCK_CONNECT --> WALLET_NOTIFY[Wallet notified<br/>of new block]
        WALLET_NOTIFY --> SCAN_T[Scan transparent<br/>outputs for our addresses]
        WALLET_NOTIFY --> SCAN_S[Trial-decrypt Sapling<br/>outputs with IVK]
        SCAN_T --> UPDATE[Update wallet rows in node.db<br/>mark tx confirmed]
        SCAN_S --> UPDATE
        UPDATE --> CONF_1[1 confirmation]
        CONF_1 --> CONF_N[N confirmations<br/>maturity depends on type]
    end

    subgraph Query["Balance Query"]
        CONF_N --> BALANCE[z23 core wallet balance<br/>wallet balance]
        CONF_N --> LIST[z23 core wallet transaction list<br/>history with confirmations]
    end
```

---

## Onion Service Architecture

The **hidden service listener** accepts HTTP requests arriving through Tor.
Handlers dispatch through C calls; the explorer returns **HTML** (web page
markup), while status and directory endpoints return **JSON** (structured
data). **ZSLP** is the token protocol used by
the store. These are selected routes; the app mounts are registered in
`core/modules/net/include/net/site_routes.def`.
The `/blog` mount renders post and index HTML from `node.db`. If its handler
returns no response, the onion dispatcher sends HTTP 503; it does not serve
HTML files from `{datadir}/blog/` as a fallback.

```mermaid
flowchart TD
    subgraph Tor["Embedded Tor (pthread)"]
        TOR_BOOT[Bootstrap Tor circuit] --> ONION_GEN[Load or create .onion identity]
        ONION_GEN --> DYNHOST[core/modules/net/src/onion_service.c<br/>hidden service listener]
    end

    REMOTE[Remote client<br/>via Tor network] -->|.onion address| DYNHOST

    DYNHOST --> HANDLE[onion_service_handle_request]
    HANDLE --> ROUTE_HTTP{Route request}

    ROUTE_HTTP -->|/status| STATUS[Node status JSON<br/>serve_status]
    ROUTE_HTTP -->|/explorer/*| EXPLORER[Block explorer<br/>HTML + charts]
    ROUTE_HTTP -->|/directory.json| DIRECTORY[Peer directory<br/>.onion + clearnet IP + height]
    ROUTE_HTTP -->|/store| STORE[ZSLP token store<br/>store_handle_request]
    ROUTE_HTTP -->|/blog| BLOG[Render blog posts<br/>from node.db]

    STATUS --> CONTROLLERS[C handler dispatch]
    EXPLORER --> CONTROLLERS
    CONTROLLERS --> NODE[Node state<br/>chain, wallet, mempool]

    style DYNHOST fill:#9966cc,color:#fff
    style ONION_GEN fill:#9966cc,color:#fff
```
