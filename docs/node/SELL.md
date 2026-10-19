<!-- Copyright 2026 Rhett Creighton - Apache License 2.0 -->

# Pay ZCL and sell a 1/1 collectible

Copyright 2026 Rhett Creighton. Licensed under the Apache License, Version 2.0.

Start here. One command names the exact next step and the fee:

```bash
z23 yardsale guide
z23 discover schema yardsale.seller.arm
```

Every money command is **plan first**. A plan never broadcasts. Only
`confirm:true` on that exact plan spends. The guide itself reads no wallet
and never prints keys or addresses.

The wallet default fee is the min-relay floor: **100 zat** (`0.00000100 ZCL`).
That is the lowest amount this node's mempool and miners will accept.

`z23 yardsale guide` lists six layers, each with a user story, the plan
command, the focused test group, and the expected proof (`simnet_confirmed`
today). Pay ZCL, Sapling, 1/1 ZSLP, yardsale swap, onion-market delivery, and
C23 package fetch are the same journey at different abstraction levels.

## The journeys

| Want | Plan (no broadcast) | Commit |
| --- | --- | --- |
| Pay ZCL | `vault intent plan --input=-` (stdin JSON) | `vault intent commit` with `confirm:true` |
| Mint a 1/1 NFT analog | `app tokens create` with `decimals:0`, `supply:"1"` | same leaf, `confirm:true` / returned `plan_id` |
| Sell it on yardsale | `yardsale.seller.arm` without `confirm` | same leaf with `confirm:true` |
| Buy a live yardsale ad | `yardsale.buy` without `confirm` | same leaf with `confirm:true` |
| Buy it from the web yard (`POST /yardsale/buy`) | same form without `confirm` — the reply renders the saved plan terms | resubmit the identical form with `&confirm=true`; changed terms with confirmation are refused; submit without confirmation to plan anew |
| Sell a file (torrent analog) | `app market offer` without `confirm` | same leaf with `confirm:true` |
| Start an exact package fetch | `zcode package fetch --datadir=/tmp/z23-sell --input='{"root":"<64hex>"}'` | inert: no build or install; a one-shot call records a resumable download |
| Onion shop | `app shop init --datadir=/tmp/z23-sell` without `confirm` | `confirm:true` |

Web-yard confirmation atomically advances the saved row from `PLANNED` to
`ARMING` before gossip. A concurrent confirmation or an uncertain interrupted
outcome cannot replay automatically; only a completed ceremony becomes
`COMMITTED`. Expired terms must be planned again.

Discover current keys instead of copying remembered ones:

```bash
z23 discover schema vault.intent.plan
z23 discover schema app.tokens.create
z23 discover schema yardsale.seller.arm
z23 discover schema yardsale.buy
z23 discover schema app.market.offer
z23 discover schema app.shop.init
```

## What each surface is

- **Yardsale** is the on-chain 1/1 collectible sale: one ZClassic transaction
  swaps ZSLP for ZCL between two wallets. Gossip only carries the ad pointer.
- **Package swarm** is the torrent analog: peers ANNOUNCE exact content-addressed
  roots and serve verified chunks. Fetch is inert.
- **Onion shop / store** is the private storefront: persistent onion identity,
  product rows, Sapling pay, hash-verified download over the SHA3 file-service
  overlay (`-tor -onion-persist`). Session keys are HKDF-SHA3-256; chunk ids
  are SHA3-256. Block hashes, txids, and transaction Merkle roots stay SHA-256d. See [`OVERLAY.md`](OVERLAY.md).

The simnet collectible example (`docs/examples/11_collectible_market.c`) proves the
same primitives on an isolated chain. Use it to see the shape; use the commands
above on a funded node.

## Funding and custody

```bash
z23 vault list
z23 core wallet balance
```

`yardsale.buy` requires confirmed funds for the price plus fee. Fund **this
node's** wallet; a `zclassicd` wallet with RPC disabled is not a Z23 spend
source. Do not export keys. Do not invent a balance from memory.

Inspect the returned plan and the leaf's confirmation fields. Approve
that one plan. There is no blanket "send all the demos" permission.

Live demonstration gates remain in
[`LIVE_TRANSACTION_DEMONSTRATIONS.md`](../quality/LIVE_TRANSACTION_DEMONSTRATIONS.md).
A running production node is not restarted by this workflow; a new default fee
applies on the next start of a binary that includes it.
