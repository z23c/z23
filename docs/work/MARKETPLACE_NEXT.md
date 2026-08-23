# Marketplace next steps — ordered checklist (2026-08-08)

Context: the metaverse MVP lane is done and pushed (`d00d5a7fd`,
`make metaverse-score` = 100/100, `make metaverse-verify` 7/7). The owner
asked "what's next?" and picked these three tracks, in this order.

Subordinate to [`FORWARD_PLAN.md`](./FORWARD_PLAN.md): this does **not**
reorder the v1 node-sovereignty lane (C3/C5/C6/C8). It is the
metaverse/marketplace parallel lane opened by the 2026-08-08 owner
directive. Boundaries inherited from [`MARKETPLACE_PLAN.md`](./MARKETPLACE_PLAN.md):
no consensus change, ZC23 stays simulation-only, live money fail-closed,
settlement is ordinary opt-in transactions with plan/commit + fee preview.

## Phase A — two-laptop real test (owner + one helper machine)

Everything so far was proven with regtest daemons on one host. This phase
is two real machines finding each other over Tor and trading a file.

- [x] A1. Journey shipped: `make commons-multihost-acceptance` in the top-level
      README (the standalone two-laptop guide was purged as superseded)
- [ ] A2. Both machines build the real-Tor binary (`vendor/tor` submodule + `libtor.a`)
- [ ] A3. Node A boots with `-tor`, serves its onion, shares the address
- [ ] A4. Node B discovers/connects to A (`/directory.json` or `-addnode`)
- [ ] A5. A offers a file; B sees it in the market listing
- [ ] A6. B buys: payment tx verifies, chunks unlock, download completes
- [ ] A7. Friction log → each snag filed and fixed

## Phase B — file-market settlement wiring (code)

The marketplace trade is wired end-to-end: seller `app market offer`
(sign → persist → content-bind → gossip) and buyer `app market purchase
plan/commit/status/retrieve` (payment → chain-verified claim →
authorize-before-read chunk delivery → root re-derivation). The legacy
`zmarket_offer`/`zmarket_buy` RPCs stay contained stubs by design.

**2026-08-09 update — B1 finding flipped Phase B:** the buyer side was
already wired end-to-end (`app market purchase plan/commit/status/retrieve`,
payment-gated chunk delivery, restart-safe retrieval). The genuine gap was
the seller side. B2 (landed in `c4bf1cb40` + `aff7ecf12`) closed it:
`app market offer` seals/persists/binds/announces a signed paid offer
(fail-closed without `-externalip` + file-service port), and the purchase
reverse-mapping gate covers the new leaf.

- [x] B1. Map the exact unwired seams — done; buyer pipeline already
  shipped, seller offer creation was the one real gap
- [x] B2. Seller offer wired end-to-end: `app market offer`
  plan/commit (content-addressed idempotent), sealed offer, content
  binding, `zfileoffer` origin flood; 11 new tests; pushed
- [x] B3. Two-node regtest acceptance script (`tools/dev/market_acceptance.sh`,
  `make test-market-acceptance`): seller offer gossip, real Sapling purchase,
  pre-confirmation retrieve refused, authorized delivery byte-identical to the
  offer root, seller claim CONFIRMED, idempotent replays — pushed `d8caa412c`.
  It exposed and we fixed four product bugs (native list body shape, missing
  chunk range validators, fetch-transport wiring, txid byte order)
- [x] B4. `make lint` + pre-push CI green on the pushed tree (919 ran,
  0 failed); docs updated (`FILE_MARKET_PROTOCOL.md`, two-laptop runbook,
  cookbook)
- [x] B5. **Onion-routed chunk delivery** — implemented and pushed
  (`6dcd7dafa` + `50bf175d6`): offer v2 (`endpoint_type=onion` + 32-byte
  onion pubkey, dual-version decode), onion-only FAILCLOSED
  `/market/chunk` route with the same authorize-before-read gate, buyer
  SOCKS-less onion fetch with slice reassembly, node-level prefer-onion
  default that refuses rather than downgrades, `/directory.json` clearnet
  suppression. Design record: [`MARKET_ONION_DELIVERY.md`](./MARKET_ONION_DELIVERY.md).
  Onion-path two-daemon acceptance proven:
  `make test-market-onion-acceptance` — a real public-Tor two-node trade
  (offer gossip, Sapling payment, authorize-before-read refusal through the
  onion route, no-Tor refusal by name, byte-identical 3×60 KiB sliced
  delivery witnessed in both tor.logs). The acceptance caught and we fixed:
  the vendored dynhost client never engaging the rendezvous machinery
  (onion_traffic + rewrite/attach on internal AP links, dedicated
  DIR_PURPOSE_DYNHOST_FETCH, 512-byte path buffer, single pending-mark),
  the tor monitor's permanent ~120 s give-up race, the retrieve RPC's 10 s
  loopback deadline vs multi-slice onion downloads (now 300 s + error
  envelope detection), and schema v64 widening market_payment_claims'
  offer_wire CHECK for the 568-byte v2 wire (claims silently failed to
  persist → delivery PENDING forever)

## Phase C — ZC23 design (owner decision first, then code)

ZC23 is simulation-only by design. Before any real distribution or
"Proof of Participation" exists, the rules get written down and the owner
picks them. Nothing here touches consensus; mining/distribution stays
simulation until the owner explicitly promotes it.

- [x] C1. Options doc: [`ZC23_DISTRIBUTION_OPTIONS.md`](./ZC23_DISTRIBUTION_OPTIONS.md)
  — PoP naming (A/B/C), distribution model (evidence-scheduled vs genesis
  pool vs hybrid), earn-for-publishing mechanics, supply shape, and the
- [x] C2. **Owner decided** (2026-08-09): Proof of Participation name,
  evidence-scheduled emission only (no genesis pool), 21M hard cap with
  self-tapering weekly budget, owner earns under the same rules, hosting
  earns ZC23 as the preservation class — guiding principle: incentivize
  the P2P ecosystem. Rules: [`ZC23_DISTRIBUTION_RULES.md`](./ZC23_DISTRIBUTION_RULES.md)
  six-point decision list for C2
- [ ] C2. Owner picks the rules
- [ ] C3. Implementation plan written (simulation-first, no consensus path)

## Standing rules for this checklist

- Copy-prove before live: every recovery or settlement path is proven on
  regtest/a datadir copy first.
- `make lint` + `make test-parallel` + pre-push CI before every push; no
  `--no-verify` on a red gate.
- `vendor/tor` submodule stays intentionally dirty; never commit it.
