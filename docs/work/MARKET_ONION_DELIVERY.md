# Onion-routed market chunk delivery — design record (2026-08-09)

> Status: **proven** (offer v2 wire, `/market/chunk` onion-only route,
> buyer onion branch, node-level prefer-onion default with refuse-not-downgrade,
> `/directory.json` clearnet suppression). The two-daemon onion acceptance
> `make test-market-onion-acceptance`
> (`tools/dev/market_onion_acceptance.sh`) drives a real two-node trade over
> public Tor — offer gossip, Sapling payment, authorize-before-read refusal,
> no-Tor refusal by name (`ONION_DELIVERY_UNAVAILABLE`), and a byte-identical
> sliced delivery witnessed in both tor.log files. The clearnet acceptance
> `make test-market-acceptance` stays green as the regression floor.

Phase B5 of [`MARKETPLACE_NEXT.md`](./MARKETPLACE_NEXT.md). Goal: buyer and
seller complete the SAME authorized, payment-gated chunk exchange with
neither side's IP exposed. This file started as a design record from a full
read of the delivery, onion, and wire code; it is now implemented and
acceptance-proven.

## Why the current path leaks

A paid offer carries the seller's file-service endpoint as clearnet
`peer_ip:peer_port` (`struct file_offer`, `lib/net/include/net/file_market.h`)
and the buyer connects directly
(`file_market_purchase_retrieval_service.c` →
`file_market_delivery_fetch_endpoint`, `lib/net/src/file_market_delivery.c`).
`/directory.json` also publishes `clearnet_ip`/`clearnet_port`
(`lib/net/src/onion_service.c:696-702`), so an onion-first seller leaks its
IP there too unless that row is suppressed.

## Building blocks that already exist

- **Inbound**: dynhost bridges onion requests into
  `onion_service_handle_request()` (`lib/net/src/onion_service.c:1046`) —
  `(method, path, body, body_len, response, response_max)`, arbitrary binary
  both directions, HTTP-framed. New endpoint = one row in
  `lib/net/include/net/site_routes.def` (single registry; POST honored
  onion-only). Binary-serving precedent: `/zcode/download`.
- **Outbound .onion client, no SOCKS**:
  `tor_integration_fetch_onion_blocking()` (`lib/net/src/tor_integration.c:515`)
  over weak-linked `dynhost_client_fetch` — used today for the
  `/directory.json` seed fetch (`lib/net/src/connman.c:357`). **GET-only**
  (literal `GET %s HTTP/1.0`, `vendor/tor/src/feature/dynhost/dynhost_client.c:125`), <!-- doc-path-ok: optional vendor/tor submodule source is absent from the default checkout -->
  1 MiB response ceiling (`ONION_FETCH_BODY_MAX`, `tor_integration.c:461`).
- **Transport-independent authorization**: the buyer ed25519 request
  signature (`file_market_delivery_request_seal/verify`) and the
  authorize-before-read gate (`file_market_delivery_prepare` →
  `market_payment_authorize_chunk`, keyed on chain-confirmed payment) do not
  depend on the transport.

## The two hard constraints

1. **Wire format is fixed and fully signed.** The 535-byte offer wire has no
   endpoint-type field and no padding; `auth_version` is pinned to 1. A v3
   onion identity (32-byte ed25519 pubkey) does not fit the 16-byte
   `peer_ip`. Old nodes drop unknown versions cleanly
   (`FILE_OFFER_AUTH_ERR_VERSION`).
2. **Session binding does not transfer.** `session_id` derives from the fs
   handshake nonces (`file_market_delivery.c:140-158`); over onion there is
   no fs handshake. Everything else (signature, payment authority) is
   unchanged.

## Recommended minimal design

1. **Offer v2** (`file_market.h`, `lib/net/src/file_market_offer.c`): decode
   v1 + v2 keyed on `auth_version`; v2 body adds `endpoint_type u8`
   (0=clearnet, 1=onion) + `onion_pubkey[32]`, fixed-width layout, wire
   ~568 bytes. `offer_id`/body-root chain stays self-consistent
   automatically (payment memo and delivery request key on `offer_id`).
2. **Seller route**: one onion-only FAILCLOSED row `/market/chunk` in
   `site_routes.def`; handler decodes the signed delivery-v3 request,
   computes the onion-derived `expected_session_id` =
   `SHA3(session_domain || genesis || "onion" || offer_id || buyer_pubkey)`,
   then reuses `file_market_delivery_request_verify` + the existing injected
   authorize/load ports. The weakening vs per-connection nonces is named
   here: a copied v3 request only re-serves an already-paid chunk to the
   buyer's own key over an encrypted channel, and only within its signed
   900-second freshness window — relevant because this webserver logs full
   request lines to `tor.log`.
3. **Buyer**: branch on `offer.endpoint_type` in
   `file_market_purchase_retrieval_service.c:348-354` — onion →
   `tor_integration_fetch_onion_blocking`; clearnet → existing `rt->fetch`.
   Staging/root re-derivation unchanged.
4. **Request transport**: GET with the 214-byte request hex-encoded in the
   path (`/market/chunk/<hex>`) — avoids touching `vendor/tor` (which stays
   intentionally dirty). POST in `dynhost_client` is the cleaner follow-up.
5. **Chunk slicing**: onion responses cap at 64 KiB
   (`dynhost_webserver.c:324`), so chunks serve as ~60 KiB slices
   (`?slice=k`). Functionally correct, slow (~850 round-trips per 50 MiB
   chunk). Raising the dynhost buffer is a one-line change in the owner's
   fork — recommended, but a separate owner decision.
6. **Close the parallel leak**: an onion-endpoint seller must suppress its
   `clearnet_ip`/`clearnet_port` row in `/directory.json`.
7. **Stub-build policy (fail-closed, never silent)**: seller commit with
   `endpoint_type=onion` refuses on a stub build or unready Tor (new named
   error beside `MARKET_OFFER_ERR_ENDPOINT`); buyer retrieve on an onion
   offer without Tor refuses with a named error — no automatic clearnet
   fallback. Clearnet v1 offers keep working exactly as today; that is the
   existing explicit downgrade path, not a new silent one.

## What this does NOT hide (be honest)

- Timing/traffic correlation: fixed-size slices over Tor are a loud
  fingerprint to guards and global observers.
- Offer gossip metadata: `zfileoffer` floods over plaintext P2P — the first
  hop injecting an offer is a strong seller hint; `seller_pubkey` + content
  root link all activity for an offer.
- Buyer linkage: `buyer_pubkey` ties a purchase's chunk requests together
  (by design, for payment binding); pseudonymous, not anonymous across
  offers if keys are reused.
- Payment privacy is unchanged — it already rides Sapling. B5 only removes
  the IP-layer exposure of the delivery leg.
