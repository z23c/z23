# On-chain P2P marketplace with atomic swaps for ZSLP/ZCL (2026-07-27)

Owner directive: an on-chain P2P marketplace with cross-chain atomic swaps
for ZSLP/ZCL. This is an application protocol over Z23 — no consensus
change, ZSLP ledger semantics untouched, every wallet-signing step is
plan/commit with a fee preview.

## What already exists (reuse, do not rebuild)

- **ZSWP HTLC swaps** (`engine/controllers/src/swap_controller.c`,
  `core/modules/script/src/htlc.c`): initiate/participate/redeem/refund wired
  end-to-end for ZCL/BTC/LTC/DOGE — secret extraction, settlement-tx build,
  broadcast, persisted SWAP_REDEEMED/SWAP_REFUNDED state.
- **ZSLP** (`contexts/market/modules/zslp/`, `contexts/market/models/src/zslp_ledger.c`,
  `contexts/market/services/src/zslp_command_service.c`): GENESIS/MINT/SEND codec,
  debit-correct UTXO ledger, wallet compose paths shared by RPC + site.
- **ZCL Market gossip** (`core/modules/net/src/msgprocessor.c` zfile* family,
  `engine/models/src/file_offer.c`): offer gossip with TTL + AR model — the
  pattern for signed order announcements.
- **ZCL fuel economics** (`docs/work/ZCODE_PLAN.md`): the cost estimator
  covers swap/offer tx fees; every plan previews ZCL cost before commit.

## The two swap shapes

1. **Same-chain ZSLP ↔ ZCL: single-transaction atomic swap.** One tx with
   inputs from both parties: seller's ZSLP UTXO(s) + buyer's ZCL UTXO(s),
   outputs = ZCL to seller, ZSLP (valid SLP SEND) to buyer, change. Each
   party signs only its own inputs (SIGHASH_ALL); the tx is invalid until
   both sign, and atomic once they do — no HTLC needed on one chain.
   Flow: maker builds an unsigned order template → taker completes + signs
   → either party broadcasts. v1: full-fill only, no partial fills.
2. **Cross-chain (ZSLP on ZCL ↔ BTC/LTC/DOGE): HTLC, extending ZSWP.** The
   ZCL-side lock output carries the token: the redeem path spends it as a
   valid SLP SEND to the buyer (secret revealed on redeem, extractable from
   the spending tx — the existing `swap_extractsecret` primitive). Refund
   returns the token to the seller after CLTV. Reuse the 97-byte dcrdex
   contract shape already in `core/modules/script/src/htlc.c`.

## Slices (each lands green, plan/commit, adversarial tests)

1. Same-chain single-tx ZSLP/ZCL swap builder + signer (plan/commit both
   sides; SLP validity proven against the ledger rules; dust/fee math
   exact; either-party broadcast).
2. Signed yardsale-ad model + gossip: seller-key-signed for-sale records
   (token id, amounts, price, expiry height, nonce), bounded TTL gossip
   reusing the zfile-offer pattern, AR model + validation, per-key rate
   limits, every rejection names the rule.
3. Yardsale projections (the rebuildable view of heard ads) + typed
   commands (`market offer|take|list|cancel`
   plan/commit where signing) and the onion market page reading the same
   projections (inheriting the UX design system).
4. Cross-chain ZSLP HTLC (redeem=SLP SEND; refund; reorg-aware state
   machine on top of the existing swap persistence).
5. Simulator lane: seller cancel-by-double-spend griefing, expiry races,
   secret-reveal front-running, refund races, reorg during settlement,
   malformed/oversized ads, SLP-invalid settlement attempts, fee
   estimation vs built tx vsize.

## Boundaries

- No consensus or ZSLP-semantics change; swaps are ordinary opt-in
  transactions.
- v1: full-fill ads only; no automatic broadcast without owner commit;
  ads are hints — settlement truth is the chain.
- Ad gossip never earns ZCODE Credit by itself; yardsale anti-spam
  is rate limits + expiry + (later) earned-credit priority, never a fee
  to list.
- The yardsale page/commands read the same projections — no second
  yardsale truth.
