# 11 — the full digital-collectible marketplace lifecycle

## What it demonstrates

This is the flagship example: the executable design doc for z23's
commerce stack. It mints one-of-one digital collectibles, claims a
permanent on-chain storefront identity, and sells them two different
ways — a plain direct payment and a trustless HTLC escrow — entirely
inside the deterministic `simnet` harness, through the real
`connect_block()` consensus path. It is built directly on top of examples
04 (ZSLP), 05 (ZNAM), and 06 (HTLC) and composes all three: an HTLC
contract's scriptPubKey carries an SLP-tagged OP_RETURN just like any
other output, so a token's provenance chain runs straight through an
escrow settlement.

The story, real blocks throughout:

1. **Mint the deeds** — three ZSLP GENESIS tokens, quantity 1, decimals 0,
   no mint baton: true one-of-one collectibles. Each `document_hash` field
   is the real SHA3-256 of a small in-program byte array standing in for
   "the artwork," so each deed is cryptographically bound to distinct
   asset bytes, not just a name. Parsed back independently of the
   projection to prove the hash-binding lives in the chain.
2. **Claim the storefront** — a ZNAM REGISTER for a gallery name, then a
   SET_TEXT `"onion"` record pointing at an illustrative storefront
   `.onion` address: the permanent on-chain pointer a buyer resolves
   before ever contacting the seller.
3. **Sale path A (direct)** — the buyer pays the asking price to the
   seller, and the SAME block also carries the ZSLP SEND handing deed #1
   to the buyer. Provenance (GENESIS -> SEND) reads straight off the
   chain.
4. **Sale path B (trustless escrow)** — deed #2's holder output is a P2SH
   HTLC instead of a plain P2PKH, but it still carries an SLP SEND
   OP_RETURN. A collector reveals the secret to redeem it (and
   `htlc_extract_secret` recovers that secret from the settled scriptSig
   afterward, the same step a real cross-chain counterparty performs).
   Deed #3 is escrowed for a sale that never completes: the CLTV timeout
   passes and the seller refunds it back to themselves — provably, via
   the projection, not just "nothing happened."

## Build / run

```bash
make -C examples && ./examples/bin/11_collectible_market
```

## Expected output sketch

```
=== 11_collectible_market: mint -> claim a storefront -> sell direct -> sell through trustless escrow ===

[1/6] minting three one-of-one collectibles (ZSLP GENESIS, quantity=1, decimals=0, no mint baton)...
      ART1 "Sovereign Sketch #1" minted at height 201; document_hash bound to 64 artwork bytes and verified via independent slp_parse
      ART2 "Sovereign Sketch #2" minted at height 303; document_hash bound to 64 artwork bytes and verified via independent slp_parse
      ART3 "Sovereign Sketch #3" minted at height 405; document_hash bound to 64 artwork bytes and verified via independent slp_parse

[2/6] claiming a permanent on-chain storefront identity (ZNAM REGISTER -> SET_TEXT "onion")...
      REGISTER "collectible-gallery" -> t1gallerydemoaddr accepted at height 508 (owner=t1YWwkeTXucACvoLV21Bpsnc3VTujmrH4Kg)
      SET_TEXT[onion] accepted at height 509; a buyer resolving "collectible-gallery" now finds:
        artisan1lect1blesgalleryfrontdoorxxxxxxxxxxxxxxxxxxxxxxxxx.onion  (illustrative address, not a live service)

[3/6] sale path A (direct): buyer pays the asking price; the SAME block carries deed #1's transfer...
      block accepted at height 611: payment of 150000 zats settled AND deed #1 handed to the buyer in the same block; provenance = 2 row(s) (GENESIS -> SEND)

[4/6] sale path B (trustless escrow), leg 1: lock deed #2 behind an HTLC, then the collector redeems it with the secret...
      secret = ab4a8978...(32 bytes, real CSPRNG — differs every run, see file header)
      deed #2 locked at height 612 behind a P2SH HTLC — the projection now shows it held at the CONTRACT's own address, not a person, until someone settles it
      redeem accepted at height 613 — collector now holds deed #2; htlc_extract_secret recovered the exact 256-bit secret from the settled scriptSig; provenance = 3 row(s)

[5/6] sale path B (trustless escrow), leg 2: a listing for deed #3 never completes — after the CLTV timeout, the seller refunds it back to themselves...
      deed #3 listed at height 614, locktime 616
      refund attempted before height 616 correctly rejected (nonfinal)
      refund accepted+mined at height 617 — the seller reclaimed deed #3; provenance = 3 row(s), ending back at the seller (nobody redeemed it)

[6/6] production counterpart — same primitives, real node:
      start with z23 yardsale guide (docs/SELL.md)

=== SUCCESS: three one-of-one collectibles minted and hash-bound, a permanent on-chain storefront claimed, one sold by direct payment, one sold through a redeemed HTLC escrow, and one reclaimed after its escrow timed out unclaimed — every step proved through real connect_block() + real projection folds ===
```

A stray `[simnet.mempool] ... reject nonfinal: ...` line prints to
stderr right before step 5's "correctly rejected" line — that is
`LOG_WARN`-style diagnostic output from the sim's own rejection path
(the same mechanism example 06 exercises), not a failure; the process
still exits 0.

Exact heights follow `simnet`'s coinbase-maturity mechanics (each
`simnet_spend`/`simnet_mint_coinbase` pair mines to a height satisfying
100-confirmation maturity, which grows each round since a fresh coinbase
is spent every time) and will shift if the funding recipe changes; the
token math, projection rows, and settlement outcomes are the invariant
part. Like example 06, the
two HTLC secrets are **not** reproducible run to run: `htlc_generate_secret()`
(`core/modules/script/src/htlc.c`) draws from the real OS CSPRNG, not the seed
tape's mockable RNG hook — genuine cryptographic secret material must
never be routed through a replayable test hook, even in a demo. Every
height, fee, size, hash, and projection row around the secrets is still
byte-for-byte deterministic.

**The composability point of this example:** SLP does not care what
scriptPubKey shape a token's holder output has. Examples 04 and 05 each
show one overlay in isolation; this example spends a token-carrying coin
into a P2SH HTLC output (still just an OP_RETURN + a value output to
`connect_block`) and later spends that HTLC output back out with a fresh
SLP SEND OP_RETURN attached to the settlement transaction. The projection
(`db_zslp_transfer_list_by_token`) shows an unbroken GENESIS -> lock-SEND
-> settle-SEND chain, proving the token's identity survives moving
through a hash-time-locked contract exactly as it would through a plain
P2PKH transfer.

## Key APIs used

| API | File |
|---|---|
| `slp_build_genesis`, `slp_build_send`, `slp_parse`, `struct slp_message` | `contexts/market/modules/zslp/include/zslp/slp.h` |
| `explorer_index_apply_slp`, `db_zslp_token_find`, `db_zslp_transfer_list_by_token` | `contexts/explorer/models/include/models/explorer_index.h`, `contexts/market/models/include/models/zslp.h` |
| `znam_build_register`, `znam_build_set_text`, `db_znam_find`, `db_znam_text_get` | `contexts/naming/modules/znam/include/znam/znam.h`, `contexts/naming/models/include/models/znam.h` |
| `explorer_index_block` | `contexts/explorer/models/include/models/explorer_index.h` |
| `htlc_build_script`, `htlc_generate_secret`, `htlc_extract_secret`, `htlc_build_redeem_scriptsig`, `htlc_build_refund_scriptsig` (via `script_id_from_script`/`script_for_p2sh`) | `core/modules/script/include/script/htlc.h` |
| `simnet_init`, `simnet_use_seed_tape`, `simnet_mint_coinbase`, `simnet_spend`, `simnet_mint_to_height`, `simnet_tip_height`, `simnet_free` | `engine/modules/sim/include/sim/simnet.h` |
| `simnet_mempool_add`, `simnet_mempool_mint`, `simnet_mempool_size`, `simnet_mempool_reject_name`, `SIMNET_MEMPOOL_REJECT_NONFINAL` | `engine/modules/sim/include/sim/simnet_mempool.h` |
| `simnet_wallet_default_fee_rate` | `engine/modules/sim/include/sim/simnet_wallet.h` |
| `sha3_256` (macro for `zcl_sha3_256`) | `core/modules/crypto/include/crypto/sha3.h` |
| `transaction_init`, `transaction_alloc`, `transaction_compute_hash`, `transaction_serialize_size`, `transaction_free`, `fee_rate_get_fee` | `core/modules/primitives/include/primitives/transaction.h`, `core/modules/core/include/core/amount.h` |

Ground-truth references this file was built from: `docs/examples/04_zslp_token.c`,
`docs/examples/05_znam_names.c`, `docs/examples/06_htlc_swap.c`,
`tests/harness/src/test_simnet.c` (sections 6-7), `tests/harness/src/test_simnet_txkit.c`,
`docs/SIMULATOR_TXNS.md`.

## Production counterpart

- **Mint the deed** — `zslp_createtoken` (`contexts/market/controllers/src/zslp_controller.c`)
  builds the exact `slp_build_genesis` OP_RETURN this example built by
  hand; `z23 app tokens list` reads it
  back.
- **Claim the storefront** — `name_register`
  (`engine/controllers/src/name_controller.c`, `z23 rpc name_register`)
  wires REGISTER end to end today. UPDATE/SET_TEXT are assembled the same
  way (`znam_build_update`/`znam_build_set_text` plus a normal transparent
  send) but have **no dedicated RPC yet** — see
  `docs/examples/05_znam_names.c`'s production-counterpart note for the exact
  gap; this example builds those transactions by hand for the same reason
  05 does.
- **Direct sale** — `zslp_send` moves the token; the payment itself is an
  ordinary wallet send. Both go through the normal transparent
  broadcast path in `contexts/wallet/controllers/src/wallet_controller.c`, exactly
  like this example's plain payment transaction.
- **Escrow sale** — `swap_initiate` / `swap_participate`
  (`engine/controllers/src/swap_controller.c`, `z23 app swap initiate` /
  `z23 rpc swap_participate`) build the same `htlc_build_script`
  contract this example built by hand. **Gap, same as example 06:** there
  is still no node-broadcast redeem/refund/settlement path today — an
  operator currently settles the P2SH address by hand (e.g. raw-transaction
  RPCs via `z23 rpc`), the way this example settles it directly against
  `simnet`.
- **File delivery** — once a buyer resolves the storefront `.onion`
  address above, the actual asset bytes ship over the P2P file market's
  chunk service (`fs_send_chunk_fast`), unlocked only after a
  mempool-verified payment txid (`handle_zfilepay` in
  `core/modules/net/src/msgprocessor.c`) — the same "pay, then receive" shape as
  this example's direct sale, at the byte-transport layer instead of the
  token layer. The seller offer command (`z23 app market offer`)
  signs, binds, and announces paid offers; the optional one-shot buy
  coordinator (`z23 app market buy`) remains planned — see the
  Vision section of `CLAUDE.md` for the current Market coverage
  boundary.
