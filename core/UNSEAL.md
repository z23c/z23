# core/ UNSEAL log — append-only owner ritual record

The top-level `core/` tree is the **sealed consensus core**: the predicates and
static, height-keyed parameter tables that decide whether a block/tx is valid.
Its byte-integrity is pinned by `core/MANIFEST.sha3` (a SHA3-256 manifest, see
`tools/core_seal.c`) and enforced by the `check-core-seal` lint gate.

**Sealed ≠ frozen.** Consensus-parity fixes still ship routinely — they just may
not go through the autonomous fast path. A deliberate change to a sealed file
requires the unseal ritual below; only the unattended/agent fast-path is
structurally refused.

## The unseal ritual

```
make core-unseal REASON="why this consensus-core change is needed"
#   → appends a dated entry to this file (old ROOT hash + reason)
#   → writes .core-unseal-token (gitignored) that `make core-seal-check`
#     honors for exactly one commit
# ... make the sealed-core edit ...
make core-seal        # re-freeze the manifest (also consumes the token)
make lint && make test_parallel   # must land green, incl. test_consensus_parity
git commit            # the reseal + the edit land together
```

The token authorizes the seal check to tolerate drift for the single commit that
introduces the change; `make core-seal` re-freezes and removes it. No agent can
mint this token as a normal source edit — it is an owner-run make target (v1.1
upgrades this to an ed25519 owner signature so consent cannot be forged).

`check-core-seal` is in **WARN/ratchet** mode until core-split wave W5, when a
later lane flips it HARD.

---

## Log

<!-- UNSEAL-ENTRIES (newest appended below; append-only, never edit past entries) -->

- 2026-07-15T19:23:20Z — REASON: re-bake corrupt SHA3 checkpoint constants, owner-approved plan wave2 W2-1
  old ROOT: 6d07d92fd9a468edd93e6f17c8825149b38e190f7df8569f077b9f0bd2b15abe
  by: owner unseal ritual (make core-unseal)

- 2026-07-18T02:31:25Z — REASON: bake shielded ROM keystone @3056758 (two-builder-verified, lane draft)
  old ROOT: 9a7e1d6a264827ccad27333695bd80557449ea7a6e75789b91c860e927b486cd
  by: owner unseal ritual (make core-unseal)

- 2026-07-18T03:06:01Z — REASON: record two-builder gate PASS in keystone provenance comment
  old ROOT: 9b922e9fcad73991469b4cef4941119f3a3e0a2eb3ab7e997478e99f2356ea94
  by: owner unseal ritual (make core-unseal)

- 2026-07-25T02:04:04Z — REASON: C23 __VA_OPT__ conversion: replace the GNU comma-swallowing ', ##__VA_ARGS__' extension at the two core/consensus sites so the tree compiles under a second compiler. Preprocessor-only, line-count preserving; proven by byte-identical stripped binary + consensus parity group.
  old ROOT: 016af0ada9b91d737137332fc6f800d18d0f60ece5533a13ddc7fff347236f84
  by: owner unseal ritual (make core-unseal)

- 2026-08-12T23:12:15Z — REASON: Bound reindex UTXO cache memory and account validation cache growth
  old ROOT: 0b33151affcd213878211c48cffdc4d959b1bbb03cccc9ff4051c8bc0c7257ca
  by: owner unseal ritual (make core-unseal)

- 2026-08-26T04:13:44Z — REASON: seed bootstrap: the only hardcoded onion seed was down (5/5 no-descriptor from two independent Tor clients, re-confirmed by the integrator); replace with a re-verified first-party seed, drop clearnet seeds booked at the testnet port and one dead address
  old ROOT: 140f4b8914457b24b9ae9d412b58bc961032a736718672fe4475ee4fb5f1c1e6
  by: owner unseal ritual (make core-unseal)

- 2026-09-01T11:02:53Z — REASON: Owner-requested physical architecture migration; move unchanged consensus sources into their single authority and regenerate path-bound seal metadata
  old ROOT: a1533630bda2379889f9db262f81cd6e265ad474f642a1ee7d1de9523ac3b1aa
  by: owner unseal ritual (make core-unseal)

- 2026-09-01T13:23:45Z — REASON: Integrate verified origin/main chainstate snapshot changes after the physical architecture migration; preserve upstream behavior and refresh the path-bound seal
  old ROOT: fc01b45b7d14af9160cb5a93293ec17385cdcdbc7a1539042784452188bc2a57
  by: owner unseal ritual (make core-unseal)

- 2026-09-01T15:03:44Z — REASON: Add ARMv8.2 FEAT_SHA512 acceleration with fail-closed portable differential parity; optimize execution without changing SHA-512 output or consensus predicates
  old ROOT: d43b2c5210cce4204ba55336027cdab44326b493a5238cd79edd606a80a07f03
  by: owner unseal ritual (make core-unseal)

- 2026-09-02T09:42:14Z — REASON: refreeze for net/download split, sync perf and Windows headless sync commits already on main (3c459730c 7dcf7c838 bf230b881 edc64cdc6 36b72395d); owner authorization 2026-09-02
  old ROOT: 55641c2b6f2b8588a9e377400b6d8ff603c4e42a59d2f3bbe6fac42aeb9ee4d9
  by: owner unseal ritual (make core-unseal)

- 2026-09-02T11:40:58Z — REASON: Bound owner-requested post-Bubbles Equihash mining cancellation without changing solution generation or validity
  old ROOT: eb2d4c960bff0c1b46f3991aa030d7bc01de00b599edb41a65ea657953a0388d
  by: owner unseal ritual (make core-unseal)

- 2026-09-02T13:33:48Z — REASON: Separate locally validated block-piece serving from fail-closed UTXO snapshot export authority; no consensus predicate change; owner requested fast Z23 block serving on 2026-09-02
  old ROOT: 797012844b6ac9b663475a39f8097a8218491da16ff58e2a613cf3256c73ba3a
  by: owner unseal ritual (make core-unseal)

- 2026-09-03T04:46:03Z — REASON: Optimize the owner-requested 3M-block Windows block-swarm scheduler without changing consensus or block validity
  old ROOT: 8b8b8313fd5089603921022dba89c0477bbc440d5c9bd9bae1dcfa21d2cd2a8b
  by: owner unseal ritual (make core-unseal)

- 2026-09-05T17:23:18Z — REASON: disarm the ALPN challenge once validated so renewal needs no restart
  old ROOT: d603fa3418cbfb7ad75154d2cfcb1ba38c3f104c3d415c7026a98abca75a3446
  by: owner unseal ritual (make core-unseal)

- 2026-09-06T03:37:19Z — REASON: Reseal after fast-sync state-offer additions to core/modules/net (24b6b4be3, 09f04fe20, 22684b47c)
  old ROOT: d70cca70fed110bfb5183c84c3ec10c6788628d051a5d927271a3a1b36024166
  by: owner unseal ritual (make core-unseal)

- 2026-09-06T19:29:27Z — REASON: reseal https_server_install.c land
  old ROOT: 45b721d0466f435e5d7c3c3f59fb61a8aad6a7c485aa6677fbcddb69b31fdf99
  by: owner unseal ritual (make core-unseal)

- 2026-09-06T14:11:00Z — REASON: checkpoint-bound state offers never go stale (owner-authorized 2026-09-06 14:05Z, fast sync)
  old ROOT: 30e82cac24cf9fb5f44c2e8de1af6d7fec714eae51c7a827e7809f35ba648a54
  by: owner unseal ritual (make core-unseal)

- 2026-09-06T21:22:07Z — REASON: reseal after the /install.sh site route landed in core/modules/net (train 44 pick z23install d572fce02)
  old ROOT: 6abf47d15167be4d6f33502201d0cc10f3ea9441a14140be15eb9288932b30a8
  by: owner unseal ritual (make core-unseal)

- 2026-09-10T13:52:50Z — REASON: Serve zclassicd beta6 NODE_BOOTSTRAP fast-sync in-band on the P2P port (owner-authorized 2026-09-10: legacy users stuck in multi-day IBD because both compiled bootstrap peers now answer with z23, which never advertised the bit)
  old ROOT: 8cb852f047f29eef74b6744c5be9e1dfb2c01838dadabce7a5e10ea4f5a69b7f
  by: owner unseal ritual (make core-unseal)

- 2026-09-10T15:08:38Z — REASON: legacy MagicBean getblocks: send inv immediately and announce only HAVE_DATA bodies
  old ROOT: 8cb852f047f29eef74b6744c5be9e1dfb2c01838dadabce7a5e10ea4f5a69b7f
  by: owner unseal ritual (make core-unseal)

- 2026-09-10T15:58:55Z — REASON: Split the beta6 fast-bootstrap seam and the BIP37 filter refusals out of msgprocessor.c into msg_beta6_bootstrap.c and msg_bloom_filter.c so the shrink-only legacy file returns under its 3031-line ceiling; dispatch rows, semantics and behaviour unchanged (owner-authorized beta6 sealed edit of 2026-09-10)
  old ROOT: e4fd36edb426d883959c7130a384435e72cdbdb66b5db2afb55b6c6a7fdf0482
  by: owner unseal ritual (make core-unseal)
