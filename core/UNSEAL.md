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

- 2026-09-10T19:55:26Z — REASON: Linear replay of MagicBean getblocks immediate-inv onto origin/main after GitHub rejected merge commits; no consensus predicate change
  old ROOT: e7852a59d4b3bfa47dffae9b2ffe012b6895416061a42b995b8945d99fd49bf7
  by: owner unseal ritual (make core-unseal)

- 2026-09-11T00:45:19Z — REASON: Move the getheaders serve budget and deferred replay into core/modules/net/src/msg_getheaders_defer.c so msg_headers.c returns under its shrink-only 2370-line baseline (landing seq 4 failed check-file-size-ceiling at 2506); pure move, no behaviour change; two refute rounds already passed on the logic; owner authority grant 2026-09-10 22:4xZ
  old ROOT: 2213de3b6c315a9e909389540be2319917c6d5a75c8186afdd04ad141b049fb4
  by: owner unseal ritual (make core-unseal)

- 2026-09-13T18:51:41Z — REASON: C3: eliminate O(batch*queue) duplicate-forward scan while preserving exact download policy and accounting
  old ROOT: 190e3ac75aed53b58b4cc19b6c82bb720fca826bea5080ff075f5e00cc39df1b
  by: owner unseal ritual (make core-unseal)

- 2026-09-13T19:25:23Z — REASON: C3 repair follow-through: move the download qset membership set into core/modules/net/src/download_qset.c so the shrink-only file-size and complexity ratchets stay satisfied; no behavior change
  old ROOT: d65d7f3bcfb45cfdf21d683e48997ee2a695fa8c119e677891a53b1a0ff3e01d
  by: owner unseal ritual (make core-unseal)

- 2026-09-13T19:26:15Z — REASON: re-seal to include the newly tracked download_qset.c/.h from the C3 qset split; same tree content
  old ROOT: 52cb6823b358e979e5db21caf7a0332d2bb70f1e2edd1dc9c1d36f7dc184ec84
  by: owner unseal ritual (make core-unseal)

- 2026-09-13T20:51:17Z — REASON: slice3: dedup P2P block intake ring by hash before slot alloc (1024-slot starvation)
  old ROOT: cd9b049fca58ade90a06d989285ad0ee63f8f7f1b66ed6ac91935a4aed4e5fab
  by: owner unseal ritual (make core-unseal)

- 2026-09-14T02:25:42Z — REASON: ACTIVE1 dl received-pending tombstone in core/modules/net download accounting (already reviewed+tested f6705235fd)
  old ROOT: a13489b1ee0f1a5d4fcbfb0f1d05e497c81ce3fb616782580daa305eb1ecc9ab
  by: owner unseal ritual (make core-unseal)

- 2026-09-14T10:53:01Z — REASON: c5-dynhost-post-client
  old ROOT: fffed5da03d6bce0933d89209fc4ba2ad7077b9c1d94452f0d173ca426014017
  by: owner unseal ritual (make core-unseal)

- 2026-09-14T21:14:03Z — REASON: difficulty_from_bits used Bitcoin's -29 shift base instead of ZClassic powLimit compact exponent 0x1f; historical-block RPC/explorer difficulty rendered 256^2 off (min-diff bits 0x1f07ffff showed 65536.0, legacy 1.0). Display-only math (RPC/explorer/netsplit ratios), not a consensus predicate. Owner unseal grant 2026-09-14 in reply to explicit request.
  old ROOT: 4bf80625c80f0352d8bfb38bee64ff0a94c73045272f64f528fd53f5be6474c9
  by: owner unseal ritual (make core-unseal)

- 2026-09-19T00:28:09Z — REASON: zblkreq: cap block-swarm piece requests at each peer's own advertised manifest end; stops fresh nodes being banned for asking past a shorter manifest. Server scoring unchanged.
  old ROOT: c3090fae6b449bd80dc449c365caa0d452a626402d0deb8c8a77c66f6eafcdf7
  by: owner unseal ritual (make core-unseal)

- 2026-09-28T03:17:26Z — REASON: Owner-authorized repair of Blue Sapling core drift landed in 3b22d6564: preserve existing scalar and signer behavior after differential parity review, then reseal the two changed sources and hot-swap mirrors
  old ROOT: c43d389c6cccac48942d3ad3ccc61575738377d155d4dee1d1435f9ba8aaf35f
  by: owner unseal ritual (make core-unseal)

- 2026-09-28T15:02:15Z — REASON: Owner-authorized Darwin file-service shutdown repair: promptly sever active ROM transfers while preserving worker-owned closes; no consensus predicate or validity table change; exact Darwin rom_fetch and consensus_parity passed on 4bdefb32dfaa5754d51c0d11147704fc5a0e5424
  old ROOT: 1dec53ee652d5947bd3961c1d97e6d4b48b710d57f49ab4ff840f7301e79147a
  by: owner unseal ritual (make core-unseal)

- 2026-09-28T15:45:19Z — REASON: Independent review follow-through for Darwin file-service stop: single listener close owner and serialize worker cleanup after server spawn failure; no consensus predicate change
  old ROOT: 730341af543447204de33edf85ec60fa51d704a8daaf5aa71680557053cad7d3
  by: owner unseal ritual (make core-unseal)

- 2026-09-28T15:54:17Z — REASON: Darwin RED follow-through: shutdown on listener does not wake accept; poll-gate accept with bounded stop latency, preserve sole listener close ownership and synchronous stop callers
  old ROOT: 8a30385fd545923d5fb508635e9826f0eea52c72d9837a94c374efc27bd3c2ce
  by: owner unseal ritual (make core-unseal)

- 2026-09-29T15:06:00Z — REASON: Owner-authorized 2026-09-29 mutual-dial tie-break: both sides keep the dial of the lower Noise static key; the loser stops redialing; plaintext/unauthenticated behaviour, consensus, scoring and resource bounds unchanged
  old ROOT: 5e0f367a0c46e3cc9df0fcb9ba095d3c8d0b70ccefee86040d51f33659473289
  by: owner unseal ritual (make core-unseal)

- 2026-09-29T16:44:10Z — REASON: tie-break test gaps M7/M8 and comment placement in connman dial
  old ROOT: 57176e528a23b4587fa91c568f633f98a0857ad6aa7d40810f09488f2f88ea3a
  by: owner unseal ritual (make core-unseal)

- 2026-10-09T02:06:34Z — REASON: integrate contributor PR 81 (cmpctblock stash OOM must not build getblocktxn from NULL indices) and PR 90 (version time-offset signed-overflow UB); owner grant 2026-10-08 in reply to explicit request
  old ROOT: 3d23199cc01202162814d2179fc67c629d93058a2b4b5ec254461e075e16e099
  by: owner unseal ritual (make core-unseal)

- 2026-10-12T03:12:30Z — REASON: SHA-3 working-state wipe in platform sha3 changes the dependency root pinned in core/modules/crypto/zcode-package.json; pin re-derived, no core source changed; lead re-seal under owner grant 2026-10-06
  old ROOT: f437547f9ba53fc14a5fbcb071af3d61a5acc740a4254bfccbe0f909f688656c
  by: owner unseal ritual (make core-unseal)

- 2026-10-12T06:52:15Z — REASON: Noise handshake deadline: noise_transport_handshake_expired and the 15 s sweep branch in connman; lead re-seal under owner grant 2026-10-06
  old ROOT: b3b32fcf4fbebeea81152d02d2632c9deed1799352d60e1e93bfca2be4471564
  by: owner unseal ritual (make core-unseal)

- 2026-10-12T16:34:56Z — REASON: Hybrid Noise_XXhfs pattern with ML-KEM-768 tokens in the noise handshake library, with review fixes; lead re-seal under owner grant 2026-10-06
  old ROOT: 0c8b1a99386821f0c66a594965ff026bd3787f72a32fad0aa839ca00e98c16be
  by: owner unseal ritual (make core-unseal)

- 2026-10-14T08:43:49Z — REASON: Node links handshake with hybrid X25519+ML-KEM-768 Noise XXhfs: transport driver uses noise_pattern_xxhfs, prologue version 0x03 suite 0x02, pattern-derived handshake lengths
  old ROOT: 2448a30172f00ee8a13b099265a24a1900eda9a6bf0481549933b609f68f70bc
  by: owner unseal ritual (make core-unseal)

- 2026-10-14T09:35:47Z — REASON: Correct handshake suite name in the noise_transport comments to Noise_XXhfs
  old ROOT: e96b4f94650c1cfc7aa3c9841590e9c5b68ac00fec44e6c1579a2a245953b9c0
  by: owner unseal ritual (make core-unseal)

- 2026-10-14T09:55:07Z — REASON: Service bit 26 NODE_NOISE_HYBRID gates the outbound Noise handshake; bit 25 retired
  old ROOT: 6c4bfa22cbcd64be0f7b3ba63079ac84fa41818570c80cf0260af38ebdebb75c
  by: owner unseal ritual (make core-unseal)

- 2026-10-14T10:12:52Z — REASON: Export noise_transport_handshake_msg_len so tools derive the hybrid first-message length from the pattern
  old ROOT: f8fb7844dc9bdbcea1da87d362cbf8b871821feccfc7565137e8e1aabd865ed2
  by: owner unseal ritual (make core-unseal)

- 2026-10-14T10:41:30Z — REASON: Bound noise_transport_handshake_msg_len to the pattern message count
  old ROOT: 8b5071ca8f1b0461a49415ea9c8caaf136bb04813b2679e3b37e947120199034
  by: owner unseal ritual (make core-unseal)

- 2026-10-14T18:37:44Z — REASON: Close plaintext links to bit-26 peers after the version exchange and drop plaintext answers to Noise dials
  old ROOT: f87c32240baece368b8380f1f761f943acba6aea39c14079134774893f12e538
  by: owner unseal ritual (make core-unseal)

- 2026-10-14T20:11:32Z — REASON: Quarantine plaintext inbound links from bit-26 peers until the dialer upgrades
  old ROOT: ecef828a7c16dacc309c82a33ae08bfc9005124ca731a53cb3fa70529e7c0e28
  by: owner unseal ritual (make core-unseal)

- 2026-10-14T22:47:31Z — REASON: Quarantine plaintext inbound links from bit-26 peers until the dialer upgrades
  old ROOT: 8320d67a5ccc0e220f0177df882b7573505a921b545295ee076aadb731a61bac
  by: owner unseal ritual (make core-unseal)

- 2026-10-15T05:17:49Z — REASON: Metadata-only tunnel SHA3 dependency integration on published plugin/network base bb0a6f6; existing owner grant claude-laptop20534 and checkpoint order20813; dependency root1b3367c246712769a812464153dacfda27eb03ed3705e73370a03805524d025d unchanged from reported grant; no core implementation edit
  old ROOT: 1288a6fed3f3bac8627269f4f6ca089e92a104445e331874296af53a1067af90
  by: owner unseal ritual (make core-unseal)

- 2026-10-15T21:11:14Z — REASON: owner-authorized 2026-10-15: public /wiki site route row; lock node->transport read in zcl23 dial
  old ROOT: 70e00ae0e4a629f895c917fc3c4e9f3b351489d4f94446b449ebcb409b7ddea9
  by: owner unseal ritual (make core-unseal)

- 2026-10-19T11:03:57Z — REASON: repin zclassic23/sha3 package root after a byte-identical Keccak/Wrap speedup (lanes state + unrolled rounds); proven by unchanged KATs, a 1000-case differential against the old implementation, and consensus parity
  old ROOT: 3a3baaab8b5652ad665b1476c79d778f50583daaf6371004f7a5b604e9279ec8
  by: owner unseal ritual (make core-unseal)

- 2026-10-20T01:02:33Z — REASON: bake checkpoint ladder rung @3200000 (owner-approved 2026-10-19; two-builder byte-identical; adds bundle trust in a newer state root, no validation predicate change)
  old ROOT: fa84ef23b919ecd72edde14eb4c9dfb8a87a8258c587464494dbf4a828c6a4b6
  by: owner unseal ritual (make core-unseal)

- 2026-10-20T01:29:24Z — REASON: state-offer freshness exemption generalised from the keystone height to any baked ladder rung height so a fresh node can be offered the h=3200000 bundle; no block/tx/header/difficulty predicate touched (owner-approved 2026-10-19 fresh-checkpoint activation)
  old ROOT: 4d3c4f6ded95fa9b5d1426901b531094cae5ef6e3d497555c9c22cd44d6e84d9
  by: owner unseal ritual (make core-unseal)

- 2026-10-23T11:11:32Z — REASON: ff1: stream the CBC-MAC over P||Q so a tweak longer than the fixed 256-byte staging buffer is encrypted instead of silently returned unchanged; ZIP 32 (empty tweak, 88 bits) output byte-identical
  old ROOT: 1611ae4fe96c2add865ebf0c0d4d90491530af7bb41912b7efd205bc8d3585c0
  by: owner unseal ritual (make core-unseal)

- 2026-10-23T10:48:37Z — REASON: Ed25519/X25519 speed: replace the 16x16-bit TweetNaCl field with a radix-2^51 field (and faster double-scalar mult) without changing any accept/reject result; proven against the frozen-oracle differential test. Owner crypto+AVX directive 2026-10-23.
  old ROOT: 8f5d93d9c5349a95f231bb681368c44f59a343444b47ad8075a98f2299e3fb86
  by: owner unseal ritual (make core-unseal)

- 2026-10-23T10:51:24Z — REASON: ChaCha20 AVX2/AVX-512 keystream tiers with runtime CPU dispatch and one-time portable-oracle KAT; AUTO picks the fastest verified tier on x86-64 from measured bench evidence. Output byte-identical to the portable tier. Owner crypto+AVX directive 2026-10-23.
  old ROOT: 2d1d5231a69242b07cf482cd2f7f14927eb30610d44bf056fae60697b15257b6
  by: owner unseal ritual (make core-unseal)

- 2026-10-23T12:43:41Z — REASON: perf(sapling): branch-free BLS12-381 fp_add/fp_sub/fp_neg (behaviour-preserving; differential vs frozen oracle)
  old ROOT: eb01e833cccbf2862b1bdb172b12a8548a40575b9c741605914915dc44b186cb
  by: owner unseal ritual (make core-unseal)

- 2026-10-23T15:04:26Z — REASON: BLS12-381 final exponentiation: Granger-Scott cyclotomic squaring inside exp-by-x (behaviour-preserving, frozen-oracle parity); lead unseal under owner grant 2026-10-19
  old ROOT: 8a374a230643da484419e06ad703a6c429c7e971b812d01be0b87432a220b78e
  by: owner unseal ritual (make core-unseal)

- 2026-10-23T16:20:03Z — REASON: block_map buckets drop the duplicated 32-byte key (compare against index->hashBlock): about -320 MB node memory, same slots, same iteration order, no consensus logic change
  old ROOT: 6c26eea8b8ada9f6784757204ac27576890e7b35ea6f93245c47c238455895bf
  by: owner unseal ritual (make core-unseal)

- 2026-10-23T23:21:43Z — REASON: chain.h: drop struct block_index.nTimeReceived, a field with no reader or writer anywhere in the tree (8 B per block index entry, ~25 MB at mainnet height); layout-only, no consensus predicate or on-disk format reads it
  old ROOT: 5acb8dd0ba8959a3dfb47502c3e875e2599e7768657dd6028b143d85658e6d9e
  by: owner unseal ritual (make core-unseal)

- 2026-10-23T22:58:42Z — REASON: tor_fetch: the blocking onion fetch wait returns as soon as process shutdown is requested instead of polling out its full timeout (shutdown latency; no consensus effect)
  old ROOT: 5acb8dd0ba8959a3dfb47502c3e875e2599e7768657dd6028b143d85658e6d9e
  by: owner unseal ritual (make core-unseal)

- 2026-10-23T21:41:38Z — REASON: bls12-381 groth16 verify: precomputed G2 lines for fixed VK points and a shared-f multi-Miller loop (speed only, GT result bit-identical)
  old ROOT: 5acb8dd0ba8959a3dfb47502c3e875e2599e7768657dd6028b143d85658e6d9e
  by: owner unseal ritual (make core-unseal)

- 2026-10-24T02:22:51Z — REASON: bls12-381 subgroup membership: endomorphism tests psi(P)==[x]P on G2 and phi(P)==-[x^2]P on G1 replace [r]P==O (exact membership tests, verdicts identical, speed only)
  old ROOT: 2ac9589bcb3e6b5b28fe2ce70434a6ebf4bf98b6c053a2b9a7f95f3eb8731b03
  by: owner unseal ritual (make core-unseal)

- 2026-10-24T04:34:44Z — REASON: block_index memory: move hashMerkleRoot, nNonce and nSolution into an optional header extension (288 -> 216 B per entry, ~238 MB at 3.3 M entries); behaviour-preserving accessors
  old ROOT: 8444fcd78413a251d62790a796df372366d80b5ca0961dcf9c4ebed364fb66ec
  by: owner unseal ritual (make core-unseal)

- 2026-10-24T06:54:13Z — REASON: sha256 arm: load only the 64-byte input block (Mac 1498aa303, owner-authorized patch 49e873ab)
  old ROOT: f83556b599fe9da3b18f21ade88a2a6805c1a18bf69a9651489f32ab9976a85d
  by: owner unseal ritual (make core-unseal)
