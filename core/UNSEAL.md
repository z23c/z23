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

- 2026-10-24T08:04:37Z — REASON: privacy switches for contributor nodes: -onlynet=onion makes no clearnet P2P dials and imports no clearnet endpoints from onion directories (default off, unchanged behaviour without it); P2P dial policy only, no consensus predicate
  old ROOT: 11c7929713c61c213e23d09fd7c2e2d2d741ce99bebbfd6b60c8e114f5f71e9f
  by: owner unseal ritual (make core-unseal)

- 2026-10-25T11:45:45Z — REASON: compact block index U1: block_map bucket 16 B to 8 B (pointer only, key read from the resident node); behaviour-preserving, lookup semantics, probe order, iteration order and hash function unchanged; no consensus predicate
  old ROOT: 56f9c50e7c396173f271a7c8487ba811e736a742f5207394fa733fb83485ff4c
  by: owner unseal ritual (make core-unseal)

- 2026-10-25T16:26:37Z — REASON: ZIP-209 Sapling pool parity: the per-block Sapling delta is -valueBalance (zclassicd ConnectBlock saplingValue += -tx.valueBalance); core added +valueBalance. Latent (runs only when the chain Sapling value is known; the live node stores 0). Oracle h=476977: valueBalance -1 ZCL, chainValue +1 ZCL. Owner-approved 2026-10-25.
  old ROOT: bf8be6cf014cd435e26209f319eb5f9cd13ab8dadfae0a9d6fa0b01d198f8af9
  by: owner unseal ritual (make core-unseal)

- 2026-10-26T21:48:23Z — REASON: Owner-authorized 2026-10-26: default-off https_server_set_front_paths so a site node can point the browser root and /start elsewhere; existing behaviour unchanged when unset
  old ROOT: bfa2e068bab92e18f15eb5be151823feb8b6929dd6e902d59161a61256840681
  by: owner unseal ritual (make core-unseal)

- 2026-10-26T22:05:12Z — REASON: Owner-authorized 2026-10-26 front-paths change: move the helpers from https_server.c to https_server_install.c to stay under the 1500-line file cap; no behaviour change
  old ROOT: e20033051bbd1bad0804e1251d0a746800e3b52d56b0a7682066959216539fd1
  by: owner unseal ritual (make core-unseal)

- 2026-10-27T00:10:19Z — REASON: Owner-authorized 2026-10-26 front-paths change, review fix: a browser GET / goes to -site-home before a public-install tree's install.sh (default unchanged when unset)
  old ROOT: f6650cbb5da2db5d4f71da632fbd112b0fffbd5e49b9a722032392c9c15d87ba
  by: owner unseal ritual (make core-unseal)

- 2026-10-28T20:13:58Z — REASON: Owner authorized 2026-10-28 narrow Pixel mempool and tip-finalization deadlock repair with independent review and regression tests; validation predicates unchanged
  old ROOT: 732b7c8429b23432a3e9fa340ba6fb9b554a87331eed6d83105cd501c80ffeb1
  by: owner unseal ritual (make core-unseal)

- 2026-10-29T11:51:34Z — REASON: Owner-authorized 2026-10-19 hardening program, behaviour-preserving: core wave 1 complexity splits of 9 functions in 5 tier-A net files (acme_b64url, acme_selfsigned, acme_arm_file, https_server_redirect, rom_seed_policy); no validity predicate touched; Sonnet writers, Sonnet non-author reviews
  old ROOT: 21061f6194fbaed2abae7d60072b91ed8f762681c53a8544245399bf8505b80f
  by: owner unseal ritual (make core-unseal)

- 2026-10-29T12:19:33Z — REASON: core hardening wave 2: behaviour-preserving complexity splits of 8 tier-A net files (addrman_codec, rom_seed, tor_integration, onion_ratelimit, file_market_offer, onion_directory, onion_identity, netbase), lead reseal
  old ROOT: f6e5e9b15d5cf0976fd5ca073ba7715b054c417e98e442bd4a36be583e7cb5ae
  by: owner unseal ritual (make core-unseal)

- 2026-10-29T12:47:17Z — REASON: core hardening wave 3: behaviour-preserving complexity splits of 8 tier-A net files (rom_fetch, file_service_transport, file_market, file_market_delivery, addnode_file, anchor_peers, addrman_integrity, netaddr) plus tor_integration log use-after-free fix, lead reseal
  old ROOT: 266bc904a81facc8b915b135cef4c877909130cf84ad232f710a42681de98a21
  by: owner unseal ritual (make core-unseal)

- 2026-10-29T13:33:35Z — REASON: core wave 4: behaviour-preserving complexity splits of 5 net files (v2_identity, file_market_delivery_client, onion_seed_race, zdir_selection, p2p_game)
  old ROOT: 9357ba046418185c30320c966da6b5805f9ad7ae3457f17cd4ef3d55607bb0e7
  by: owner unseal ritual (make core-unseal)

- 2026-10-29T14:07:01Z — REASON: send real MIME types from core net HTTP replies (onion_service, https_server, file_market_delivery_onion): the 10-12 rename wrote engine/application/*; header strings only, no consensus code
  old ROOT: 99190a8e93e755171d522ceb41ad73839ab52ed40501267efe3f5602c8c372fe
  by: owner unseal ritual (make core-unseal)

- 2026-10-29T14:19:01Z — REASON: core wave 5: behaviour-preserving complexity splits of 6 net files (file_market_delivery_onion, file_market_payment, nat, onion_stream, https_server, onion_service)
  old ROOT: d2c03c7da5594351d12091fb18d539c3ecff41d55bb7075584f8d3395b38b45d
  by: owner unseal ritual (make core-unseal)

- 2026-10-29T19:03:07Z — REASON: addrman: charge a failed dial against an address at most once until some connection succeeds, and retry a proven peer within a minute while no outbound peer is healthy, so a local network outage (offline, or Android withholding network from a background app) cannot strand the node without peers for hours; directed by the owner 2026-10-29
  old ROOT: e8be97ea47e0f2cc648d2a5c3e247f2a19187dff31821eb8c2f182b5846746c6
  by: owner unseal ritual (make core-unseal)

- 2026-10-29T20:11:38Z — REASON: addrman review fixes: cap a failed dial at one charge per connection epoch only while no outbound peer is healthy, and count every connection as a new epoch; directed by the owner 2026-10-29
  old ROOT: 1171b5099d05b85ec56ccb5c04f608028aadea4d1b7f649750ac04426b6a0af8
  by: owner unseal ritual (make core-unseal)

- 2026-10-30T00:03:15Z — REASON: behaviour-preserving complexity split of 10 tier-A network files (core wave 6): addrman, addrman_codec, dandelion, file_service_handshake, file_service_private_chunk, flyclient, https_server_install, net_listen, onion_stream_telemetry, tor_config_log; no validity decision
  old ROOT: f11519173354f225ec536915da2e06880e87bbdbc7e61205faeaed9a4a164626
  by: owner unseal ritual (make core-unseal)

- 2026-10-30T01:04:33Z — REASON: core wave 7: behaviour-preserving complexity splits and whole-function moves in net (wave 6 + peer_lifecycle incident JSON move + file_service client/self-test move); owner-authorized hardening program, non-author reviews LAND
  old ROOT: 3baddb9856e6afe78e28fddaeb0e2abbb93c9a302ab14ccacafb6365f9ccf798
  by: owner unseal ritual (make core-unseal)

- 2026-10-30T02:01:18Z — REASON: core wave 7 follow-up: file_service_selftest.c compiles to an empty unit without ZCL_TESTING (-pedantic error in dev-bin); add the repo's nonempty-translation-unit typedef
  old ROOT: 4a4bf02911d36d06667f8d8ec03bac0c22c127fda874286d28fb25caf402dc50
  by: owner unseal ritual (make core-unseal)

- 2026-10-30T05:44:52Z — REASON: wave 7: file_service_client.c purpose comment moved above the feature macro (check-file-purpose)
  old ROOT: dd0101eaafbf98e26869d5e303c99d24cbe518d5a1c562381b7be87f705e5e31
  by: owner unseal ritual (make core-unseal)

- 2026-10-30T20:49:17Z — REASON: Owner-authorized 2026-10-30 unseal: Android embedded Tor sets ReducedConnectionPadding 1 to cut idle channel padding wake-ups on phones; circuit padding kept for onion circuit privacy; servers unchanged (byte-identical torrc); no consensus predicate
  old ROOT: 885b73e66178c1b1e1f665830850f05b17939c2d876839135c6b7723fd314d9f
  by: owner unseal ritual (make core-unseal)

- 2026-10-30T23:35:46Z — REASON: Owner-authorized 2026-10-30 unseal: a Tor-ready node turns onion-directory relay hints with a known P2P port into addrman candidates, walks the seed directories once after Tor is ready, and reserves one outbound slot for an onion peer; no consensus predicate, clearnet behaviour unchanged when Tor is off
  old ROOT: cd527dd7479b71f1606b1bdacc957208ca5feb20e8cb1ee632c6f81a3b2bc156
  by: owner unseal ritual (make core-unseal)

- 2026-10-31T05:02:46Z — REASON: compact_blocks.c: split 2 function(s) under the complexity cap;  behaviour-preserving
  old ROOT: 31280c3ea6b838e1de3db361aaae809cb07b57ed3870855203a6eda5602f2bdf
  by: owner unseal ritual (make core-unseal)

- 2026-10-31T05:06:36Z — REASON: connman_dialer.c: split 3 function(s) under the complexity cap;  behaviour-preserving
  old ROOT: a3c24d37cd701b53ef70d5e852bca3dccc924c8dd3699880b50effb58962aa46
  by: owner unseal ritual (make core-unseal)

- 2026-10-31T05:08:08Z — REASON: core/modules/net/src/header_serve_repair.c: split 2 function(s) under the complexity cap;  behaviour-preserving; core/modules/net/src/header_serve_repair.c: split 2 function(s) under the complexity cap;  behaviour-preserving (throttle helper); core/modules/net/src/header_serve_repair.c: split 2 function(s) under the complexity cap;  behaviour-preserving (comment fidelity)
  old ROOT: 11927b8274d8049b699ead31639d1be747a91b2ba181ab8cc2fb1f823bd01fcf
  by: owner unseal ritual (make core-unseal)

- 2026-10-31T09:36:18Z — REASON: sapling consensus parity: reject non-canonical Fr encodings (cm, anchor, Fr == r, Jubjub y == r) exactly as zclassicd's librustzcash does;  closes a split where Z23 accepted an output zclassicd rejects. Owner approved 2026-10-30 ('you have authority, do it').
  old ROOT: d9bd425d5f66793bdf253ce2717af74e90aa19681b561cd2be83d5d37a6048e8
  by: owner unseal ritual (make core-unseal)

- 2026-10-31T09:48:12Z — REASON: sync stage lock order: take progress_store_tx_lock before s->lock in stage_run_once and stage_set_cursor (TSAN lock-order-inversion in test_boot_matrix, 10-30);  behaviour-preserving, no consensus predicate change
  old ROOT: 9bb1a940f2057c9298832184249a06d8143a2617a06b11740493c201b4ad91e1
  by: owner unseal ritual (make core-unseal)

- 2026-10-31T09:57:55Z — REASON: script_num_from_bytes: accumulate in uint64_t so an 8-byte script number (0xff top byte) no longer left-shifts a signed int64 out of range (UBSan, test_script under t-asan, 10-30);  bit-identical results, consensus callers cap at 4-5 bytes
  old ROOT: ac1a3fef849c0598d6aab95265ea3ad47fbfb6c534a2edb4fc7f2f8954e190f8
  by: owner unseal ritual (make core-unseal)

- 2026-10-31T10:02:27Z — REASON: core/net: split 15 networking functions under the complexity cap;  behaviour-preserving, each split gpt-terra LAND, no consensus predicate change
  old ROOT: 13ecbcd25a9e2c0a7f0d45fe61c67515c8bcc0b8f5636d578a52a23b2344db36
  by: owner unseal ritual (make core-unseal)

- 2026-10-31T10:06:59Z — REASON: refactor(connman.c): split 4 function(s) under the complexity cap;  behaviour-preserving, each split gpt-terra LAND, no consensus predicate change
  old ROOT: 8a193556934b96042ebca06feded86699f5a3d799903ee6d0d9f8bcdfa17c024
  by: owner unseal ritual (make core-unseal)

- 2026-10-31T10:11:49Z — REASON: connman.c: move outbound health accessors to a sibling file so the complexity split fits the file-size pin, with the feature-test macros connman.c defines;  behaviour-preserving
  old ROOT: fc5819143011022f63d1ac233ed07c38a0a7e9da5bd29a5202b93462048a3ae1
  by: owner unseal ritual (make core-unseal)

- 2026-10-31T10:14:13Z — REASON: refactor(fast_sync.c): split 4 function(s) under the complexity cap;  behaviour-preserving, each split gpt-terra LAND, no consensus predicate change
  old ROOT: 8bbb4e99da887726d7b2269d3a8812ad893c325283b81d1a49762de8d066335b
  by: owner unseal ritual (make core-unseal)

- 2026-10-31T10:14:34Z — REASON: fast_sync.c: move block_piece_manifest active-chain builder to fast_sync_block_piece_active_chain.c so the complexity split fits the file-size pin;   behaviour-preserving
  old ROOT: b39206f333eb30a3385477c00feb54353fca9e065b484f9f7055651f1918eddb
  by: owner unseal ritual (make core-unseal)

- 2026-10-31T10:15:52Z — REASON: refactor(msg_headers.c): split 6 function(s) under the complexity cap;  behaviour-preserving, each split gpt-terra LAND, no consensus predicate change
  old ROOT: 8a463bd30e5395f1c70f1f6d3c625a3fa1dcb9c5db11e525e7aa068d88101f7a
  by: owner unseal ritual (make core-unseal)

- 2026-10-31T10:16:45Z — REASON: msg_headers.c: move a self-contained function group to a sibling file so the complexity split fits the file-size pin;   behaviour-preserving;  msg_headers_range_parallel.c: add the includes the moved functions need;   behaviour-preserving
  old ROOT: 735bb946ff5f9212ee65cb3e88149f1bca2ec338a61297b02de8648fe7f7327c
  by: owner unseal ritual (make core-unseal)

- 2026-10-31T10:18:28Z — REASON: refactor(msgprocessor.c): split 4 function(s) under the complexity cap;  behaviour-preserving, each split gpt-terra LAND, no consensus predicate change
  old ROOT: c2383fecf531b6933e048281fb991ea81f24d75bd527a669d2d63dc57ba8673d
  by: owner unseal ritual (make core-unseal)

- 2026-10-31T10:21:07Z — REASON: msgprocessor.c: move a self-contained function group to a sibling file so the complexity split fits the file-size pin;   behaviour-preserving
  old ROOT: 52c2a14d9c54b59b7486d85961dabb1fb69472780f4022072fe84989007784e5
  by: owner unseal ritual (make core-unseal)

- 2026-10-31T10:22:30Z — REASON: refactor(net.c): split 5 function(s) under the complexity cap;  behaviour-preserving, each split gpt-terra LAND, no consensus predicate change
  old ROOT: 0e8727eac9e97f10034953a2f611d6ab8d1ac347ff82ecff48c1254d27233d3f
  by: owner unseal ritual (make core-unseal)

- 2026-10-31T10:23:46Z — REASON: net.c: move ban persistence (banlist.dat) to a sibling file so the complexity split fits the file-size pin;   behaviour-preserving
  old ROOT: 35823679a85ecb52ed992815597e41e6c5375f2dbc06e669e2a0c70160f83595
  by: owner unseal ritual (make core-unseal)

- 2026-10-31T10:24:52Z — REASON: core/modules/net/src/connman_onion_seeds.c: split 3 function(s) under the complexity cap;  behaviour-preserving
  old ROOT: c154ccd1fc3452755b78c925cd7564acdcde95c0309911a6a430bc9e4db9ae89
  by: owner unseal ritual (make core-unseal)

- 2026-10-31T10:26:28Z — REASON: https_server: race-free listener fds (TSAN g_http_fd stop vs accept);  behaviour-preserving; https_server: race-free listener fds;  split stop helpers to stay under complexity cap; https_server: review round: pass listener fd by arg, handle shutdown failure; https_server: review round 2: bounded accept wait so stop join cannot hang on shutdown failure; https_server: review round 3: nonblocking listen sockets so accept never blocks; https_server: review round 4: check restore of blocking mode on accepted sockets; https_server: review round 5: drain client queue only after listeners are joined; https_server: review round 6: back off on listener poll errors
  old ROOT: 83d3660fa21e9e18c639f12ef6e0be69e52910a62d4f2d70162d3e5f82be1b36
  by: owner unseal ritual (make core-unseal)

- 2026-10-31T10:28:01Z — REASON: Owner-authorized 2026-10-19 hardening program, behaviour-preserving: move the https_server.c certificate section unchanged into https_server_cert.c so the listener fd-race fix fits the 1500-line ceiling;  no validity predicate touched
  old ROOT: ea2dbcfcba22bee3aee326ffa3038d241d6310e4839420d4a156680e342126dd
  by: owner unseal ritual (make core-unseal)

- 2026-10-31T16:38:08Z — REASON: Split the socket reactor's per-iteration steps out of connman.c; behaviour-preserving, each split gpt-terra LAND, no consensus predicate change
  old ROOT: a401d49d6554176329c7868cc66350b8d4b27b26079585d73a49ffc4edd471b5
  by: owner unseal ritual (make core-unseal)

- 2026-10-31T16:45:38Z — REASON: Split process_inv and process_tx_msg into per-item and relay helpers; behaviour-preserving, each split gpt-terra LAND, no consensus predicate change
  old ROOT: 3799c3da4e7eda73277bcdf7e9f9004b8a61d28cb4c5d09b4daa9b7d00c5bc8d
  by: owner unseal ritual (make core-unseal)

- 2026-10-31T16:48:37Z — REASON: Split process_version and the build identity prefix parser into helpers; behaviour-preserving, each split gpt-terra LAND, no consensus predicate change
  old ROOT: 8f9eb0a082b47744789ccacbd6ced776319a30ea8ce044c536781f20471cbc77
  by: owner unseal ritual (make core-unseal)

- 2026-10-31T16:53:55Z — REASON: Split process_block_msg into intake, accept and relay helpers; behaviour-preserving, each split gpt-terra LAND, no consensus predicate change
  old ROOT: dd429eb15ab28d8dff2031597da23c6167b5610db497bf1923784b95a89aa426
  by: owner unseal ritual (make core-unseal)

- 2026-10-31T17:22:16Z — REASON: review fix on the core-net splits: restore the DoS=0 comment to its own else branch (comment-only placement, no behaviour change)
  old ROOT: 5fbb0edc894ec8957a6338810abc79c3404d6bd5bc5bb2843d8421b3b15216e8
  by: owner unseal ritual (make core-unseal)

- 2026-10-31T18:13:20Z — REASON: duplicate audit fix on the core-net splits: the build identity prefix check reuses build_identity_hex_run with a length parameter instead of a second copy of its loop (behaviour-preserving, owner 10-19 hardening authority)
  old ROOT: 06cd5c203992129d41999286d02900009071a70068d56e0152450b7728a0bbda
  by: owner unseal ritual (make core-unseal)

- 2026-10-31T08:54:54Z — REASON: Owner unseal grant 2026-10-30 (you have authority to unseal core): add a proving-only Sapling-pair path loaded on demand at the first proof of a send (sapling_note_proving_pair_dir, sapling_proving_session_acquire/release, sapling_proving_status, zclassic_sapling_prover_unarm) so a phone holding only the two pinned Sapling proving files can send; same SHA-512 pins, verifying-key prefix check and self-test; no Sprout proving; sapling_init_params first/late loaders, verifying keys and every consensus predicate unchanged
  old ROOT: d9bd425d5f66793bdf253ce2717af74e90aa19681b561cd2be83d5d37a6048e8
  by: owner unseal ritual (make core-unseal)

- 2026-10-31T12:19:02Z — REASON: Owner unseal grant 2026-10-30 (you have authority to unseal core): make Sapling fixed-generator first use thread-safe with pthread_once in sapling.c. TSan showed concurrent first use racing and disagreeing; the Sapling pair self-test on a send thread can enter the same path as validation. Results and consensus predicates unchanged.
  old ROOT: 24987fe04f09e7491ee0b07da08f7c09d53f55d57960920de10929ecc87afdb8
  by: owner unseal ritual (make core-unseal)

- 2026-10-31T19:08:57Z — REASON: Sapling proving pair: read failures report their own reason code instead of the SHA-512 pin code and a standing refusal ends readiness until the refused files change (params_init.c); owner grant 2026-10-30 (you have authority to unseal core), behaviour-scoped, wallet-side proving only, no verifier or consensus predicate touched; lane prove-sapling-pair
  old ROOT: 806115f0f47b525b33ae72dcb9a12443ae57834e48fc85437b7c58bb63679cb5
  by: owner unseal ritual (make core-unseal)

- 2026-10-31T19:18:45Z — REASON: Sapling proving pair review follow-up: sapling_proving_available and sapling_proving_status report not-ready while a refusal stands for unchanged pair files (params_init.c); owner unseal grant 2026-10-30 (you have authority to unseal core), wallet-side proving only, no verifier or consensus predicate touched
  old ROOT: 355e0a349c7b2ee1f9f7bd2ea974e210fd22406e97110e94b55a95a8f9105176
  by: owner unseal ritual (make core-unseal)

- 2026-10-31T21:19:07Z — REASON: Sapling proving pair review follow-up: only lasting refusals (pin, prefix, self-test, missing or forbidden file) stand for unchanged pair files, transient read failures retry; remember-refusal path initialised (params_init.c); owner unseal grant 2026-10-30 (you have authority to unseal core), wallet-side proving only, no verifier or consensus predicate touched
  old ROOT: 86cc2f0444493f991e90fb76ab23feacf84bf7271c54322e589322075acbe2a5
  by: owner unseal ritual (make core-unseal)

- 2026-10-31T21:20:05Z — REASON: records the rebase reseal of the Sapling proving pair commit 1fe947e5ac onto origin/main 3f02a64ffb (ROOT a401d49d, which changed core); written at this time, after the reseal, no sealed file touched by this entry; owner unseal grant 2026-10-30 (you have authority to unseal core)
  old ROOT: a401d49d6554176329c7868cc66350b8d4b27b26079585d73a49ffc4edd471b5
  by: owner unseal ritual record (appended by hand: make core-unseal records only the current ROOT)

- 2026-10-31T21:49:41Z — REASON: Sapling proving pair review follow-up: a failed proving self-test (memory on a phone) is temporary and the next send retries, status says it will retry (params_init.c); owner unseal grant 2026-10-30 (you have authority to unseal core), wallet-side proving only, no verifier or consensus predicate touched
  old ROOT: 467bd9d7f92dbdbc0120b962779eb82efe088dbbef5e402c348f1ab43261be07
  by: owner unseal ritual (make core-unseal)

- 2026-11-01T00:10:56Z — REASON: Sapling proving pair gate follow-up: read the pair files through zcl_read_whole_file so params_init.c holds no write-capable libc call (capability closure), keep the file identity portable to Windows, and let a failed read stand only for a missing, forbidden or non-regular file (params_init.c); owner unseal grant 2026-10-30 (you have authority to unseal core), wallet-side proving only, no verifier or consensus predicate touched
  old ROOT: ad79c439e51554d9605ff666d7a5890b766b1453ccdb4759f07ba60d91aecf5d
  by: owner unseal ritual (make core-unseal)


- 2026-11-01T00:12:25Z — REASON: records the rebase reseal of the Sapling proving pair commit onto origin/main 5c1d134912 (ROOT ab77ad2d, which changed core/modules/net); ROOT before this entry was written: 47c3d39238ae44aa7070e017a059bd642f6b38aecd09d3b7788a7cca9d2145ad; this entry touches no sealed source; owner unseal grant 2026-10-30 (you have authority to unseal core)
  old ROOT: ab77ad2dca2a69f3758177f5bfeb27c2dc19b4e03fc620fcf018674a73b1858e
  by: owner unseal ritual record (appended by hand: make core-unseal records only the current ROOT)

- 2026-11-01T00:44:56Z — REASON: Sapling proving pair: include unistd.h for the access check in pair_unreadable_is_transient (params_init.c); owner unseal grant 2026-10-30 (you have authority to unseal core), wallet-side proving only, no verifier or consensus predicate touched
  old ROOT: d201db1f59cbf926503d1fb889c045587aa58d45e0c94fc505dee22c2c1fff5a
  by: owner unseal ritual (make core-unseal)

- 2026-11-01T04:27:19Z — REASON: Sapling pair proving on every network and a per-process self-test verdict for unchanged pinned pair files: params_init.c gains a file-identity-keyed pass cache for the pair self-test and sapling_prover_native.c gains zclassic_sapling_prover_adopt_verified; owner-authorized 2026-10-30 for behaviour-scoped core changes. No verifying key, verification path or consensus predicate is touched.
  old ROOT: 0b74d6fba3ef53dbdaa8fff52aabb6567f0c0b247d0d5593d65407cf56b2c65d
  by: owner unseal ritual (make core-unseal)

- 2026-11-01T08:29:40Z — REASON: Pair review fixes: comments now state the per-process self-test skip, and zclassic_sapling_prover_adopt_verified moves from the public sapling_prover.h to src/sapling_prover_internal.h. No behaviour, verifying key or consensus predicate changes.
  old ROOT: a92cf67b9f5c7793702a85b04dcfd27a434467cfd2e2fc0e20eecb008e299747
  by: owner unseal ritual (make core-unseal)

- 2026-11-01T13:18:24Z — REASON: refactor(session_transport): split 1 function(s) under the complexity cap (glm); behaviour-preserving, each split gpt-terra LAND, no consensus predicate change
  old ROOT: a63df6dc83dc8eafc1c8a04acb83d83f8139fb674630c85ac4e0bed1faa37df5
  by: owner unseal ritual (make core-unseal)

- 2026-11-01T13:26:41Z — REASON: refactor(noise_handshake): split 1 function(s) under the complexity cap (glm); behaviour-preserving, each split gpt-terra LAND, no consensus predicate change
  old ROOT: 1fb6dc002cb72ca0a2f53f37aca3f3138e38568815cd411aa638ad6f8f87b052
  by: owner unseal ritual (make core-unseal)

- 2026-11-01T13:38:40Z — REASON: refactor(sync_reduce): split 1 function(s) under the complexity cap (glm); behaviour-preserving, each split gpt-terra LAND, no consensus predicate change
  old ROOT: 374b6eff8f12196128115aff2ac56b287a8c75252acdebf8fab951ea246929b9
  by: owner unseal ritual (make core-unseal)

- 2026-11-01T14:14:07Z — REASON: refactor(stage): split 1 function(s) under the complexity cap (glm); behaviour-preserving, each split gpt-terra LAND, no consensus predicate change
  old ROOT: e586691465e2ed8c823fe75e782f9c34c7082e4e1a0b7c8b6a96da308daaacf8
  by: owner unseal ritual (make core-unseal)

- 2026-11-01T14:20:29Z — REASON: refactor(script): split 1 function(s) under the complexity cap (grok); behaviour-preserving, each split gpt-terra LAND, no consensus predicate change
  old ROOT: 5b10779f8fb612c29ada6557bf7e4fd8f9c57419c83317fe6c4880578f9e1ea2
  by: owner unseal ritual (make core-unseal)

- 2026-11-01T14:34:13Z — REASON: refactor(fast_sync_coins_artifact): split 1 function(s) under the complexity cap (glm); behaviour-preserving, each split gpt-terra LAND, no consensus predicate change
  old ROOT: e8601397dd35b488dbec9e8c9f625039cea94f8001c23cc58197c3ad8d6aef3a
  by: owner unseal ritual (make core-unseal)

- 2026-11-01T14:47:03Z — REASON: refactor(download_diagnostics): split 1 function(s) under the complexity cap (glm); behaviour-preserving, each split gpt-terra LAND, no consensus predicate change
  old ROOT: 0eb6e0df85a205af9ea898f3e981a7725a28196043d022141d91028cd7c4438c
  by: owner unseal ritual (make core-unseal)

- 2026-11-01T14:50:48Z — REASON: refactor(tx_structural): split 1 function(s) under the complexity cap (grok); behaviour-preserving, each split gpt-terra LAND, no consensus predicate change
  old ROOT: cf627c9264d539c718065e63750e0c95b247d3511fcf9006e543a5673f52d766
  by: owner unseal ritual (make core-unseal)

- 2026-11-01T15:02:42Z — REASON: refactor(script_error): split 1 function(s) under the complexity cap (grok); behaviour-preserving, each split gpt-terra LAND, no consensus predicate change
  old ROOT: 1228ab4631ad9b402a4cbb904295a953bc58c6ce32aa9c40fffe5cea43b180f5
  by: owner unseal ritual (make core-unseal)

- 2026-11-01T15:12:38Z — REASON: refactor(process_block_tip_child): split 2 function(s) under the complexity cap (grok); behaviour-preserving, each split gpt-terra LAND, no consensus predicate change
  old ROOT: affbf96397ca925c5949f8134b0556146e6aebc4288255d43e046665e0aaf3a8
  by: owner unseal ritual (make core-unseal)

- 2026-11-01T15:13:08Z — REASON: refactor(accept_to_mempool): split 1 function(s) under the complexity cap (grok); behaviour-preserving, each split gpt-terra LAND, no consensus predicate change
  old ROOT: e745bc16d4ad9e477227ab5fadf5ec78f224d3a883e6d39b5b53604ff62576d3
  by: owner unseal ritual (make core-unseal)

- 2026-11-01T15:13:31Z — REASON: refactor(utxo_snapshot_loader): split 4 function(s) under the complexity cap (grok); behaviour-preserving, each split gpt-terra LAND, no consensus predicate change
  old ROOT: fd4107aa7f16309d1cf7de54cef6900066c71967da1e9848afda4fa3ae956bc1
  by: owner unseal ritual (make core-unseal)

- 2026-11-01T20:59:10Z — REASON: refactor(contextual_check_tx): split 1 function(s) under the complexity cap (grok);  behaviour-preserving, each split gpt-terra LAND, no consensus predicate change
  old ROOT: 4a8236ad28672a5fd3d7913c676498908dd37710788888b3899549b5b33c1ef8
  by: owner unseal ritual (make core-unseal)

- 2026-11-01T20:59:22Z — REASON: refactor(coins_math): split 1 function(s) under the complexity cap (grok);  behaviour-preserving, each split gpt-terra LAND, no consensus predicate change
  old ROOT: 9503ee107213be517ca9831abacf9e748678604a1b60ee43bc00a47b0702e8ff
  by: owner unseal ritual (make core-unseal)

- 2026-11-01T20:59:31Z — REASON: refactor(sighash): split 2 function(s) under the complexity cap (grok);  behaviour-preserving, each split gpt-terra LAND, no consensus predicate change
  old ROOT: 71ef769117a92abfcdff3cfa38ba14ec172e4f32f8e599361280c82a5544dbe7
  by: owner unseal ritual (make core-unseal)

- 2026-11-01T20:59:42Z — REASON: refactor(pow): split 1 function(s) under the complexity cap (grok);  behaviour-preserving, each split gpt-terra LAND, no consensus predicate change
  old ROOT: a2bd36ec5fade4b8f19961b0305c4e34f917aa04f6ba694f89673957daf3ba0e
  by: owner unseal ritual (make core-unseal)

- 2026-11-01T20:59:53Z — REASON: refactor(sigencoding): split 1 function(s) under the complexity cap (grok);  behaviour-preserving, each split gpt-terra LAND, no consensus predicate change
  old ROOT: 4251aa07c8c3fe13f191f8cded86f54b86150b97f7be6e91a82842aa5cf7e908
  by: owner unseal ritual (make core-unseal)

- 2026-11-01T21:00:03Z — REASON: refactor(fees): split 1 function(s) under the complexity cap (grok);  behaviour-preserving, each split gpt-terra LAND, no consensus predicate change
  old ROOT: 4c150d15a9956c7b4446076566ff67df4695756b6da8aadf086113c19c7fbf0e
  by: owner unseal ritual (make core-unseal)

- 2026-11-01T21:00:14Z — REASON: refactor(coins_view): split 1 function(s) under the complexity cap (grok);  behaviour-preserving, each split gpt-terra LAND, no consensus predicate change
  old ROOT: b4fb8b4593089d6f7abbc4985b75ae3fcd96da0a8a61c049afc8314397af55b2
  by: owner unseal ritual (make core-unseal)

- 2026-11-01T21:00:24Z — REASON: refactor(coinbase): split 1 function(s) under the complexity cap (grok);  behaviour-preserving, each split gpt-terra LAND, no consensus predicate change
  old ROOT: 851f1a59534d521113295282857c903b52e32dfbfc78e3e1e5c5aec33dd3d6d7
  by: owner unseal ritual (make core-unseal)

- 2026-11-01T21:00:35Z — REASON: refactor(txmempool): split 1 function(s) under the complexity cap (grok);  behaviour-preserving, each split gpt-terra LAND, no consensus predicate change
  old ROOT: d4fd1113b26ed7a2ca0fff43a2bc241f5824d5a5719d69d16842d4895944aaf0
  by: owner unseal ritual (make core-unseal)

- 2026-11-01T21:00:43Z — REASON: refactor(merkleblock): split 1 function(s) under the complexity cap (grok);  behaviour-preserving, each split gpt-terra LAND, no consensus predicate change
  old ROOT: aaea0f02e524c236bc995aa6b93c5c4bb0b25f06292f372f0a107d57b922f0d2
  by: owner unseal ritual (make core-unseal)

- 2026-11-01T21:00:54Z — REASON: refactor(gen): split 1 function(s) under the complexity cap (grok);  behaviour-preserving, each split gpt-terra LAND, no consensus predicate change
  old ROOT: c5d51ec23ac12ca531842e16d2953ba48daede104702280a8099bc97dbf68554
  by: owner unseal ritual (make core-unseal)

- 2026-11-01T21:01:03Z — REASON: refactor(update_coins): split 1 function(s) under the complexity cap (grok);  behaviour-preserving, each split gpt-terra LAND, no consensus predicate change
  old ROOT: 5a9db2e5216ddfc0e025ce8e27ce4a3430e5e3926ea363a5e40c68eee9ddec66
  by: owner unseal ritual (make core-unseal)

- 2026-11-01T21:01:11Z — REASON: refactor(fast_scan): split 1 function(s) under the complexity cap (grok);  behaviour-preserving, each split gpt-terra LAND, no consensus predicate change
  old ROOT: 82a2053bb7d58401a0e216a4e505d8f962ee4d5d5918811ce68e46d696a4053a
  by: owner unseal ritual (make core-unseal)

- 2026-11-01T21:01:22Z — REASON: refactor(params_fetch): split 1 function(s) under the complexity cap (grok);  behaviour-preserving, each split gpt-terra LAND, no consensus predicate change
  old ROOT: 36fe1c8e1dbe7927c147dfbb5692dde2d7280db0ea1e4fd05e57dc726a00a691
  by: owner unseal ritual (make core-unseal)

- 2026-11-01T21:01:30Z — REASON: refactor(sapling_prover_native): split 3 function(s) under the complexity cap (grok);  behaviour-preserving, each split gpt-terra LAND, no consensus predicate change
  old ROOT: 3660872d348f0d837ef9c9e9cbf78d8a13f27705176f5b7745fcfc4bbf907903
  by: owner unseal ritual (make core-unseal)

- 2026-11-01T21:01:39Z — REASON: refactor(msm_parallel): split 1 function(s) under the complexity cap (grok);  behaviour-preserving, each split gpt-terra LAND, no consensus predicate change
  old ROOT: ef14630b27b3140060336ffbee343a3c4da9e9874f0987aa44b12b8fa5c9f079
  by: owner unseal ritual (make core-unseal)

- 2026-11-01T21:01:47Z — REASON: refactor(circuit_gadgets): split 1 function(s) under the complexity cap (grok);  behaviour-preserving, each split gpt-terra LAND, no consensus predicate change
  old ROOT: 98aa8cd4ad555b70a8d5df358676e413b9523e51f3b490c373c08e6d2189b611
  by: owner unseal ritual (make core-unseal)

- 2026-11-01T21:01:59Z — REASON: refactor(fr): split 1 function(s) under the complexity cap (grok);  behaviour-preserving, each split gpt-terra LAND, no consensus predicate change
  old ROOT: acd8ce85e073ef44764b0c3ed5e886aa20f8286beb6eea0777aab45f0b4eb74e
  by: owner unseal ritual (make core-unseal)

- 2026-11-01T21:02:06Z — REASON: refactor(circuit_pedersen): split 1 function(s) under the complexity cap (grok);  behaviour-preserving, each split gpt-terra LAND, no consensus predicate change
  old ROOT: 5f763371299bfa6a443f8d26a07408cb02733461e0292874712e22017dd7aab5
  by: owner unseal ritual (make core-unseal)

- 2026-11-01T21:02:14Z — REASON: refactor(incremental_merkle_tree): split 3 function(s) under the complexity cap (grok);  behaviour-preserving, each split gpt-terra LAND, no consensus predicate change
  old ROOT: 21f507775674605110d6a2c6720784acc7b2186e5a5c70208a0dd0d191638cb8
  by: owner unseal ritual (make core-unseal)

- 2026-11-01T21:02:24Z — REASON: refactor(sapling_circuit): split 1 function(s) under the complexity cap (grok);  behaviour-preserving, each split gpt-terra LAND, no consensus predicate change
  old ROOT: ce4ef754a048157edc2d0ee2534036f32b1f4c65c7c99bba044975f5ce7bb27d
  by: owner unseal ritual (make core-unseal)

- 2026-11-01T21:02:32Z — REASON: refactor(sapling): split 1 function(s) under the complexity cap (grok);  behaviour-preserving, each split gpt-terra LAND, no consensus predicate change
  old ROOT: e51eaa8d946f144a71609730151a27a96aa43a6546528256a623f68f74a5cf3e
  by: owner unseal ritual (make core-unseal)

- 2026-11-01T21:02:45Z — REASON: refactor(circuit_bits): split 1 function(s) under the complexity cap (grok);  behaviour-preserving, each split gpt-terra LAND, no consensus predicate change
  old ROOT: a6af23c21cbc60aa16d90accdc493c36ad5d2e4545a6faa38235c3a0bcf1dbed
  by: owner unseal ritual (make core-unseal)

- 2026-11-01T21:02:56Z — REASON: refactor(params_init): split 1 function(s) under the complexity cap (grok);  behaviour-preserving, each split gpt-terra LAND, no consensus predicate change
  old ROOT: 6088d2bce6b6bb614ddd05f48346d76ee70318aed6b5e287c995278e9379da81
  by: owner unseal ritual (make core-unseal)

- 2026-11-01T21:03:12Z — REASON: embedded Tor must not take the node's SIGTERM;   __DisableSignalHandlers 1;   no consensus change
  old ROOT: 4c9ffca2861e0c4fc7affaf21a585b750a5ab3660843da2bfdf01a8babc8e658
  by: owner unseal ritual (make core-unseal)

- 2026-11-01T21:03:22Z — REASON: tor_write_torrc: check every write and fclose, remove partial torrc on failure, so __DisableSignalHandlers 1 cannot be silently lost;   no consensus change
  old ROOT: 6b33247d60b651efdd284dc98266a643eba9c91ac59ba678b8d23db9da1ee25a
  by: owner unseal ritual (make core-unseal)

- 2026-11-01T21:03:35Z — REASON: tor_integration: ZCL_TESTING-only seam to append one torrc line (DisableNetwork 1) so the in-process SIGTERM test needs no public network;   no production or consensus change
  old ROOT: 95fc58911b02d8aaaa9e4379d5110458ca0db47a55417e3b2294bea12ebf0ae9
  by: owner unseal ritual (make core-unseal)

- 2026-11-01T21:03:44Z — REASON: tor_write_torrc: check removal of a partial torrc and log failure;   no consensus change
  old ROOT: 517bd420f816621d54d07199b17d6073cd4764d74b29b400e4d72813630dde9e
  by: owner unseal ritual (make core-unseal)

- 2026-11-01T21:03:57Z — REASON: test_tor: skip the write-failure half only when /dev/full is absent (ENOENT);  behaviour-preserving, each split gpt-terra LAND, no consensus predicate change
  old ROOT: 7f9a83114dcad8a07da6d2715ad2b2faad098cba7914ccdf3b6e5c6a92d85f2b
  by: owner unseal ritual (make core-unseal)

- 2026-11-01T21:04:12Z — REASON: Save peer state before the clean marker, not inside release-resources;  behaviour-preserving, each split gpt-terra LAND, no consensus predicate change
  old ROOT: 014e91d505ced79a21656f7ccfa572d22f53e35a27a2ea1c0a15df2e6a9c2822
  by: owner unseal ritual (make core-unseal)

- 2026-11-01T21:04:27Z — REASON: connman_save_addrman returns bool (behaviour-preserving) so shutdown can see a failed peer-state save;   owner-authorised via lead
  old ROOT: a69296e429104c29f2caed0d20c835896e8814dfccaf432e35417b8c5ae0070f
  by: owner unseal ritual (make core-unseal)

- 2026-11-01T21:04:46Z — REASON: Test each peer-state save failure source and the shutdown retry seam;  behaviour-preserving, each split gpt-terra LAND, no consensus predicate change
  old ROOT: 632c90b5bed4908ada767f71672f2f386846f92666539226502767e67abb8b13
  by: owner unseal ritual (make core-unseal)

- 2026-11-01T21:05:07Z — REASON: test_net_bootstrap: peer-save fixture under test-tmp, removed recursively;  behaviour-preserving, each split gpt-terra LAND, no consensus predicate change
  old ROOT: 0104ee41728005c25195204e454dea443358ecf3f28f258fc9a0a44df71815ea
  by: owner unseal ritual (make core-unseal)

- 2026-11-01T21:05:29Z — REASON: Export process_block_tip_is_best_work from the sealed validation core so the genesis walk publisher can earn the best-work flag by the same predicate;  behavior-preserving, no consensus predicate change (re-seal after rebase onto current main)
  old ROOT: 724851fdb0435ccf6a79a353d4f91bc60cd41573b45551aeb962ae76ab0b21ad
  by: owner unseal ritual (make core-unseal)

- 2026-11-01T21:19:13Z — REASON: refactor(stage_lcc): split 1 function(s) under the complexity cap (glm); behaviour-preserving, each split gpt-terra LAND, no consensus predicate change
  old ROOT: cc7fb7696310870353ca6870904e131dce4cccf068ab93366cb594cb90c95556
  by: owner unseal ritual (make core-unseal)

- 2026-11-01T21:19:22Z — REASON: refactor(mmb): split 1 function(s) under the complexity cap (glm); behaviour-preserving, each split gpt-terra LAND, no consensus predicate change
  old ROOT: c0c4a58e2892f32746142725644f408c6acf913420e8e6fbc0c6ac65cf61bdcb
  by: owner unseal ritual (make core-unseal)

- 2026-11-01T21:19:31Z — REASON: refactor(msg_blocks): split 1 function(s) under the complexity cap (kimi); behaviour-preserving, each split gpt-terra LAND, no consensus predicate change
  old ROOT: 145dfea6c3fdad07e2f0bb015d3081382abc665e8af62d99c3bd7917f8017c53
  by: owner unseal ritual (make core-unseal)

- 2026-11-01T21:19:40Z — REASON: refactor(params_fetch_session): split 1 function(s) under the complexity cap (kimi); behaviour-preserving, each split gpt-terra LAND, no consensus predicate change
  old ROOT: 6e1c17dbc4fe92fbed354b46d56e8b59aa786aa08b1bb920a0a1cf2aaec2dc75
  by: owner unseal ritual (make core-unseal)

- 2026-11-01T21:19:49Z — REASON: refactor(connect_block): split 1 function(s) under the complexity cap (grok); behaviour-preserving, each split gpt-terra LAND, no consensus predicate change
  old ROOT: 5c55df764d0c75529cf560ab3e51fd0e59ad777cfaa7e4a32a6890881094b584
  by: owner unseal ritual (make core-unseal)

- 2026-11-01T21:28:45Z — REASON: refactor(block_successor): split 1 function(s) under the complexity cap (grok); behaviour-preserving, each split gpt-terra LAND, no consensus predicate change
  old ROOT: cadcb9b6b86a0e2ea77d18bade5bb9a19822a33a82165b9a2275bba3c709d1a9
  by: owner unseal ritual (make core-unseal)

- 2026-11-02T00:07:48Z — REASON: refactor(sapling_structural): split 1 function(s) under the complexity cap (grok); behaviour-preserving, each split gpt-terra LAND, no consensus predicate change
  old ROOT: d75f27fb8939bb9af238382d4a64d175692fa2fb6a67431a850129ebf25d51b3
  by: owner unseal ritual (make core-unseal)

- 2026-11-02T00:07:58Z — REASON: refactor(bn254): split 1 function(s) under the complexity cap (grok); behaviour-preserving, each split gpt-terra LAND, no consensus predicate change
  old ROOT: fde063b6d6ccbb409ff7af669f05b46ac6d3450abc15ce59b9afa89233fbcecf
  by: owner unseal ritual (make core-unseal)

- 2026-11-02T05:10:13Z — REASON: repin core/modules/crypto zclassic23/sha3 dependency root (sha3 pins zclassic23/base, whose root moved when base log_macros.h gained LOG_X_IN forms); metadata only, no consensus predicate change
  old ROOT: 7d0194ae6bc82e0756d0e9f5cad1f8bb4f5dd4d0565aa52f500301196a536969
  by: owner unseal ritual (make core-unseal)

- 2026-11-02T06:21:16Z — REASON: refactor(noise_transport): split 1 function(s) under the complexity cap (glm); behaviour-preserving, each split gpt-terra LAND, no consensus predicate change
  old ROOT: ab1bb4862a23a11bfd53b8cf107f12c5f77f743fff77de2547e964f7169e282a
  by: owner unseal ritual (make core-unseal)

- 2026-11-02T06:21:36Z — REASON: refactor(accept_block_header): split 1 function(s) under the complexity cap (glm); behaviour-preserving, each split gpt-terra LAND, no consensus predicate change
  old ROOT: 76c3c0ad3638a0c64edbab51306a6cacf23f01f284035b7b3892b10b4a8ace99
  by: owner unseal ritual (make core-unseal)

- 2026-11-02T06:21:50Z — REASON: refactor(msgprocessor_snapshot_payload): split 1 function(s) under the complexity cap (glm); behaviour-preserving, each split gpt-terra LAND, no consensus predicate change
  old ROOT: 1b6b882e84ac8343e4c36ef8580ef303033ec3c6666a961888939265bc7bf650
  by: owner unseal ritual (make core-unseal)

- 2026-11-02T06:21:58Z — REASON: refactor(script_standard): split 1 function(s) under the complexity cap (grok); behaviour-preserving, each split gpt-terra LAND, no consensus predicate change
  old ROOT: 8b4203ae686cb47c29acfa6e472fd42b4d3af5206466a240133c19272ccc0417
  by: owner unseal ritual (make core-unseal)

- 2026-11-02T06:22:12Z — REASON: refactor(chainstate): split 2 function(s) under the complexity cap (grok); behaviour-preserving, each split gpt-terra LAND, no consensus predicate change
  old ROOT: 4d23deca720e7f282b7402865e8a6ac5db4ddc6af7a05b3790faedc81e270fbb
  by: owner unseal ritual (make core-unseal)

- 2026-11-02T06:22:25Z — REASON: refactor(file_service_client): split 2 function(s) under the complexity cap (grok); behaviour-preserving, each split gpt-terra LAND, no consensus predicate change
  old ROOT: 4cb45c6a55205b239ffccb703e7c1805ad6e6336c727f675e985ae7e5d5e71b0
  by: owner unseal ritual (make core-unseal)

- 2026-11-02T06:22:33Z — REASON: refactor(process_block_revalidate): split 1 function(s) under the complexity cap (grok); behaviour-preserving, each split gpt-terra LAND, no consensus predicate change
  old ROOT: 58db85bbe323ab2fa5e057606d3b475a52004bd997c062c850626b020d7849aa
  by: owner unseal ritual (make core-unseal)

- 2026-11-02T06:25:46Z — REASON: refactor(script_interp): split 1 function(s) under the complexity cap (grok); behaviour-preserving, each split gpt-terra LAND, no consensus predicate change
  old ROOT: 27c27e9c997c177d147f319504a4b89eae97fee0de606efd4fbc3fd99c25bf5a
  by: owner unseal ritual (make core-unseal)

- 2026-11-02T08:22:47Z — REASON: refactor(addrman_codec): split 1 function(s) under the complexity cap (grok); behaviour-preserving, each split gpt-terra LAND, no consensus predicate change
  old ROOT: 629f667a565d680a4513f350e975ec8308b99f39809f6bcccd1192a57da04506
  by: owner unseal ritual (make core-unseal)

- 2026-11-02T08:23:08Z — REASON: https install: refuse a trailing-slash URL that resolves to a file; behaviour-preserving, each split gpt-terra LAND, no consensus predicate change
  old ROOT: 42698d56c56d5f87d7ad573076f8138fc7aa52a2171e5d22ef76b43f0a4aa51e
  by: owner unseal ritual (make core-unseal)

- 2026-11-02T11:02:16Z — REASON: refactor(core_io): split 2 function(s) under the complexity cap (grok); behaviour-preserving, each split gpt-terra LAND, no consensus predicate change
  old ROOT: da0f33673610ce97aedb5d84ac83d04f36e70b8dc51415837dd807c7d9f530b1
  by: owner unseal ritual (make core-unseal)

- 2026-11-02T11:02:24Z — REASON: refactor(utxo_commitment): split 2 function(s) under the complexity cap (grok); behaviour-preserving, each split gpt-terra LAND, no consensus predicate change
  old ROOT: 84f532e346250370f583cf7a2529976505a2772106af47d39c53ffbd372f4f0a
  by: owner unseal ritual (make core-unseal)

- 2026-11-02T11:35:47Z — REASON: refactor(process_block_invalidate): split 3 function(s) under the complexity cap (grok); behaviour-preserving, each split gpt-terra LAND, no consensus predicate change
  old ROOT: 013f3a865186500a83f3dd066c95f729146d1f7f043e3c7b7fcb8d6695ad78a2
  by: owner unseal ritual (make core-unseal)

- 2026-11-02T12:44:59Z — REASON: refactor(msg_headers): split 1 function(s) under the complexity cap (grok); behaviour-preserving, each split gpt-terra LAND, no consensus predicate change
  old ROOT: 62e3093c4c1176a9ff92053afe78e16ccce5945e023c9633550796a41815a19e
  by: owner unseal ritual (make core-unseal)

- 2026-11-02T12:46:34Z — REASON: refactor(msg_headers): move getheaders request builders to msg_headers_getheaders.c; behaviour-preserving, each split gpt-terra LAND, no consensus predicate change
  old ROOT: 4c5ed6853c9048eba00ff0d2a7cd801fd30700826a4ca33233b36ab2f7b04278
  by: owner unseal ritual (make core-unseal)

- 2026-11-02T12:47:00Z — REASON: refactor(download): split 2 function(s) under the complexity cap (grok); behaviour-preserving, each split gpt-terra LAND, no consensus predicate change
  old ROOT: d24d38f96c68138ac6a2cb2f4fd9fad234e20b4dd242830363f49aa6b555de69
  by: owner unseal ritual (make core-unseal)

- 2026-11-02T12:47:20Z — REASON: refactor(download): move assignment-window helpers to download_assign_windows.c; behaviour-preserving, each split gpt-terra LAND, no consensus predicate change
  old ROOT: 3556c9082fe02d91fc69c29b9ff9fd2668fb997997283ff56727dc19ec50a90f
  by: owner unseal ritual (make core-unseal)

- 2026-11-02T14:15:47Z — REASON: Honour -bind on the HTTPS front door, HTTP redirect and file-service listeners (core/modules/net/src/https_server.c, file_service.c), which bind every interface regardless of -bind; network exposure only, no consensus predicate; lead-run under the owner grant of 2026-10-30 (authority to unseal core for reviewed behaviour-scoped changes)
  old ROOT: 62e3093c4c1176a9ff92053afe78e16ccce5945e023c9633550796a41815a19e
  by: owner unseal ritual (make core-unseal)

- 2026-11-02T15:10:12Z — REASON: Follow-up to the 2026-11-02T14:15:47Z -bind listener change, same behaviour scope: split https_server_start_on_port and fs_server_thread under the complexity cap and define fs_server_listener_name once across platform arms; no consensus predicate; lead-run under the owner grant of 2026-10-30
  old ROOT: b8a857dd77f2781977774a44d0d2ab545428fd0b4b9c3accf023ac217748c964
  by: owner unseal ritual (make core-unseal)

- 2026-11-02T15:31:33Z — REASON: Follow-up to the 2026-11-02 -bind listener change, same behaviour scope: accept HTTPS and redirect clients into struct sockaddr_storage so an IPv6 -bind listener accepts on every platform (https_server.c accept loops); no consensus predicate; lead-run under the owner grant of 2026-10-30
  old ROOT: bd48b1475612a54c9a4f6e6406bb4dbae0d46b8021b2f6f9f5fd0e654dcb334c
  by: owner unseal ritual (make core-unseal)

- 2026-10-31T17:37:41Z — REASON: Private wallet broadcast runs no onion service: start embedded Tor with DisableNetwork, claim dynhost hs_service, verify, then enable the network; default unchanged for other nodes. Owner grant 2026-10-30 to unseal core for reviewed, behaviour-scoped changes; no consensus predicate touched.
  old ROOT: d9bd425d5f66793bdf253ce2717af74e90aa19681b561cd2be83d5d37a6048e8
  by: owner unseal ritual (make core-unseal)

- 2026-10-31T23:21:25Z — REASON: Private wallet broadcast: back off and rate-limit the log of a failing DisableNetwork enable in core/modules/net/src/tor_integration.c (a missing control socket retried every millisecond). Owner grant 2026-10-30 to unseal core for reviewed, behaviour-scoped changes; no consensus predicate changes.
  old ROOT: e1d38182e1ab35f6e7c240d9d1e21c711727b3c635770bb6e6092ea2c819452e
  by: owner unseal ritual (make core-unseal)

- 2026-10-31T21:52:24Z — REASON: commit 2cf81eec86 changed core/modules/net/src/tor_integration.c to read the wall clock through clock_now_wall_ms (check-no-raw-clock-outside-platform); behaviour-preserving, no consensus predicate changes. RECORDED AFTERWARDS: this entry was appended at 2026-10-31T23:21:42Z, after the reseal, because the reseal ran under the 2026-10-31T17:37:41Z token without a new entry. The time is that of core/MANIFEST.sha3 on r1 (mtime 21:52:24Z) and of the reseal log.
  old ROOT: adad80000fb59f9f2caee58b7d10c3a6b666db9e9898bde7e25c985b657026e1
  by: appended by the lane author; not the unseal ritual
  (the new ROOT was e1d38182e1ab35f6e7c240d9d1e21c711727b3c635770bb6e6092ea2c819452e at 2cf81eec86)

- 2026-11-01T00:17:37Z — REASON: reseal after rebasing the private wallet broadcast lane onto origin/main 5c1d134912, which carries another writer's core/modules/net unseal entries; the sealed files of this lane (core/modules/net/src/tor_integration.c, core/modules/net/src/tor_config_log.c, core/modules/net/include/net/tor_integration.h) are unchanged by the rebase. Written at the time of the reseal.
  old ROOT: ab77ad2dca2a69f3758177f5bfeb27c2dc19b4e03fc620fcf018674a73b1858e
  by: appended by the lane author after make core-seal; not the unseal ritual
  (the new ROOT is the one in core/MANIFEST.sha3 at the commit that carries this entry)

- 2026-11-01T12:08:18Z — REASON: reseal after rebasing the private wallet broadcast lane onto origin/main 1f1fcb2f0c, which carries the wallet lock, screens and Sapling pair loader unseals. The lane's own core/modules/net changes (tor_integration.c, tor_integration.h, tor_config_log.c) replay unchanged; core/MANIFEST.sha3 and the two hotswap seal headers were taken from main during the rebase and recomputed with make core-seal.
  old ROOT: a63df6dc83dc8eafc1c8a04acb83d83f8139fb674630c85ac4e0bed1faa37df5
  by: appended by the lane author after make core-seal; not the unseal ritual
  (the new ROOT is the one in core/MANIFEST.sha3 at the commit that carries this entry)

- 2026-11-02T01:24:31Z — REASON: reseal after rebasing the private wallet broadcast lane onto origin/main 0683540c9a, which carries further sealed-core changes (process_block_tip_is_best_work export and complexity splits in block_successor, connect_block and msg_blocks). The lane's own core/modules/net changes (tor_integration.c, tor_integration.h, tor_config_log.c) replay onto main, with the DisableNetwork line added to main's buffered torrc writer; core/MANIFEST.sha3 and the two hotswap seal headers were taken from main during the rebase and recomputed with make core-seal.
  old ROOT: d75f27fb8939bb9af238382d4a64d175692fa2fb6a67431a850129ebf25d51b3
  by: appended by the lane author after make core-seal; not the unseal ritual
  (the new ROOT is the one in core/MANIFEST.sha3 at the commit that carries this entry)

- 2026-11-02T07:24:49Z — REASON: reseal after rebasing the private wallet broadcast lane onto origin/main 50e19f1e7c, which carries further sealed-core changes (sapling_structural and bn254 complexity splits). The lane's own core/modules/net changes (tor_integration.c, tor_integration.h, tor_config_log.c) replay unchanged; core/MANIFEST.sha3 and the two hotswap seal headers were taken from main during the rebase and recomputed with make core-seal.
  old ROOT: 7d0194ae6bc82e0756d0e9f5cad1f8bb4f5dd4d0565aa52f500301196a536969
  by: appended by the lane author after make core-seal; not the unseal ritual
  (the new ROOT is the one in core/MANIFEST.sha3 at the commit that carries this entry)

- 2026-11-02T08:25:13Z — REASON: reseal after rebasing the private wallet broadcast lane onto origin/main d3d533e1cd, which carries sealed-core changes from other lanes (validation chainstate and process_block_revalidate among them, recorded by their own entries). The lane's own core/modules/net changes (tor_integration.c, tor_integration.h, tor_config_log.c) replay unchanged; core/MANIFEST.sha3 and the two hotswap seal headers were taken from main during the rebase and recomputed with make core-seal.
  old ROOT: 629f667a565d680a4513f350e975ec8308b99f39809f6bcccd1192a57da04506
  by: appended by the lane author after make core-seal; not the unseal ritual
  (the new ROOT is the one in core/MANIFEST.sha3 at the commit that carries this entry)

- 2026-11-02T12:28:52Z — REASON: reseal after rebasing the private wallet broadcast lane onto origin/main 4b1f009f68, which carries sealed-core changes from other lanes, recorded by their own entries. The lane's own core/modules/net changes (tor_integration.c, tor_integration.h, tor_config_log.c) replay unchanged; core/MANIFEST.sha3 and the two hotswap seal headers were taken from main during the rebase and recomputed with make core-seal.
  old ROOT: da0f33673610ce97aedb5d84ac83d04f36e70b8dc51415837dd807c7d9f530b1
  by: appended by the lane author after make core-seal; not the unseal ritual
  (the new ROOT is the one in core/MANIFEST.sha3 at the commit that carries this entry)

- 2026-11-02T14:02:12Z — REASON: reseal after rebasing the private wallet broadcast lane onto origin/main 59ee3c11c8, which carries sealed-core changes from other lanes, recorded by their own entries. The lane's own core/modules/net changes (tor_integration.c, tor_integration.h, tor_config_log.c) replay unchanged; core/MANIFEST.sha3 and the two hotswap seal headers were taken from main during the rebase and recomputed with make core-seal.
  old ROOT: 62e3093c4c1176a9ff92053afe78e16ccce5945e023c9633550796a41815a19e
  by: appended by the lane author after make core-seal; not the unseal ritual
  (the new ROOT is the one in core/MANIFEST.sha3 at the commit that carries this entry)

- 2026-11-02T15:56:33Z — REASON: reseal after rebasing the private wallet broadcast lane onto origin/main 9f4ed8d410, which carries sealed-core changes from other lanes, recorded by their own entries. The lane's own core/modules/net changes (tor_integration.c, tor_integration.h, tor_config_log.c) replay unchanged; core/MANIFEST.sha3 and the two hotswap seal headers were taken from main during the rebase and recomputed with make core-seal.
  old ROOT: 356f85e4efa95e0ed525d4a8156a090b59a1c7a00ad2a5d7765ce935a49e82bd
  by: appended by the lane author after make core-seal; not the unseal ritual
  (the new ROOT is the one in core/MANIFEST.sha3 at the commit that carries this entry)

- 2026-11-02T17:19:55Z — REASON: reseal after rebasing the private wallet broadcast lane onto origin/main b81422231d, which carries sealed-core changes from other lanes, recorded by their own entries. The lane's own core/modules/net changes (tor_integration.c, tor_integration.h, tor_config_log.c) replay unchanged; core/MANIFEST.sha3 and the two hotswap seal headers were taken from main during the rebase and recomputed with make core-seal.
  old ROOT: 608c4a1e4fcdad4c1afa3fe0be8d8c326b830dbe1631ce01a11204727821a9f6
  by: appended by the lane author after make core-seal; not the unseal ritual
  (the new ROOT is the one in core/MANIFEST.sha3 at the commit that carries this entry)

- 2026-11-02T19:05:59Z — REASON: equihash: free this round's merged rows on a PoW reject; behaviour-preserving, each split gpt-terra LAND, no consensus predicate change
  old ROOT: e23bc5b69bf867c14bd27b4a7091f11d8838ad83251adf6f41ceff2e775bef54
  by: owner unseal ritual (make core-unseal)

- 2026-11-02T19:13:38Z — REASON: Replace banned string calls in sealed core with bounded snprintf; behaviour-preserving, each split gpt-terra LAND, no consensus predicate change
  old ROOT: e29b2dfd5b8617428699494c884dff4f7635ea4b17f1869d356d44cf0e323771
  by: owner unseal ritual (make core-unseal)

- 2026-11-02T21:11:02Z — REASON: Tor scheduler: write Schedulers KISTLite,Vanilla in the generated torrc. KIST calls ioctl(SIOCOUTQNSD) on every socket each scheduler run; Android SELinux denies it to apps (EACCES), Tor only disables KIST on EINVAL, so the phone retries the denied call several times a second (2118 audit denials in one node logcat window; zcl_tor 0.07 to 0.10 core on two builds). Not a consensus predicate. Lead unseal under the owner grant of 2026-10-30; re-applied on the new main root after a seal conflict.
  old ROOT: 47f5272a95a095a3c4a69e3fc53c4a795a4bdb4be7a56cd1f216a8e4d631b881
  by: owner unseal ritual (make core-unseal)

- 2026-11-03T00:24:31Z — REASON: Owner grant 2026-10-30 'you have authority to unseal core': record each peer's best accepted header height for getpeerinfo best_height; P2P bookkeeping only, no consensus predicate or validation change.
  old ROOT: c3d19ca28d8e99e3ff7be0ccaab4021d1409c6370e99b85b74951e4c591637a4
  by: owner unseal ritual (make core-unseal)

- 2026-11-03T08:29:20Z — REASON: behaviour-preserving complexity splits of 22 core functions (8 reviewed lanes: crypto_registry, transaction, script_interp, msgprocessor_snapshot, circuit_spend, crypto pkg, rom_fetch, groth16_prover); owner-authorized 2026-10-19 hardening program
  old ROOT: af865887b569d4501530707471b29c636349ac80b113d6dd152c36c9136d99f4
  by: owner unseal ritual (make core-unseal)

- 2026-11-03T09:08:55Z — REASON: add core batch: no NULL-base pointer arithmetic in sha256/sha512/htlc/siphash and close the status db handle on open failure (Mac UBSan; reviewed lane core-batch-1103 f859bfd44a); owner-authorized 2026-10-19 hardening program
  old ROOT: 60f05baecb7a8fb3ad8545bac9c2cb68802674e4f8560416a5f7efb02c11aede
  by: owner unseal ritual (make core-unseal)

- 2026-11-04T23:20:34Z — REASON: Owner authorized 2026-11-04 onion-only peer bootstrap using configured P2P endpoints and known-self guard; no consensus predicate change
  old ROOT: 36e585df84361875e16bd06cd8ade2f77dc89b7c88816404aa3c40eb9f0dfdaf
  by: owner unseal ritual (make core-unseal)

- 2026-11-05T05:54:56Z — REASON: Cancel in-flight onion dialing during orderly node shutdown without changing consensus
  old ROOT: 67502a564613cb4c7be8dd3acdac85d4c460de5717f923e07538dee1de54e6c6
  by: owner unseal ritual (make core-unseal)

- 2026-11-05T06:12:20Z — REASON: Factor shutdown cancellation cleanup without changing behavior
  old ROOT: 5793aa3ac1d0a80396c25f36546865403f3a27ad226e5ec34491e6c0846c5082
  by: owner unseal ritual (make core-unseal)

- 2026-11-05T16:14:01Z — REASON: FlyClient gate: bind a peer proof to headers this node validated, with a distinct no-offence refusal code for a proof we cannot check; sync strategy only, no consensus predicate change; owner instruction 2026-11-05 you have authority to unseal core to fix everything, as relayed by the lane brief
  old ROOT: a61c915fbc9da7096874695da51b2bf58e1086c1a662047f1420776121eae718
  by: owner unseal ritual (make core-unseal)

- 2026-11-05T16:20:03Z — REASON: Dandelion: retry a refused stem-peer RNG draw after 60 seconds instead of fluffing for the whole 600 second epoch; relay policy only, no consensus predicate change; owner instruction 2026-11-05 you have authority to unseal core to fix everything, as relayed by the lane brief
  old ROOT: cd033043e85ff2c7030cad8d85442a9e3f4b87b3f28823b90edd8de8bb41a165
  by: owner unseal ritual (make core-unseal)

- 2026-11-05T18:03:16Z — REASON: Snapshot offers: read the offered block's hash and chain work from its validated blocks row, since nothing writes node_state tip_hash, and refuse an offer or chunk manifest without one; correct the stand-down contract comment; sync strategy only, no consensus predicate change; owner instruction 2026-11-05 you have authority to unseal core to fix everything, as relayed by the lane brief
  old ROOT: 457b60267e7e7e89e3126d595fa30be43110c7c3c2c0d3942f57716e9d4665ae
  by: owner unseal ritual (make core-unseal)

- 2026-11-05T19:39:04Z — REASON: Block manifest: arm the swarm only on a manifest that itself validated and anchored; cap block_swarm_init pieces. No consensus predicate change.
  old ROOT: 61a72f1a81b5e3241adb55a10f21dc74a7f8a06e112d7294c3d811fc814d3e41
  by: owner unseal ritual (make core-unseal)

- 2026-11-05T19:39:17Z — REASON: Block manifest: compute the expected piece count in 64 bits so the widest height range is defined. No consensus predicate change.
  old ROOT: 4f8bbe45e7fbb3a930066025dcc9c8f7c303291bb13c665df139958fb84bc679
  by: owner unseal ritual (make core-unseal)

- 2026-11-05T19:39:30Z — REASON: Compact block: place prefilled transactions at the absolute positions the decoder stores, refuse a position past 16 bits. Wire bytes unchanged. No consensus predicate change.
  old ROOT: 25bb121bccf955b07e221b606cd391257e6c44e880bec9529cf24747265b7412
  by: owner unseal ritual (make core-unseal)

- 2026-11-05T19:47:07Z — REASON: Signed file offer: refuse a name field with a NUL inside its declared length or nonzero padding, so one signed offer has exactly one wire form. Honest encoders already write that form. Relay validity only, no consensus predicate change.
  old ROOT: 80c445ee158eeededd3a1bf4c2e6649d6f468f942b9f624381a25948074c5552
  by: owner unseal ritual (make core-unseal)

- 2026-11-05T21:01:24Z — REASON: Legacy peers read a header as a promise to serve the body: serve them only the active chain where the body is held (net serve path, no consensus predicate)
  old ROOT: a49efa5cf444f542b5fc90b42ec05727da285df90b6dc9f7bc583a3aefb55791
  by: owner unseal ritual (make core-unseal)

- 2026-11-05T21:24:20Z — REASON: Move two header-sending functions out of msg_headers.c, no behaviour change, so the file stays under its size limit
  old ROOT: 6387a59315fff6349d41a0be80d787ee34b162af14745203e476094957bc9c9f
  by: owner unseal ritual (make core-unseal)

- 2026-11-05T22:32:17Z — REASON: Stop a legacy getheaders reply at a gap instead of skipping it
  old ROOT: b31e6304f44d494664620227bfc3a6f17817ba9d37c62755ad71a0fbef13dc9b
  by: owner unseal ritual (make core-unseal)

- 2026-11-05T22:32:39Z — REASON: Finish a getdata request past the send budget from the send tick
  old ROOT: 2388ff94fed28ab3e4f67d435f891acc5de210ecc34fc3f0e72b3c3370f18557
  by: owner unseal ritual (make core-unseal)

- 2026-11-05T22:32:51Z — REASON: Ignore a FlyClient reply from anyone but the peer asked
  old ROOT: 29284f6958c0e5aa01f5164997225fb17f243112fd1fbece191d6723bfa9108c
  by: owner unseal ritual (make core-unseal)

- 2026-11-05T23:52:36Z — REASON: A body that does not match its header no longer marks the block seen
  old ROOT: 64cf473ef400951a39584c1beb5a16ef8f4f5241e856d712bc7006db488f64cd
  by: owner unseal ritual (make core-unseal)

- 2026-11-05T23:53:13Z — REASON: Hold no download slot for a compact body on an unknown header
  old ROOT: 810d35adf2b84a252558d61925d7ac01141b386a3beabbbd7610faa69b6f9df7
  by: owner unseal ritual (make core-unseal)

- 2026-11-05T23:53:50Z — REASON: Ask nothing for a compact body at or below the tip; bind swarm pieces to bodies
  old ROOT: 1af14aac67dce1140d753c00a3b69911fd667aa8179eadfbd22d25be9baf6a26
  by: owner unseal ritual (make core-unseal)

- 2026-11-05T23:54:28Z — REASON: A manifest no longer starts a swarm; a peer's chunks stay out of the live table
  old ROOT: 0a72eb43d6c4ea2926d86a7b048aebc2bda2d4bd1a343242c23b2a7ffa9c5cd9
  by: owner unseal ritual (make core-unseal)

- 2026-11-06T01:48:05Z — REASON: Integrate approved state-link advertisement with landed upstream seal
  old ROOT: 4d075f52fbf6c4785daf538c5a84b800dafa668584b11ec6a168d15cdc368137
  by: owner unseal ritual (make core-unseal)

- 2026-11-06T00:19:28Z — REASON: Integrate approved state-link advertisement with landed upstream seal
  old ROOT: 64cf473ef400951a39584c1beb5a16ef8f4f5241e856d712bc7006db488f64cd
  by: owner unseal ritual (make core-unseal)

- 2026-11-05T23:38:14Z — REASON: Integrate approved state-link advertisement with landed upstream seal
  old ROOT: b31e6304f44d494664620227bfc3a6f17817ba9d37c62755ad71a0fbef13dc9b
  by: owner unseal ritual (make core-unseal)

- 2026-11-05T23:33:14Z — REASON: Owner approved 2026-11-05: advertise in-band state transfer in the version handshake; no consensus predicate changes
  old ROOT: 61a72f1a81b5e3241adb55a10f21dc74a7f8a06e112d7294c3d811fc814d3e41
  by: owner unseal ritual (make core-unseal)

- 2026-11-06T00:50:59Z — REASON: Check the block merkle root without a second allocation
  old ROOT: 4d075f52fbf6c4785daf538c5a84b800dafa668584b11ec6a168d15cdc368137
  by: owner unseal ritual (make core-unseal)

- 2026-11-06T00:52:17Z — REASON: Hold getdata and getheaders only while a snapshot is being served
  old ROOT: 18a5c995eaa1426aed57056b5d522136cfbb0e4370467e3715593d73de01e8a1
  by: owner unseal ritual (make core-unseal)

- 2026-11-06T00:58:11Z — REASON: Keep a block asked for during a snapshot serve and finish it after
  old ROOT: a3e4344f4b13f60fab86918666042bf174a194d28aec11ca63beeb1f1577fb55
  by: owner unseal ritual (make core-unseal)

- 2026-11-06T00:59:04Z — REASON: Throttle the log line for a chunk dropped with no swarm active
  old ROOT: 374b2091ff94bb9963e7b43787ebb1bf29548472bcb67fb4b1c9b9df80d86e1a
  by: owner unseal ritual (make core-unseal)

- 2026-11-06T01:23:16Z — REASON: Comments on held getdata and the send tick name the snapshot serve as well as the send budget. No behaviour change.
  old ROOT: 928e0668bb558123fe7ecb2dfc9e8dd8bfdfac229726143ad2ae6f041b534320
  by: owner unseal ritual (make core-unseal)

- 2026-11-06T02:46:27Z — REASON: Integrate approved state-link advertisement with landed upstream seal
  old ROOT: 82a532edf7e44ead87631be2852a141845f6cc099104c0b09689a67e042f9e2d
  by: owner unseal ritual (make core-unseal)

- 2026-11-06T02:32:22Z — REASON: Copy the mempool in one pass for compact block reconstruction
  old ROOT: 82a532edf7e44ead87631be2852a141845f6cc099104c0b09689a67e042f9e2d
  by: owner unseal ritual (make core-unseal)

- 2026-11-06T02:32:43Z — REASON: Do not rebuild a compact block that is already pending or already stored
  old ROOT: 52482eb35412870dae7f8ac5f6f5268d63701db722d40230fa35f851c2fe9298
  by: owner unseal ritual (make core-unseal)

- 2026-11-06T02:33:03Z — REASON: Floor the compact fallback history check at the provable frontier
  old ROOT: cba5628f8714b3093ad772ee44ff26343e4a6410307a123df8ce162365b541da
  by: owner unseal ritual (make core-unseal)

- 2026-11-06T02:33:20Z — REASON: Correct the mempool snapshot comments and return no array when it is empty
  old ROOT: db87d45a4941e40e4969a1b0e6b6d0b1d5b9ff6bc6a7d4983712b7b278b75688
  by: owner unseal ritual (make core-unseal)

- 2026-11-06T02:33:36Z — REASON: Drop a re-announced stored block only once it is on the active chain
  old ROOT: cd3f3a8fd748a84cf44ac73713e8ee43bdb66c727bf79719e7574f5e9265451f
  by: owner unseal ritual (make core-unseal)

- 2026-11-06T03:17:56Z — REASON: Integrate approved state-link advertisement with landed upstream seal
  old ROOT: 541b8a4eb1e4143895115b09ff493179e8acba37e8e8eadb112728d57ee4cd28
  by: owner unseal ritual (make core-unseal)

- 2026-11-06T04:21:39Z — REASON: Remove the unreachable utxo_activation_paused condition
  old ROOT: 48901636b304be5ba783e1209e88f8353b3b6d20e221ee77098f83276674dfce
  by: owner unseal ritual (make core-unseal)

- 2026-11-06T05:26:31Z — REASON: End embedded Tor on its own thread through its owning control socket
  old ROOT: ae415e90df987b9bd3429c7e25aba323a3963e3130e563efb815ebf8212f1ccc
  by: owner unseal ritual (make core-unseal)

- 2026-11-06T05:27:09Z — REASON: Register the persistent onion identity from Tor's own thread
  old ROOT: 6950828ea128837247ea981837fc2b1c28b41e1adb1ecaade046caef4ce5143e
  by: owner unseal ritual (make core-unseal)

- 2026-11-06T05:27:38Z — REASON: Open Tor's control socket pair close-on-exec from birth on Linux
  old ROOT: ecfaa435ee5bdb667a63e42724bb9b726f13328656167862921735699d8a1f14
  by: owner unseal ritual (make core-unseal)

- 2026-11-06T05:28:14Z — REASON: Name the 15 s frontend-stop alarm as what ends a node with Tor stuck
  old ROOT: 65bddea1a06fae69423193cfac04dc78c3bfc85fe849679702a1c712edc55e76
  by: owner unseal ritual (make core-unseal)

- 2026-11-06T05:28:49Z — REASON: Check that dynhost's slot holds the persistent service, not just anything
  old ROOT: 019c0299b613b8cb502e90e956792971df2302b756c3a5083c3c39761255476c
  by: owner unseal ritual (make core-unseal)

- 2026-11-06T05:29:58Z — REASON: Make the Tor start race test real, and test a start after Tor ended by itself
  old ROOT: 9c15f56ebad69107cb59dc34be1941104b329dc376e9ce89d3ad735d4c1509a6
  by: owner unseal ritual (make core-unseal)

- 2026-11-06T05:30:33Z — REASON: Rotate the onion identity once per process, not at every start
  old ROOT: f90f9713f87c2dfd52c447881bd62f29ccc2d9c399d28d947deeb469e1b47c91
  by: owner unseal ritual (make core-unseal)

- 2026-11-06T05:32:18Z — REASON: Stop a Tor watch retry from starting Tor after stop returned
  old ROOT: 3b298c47f0ea5a4aabcf31c77df2a2eced8d1cc3a98484124ecb07f268333e8d
  by: owner unseal ritual (make core-unseal)

- 2026-11-06T05:32:41Z — REASON: Cap in-process Tor starts below the point where Tor can abort the node
  old ROOT: 177ca7d7d6aa930d3cf924d41c68d3a777a42f674784626f3e15c1d771b910d0
  by: owner unseal ritual (make core-unseal)

- 2026-11-06T05:33:09Z — REASON: Stop probing Tor's control descriptor number after Tor may have closed it
  old ROOT: d133300668d066da7353c1b4ba27fa62d5578357bae510188865cf26f8cba328
  by: owner unseal ritual (make core-unseal)

- 2026-11-06T06:24:59Z — REASON: Work out two merkle roots in the array each caller already owns
  old ROOT: 6fb5a6f97cab20d9ae219c9c01fd480fac0eed7322983c90b5bcc56d2d5ddfc9
  by: owner unseal ritual (make core-unseal)

- 2026-11-06T06:25:15Z — REASON: Stop reading a local allocation failure as a verdict on a block or piece
  old ROOT: d31622b9d07398a5be5065fb1122263eca16969d574f74e5630385ec09b60ffb
  by: owner unseal ritual (make core-unseal)

- 2026-11-06T06:25:26Z — REASON: Leave a block unseen when a check on it runs out of memory
  old ROOT: b34519dbdb1a15fb1f856ff005be5278ad690e4eaabbc39f3bb409f689ed834b
  by: owner unseal ritual (make core-unseal)

- 2026-11-06T06:25:38Z — REASON: Log a peer's swarm manifest line once, not once per message
  old ROOT: a9264a483a483547da308f37d0d9254befd40fd750bfcfe2107a84d62d2265ad
  by: owner unseal ritual (make core-unseal)

- 2026-11-06T06:25:49Z — REASON: Update comments that no longer match the code around swarm and revalidation
  old ROOT: 161d916d24f002e35fd1a2857dadf48932f2168bc97dfb2016576a268ab103e0
  by: owner unseal ritual (make core-unseal)

- 2026-11-06T06:26:01Z — REASON: Report an Equihash check that runs out of memory as a local error
  old ROOT: c791f7ab7df76f841b77dc90768f81e1c11f59adb2bef536e4be39ca195c39b4
  by: owner unseal ritual (make core-unseal)

- 2026-11-06T06:26:15Z — REASON: Leave a compact block unseen when it could not be submitted
  old ROOT: 21b3abf686b1de010648bf9e3e4903e4f0e02915ed64f3d2dc86a4e6c7dce157
  by: owner unseal ritual (make core-unseal)

- 2026-11-06T06:26:31Z — REASON: Connect and mempool out-of-memory checks; guard the compact requeue
  old ROOT: 3d0fa71838e985c3b8c94a9b334992c10288c85eecfb1e9ebdea70e5d0ab7604
  by: owner unseal ritual (make core-unseal)

- 2026-11-06T06:26:43Z — REASON: Keep the connect path's out-of-memory signal with its own block
  old ROOT: 1bcfba073a7d3f5731d2392b33a66fc3625c09f799e90820074e98fa3cc63094
  by: owner unseal ritual (make core-unseal)

- 2026-11-06T06:26:55Z — REASON: Treat a bad undo count as a bad record, not a memory failure
  old ROOT: 652c67d10321259bfa9988225a25ea911c2b4d43dc5eebf17007611f9447d614
  by: owner unseal ritual (make core-unseal)

- 2026-11-06T06:27:07Z — REASON: Requeue a retryable block unless it is held, failed or on the chain
  old ROOT: 747d63fffe21d98be43ed2782d2c1e6f03fa43f5b9643ec754372bc7be5cdfcd
  by: owner unseal ritual (make core-unseal)

- 2026-11-06T04:39:14Z — REASON: FlySync island start: let checkpoint_header_fetch walk a hash-linked header window backward from a baked rung by empty-locator getheaders (no acceptance predicate changes); serve an empty-locator getheaders with the hash_stop header itself as zclassicd does
  old ROOT: 48901636b304be5ba783e1209e88f8353b3b6d20e221ee77098f83276674dfce
  by: owner unseal ritual (make core-unseal)

- 2026-11-06T09:31:10Z — REASON: Rebase reseal: carry the FlySync header-window walk onto origin/main; no code change beyond the rebased commit
  old ROOT: b8c23a890c42b9f4909553186b50cce524dbe97654e76a8e414b8a5a6e0ee116
  by: owner unseal ritual (make core-unseal)

- 2026-11-06T04:54:06Z — REASON: P2P serving parity with zclassicd: a getheaders with an empty locator returns exactly the hash_stop header (zclassicd main.cpp ProcessMessage getheaders). Serving only; no validation predicate changes
  old ROOT: e82bb56ad47a0df220c1f73405d65b259edf3b67d02bedd832a1c3424582408b
  by: owner unseal ritual (make core-unseal)

- 2026-11-06T09:31:55Z — REASON: Rebase reseal: carry the empty-locator getheaders serve fix onto origin/main; no code change beyond the rebased commit
  old ROOT: 8e0b4d0677abb3f1bce4dfaf3cf88c6c8f336aa11512264e18c0fbbbbe854c5c
  by: owner unseal ritual (make core-unseal)

- 2026-11-06T04:58:45Z — REASON: FlySync: an engine-set hold on outgoing getheaders requests (push_getheaders_from, push_getheaders, push_getheaders_span) and an engine-set switch that stops advertising NODE_NETWORK on a node without full history. Request and advertisement only; no validation predicate changes
  old ROOT: a73b588bd7a5585e774631caa643c10a23db5547026363c5596e89b1773a08ce
  by: owner unseal ritual (make core-unseal)

- 2026-11-06T09:32:24Z — REASON: Rebase reseal onto origin/main: Let the engine hold outgoing header requests and drop NODE_NETWORK; no change beyond the rebased commit
  old ROOT: 468f62ad1e6403eb430bc28b0b36319e66fad0e4798079bc0db6c0cb7f0fe684
  by: owner unseal ritual (make core-unseal)

- 2026-11-06T06:12:43Z — REASON: Split push_getheaders_from so the FlySync header-sync hold check sits in a thin wrapper under the cyclomatic cap. Request path only; no behavior or validation predicate change
  old ROOT: 0ae3f5cd0d2d0b8319d6438afb3c392e4936987aa042dc41915e7815b5209745
  by: owner unseal ritual (make core-unseal)

- 2026-11-06T09:33:23Z — REASON: Rebase reseal onto origin/main: FlySync: keep the hold under the complexity cap; no offers once installed; no change beyond the rebased commit
  old ROOT: e2a8455f973cd2993dd44cf707ba2683ee72eb8453384392208f474b87432dc9
  by: owner unseal ritual (make core-unseal)

- 2026-11-06T07:37:33Z — REASON: Comment only: narrow the empty-locator getheaders parity note in msg_headers.c to the known-hash_stop case; no code change
  old ROOT: 9dc222e1a24ecfd552c4f3755f245d31a55bd1964d92f82d815f3b6dbcf60ee4
  by: owner unseal ritual (make core-unseal)

- 2026-11-06T09:33:47Z — REASON: Rebase reseal onto origin/main: msg_headers: narrow the empty-locator parity note to a known hash_stop; no change beyond the rebased commit
  old ROOT: 962b57f05a8d3c03e14a528223f66b85e83c91837906b8bced6555fc8ea710c3
  by: owner unseal ritual (make core-unseal)

- 2026-11-06T11:52:34Z — REASON: Report a sighash precompute or block merkle check that runs out of memory as a local error, not a verdict on the block or the peer
  old ROOT: b8c23a890c42b9f4909553186b50cce524dbe97654e76a8e414b8a5a6e0ee116
  by: owner unseal ritual (make core-unseal)

- 2026-11-06T20:10:46Z — REASON: Rebase reseal onto origin/main: Connect precompute and block body checks out of memory are not verdicts; no change beyond the rebased commit
  old ROOT: 9bded4c431f43bb20b95f43dbd3e0cbc0ce9ea1af4f0c6750d1e8aa9f2ea1ee0
  by: owner unseal ritual (make core-unseal)
