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
