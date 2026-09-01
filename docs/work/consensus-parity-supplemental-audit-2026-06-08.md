# Consensus parity backlog (c23 vs zclassicd) — supplemental audit (2026-06-08)

> **Status:** all 6 confirmed divergences below have LANDED in the tree. This
> doc is kept as a parity-regression record. The durable payload is section 3
> (refuted candidates — do not re-investigate) and section 4 (111 sub-rules
> verified decision-identical).

Source of truth: zclassicd reference at a local `zclassic-cpp` checkout (origin
`ZclassicCommunity/zclassic`). c23 audited at the post-fix state of branch
`consensus/zclassicd-parity-2026-06-08` (FR-1 expiry, FR-2 finality, FR-3
tx-size, miner cap already landed). Method: 8 consensus surfaces read against
both trees, every candidate divergence adversarially refuted by 2 skeptics
(refute-by-default), then synthesized. 6 confirmed, 4 refuted, 111 sub-rules
verified decision-identical.

## 1. Executive summary

**HISTORY-FORKING ALARM: NONE proven.** No divergence rewrites the verdict on
any already-accepted block. All 6 are practically **forward-forking**: each
diverges only at/near the live tip or on future/crafted blocks. Every
historical block already passed at-tip validation on the live network, and a
strictly-more-permissive c23 cannot disagree with a zclassicd accept. (The
inverse — these fixes *tightening* c23 — is also history-safe: zclassicd already
enforces every one of these rules, so the immutable chain contains no block that
violates them. Adding the rule to c23 cannot newly-reject history, exactly the
FR-3 argument.)

**Root pattern:** `contextual_check_block()` had ZERO production callers — the
reducer connect path ran only context-free structural checks plus the staged
proof gate. Four of six confirmed items shared that single root cause; the call
is now wired on the connect path with an IBD early-return gate.

| # | Surface | Class | Reachability |
|---|---------|-------|--------------|
| 1 | CHECKDATASIG sigop undercount | history-applicable rule / forward-reachable | adversarial/future block crossing 20000 sigops |
| 2 | ContextualCheckBlock per-tx rules unwired (expiry / version-gating / finality / bad-cb-height) | forward | live/future tip |
| 3 | JoinSplit Ed25519 sig not on connect path | forward | live/future tip |
| 4 | Height-gated Sapling/Overwinter structural rules unwired | forward | live/future tip |
| 5 | Coinbase-must-be-shielded rule absent (`bad-txns-coinbase-spend-has-transparent-outputs`) | forward | live tip & forever forward |

## 2. CONFIRMED divergences (all landed)

### #1 — CHECKDATASIG/CHECKDATASIGVERIFY counted as 0 sigops (block sigop undercount)
- **c23 vs zclassicd:** c23 omitted `SCRIPT_VERIFY_CHECKDATASIG_SIGOPS` (bit 11)
  at both block-sigop count sites (`check_block.c` CheckBlock with
  `SCRIPT_VERIFY_NONE`; `connect_block.c:286` ConnectBlock flags). zclassicd
  includes the bit via `STANDARD_SCRIPT_VERIFY_FLAGS` (`src/main.cpp:4006`) and
  `SCRIPT_VERIFY_CHECKDATASIG_SIGOPS` in ConnectBlock (`src/main.cpp:2567`). Bit
  11 affects sigop counting only, never EvalScript execution.
- **Decision that differs:** every top-level `OP_CHECKDATASIG` (0xba) /
  `OP_CHECKDATASIGVERIFY` (0xbb) contributed **0** sigops in c23 vs **+1** in
  zclassicd; a block whose true sigop total crosses `MAX_BLOCK_SIGOPS=20000` only
  via these opcodes was ACCEPTED by c23 / REJECTED by zclassicd (`bad-blk-sigops`).
  Reachability: unconditional rule (active since genesis), but ~20000 *top-level*
  CHECKDATASIG opcodes in one block is exotic — no known historical block crosses
  it; history-safe.
- **LANDED:** `core/consensus/src/check_block.c:59` defines
  `DOMAIN_CONSENSUS_SIGOP_COUNT_FLAGS SCRIPT_VERIFY_CHECKDATASIG_SIGOPS`, used at
  `check_block.c:183`.

### #2 — ContextualCheckBlock per-tx height-gated rules NOT enforced on connect (`contextual_check_block` had zero production callers) — ROOT
- **c23 vs zclassicd:** c23's `contextual_check_block` (which calls
  `contextual_check_transaction` for expiry/version-gating and `is_final_tx`, and
  guards `bad-cb-height`) was orphaned — callers were only tests; the live path
  `connect_block.c:125` → `check_block()` ran only context-free
  `check_transaction`. zclassicd invokes `ContextualCheckBlock`
  (`src/main.cpp:4070` → `ContextualCheckTransaction`, `IsFinalTx`)
  unconditionally from AcceptBlock and TestBlockValidity, short-circuiting only
  while `IsInitialBlockDownload()` is true (latches false permanently at tip).
- **Decision that differs:** on connect, c23 never ran any height-gated per-tx
  rule — Overwinter expiry (`tx-overwinter-expired`), network-upgrade version
  gating, per-tx finality (`bad-txns-nonfinal`), BIP34 `bad-cb-height`. A tip
  block containing an expired, non-final, or height-inappropriate-version tx was
  ACCEPTED by c23 / REJECTED by at-tip zclassicd → permanent fork. (Shielded
  *proofs* are separately enforced via the staged proof reducer.)
- **LANDED:** `engine/jobs/src/script_validate_contextual.c:107` calls
  `contextual_check_block(...)` on the production connect path, gated by the
  `is_ibd` predicate (`script_validate_contextual.c:94`) matching zclassicd's IBD
  semantics so c23 does not become stricter than zclassicd during sync.

### #3 — JoinSplit Ed25519 signature NOT verified on the block-connection consensus path
- **c23 vs zclassicd:** c23's `ed25519_verify` over the JoinSplit sig existed but
  its only non-test caller was `accept_to_mempool.c:125` (mempool) plus the dead
  `contextual_check_block`; the authoritative connect gate (reducer →
  `check_block()` structural + proof gate `proof_validate_stage.c`) verified
  Sapling spend/output/binding + Sprout zk-SNARK but OMITTED the JoinSplit Ed25519
  sig (only background `bg_validation_proofs.c` checked it, with no
  invalidate/reorg on failure). zclassicd verifies it via
  `crypto_sign_verify_detached` over `dataToBeSigned` inside
  `ContextualCheckTransaction` (`src/main.cpp:1044-1058`), reason
  `bad-txns-invalid-joinsplit-signature`.
- **Decision that differs:** a block with a Sprout-joinsplit tx carrying a valid
  zk-proof but a **forged** `joinSplitSig` was accepted/finalized by c23 /
  rejected DoS(100) by zclassicd. The zk-SNARK binds `joinSplitPubKey` into
  `h_sig` but does NOT substitute for the Ed25519 signature over the tx sighash.
- **LANDED:** `engine/jobs/src/proof_validate_stage.c:141` calls `ed25519_verify`
  over the sighash before the per-joinsplit zk-SNARK loop; on failure
  `first_failure_proof_type="joinsplit_sig"` (`proof_validate_stage.c:144`),
  propagating `ok=0` to block `tip_finalize`.

### #4 — Height-gated Sapling/Overwinter structural tx rules NOT enforced on connect
- **c23 vs zclassicd:** c23's `core/consensus/src/sapling_structural.c:36-161`
  (overwinter-not-active, tx-overwintered-flag-not-set,
  bad-sapling-tx-version-group-id, bad-tx-sapling-version-too-low/high,
  tx-overwinter-active, pre-Sapling bad-txns-oversize) was reached only via
  `contextual_check_tx.c`, whose only non-test callers were mempool and the dead
  `contextual_check_block`; the connect gate enforced only the
  height-**independent** version rules. zclassicd runs these per-tx via
  `ContextualCheckBlock` (`src/main.cpp:935-1025`); Overwinter+Sapling both
  activate at `476969`.
- **Decision that differs:** at height ≥ 476969, a block whose tx is
  non-overwintered (Sprout-format), carries the wrong version-group-id for the
  height, or an out-of-range Sapling version, passed c23's connect gates and was
  finalized while zclassicd rejected it. (The OVERWINTER group-id is accepted by
  `tx_structural` at a Sapling height, so the Sapling-group-id rule genuinely
  escapes the context-free path.)
- **LANDED:** same surface as #2 — `contextual_check_block` is now called from
  the connect path (`engine/jobs/src/script_validate_contextual.c:107`), IBD-gated.

### #5 — Missing rule: coinbase outputs must be spent only to shielded outputs
- **c23 vs zclassicd:** c23's coinbase-input branch had the maturity check but
  no coinbase-protection check; `fCoinbaseMustBeProtected`/
  `fCoinbaseEnforcedProtectionEnabled` flags were write-only, and the reducer
  value path lacked it. zclassicd rejects inside `Consensus::CheckTxInputs`
  (`src/main.cpp:2062-2070`, enabled via `src/chainparams.cpp:85`).
- **Decision that differs:** zclassicd REJECTS
  (`bad-txns-coinbase-spend-has-transparent-outputs`) any tx that spends a
  coinbase output and has a non-empty transparent `vout`; the rule was absent in
  c23, which ACCEPTED such a tx. Not height-gated (active from genesis on
  mainnet; disabled only on regtest, so the carve-out is automatic).
- **LANDED:** `engine/jobs/src/utxo_apply_delta.c:315` and
  `engine/jobs/src/utxo_apply_stage.c:475` reject
  `bad-txns-coinbase-spend-has-transparent-outputs` when a spent input is
  coinbase and the tx has transparent outputs.

## 3. Refuted candidates (do not re-investigate)

- **pow-diffadj operator-precedence in `scaleDifficultyAtUpgradeFork`/BUTTERCUP
  window** (`c23 pow.c:50-55` vs `zclassicd pow.cpp:45-49`): mainnet sets
  `scale=true`, both parses identical at every mainnet height incl. BUTTERCUP. Only
  testnet/regtest observable.
- **BIP34 height encoding for heights 1-16** (`check_block.c:357-385` vs
  `main.cpp:4096-4103`): real chain mined heights 1-16 via `OP_N`; no future block
  can have height ≤ 16. Unreachable on mainnet.
- **Missing Sprout value-pool checkpoint seed (ZIP209 turnstile @440329):** flips a
  decision only if a future block drives the Sprout pool negative, which the verified
  joinsplit zk-SNARKs already prevent. Dormant defense-in-depth.
- **BIP30 same-height self-write tolerance** (`connect_block.c:261-276` vs
  `main.cpp:2560-2565`): post-BIP34 coinbase txids are height-unique; the tolerance
  fires only on a kill-9 partial-apply residue of the same block. Recovery-path only,
  decision-identical on the normal path.

## 4. Clean surfaces verified decision-identical (111 sub-rules)

Spot-confirmed identical between trees:
- **Context-free structural tx checks** (`tx_structural.c` vs
  `CheckTransactionWithoutProofVerification`): version floors, version-group-id
  accept set, vin/vout-empty, `MAX_TX_SIZE_AFTER_SAPLING=102000`, value/MoneyRange,
  valueBalance sign, joinsplit vpub bounds, duplicate inputs/joinsplit/sapling
  nullifiers, coinbase shape, scriptSig length [2,100], null-prevout — DoS scores +
  reject strings byte-identical. Wired on the connect path. All consensus constants
  match.
- **`transaction_is_coinbase` / `outpoint_is_null` / `is_expired_tx` (strict `>`)** —
  identical.
- **Shielded proof verification** (Sapling spend/output/binding Groth16 + spendAuthSig,
  Sprout Groth16/PHGR13) IS enforced via `proof_validate_stage.c` reducer gating
  `utxo_apply` — same decision, different mechanism. (Only JoinSplit Ed25519 sig
  missing → #3.)
- **Script-verify:** branch IDs (incl. intentional Bubbly==Buttercup `0x930b540d`),
  activation heights, CurrentEpoch/BranchId selection, Sapling/Overwinter + Sprout
  SignatureHash, SIGHASH type handling, strict-DER (always on), LOW_S/STRICTENC
  (flag-gated, OFF in both consensus paths), all script-flag bit values, P2SH
  (genesis-active), CLTV, CSV absent (OP_NOP3 plain NOP) in both, NULLDUMMY/NULLFAIL/
  SIGPUSHONLY/CLEANSTACK/MINIMALDATA (OFF in both), OP_CHECKDATASIG **execution**
  identical, legacy sigop walker mechanics, `MAX_BLOCK_SIGOPS=20000`, sig-version —
  identical.
- **Block-contextual:** merkle root + CVE-2012-2459 mutation detection,
  first/only-coinbase, txn-count/size bounds, BIP34 height for heights >16, equihash
  solution size + (N,K) per-epoch table (200,9 pre-585318 → 192,7 from BUBBLES),
  CheckBlockHeader 4 checks (`MIN_BLOCK_VERSION=4`), MTP time-too-old (`<=`), version
  floor, `bad-diffbits`, per-tx finality cutoff (header time, our FR-2) — identical.
- **pow-diffadj:** all constants, activation heights/protocol versions,
  `GetNextWorkRequired` control flow + min-difficulty ramp, `CalculateNextWorkRequired`
  retarget math (div-before-mul truncation order preserved), `IncreaseDifficultyBy`,
  `CheckProofOfWork`, `CheckEquihashSolution`, `arith_uint256` SetCompact/GetCompact,
  `GetBlockProof`, `GetMedianTimePast` (11-block), upgrade-state gate (PoWTargetSpacing
  150→75 at BUTTERCUP 707000), `nPowAllowMinDifficulty` disabled on mainnet —
  identical.
- **subsidy-founders:** base reward `12.5*COIN`, slow-start ramp, halving (pre/post-
  BUTTERCUP triple-halving), intervals (840000/1680000), `halvings>=64` guard, all 48
  founders addresses byte-identical and in order, `GetLastFoundersRewardBlockHeight=
  840000`. Founders reward is NOT consensus-enforced in either tree (vestigial Zcash
  vector) — decision-identical. Coinbase value cap `bad-cb-amount` identical.
- **upgrade-heights:** activation heights, protocol versions, branch IDs,
  `enum upgrade_index` ordinals, Equihash N/K table, ALWAYS_ACTIVE/NO_ACTIVATION
  sentinels, no stock-Zcash upgrades active. Two cosmetic non-fork bugs (off accept
  path): `consensus_is_branch_id`/`consensus_is_activation_height_any` unconditionally
  return true (no caller); `chain_inspect_controller.c:148-150` `epoch_names[]`
  mislabels a display JSON string.
- **coinbase-maturity-bip30:** `COINBASE_MATURITY=100`, maturity comparison (`<100`),
  BIP30 core predicate (no BIP34 carve-out — Zclassic never had the duplicate-coinbase
  blocks), deferred-validation skip below snapshot height, BIP34 height-uniqueness —
  identical.
- **shielded-consensus (clean portion):** in-tx duplicate nullifier detection (Sprout +
  Sapling), valueBalance sources/sinks + overflow, shielded value-pool transparent
  accounting, ZIP209 turnstile on a from-genesis chain, Sapling/Sprout proof gating in
  `proof_validate_stage.c`, shielded sighash, activation heights. (Known FR-4
  `bad-sapling-root-in-block` and FR-5 `HaveShieldedRequirements` stub owned by Codex.)
