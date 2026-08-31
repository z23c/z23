# ZCODE — decentralized C23 source-package hosting (foundation, 2026-07-27)

> User-facing entry point: [`../METAVERSE.md`](../METAVERSE.md); acceptance
> bar: [`../METAVERSE_MVP.md`](../METAVERSE_MVP.md). This is a retained
> foundation record, not a current-work queue. Current ordering lives only in
> [`FORWARD_PLAN.md`](./FORWARD_PLAN.md).

> **Execution order superseded on 2026-08-01.** Slices 1–13 below are the
> shipped package-hosting foundation. The unchecked payout slices 14–15 are
> deliberately not next. Active work is the free P2P agentic C23 development
> network in [`ZCODE_DEVELOPMENT_NETWORK.md`](./ZCODE_DEVELOPMENT_NETWORK.md):
> canonical tasks/candidates/policies/reviews/work receipts, a real local
> ZBuild worker, requester-coordinated P2P work, typed `zcode create|use|improve`,
> and FRONTIER/CANDIDATE/PROVEN durability. Trustworthy useful-work receipts
> precede token payout and decentralized custody. The planned transferable
> asset is now named ZC23; its creation-backed issuance covenant and safe
> pre-genesis order are authoritative in
> [`ZC23_LIVING_COMMONS.md`](./ZC23_LIVING_COMMONS.md).

Foundation record for the ZCODE program. The authority on existing foundations is
[`../P2P_SOURCE_HOSTING.md`](../P2P_SOURCE_HOSTING.md); this file carries the
owner's original 15-slice build order, naming, and boundaries on top of it.
That order is retained as history, not as the current queue. Consensus
parity is untouched: ZCODE is an application protocol over Z23.

Core description: publish, test, maintain and share permissive C23 code
through Z23. Earn nontransferable ZCODE Score, appear in evidence-based
ZCODE Rankings, and collect identity-bound ZCODE Badges. Any future ZC23
issuance is separately creation-attributed; transferable balance is never
score or proof.

## Naming (use consistently)

- Protocol, network, package library, and development system: ZCODE
- Planned transferable ZSLP token ticker: ZC23
- Nontransferable contribution score: ZCODE Score; leaderboards: ZCODE Rankings
- Identity-bound achievements: ZCODE Badges
- Local nontransferable reciprocity/quota credit: ZCODE Credit

Existing `zcl.zcode.*` domains and internal identifiers remain byte-stable.
This terminology is public-facing and does not authorize token genesis.

## Identity chain

```text
ZNAM name → signed release record → immutable package root
          → verified manifest → verified SHA3 chunks
```

The package hash is authoritative. ZNAM is only a human-readable pointer;
changing a ZNAM record must never change the identity of an existing release.
secp256k1 publisher keys are the authoritative contributor identity. Release
ID = domain-separated SHA3-256 over a canonical binary encoding — never sign
JSON (JSON is display-only).

## Existing foundations (reuse — do not duplicate)

- `lib/vcs/package_manifest.*` — frozen content.v2 manifest + chunk verify (KAT in P2P_SOURCE_HOSTING.md)
- `lib/vcs/package_swarm.*` — pure ANNOUNCE/WANT/DATA/CANCEL wire codec
- `lib/vcs/vcs_object.*` — CAS put discipline (tmp/fsync/atomic rename, rehash on read)
- `lib/zslp/` codec + `app/models/zslp_ledger.*` — contributor token + badge assets
- `lib/znam/` + `app/models/znam.*` — ZNAM names (`ZNAM_TYPE_CONTENT` fits package roots)
- `app/models/principal.*` + `auth_challenge.*` — external pubkey identity
- `lib/net/peer_scoring.*` — offence taxonomy (INVALID_CHUNK=50 already exists)
- `app/controllers/src/name_site_controller.c` — web/native/model integration template
- Onion routes: prefix dispatch in `https_server.c` + `onion_service.c`; classify
  new routes in `lib/net/src/onion_ratelimit.c`

## The 15 slices (build in this order; each lands green as its own commit)

1. [x] Signed ZCODE package release envelope
2. [x] 10 GiB content-addressed package store (`-packagehost=0|1`, `-packagequota=10737418240`,
       disabled by default; 2 GiB pins / 4 GiB hot verified / 3 GiB rare / 1 GiB staging+quarantine;
       `<datadir>/zcode/{manifests,releases,attestations,badges,cas/sha3/aa/,staging/,pins/}`;
       verify-before-store, dedup, atomic rename, crash recovery, never evict pins,
       no credit for unverified bytes, quota enforced before accepting; 64 MiB per-package v1 cap)
3. [x] Package publication and local search
4. [x] Contributor identity + ZNAM pointers
5. [x] Declarative C23 build recipe (bounded: public_headers/sources/test_sources/include_dirs/
       defines/allowed system libs = libc,libm,pthread/expected exit/max seconds/max bytes;
       node never compiles or executes downloaded code)
6. [x] External verifier attestations (`zclassic23-package-verify <release-root>`: no network,
       no wallet, no datadir, read-only source, tmp build dir, CPU/RAM/proc/time limits,
       GCC+Clang, ASan+UBSan, delete binaries after attestation; ≥2 approved independent
       verifier keys sign matching attestations before any reward)
7. [x] Contribution scoring (bounded deterministic; semantic-line component ≤500/release,
       tests > source; caps per release/contributor-week/releases-day)
8. [x] Simulated legacy rewards (placeholder token ID only — never ZC23 in dev;
       settlement accrues into a daily queue — see ZCL fuel economics below)
9. [x] Daily/weekly/monthly/all-time rankings (rank earned score, never token balance;
       store earned_score / token_rewards_received / current_token_balance separately)
10. [x] Simulated ZCODE badges (ZSLP-based, permanent, no double-issue per period,
        owner-reviewed plan/commit issuance in v1)
11. [x] Local P2P ratio + anti-spam policy (free allowance for new users; verified-bytes
        ratio is local credit; no global ZC23 mint for bandwidth; every rejection names
        the exact failed rule)
12. [x] Authenticated package swarm (wire package_swarm codec to authenticated transport
        only after signatures + storage are complete; rarest-first, bounded windows,
        timeouts/retries/cancel/disconnect-requeue/resume, per-peer offence accounting)
13. [x] Onion website (`/zcode*` routes, same models/projections as typed commands —
        no second package truth)
14. [ ] Owner-reviewed real ZC23 transfers (plan/commit; no automatic payout in v1;
        daily batched settlement — one ZSLP SEND per settlement window, not one per reward)
15. [ ] Owner-reviewed badge issuance

## ZCL fuel economics (owner directive, 2026-07-27)

ZCL is the fuel: every ZSLP mint/send (rewards, badges) and every ZNAM
record pays a ZCL transaction fee. Two deliverables:

1. **Daily batched settlement.** Rewards and badge transfers accrue as
   off-chain score facts and settle in ONE batched ZSLP SEND per settlement
   window (default daily), so N payouts cost ≈ one transaction instead of N.
   The settle plan must preview the exact ZCL fee before commit
   (`zcode reward plan` shows `estimated_fee_zcl`, recipient count, byte
   size); the owner confirms an irreversible spend, matching the burn-preview
   discipline in `docs/P2P_SOURCE_HOSTING.md`. Fee model: transparent ZCL tx
   with 1 OP_RETURN (ZSLP lokad payload) + N token outputs + change; size and
   fee grow ~linearly in N, so the per-recipient fee falls as the batch grows.
   Settlement stays reorg-aware and idempotent: a settled window records its
   txid; re-settling the same window is rejected by naming the rule.
2. **Cost-estimation surface.** A read-only estimator that reports the ZCL
   fuel cost of running these P2P open-source systems at declared scale —
   parameters: packages hosted, package bytes, swarm bandwidth, releases/day,
   reward recipients/day, badges/day, ZNAM records, verifier attestations,
   and LLM-token volume where an LLM-assisted workflow is part of the system.
   Output: per-action fee breakdown (bytes × fee rate), daily/monthly ZCL
   totals, and the batching savings vs naive per-action sends. Exposed as a
   typed command (`zcode cost estimate`, bounded typed JSON) and later an
   onion route, both reading the same projection. No chain writes — pure
   arithmetic over the current fee rate and payload sizes.

Tests for the economics slice(s): batch-size accounting matches the real
built transaction's vsize; fee preview within the wallet's own estimate;
idempotent re-settle rejection; reorg of the settlement tx returns the window
to the queue; estimator output is deterministic for fixed inputs and matches
the per-action formulas.

## Preference signaling, custody, and authority

Earlier drafts ambiguously put token-weighted governance back in scope. That
language is superseded by the ZC23 Living Commons covenant.

A ZC23 balance may be used only for non-authoritative preference signaling or
to determine how a holder directs that holder's own patronage. Balance,
transfer volume, patronage, PageRank, popularity, and marketplace activity do
not control evidence acceptance, ZCODE Score, rankings, badges, contributor
identity, committee selection or weight, the immutable genesis policy, local
node policy, ZClassic consensus, or another person's funds.

Collective custody remains a separately owner-gated transaction-policy
problem. If pursued, it starts with the existing consensus-valid
`OP_CHECKMULTISIG` primitive and exact plan/commit simulation. Experimental
threshold ECDSA remains disabled research behind independent audit and custody
gates. Neither custody mechanism grants policy authority, and no balance
selects its signers.
<!-- claim: symbol-present OP_CHECKMULTISIG core/consensus/src/script_interp.c # future custody simulation reuses an existing consensus primitive -->

## Typed commands (one branch)

`zcode package publish plan|commit`, `search|show|fetch|pin|unpin|peers|verify`;
`zcode contributor show|packages|rewards|badges`;
`zcode leaderboard daily|weekly|monthly|all`;
`zcode reward score|eligible|queue|plan|commit|receipt`;
`zcode badge eligible|plan|issue`; `zcode seed status|ratio`; `zcode storage status`;
`zcode cost estimate` (read-only ZCL fuel-cost projection).
All replies bounded typed JSON; publishing/rewards/badges use plan/commit.

## Boundaries (absolute)

- No consensus change; no real ZC23 token during development; no automatic
  mint/badges/execution of downloaded code; no downloaded build scripts
  (Make/CMake/shell/Python/configure never run); no ranking by transferable
  balance; ZNAM never trusted over hashes; anonymous peer count is never a
  verifier quorum; no global ZC23 for bandwidth; never test against the live
  wallet or canonical datadir; extend canonical models instead of adding a
  second package database.
- License allowlist v1: 0BSD, MIT, Apache-2.0, BSD-2-Clause, BSD-3-Clause,
  ISC, Zlib. Unknown/missing/compound rejected. Package must include license text.
- Package structure: `include/ src/ tests/ examples/ LICENSE zcode-package.json`;
  reject absolute paths, traversal, symlinks, device files, sockets, hidden
  executable payloads, oversized manifests, unknown modes, duplicate paths.

## Current state (2026-07-27, for the next developer)

Slices 1–13 are merged to `main` and pushed. Everything below is live in
the tree today:

**Trust model (the headline).** The acceptance signal for a published
package is **bit-identical reproduction by any third party**: an
independent rebuild of the same package root + recipe root + dependency
lock that emits byte-for-byte the committed artifacts
(`lib/vcs/package_reproduce.*` compares two `package_build` receipts and
names the first divergence). It is runnable today —
`zclassic23-package-verify <root> --store=<dir> --emit=<dir>
--lock-root=<hex> --reproduce-against=<build-report>` exits 0 on
`reproduction=MATCH` and 6 with a loud stderr `REPRODUCTION MISMATCH`
naming the diverging rule otherwise. `zcode package verify` reports the
`reproduction` object over the receipts filed under
`<datadir>/zcode/receipts/` (reproduced = ≥2 distinct build receipts
committing byte-identical output sets), and the reward-eligibility gates
5–8 (`lib/vcs/package_eligible.*`) pass on a recorded reproduction with
no quorum at all. The ≥2 approved-signer attestation quorum is now
explicitly the **latency optimization** over reproduction — fast-path
trust before a local reproduction exists, never a substitute for one.
What remains for the full flip: publishing the reference build-report on
the wire (the release envelope does not yet commit an artifact manifest,
and receipts carry no signer identity, so "independent" is currently
"distinct build events recorded locally", not proof of distinct
machines).

- **Library:** `lib/vcs/` — release envelope + node-bound acceptance,
  `package_store` (10 GiB CAS, `-packagehost`/`-packagequota`, quota pools
  20/40/30/10 pins/hot/rare/staging, 64 MiB package cap), `package_publish`
  (license + manifest grammar), `package_index`, `package_contributor` +
  `zcode_pointer` (ZNAM binding via P2PKH owner auth), `package_recipe`
  (declarative C23 builds), `package_attest` + `package_verify_policy`
  (≥2 approved-key quorum — the latency fast path), `package_reproduce`
  (the headline signal: the bit-identical reproduction verdict over two
  build receipts + the receipts-directory scan),
  `package_score` + `package_eligible`
  (deterministic semantic-unit scoring, 8-gate eligibility),
  `package_reward` (durable ledger + daily simulated settlement,
  placeholder token id `zcode-placeholder-token-v1-sim!!`),
  `package_rank` (UTC day / ISO week / calendar month / all-time),
  `package_badge` (13 types, permanent, dedup per contributor+type+period),
  `package_policy` + `package_service` (tiers, local ratio, offence
  accounting), `package_swarm_node` (BitTorrent-like engine over the
  `zpkgswm` wire, rarest-first, resume-after-restart).
- **Verifier binary:** `build/bin/zclassic23-package-verify` — the only
  program that compiles package code (gcc+clang × plain+ASan/UBSan,
  Landlock+seccomp+rlimits, recipe-only input, binaries deleted after).
  `--reproduce-against=<build-report>` on `--emit` is the third-party
  bit-identical reproduction check (exit 0 MATCH / exit 6 MISMATCH).
  Approved verifier keys: `<datadir>/zcode/approved_verifiers` (one
  compressed pubkey per line, local config only).
- **Commands:** `zcode.package.{publish.plan,publish.commit,search,show,
  recipe,verify,resolve,fetch,peers,pin,unpin}`, `zcode.contributor.{show,
  packages,badges}`, `zcode.reward.{score,eligible,queue,plan,commit,
  receipt}`, `zcode.leaderboard.{daily,weekly,monthly,all}`,
  `zcode.badge.{eligible,plan,issue}`, `zcode.seed.{status,ratio}`,
  `zcode.storage.status`. `discover help zcode` enumerates the live tree.
- **Site:** `/zcode*` routes on both HTTPS and the onion service
  (`app/controllers/src/zcode_site_controller.c` + `app/views/src/zcode_view*.c`,
  shared `site.css`/layout, same projections as the commands).

Former numbered tail (both owner-gated and now explicitly deferred — they
move real value but do not make decentralized development useful):

- **Slice 14** — owner-reviewed real ZC23 transfers: wire auto-enqueue of
  eligible releases into the reward queue, admit owner-approved claims,
  settle the daily queue as ONE batched ZSLP SEND against the real
  (post-simulation) ZC23 token; add the fee-preview arithmetic
  (`estimated_fee_zcl`) the settlement plan deliberately omits today.
- **Slice 15** — owner-reviewed real badge issuance: the simulated
  `zcode.badge.issue` already signs and persists; slice 15 turns reviewed
  batches into real ZSLP badge assets.

Known honest gaps (named by the slice agents, none blocking):

- Swarm rarity is package-level advertiser count (no per-chunk bitfield yet);
  `zcode.package.fetch` on a non-`-packagehost` node only persists the
  resume record; no diagnostics-registry dump for the swarm subsystem.
- POPULAR_PACKAGE / RARE_PACKAGE_SEEDER badges and the verified-bytes /
  distinct-users leaderboard categories report unavailable until slice-12
  facts accumulate on a real network.
- `lib/kernel/src/command_registry.c` gained `day` as an input key in the
  slice-12 commit (repairs a pre-existing CLI-side rejection of
  `zcode reward plan/commit --input='{"day":...}'`).
- The reward ledger/service book start empty on pre-ZCODE datadirs
  (fail-open history, by design).
- The agentic-development object wires now exist in
  `lib/vcs/include/vcs/zcode_dev.h`; their CAS/task-index and typed command
  adapters are not yet live. The existing ZBuild worker supervisor does not
  yet claim or execute actions. See
  [`ZCODE_DEVELOPMENT_NETWORK.md`](./ZCODE_DEVELOPMENT_NETWORK.md) for the
  truthful active queue.

## Process per landing unit

Smallest complete feature → focused adversarial tests → `make build-only` +
`make t-fast ONLY=<group>` + `make lint` green in an isolated worktree →
commit → merge to main → push → update the active development-network plan.
