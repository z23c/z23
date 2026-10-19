# Sovereign cutover runbook — install the consensus-state bundle

**Status: proven mechanism.** `-install-consensus-bundle` reaches the
**CHECKPOINT_CONTENT ACTIVATE** authority
(`engine/composition/src/consensus_state_snapshot_install_checkpoint_authority.c`) and
admits-and-activates a bundle whose coins reproduce the compiled SHA3
checkpoint and whose Sapling frontier roots to the local validated header.
This runbook is the **reference procedure** for installing that cure (a
fresh node, a future regression, or a second lane) — re-verify every fact
below against the live node and current source before running any command
in it; heights, commits, and producer state rot fast in this repo. Current
live state: `docs/HANDOFF.md`.

The cure flows through a **complete consensus-state bundle** (coins +
Sprout/Sapling anchors + nullifiers, `history_complete=true`,
`activation_boundary=0`) and a dedicated boot-time consumer flag,
`-install-consensus-bundle=PATH`. `-refold-from-anchor` still exists in the
binary and `tools/repro_on_copy.sh` still supports it (a sticky-escalator
recovery rung uses it), but it is a different, narrower recipe
(transparent-only, no independent shielded-history validation): do not use
it in place of this bundle-install cure.

## The mechanism (for orientation — full contract in source)

- **Producer side** (a separate lane; not this doc's scope): a `-mint-anchor`
  fold that reaches the compiled checkpoint height (currently 3,056,758,
  `core/chainparams/src/checkpoints.c`) exports a `zcl.consensus_state_bundle.v1`
  file to `<producer-datadir>/consensus-state-bundle-3056758.sqlite`
  (`engine/composition/src/boot_mint_anchor.c:boot_mint_anchor_export_bundle`,
  `engine/composition/include/config/boot.h:420-430`). The export is proof-bound to the
  exact running binary (`running_binary_digest == SHA3(/proc/self/exe)`) and
  refuses while the in-RAM fold overlay is live. Current producer status:
  `docs/HANDOFF.md`.
- **Consumer side** (this doc, currently contained in production):
  `-install-consensus-bundle=PATH`
  (`engine/composition/src/boot_install_consensus_bundle.c`, wired in `engine/composition/src/boot.c`
  right after snapshot autodetect, contract in `engine/composition/include/config/boot.h`).
  Steps, all fail-closed:
  1. Containment — refuses on the canonical datadir (`~/.zclassic-c23`)
     unless `ZCL_DEPLOY_ALLOW_CANONICAL` is set non-empty in the environment;
     dev/copy datadirs proceed unconditionally.
  2. Admits + strictly validates the immutable bundle file (recomputes the
     UTXO root/count/supply, verifies every anchor tree→root, verifies the
     nullifier digest).
  3. Gates it through the publication compare-and-swap
     (`consensus_state_publication_cas_run`) — must return `ADMIT` (artifact +
     selected-chain + producer-source receipts all present and mutually
     binding, durable frontier not behind the bundle). A decision record
     (`consensus_state_publication_decision.v1`) is written to the datadir
     regardless of outcome.
  4. Today, production refuses after contained admission because the bundle's
     receipt is not independent authority. The following transaction is
     exercised under `ZCL_TESTING` only. Once a real external replay receipt
     exists, an authorized `ADMIT` can atomically install via
     `consensus_state_snapshot_install_activate`: one `BEGIN IMMEDIATE`
     transaction that clears the reducer-derived logs/deltas, replaces
     `coins`, resets both anchor tables + the nullifier set to activation
     cursor 0 (**complete history**, not the empty-table/positive-cursor
     shape that caused the wedge), streams every coin/anchor/nullifier row
     from the bundle, forces the 8 reducer stage cursors to the bundle height
     (`coins_applied_height = height+1`, `tip_finalize` cursor `= height`),
     sets `COINS_KV_MIGRATION_COMPLETE_KEY` + `COINS_KV_SELF_FOLDED_KEY`
     (same provenance markers `coins_kv_is_proven_authority()` /
     `coins_kv_contains_refold_marker()` read — G-SOV part 3 is satisfied the
     same way a from-anchor refold satisfies it), clears superseded shielded
     replay/backfill/refold sessions, seeds the tip anchor inside the same
     transaction, and requires exact destination commitments plus
     `H*=served=height` and `coins_applied=height+1` **before** `COMMIT`.
     The durable ADMIT's expected H*/hash is rechecked under that same lock.
     While holding the process transaction lock, it captures a **physically
     restorable prior generation** from the already-open singleton through the
     classified datadir capability with `VACUUM INTO`. It then immediately
     takes `BEGIN IMMEDIATE` and requires the SQLite data-version, total-change
     counter, and file identity to be unchanged before the first cutover write.
     The result is independently reopened/quick-checked and sidecar-checked,
     then the file and parent directory are fsynced — see Rollback below.
  5. **TERMINAL either way** — the process `_exit()`s after printing
     `INSTALLED: -install-consensus-bundle: ...` (exit 0) or a typed
     `REFUSED: -install-consensus-bundle: ...` (exit non-zero). It never
     starts P2P/RPC/frontend services. A subsequent **normal** boot (no
     `-install-consensus-bundle` flag) is required to actually fold forward
     from the installed anchor to tip.
     A rare `COMMIT_OUTCOME_UNKNOWN` refusal does not claim the old or new
     generation won; stop and inspect/restore the named durable prior copy.
  6. `ACTIVATE` refuses a bundle that is not a complete genesis-derived
     history (`history_complete=false`, `activation_boundary!=0`, or any
     nonzero shielded/nullifier source cursor) — mixed provenance (bundle
     rows beside a still-borrowed set) is structurally impossible, not just
     discouraged.

## Independent replay-receipt authority (`-verify-consensus-bundle=PATH`)

A bundle can also `ADMIT`/`ACTIVATE` via an independent replay receipt
instead of (or in addition to) the `CHECKPOINT_CONTENT` authority the
"Known-good" section above exercised. `-verify-consensus-bundle=PATH`
(`engine/composition/src/boot_verify_consensus_bundle.c`) replays the bundle against a
datadir whose own folded tables (`coins`, `sprout_anchors`,
`sapling_anchors`, `nullifiers`) independently re-derive the bundle's
digests, and on success writes `consensus_state_replay_receipt.v1` into that
datadir. Two binding rules make this receipt easy to misuse if skimmed:

- **The receipt must physically live inside the exact datadir that
  `-install-consensus-bundle=PATH` is about to run against** —
  `activate_receipt_authority_available()`
  (`engine/composition/src/consensus_state_snapshot_install_checkpoint_authority.c`) reads it via the
  install target's own `datadir_fd`, not a path argument. Copying the bundle
  without also copying the receipt file leaves the install target on the
  `CHECKPOINT_CONTENT` fallback (or `VERIFIED_CONTAINED`/refused, if that
  fallback doesn't apply).
- **The receipt is bound to the exact binary that wrote it.**
  `rr_verifier_binary_digest()` hashes `/proc/self/exe` at verify time and
  the authority check `memcmp`s it against the digest baked into the
  receipt; a receipt produced by a different build silently fails to
  authorize (no loud refusal — the install just falls through to whatever
  other authority applies). Use **one** candidate binary for every
  `-verify-consensus-bundle` and `-install-consensus-bundle` call in a given
  cutover attempt; rebuilding between them invalidates the receipt and
  requires a fresh verify pass.

Because `-verify-consensus-bundle` must run against a datadir that itself
folded genesis→anchor, and this repo never runs commands directly against a
protected producer datadir, the practical pattern is: `cp -a` the finished
producer datadir once (the receipt-verify step writes into it, which is a
write), verify against that copy, then carry the copy's bundle + receipt
pair together as the portable artifact for every subsequent install call
(copy-prove and, later, live).

## Preconditions (do not start the cutover before all of these hold)

1. **The bundle artifact exists and is admissible.** Re-verify this fresh —
   do not assume it holds from a prior run. Confirm
   `<producer-datadir>/consensus-state-bundle-<anchor>.sqlite` is present
   (currently expected at
   `$HOME/.zclassic-c23-mint-receipt/consensus-state-bundle-3056758.sqlite`)
   and non-empty. The install call re-validates it fully (root/count/supply,
   every anchor tree, nullifier digest) — a bad copy is refused, not trusted —
   but do not spend a copy-prove run on a file that is not even present.
2. **The A3 consumer lane is merged to `main`** — `boot_install_consensus_bundle`,
   `consensus_state_snapshot_install_activate`, and the `-install-consensus-bundle`
   flag wiring in `engine/composition/src/boot.c` / `engine/composition/include/config/boot.h` must be
   on the branch you build. Confirm with
   `grep -n install_consensus_bundle engine/composition/include/config/boot.h` — the field
   and the `boot_install_consensus_bundle()` declaration must both be present.
3. **Gates green on that build.** `make build-only`, `make lint`, and
   `make test-parallel` clean (`test_consensus_state_snapshot_install` in
   particular — it has an ACTIVATE-mode leg that seeds a live progress store
   into the exact `anchor_backfill_gap` wedge shape, proves a tampered bundle
   and a non-`ADMIT` CAS decision both refuse and leave the wedge intact, and
   proves a real `ADMIT` bundle installs atomically and cures it).
4. **`tools/repro_on_copy.sh` supports `--install-consensus-bundle=PATH`** on
   the checked-out tree (this lane's addition — verify with
   `tools/repro_on_copy.sh --help 2>&1 | grep install-consensus-bundle` or by
   reading the script header).

## Known-good

**Status: proven mechanism**, last exercised end-to-end on a copy-proof
fixture — the verb, the chain-binding gate, the publication CAS, the
CHECKPOINT_CONTENT authority path, and the atomic cutover all behave exactly
as designed: no installer defect found, no gate predicate touched. The
node's own `core consensus utxo commitment` recompute and an independent
recompute outside this repo's code both matched the compiled checkpoint
root — the UTXO integrity claim is doubly verified, not self-reported.
Admission (root/count/supply + every anchor tree + nullifier digest
recompute over the artifact) dominates wall time; budget the maintenance
window accordingly for a live cutover. The remaining blocker for the
CANONICAL cutover is not this installer but building the canonical
datadir's own evidence (validated chain state at/above the anchor with
pass records + proven coins authority) — see `self-verified-tip-plan.md`.

## Copy-prove step (mandatory — never live surgery)

Gate on **H\* CLIMB**, never "the install call printed INSTALLED" — that call
proves the install landed, not that the reducer can fold the ~124k blocks from
the anchor to (and past) the live wedge on real bodies. The harness enforces
this by construction: `--install-consensus-bundle` is a **two-phase** run —
phase 1 is the terminal install call, phase 2 is a normal boot with the
existing tip-watch loop — and phase 2 only starts if phase 1's log contains
the literal `INSTALLED: -install-consensus-bundle:` banner and it exited 0.

```bash
tools/repro_on_copy.sh sovereign-bundle-cutover \
  --src=$HOME/.zclassic-c23 \
  --full \
  --expect-climb-past=3176325 \
  --install-consensus-bundle=$HOME/.zclassic-c23-mint-receipt/consensus-state-bundle-3056758.sqlite \
  --deadline=3600
```

Notes:
- `--expect-climb-past=3176325` is the **current live wedge height**, not the
  bundle's own anchor height (3,056,758). The point of this gate is to prove
  the forward fold actually clears the exact height the borrowed-seed path
  got stuck on — re-derive this number fresh from `docs/HANDOFF.md` /
  `z23 dumpstate reducer_frontier` before running; it rots.
- `--full` is required (the forward fold reads on-disk block bodies); the
  harness refuses `--install-consensus-bundle` on a `--light` copy.
- `--deadline` bounds *both* phases: the install call (which should return in
  seconds) and the subsequent tip-watch window. Size it for the expected
  ~30–60 minute forward-fold window (see below) plus slack, not just the
  install call.
- The bundle PATH is resolved relative to `--src` if it lives under the live
  datadir tree (rewritten onto the COPY, same rule `--like-live` uses for
  datadir paths); an absolute path outside any datadir (e.g. the producer's
  own datadir, as in the example above) is used verbatim and is **not**
  copied — it is read directly from its real location, so it must stay
  present and unchanged for the duration of the run.
- This mode never sets `ZCL_DEPLOY_ALLOW_CANONICAL` — the COPY is never the
  canonical datadir, so the install call's canonical-lane containment gate is
  not exercised by copy-prove. That is expected; the live cutover run below
  sets it explicitly.

**Acceptance (all of G-SOV, not just a green exit code):**
1. `H*` climbs strictly past 3,176,325 (or whatever the live wedge height is
   at run time) toward the header tip. Watch via `getblockcount` (the harness
   does this for you) and cross-check `z23 dumpstate reducer_frontier`
   on a live probe of the copy's own RPC port.
2. `coins_applied_height == H* + 1` at every observed step — no rowless span.
   The decisive positive proof in-tree is
   `test_reducer_forward_progress_gate.c` PART-1
   (`ok && found && hstar==N && applied==N+1`).
3. `coins_kv_is_proven_authority() == true` **and**
   `coins_kv_contains_refold_marker() == true` on the copy after the run
   (both markers are set by the ACTIVATE install itself — confirm via
   `z23 dbquery` `SELECT key FROM progress_meta WHERE key IN
   ('coins_kv_migration_complete','coins_kv_self_folded')` or the equivalent
   native `dumpstate` call, not by assumption).
4. **Mirror same-height hash-agree:** cross-check the copy's block hash at
   3,176,325 (or the live wedge height) and again at the copy's final climbed
   tip against `zclassicd` (RPC 8232) or the soak/dev mirror nodes
   (`:18242`/`:18252`, confirmed near-tip and NOT wedged per `docs/HANDOFF.md`).
   A hash mismatch at either height is a hard stop — do not proceed to the
   live cutover.
5. No `download_queue_starved` escalation to `EV_OPERATOR_NEEDED` during the
   climb (`z23 ops debug dash selfheal` / `z23 dumpstate
   condition_engine` on the copy), and no
   finalized row at any height whose own upstream verdict was not `ok=1`
   (`z23 dbquery` over `tip_finalize_log` vs `utxo_apply_log`).

Only a run that clears all five items is a PASS. `test_parallel` green on the
candidate build is a regression floor, not evidence of any of the above.

## Owner-gated cutover (live — only after copy-prove clears every item above)

**NEVER run this against the canonical datadir until the copy-prove run
above has passed.** The live node stays wedged and readable throughout most
of this sequence; the only unavailable window is between step 2 and step 5.

1. **Stop the live service** (the install call needs exclusive write access
   to the live kernel store, `consensus.db`; a running node holds it open):
   ```bash
   systemctl --user stop zclassic23
   ```
2. **Build + install the current-`main` candidate binary.** `make deploy`
   builds, installs the binary to the service's `ExecStart` path, and ends
   with `systemctl --user restart zclassic23` — that restart is fine here
   (it comes back up on the still-wedged state, a normal boot), but it means
   you must stop the service again before the install call:
   ```bash
   make deploy
   systemctl --user stop zclassic23
   ```
   Confirm the binary that will run the install call is the one just built:
   `SERVICE_BIN=$(systemctl --user show zclassic23 -p ExecStart --value | sed -n 's/.*path=\([^ ;]*\).*/\1/p')`
   then `"$SERVICE_BIN" -version` or equivalent build-identity check against
   `git rev-parse HEAD`.
3. **Run the one-shot install directly** (not via systemd — this call is
   terminal and must not be treated as a normal service start):
   ```bash
   ZCL_DEPLOY_ALLOW_CANONICAL=1 "$SERVICE_BIN" \
     -datadir=$HOME/.zclassic-c23 \
     -install-consensus-bundle=$HOME/.zclassic-c23-mint-receipt/consensus-state-bundle-3056758.sqlite
   ```
   Require the literal `INSTALLED: -install-consensus-bundle:` line on stderr
   and exit code 0 before proceeding. On any `REFUSED:` line, STOP — do not
   retry with a different bundle file or with the containment gate defeated
   by habit; diagnose the typed reason first (a stale/tampered bundle, a
   non-`ADMIT` CAS decision, or a store error all print a specific message).
   The install failing leaves the prior wedged state byte-for-state
   unchanged (transactional; nothing partially applies).
4. **Boot normally** (no `-install-consensus-bundle` flag — a second pass of
   that flag is a no-op refusal path, not a resume mechanism):
   ```bash
   systemctl --user start zclassic23
   ```
   `-nobgvalidation` is not required for the forward fold to proceed (it only
   gates the separate from-genesis background crypto-replay thread), but
   operators have historically paired it with the immediate post-cutover
   window to keep CPU headroom on the reducer; re-enable full background
   validation once the node holds at tip if it was disabled.
5. **Expect a ~124k-block forward refold, ~30–60 minutes**, folding
   anchor+1 (3,056,759) through on-disk block bodies to the current header
   tip. Re-derive the actual block count fresh at execution time
   (`current header tip − 3,056,758`) rather than trusting this figure — the
   chain has grown since this was written. Watch progress with
   `z23 status`, `z23 dumpstate reducer_frontier`, and
   `z23 anchorstatus`.
6. **Verification (same G-SOV items as copy-prove, now against the live
   node):** `H*` climbs strictly past 3,176,325 and keeps advancing;
   `coins_applied_height == H*+1` throughout; `coins_kv_is_proven_authority()`
   and `coins_kv_contains_refold_marker()` both true; the served block hash at
   3,176,325 and at the new live tip hash-agrees with `zclassicd` (RPC 8232)
   and with the soak/dev mirrors; no `download_queue_starved` escalation
   during the climb. Do not declare the cutover done on "booted without
   FATAL" — that is exactly the false-green trap `-load-verify-boot` has
   historically hit (it no-ops once `coins_kv_is_proven_authority()` is true).
7. Update `docs/HANDOFF.md` with the new live H\* and confirm the wedge
   condition (`utxo_apply.anchor_backfill_gap`) has cleared in
   `z23 dumpstate condition_engine` / `z23 ops debug dash selfheal`.

## Rollback

The install captured a physically restorable prior generation of the kernel
store (`consensus.db` — the reducer's own singleton SQLite file; see
`docs/DEFENSIVE_CODING.md` "The one principled exception") **under the
process transaction lock immediately before the cutover transaction**, named
in the `INSTALLED:` banner and recorded in the decision record:
`<datadir>/consensus.db.preinstall.<epoch>.<pid>.<sequence>`
(a standalone `VACUUM INTO` image whose data-version/change fence matches the
cutover transaction — `consensus_state_snapshot_install_activate.c`
`activate_backup_prior_generation`). To roll back after a committed install
that turns out to be bad (e.g. the post-install forward fold surfaces a new
consensus-parity divergence, not caught by copy-prove):

1. **Stop the live service:**
   ```bash
   systemctl --user stop zclassic23
   ```
2. **Preserve the failed post-install state for diagnosis** before
   overwriting anything:
   ```bash
   cp -a $HOME/.zclassic-c23/consensus.db \
     $HOME/.zclassic-c23/consensus.db.failed-install-$(date +%Y%m%d-%H%M%S)
   ```
3. **Swap the prior logical generation back** (the exact file the install
   printed as `prior_generation_path`, not a guess at the naming pattern —
   confirm it with `ls $HOME/.zclassic-c23/consensus.db.preinstall.*` if the
   banner output was not preserved):
   ```bash
   cp -a $HOME/.zclassic-c23/consensus.db.preinstall.<epoch>.<pid>.<sequence> \
     $HOME/.zclassic-c23/consensus.db
   rm -f $HOME/.zclassic-c23/consensus.db-wal $HOME/.zclassic-c23/consensus.db-shm
   ```
4. **Boot normally and re-confirm the pre-install state** (the old wedge, at
   `H*=3,176,325` on `utxo_apply.anchor_backfill_gap`, or wherever it was)
   before deciding on a next attempt:
   ```bash
   systemctl --user start zclassic23
   ```
5. `consensus.db` is the reducer kernel singleton — the coins/anchor/nullifier
   tables (`coins_kv.c`) share this same file, keyed off the same handle as
   the stage cursors and `*_log` tables, so this `VACUUM INTO` swap restores
   the coin/anchor/nullifier state together with the reducer cursors, not
   just cursor bookkeeping. It does not touch `node.db` (blocks, wallet keys,
   peers, mempool) or `progress.kv` (the `address_index`/`txindex`
   projections). Preinstall generations are not deleted automatically; clean
   up old `consensus.db.preinstall.*` files by hand once an install is
   confirmed good and stable at tip — they are not tracked or pruned by any
   code path.

## Standing rule

**`-install-consensus-bundle=PATH` is the ONE install path, not a
one-time cure script.** It is exercised by three overlapping needs, all
through the same code and the same copy-prove discipline documented above:

- **The sovereign cure** (this doc) — install a genesis-derived complete
  bundle to replace the borrowed transparent-only seed and clear
  `utxo_apply.anchor_backfill_gap` permanently.
- **A sticky-escalator ladder rung** — a future rung that needs to re-seed a
  stalled or corrupted node from a known-good, self-derived bundle rather
  than re-deriving from genesis on the affected node itself (faster
  recovery; the bundle is the transportable unit).
- **Boot-restore after a catastrophic local-state loss** — same install call,
  same containment gate, same G-SOV acceptance bar, run against a fresh or
  reset datadir instead of a wedged one.

Any future caller of this mechanism (autonomous or operator-invoked) MUST
still clear copy-prove + all of G-SOV before touching a canonical datadir —
the containment gate (`ZCL_DEPLOY_ALLOW_CANONICAL`) makes the canonical case
opt-in, but it is not a substitute for the copy-prove step; it only stops an
*accidental* canonical install, not an unproven one deliberately opted in.
