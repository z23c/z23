# Fresh-start seam — why a genuinely bare boot reaches no state and folds nothing

Scope: one bare `z23` process, an empty datadir, an isolated `$HOME`
(no `~/.zclassic`), no snapshot/bundle/import flags. This file maps, in
present tense and against code at `HEAD`, every state source such a boot can
legitimately use, the exact predicate that refuses each one, and the two
independent defects that keep `H*` at 0.

Read with [`CONSENSUS-STATE-BUNDLE.md`](./CONSENSUS-STATE-BUNDLE.md) (artifact
naming/ownership) and [`../CONSENSUS_PARITY_DOCTRINE.md`](../CONSENSUS_PARITY_DOCTRINE.md)
(why a header match is not a state authority).

---

## 0. The two defects, stated once

There are **two independent seams**, not one. Fixing either alone does not
produce a working fresh machine.

| # | Seam | Effect |
|---|---|---|
| **A** | The instant-on fast-start (the "weld") never runs when the node is started with `-connect=` and no `-fileservice=`: the file-service seed list is assembled to zero entries and the fetch returns before any discovery. | No bundle, no header seed → `bootstrap.no_state_source`. |
| **B** | The declared fallback — "the node still proceeds with normal from-genesis IBD" — is **false**. `body_persist` wedges permanently at height 0 because genesis is marked `BLOCK_HAVE_DATA` with `nFile = -1` and no body bytes on disk. | `H* = 0` forever, no blocker of its own. |

Seam B is the reason the node folds *exactly zero* blocks even while it is
downloading and persisting real block bodies at 178k+ and admitting headers at
~730/s.

---

## 1. Seam A — where a bare boot concludes it has no state source

### 1.1 The decision point

`engine/composition/src/boot_auto_install_bundle.c:643-652` (inside
`boot_select_state_source`, called from `engine/composition/src/boot.c:3798`):

```c
    if (!out->auto_installed_bundle && !out->consumed_auto_refold &&
        !out->do_from_anchor &&
        !boot_consensus_bundle_marker_exists(ctx->datadir) &&
        !boot_install_bundle_pending(ctx->datadir) &&
        !nss_bundle_staged(ctx->datadir) &&
        nss_no_meaningful_chain_state(ms)) {
        struct no_state_source_facts f;
        nss_classify(ctx, &f);
        no_state_source_raise(&f);
    }
```

`no_state_source_raise` is `engine/conditions/src/no_state_source.c:87`; the
typed blocker id is `bootstrap.no_state_source`, class `dependency`,
`retry_budget = -1`.

### 1.2 The predicate that actually refuses

The seven conjuncts above are all *consequences*. The single upstream refusal
is in the weld's seed assembly, `engine/composition/src/boot_bundle_fetch.c:486-497`:

```c
    if (ctx && ctx->file_service_peer && ctx->file_service_peer[0]) {
        bbf_add_peer(peers, &np, cap, ctx->file_service_peer);
        ...
    }

    if (!(ctx && ctx->connect_only)) {
        for (int i = 0; ZCL_BUNDLE_FETCH_CLEARNET_SEEDS[i]; i++)
            bbf_add_peer(peers, &np, cap, ZCL_BUNDLE_FETCH_CLEARNET_SEEDS[i]);
    }
    return np;
```

`ctx->connect_only` is set by `-connect=` at `engine/composition/src/args.c:259`. With
`-connect=` and no `-fileservice=`, `np == 0` and
`boot_bundle_fetch_maybe` returns at `engine/composition/src/boot_bundle_fetch.c:817-822`
before discovery, before the header seed, before the bundle:

```c
    if (np == 0) {
        LOG_INFO(BBF_SUBSYS,
                 "no file-service seeds available (connect-only with no "
                 "-fileservice peer) — skipping instant-on fetch");
        return false;
    }
```

**Consequence for the C3 stopwatch.** `tools/scripts/cold_start_to_tip_stopwatch.sh:525-537`
launches the node with `-connect="$PEER"` and only adds `-fileservice=` when
`--file-peer=` was passed. A stopwatch run without `--file-peer` therefore
measures a node whose fast-start path is structurally disabled by the harness's
own isolation choice. It is not a measurement of the weld.

### 1.3 The blocker reason mislabels this

`nss_classify` (`engine/composition/src/boot_auto_install_bundle.c:556-583`) asks
`boot_bundle_fetch_should_run(ctx->datadir, ctx)`, which does **not** consult
`connect_only` (`engine/composition/src/boot_bundle_fetch.c:42-64`). So the classifier
concludes "eligible + attempted, nothing landed", finds no
`<datadir>/bundles/directory.json`, and reports
`NO_STATE_SOURCE_FETCH_NO_SEED`. The published reason is

> `no fast-start state source selected (fetch=no_seed bundle=none)`

which reads as "no reachable seed served a usable manifest". The truth is "the
seed set was empty before any peer was contacted". `fetch=no_seed` is
observationally indistinguishable today from a genuine discovery miss.

---

## 2. Every state source a bare boot could use, and what refuses it

| Source | Where it would be selected | What refuses it on a bare boot |
|---|---|---|
| **Compiled SHA3/ROM checkpoint** (`core/chainparams/src/checkpoints.c`, `get_sha3_utxo_checkpoint` / `get_rom_state_checkpoint`) | as the *authority* for a bundle install, `engine/composition/src/consensus_state_install_runtime.c:592-602` | Nothing refuses it — but it is a **commitment, not loadable state**: `struct sha3_utxo_checkpoint` (`core/chainparams/include/chain/checkpoints.h`) holds height, block hash, a SHA3 over the canonical UTXO set, count and supply. It can *verify* a UTXO set; it cannot *be* one. It is inert without bytes to check. |
| **rom_fetch swarm download** (`core/modules/net/src/rom_fetch.c`, `engine/composition/src/boot_bundle_fetch.c`) | `boot_select_state_source` → `boot_bundle_fetch_maybe`, `engine/composition/src/boot_auto_install_bundle.c:605` | `np == 0` under `-connect=` without `-fileservice=` (§1.2). Without `-connect=` it runs against `ZCL_BUNDLE_FETCH_CLEARNET_SEEDS` (`engine/composition/include/config/bundle_fetch_seeds.h`). |
| **Header-chain seed artifact** (`block_index.bin`) | `boot_header_seed_import_maybe`, `engine/composition/src/boot_auto_install_bundle.c:614` | `engine/composition/src/boot_header_seed_import.c:57-59` — `stat("<datadir>/bundles/block_index.bin")` fails because the fetch above never ran. Pure no-op, fail-open. |
| **Consensus-state bundle install** (`engine/composition/src/consensus_state_snapshot_install.c`, `consensus_state_install_runtime.c`) | `boot_maybe_auto_install_consensus_bundle`, `engine/composition/src/boot_auto_install_bundle.c:395` | `boot_autodetect_consensus_bundle` returns NULL: `opendir("<datadir>/bundles")` fails (`engine/composition/src/boot_auto_install_bundle.c:92-94`). Nothing was downloaded. If a bundle *were* staged, the next gate is §3. |
| **Legacy `~/.zclassic` import** | `engine/composition/src/boot.c` legacy-import ladder | Two refusals: the harness passes `-nolegacyimport`, and the isolated `$HOME` has no `~/.zclassic` at all. On a genuinely fresh machine the second refusal is the real one and is correct. |
| **`utxo-anchor.snapshot` from-anchor reset** | `out->do_from_anchor`, `engine/composition/src/boot_auto_install_bundle.c:628-632` | `engine/composition/src/boot_anchor_snapshot_reachability.c:131-138` — `stat("<datadir>/utxo-anchor.snapshot")` returns `ANCHOR_SNAPSHOT_ABSENT`. This artifact is minted by an already-synced node (`-mint-anchor` / `tools/seed_anchor_snapshot.sh`) and is **not** among the artifacts the weld fetches. A fresh datadir cannot have one. |
| **From-genesis fold** | the declared fallback in the comment at `engine/composition/src/boot_auto_install_bundle.c:636-642` | Not refused — *wedged*. See §4. |

---

## 3. The install gate is NOT circular at HEAD

The historically reported circularity — "the install gate reads a
validated-header frontier only the install can populate" — is **refuted** by
current code. Both sides:

**The gate** (`engine/composition/src/consensus_state_install_runtime.c:505-520`):

```c
        if (checkpoint_bundle && ms) {
            (void)consensus_state_install_restore_checkpoint_header_frontier(
                ms);
        }
        if (checkpoint_bundle && ms &&
            !consensus_state_checkpoint_header_ready(ms)) {
            out->retriable_headers_not_ready = true;
            ...
            rc = ZCL_ERR(-2,
                         "checkpoint bundle deferred: validated header chain has "
                         "not yet reached checkpoint height %d (header frontier "
                         "h=%d) — retriable wait, not a bundle rejection",
```

**The breaker** (`engine/composition/src/consensus_state_install_header_frontier.c:33-83`):

```c
bool consensus_state_install_restore_checkpoint_header_frontier(
    struct main_state *ms)
{
    ...
    struct block_index *candidate =
        block_map_find(&ms->map_block_index, &cp_hash);
    if (!candidate || candidate->nHeight != cp->height ||
        !candidate->phashBlock) { ... return false; }

    /* Frozen full PoW + Equihash validation precedes the durable fact. */
    if (!validate_headers_stage_ensure_pass_record(ms, cp->height)) { ... }
    ...
    enum csr_result rc = csr_promote_header_tip(
        csr_instance(), &ms->chain_active, &ms->pindex_best_header, candidate,
        "instant_on_checkpoint_frontier", &promoted);
```

The install itself mints the pass record and promotes the header frontier, from
the **baked** checkpoint hash, after a full Equihash validation. So the gate's
real requirement is narrower than "a validated-header frontier": it is

> **the baked checkpoint header must be present in `ms->map_block_index`.**

Two things can put it there, and neither is the install:

1. `boot_header_seed_import_maybe` → `load_block_index_flat` (the downloaded
   `block_index.bin` artifact), `engine/composition/src/boot_header_seed_import.c:101`.
2. Ordinary P2P header sync, which happens *after* `boot_select_state_source`
   and re-arms the install through the `checkpoint_bundle_install_ready`
   condition (`engine/conditions/src/checkpoint_bundle_install_ready.c:89,129`).

**The residual dependency is a timing wall, not a cycle.** Measured header rate
on a bare boot against one peer is ~730 headers/s (449,600 validated headers in
598 s). Reaching the compiled checkpoint at h=3,056,758 by P2P headers alone is
therefore **~70 minutes** before the install can even be attempted. The header
seed artifact exists precisely to collapse that wall, and it rides the same
seed set that §1.2 empties.

The design already anticipates a zero-fold node: the chain-binding decision has
an explicit clean-genesis relaxation,
`engine/services/src/consensus_state_chain_binding_service.c:231-232`
(`fresh_genesis_admissible = (cp_auth || assisted) && observation->fresh_genesis_bootstrap`),
and the compiled-checkpoint content authority
(`consensus_state_chain_binding_uses_checkpoint_authority`,
same file lines 99-121) admits a bundle **only** when its manifest reproduces
the compiled checkpoint's block hash and Sapling frontier root/height
byte-for-byte. Trust roots in the shipped binary, not in the seeder. That is the
sovereignty-correct shape and it is already built.

---

## 4. Seam B — the from-genesis fold is wedged at height 0

This is a genuine defect, independent of everything above, and it is why `H*`
stays at 0 while the node is demonstrably healthy on the wire.

### 4.1 Genesis is marked `HAVE_DATA` with no body

`engine/services/src/block_index_loader.c:783-793` (fresh datadir path):

```c
    if (ms->map_block_index.size == 0) {
        struct block_index *genesis = chainstate_insert_block_index(...);
        if (genesis) {
            genesis->nHeight = 0;
            genesis->nStatus = BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA;
```

and again defensively at `engine/composition/src/boot.c:2988-2995`. Neither writes block
bytes. `disk_block_pos_init` sets `nFile = -1`
(`core/modules/chain/include/chain/chain.h:85`), and no `write_block_to_disk` call ever
targets genesis — the only writer is `engine/reducer/services/src/reducer_ingest_service.c:301`,
fed by P2P block ingest, and no peer sends the node its own tip.

### 4.2 `body_persist` reads it, fails, and clears the bit forever

`engine/jobs/src/body_persist_stage.c:188-210`:

```c
    struct block_index *bi = stage_body_index_at(ms, next_h);
    if (!bi || !bi->phashBlock ||
        !(block_index_status_load(bi) & BLOCK_HAVE_DATA)) {
        atomic_store(&g_last_blocked_unix, platform_time_wall_unix());
        return JOB_IDLE;
    }
    ...
    if (!read_ok) {
        block_free(&owned);
        return requeue_body_for_refetch(bi, next_h, "read_failed",
                                        &g_read_failed_total);
    }
```

`requeue_body_for_refetch` (same file, 129-142) clears `BLOCK_HAVE_DATA`, holds
the cursor, and returns `JOB_IDLE`. The remedy it relies on — "let the normal
`!HAVE_DATA` sync path re-download the body" — **cannot fire for genesis**. The
block-request collector at `core/modules/net/src/msg_headers.c:112-129` starts at
`active_chain_tip(&ms->chain_active)` and only ever collects
`main_state_best_known_successor(...)` entries; the headers-driven sequence
queue at the same file, lines 709-716, additionally requires
`pindex->nHeight > pre_tip_height`. Genesis *is* the tip, so height 0 is
structurally unrequestable. On the next tick the `HAVE_DATA` guard above
short-circuits to `JOB_IDLE`, so the counter never advances again and
`blocked_count` stays 0. There is no genesis special case in
`body_persist_stage.c`, `body_fetch_stage.c` or `script_validate_stage.c`.

### 4.3 Observed, `20260727T235031Z-1331679`

```
23:50:40  WARN [body_persist] body_persist_stage.c:138 requeue_body_for_refetch():
          [body_persist] read_failed height=0: cleared HAVE_DATA, holding cursor
          for body re-fetch
```

Three seconds after boot; never recovers across the remaining 614 s. End-of-run
stage cursors from the same artifact:

| stage | cursor | advanced | blocked | note |
|---|---|---|---|---|
| `header_admit` | 450081 | 450081 | 0 | healthy |
| `validate_headers` | 450081 | 8438 | 0 | 450081 passed, 0 failed |
| `body_fetch` | 178110 | 178110 | 0 | healthy |
| `body_persist` | **0** | **0** | **0** | `read_failed_total=1`, `idle_count=26545` |
| `script_validate` … `tip_finalize` | 0 | 0 | 0 | starved by `body_persist` |

Bodies were arriving and landing on disk the whole time
(`reducer_persist_ingested_body_locked(): persisted ingested block bodies
through h=178176`). The pipeline was never body-starved; it was pinned on
block 0.

Note the honesty gap: `body_persist` returns `JOB_IDLE`, not `JOB_BLOCKED`, and
names no blocker of its own. Nothing in the four active blockers points at
height 0 — `bootstrap.no_state_source` and `chain.tip_behind_header_chain`
describe adjacent facts, and the two `sticky_escalator.*` rungs describe absent
recovery artifacts. The wedge itself is unnamed, and is only visible by reading
`stage-body_persist.json` or grepping `node.log`.

---

## 5. The two failed self-heal routes

Both routes want an artifact a fresh datadir cannot have, and both name it
correctly.

**`sticky_escalator.resnapshot_no_base`** — `engine/services/src/sticky_escalator.c:457-471`.
It asks `reducer_frontier_nearest_loadable_self_verified_base(...)` for either a
self-valid seal (needs a prior successful fold — `H*` is 0, so none) or the
compiled checkpoint *plus its snapshot artifact*
(`boot_refold_from_anchor_artifact_available`, line 450). Neither exists.
Refuses fail-closed, correctly: the compiled checkpoint is a proven hash, not
loadable state.

**`sticky_escalator.refold_no_anchor_artifact`** — `engine/services/src/sticky_escalator.c:654-678`.
Same predicate, same artifact:
`<datadir>/utxo-anchor.snapshot`, resolved by
`boot_anchor_snapshot_path_resolve` (`engine/composition/src/boot_anchor_snapshot_reachability.c:49-75`)
and rejected `ANCHOR_SNAPSHOT_ABSENT` at line 132.

**Who was supposed to produce it:** an already-synced node running the
`-mint-anchor` ceremony or `tools/seed_anchor_snapshot.sh`. It is a *recovery*
artifact for a node that once had state, not a *bootstrap* artifact. Neither
escalator rung is a fresh-start path and neither is wrong to refuse. They are
noise in this failure mode, downstream of §1 and §4.

---

## 6. Smallest sovereignty-respecting change

Three changes, in dependency order. None of them touches `core/`, none of them
weakens a consensus predicate, and none of them lets a peer's word substitute
for the baked checkpoint.

**(1) Let the genesis body exist. [required, small]**
`body_persist` at height 0 must not depend on a block file that no writer
produces. The sovereignty-clean options, cheapest first:

* Serialize the compiled genesis block (already fully specified in
  `core/chainparams`) to `blocks/blk*.dat` once, on the fresh-datadir path in
  `engine/services/src/block_index_loader.c:783-793`, and set `nFile`/`nDataPos`
  on the index entry. The bytes come from the binary, so no trust is added.
* Or make `body_persist`/`script_validate`/`utxo_apply` treat height 0 as a
  compiled constant and advance without a disk read (genesis has one coinbase,
  zero spendable outputs by consensus).

Either way, add a `JOB_BLOCKED` + named blocker when
`requeue_body_for_refetch` fires at a height the fetch path cannot re-request,
so this class can never be silent again.

**(2) Stop `-connect=` from emptying the file-service seed set. [required, small]**
`-connect=` is a *P2P* containment flag; `bbf_assemble_seeds`
(`engine/composition/src/boot_bundle_fetch.c:492`) currently reads it as a file-service
containment flag too. Options: honour the compiled clearnet seeds under
`connect_only` (they are unauthenticated transport and every byte is
content-verified before it lands, per that file's own trust note), or give the
stopwatch a `-fileservice=` default derived from `--peer`. Whichever is chosen,
`nss_classify` must gain a distinct outcome token — `fetch=seeds_suppressed` —
so the blocker never again reports `no_seed` for a fetch that was never
attempted.

**(3) Make the header seed a first-class prerequisite, not an optimisation. [required, medium]**
The install correctly defers until the baked checkpoint header is in the block
map (§3). By P2P that is ~70 minutes. `boot_bundle_fetch_maybe` already
downloads the header seed first
(`engine/composition/src/boot_bundle_fetch.c:866-877`) — but it is `have_header_seed`-optional
and a miss is only a `LOG_WARN`. On a bare boot the header seed is on the
critical path and its absence should raise a named blocker
(`header_seed.*` ids already exist in `engine/composition/src/boot_header_seed_import.c:37-43`),
not a warning.

### Is the honest fix small?

**Items (1) and (2) are small and mechanical. Item (3) is small in code and
large in operations.** The mechanism is complete: the swarm transport, the
content-verified download, the compiled-checkpoint content authority, the
clean-genesis relaxation, and the durable install-on-next-boot request all
exist and are wired. What is missing is not code — it is that the *fresh-boot
path has never been exercised end to end*, because every prior cold start was
assisted (legacy import, staged bundle, or a header-source copy) and therefore
floored the reducer cursors above 0, hiding §4 entirely.

Expect the first genuinely bare run after (1)+(2)+(3) to surface further
defects on the same never-executed path. That is the real cost, and it is not
avoidable by making the change smaller.

### What must not be built

Do **not** add a path that accepts a peer-supplied state root because it
matches a validated header. ZClassic headers commit neither the UTXO set nor
the shielded frontier nor nullifiers. The only admissible shape is the one
already implemented: the bundle's manifest must reproduce the compiled
checkpoint's block hash, Sapling frontier root and frontier height
byte-for-byte
(`engine/services/src/consensus_state_chain_binding_service.c:99-121`), and real
block bodies are folded forward from there.

---

## 7. Reproduce

```bash
bash tools/scripts/cold_start_to_tip_stopwatch.sh \
    --peer=<host>:8033 --budget=600
```

Then read, from the run's artifact directory:

* `proof.json` → `verdict`, `max_hstar`, `final_network_tip`
* `stage-body_persist.json` → `cursor`, `read_failed_total`, `idle_count` (§4)
* `blocker.json` → the four typed blockers and their `reason` strings
* `node.log`, grep `requeue_body_for_refetch` (§4.3) and
  `no file-service seeds available` (§1.2)

To separate the two seams, re-run with `--file-peer=<host>:18034`: that arms
the weld (§1) and leaves only §4 in play.

---
## 8. What changed (current state of both seams)

Both seams are closed in code. The bare-boot path now folds; it does **not**
yet fast-start, because no reachable seed served a bundle manifest in the
smoke run.

**Seam B — closed.** `engine/composition/src/boot_services.c` seeds the genesis anchor on
**every** network, not just regtest: when nothing else seeded this boot, the
tip is at height 0, the tip hash equals the compiled
`consensus.hashGenesisBlock`, and the finalize cursor is unseeded, it stamps
every upstream cursor to 1. This is the correct fold verdict, not a skip —
zclassicd's `ConnectBlock` special-cases the genesis block by hash and returns
before `UpdateCoins` (its coinbase is consensus-unspendable), the exemption
`engine/jobs/src/utxo_apply_delta.c` and `engine/jobs/src/psc_extract.c` already
mirror. The identity asserted comes from the byte-sealed `core/`; the anchor
row carries no UTXOs, anchors or nullifiers.

**The §4 hold is now NAMED.** `engine/jobs/src/body_persist_stage.c` arms a
wall-clock hold when `requeue_body_for_refetch` fires and raises
`body_persist.body_unfetchable` once the height has gone 60 s without a body,
clearing on any cursor advance. A repeat *count* cannot work here: the requeue
fires once and the `BLOCK_HAVE_DATA` gate then idles without re-reading, which
is exactly why the wedge was invisible. `blocker_remedy_bindings.def` binds the
new id to `OWNER` — a height at or below the active tip is not re-requestable,
so no condition can honestly claim to remedy it.

**Seam A — closed.** The file-service seed set moved to
`engine/composition/src/boot_bundle_fetch_seeds.c`. Under `-connect=` with no
`-fileservice=` it now assembles the operator's own `-connect` hosts at
`FS_PORT` instead of assembling to zero. Containment is unchanged: no compiled
seed, no gossiped address, nothing the operator did not name. `nss_classify`
gained `NO_STATE_SOURCE_FETCH_SEEDS_EMPTY` (`fetch=seeds_empty`) so "the seed
set was empty, nothing was contacted" can never again be reported as
`no_seed`, which means "seeds were contacted and none served a usable
manifest".

**What is still missing.** The §3 timing wall is untouched: reaching the
compiled checkpoint by P2P headers alone is still hours, so a bundle install
still depends on the header-seed artifact landing first, and the header seed is
still fail-open (a miss is a `LOG_WARN`, not a named blocker). A bare boot with
no reachable file-service seed therefore does full from-genesis IBD — correct,
self-verified, and very slow.
