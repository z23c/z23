<!-- Copyright 2026 Rhett Creighton - Apache License 2.0 -->
# Canonical Consensus-State Bundle

This file is the naming and ownership authority for bootstrap artifacts. A
schema suffix such as `.v1` versions an on-disk contract; it is not a product
edition, implementation phase, trust level, or competing architecture. A new
suffix is allowed only for an incompatible encoding change. There is one
canonical codec; the implementation may have only one canonical writer and one
canonical reader for the current schema.

ZClassic consensus is unchanged. Z23 remains bit-for-bit
consensus-compatible with `zclassicd`; bundle and receipt schema evolution is
local storage/provenance plumbing and changes no block, transaction, script,
activation, or proof-validity rule. `USS v1`, `USS v2`, and `USS v3` are frozen
legacy import encodings. They remain readable so existing recovery artifacts do
not become useless, but no new feature is added to them and no producer may
publish them as complete sovereign state. In particular, legacy USS v3 contains
current Sapling/Sprout frontiers and nullifiers but not historical anchor rows.

The one designated canonical writable format is:

```text
zcl.consensus_state_bundle.v1
```

Its completed contract must own one bounded manifest and these independently
committed components:

- canonical transparent UTXOs, count, and supply;
- complete Sapling anchor history and current frontier;
- complete Sprout anchor history and current frontier;
- complete pool-qualified nullifier history;
- anchor height, exact local-chain block hash, and chainwork;
- a versioned source receipt, the v2 SHA-256 current-source identity claim,
  running-binary/toolchain/build-input claims, source fold cursor, chain-corpus
  digest, proof-manifest digest, and artifact digest; these are partial producer
  provenance, not complete reproducible-build proof;
- trust posture (`sovereign` or explicitly assisted), signature set, target
  lane, acceptance receipt, and rollback generation.

## Implementation status

An exporter qualification failure is a persistent dependency warning. It does
not suppress validation, transaction relay, wallet use, or public serving by an
otherwise ready node. New joiners otherwise pay the growing distance from the
newest bundle as block-download time.

The exporter recovers on its own. The durable producer session is bound to the
running executable's image digest, so every binary upgrade — even a rebuild of
the identical source tree — makes the stored session foreign and
`consensus_state_producer_receipt_begin()` refuses. That refusal used to be
decided once at boot and never re-run, so an upgraded node silently stopped
minting for good. `bundle_exporter` now re-runs every qualification rung and
re-opens the session on its ordinary tick, with exponential backoff from one
tick to one hour, and raises the `bundle_exporter.degraded` condition only
after three consecutive failed attempts — long enough that boot ordering does
not trip it, short enough that a real outage is named within a minute or two.
The condition's reason carries the literal refusal first (for a mismatch, the
exact diverging field), then the newest minted height and its age in days, and
the whole sentence is short enough to fit `BLOCKER_REASON_MAX` unclipped. It is
cleared the moment a generation is minted or the session is re-derived.

Re-deriving is gated, not automatic. A foreign session row is retired and a new
one derived from the running binary **only** when the source epoch already
stamped into that datadir's fold rows is byte-identical to the running build's
(`source_tree_root`, `toolchain_digest`, `build_inputs_digest`, `source_clean`
— the executable image is deliberately not an input to it). That is the case
where the export's own stage-row proof still holds verbatim over every
`genesis..H*` row already on disk, so the re-derive changes nothing the bundle
claims. When the source epoch actually changed, every stamped row carries the
old epoch, no bundle could be proven from them, and the session stays refused
and named — recovery there needs a re-fold, or the operator's explicit
`producer session retire`.

`consensus_state_snapshot_install()` is a deliberately contained, read-only
admission validator. The name reserves the single future installation service;
it does not imply that publication exists today. It:

- opens a non-writable regular external SQLite file with
  `O_NOFOLLOW|O_CLOEXEC`, opens SQLite through the retained
  `/proc/self/fd` identity, and holds one read transaction for the receipt's
  lifetime;
- rejects unfinished WAL/SHM/journal sidecars, enables defensive/query-only/
  untrusted-schema SQLite posture, and bounds SQLite row/query resources;
- hashes the complete SQLite file before and after semantic validation, rejects
  any byte or descriptor-identity change, and exposes whole-file revalidation
  for long evidence-capture operations;
- runs `integrity_check`, requires the closed canonical six-table schema (no
  extra tables, indexes, views, triggers, or columns), checks exact required
  scalar/blob storage classes and singleton cardinality, validates height/hash
  against the contained wrapper's caller assertion, and independently
  recomputes UTXO/anchor/nullifier digests and counts;
- rejects malformed values, non-canonical/duplicate UTXOs, duplicate roots or
  nullifiers, invalid pools, supply outside `MoneyRange`, and internally
  inconsistent component claims; and
- returns `CONSENSUS_INSTALL_VERIFIED_CONTAINED` for a structurally valid bundle,
  returns false, and performs no write to `progress.kv` or `node.db`.

`consensus_state_snapshot_export()` now implements a contained canonical writer
for a quiesced, process-owned `progress.kv`. Under one progress-store lock and
frozen read transaction it refuses an active RAM coin overlay, requires exact
computed H*, convention-aware durable tip/hash, `coins_applied=H+1`, explicit
genesis anchor/nullifier cursors, a self-folded coin set, continuous successful
header/stage rows, and an exact receipt for the running executable. It streams
all coins, historical anchors, and pool-qualified nullifiers; recomputes every
component commitment; emits the canonical eight-row `bundle_proof`; preserves
the source receipt; and verifies the result through the independent contained
reader before an exact-inode, no-replace link. When H is the compiled checkpoint
it also requires exact compiled hash/root/count/supply. For receipt v2,
`source_tree_root` is the decoded 32-byte SHA-256
`zcl.dev_source_identity.v2` claim over the current build-source
inventory, and `producer_commit` must be empty. The versioned SHA3 epoch and
receipt digests bind that claim to the running executable, validation profile,
chain corpus, fold cursor, and the recorded toolchain/build-input claims. The
legacy-named `source_clean` column is a v2 capture-completeness assertion,
always true for a production v2 writer; it is not Git HEAD cleanliness and
does not consume Git or gitlink object ids. Dirty bytes are already bound by
the source root. The
source identity recursively inventories initialized Gitlinks/submodules without
consuming their Git object ids and includes the exact selected linked archives
even when ignored. It still excludes other ignored/generated inputs, the
complete toolchain/configuration/dependency closure, and independent rebuild
evidence. The receipt is therefore partial producer provenance bound to a known
executable, not a complete or independently reproduced build proof.

The still-unpublished v1 contract distinguishes `full` validation from
`checkpoint_fold`. Script, proof, and UTXO rows written by the fast mint say
`checkpoint_fold`; they never say `verified`. That posture is contained at every
serving edge: it cannot raise `BLOCK_VALID_SCRIPTS` or verified counters, cannot
advance serving H*, tip finalization, or a repair authorizer, and cannot pass a
normal serving boot. The canonical exporter accepts only `full`; a separate
non-serving producer frontier and terminal generation receipt would have to be
designed before checkpoint-fold state could be emitted by any future diagnostic
writer. Serving H* and tip finalization must never be weakened to make such an
export possible.

The profile and legacy-named source capture-completeness bit remain bound by
the source receipt, bundle manifest, and artifact digest, and the contained
reader and candidate reader
reject any mismatch or unknown value. A checkpoint fold proves exact
transparent-state agreement at the compiled checkpoint only. It does not prove
the signatures or shielded proofs that the fast producer explicitly skipped,
does not establish complete history, and is never reported or published as full
replay evidence.

Each new script/proof row also carries the source epoch prepared in
`progress_meta`; missing/foreign epochs refuse export. This is a fail-closed
legacy-row floor: old fast rows that said `verified` acquire a NULL column and
cannot be authorized by inserting a receipt later. Producer receipt ownership
is now wired into `boot_mint_anchor_run()`: `begin()` records the running binary,
validation profile, and source epoch before the fold; `finalize()` requires that
same executable and binds the completed height/hash/fold cursor; and a successful
full-validation finalization immediately invokes the contained exporter.
Checkpoint-fold minting remains non-serving and skips bundle export. A missing
or foreign session, unstamped build, incomplete corpus, or failed finalization
leaves the producer non-exportable.

This wiring does not introduce a bundle v2. The canonical bundle remains the
closed `zcl.consensus_state_bundle.v1` encoding, while its embedded source
receipt is versioned independently. Readers retain exact v1 receipt
parse/inspection compatibility and accept current v2 receipts under their
distinct digest domains. Current builds originate
`zcl.consensus_state_producer_session.v2` and finalize
`zcl.consensus_state_source_receipt.v2`; they never originate or relabel a v1
claim. No binary may resume or finalize a v1 session, or publish/install state
from a v1 receipt. The frozen codec still requires its lowercase 40-hex Git
commit to inspect the historical digest because that field was part of the
legacy format; it never makes the evidence admissible. V2 binds the SHA-256
source identity instead and requires `producer_commit` to remain empty; optional
GitHub trace metadata belongs outside receipt authority. A future
bundle suffix is reserved for an incompatible bundle encoding change, not for
receipt migration, implementation milestones, or trust profiles.

Both reducer consumers and export proof are hash-bound. Script and proof stage
receipts carry the exact selected header hash; a missing, malformed, or foreign
hash is a named revalidation dependency and is never accepted as legacy
authority for a body read or coin write. The exporter counts proof rows only
when they join the admitted header hash at the same height.

The exporter now has one production call site: the receipt-owning full-profile
`-mint-anchor` path invokes it immediately after successful finalization. It has
no manual/refold caller and remains an artifact writer, not a node-state
publisher. Its output contract is a duplicated directory descriptor plus one
normalized filename component. It writes an anonymous `O_TMPFILE` through an
exporter-private fd-only SQLite VFS, validates the exact retained inode, then
uses an exact-inode, no-replace hard link and directory fsync. No staging
pathname exists to swap or clean up, parent-path replacement cannot redirect
the artifact, and a late final-name collision is refused without deletion.
There is no publisher transaction or crash-atomic state installation claim. A
`history_complete` bit, producer receipt, nonzero digest, or caller-supplied
height/hash is not proof of sovereignty.

The general node datadir guard is now a real process-lifetime, nonblocking
exclusive `flock` over an `openat(O_NOFOLLOW|O_CLOEXEC)` PID inode, with PID and
directory fsync. Stale PID text is diagnostic only, symlink/hardlink aliases are
refused, and release retains the inode to prevent split-lock races. This closes
the basic two-writer prerequisite; it does not itself authorize state exchange.

Every newly invoked producer datadir is durably and permanently bound to either
the full or checkpoint-fold lane before reset/resume. The binding survives a
completed artifact and normal boot rejects every producer lane. Normal boot also
rejects the older checkpoint-bound in-progress marker, which contains
pre-change producers created before this contract existed. Their old fast
rows say `verified`, and neither those rows nor the old marker records which
crypto mode produced them. Pre-lane state is therefore never allowed to bind to
the full lane: it may resume only after a conservative checkpoint-fold binding.
Keep those datadirs isolated, resume the known fast producers only with the fast
command, and never use or copy one as a serving-node datadir.

There is an unavoidable forward-only limit: pre-change fast and full producers
are byte-for-byte indistinguishable in these old rows. Code cannot retroactively
infer a fact that was never recorded. Markerless legacy state is detected from
its durable refold/applied frontier and receives the same checkpoint-fold-only
posture. It cannot be ratified as full by backfilling a receipt. New source-epoch
columns also remain NULL on legacy rows, so a later receipt cannot authorize
them for canonical export.

`consensus_state_chain_evidence_build()` is the separate process-singleton
selected-chain binder. It accepts only the opaque descriptor-bound artifact
receipt; a caller-created manifest cannot construct evidence. It requires an
unchanged durable frontier, exact selected H/hash,
failure-free validation and header-pass rows at bundle H and the sparse Sapling
frontier source, the Sapling root both at its source height and still current at
bundle H, and selected-header ancestry/work. It samples all predicates twice,
re-hashes the artifact around capture, and binds the whole-file validation
receipt. Its lane tag is descriptive, never authority. The opaque result is
diagnostic and can go stale immediately; no publisher consumes it. It does not
support caller-selected copy/datadir contexts because reducer/proof authority
comes from the open process singleton.

## Required before activation

The future protected publisher may become callable only after all of these are
implemented and proven together:

1. A full-history producer exports every transparent coin, Sapling/Sprout anchor
   row, and pool-qualified nullifier with exact component counts and digests.
   A canonical sovereign candidate additionally requires `source_clean=true`
   (the v2 exact-capture completeness assertion) and validation profile `full`;
   checkpoint-fold, incomplete, or legacy-v1 dirty evidence must remain
   explicitly assisted/contained and can never be silently promoted.
2. One single-use protected candidate must combine the artifact receipt and
   selected-chain evidence with sovereign trust posture, signed/expiring owner
   authority, exact target-store identity, lane, nonce, and rollback digest. It
   must recapture/CAS inside publication; diagnostic evidence is insufficient.
3. Export and admission must remain descriptor-bound, whole-file-hashed,
   closed-schema validated, no-replace operations. A future caller may pass a
   capability directory descriptor, never pathname authority.
4. A boot-only publisher must build and fully validate a separate
   `synchronous=FULL` candidate `progress.kv`, strictly close the active store,
   atomically exchange old/new files, fsync the directory, and strictly reopen
   without auto-quarantine/fresh-empty fallback. It must clear or prove every
   reducer log/projection dependency and leave every handle in autocommit after
   failure.
5. The prior complete generation remains physically restorable; its receipt is
   a locator and digest for real rollback state, not merely a generation number.
6. A file-backed ENOSPC/I/O/SIGKILL-at-every-boundary harness reopens the store
   and observes exactly the old or new complete generation, never a hybrid.
7. Only then do manual load and refold route through the service, followed by
   copy proof, parity, warm restart, kill-9 resume, and owner-gated canonical
   deployment.

When those gates pass, writers emit bundle v1 only. Legacy writers are deleted
only after the bundle producer, publisher, copy proof, restarts, and canonical
cutover have all passed.

## Producer/export contract

Do not extend `snapshot_from_coinskv --shielded` into this writer. That legacy
tool accepts an operator-supplied height/hash and collects only current
frontiers. The canonical exporter runs at the end of the self-mint and takes
one frozen read transaction over the complete producer `progress.kv` after the
RAM overlay is durably flushed.

Before opening an output, the exporter requires `H* == H`,
`coins_applied == H+1`, all applicable stage cursors at their serving
convention, both anchor activation cursors at zero, the nullifier activation
cursor at zero, continuous successful reducer-log evidence, and an
executable-bound source receipt. At the compiled checkpoint, its
height/hash/root/count/supply must also match exactly; the immediate cure
accepts no other anchor. It copies:

| Producer authority | Bundle authority |
|---|---|
| `coins` | `coins`, ordered by `(txid,vout)` |
| every `sprout_anchors` row | `anchors(pool=0,...)` |
| every `sapling_anchors` row | `anchors(pool=1,...)` |
| every `nullifiers` row | `nullifiers`, pool-qualified |
| exact versioned source receipt | `source_receipt` v1-compatible/v2-current partial producer claims and executable/corpus binding |
| `stage_cursor` and eight reducer logs | canonical ordered `bundle_proof` summaries |

The latest frontier for each pool is the unique greatest stored height at or
below H; it need not have been first stored at H. Every historical row is still
copied. The Sapling frontier is later required to match the locally validated
selected-chain header root. Sprout, nullifiers, and transparent state are never
described as header- or PoW-bound.

The destination is an anonymous `O_TMPFILE` in the descriptor-bound target
directory. An exporter-private SQLite VFS performs main-database I/O only on
that retained inode, with MEMORY journaling, `synchronous=FULL`, and no SQLite
sidecars. The exporter writes the manifest last, strictly closes and reopens a
true read-only descriptor, runs full integrity and contained-admission
verification, then creates the final name by an exact-inode no-replace hard
link and fsyncs the directory. Pre-link failure closes the anonymous inode; it
never unlinks a pathname. If the post-link identity/directory durability check
is ambiguous, the validated link is left for explicit inspection and the call
returns failure rather than racing to delete an unrelated replacement.

## Protected local-chain binding contract

The current diagnostic binder starts from opaque contained-bundle validation
evidence. It captures a consistent before frontier,
requires bundle H no higher than durable served H*, resolves the exact selected
chain block at H, checks failure-free `BLOCK_VALID_SCRIPTS` status and a durable
header-validation pass row, and proves the header tip descends from it.

It then resolves the selected-chain block at `sapling_frontier_height`, requires
a durable validated-header pass, compares the bundle Sapling root directly to
that block's `hashFinalSaplingRoot`, and requires that same root at bundle H so
a sparse frontier cannot be stale. A consistent equal after-frontier and
second sample of every ancestor predicate are mandatory. The evidence digest
binds the descriptor/whole-file validation receipt, logical bundle artifact,
H/hash, Sapling height/root/block hash, served H*/hash, header tip/hash/chainwork,
and descriptive lane tag. Publication remains unavailable and must recapture/
CAS from the same target store while boot-quiesced. A standalone freshness
boolean is intentionally not an activation interface.
