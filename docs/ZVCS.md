# ZVCS — the in-binary version-control system

ZVCS is z23's own content-addressed version-control system,
implemented in `contexts/commons/modules/vcs/` (Apache-2.0, `Copyright 2026 Rhett Creighton`). It
is not a git wrapper and does not shell out to git: `git` stays outside the
binary entirely as an external GitHub publish/trace bridge (source-tree
publishing, PR review, and the human-facing history this repo already has).
Git object ids, including SHA-1 ids, may be retained as optional external trace
metadata, but are never ZVCS, source-identity, or producer-receipt authority.
ZVCS is the layer *inside* the binary that turns "the agent edited files and
the dev loop went green" into a durable, self-hashing commit — without ever
invoking a subprocess.

This document is the canonical description of what ZVCS is, what it stores,
and what actually calls it today. See also
[`docs/work/HOTSWAP.md`](work/HOTSWAP.md) §"ZVCS auto-anchor" and §"Sealed-consensus
refusal" for how the dev loop integrates it, and
[`docs/adr/0002-sealed-consensus-core.md`](adr/0002-sealed-consensus-core.md)
for why the sealed `core/` tree and ZVCS's seal guard exist together.

## Why an in-binary VCS

Two invariants motivate keeping a VCS inside the node binary instead of
depending on the operator's git install:

1. **Sovereignty.** The node is meant to run unattended, potentially on
   hardware that never has git installed. An agent driving the dev loop
   needs a durable record of "what source tree produced this passing
   verdict" that does not depend on an external toolchain. ZVCS supplies
   that record using only stock libc and the in-tree SHA3-256
   (`platform/modules/sha3/src/sha3.c`).
2. **"Code fearlessly, not recklessly."** A sealed-path change (see
   ADR-0002) must be structurally impossible to auto-commit. Git has no
   concept of a sealed path; ZVCS's seal guard (`contexts/commons/modules/vcs/src/vcs_seal.c`) is
   built into the commit path itself, so a snapshot that would touch a
   sealed file is refused (`VCS_REFUSED`, exit code `3`) unless a one-shot
   unseal token is present.

The **hard gate** that keeps this true is
`tools/scripts/check_vcs_no_git.sh` (wired into `make lint` as
`check-vcs-no-git`): it fails the build if any file under `contexts/commons/modules/vcs/`
references the word `git`, or calls `exec*`, `execve`, `system(`, `popen(`,
or `fork(`. `contexts/commons/modules/vcs/` is sovereign by construction, not by convention — a
regression that adds a `system("git ...")` call anywhere in that directory
turns the build red.

`tools/scripts/check_vcs_no_sha1.sh` is the separate source-authority gate. It
keeps SHA-1 primitives out of `contexts/commons/modules/vcs/`, prevents the dev source identity from
hashing Git HEAD/object data, and requires producer-receipt writers to use the
baked SHA-256 source id. Its scope is deliberately **not** all cryptographic
code: ZClassic consensus still implements `OP_SHA1`, exactly as `zclassicd`
does, and removing or changing that opcode would violate consensus parity.
This source-identity/receipt migration changes no block, transaction, script,
PoW, or activation rule.

## The model: a flat, path-sorted manifest — not git's blob/tree DAG

Git's tree object is a recursive directory DAG: one tree object per
directory, nested arbitrarily deep. ZVCS deliberately does **not** do that.
A ZVCS commit points at exactly **one manifest**: a flat, path-sorted list of
every tracked file (`contexts/commons/modules/vcs/include/vcs/vcs_manifest.h`):

```
[1  version]
[8  entry_count]
repeated entry_count times, in ascending path order:
  [2  path_len][path bytes (no NUL)][4 mode][8 size][32 blob]
```

The reason is the diff primitive it buys: "what changed between two
snapshots" becomes a **linear merge-join** of two sorted manifests
(`vcs_manifest_diff()`) — one pass over both lists, no tree recursion, no
recursive object fetches. That is the O(n) primitive an agent (or the
dev-loop status check) actually needs, and it is simple enough to read,
grep, and step through in `gdb` (Law 3: "if gdb cannot step it, it is not
beautiful").

`tree_hash` — the manifest's own content address — is:

```
tree_hash = SHA3(0x22 || concat over sorted entries of
                 SHA3(0x21 || path || 0x00 || mode_le || size_le || blob))
```

## SHA3-256 with domain tags, everywhere

Every hash ZVCS computes is SHA3-256 (the same in-tree FIPS-202
implementation the sealed `core/` manifest and the node's other integrity
checks use — `platform/modules/sha3/src/sha3.c`), and every hashed preimage starts with
a one-byte **domain tag** so that a blob, a manifest entry, a manifest, and a
commit can never collide even if their raw bytes happen to match
(`contexts/commons/modules/vcs/include/vcs/vcs_object.h`):

| Tag | Value | Meaning |
|-----|-------|---------|
| `VCS_TAG_BLOB` | `0x20` | raw file content |
| `VCS_TAG_ENTRY` | `0x21` | one manifest entry (path/mode/size/blob) |
| `VCS_TAG_MANIFEST` | `0x22` | a serialized path-sorted manifest |
| `VCS_TAG_COMMIT` | `0x23` | a commit preimage, addressed by `commit_id` |
| `VCS_TAG_SEALSET` | `0x24` | the sealed-path set commitment |
| `VCS_TAG_ANCHOR` | `0x25` | reserved for a later wave (anchor binding) |

Tag values are **permanent**: once assigned, a tag is never reused for a
different object kind — that is what makes the object store's addressing
collision-proof by construction rather than by convention.

Every object read **recomputes** the hash and rejects a mismatch
(`vcs_object_get()`); ZVCS never trusts a stored hash without re-deriving it.
The same "recompute, never trust" discipline used elsewhere in this codebase
(`seal_kv`, the sealed `core/MANIFEST.sha3`).

## Source identity v2 — current bytes, not Git history

Do not conflate the ZVCS `tree_hash` above with the dev-loop supersession id.
They are separate, versioned contracts:

- A ZVCS manifest/tree/object id is domain-separated SHA3-256 over the ZVCS
  object formats.
- `tools/dev/source-identity.sh capture` emits
  `zcl.dev_source_identity.v2`: a 64-hex SHA-256 identity over a canonical
  inventory of the current worktree. Git is used only to enumerate paths and
  inspect index modes/hidden flags. The preimage binds paths, canonical regular
  file modes and current file-byte SHA-256 digests, symlink targets, explicit
  tracked deletions, recursively inventoried initialized gitlink/submodule
  bytes, missing-gitlink markers, and the exact linked static archives selected
  by the build even when those archives are Git-ignored. It does not consume
  Git HEAD, commit, tree, blob, index, or gitlink object ids.
- `source-identity.sh paths` remains an explicitly non-authoritative,
  HEAD-relative manual diagnostic only. The dev watcher no longer invokes it
  for classification, proof routing, or publication; wake paths are hints and
  every nonempty event takes the conservative reload/Core/parity boundary.
  The `capture`, `capture-record`, and verification modes do not execute the
  HEAD comparison. They hash the complete v2 inventory directly. Therefore an
  empty/history-only Git commit leaves the source id unchanged, while a visible
  byte, path, mode, symlink, deletion, or non-ignored untracked-file change
  supersedes it.

The Makefile obtains the source id, a v2 capture-completeness bit, and a
host-local mutation token from one `capture-record`. The legacy-named `clean`
slot is always true after a successful exact capture; it is not Git cleanliness
and never compares HEAD or gitlink object ids. Dirty worktrees need no special
authority bit because their exact current bytes are already in the source id.
Cached build paths are selected by a host-local compile epoch that binds the
source id and completeness bit, mutation token, compiler/tool/search-root
fingerprint, build profile, and effective compile/link flags. A source mutation
therefore selects a new full object tree; `ccache`/`sccache` may recover
unchanged TU work, but Make never admits an object from a different epoch.
Per-TU object/depfile writes, candidate links, and stable-alias refreshes use
private staging paths plus atomic renames. Candidate and alias publication both
re-verify the complete source/compiler/session record. The mutation token binds
enumerated-input inode, size, mode, and nanosecond mtime/ctime metadata, while
an independently refreshed inventory catches stable path-set changes. This
closes ordinary edit/revert ABA for captured inputs. It is a short-lived race
guard, never a source or release identifier or a claim of an immutable
filesystem snapshot; hermetic publication still requires the Phase-3
publication epoch and independent rebuild receipts.

This v2 id is a **dev supersession identity**, used to detect source drift and
bind a build to the bytes the developer could see. It is not the future
immutable publication epoch and not complete reproducible-build provenance:
ignored files beneath the actual C23 source/include/template roots, generated
vendor headers, and linked archives are covered, but generated inputs outside
those roots remain outside this narrow source-id contract. The host-local
compile epoch additionally fingerprints admitted compiler/toolchain,
environment, dependency-search, and effective-build inputs for cache isolation;
that operational fingerprint is still not an independently reproducible
publication receipt. Phase-3 publication and independent rebuild receipts
remain required.

The earlier v1 identity hashed Git HEAD plus only the visible dirty overlay.
Its documented 128-path/0.07–0.08 second measurements describe that retired
preimage and must not be quoted for v2. The fast/portable v2 implementations
are byte-equivalence tested, including the history-only-commit invariant.
The full `capture-record` now includes recursive gitlink bytes, selected linked
archives, and two mutation-token passes. Its latency is machine/worktree
dependent and is treated as a correctness cost, not a portable performance
promise.

## Producer source receipt v2

The current producer-receipt implementation consumes the baked v2
source id through `zcl_build_source_id_sha256()`; it no longer derives new
authority from `zcl_build_commit_full()`. Git commit text is not baked into the
sovereign executable either, because its exact-byte digest is receipt authority;
GitHub publication may attach commit trace in an external sidecar. A newly
created producer session uses
`zcl.consensus_state_producer_session.v2`, and its finalized receipt uses
`zcl.consensus_state_source_receipt.v2`. The 32-byte `source_tree_root` is the
decoded SHA-256 source id. Versioned SHA3-256 epoch/receipt digests then bind
that claim with the toolchain/build-input claims, legacy-named capture-
completeness field, exact running binary, validation profile, chain corpus,
and fold cursor as applicable.

V2 requires `producer_commit` to be empty. Its legacy-named `source_clean`
column means the exact v2 inventory capture completed and is always true for a
production v2 writer; it is not a Git HEAD cleanliness claim. GitHub/external
trace metadata lives outside the authoritative receipt. Receipt/session v1
remains a read-only compatibility identity/codec for already-durable legacy
evidence. It can be inspected, but no current producer may resume or finalize
it, no external v1 receipt may validate for installation, and the publication
CAS never admits it. Current builds neither originate a new v1 claim nor
silently rewrite one as v2. The producer claims are still not independent
reproducible-build proof, and a receipt does not authorize bundle publication
or runtime activation by itself.

## The three stores

A ZVCS repo lives beside `.git/` in the working copy, at
`<repo_root>/.zvcs/`:

- **`objects/`** — the sharded content-addressed object store
  (`contexts/commons/modules/vcs/src/vcs_object.c`). Objects live at `objects/<2-hex>/<62-hex>`
  where the 64-hex name is the object id. Writes are atomic (tmp file,
  fsync, rename) and idempotent — putting already-present content is a
  no-op. Two addressing modes exist: content-addressed (`vcs_object_put`,
  used for blobs and commits — the id *is* the hash of the tagged content)
  and explicitly-addressed (`vcs_object_put_addressed`, used for manifests,
  which are addressed by their *structural* `tree_hash` rather than the raw
  serialized bytes — the reader re-derives and checks the address on load).
- **`commits.log`** — an append-only, self-verifying commit log. This is not
  a bespoke format: it is `engine/modules/storage/src/event_log.c`, the same durable,
  fsync'd, CRC'd fact log the chain reducer itself uses, with one new event
  type, `EV_VCS_COMMIT = 25` (`engine/modules/storage/include/storage/event_log.h`).
  Each commit record is a fixed-layout struct serialized to
  `VCS_COMMIT_RECORD_BYTES` (496) bytes and appended verbatim.
- **`index.kv`** — a dedicated SQLite WAL file, one handle per repo, one
  writer, writes framed in `BEGIN IMMEDIATE`
  (`contexts/commons/modules/vcs/include/vcs/vcs_index.h`). This is deliberately **outside** the
  node.db ActiveRecord lifecycle, following the same kernel-store doctrine
  as `consensus.db` (`storage/progress_store.h`, historically `progress.kv`)
  and `seal_kv`: a small
  dedicated single-writer store below the AR layer, marked with the
  `// raw-sql-ok:vcs-index-kernel-store` lint-gate exemption. Every row in
  `index.kv` is **derived** — regenerable from the worktree plus
  `commits.log` by `vcs_index_rebuild()` ("recompute, never repair"). Tables:
  `stat_cache` (mtime/size/ctime → blob hash, the warm-path cache that lets
  `vcs_status`/`vcs_manifest_build` skip re-reading unchanged files),
  `refs` (currently just `HEAD`), `seal_pin` (the currently-accepted
  sealset hash), `anchor` (per-commit generation/verdict binding), and
  `meta` (free-form key/value).

## The commit record

A commit is a self-hashing, fixed-layout, little-endian struct
(`contexts/commons/modules/vcs/include/vcs/vcs_commit.h`). The canonical preimage, in order:

```
[4   version]
[32  parent]              (all-zero for the first commit)
[32  tree_hash]            the manifest this commit points at
[32  sealset_hash]         SHA3 commitment over sealed-path entries
[32  generation_sha256]    the binary generation this cycle produced
[4   verdict_status]       0 = passed dev-cycle; nonzero = not passed
[24  phase]                e.g. "resident_commit", "transactional_reload"
[8   elapsed_ms]
[32  failure_hash]
[64  agent_id]             from ZCL_AGENT_ID
[64  session_id]           from ZCL_SESSION_ID
[128 task_ref]             from ZCL_TASK_REF
[8   committed_at]         unix seconds
```

```
self_sha3  = SHA3(preimage)              (self-verify discipline, seal_kv-style)
commit_id  = SHA3(0x23 || preimage)      (the object-store address)
```

The record (`preimage || self_sha3`) is appended to `commits.log` **and**
stored as an object addressed by `commit_id`, so `vcs_object_get(commit_id,
VCS_TAG_COMMIT)` round-trips it. `vcs_commit_deserialize()` deliberately
distinguishes "hard parse failure" (bad length/version → `false`) from "the
record parses but its self-hash doesn't recompute" (`true`, `*self_ok =
false`) — a reader can step past a corrupted record instead of aborting the
whole log walk.

`generation_sha256` is what binds a source snapshot to the *binary* it
produced: a raw SHA-256 digest of the exact hot-swap `.so` (`artifact_sha256`
from the native hot-swap result) or the exact reload generation
(`candidate_sha256` from the `zcl.agent_dev_deploy.v1` state file), decoded
by `vcs_devloop_hex32_decode()`. A `check` cycle (docs-only, no build) has no
generation to bind, so it commits with an all-zero `generation_sha256` —
the source snapshot still lands, honestly labeled as build-less.

## Auto-anchor: every green dev cycle gets a commit

`contexts/commons/modules/vcs/src/vcs_devloop.c` is the one piece of glue between the dev loop
and ZVCS: `vcs_devloop_anchor_cycle()`, called from
`tools/dev/devloop_cycle.c:finish_cycle()` after a passing
`zcl.dev_cycle.v1` verdict. It records the verdict's phase and any generation
digest the verified cycle actually produced. A historical/reserved phase name
such as `resident_commit` or `transactional_reload` is not, by itself, proof
that a runtime generation was published. During current Phase-0 containment,
the public watcher and change surfaces verify/check only; apply, hot-swap,
reload, stage, generation relinking, and deploy-dev entry points fail closed.

This call site is **fail-open by design**, stated directly in the header
comment: a ZVCS failure here must never fail the dev cycle or crash the
loop. `finish_cycle` still returns `passed`/`rejected` exactly as it would
without ZVCS; the verdict JSON gains one extra field —
`"vcs_commit":"<64-hex commit id>"` on success, or `"vcs_error":"<message>"`
on failure. The one status that is surfaced loudly (not just logged) is
`VCS_DEVLOOP_ANCHOR_REFUSED` — a sealed-path snapshot refusal — which adds
`"vcs_sealed_refusal":true`. As of this wave that refusal is **advisory
only** to the verification verdict at this integration point: it means the
cycle's ZVCS source snapshot did not land, not that source authority was
granted. Any future reopening of runtime publication must enforce the sealed
preflight and proof/CAS transaction before mutation; the current contained
surface does not publish a running generation.

The very first call on a fresh `.zvcs/` walks the whole tracked worktree
once (logged via `LOG_INFO`); every call after that tracks only the change
set, because the object store dedupes unchanged blobs and the `stat_cache`
skips re-reading files whose mtime/size/ctime match the cached row.

## Seal integration — a snapshot cannot silently touch consensus

`contexts/commons/modules/vcs/src/vcs_seal.c` is ZVCS's own sealed-path guard, independent of (but
aligned with) the physical `core/` seal described in ADR-0002. On every
`vcs_snapshot()`:

1. Load the sealed glob set — from `.zvcs/sealed_paths` if present, else the
   compiled default: `core/`, `domain/consensus/`, `lib/consensus/`, <!-- doc-path-ok: quotes the compiled glob set in contexts/commons/modules/vcs/src/vcs_seal.c, which still lists the pre-core/ globs -->
   `core/modules/validation/`, `core/modules/chain/`, `core/modules/mining/`, `engine/jobs/`.
2. Compute `sealset_hash` — `SHA3(0x24 || concat over the bytewise-sorted
   entry hashes of every manifest entry matching a sealed glob)`. Sorting
   makes it order-independent and stable.
3. Compare against the pinned `sealset_hash` in `index.kv`'s `seal_pin` row.
   Unchanged (or no pin yet, i.e. the first snapshot) → `VCS_SEAL_OK`. Changed
   with a valid one-shot unseal token authorizing exactly that new sealset →
   the token is **consumed** and the snapshot proceeds. Changed with no valid
   token → `VCS_SEAL_REFUSED`, which propagates out of `vcs_snapshot()` as
   `VCS_REFUSED` (exit code `3`).

v1 unseal is a one-shot token (`vcs_seal_grant_unseal()` /
`VCS_SEAL_TOKEN_KEY`); the header marks a v1.1 upgrade to an ed25519 owner
signature as future work, so consent cannot be forged by a token an agent
could mint itself.

## Revert semantics — forward-only, never rewrites history

`vcs_revert()` does **not** rewrite `commits.log` or move `HEAD` backward.
It:

1. Loads the target commit's manifest and diffs it against the current
   worktree manifest (a merge-join, same primitive as `vcs_status`).
2. Rewrites every file that differs and deletes every tracked file absent
   from the target, atomically (`write_file_atomic`: tmp file, fsync,
   rename).
3. Records the restoration as a **new forward commit** — `task_ref` is
   stamped `revert:<first 16 hex chars of the target commit id>` — so the
   append-only log gains one more entry rather than losing any.

The native dev command exposes this source-only operation as
`dev.vcs.revert` with `relink_generation=false`. Passing
`relink_generation=true` is contained and refuses **before** source mutation;
it does not rebuild, relink, deploy, or activate a generation. The lower-level
`vcs_revert()` relink callback remains an internal seam for a future durable
transaction, not public activation authority.

## Module map (`contexts/commons/modules/vcs/`)

| File | Owns |
|------|------|
| `vcs.c` / `vcs.h` | The façade: `vcs_open`/`vcs_close`, `vcs_snapshot`, `vcs_status`, `vcs_log`, `vcs_revert`. Composes everything below. |
| `vcs_object.c` / `vcs_object.h` | The sharded content-addressed store under `.zvcs/objects/`. |
| `vcs_manifest.c` / `vcs_manifest.h` | The flat path-sorted manifest: build from the worktree, serialize/parse, `tree_hash`, merge-join diff. |
| `vcs_commit.c` / `vcs_commit.h` | The self-hashing commit record: serialize/deserialize, `commit_id`. |
| `vcs_index.c` / `vcs_index.h` | The derived `index.kv` SQLite WAL store (stat cache, refs, seal pin, anchor, meta) + `vcs_index_rebuild()`. |
| `vcs_seal.c` / `vcs_seal.h` | The sealed-glob guard: glob loading/matching, `sealset_hash`, unseal-token grant/check. |
| `vcs_devloop.c` / `vcs_devloop.h` | The dev-loop ↔ ZVCS glue: `vcs_devloop_anchor_cycle()`, fail-open by design. |
| `vcs_walk.c` / `vcs_walk.h` (private) | Tracked-set traversal shared by the manifest builder and index rebuild: the ignore predicate (`.git/`, `.zvcs/`, `build/`, `vendor/lib/`, `*.db`, `node.db*`, `test-tmp*`) and per-file blob hashing. |
| `vcs_priv.h` | Private helpers shared across the `.c` files (hex encoding, etc — not part of the public API). |

Test coverage: `make t ONLY=vcs_core` covers the object store, manifest,
index, and seal guard in isolation; `make t ONLY=vcs_devloop` covers the
dev-loop glue (`vcs_devloop_anchor_cycle`, hex decoding, and the
sealed-refusal path). Both are registered in `tests/harness/src/test_parallel.c`.

## The current `dev vcs` surface

The native dev registry exposes `dev.vcs.revert` for append-only source-tree
reverts. It requires a dev build and a 64-hex ZVCS commit id; use
`relink_generation=false` under current containment. There is still no native
`dev.vcs.status` or `dev.vcs.log` leaf. Do not infer additional ZVCS or
runtime-publication authority from the
existence of the façade functions in `vcs.h`.
