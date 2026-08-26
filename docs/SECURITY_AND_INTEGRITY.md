# Security and Integrity Model

Z23's security model is built around operator ownership: one local
full-node binary, explicit network listeners, private wallet state, an
onion-hosted explorer, and a typed local native command operator surface. Tor support
publishes the operator's own service, wallet/key code stays inside the
operator's datadir, and fuzz/chaos harnesses exercise isolated recovery paths.
This document states the boundary, safeguards, and evidence that make those
properties auditable.

## Current status

- Z23 is pre-v1 and in active stabilization. It is not production-ready
  and has no supported release line yet.
- The v1 bar is [`MVP.md`](./MVP.md). The project does not claim v1 until all
  eight operator acceptance criteria pass at the documented bar.
- Known gaps are documented instead of hidden. Examples include the current
  live forward-progress blocker, off-chain ZMSG plaintext transport, and
  incomplete marketplace/swap settlement paths.
- Findings from external security review (fixed, refuted-with-citations, or
  deferred) are folded into "Concrete safeguards" below.

## Operator-owned scope

This repository supports authorized operation and development of a ZClassic
node and its local operator surfaces:

- validating and serving the ZClassic P2P protocol;
- running an operator-owned wallet, block explorer, onion service, and RPC
  interface;
- testing this implementation with local unit tests, fuzzers, simulators,
  isolated regtest nodes, and consenting peers.

All network, wallet, fuzz, and chaos workflows are scoped to resources the
operator controls or has explicit permission to use. If a test needs a live
process, peer, datadir, network, or wallet, use operator-owned resources,
isolated fixtures, or consenting peers.

## Security properties by component

| Component | Purpose | Safety boundary |
|-----------|---------|-----------------|
| Embedded Tor | Publish the operator's own explorer/API as a hidden service | `-tor` is explicit; opt-in build (default links a stub, onion off); test harnesses disable Tor |
| P2P networking and peer scoring | Implement the public ZClassic node protocol | Peer policy protects consensus and network health |
| Wallet and key code | Local transparent/Sapling wallet operation | Diagnostics must not return private key material |
| Native commands | Local typed operator API for AI-assisted node operation | Destructive commands are explicit and privilege-gated |
| `z23 dbquery` | Incident-response inspection of local `node.db` | SELECT-only, semicolon-rejected, limited, and rate-gated |
| Fuzzers, chaos, kill-9 harnesses | Find crashes and recovery bugs in this codebase | Isolated datadirs and ports; no live-node mutation |
| Atomic swap and market code | Application protocol scaffolding | Settlement gaps are documented; scaffolding is not claimed complete |

## Shielded transaction validation posture

This is stated explicitly because an auditor reading the source will find
`return true` in a shielded-validation helper and should know what it does and
does not mean.

- **Nullifier double-spend is enforced** on the live block-application (reducer
  fold) path — `utxo_apply_check_and_insert_nullifiers()`
  (`app/jobs/src/utxo_apply_nullifiers.c`): a two-pass check rejects a nullifier
  reused against the durable set or within the same block, then inserts the
  block's nullifiers only after it validates.
- **Shielded anchor membership is enforced** on that same reducer fold path.
  `coins_view_cache_check_shielded_requirements()`
  (`lib/coins/src/coins_view.c`) is a real implementation — no longer the
  `return true` placeholder earlier revisions of this doc described. It
  resolves every JoinSplit and Sapling Spend anchor through
  `coins_view_get_anchor()`, honors the empty-tree root as a per-pool
  constant, and reproduces zclassicd's per-transaction `intermediates` map
  (an anchor produced by an earlier JoinSplit of the *same* transaction is
  valid; one produced by an earlier transaction of the same block is not yet
  pushed). The enforcement point is `app/jobs/src/utxo_apply_anchors.c`;
  `coins_view_cache_have_joinsplit_requirements()` is now a thin bool wrapper
  over it. Pinned by `lib/test/src/test_parity_lockin_anchor_membership.c`,
  registered in the canonical catalog as
  `ZCL_TEST_GROUP(parity_lockin_anchor_membership)`.
  <!-- claim: symbol-present coins_view_get_anchor lib/coins/src/coins_view.c # membership really resolves anchors -->
  <!-- claim: symbol-present coins_view_cache_check_shielded_requirements app/jobs/src/utxo_apply_anchors.c # and is really called on the fold path -->
  <!-- claim: symbol-present parity_lockin_anchor_membership tools/dev/test_group_catalog.def # the lock-in test actually runs -->
- **Groth16 spend/output proofs, the binding signature, and the JoinSplit
  Ed25519 signature are checkpoint-gated ONLY in the legacy `connect_block()`
  path** (`lib/validation/src/connect_block.c`), equivalent to Bitcoin Core's
  `-assumevalid` (removed as a direct flag; controlled via
  `-deferproofvalidationbelow=<blockhash|0>`, default the highest in-binary
  PoW checkpoint, height 3,100,000; `core/chainparams/src/chainparams.c`). That path
  is driven by `-reindex-chainstate` (`reindex_chainstate()` in
  `config/src/boot_index.c`), by the offline harness/simnet code, and by the
  background revalidation walker (`app/services/src/bg_validation_service.c`,
  `-nobgvalidation` to disable) — which itself re-verifies every proof it
  walks and clears the deferred-height gate once the walk passes it.
  **The reducer's state-advancing path — `proof_validate_stage()`
  (`app/jobs/src/proof_validate_stage.c`), which owns the durable `ok=1`
  cursor and H\* on a normal boot — verifies every Groth16 spend/output
  proof, binding signature, and JoinSplit Ed25519 signature
  UNCONDITIONALLY on every height; it has no checkpoint-gated skip.** The
  only crypto pass-through in that reducer pipeline is the `mint_skip_crypto`
  toggle (`app/jobs/include/jobs/mint_skip_crypto.h`), which is exclusively
  set by the offline one-shot `-mint-anchor` driver
  (`config/src/boot_mint_anchor.c`, gated under `ctx->mint_anchor`), defaults
  OFF on every normal boot (a normal boot never calls the setter), and its
  output is durably marked `checkpoint_fold` (never `verified`) —
  excluded from serving validity, H\*, and tip finalization. Enforced by the
  lint gate `check-mint-skip-crypto-offline-only` + `test_mint_skip_crypto`.
- **Anchor (note-commitment-tree root) membership is not checked independently.**
  It is certified *implicitly* by the Groth16 proof, whose circuit constrains the
  Merkle path of the commitment to equal the claimed anchor
  (`lib/sapling/src/sapling_circuit.c`). On the reducer path this proof is
  verified unconditionally (above); on the legacy `connect_block()` path it
  carries the same deferred-height gating as proof verification there.

Net: on the reducer path that actually advances the node's durable tip, a
reorg cannot exceed the bounded reorg depth AND every Groth16/Ed25519
proof/signature below tip is verified — there is no `assumevalid`-style trust
window on the live, state-advancing path. The `assumevalid`-equivalent
deferred-height gate is real but confined to the legacy `connect_block()`
reindex/import/simnet path, where it carries the same practical exposure as
any `assumevalid`-style node until the background walker (or a later
`-reindex-chainstate`) passes that height. Independent (non-`assumevalid`)
anchor-membership verification on that legacy path is tracked as a hardening
item, not a claimed property.

## Concrete safeguards

- **Defensive-coding gates:** `make lint` checks raw SQLite writes, raw
  allocation use, silent error paths, native command error bodies, supervisor liveness,
  app-shape boundaries, one-write-path rules, and no-silent-ready rules. The
  detailed contract is [`DEFENSIVE_CODING.md`](./DEFENSIVE_CODING.md).
- **Local integration gate:** `make ci` runs lint before tests, then the test
  harness, benchmark regression, hermetic MVP slice gates, crash tests, and
  fuzz smoke tests where the toolchain is available. This checkout contains two
  GitHub Actions workflows under `.github/workflows/` (`pr-security-review.yml`,
  `pr-security-comment.yml`) that run an automated, fork-safe security
  review/comment on pull requests; there is no hosted build/test CI workflow
  (CI runs locally via `make ci`).
- **Operator-private HTTP routes:** `/api/wallet`, `/api/messages`, and
  `/api/swaps` are classified operator-private (`api_route_is_operator_private`,
  `lib/net/src/https_server.c`) and 403'd before dispatch on the 0.0.0.0 TLS
  clearnet listener (no CORS header); public chain-data routes are unaffected,
  the onion listener exposes no `/api`, and the in-process `wallet_gui`
  consumer bypasses the listener entirely.
- **Script opcode parsing is guarded against buffer overflow:** `script_get_op`
  enforces a destination-capacity guard before the opcode-data memcpy (an
  unguarded copy could write up to ~9994 bytes into 520-byte caller buffers —
  remote DoS/corruption on the validation path), paired with a
  `script_get_sig_op_count` fix so sigops after an oversized push are never
  undercounted.
- **Coinbase subsidy is capped** on the live reducer path
  (`app/jobs/src/utxo_apply_delta.c`, status `bad_cb_amount` — deliberately
  distinct from `value_overflow` so repair machinery never treats inflation as
  repairable).
- **Nullifier double-spend is enforced by a consensus nullifier set**
  (`nullifier_kv`, Sprout/Sapling separate namespaces, checked + inserted
  atomically with the coins commit inside the `utxo_apply` stage txn).
  **Known limit:** nullifier enforcement is activation-forward on
  snapshot-seeded datadirs (a from-genesis replay/reindex gets the complete
  set automatically); the pre-activation backfill gap is a permanent typed
  blocker (`utxo_apply.nullifier_backfill_gap`), remediated by the owner-gated
  `app/services/src/nullifier_backfill_service.c` populate-only walker.
- **Wallet backups are encrypted** when `WALLET_BACKUP_PASSWORD` is set
  (ChaCha20-Poly1305 via `wallet_backup_encrypt_file`); no password means
  plaintext continues with a loud boot warning, since refusing would silently
  kill the fleet-wide key-loss safety net.
- **Operator-private HTTP routes** are guarded as described above.
- **Refuted findings (pinned so they are not "fixed" again):** the retarget
  half of "difficulty retarget not enforced on live ingest" is false — every
  P2P header runs `accept_block_header → contextual_check_block_header →
  GetNextWorkRequired` (`bad-diffbits`); and "SIGHASH_SINGLE should return the
  Bitcoin `uint256(1)` sentinel" is a false positive — zclassicd itself throws
  and catches a `logic_error` there and returns false (bug-for-bug parity,
  pinned by `lib/test/src/test_sighash_malleability.c`); implementing the
  sentinel would be the actual fork.
- **Data-integrity discipline:** application writes go through the ActiveRecord
  lifecycle or explicit storage-layer APIs; chain progress is represented as
  durable stage cursors; recovery and self-heal paths must be observable.
- **Live-data discipline:** consensus-adjacent fixes are proven on a datadir
  copy before deployment. The isolated node harness refuses live datadirs and
  live ports and runs on throwaway `/tmp/zcl23-*` state.
- **Release integrity:** `tools/release.sh` builds with deterministic release
  flags, writes `BUILDINFO`, emits a SHA3-256 attestation, and supports GPG.
  Its `--unsigned` output is explicitly local-development-only. Stable
  publication is contained until exact-candidate quality evidence,
  independently reproduced bytes, complete SBOM/provenance/manifests, and the
  required offline signature quorum are all enforced.
- **Dependency provenance:** the shipped binary is not libc-only — it
  statically links vendored, source-built, SHA256-pinned third-party static
  libraries (OpenSSL, libevent, LevelDB, and secp256k1; see
  `tools/scripts/build_vendor.sh` and [`BUILD.md`](./BUILD.md)'s dependency
  table). The precise claim is **no unvendored, unpinned, or dynamically
  fetched-at-runtime dependencies** — every third-party source tarball is
  fetched from a pinned URL and verified against a pinned SHA256 before it is
  built and linked in; `libsecp256k1.a` (a custom fork build) ships
  committed. Vendored and ported third-party code is tracked in
  [`ATTRIBUTIONS.md`](./ATTRIBUTIONS.md), [`../NOTICE`](../NOTICE), and the
  repository tree. Packaging of several static libraries is still a known
  pre-v1 build gap and is documented in the README.

## Reproducible build gate: what is proven, what remains

The node binary is byte-for-byte reproducible across two independent builders.
`make repro-verify` (`tools/scripts/repro-verify.sh`) is the standing proof: it
snapshots the current working tree into two isolated build directories whose
absolute paths differ in both value and length, builds `build/bin/z23` in
each, and SHA3-256- plus `cmp`-compares the two shipped (stripped) artifacts. It
prints one `PASS`/`FAIL` line. It is opt-in (two full whole-program LTO links,
~2x a normal build) and is intentionally NOT on the `make lint` / `make ci`
path.

For a P2P-reconstructed source carrier, the same gate has a Git-free mode.
`ZCL_SOVEREIGN_SOURCE_ROOT` names the independently accepted ZVCS authority and
`ZCL_SOVEREIGN_VERIFY_BIN` names a pretrusted bootstrap binary that re-derives
that root through the native source-capture implementation. Snapshots exclude
both `.git` and `.zvcs`; `ZCL_REPRO_REFERENCE_BIN` adds a required byte compare
against the exact accepted candidate. This proves reconstruction/build
identity, not human acceptance of a signer: acceptance authority must already
have been resolved from the signed task/candidate/proof/lane chain.

**Proven now (full byte identity):** two builders in different absolute
directories produce an identical `build/bin/z23` — identical SHA3-256,
identical `.note.gnu.build-id`, identical bytes. `.text`/`.rodata`/`.data` were
already identical because the shipped binary is stripped (`strip -s`); the only
divergences an empirical two-directory build exposed were the absolute build
directory baked into DWARF, fixed by behavior-identical determinism flags
(`REPRO_CFLAGS` in the Makefile, no optimization or codegen change):

- `DW_AT_comp_dir` (the compile-time working directory, an absolute path) is
  remapped to a fixed virtual root with `-ffile-prefix-map=$(CURDIR)=/zclassic23`.
  Left unmapped it perturbs the split `.debug` sidecar — and therefore the
  `.gnu_debuglink` CRC32 (4 bytes) in the shipped binary — and the pre-strip
  link content — and therefore the content-derived `.note.gnu.build-id` sha1
  (20 bytes).
- `DW_AT_producer` records the exact gcc switch line when GCC defaults to
  `-grecord-gcc-switches`; that line embeds the absolute `-ffile-prefix-map`
  argument, so it is re-canonicalized with `-gno-record-gcc-switches`.

`__FILE__` / `LOG_*` strings are compiled with relative source paths, so they
are already builder-independent; the macro-prefix map does not touch them and
log/error text is unchanged. Source `file:line` crash symbolization
(`tools/scripts/symbolize_crash.sh` via the `.debug` sidecar) is unaffected —
`DW_AT_name` entries stay relative and the line program is unchanged; only the
(already-unresolvable-post-deploy) `comp_dir` source-root hint moves.
`__DATE__`/`__TIME__` are absent from the tree; the link-order source list is a
sorted `$(wildcard)` glob; the vendored static archives under `vendor/lib/` are
the same files on both of this gate's builders — it snapshots one working tree
— so archive-timestamp determinism is moot *for this gate*. That is a narrower
statement than it looks: `vendor/lib/` is `.gitignore`d apart from
`libsecp256k1.a`, so on a genuinely different machine those archives are
rebuilt by `tools/scripts/build_vendor.sh` from checksum-pinned sources and
their byte identity is **not** asserted anywhere. `z23 zcode node verify` names
each one as an `unverified` component for exactly this reason. The
content-derived `--build-id=sha1` is kept (not forced to `none`) because, once
`comp_dir` is canonical, it is itself reproducible and remains a useful
integrity anchor.

### The user-facing check: `z23 zcode node verify`

`make repro-verify` is a maintainer gate: it proves this *source tree* builds
deterministically here. It does not answer the question an ordinary user has,
which is narrower and more important — *are the bytes I am running the bytes my
own machine builds?* `z23 zcode node verify` answers that one. It hashes the
artifact you have (by default this process's own executable), rebuilds `z23`
from `source_dir` in an isolated tree via `tools/scripts/node_reproduce.sh`,
and byte-compares. It contacts nothing.

It structurally cannot perform the worthless check. Comparing a published hash
against the file it was published beside has one participant; the comparator
(`lib/vcs/src/node_reproduce.c`) refuses unless one receipt carries producer
`received` and the other `local-rebuild`, so no argument list reaches that
comparison, and no input key accepts a hash or someone else's receipt.

The `verdict` is the answer, never the envelope status:

| verdict | what it means |
| --- | --- |
| `match` | every artifact byte-identical, nothing left uncovered |
| `partial` | everything comparable matched, and the named `unverified` components were not rebuilt here. **Not a pass** |
| `source-differs` | this checkout is not the source that binary came from. Says nothing about the publisher |
| `toolchain-differs` | same source, different compiler — the ordinary reason two honest builds differ. Not evidence against anyone |
| `claim-false` | same source *and* the same recorded toolchain, different bytes: the artifact is not what this source and toolchain produce |
| `undiagnosed` | the bytes differ and an identity is missing, so it names neither rather than guessing |

Both sides' toolchain identity is read the same way — SHA3-256 over each ELF's
`.comment` section, by one implementation — because measuring the two sides
differently would grade every honest build a toolchain mismatch.

**What it covers today, exactly:** the linked `bin/z23` artifact. **What it
does not:** the vendored static archives under `vendor/lib/` (consumed as
prebuilt inputs, not rebuilt — and `libsecp256k1.a` is a binary committed to
the tree whose own `vendor/provenance/` manifest records
`source_status=legacy-import-source-unresolved`), the per-translation-unit LTO
intermediates (gcc streams absolute paths into the compressed LTO IR where
`-ffile-prefix-map` cannot reach), and the host toolchain itself. Each is
emitted by name in the reply's `unverified` list, and the presence of even one
makes the verdict `partial` rather than `match`. That is the honest ceiling for
the shipped node today; dropping those components to print a green `match` is
how a verified result stops meaning anything.

**The honest report on residual divergence:** the gate strips nothing itself —
it compares the artifacts exactly as shipped. If a future toolchain change
reintroduces a divergence, `repro-verify` reports the differing byte count, the
first differing byte offsets, and the differing ELF sections in full rather than
masking them with aggressive stripping; a residual diff is surfaced, never
papered over.

**What remains (out of this gate's scope):** byte identity is proven for the
default portable `-march=x86-64-v3` profile on a single toolchain/host class;
cross-*toolchain* (different gcc versions) reproducibility is not asserted. A
`ZCL_NATIVE=1` build is machine-specific by design and is excluded. The
`ci-reproducible` target / `tools/scripts/check_reproducible_build.sh` remains
the complementary same-directory check under the exact `tools/release.sh`
release flag profile (pinned `SOURCE_DATE_EPOCH`, `-Wl,--build-id=none`); it and
`repro-verify` share the `REPRO_CFLAGS` determinism through the resolved release
flag set. The full offline signature quorum, SBOM/provenance, and independent
third-party reproduction that gate *stable publication* remain contained (see
Release integrity above).

## Check it yourself

The README states these properties; this is where each one names the mechanism
*and* the command that shows it, so none of them has to be taken on faith.

| Property | Check it yourself |
| --- | --- |
| **A validity decision has exactly two inputs** - the binary you compiled, and the proof-of-work-heaviest header chain. No operator attestation, no certificate authority, no registry lookup anywhere in a consensus path. | [`HOW_THE_NODE_WORKS.md`](./HOW_THE_NODE_WORKS.md) |
| **`core/` is byte-sealed** - checkpoints, chain params and consensus math are pinned by `core/MANIFEST.sha3`. Any byte change fails `check-core-seal` and needs a recorded unseal ([`../core/UNSEAL.md`](../core/UNSEAL.md)). This binds an AI agent working on the code exactly as much as it binds you. | `make lint` |
| **Consensus stays bit-compatible with `zclassicd`** - enforced by `check-consensus-parity` plus a golden-value test group; consensus-changing contributions are declined ([`CONSENSUS_PARITY_DOCTRINE.md`](./CONSENSUS_PARITY_DOCTRINE.md)). | `make -j"$(nproc)" t-fast ONLY=consensus_parity` |
| **The process restricts itself before it reports ready** - `-sandbox=steady` applies `no_new_privs`, `PR_SET_DUMPABLE(0)`, Landlock datadir grants and a seccomp deny-list, installed with seccomp `TSYNC` so already-running threads are covered, not only new ones. | `build/bin/z23 ops state --subsystem=sandbox` |
| **No subprocess execution** - zero `system()` and `popen()` in shipped app/lib/config code, enforced by a gate rather than by convention. An explicitly admitted commons build or test action may invoke its bound toolchain only inside the separate bounded worker lifecycle; fetching source never invokes it. | `make lint` |
| **Wallet secrets have exactly one writer** - the encryption-aware `wallet_sqlite` layer. The old plaintext mirror is deleted and a gate ratchets that it never returns. Keys wrap in AES-256-GCM (PBKDF2-HMAC-SHA512, 200k iterations) under a passphrase ([`CUSTODY_MODEL.md`](./CUSTODY_MODEL.md)). | `make lint` |
| **Crash recovery is executed, not claimed** - a node is kill-9ed mid-write on an isolated datadir and must fold back to its tip with no manual repair. | `make test-crash-bootstrap` |
| **Read-only queries are constrained by construction** - SELECT-only, semicolons rejected, auto-`LIMIT`, a wall-clock budget, and wallet-secret tables denied by name. | `build/bin/z23 core storage query` |
| **Public hosting default-refuses** - a node announces and serves only packages it can classify into a named public shape, and the licensed shapes require a verified author signature, an allowlisted SPDX identifier and real `LICENSE` text before a byte moves ([`P2P_SOURCE_HOSTING.md`](./P2P_SOURCE_HOSTING.md)). Anything unrecognised is refused by name. | `make -j"$(nproc)" t-fast ONLY=zcode_swarm` |
| **The bytes you run are the bytes your own machine builds** - not "signed by someone reputable", and not a published hash checked against the file it was published beside. The command rebuilds locally and compares, names what it did *not* cover, and reports `partial` rather than `match` while anything is uncovered. | `z23 zcode node verify --input='{"source_dir":"."}'` |
| **The gates run on your machine**, with no hosted CI service in the loop. | `make lint && make ci` |

And the boundaries, stated plainly. Z23 has no central coordinator and no
central package registry. It never executes downloaded C merely because it was
fetched or stored. It does not claim that tests, signatures or reproduction
prove general safety. The C23 Commons does not change ZClassic consensus. It
does not require one AI vendor - AI workers are replaceable proposal engines.
And it has no live ZC23 token economics today; those surfaces remain
simulation-only.

## Reviewer checklist

High-signal local checks:

```bash
git status --short --branch
make lint
make ci
```

Evidence files worth reading first:

- [`../README.md`](../README.md) - public status and feature scope.
- [`../.github/SECURITY.md`](../.github/SECURITY.md) - vulnerability reporting.
- [`MVP.md`](./MVP.md) - v1 acceptance criteria and readiness score.
- [`RUNBOOK.md`](./RUNBOOK.md) - operational safety rails.
- [`../tools/scripts/isolated_node_env.sh`](../tools/scripts/isolated_node_env.sh) - isolated process/datadir guardrails.
- [`../tools/release.sh`](../tools/release.sh) - reproducible release and signing logic.

## Reporting

Report vulnerabilities privately through GitHub security advisories as described
in [`../.github/SECURITY.md`](../.github/SECURITY.md). Do not bury a valid
finding in reassuring language. If a claim is not currently proven, document the
gap and the proof needed to close it.
