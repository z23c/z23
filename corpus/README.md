# corpus/ — the C23 corpus odometer

This directory holds the canonical outputs of the **C23 corpus census**: a
signed, simulation-only lower-bound checkpoint (`c23_corpus_checkpoint.v1`)
counting the C23 code in this repository plus, eventually, existing Commons
packages, scope by scope. The counting rules live in the pure census core
(`lib/vcs/include/vcs/zcode_c23_corpus_census.h` — the authority); the
offline driver is `tools/corpus_census.c`, built as
`build/bin/corpus-census` and wired as `make corpus-census`.

## Contents

- `scopes.def` — the canonical scope definition (one scope per line;
  header comment documents the format, the file-claim precedence, and the
  declared provenance).
- `checkpoint-NNNNNN.hex` — the signed checkpoint wire (lowercase hex).
- `shard-NNNNNN-<i>.hex` — the corpus shard wires the checkpoint binds
  (≤28 entries each, inside the 8192-byte inline reader bound).
- `evidence-NNNNNN.json` — every per-scope source assignment and admission
  wire, every constructed root, and the exact construction recipes.
- `report-NNNNNN.json` — the KPI report: admitted/excluded LOC (production
  and test separately), downstream-used LOC (admitted packages pinned by
  another scope's dependency closure), growth deltas against the previous
  sequence's report (`--previous-report`), per-scope breakdown, missing
  evidence bits, and the honesty disclosures.

## Live status

`zcode commons corpus status` reads the resident signed checkpoint at
`<datadir>/zcode/corpus/checkpoint.hex` when the census was run with
`--install <datadir>` (or `CORPUS_INSTALL=<datadir>` via the make target).
The reply carries `resident_checkpoint`: `loaded` (decoded, signature and
shape re-validated), `rejected` (present but failed validation — logged,
never trusted), or `missing` (the historical `checkpoint_missing`
rendering).

## Re-run

```bash
make corpus-census            # builds the driver, runs a SMOKE census
                              # into build/corpus-census/ (never corpus/)
```

Advancing the committed sequence is explicit (the predecessor root and the
previous report are auto-discovered from `CORPUS_OUT`; the
`CORPUS_PREDECESSOR_ROOT` / `CORPUS_PREVIOUS_REPORT` variables override):

```bash
make corpus-census CORPUS_OUT=corpus CORPUS_SEQUENCE=<n> \
    CORPUS_CUTOFF_HEIGHT=3050000 CORPUS_CUTOFF_MTP=1754000000 \
    CORPUS_QUALITY_ATTESTED=1 CORPUS_INSTALL=<datadir>
```

The signer seed lives OUTSIDE the repo at
`$HOME/.config/zclassic23/corpus-census-signer.seed` (32 raw bytes, mode
0600; generated from the kernel CSPRNG on first use, with the new pubkey
logged). Same tree + def + seed + cutoff args give byte-identical
artifacts — no wall-clock enters any signed object.

## Verify

```bash
build/bin/zclassic23 zcode commons corpus verify \
    --checkpoint="$(cat corpus/checkpoint-000001.hex)"
build/bin/zclassic23 zcode commons corpus shard verify \
    --shard="$(cat corpus/shard-000001-0.hex)"
```

Both return `"verified":true` after decoding and validating the wires
(signature, canonical order, aggregate consistency). The readers are
fail-closed: anything malformed is rejected with a named reason.

## Admitting a published Commons package

`scopes.def` has a second line form for packages published through the C23
Commons package store:

```
package <name> | root <64hex> | store <label> | kind <human|ai|import> | spdx <id>
```

`store` is a **label**, not a path: one path component of `[A-Za-z0-9._-]`
(never `.`, `..`, `/` or `~`). The census resolves it to
`<store-root>/<label>/zcode`, where store-root comes from `--store-root`,
else `$ZCL_CORPUS_STORE_ROOT`, else `$HOME`. Both producers refuse a
path-shaped store field outright — `store_label_valid()` in
`tools/corpus_census.c` and `pf_store_label()` in `tools/package_factory.c` —
so an absolute datadir cannot reach a commit through either of them.

It is a label because this def line is copied **verbatim** into every
evidence record (`scopes_def_line`) and hashed into
`assignment_evidence_root`. While the field held an absolute datadir, the
operator's home directory shipped in 162 tracked files: 2,302 copies as
`"store"` in the evidence and KPI reports, 1,151 more inside
`scopes_def_line`, and 146 as `"datadir"` in `corpus/factory/*.report.json`.
None of it was load-bearing — every root is computed over content hashes,
and `root` (the package manifest root, re-derived from the store and refused
on mismatch) is what binds the bytes. Where those bytes sit on one host is an
operator-local coordinate and belongs in a flag.

> **Flag day.** Package def lines carried `store /home/<user>/<label>`
> through sequence 42. Sequence 43 onward hashes the label form, so the
> sequence-42 `assignment_evidence_root` values are **not** reproducible from
> today's `scopes.def`. The committed sequence-42 checkpoints and shards
> still verify (the readers decode and re-validate the wires; they do not
> re-read `scopes.def`), and the sequence chain is unaffected — the
> predecessor root is discovered from `report-000042.json`, which does not
> depend on the def. The pre-migration artifacts under `corpus/` therefore
> still contain the old paths; they are grandfathered in
> `tools/lint/operator_paths_baseline.txt`, which is shrink-only. See
> "Regenerating the committed artifacts" below.

Unlike repo scopes (enumerated via `git ls-files`), a package scope is
enumerated from the **package store** at `<store-root>/<label>/zcode`, so
every evidence bit binds the exact published bytes, not a working tree:

- `root` is the package manifest root. The census loads the stored manifest
  and re-derives the root; a mismatch refuses the scope.
- Exactly one signature-verified release under `releases/` may name the
  root; its declared license must equal the `spdx` field, and the census
  re-derives the recipe root from `recipes/<recipe-root-hex>`.
- Files are reassembled from the chunk-hash-verified CAS, read-only — the
  census never opens the store through `vcs_package_store_open`, so no
  recovery sweep, GC, or access-count mutation happens as a side effect.
- REPRODUCIBLE requires >= 2 DISTINCT byte-identical confined build
  receipts filed under `<datadir>/zcode/receipts/`; QUALITY maps to
  "confined build+test receipt green". The assignment author binding is the
  release publisher's pubkey.

The one pipeline that produces all of this evidence is the package factory
(`tools/package_factory.c`, `build/bin/package-factory`): it gates the
package layout, prepares/seals/signs the release, publishes into two
independent local stores, files the second distinct confined-build receipt
(quick + standard flag profiles on one host — disclosed), verifies
reproduction, and optionally registers the scope line
(`--register-corpus --census-def corpus/scopes.def`). Prove it end to end
with:

```bash
make package-factory-selftest
```

After registering a package scope, re-run the census (above) so the signed
checkpoint binds the new package evidence.

## Regenerating the committed artifacts

The 162 pre-migration artifacts still carry the old absolute store paths.
They are **not** hand-editable: `evidence-NNNNNN.json` and
`report-NNNNNN.json` are the recorded inputs and outputs of a signed run, and
rewriting their bytes to look clean would forge evidence that no census
produced. The only honest way to retire that debt is to re-run the census on
the label-form def and let it emit a new sequence.

That is blocked today, and the block is worth recording: the package stores
those 73 lines name (`.zclassic-c23-commons-factory-a`, `-c`, …) **no longer
exist on the maintainer host**, so a package scope fails closed on a missing
manifest. Advancing the sequence therefore requires republishing the packages
through `make package-factory-selftest` / the factory pipeline first. Until
then the old bytes stay, grandfathered and shrink-only — which is also why
this is the last set of artifacts that can contain such a path: both
producers now refuse one.

## Honesty disclosures (carried in every report)

- **Founding self-screen admission.** Every scope's admission is a
  self-signed `SELF_SCREENED` `commons_admission.v1` (tier 0); zero
  independent operator groups have participated.
- **Reproduction** is dual-worktree source rederivation (`git worktree`
  at HEAD, byte-identical release roots), NOT independent build
  reproduction. Scopes with uncommitted content honestly lose the bit.
  Package scopes use the stronger receipt binding (>= 2 distinct
  byte-identical confined build receipts) — but on ONE host; independent
  operator reproduction is future work.
- **Quality** is the operator's `--quality-attested` flag (`make lint`
  pass state at census time), not an independent review. With it unset,
  every entry is excluded `REVIEW_REQUIRED` and admitted LOC is zero —
  the correct first-checkpoint outcome.
- **Durable hosting: none yet.** `possession_root` is recorded in the
  report only; every entry carries `possession_root = 0` and no DURABLE
  flag (nothing is 5-ACK/3-operator-group durable).
- **Simulation-only, not owner-approved.** There is no live ZC23 token
  economics.
- `source_kind` is **declared provenance**: no per-file authorship marker
  exists in-tree, so all scopes are declared `human`.
- `vendor/` and `core/` are out of corpus by design (third-party material
  and the byte-sealed consensus core).
