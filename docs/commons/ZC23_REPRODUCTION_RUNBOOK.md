# ZC23 portable reproduction runbook

Status: simulation and protocol acceptance only. This procedure does not
authorize or perform ZC23 genesis, minting, payout, custody, wallet access,
deployment, service changes, or live-datadir access.

## Secure build release qualification

The build fabric has a separate, inert qualification boundary for release
candidates. It reuses the existing action, receipt, worker-trust and CAS
models. The supervisor requires three distinct signed receipts for one exact
action and artifact: the admitted candidate, a clean shadow, and an independent
reproduction. Both later receipts must match the candidate's canonical
physical observation. It also requires one already-admitted exact
`c23.package.test.v1` action for the same source identity. That action's task
binds the canonical `build_release_regressions.v1` requested-intent manifest;
its signed work receipt is the physical observation, and its existing proof
set must satisfy the task's proof policy. Qualification inspects that proof set
without writing trust state or admitting evidence.

A signed `build_release_confirmation.v2` binds the regression action and proof
set, three distinct content-verified physical-machine evidence roots, and an
explicit human `CONFIRM` decision. The confirmer must be a separate approved
identity with the exact `release-confirmation.v2` capability.

Only then may the supervisor write a
`build_release_qualification.v2` object to the same CAS. That object is a
qualified candidate identity, not publication authority. The API always
reports `publication_performed=false`; it cannot deploy, restart a service,
publish a package, admit a worker result, or touch a live datadir. A `CANCEL`
decision, missing physical evidence, reused executor, unapproved confirmer,
observation mismatch, changed artifact, absent/poisoned regression proof, or
wrong regression intent remains a named red invariant and produces no
qualification object.

The permanent historical corpus is stale WAL ownership, lease takeover,
mempool/cache generation, provider reconnect, UTXO mirror storm, diagnostic
teardown, and rollback. Its 12 exact group ids are source-canonical and checked
against `test_group_catalog.def`; Makefile/manifest drift fails closed. Run its
focused physical gate with:

```sh
make secure-release-regressions
```

That command uses the strict harness, exact-set selection, no result cache, and
the checkout-wide build/run lock. A green focused run is evidence preparation,
not qualification: the release boundary still requires the candidate-bound
all-groups action, canonical proof set, physical reproductions, and human
confirmation.

Distinct keys, paths, IP addresses and hostnames are not physical proof. The
human signature attests that the three separately rooted physical evidence
objects were actually reviewed. A real acceptance record must therefore keep
the off-host command transcript or hardware-backed evidence bytes at those
roots; a one-host fixture proves only protocol behavior.

## What this proves

The Living Commons reproduction path has three roles:

- **A — requester** prepares the exact public package and canonical challenge.
- **B — reproducer** starts from roots, fetches the public inputs, rebuilds in
  confinement, and signs the exact reproduction work receipt with B's existing
  contributor/ZID-bound worker key.
- **C — observer** starts from roots, fetches both sides, independently reloads
  every canonical object, applies the approved-reproducer policy, and rebuilds
  the Commons projection.

Canonical semantic wires travel as ordinary one-chunk `content.v2` objects.
Package manifests and chunks travel through the existing package store and
`zpkgswm`; signed provider records and root-only discovery use the existing
ZCODE DHT. There is no second CAS, transport, worker ledger, identity system,
or database of truth.

The local protocol acceptance is:

```sh
make zcode-reproduction-acceptance
```

It composes exact permanent groups for the three-process policy path, real
`zpkgswm` frames, signed DHT discovery, corruption refusal, provider fallback,
restart/resume, cancellation races, challenge expiry/replay bounds, and
byte-identical projection rebuild. Its honest verdict is:

```text
distinct_signer_simulation=true
approved_fixture_policy=true
actual_off_host_credit=false
```

Separate processes, workspaces, package stores, and signing keys on one
physical machine prove protocol separation, not physical independence. They
never clear the independent-reproduction unit or the real SHA3 gate.

The source-publication path now has a narrower end-to-end adapter:
`zcode package source reproduce` fetches one exact `content.v2` carrier,
reconstructs it in fresh scratch, verifies its complete accepted-work chain,
and publishes a signed one-shot `SOURCE_REPRODUCTION_ACK`. The developer
publication collector can bind that immutable wire only when its signer
lineage is distinct from the publisher and storage witnesses. This proves
source-carrier reproduction only; it does not run the canonical build below,
produce a `work_receipt.v1` REPRODUCE receipt, or attest a physical second
host.

## Requester A: public challenge material

A commits the simulation-only reproduction request to an explicit isolated
scratch workspace. The request binds the exact task, candidate, package,
release, recipe, dependency lock, toolchain capsule, reference build report,
output manifest, fixed reproduction action, challenge nonce, budgets,
confinement grade, requester binding, and expiry.

A may publish only root-addressed public material:

- the package manifest and every package chunk;
- the canonical request and referenced public evidence wires;
- the reference build report and expected artifact manifest;
- the simulation policy candidate and approved-reproducer set.

A must not export wallet data, private keys, API or SSH credentials, canonical
datadir paths, absolute source paths, environment secrets, or mutable database
rows. A root without its verified bytes is not evidence, and a DHT/provider
record is a discovery hint rather than object truth.

## Reproducer B: exact confined rebuild

On a genuinely separate owner-approved machine, B obtains the package root,
package-store path, lock root, reference report, and empty output/work
directories through an authenticated out-of-band handoff. B then runs the
existing verifier directly:

```sh
build/bin/z23-package-verify "$PACKAGE_ROOT" \
  --store="$PACKAGE_STORE" \
  --emit="$OUTPUT_DIR" \
  --lock-root="$LOCK_ROOT" \
  --reproduce-against="$REFERENCE_REPORT" \
  --work="$WORK_DIR" \
  --require-full-isolation
```

Exit zero proves that this invocation re-derived the package under full local
confinement and produced a canonical build report byte-identical to the
reference. It does **not** by itself prove that B is approved, distinct, or
off-host, and an unsigned build report earns no independent-reproduction
credit.

B must next bind the exact request root, reproduced build-report root and
artifact-manifest root in the existing signed `work_receipt.v1` REPRODUCE
action, using B's already-approved contributor/ZID-bound worker key, and place
that receipt in the existing proof-set path. The source-reproduction command
does not perform this build-receipt/admission handoff, and the repository does
not yet ship one end-to-end remote command that does. Until that adapter
exists, the genuine off-host build gate remains blocked and must not be
cleared by copying a fixture key or self-reporting a hostname.

## Observer C: independent admission

C starts with semantic roots and ordinary discovery records, fetches the
canonical bytes and package, and re-derives all roots. C must independently
reload and validate the task, candidate, proof policy/set, PROVEN lane, Score
receipt, request, reference and reproduced reports, artifact manifest, package
release/recipe/lock/capsule, contributor bindings, approved-reproducer set,
policy candidate, challenge time/epoch, and active fixture branch.

Admission fails closed on missing bytes, altered reports, an unapproved or
related signer, stale/replayed challenge, wrong task/candidate/policy, partial
package, corrupt provider, contradiction, reorg, or duplicate event. Only an
owner-approved second host plus the signed receipt/admission path may set the
future off-host evidence fact. Protocol code does not infer physical
independence from process IDs, paths, network addresses, or operator claims.

C may then derive only the simulation-only shadow attribution and epoch and
rebuild the local projection from canonical CAS objects. The projection is a
cache, not authority. All resulting surfaces continue to report
`token_exists=false`, `funds_moved=false`, `custody_used=false`, and
`genesis_gate_satisfied=false`.
