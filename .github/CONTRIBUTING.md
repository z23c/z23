<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Contributing to Z23

## What a good change does here

Z23 exists to make useful software abundant without taking control away from
the user — software made for you, not imposed on you. The product is one
journey: describe desired behavior, reuse existing C23 first, create only the
missing code, build fast, show the real consequence, reproduce it on another
node, accept the exact version, use it in a real application.

Every change should improve at least one of these:

- reuse useful C23 code;
- shorten the path from intent to working software;
- make the result smaller, faster, safer, or easier to customize;
- remove duplication or a central dependency;
- improve exact reproduction and long-term preservation.

Prefer deletion, reuse, and composition over new abstractions. Keep the
blockchain small and sovereign, and the large software corpus off-chain and
content-addressed. The durable statement of this is
[`AGENTS.md`](../AGENTS.md#north-star).

## Prerequisites

- **gcc 14+** (or a clang with working `-std=c23` support) and GNU make.
- For the one-time vendored-library build: `cmake`, `autoconf`, an autotools
  toolchain, `curl` or `wget`, `unzip`, and `sha256sum`.
- Vendored static libraries under `vendor/lib/` are built locally by
  `make vendor` from pinned source tarballs and SHA-256 hashes. A fresh clone
  links without manual archive copying; see [`docs/BUILD.md`](../docs/BUILD.md)
  for each dependency's source, version, and build notes.

## Step 0 — set up the checkout

```bash
make setup
```

`make setup` verifies and builds pinned dependencies, installs checkout-local
native receipt hooks, and primes generated development state. Afterwards,
ordinary builds are offline.

## Build and test

```bash
make -j"$(getconf _NPROCESSORS_ONLN)" z23    # public node only (the default goal)
make -j"$(getconf _NPROCESSORS_ONLN)" all    # test harness + node + auxiliary tools
make vendor              # build missing vendor/lib archives from pinned sources
make -j"$(getconf _NPROCESSORS_ONLN)" build-only          # compile check, no final link
make -j"$(getconf _NPROCESSORS_ONLN)" dev-bin             # fast non-LTO local node binary: build/bin/z23-dev
make -j"$(getconf _NPROCESSORS_ONLN)" t-fast ONLY=<group> # one registered test group
make fast-ci             # cache-aware lint/build/focused-test agent loop
make -j"$(getconf _NPROCESSORS_ONLN)" test                # full test suite
make lint                # defensive-coding gates (must be clean)
make ci                  # local full gate: lint + tests + MVP slices + fuzz where available
```

`make build-only` and `make dev-bin` are the compile-check and local-node
targets; use their parallel forms above. `make dev-bin` is the normal way to get a changed local node/agent executable
without paying release LTO. `make t-fast ONLY=<group>` is the normal test inner
loop: it rebuilds the fast harness and runs only the matching group(s). `make
fast-ci` adds cache-aware lint/build/focused-test selection from changed files.
Never run the full `test_zcl` binary in the inner loop.

## The defensive-coding contract

[`docs/DEFENSIVE_CODING.md`](../docs/DEFENSIVE_CODING.md) is mandatory
reading before writing any code — the AR-lifecycle-write, logged-error,
checked-allocation, and supervised-loop rules there are enforced by the
compiler and by the `make lint` gates (`make ci` runs lint before tests), not
by review goodwill.

Files under `app/` must live in exactly one of the eight shape folders
(`models/`, `views/`, `controllers/`, `services/`, `jobs/`, `conditions/`,
`events/`, `supervisors/`) — lint-enforced; see
[`docs/FRAMEWORK.md`](../docs/FRAMEWORK.md).

## The `core/` tree is sealed — read this before patching consensus

Everything under `core/` (checkpoints, chain parameters, consensus math) is
pinned to a SHA3-256 manifest at `core/MANIFEST.sha3`. Change one byte of it and
the HARD lint gate `check-core-seal` fails `make lint`, and therefore `make ci`
and the pre-push hook. This is deliberate: it makes it structurally impossible
for a contributor — human or AI agent — to alter consensus without an explicit,
deliberate unseal ritual documented in `core/UNSEAL.md`.

Two things follow, and we would rather you learn both now than after a weekend
of work:

- **The wall is real, not a misconfiguration.** If your build suddenly fails
  `check-core-seal`, you edited a sealed file. That is the gate working. Don't
  regenerate the manifest to make it pass.
- **A consensus-changing PR would be declined anyway** — see
  [Consensus parity is inviolable](#consensus-parity-is-inviolable) below. So if
  the change you have in mind requires unsealing `core/`, the seal is not the
  obstacle; the policy is. Please open an issue and describe the idea before
  writing the code. We would much rather thank you and credit you at the idea
  stage than decline finished work.

Non-consensus changes never touch `core/`, and this gate will never bother you.

## What the git hooks do

`make install-hooks` builds one C23 hook executable and sets a checkout-local
`core.hooksPath`. The installed hooks are:

- **`post-commit`, `post-merge`, and `post-checkout` — proof notifications.**
  They enqueue exact local verification and return immediately.

- **`pre-push` — receipt admission.** It parses Git's advertised ref tuple,
  proves the remote base is an ancestor, and admits only a complete sealed
  receipt for that exact local commit/base pair. It never runs a compiler,
  test, lint, Make, or shell process. Missing or running evidence refuses
  quickly and prints the exact `z23-dev dev proof wait` command.

- **`pre-commit` — a lane guard, not a code check.** It refuses a commit only
  when the *main* checkout is sitting on a non-`main` branch, because
  branch work belongs in a linked worktree. It never inspects your code. In a
  worktree it always exits 0, and `ZCL_LANE_COMMIT_OK=1 git commit` overrides it.

Automated jobs, when enabled, run only on explicitly managed self-hosted
runners. They consume no GitHub-hosted minutes and do not replace exact local
receipts or maintainer review.

## Adding a test

Add `tests/harness/src/test_<name>.c` and register its group in the
canonical `tools/dev/test_group_catalog.def` as
`ZCL_TEST_GROUP(<name>)`. Run it with
`make t-fast ONLY=<name>`.

Both halves are required. The `check-test-registration` lint gate fails a test
file that compiles and links but is dispatched by no runner — it exists because
three real tests once sat in the tree for weeks, fully merged, proving nothing.

## Pull requests

Before opening a PR:

1. `make lint` — clean, no new gate violations or baseline regressions.
2. `make -j"$(getconf _NPROCESSORS_ONLN)" t-fast ONLY=<group>` for focused groups you touched.
3. `make -j"$(getconf _NPROCESSORS_ONLN)" test` for broad shared behavior or before release-sized changes.

Automation uses only maintainers' self-hosted runners; untrusted pull-request
code is not automatically compiled on persistent machines. Maintainers run
the required local gates before merging. Keep commits
honest about what is proven versus scaffolding — the project documents
incomplete subsystems as incomplete, and PRs are expected to do the same.
That expectation is partly mechanized: several lint gates exist specifically to
reject an unprovable claim rather than trust the author's word for it. See
[`docs/AI_SAFETY_GATES.md`](../docs/AI_SAFETY_GATES.md).

Not ready to send a patch? Open an issue first — the forms in
[`.github/ISSUE_TEMPLATE/`](ISSUE_TEMPLATE/) ask for `z23 status` output
and whether the change touches consensus, which is usually enough to tell you
whether the work is worth starting.

## Consensus parity is inviolable

z23 stays bit-for-bit consensus-compatible with `zclassicd`. A PR that
changes consensus (Equihash params, activation heights, block/tx validity) is
**declined on principle** — even if framed as opt-in, miner-signaled, or a
"sidegrade" — because a consensus change must never ship to z23 first. We
will thank you, credit the idea, and decline the change (we may reimplement the
*non-consensus* part ourselves). Non-consensus PRs are judged purely on merit.
Enforced by the `check-consensus-parity` lint gate + the `test_consensus_parity`
golden values; full policy in
[`docs/CONSENSUS_PARITY_DOCTRINE.md`](../docs/CONSENSUS_PARITY_DOCTRINE.md).

## Conduct

Keep it technical. Critique code, designs, and claims as hard as you like;
don't attack the person making them. The maintainer moderates, and will edit,
lock, or remove content that crosses that line.

That is the whole policy, deliberately. This project is maintained by one
person, and publishing a formal enforcement process nobody is staffed to run
would be a promise with no way to keep it — the same uncited-victory failure
the rest of this repository is built to prevent, in social form.

## Licensing of contributions

Z23 is licensed under the **Apache License 2.0**
([`LICENSE`](../LICENSE)), and contributions are accepted on
**inbound = outbound** terms:

- **By submitting a pull request, issue patch, or other contribution,
  you agree that your contribution is licensed under the Apache License
  2.0**, the same license as the project. (This is also the default
  under [GitHub's Terms of Service §D.6](https://docs.github.com/en/site-policy/github-terms/github-terms-of-service#6-contributions-under-repository-license);
  we state it explicitly so there is no ambiguity later.)
- You confirm you have the right to submit the work — it is your own,
  or you are authorized to contribute it under these terms.
- A `Signed-off-by` line (`git commit -s`, [DCO 1.1](https://developercertificate.org/))
  is welcome and encouraged, but a submitted PR constitutes agreement
  either way.

**Third-party code:** new original work defaults to Apache-2.0. Vendored
or ported third-party code under other **permissive** licenses (MIT,
BSD-2/3-Clause, ISC, Zlib, Blue Oak 1.0.0, Apache-2.0) is acceptable —
preserve the upstream copyright notice in [`NOTICE`](../NOTICE) and
credit the source in [`docs/ATTRIBUTIONS.md`](../docs/ATTRIBUTIONS.md).
Copyleft code (GPL/LGPL/AGPL/MPL) cannot be accepted into this tree.

**Attribution:** contributor authorship is preserved in git history —
PRs are merged with merge commits, never rewritten under someone else's
name — and contributors are recognized in
[`docs/CONTRIBUTORS.md`](../docs/CONTRIBUTORS.md) and GitHub's contributor graph.
