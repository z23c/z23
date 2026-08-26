# ZCODE C23 Development Loop — Five-Minute Walkthrough

Z23 exists to make useful software abundant without taking control away from
the user: software made for you, not imposed on you. This walkthrough is the
middle of that journey as a developer product. The human describes desired
behavior; ZCODE reuses existing C23 first, creates only what is missing,
returns a contained candidate with exact evidence, and ends in an explicit
human accept-or-reject decision about one exact version. Public permissively
licensed source remains free, and neither a model nor a token receives
technical authority. AI workers are replaceable; the exact source, recipe, and
evidence are the durable layer.

Ask the node for the journey before following this page — it answers with the
current start command and the plain step order:

```bash
z23 zcode guide
```

The steps after acceptance — publish, fetch on another node, reproduce
independently, then use the exact version — are in
[`../C23_COMMONS_QUICKSTART.md`](../C23_COMMONS_QUICKSTART.md).

This is a development-only path. It does not use a wallet, token, transaction,
custody path, node datadir, deployment, service, or consensus code.

## 1. Inspect the project (read-only)

From a small single-package C23 checkout:

```bash
z23-dev zcode project inspect \
  --input='{"workspace":"."}'
```

Check the proposed name, headers, sources, tests, include directories,
resource ceilings, and proof profile. If `zcode-package.json` is absent, use
`zcode project init plan` and inspect every inferred field before the matching
`init commit`; initialization refuses overwrite, links, and special files.

## 2. Start one goal

```bash
z23-dev zcode work start -datadir=/tmp/z23-work \
  --input='{"workspace":".","goal":"Make the parser reject overflowing lengths","profile":"quick"}'
```

The response leads with a human work ID and context measurements. Roots stay
under `expert`. `quick` expands to an exact existing proof policy; it is not a
weaker alternate proof system.

## 3. Hand the bounded packet to an adapter

The always-available path is manual and model-neutral:

```bash
z23-dev zcode work run -datadir=/tmp/z23-work \
  --input='{"workspace":".","work":"latest","adapter":"manual"}'
```

Give the file at `adapter_packet_path` to the external coding tool you choose,
and allow it to edit only the returned `candidate_workspace`. Do not edit the
authoritative workspace. Keeping the bounded packet in a mode-0600 file avoids
the native command's small human-result budget while preserving its exact goal,
selected excerpts, write scope, recipe, proof expectations, and resource
ceilings.

An installed Codex CLI is an opt-in convenience when exactly one documented
single-run credential (`CODEX_API_KEY` or `CODEX_ACCESS_TOKEN`) is present:

```bash
z23-dev zcode work run -datadir=/tmp/z23-work \
  --input='{"workspace":".","work":"latest","adapter":"codex"}'
```

That runner uses a fixed executable, a scrubbed environment, Landlock, and
resource/output/time limits. It never reads a saved `auth.json`, wallet,
node datadir, SSH key, or node credential. If the single-run credential or
confinement is unavailable, it returns `ADAPTER_UNAVAILABLE`; use `manual`.

## 4. Capture, build, test, and repair

After a manual adapter edits the candidate, repeat the same `work run` command.
ZCODE captures a new immutable candidate, refuses out-of-scope files, then runs
the existing package action in confinement. A compiler or test failure returns
`REPAIR_NEEDED`, preserves the failed candidate and signed evidence, and emits
a bounded attempt-2 packet. At most three candidate attempts are admitted.

Inspect the result at any time:

```bash
z23-dev zcode work show -datadir=/tmp/z23-work \
  --input='{"workspace":".","work":"latest"}'
```

`work show` and `work status` are the same read-only verified view. Read the
goal, changed files, line delta, API impact, build/test result, remaining risk,
scope violations, and next safe command before looking at expert roots.

When the selected profile requires a separate review, a human reviewer records
bounded findings without editing or accepting the candidate:

```bash
z23-dev zcode work review -datadir=/tmp/z23-work \
  --input='{"workspace":".","work":"latest","adapter":"manual","verdict":"approve","findings":"No blocking findings."}'
```

The command binds the already-trusted non-review proof set, uses a distinct
reviewer identity, and creates the existing `review.v1` plus signed REVIEW work
receipt. Status then shows the verdict; conflicting-review execution remains a
named v0.1 blocker rather than silently replacing the first review.

## 5. Make the human decision

Acceptance is explicit and pins the exact candidate and evidence:

```bash
z23-dev zcode work accept -datadir=/tmp/z23-work \
  --input='{"workspace":".","work":"latest"}'
```

The command may first record CANDIDATE proof readiness, then creates the signed
PROVEN accepted-work root as the explicit human decision. A plain CANDIDATE is
not accepted. The command does not apply the patch to the authoritative source
tree and is idempotent.
Apply a reviewed accepted patch through the developer's normal source-control
workflow. To reject a result today, do not run `accept`; retain its evidence or
remove only its isolated scratch workspace. A durable task-level `work cancel`
is intentionally not advertised yet: the existing signed cancel wire cancels
an in-flight P2P request, not canonical task history, and reusing it would make
a false authority claim.

Goal-to-decision uses at most five ZCODE commands on the manual path: start,
export, admit/build, show, accept. Inspection is the one-time project preflight.

## Permanent acceptance gate

```bash
make zcode-development-acceptance
```

The exact hermetic test proves source-tree byte identity through start, handoff,
failed build, repair, evidence, and acceptance; isolated candidate materialization;
out-of-scope refusal; candidate-bound package build/test evidence; state rebuild
after deleting the scratch worker database; exact idempotent PROVEN acceptance;
typed unavailable/refused adapters; and no source application. The ordinary
lint boundaries separately prohibit reaching wallet, transaction, custody,
deployment, or consensus owners from this slice.
