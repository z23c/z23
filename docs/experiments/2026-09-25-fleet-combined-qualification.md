<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Exact-root fleet reuse integration checkpoint

Date: 2026-09-25 UTC. Compiler: GCC 16.1.1. CPU: AMD Ryzen 7 PRO 8840U.
This checkpoint starts from `origin/main`
`7a9f354f3f7996383c0e7c858346ac29a5ad8957`. Three independent owned
hypotheses produced signed source proposals:

| Hypothesis | Signed proposal commit | Native directive / ACK / RESULT |
| --- | --- | --- |
| Receiver-local signed lookup | `9c68d73e7e19aa8c275ad238462e745afeac7dc9` | D-LOOKUP-1 / 598 / 602 |
| Bounded exact-root transfer | `f28510d43f32c72fc750e8c5216cc57e19227f91` | D-TRANSFER-1 / 600 / 603 |
| Per-issuer MMR history | `ea04f02ed9252fd1dfb0bc3fd663471a930b3b82` | D-MMR-1 / 599 / 605 |

Native mail coordinates ownership but is unsigned. The signed commits, exact
source bytes, claim ledger, local policy, and admissible receipts must be
verified separately. In particular, mail row 607 contained a mistyped full
integration commit root; problem row 608 corrected it using `git rev-parse`.
No receiver can treat row 607 as object authority.

## Combined local checks

The three signed proposals were merged into the same integration tree. Review
also made missing receiver time (`now_unix == 0`) an unavailable lookup
result, with a negative test. The reviewed lookup C source SHA-256 is
`fca4836f9ee73d1576da053139625d84954c135d88f6d36cef649f53f075fbc3`.
The combined generated inventory SHA-256 is
`9a15100c3b48da6d00f4cb1a4cdf8d592f1ade3e713cb279afc8fc2870bd3a9a`.

| Gate | Exact command | Outcome | Log SHA-256 |
| --- | --- | --- | --- |
| Signed observation lookup | `make CC=gcc -j2 t-fast ONLY=dev_proof_signer` | 1/1; zero skips | `f23cf007772b2b4c7fdc8bdd4aa43024114398598c70eabd8c5b0a3e68a865c6` |
| Peer package transfer | `make CC=gcc -j8 t-fast ONLY=zcode_swarm` | 4/4; zero skips | `b734fb38ac64c1469fb32553c261a9876140dd6ed3132b06932dae3678de92fc` |
| Signed history checkpoint | `make CC=gcc -j8 t-fast ONLY=zcode_dev_objects` | 1/1; zero skips | `8b72d408eaa5323c4b3b7d654d2f8a8eb464dda152f93124e199b293bcdd43ca` |
| Fast lint | `make CC=gcc -j8 lint-fast` | 33/33 | `317f76e98dc3d9a6c55b27bc8e3421e38eaed431f76c3734bc3db0c0126578ac` |
| Flag, architecture, inventory | `make CC=gcc check-flag-registry check-architecture-tree check-capability-inventory-generated` | all pass | `7058627bc6ec9a773e7714de92eadb2821a617947ac77aa85e0a247d7b119efa` |

The signer selected test body took 928 ms. Its cold prerequisite compiled
2,363 dev objects and about 3,600 test objects over roughly 15 minutes at
`-j2`; these are per-worktree objects. The subsequent warmed swarm selector
took 40 s wall, with 36.010 s in its selected test body, and the dev-object
selector took 15 s wall, with 10.797 s in its selected test body. During
several cold-build samples the CPU pressure 10-second average was below 0.25
and memory pressure was zero. These samples do not prove a safe wider build
limit; they identify prerequisite compilation as the largest observed wall
component in this integration.

## Evidence ceilings and next check

The receiver lookup checks explicit local CAS leaves, their roots and
signatures, exact group/key, receiver-mapped signer domains, freshness and
visible PASS/FAIL conflicts. Its caller must supply a complete root set and
still bind artifacts, policy generation and action before reuse. The transfer
patch caps work-root fetches and refuses a tighter ceiling even when a root
is already cached. In the isolated four-node in-process fixture, repeat
fetches transferred zero payload bytes for 128 present objects; a source edit
transferred 2,799 bytes and reused 5,777. These are fixture payload counts,
not measured fleet wire savings. The MMR checkpoint authenticates one
issuer's ordered history; it does not validate observations or select a fork.

The earlier 100-change local workload generated, built, previewed, tested,
and locally verified 100 revisions with 206 added source LOC. DEV-accepted
and fully accepted LOC remain zero. No physical fleet job avoidance, peer
observation lookup hit, policy-bound skip, bounded work subscription,
partition-safe advisory lease, fleet byte saving, or node-health improvement
has been measured from this integration. A full normal land proof and
independent remote observation are still required before the combined source
can become the shared baseline.

The ranked measured bottleneck is cold per-worktree object compilation,
followed by source-base movement that superseded earlier full proof receipts.
The highest-leverage proposed fix is exact-closure verified object reuse for
unchanged source/header/compiler/flags/build-graph inputs while retaining
source-epoch quarantine and all existing gates. The proof owner received the
exact observations in native mail rows 588 and 589. This integration makes no
claim that the proposed fix is implemented.

## Full-proof counterexample and correction

Native land action seq1 built signed commit
`9b614d1d9e9edd8d2c41a244540f7fd831503af2` against the same main base.
Its full impacted suite passed 101/101 groups with zero skips in 464.422 s,
but full lint refused `check_capability_closure`: the new local lookup's error
diagnostics reached `CAP_FS_WRITE` without a `module_capabilities.def` row.
The failed lint log SHA-256 is
`b3e1e70fa3a16e533a5cbfea656cb9b75c491718dd7202def959af1344110622`;
the passing test log SHA-256 is
`aaba48bdf53c732b679fd215459f8c1ad94acfb42a5bc6980fa7a1bc11ccf3f0`.
Land seq1 settled failed, with no receipt or push. The integration adds a
`CAP_FS_WRITE` row for that exact source, describing its diagnostic-stream
use. `make CC=gcc check-capability-closure` then passed without a gate change
(log SHA-256
`29ab58eb4836019232ab9e654b538e18057b75e1ca846568d2f295fc5f440eea`).
This correction still requires a new signed tip and complete normal proof.

The complete local lint rerun exposed a second independent RED gate:
`check-byte-order-codec-single` refused private integer packing in
`zcode_observation_mmr.c`; its wrapper selftest had exited 1 without a
diagnostic, while the production scan named that file. The complete RED lint
log SHA-256 is
`b79f2af617d4995f63214e8b06a1ff2f083ee8f878096a686b98841fa6325300`.
The MMR implementation now calls the canonical `base/serialize_le.h` codec
for every 32- and 64-bit wire field. The direct gate's selftest and production
scan pass (log SHA-256
`934e15508c791334f4a6c1a830c83fb7dec60c59fa65d43983733b85c56ba322`).
No baseline row or gate threshold changed. A new combined test and full lint
verdict are required for this source revision.
