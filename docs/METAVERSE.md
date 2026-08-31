# The Z23 Metaverse

**Z23 is a metaverse where people and AI create real things together,
and nobody owns the world they build in.** The metaverse is not one app or one
server — it is the shared, permissionless creation environment formed by the
ZCODE package library, the development network, the proof-of-contribution
evidence graph, and a federation of sovereign, user-hosted *spaces*. Every
piece of it runs inside the same single C23 binary as your node, on your own
machine, reachable over your own onion.

## The five-minute tour

Every command below is typed, local-first, and safe to run on any node. Start
with the guide — it maps the whole create/inspect/fetch loop; the listings
will be empty until you or your peers publish something, and that is the
honest answer, not a bug:

```bash
build/bin/z23 zcode guide                            # the creator's map: find, inspect, fetch, create, improve
build/bin/z23 discover search metaverse              # orient in the live command tree
build/bin/z23 zcode package search --input='{"datadir":"/tmp/zcl23-tour"}'   # browse the local commons
build/bin/z23 metaverse property list --input='{"datadir":"/tmp/zcl23-tour"}'   # holdings, with evidence grades
build/bin/z23 zcode commons status --input='{"workspace":"/tmp/zcl23-tour-commons"}'   # the ZC23 Living Commons projection
```

To see a real committed space instead of an empty listing, create one:
`metaverse space plan` then `metaverse space commit` returns the 64-hex root
to paste into `metaverse space show --input='{"root":"<64hex>",...}'`. The
scripted tour below walks exactly that path.

The hermetic, scripted version of this tour (isolated regtest node, zero live
state) is criterion MM1 of [`docs/METAVERSE_MVP.md`](./METAVERSE_MVP.md).

## The layers, and where each is specified

This page is the user-facing entry point. The authoritative specs remain the
four maintainer documents — when prose here and a spec disagree, the spec wins
(and [`docs/METAVERSE_MVP.md`](./METAVERSE_MVP.md) tracks what is actually
proven, gate by gate):

- **ZCODE package commons** — decentralized C23 source-package hosting:
  signed release envelopes, a 10 GiB content-addressed store, publication and
  search, contributor identity, declarative build recipes, and third-party
  bit-identical reproduction as the headline trust test
  (`build/bin/zclassic23-package-verify --reproduce-against`).
  Spec: [`docs/work/ZCODE_PLAN.md`](./work/ZCODE_PLAN.md). Site: `/zcode` on
  your node's explorer/onion. Commands: `zcode package *`.
- **Development network** — free, requester-coordinated P2P agentic C23
  development: tasks, candidates, reviews, work receipts, and durability lanes
  over authenticated swarm transport. Spec:
  [`docs/work/ZCODE_DEVELOPMENT_NETWORK.md`](./work/ZCODE_DEVELOPMENT_NETWORK.md).
  Commands: `zcode create|use|improve|evidence|accept|lane`.
- **Scientific metaverse** — proof-of-contribution: studies, benchmark
  results, reproductions, findings, curation votes, and deterministic
  discovery ranking over a Noise-bound Kademlia DHT. Spec:
  [`docs/work/ZCODE_SCIENTIFIC_METAVERSE.md`](./work/ZCODE_SCIENTIFIC_METAVERSE.md).
  Commands: `zcode science *`, `zcode network *`.
- **Living Commons / ZC23** — the patronage-asset covenant: an immutable
  9-clause genesis policy (no creation no mint, complete supply attribution,
  the commons stays free, money is neither truth nor reputation). **ZC23 today
  is simulation-only** — no live token, no GENESIS/MINT/SEND, no wallet or
  consensus path. Spec: [`docs/work/ZC23_LIVING_COMMONS.md`](./work/ZC23_LIVING_COMMONS.md).
  The additive pre-genesis Family Commons and evidence-economics contract is
  [`docs/work/ZC23_FAMILY_COMMONS.md`](./work/ZC23_FAMILY_COMMONS.md);
  `family-c23.v1` is the default public profile and incomplete evidence fails
  closed.
  Commands: `zcode commons *`, `zcode patronage *` (simulation),
  `zcode continuity *`.
- **Spaces and property** — signed, delegated `space_manifest.v1` /
  `service_descriptor.v1` objects over the existing CAS/DHT, bounded read-only
  scout missions that produce signed local evidence maps, and the property
  catalog projecting everything your node can prove you hold. Commands:
  `metaverse space *`, `metaverse space scout *`, `metaverse property *`.

## Terminology

- **ZCODE** — the package/creation ecosystem (the library, the dev network,
  the science graph).
- **ZC23** — the simulated patronage asset of the Living Commons covenant.
- **Score / Credit / Badges** — evidence-derived contribution accounting
  (deterministic, reproducible, never purchasable).
- **Space** — a sovereign, user-hosted signed manifest: read-only verbs,
  object roots, capability roots. It grants no authority and is never
  executable.
- **Commons** — the shared CAS/DHT substrate plus its projections.

## Honest status

- Merged and gate-proven: package commons (slices 1–13), dev-network object
  foundation and typed path, science S0–S7 (DHT, space/scout foundation),
  Living Commons LC0–LC5 (creation attribution, epoch accounting, simulated
  patronage intents/funding, continuity policy).
- Simulation-only: all patronage funding/settlement, rewards, badges.
- Fail-closed pending owner gates: real ZC23 issuance (blocked by design on
  challenge-mature founding contributions, green shadow epochs, exact
  active-chain proofs, custody gates, and owner authorization).
- The scoped acceptance bar is
  [`docs/METAVERSE_MVP.md`](./METAVERSE_MVP.md); run `make metaverse-verify`
  only when the current forward plan selects that scope.

<!-- claim: file-present docs/METAVERSE_MVP.md # the acceptance bar -->
<!-- claim: file-present docs/work/ZCODE_PLAN.md # package commons spec -->
<!-- claim: file-present docs/work/ZCODE_DEVELOPMENT_NETWORK.md # dev network spec -->
<!-- claim: file-present docs/work/ZCODE_SCIENTIFIC_METAVERSE.md # science spec -->
<!-- claim: file-present docs/work/ZC23_LIVING_COMMONS.md # Living Commons spec -->
<!-- claim: file-present docs/work/ZC23_FAMILY_COMMONS.md # additive Family Commons spec -->
<!-- claim: symbol-present metaverse-verify Makefile # the scoped acceptance aggregate -->
