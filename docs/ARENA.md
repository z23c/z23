<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# ZCODE Arena

The Arena is the smallest complete example of what Z23 is for: someone
writes exact C23, any node builds and runs it under bounded authority, and
every other node can reproduce the result byte-for-byte instead of taking
anyone's word for it.

It is a headless aerial dogfight. Two **pilot** programs fly a team each. The
match core advances 60 ticks per second of match time with integer arithmetic
only, so the same seed and the same controls produce the same bytes on any
machine and any compiler. The match writes a **replay** — the exact control
stream plus the final state — and two cryptographic roots over it.

![ZCODE Arena](assets/zcode-arena.svg)

## Run it

```bash
make arena-demo
# or, from the fetched C23 package after `zcode use`:
#   zdogfight play --seed 7 --planes 2
```

No blockchain sync, no Tor, no wallet, no browser, no JavaScript, no Python, no
network, and no running node. It compiles the arena core, two pilots and the
runner, plays a match, re-simulates the replay, checks the roots against the
pinned reference, and proves that a single altered byte is refused.

Expected output:

```text
ZCODE ARENA
Red Ace defeated Blue Drone 10-6
11,941 deterministic ticks

Replay verification:       MATCH
Result vs pinned roots:    MATCH
Altered control byte:      REFUSED (match-incomplete)

Seed:                      7 (3v3)
Red pilot:                 Red Ace — zdogace 0.1.1
Blue pilot:                Blue Drone — zdogdrone 0.1.0
Replay root:               05ed352dbb2213aad289cdf403d424d18d9ae075db57252a52c4e745a25e8396
Final-state root:          e4b37a9b94547cead91a7d4ae2a63b0385b29a99bb603bd0ac3519cebd270ebd
State-root chain:          657cbc598e8cfff4e3a67e0b11de17a6b576be686ae924149614eca3e156f87b
```

Those three roots are the acceptance. If your machine prints them, your machine
ran the same match — not a similar one.

## Watch it

```bash
make arena-view                    # play the demo match, then show it
make arena-view REPLAY=/tmp/my.replay
make arena-view-check              # roots + deterministic 1280x720 PNG
```

`make arena-view` is the one command. It plays the pinned demo, re-derives
the match, and writes a 1280×720 PNG from the hosted C23 software
framebuffer with Inter HUD (score, clock, camera, minimap, controls, roots,
and the 320×180 hosted inset). When `pkg-config` finds raylib 6.0, it also
opens the optional native window (`tools/arena_view.c`) with `--show`.

The picture is a verified replay, not a diagnostic. HUD typography uses the
bundled SIL-OFL Inter Medium and SemiBold Basic Latin subsets through the
existing software canvas. If those faces cannot rasterize, the PNG path
refuses instead of inventing glyphs. Roots on the footer are recomputed here
from the replay bytes; pixels never write match state.

The optional raylib window adds chase/cockpit/orbit/overview cameras, TAB to
cycle planes, C for camera, SPACE to pause, arrows to seek, +/- for speed.
A live tactical minimap and the same hosted C23 inset sit on that window.
Automated runs never need it: `make arena-view-check` uses `arena_frame`
(no window) and compares two PNG renders for byte identity.

Linux is the measured host for the software PNG path. The interactive raylib
window is optional and was not measured on this host (raylib is not required
and is not installed by the check). macOS can build the public node natively
and should compile this software path; the raylib window is still optional
there, and Linux Landlock/seccomp pilot confinement is unavailable — the
demo already retries unconfined and the roots stay identical. Windows was
not measured; the software compositor is portable C23, and the raylib
window remains optional. Descriptor-bound A/B execution is a separate
Linux-only node feature and is not part of this demo.

Related targets:

| Command | What it does |
|---|---|
| `make arena-demo` | play, verify, check the pinned roots, refuse a tampered replay |
| `make arena-view` | play the demo, write the 1280×720 Inter HUD PNG, and open the optional raylib window when present (`REPLAY=` to view a file) |
| `make arena-view-check` | refuse incomplete argv; re-derive the pinned demo roots; write and byte-compare a 1280×720 PNG (no raylib, no window) |
| `make tools/arena-frame` | hosted C23 1280×720 PNG compositor (`arena_frame --replay f --png out.png`) |
| `make tools/zdogview` | C23 integer 3D CLI: `zdogview verify` / `zdogview render --out f.ppm` |
| `make arena-svg` | regenerate `docs/assets/zcode-arena.svg` from a freshly verified match |
| `make arena-svg-check` | fail if the committed artwork is stale |
| `make arena-demo-opt-parity` | rebuild the pilots at `-O0` and `-O2` and require identical roots |
| `make tools/arena-selftest` | run the arena core's, both pilots', and zdogview's own test suites |

## The pieces

| Package | Role |
|---|---|
| [`contexts/commons/packages/zdogfight`](../contexts/commons/packages/zdogfight) | the match core: world, flight model, guns, kills, scoring, canonical state encoding, pilot ABI |
| [`contexts/commons/packages/zdogace`](../contexts/commons/packages/zdogace) | a pursuit pilot — flies red |
| [`contexts/commons/packages/zdogdrone`](../contexts/commons/packages/zdogdrone) | a simple patrol pilot — flies blue |
| [`contexts/commons/packages/zprng`](../contexts/commons/packages/zprng) | the only entropy source, drawn solely by respawns |
| [`contexts/commons/packages/zdogview`](../contexts/commons/packages/zdogview) | integer 3D view of a verified replay (C23, Apache-2.0; no raylib) |
| [`tools/arena_runner.c`](../tools/arena_runner.c) | plays a match between two confined pilot processes; also verifies a replay |
| [`tools/arena_svg.c`](../tools/arena_svg.c) | renders a verified replay to a deterministic SVG |
| [`tools/arena_frame.c`](../tools/arena_frame.c) / [`tools/arena_hud.c`](../tools/arena_hud.c) | hosted C23 1280×720 PNG + Inter HUD (the measured picture; no raylib) |
| [`tools/arena_view.c`](../tools/arena_view.c) | optional local raylib 6.0 window over `zdogview` (`make arena-view` passes `--show` when the binary exists) |

Every Arena package is ordinary C23 under Apache-2.0 (Copyright 2026 Rhett
Creighton). Any node can publish, discover, fetch, confined-build,
independently reproduce, and serve them over the package swarm with no GitHub
and no central registry. Exact identity is the `package_root` in each
`zcode-package.json`. Publish validation refuses any other language and any
license outside the frozen permissive allowlist — see
[`P2P_SOURCE_HOSTING.md`](P2P_SOURCE_HOSTING.md). A fetch is inert. Import
reconstructs the signed carrier; pin keeps the replica. After that this node
announces the same root, so the original publisher can disappear and later
peers still fetch the exact bytes from whoever still holds them. The swarm
net test `useful C23 packages host redundantly` is that proof for `zprng`,
`zdogfight`, `zdogdrone`, `zdogace`, and `zdogview` (A publishes, B mirrors,
A is removed, C fetches from B). The two-node arena script below is the
match-play journey for the four match packages (`zprng`, `zdogfight`,
`zdogace`, `zdogdrone`).
The raylib window is a local display of those verified bytes, not a swarm
dependency.

Keep-alive of a root a peer already heard is inventory, not flood.
Re-announcing a root this node already holds is how redundancy works: B
serves the same exact carrier after A disappears. There is no central
tracker. The remaining announce bound is unique *new* roots per hour from a
NEW_USER, capped at the serving-set size (64). The four match packages sit
inside that library shelf.

A pilot is an ordinary program. Per tick, for each of its living planes, it
reads one 82-byte observation frame on stdin and writes one 7-byte control
frame on stdout. That is the whole interface.

Each pilot runs **confined**: a Landlock domain whose only filesystem grant is
read+execute on the pilot binary itself, the session seccomp deny-list with
W^X, a scrubbed environment, and a CPU-seconds budget. A pilot that crashes,
stalls past its budget, or sends a short frame is marked dead, and from that
tick onward its whole team receives neutral controls — recorded in the replay
like any other control. A misbehaving pilot cannot abort a match or make it
nondeterministic; it can only lose.

Confinement is a property of your kernel, not of the match. `arena_runner`
refuses to run unconfined by default and exits 3 with a named reason when
Landlock or seccomp is unavailable — inside some containers, on older kernels,
under some VMs. `make arena-demo` catches that one exit code, re-runs with
`--no-sandbox`, and prints which mode it used:

```text
Pilot confinement:         Landlock + seccomp
```

The roots are identical either way, because confinement bounds what a pilot
*process* may do and is not an input to the simulation. Nothing else about the
demo changes: every root, the re-simulation and the tamper refusal are checked
at full strength in both modes. If you are running a pilot you did not write,
use a kernel that can confine it.

## Write your own pilot

Copy the smaller pilot and change its decision function:

```bash
cp -r contexts/commons/packages/zdogdrone contexts/commons/packages/mypilot
```

Then edit `contexts/commons/packages/mypilot/src/`. The decision function receives a
`zdog_obs` — your plane's position, attitude, speed, health, the score, ticks
left, and the nearest living enemy's relative position, distance, velocity and
health — and fills a `zdog_ctl` with roll, pitch, throttle and a fire flag.

Rules your pilot must respect to stay deterministic: integer arithmetic only
(the core has no floating point anywhere), no clock, no `rand()`, no
filesystem, no network, no allocation. `zdog_sin16`/`zdog_cos16` are exported
so your bearing maths uses the exact table the simulation uses.

Build and fly it against the shipped pilots:

```bash
cc -std=c23 -O1 -static -D_POSIX_C_SOURCE=200809L \
   -Icontexts/commons/packages/mypilot/include -Icontexts/commons/packages/zdogfight/include \
   -Icontexts/commons/packages/zprng/include \
   contexts/commons/packages/mypilot/app/main.c contexts/commons/packages/mypilot/src/*.c \
   contexts/commons/packages/zdogfight/src/zdogfight.c contexts/commons/packages/zdogfight/src/zdogfix.c \
   contexts/commons/packages/zprng/src/zprng.c -o /tmp/mypilot -lm

build/bin/arena_runner --seed 7 --planes-per-team 3 \
    --pilot-red /tmp/mypilot --pilot-blue build/bin/pilot_zdogdrone \
    --replay-out /tmp/my.replay
```

`-static` is required: the sandbox's W^X denial refuses the executable mapping
a dynamic loader needs.

## Verify a replay

```bash
build/bin/arena_runner --verify-replay /tmp/my.replay
```

Verification re-applies the recorded control frames with **no pilots at all**
and requires three things: the match reaches its end phase at exactly the
recorded tick count, the re-encoded final state is byte-identical to the block
stored in the file, and the recomputed roots match. Anything else exits 1 with
a named mismatch — `header-magic`, `size`, `ctl-frame`, `match-incomplete`,
`tick-count`, or `final-state`.

That is why the demo's tamper leg matters. It flips exactly one byte of the
recorded control stream and the verifier refuses by name. "Verified" here is a
predicate somebody else can run, not an adjective this project prints about
itself.

The three roots:

- **replay root** — SHA3-256 over the whole replay file. Identifies the exact
  match, controls included.
- **final-state root** — SHA3-256 over the 2,163-byte canonical final-state
  encoding. Identifies the outcome independently of how it was reached.
- **state-root chain** — a SHA3-256 chain folded every 600 completed ticks, so
  two nodes that disagree can find the first ten-second window where they
  diverged instead of only learning that they did.

## The three-node proof

`make arena-demo` proves reproduction on one machine. The cross-node proof is
[`tools/dev/arena_acceptance.sh`](../tools/dev/arena_acceptance.sh), and it is
the reason the pinned roots above are worth anything.

It stands up three isolated nodes on one host. Nodes B and C start from clean
datadirs, run the same `z23 join` command an operator runs, and then boot
without command-line package-host or build-worker overrides. Node A serves the
four published arena packages. Node B fetches them over the package swarm,
installs each through the confined build-and-test worker, and builds its own
pilot binaries from its own store. Then both nodes play the same match
independently. The proof asserts that B's pilot binaries and installed
archives are byte-identical to A's, that both replays are byte-identical, and
that all three roots and the winner and tick count agree. Before any build,
the proof stops A and requires clean node C to fetch byte-identical inert
package bytes from B alone over ordinary P2P inventory. Chain height and
mempool stay zero and the ZID-gated DHT stays disabled: joining this SWARM leg
needs no wallet transaction, fee, identity anchor, or invitation. It also
flips a byte in a copy of B's replay and requires a named refusal, and
SIGKILLs a build worker mid-build to show the identical retry reproduces
identical archives.

Run it deliberately — it spawns three real node processes:

```bash
make commons-no-coin-onboarding-acceptance
```

## Honest gaps

These are named because they are real, not because they are about to be fixed.

- **The Arena is not on-chain and not consensus.** Nothing here touches
  ZClassic consensus, block validation, wallet custody, or the ledger. There is
  no live ZC23 token economics; scoring is a simulation.
- **The pinned demo pilots are repo-source, not the published packages.** The
  published `zdogace` 0.1.0 carries a steering-sign quirk; the sign-fixed 0.1.1
  in `contexts/commons/packages/` is what the demo builds. Both are exact and deterministic —
  they simply play different matches. The published-package leg of the
  acceptance script pins its own separate roots.
- **The cross-node proof runs two nodes on one host.** It proves independent
  fetch, install, build and replay across two disjoint datadirs and stores; it
  does not prove reproduction across two CPU microarchitectures. The
  self-hosted `arena` workflow is an additional clean-checkout observation, not
  independent platform qualification. The package-swarm proof therefore
  remains same-host evidence.
- **Match definitions are carried out of band.** The acceptance script writes
  the seed, plane count and package roots to a file both nodes read. There is
  no signed on-network challenge/accept wire for a match yet; the transport
  under test there is the package swarm, not the match definition.
- **A NEW_USER learns unique new roots, not keep-alives.** Announce flood
  counts unique *new* roots per hour from a NEW_USER, capped at the serving-set
  size (64). Keep-alive of a root the peer already heard is inventory, not
  flood. Re-announce of a root this node already holds is how redundancy
  works; there is no central tracker. A store serving more than 64 complete
  packages cannot introduce the excess to a fresh NEW_USER in one hour
  window. The four match packages (`zprng`, `zdogfight`, `zdogace`,
  `zdogdrone`) sit inside that library shelf.
- **Release-envelope import is DHT-gated.** The raw swarm delivers exact
  package content, but persisting the signed release envelope needs the
  authenticated DHT provider route, so the acceptance script hands those
  envelopes over the same out-of-band channel.
- **The artwork is a contact sheet, not an animation.** Six deterministic
  overhead snapshots, chosen by fixed rules over the re-simulation. The
  interactive 3D window is [`tools/arena_view.c`](../tools/arena_view.c) —
  local, optional raylib 6.0, and not part of `make test` or the two-node
  swarm proof. `make arena-view-check` re-derives the pinned roots and a
  deterministic 1280×720 PNG from the hosted C23 framebuffer with Inter HUD;
  it does not need raylib. The committed artwork stays a byte-deterministic
  SVG so `arena-svg-check` remains a real staleness gate, and no browser or
  renderer is required by any default acceptance.

## Where this sits in the project

Z23 is first a public ZClassic full node. The Arena is an application of
the second thing it does: the decentralized C23 Commons, where ordinary nodes
publish, discover, fetch, verify, build, independently reproduce and serve
exact C23 packages without GitHub or a central registry. Package activity never
takes priority over consensus, relay, sync, peer health, wallet custody or
deployment — see [`AGENTS.md`](../AGENTS.md).

The Arena is the version of that story you can check in under a minute.
