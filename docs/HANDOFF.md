> **Read this file first for current live-node state.** Older revisions are
> evidence, not standing fact — recover them with
> `git log --follow -- docs/HANDOFF.md`.

# HANDOFF — current state

This page records only the current state of the maintainer's hosted node. It
does not define product direction or development priority. Read
[`../AGENTS.md`](../AGENTS.md) for the durable contract and
[`work/FORWARD_PLAN.md`](work/FORWARD_PLAN.md) for the current ordered mission,
then re-derive every live claim below through the node.

The typed status commands are ground truth; this page is a pointer to
evidence files, never a substitute for re-checking them:

```bash
z23 status
z23 dumpstate reducer_frontier
tail -5 ~/.local/state/zclassic23-slo/uptime-ledger.jsonl
```

## Current state

**2026-08-06 21:54 AST — identity-bound custody and the transaction-laboratory
infrastructure gate are CURRENT; the laboratory remains unfunded and has
broadcast zero transactions.** Re-derived from the live native readers after
the owner-gated challenger deployment and watched restarts:

- `metaverse agent money` reports both assigned wallets complete and CURRENT:
  dev confirmed `0.30000000 ZCL`, pending/encumbered/intent-reserved zero,
  agent-available `0.05000000 ZCL`; prod confirmed `0.00000000 ZCL` with all
  other amounts zero. The known portfolio total is `0.30000000 ZCL`. The
  private binding was rotated to the live persistent identities; no funds
  moved.
- Canonical typed `status` passes and `reducer_frontier` reports complete H*
  exactly equal to the observed network tip with no next-frontier blocker.
  Canonical remains active with `NRestarts=0`, a 120-second watchdog, and an
  advancing watchdog timestamp. A 6G live trial pinned the full-datadir cgroup
  at its soft cap and starved RPC; a clean 24G restart restored RPC and current
  custody. Commit `58f11e33` records that measured 24G production envelope.
  The isolated dev lane is active under its matching 4G soft/hard envelope and
  120-second watchdog. Its prior 3G soft cap produced intermittent custody RPC
  and one restart (`NRestarts=1` remains visible); the 4G envelope is committed
  rather than hiding that measured result.
- `catalog_coverage` reports `sprout_anchor` complete at the live tip with lag
  zero; no active sprout/catalog blocker remains. This closes the former false
  sparse-journal lag fact.
- The fixed off-host judge is `PASS`: six clean agreeing samples span 7,375
  seconds, every clean sample is backed by at least two distinct remote peers,
  and there are zero contested witnesses and zero disagreements. The timer
  remains active. Its history also contains 141 fail-closed `could-not-ask`
  rows, principally intermittent native query-budget interruptions; those are
  operational evidence to improve, not agreement and not a reason to weaken
  the judge. Raw endpoint/path-bearing rows remain private and are not printed
  by `make tip-agreement-status`.
- `make transaction-lab-status` remains 39/39 isolated proofs, 38/39
  simulated/live confirmations, 35/39 mainnet-capable, and **0/39 live**.
  The two isolated micro-lab wallets are 2/2 ready, address-redacted,
  key-unexported, and unfunded. The infrastructure stop is cleared; the next
  money action is still an exact, non-broadcasting `dev` plan followed by the
  separate owner-review/approval message required by the live runbook. Never
  treat this acceptance result as blanket approval for unknown outputs or
  changed fees.

The real-Tor fork fix is on its `main`; parent `main` contains reproducible
`make tor-full`, rollback-safe deploy capture, explicit owner-only challenger
verification, accurate native-C23 Sapling audit text, and private status
output. The live challenger proves exact bytes and diagnostics but deliberately
does not claim the structurally unavailable stable-health verdict on this
snapshot-seeded datadir. Re-check live commands before trusting this paragraph;
newer `main` commits landed after the challenger build.

**2026-08-05 — S7.2 operational integrity plus Sovereign Space/Scout COMPLETE
on integrated `main`; not deployed.** Initial integration merge `21428f0a9`
preserves fetched `origin/main` `9f678f70f`, final lane head `d77d61eef` and
implementation head `1312261ee` as ancestors; product/test head `3ccb853f8`
adds the literal-empty-datadir proof described below. A final fetch found
`origin/main` advanced to `8ef119603`; conflict-free refresh merge `de6933a22`
preserves its transaction-demonstration catalog and all earlier integration
history. The lane first closes the operational gaps left after S7.1.
Possession validation is generation-bound,
race-closed and scheduled under strict package/chunk/byte budgets; mandatory ACK
plan, commit, restart and renewal proofs remain synchronous and full-byte.
Replication status now composes bounded distributed PROVIDER and STORAGE_ACK
discovery, preserves conflicts and incomplete evidence, distinguishes remote
signed claims from locally revalidated possession, and makes `durable` fail
closed. Pointer sequence is comparable only inside one signed publisher stream;
equal-slot conflicts remain unusable evidence, denied candidates are skipped
individually, and unrelated hostile high sequences cannot crowd out an honest
root. Lookup and publication use monotonic scheduling, bounded frontier restart
under churn and recursive cancellation without widening restricted fetches.

The first sovereign-space objects are canonical bounded
`service_descriptor.v1` and delegated, expiring, signed `space_manifest.v1`
wires in the existing CAS. A descriptor names a full protocol root, read-only
verbs, object roots and capability roots; it grants no authority and is never
executable. Typed `metaverse.space.plan|commit|show|publish|discover` commands
reuse the existing generic POINTER/PROVIDER, authenticated Noise route,
restricted swarm and local sovereignty engine. FETCH, STORE, INDEX, SERVE and
FORWARD stay independent local decisions. The two READ planners now use
strictly non-creating delegation/key loads. The read-leaf integrity test
recursively snapshots typed datadir paths, so nested payload-directory writes
cannot hide behind an unchanged top-level file set; on integrated main, all
four Space/Scout READ leaves additionally begin with a literally zero-entry
datadir and prove that no `zcode/`, nested payload,
policy/publication/space/scout path or database appears.

`metaverse.space.scout.plan|run|show` defines one bounded read-only mission:
sorted starting roots, explicit depth/space/portal/byte caps and a monotonic
deadline. It follows only locally permitted portal manifests and writes a
canonical deterministic evidence map plus a separately signed local
attestation. Results enumerate visited roots, owners, advertised services,
portal outcomes, typed failures, policy denials and truncation. The map is
local evidence, never authority or global truth. Scout never invokes service
verbs, packages, wallets, messaging or an execution callback.

The new hermetic acceptance proof uses sixteen real DHT services and
Noise-bound sessions on a sparse chain. A root-only late joiner crosses
multiple record pages and hops through iterative POINTER and PROVIDER
discovery, an authenticated provider route and the unchanged
ANNOUNCE/WANT/DATA swarm before semantic CAS admission. Its 24 alpha-pointer
rows include eight real equal-slot conflict pairs, seven independent hostile
high-sequence streams and one low-sequence honest stream. The proof also covers
cycles, a dead root, provider disconnect/zero/rebind, two genuinely distinct
local policy maps (one blocks delta while the other admits it), default-denied
unknown EXECUTE with zero execution requests, deterministic repeat maps and
byte-identical records, permitted CAS objects, evidence and attestation after
DHT/store/swarm restart. The earlier 12-node replication proof remains a
separate complementary test.

Fresh refreshed-integration receipts at head `de6933a22`: both canonical
seven-daemon DHT runs pass (the science target deliberately reruns that
prerequisite), and the two-daemon science acceptance passes its package and
generic blob carriers, cold restart, semantic-root rederivation and SQL-wipe
reconstruction. Focused space/scout, DHT, possession/store, swarm, science,
market, yardsale, transaction, multisig, 32 GiB ROM, 2,048-entry block-cache,
native/API catalog and read-integrity regressions pass; the transaction lab is
39/39 with 38/39 simulated/live confirmations, 35/39 classified as
mainnet-broadcast-capable and only the explicitly blocked mainnet custody tier
absent. The focused ASan+UBSan DHT/model gate, including
the 12-node replication and 16-node Space/Scout proofs, passes with no
sanitizer finding or suppression. The complete `make lint` gate set and full-program LTO
pass. The strict cold suite registered 904 groups, ran 895, cached 0,
policy-gated 9 parameter-heavy groups, failed 0 and reported 19 explicit
self-skip markers (86.9 s, 32 workers). The first refreshed cold run had one
performance-detector anti-vacuity miss under concurrent load; its exact
isolated reproduction passed (clean growth 968 permille, injected growth 3412
permille), then the full uncached suite reran cleanly. `ci-reproducible` produced two
identical 25,782,344-byte binaries at SHA3-256
`6b7f2c5e54987668a071bf3a22342bae46e895ded06a2732373f7890eb07d1f0`;
different-length snapshot paths produced two identical 25,782,424-byte
binaries at `3b26e100872a69ea586f728ba5c752486124120578f67cd5220729aefcb6e952`.
Mandatory pre-push CI passes strict build-only, fast lint and all 895 runnable
source-wide groups (9 parameter gates, 19 declared self-skips); its live
topology probe remains intentionally disabled by `ZCL_FAST_LIVE=0`.

Independent implementation review first rejected a hidden `zcode/dht` mkdir
from READ planners; the lane fixed the load path and recursive test. A separate
integration reviewer audited merge `21428f0a9`, proved it has no resolution
delta, verified the newer transaction/proof/capacity files byte-identical to
the main parent, reran the focused matrix plus the complete `make lint` gate set and returned
**BANKABLE**. Its final audit also replayed the literal-empty-datadir group,
verified every integrated count/hash and audited the receipt-only delta; final
verdict remains **BANKABLE**. Post-drift re-review proved refresh merge
`de6933a22` has no resolution delta, its six upstream files are byte-identical
to `8ef119603`, replayed the literal-empty and transaction-lab proofs and again
returned **BANKABLE**. Exact phase and integrated receipts and honest bounds
are in `docs/work/wt-zcode-s7-2-space-scout.md`.

Honest limits: no doorbell, board, mailbox, store interaction, agent action,
remote service invocation, arbitrary package execution, REST silo, consensus
change, wallet spend, deployment or live-datadir operation was added. Unknown
C23 remains default-denied and can execute only under explicit local policy in
the confined ZCODE executor. Scout records advertised service roots but does
not fetch or invoke descriptors, and scheduled asynchronous discovery may
require a later mission rerun after admission. Future signed space manifests,
doorbells, BBS objects and user-defined services must remain local-policy
subjects and reuse this CAS + generic POINTER/PROVIDER + authenticated swarm
foundation; shared blocklists remain advisory and opt-in, never global bans.

**2026-08-05 — S7.1 distributed record discovery and possession-backed
replication COMPLETE; not deployed.** ZCODE now has one generic signed
discovery substrate over the
existing S6 Noise/`zpkgswm` sessions—no science-only carrier and no second
socket stack. The exact 551-byte v1 record is one of PROVIDER, POINTER or
STORAGE_ACK and binds network genesis, a canonical namespace, semantic and/or
transport roots, provider node ID, sequence, validity window, owner group
where applicable, and the chain-bound delegated online signer. PROVIDER is a
two-hour hint, never possession proof. POINTER is bounded to seven days
(science publish uses one day so it remains inside the default delegation).
STORAGE_ACK is bounded to seven days and can be authored only by the package
store after it parses and root-binds the manifest, reads and hashes every
chunk, proves the complete transport root and confirms a local pin. A generic
caller cannot mint an ACK; STORE_RESULT remains a distinct transport-admission
response. Unpin, missing bytes, corruption or failed revalidation stops
renewal, so durability falls when the last valid ACKs expire.

Records use `zcode/dht/records.v1`, a strict canonical projection that cold
reloads active records and preserved conflicts byte-for-byte and prunes
ordinary expiry. Caps are 4,096/node, 64/root, 256/provider and 8 conflicts;
traffic is eight records/frame, eight record operations and 256 accepted
records/peer. It reuses S6 authentication, independent replay namespaces,
4/s rate with burst 8, deadlines, routing, unlock/relock generation checks and
the one global three-query budget. Malformed, oversized, cross-network,
stale, replayed, expired and unauthorized traffic fails closed. Records are
application evidence only and never touch consensus. The cache is not network
discovery: a domain-separated key binds network, record kind, namespace and
selected root, then the existing `k=16`, `alpha=3`, 64-candidate DHT iterates
signed record queries until the closest responsible set stabilizes, the
deadline expires or the verified-result cap is met. Failed members of the
closest 16 admit candidates 17–64. Public begin/poll/cancel uses opaque lookup
and owner tokens; synchronous provider/science callers wrap that same state
machine. Results paginate deterministically to 64, prefer distinct provider
IDs and preserve same-sequence conflicts separately.

The one local sovereignty engine is consulted for DISCOVER, FETCH, STORE,
INDEX, SERVE, FORWARD and EXECUTE. Its 1,024-rule canonical policy supports
exact full root, package, publisher ZID, service type and local classification.
Unknown objects default to metadata discovery only; fetch/store/index/serve/
forward/execute require local allowance. Local blocks affect only this node;
shared advisory rules are opt-in and cannot create a global ban. The read
surface exposes only rule count, opt-in state and a digest—private rules and
keys stay redacted—and loading an absent policy creates no directories.

Typed surfaces are `zcode.network.records.begin|poll|cancel`,
`zcode.network.providers`, `zcode.network.publish`
(plan/commit), `zcode.network.policy.list|mutate` (redacted plus plan/commit),
`zcode.network.replication`, and plan/commit `zcode.package.pin|unpin`.
Replication targets up to eight providers and says `durable` only after five
live ACKs from distinct provider IDs across three declared owner groups. That
is declared diversity, explicitly not proof of separate operators, machines
or failure domains; partial success and expired ACKs remain visible. Publish
targets the closest eligible DHT nodes and persists key-free renewal intents.
Restart uses a fresh online delegation, applies bounded backoff/expiry and
halts forwarding immediately when local policy changes.

The root-only science gap is closed. `zcode.science.publish` creates the
verified one-chunk transport object, one-day science POINTER and two-hour
PROVIDER. Fetch deterministically retains pointer conflicts, rechecks local
policy for semantic root, transport root, publisher ZID and service type,
discovers provider records, accepts only chain-bound ZENDP reachability, dials
through connman, and requires a fresh Noise/delegation-authenticated session.
The restricted swarm verifier can fetch only the selected transport root and
falls through absent, timed-out, lying or corrupt providers.

`make test-science-acceptance` is exact and green. Its prerequisite
seven-identity daemon proof passes sparse multi-hop and broken-nearest recovery,
eight simultaneous callers with exactly three live queries, canonical restart
and zero-peer cold bootstrap. The two-daemon science phase starts B with only
A's semantic root, resolves the signed POINTER and PROVIDER, fetches through
the unchanged manifest/chunk verifier, re-derives the science root from bytes,
admits it and projects `study.show found=true`. Both nodes cold restart; after
direct SQL deletion of all six science projection tables, rebuild is
byte-identical and CAS counts remain A=20/B=21. A separate hermetic 12-node
sparse proof covers cache/peer-DB/direct-publisher absence, multi-hop lookup,
closest-node publication, candidate-frontier escape, bounded traffic, restart
renewal, physical CAS-byte loss, ACK non-renewal and a one-node root ban while
an alternate path remains usable. These are complementary proofs, not a claim
of one 12-daemon deployed topology.

Final receipts include the exact DHT and root-only science gates above; all
eight selected adversarial groups; focused DHT, record, swarm, science, store,
market and yardsale regressions; the focused ASan+UBSan DHT/model gate with
zero suppressions; the complete `make lint` gate set; and full-program LTO. The cold uncached
suite registered 902 groups, ran 893, cached 0, policy-gated 9 parameter-heavy
groups, failed 0 and reported 19 explicit self-skip markers (85.7 s, 32
workers). After merging concurrent wallet/transaction work, integration head
`09770961f` reran the complete `make lint` gate set, strict build-only, the exact combined DHT
plus science acceptance, and both reproducibility proofs. Same-tree produced
two identical 25,602,728-byte binaries at SHA3-256
`2f0f08773db50719178eb16d68da81a3583fba4d919a18207c47cdbe3b425a70`;
different-length builder paths produced two identical 25,602,808-byte binaries
at `f8b599b5aa190e35dd80159fee9e728d0c9e27998eb780dd12a077665ab730fc`.
The lane and integration receipts are recorded in the S7.1 assignment
document.

Honest limits at the S7.1 integration head (superseded by the S7.2 section
above): signed discovery records are expiring hints, not content truth,
availability proof, scientific acceptance or operator independence. Unknown
C23 is never auto-executed; execution remains explicit local policy plus the
confined ZCODE executor. That S7.1 head added no space manifest, doorbell,
board, mailbox, agent mission, arbitrary service execution, REST protocol
silo, consensus change, wallet spend, deployment or live-datadir mutation.
Future sovereign spaces must reuse these generic namespaces, objects and
transport.

**2026-08-04 — S6 production hardening COMPLETE; not deployed.** The existing
`zpkgswm`/Noise transport now carries bounded `FIND_NODE`/`NODES` traffic;
there is no second socket stack. A node ID is bound to an active,
chain-anchored ZID master, a delayed active-chain beacon, its delegated online
Ed25519 key, and the authenticated Noise static key/session. Routing is fixed
at k=16/alpha=3 with a 1,024-contact cap, a deterministic 64-entry candidate
pool, closest-16 active frontier, 64 authenticated peer slots, three active
queries, eight fairly queued lookups, and a 30-second per-lookup ceiling.
Candidates retain explicit unverified, unreachable, authenticated, queried,
in-flight, responded, or failed state; replacement probes separately retain
WAITING, IN_FLIGHT, RESPONDED, FAILED, or EXPIRED state. Address-free NODES
results request a deduped, backoff-bound dial only through an accepted, signed,
chain-bound ZENDP endpoint; a matching fresh Noise session plus delegation is
still the sole promotion authority. The fixed-size reachability index is
invalidated on endpoint, ZID, and header generations. Replay namespaces split
FIND_NODE requests from NODES responses, each node ID retains one service
session, and locally generated connection serials never alias peer claims.
Canonical `contacts.v2` persistence is strict, network/self bound, uniquely
serialized, and cold-revalidated.

Public lookup admission is genuinely asynchronous:
`zcode.network.find.begin|poll|cancel` uses opaque 128-bit lookup IDs and a
separate owner token, with expiry and idempotent terminal polling; the existing
`zcode.network.find` is only a client-side wrapper. External chain, database,
disk, endpoint, ancestry, and network work occurs outside the global DHT lock,
then relocks against captured generations. Read-only status surfaces remain
`zcode.network.status|peers`; `ops state --subsystem=zcode_dht` reports rounds,
XOR progress, candidate/frontier composition, queue wait, termination reasons,
reachability/cache operations, ancestry work, contacts, probes, frame counters,
and persistence without keys, raw delegations, peer addresses, or an
operator-diversity claim.

The acceptance proof (`make test-zcode-dht-acceptance`) retains the original
two-node hostile-frame/persistence checks, then creates seven independent
identities on a common closed-chain fixture. It builds only a sparse neighbour
chain plus one alternate edge, files six signed endpoints at the lookup origin
without inserting contacts, kills the nearest path, and proves target recovery
in at least three rounds with XOR progress and bounded traffic. It also proves
eight simultaneous external callers while exactly three network queries are
stalled, replay pressure beyond 16 unique signed frames, zero-peer autonomous
cold bootstrap, multi-contact persistence, and fresh reauthentication. A
deterministic 32-node model runs 12,000 transitions with continuous cap,
authentication, replay, churn, persistence, and incumbent invariants; the
focused ASan+UBSan gate runs codecs, routing, service, lookup, and that model
without suppressions. The final evidence set is: focused
DHT/Noise/transport/argv/connman/RPC tests; yardsale and store tests including
both opt-in store stress groups; the complete `make lint` gate set; the cold uncached suite
(898 registered, 889 run, zero cached, 9 parameter-gated, zero failed, 19
explicit self-skips); full LTO; science acceptance; and both reproducibility
gates. Same-tree SHA3-256 is
`e808a8cef470c3bd32b67f9d430bc6dc908ea3280584937a8316c8aca4aea3be`;
different-path builder SHA3-256 is
`e05529ca82b1ad86a949bbc24e8e94e7c57abea2856f612afe33a2721ddb8d0f`.
Implementation head was `545e6b2b9`. At that S6 head, provider/root discovery,
STORE acknowledgements, replication and automatic science blob-root discovery
were still open; the S7 section above supersedes that historical limit.

**2026-08-03 — G4 (findings had no command-leaf admission) CLOSED.**
New leaves `zcode.science.findings.plan|commit`: exact expiring plan +
confirm:true commit, durable idempotency, CAS store addressed by the
canonical root, findings projection in the rebuild-identical mapping.
Service lives in `app/services/src/zcode_science_findings.c` (E1 split);
the plan/commit plumbing is exported via `zcode_science_service.h`.
Schema v51 rebuilds `zcode_science_plans` with the kind CHECK extended
to 'findings' (SQLite cannot ALTER a CHECK; rows carry over) and the
model kind allowlist matches. The fixture's new `mkfindings-emit`
composes the deterministic wire without touching the CAS, so the
acceptance script now admits findings through the leaves and the fresh
review binds the CLI-admitted findings (H1). Execution-context documents
stay fixture-seeded — content roots, not ledger objects. Proven:
`make test-science-acceptance` PASS with G4 gated CLOSED;
`t-fast ONLY=zcode_science_store` (new test_zstore_findings_plan_commit)
plus schema_migration/sqlite/blog groups green.

**2026-08-03 — G1 (science objects have no node-to-node carrier) CLOSED.**
`zcode.science.publish` mirrors a committed science wire into the package
store as a one-chunk content.v2 blob (`vcs_blob_put_to`); the blob root is
the transport address, the science root stays the semantic address and is
re-derived from the fetched bytes at admit time — never trusted from a
claim. `zcode.science.fetch` schedules the swarm fetch and admits the blob
(`vcs_blob_get_from` → wire identify → idempotent `put_addressed` → full
`zcode_science_rebuild`). Proven in the original
`make test-science-acceptance`: node A
publishes its study, node B fetches and admits it post-restart with the
identical science root/kind and `study.show found=true`. Historical limit at
that commit: the blob root traveled out of band because S6 found authenticated
node IDs only. S7 now closes that limit with signed generic POINTER/PROVIDER
records. Files:
`app/services/src/zcode_science_carrier.c` (carrier;
`zcode_science_service.h` declares publish/admit),
`tools/command/native_zcode_science_command.c`,
`config/commands/zcode_science.def`, `lib/test/src/test_zcode_science_store.c`,
`tools/dev/science_acceptance.sh` (G1 leg flipped to positive proof).

**2026-08-03 10:01 UTC — G2 (fresh-node swarm fetch stall) CLOSED on main**
as `9e375d355`, verified by `make test-science-acceptance` (two fresh nodes;
B fetched 5 chunks node-to-node and rederived the package root; both nodes
then cold-booted and rebuilt every science object from CAS hashes). The fix
is three stacked parts: a NEW_USER 4/hour bootstrap announce quota
(`VCS_POLICY_FREE_ANNOUNCE_PER_HOUR`), deduped per-sync re-announce to every
known peer, and a supervisor clock-driven swarm (`net.zcode_swarm` child,
1 s period, net domain) — the swarm tick previously only fired on inbound
peer messages, so an idle healthy connection never announced or fetched.
NOT YET DEPLOYED: the canonical source ID below predates G2 and the later
science commits above.

**Recovered 2026-08-03; transaction laboratory remains gated.** The canonical
service had been offline in a watchdog restart loop with its configured checkout
binary absent. Recovery used the owner-declared intervention path and the
complete-state bundle at h=3,056,758; no datadir surgery and no canonical wallet
keys were used. The bundle SHA-256 is
`6bc3bf5152e5cd38deadc344d563478696d3800f4417e564119319196447ae83`.
Its copy proof climbed H* from 3,056,758 through 3,203,198, survived restart,
and matched zclassicd at the checked heights before canonical install. This
supersedes the earlier same-day pinned-binary watchdog-loop note: the dedicated
pet-thread fix is present in the recovered binary, but the normal 6G/watchdog
posture still fails for the separately measured reason recorded below.

The running inode (re-check `/proc/$(systemctl --user show zclassic23
-p MainPID --value)/exe`, never a pathname that may have been overwritten) is:

- source ID `6e379d5744d64c6695965e5e61c011a76b6993845d10193fedf8e135379b628c`
- artifact SHA-256 `2733b1e250a459cb8a7c8e15046c54a9b54454ce4ab67403749e526ad0c6b975`
- active since 2026-08-03 05:56:55 UTC; `NRestarts=0` at the last check

The first uninterrupted post-recovery SLO window is durable in
`~/.local/state/zclassic23-slo/uptime-ledger.jsonl`: 61 canonical samples from
`ts=1785731596` through `1785735219` (3,623 seconds), 100% reachable,
`node_state_ok=true` throughout, one unchanged active-enter epoch, zero
restarts, H* 3,203,471 -> 3,203,519, 6-8 peers, and maximum local-oracle gap
3. Exact same-height zclassicd hash checks passed during and after the window;
the latest recorded check in this recovery session was h=3,203,568,
`00000c3408d6e53231696c2005db5243e82268f7965e847f1096d8aa0798dfec`.
The typed frontier had zero H* blockers and only the normal one-height working
edge when it was not returning the explicit retryable `progress_store_busy`.

Do **not** start the mainnet transaction laboratory yet. Four acceptance facts
remain open:

1. Off-host hash parity is `NO_EVIDENCE`: the agreement ledger's latest judge
   saw 12/12 `could-not-ask` samples. Connected peers advertise heights but not
   hashes from two distinct hosts. The prober deliberately has no public-API
   bypass; more independent peers must surface learnable hashes. Never lower the
   two-host floor.
2. Normal service armor is not yet safe. A watched warm restart at
   `MemoryHigh=6G` raised `boot.stage_regression` plus critical memory pressure;
   the health-gated pet sent no post-READY heartbeat, so the 10-minute systemd
   watchdog would have recreated the abort loop. The operator stopped that run
   before the deadline and restored `MemoryHigh=24G` plus the explicit
   `WatchdogSec=0` incident drop-in. The checked-in startup budget is now four
   hours: a later forced-unclean recovery with a 55.3 GB WAL was still making
   named `quick_check` progress after 98 minutes; the former 30-minute,
   provisional one-hour, and two-hour limits were too tight for a safe margin.
3. The standing non-consensus blocker is
   `catalog.sprout_anchor.lag_exceeded` (cursor frozen at 2,124,937). It does not
   block H* progress, but it remains named and visible.
4. `make ci-reproducible` aborted build A twice because the source mutation
   token changed during the LTO build while the byte identity stayed identical
   and Git stayed clean. No byte comparison occurred; this is a gate blocker,
   not a reproducibility mismatch. Lint, build-only, the whole-program test
   binary, and the strict suite (881 groups run, 0 failed) passed.

Recovery evidence fixes are in the adjacent
`fix(recovery): preserve exact evidence bindings` commit: the SLO probe now derives the live
zclassicd port (8023 here), accepts normal spaced JSON, and the installer
retains the exact prior-generation path in its success banner. No lab wallet,
key, transaction, or funding was created.

C8 byte-exact UTXO parity (2026-08-02): the producer full-fold lane
(`~/.zclassic-c23-producer-fold`, from-genesis fold at h=3192878, then live
sync) holds a UTXO set byte-identical to the live zd chainstate at
height 3203194 — sha3 `9a8a4ba72ccb030ccba2daaf426fa3faeb496c3decee0372f12729c09cea4919`,
txouts 1345675, supply 10412541.81045529, both sides equal:
`VERDICT=PASS exact_tier=match from=genesis-producer-full-fold height=3203194`.
The instrument is committed as `tools/scripts/byte_exact_utxo_check.sh`
(compare `getutxocommitment` on the c23 producer vs
`--legacy-utxo-commitment` over the read-only zd chainstate at one agreed
height; zd replies are JSON-RPC envelopes, c23 replies are flat — the
script parses each correctly). This is the byte-level C8 evidence the
height-only live parity service cannot provide; rerun on the linger
cadence and keep the transcript.

Operational lesson (2026-08-02): do NOT run producer-lane heavy jobs
(full-fold sync, `--legacy-utxo-commitment` SHA3 passes, byte-exact checks)
alongside the canonical node. The 10-min systemd watchdog is ENABLED
(journal: `Watchdog timeout (limit 10min)!` → SIGABRT, status=134); the
contention starved the canonical node's watchdog pings twice in 25 min
(NRestarts 33→35, soak window broken). The node self-recovered in 126 s
once the producer lane was stopped — but C6 soak accrual restarted from
zero. Restart #36 the same evening came from an unrelated tenant's
parallel LLVM build pushing load-average past 10 during boot — same
sensitivity, different source: the watchdog pets are hostage to ANY
heavy host load in the boot window, not just our own lanes. Run
producer lanes when the canonical node is operator-paused, nice/ionice
them below watchdog sensitivity, and expect external build storms to
cost a restart each.

**Check this before diagnosing anything live:**

```bash
make agent-doctor | sed -n 2p     # live_node=… running_this_tree=true|false
```

That line was added 2026-07-28 because the same mistake was made twice in one
session: a defect was diagnosed from the checkout, written up, and turned out
to be already fixed in `main` and merely never shipped. The node behaves
exactly like a node with a real bug, so nothing about its behaviour reveals
the gap. `running_this_tree=false` means **stop and ship, or read the
deployed source** — do not reason about live behaviour from the checkout.

Two instruments that were off or absent are worth knowing about:

- **The systemd watchdog is still disabled** (`WatchdogSec=0` in
  `~/.config/systemd/user/zclassic23.service.d/zzzzz-watchdog-incident.conf`).
  It was turned off during the 2026-07-27 keepalive incident when systemd
  SIGABRT'd a healthy node seven times. The deploy deliberately did NOT
  re-enable it — one variable at a time — so whether that regression is gone
  is still **unknown**. Turning it back on is the test. Delete the drop-in and
  `systemctl --user daemon-reload` when someone is watching.
- **A rollback copy of the pre-deploy binary** is at
  `~/.local/bin/zclassic23-live.rollback-20260728-024526` (sha256
  `63c8206c92bc…`). `make ship`'s local path installs, restarts and verifies
  but does **not** roll back automatically — only the remote path does. Delete
  the copy once the current binary has proven itself.

## What shipped in the 2026-07-28 deploy

Everything below had been sitting committed-and-gated but undeployed — in one
case for eighteen hours while its absence was being misdiagnosed as a live
defect. It is now RUNNING. Kept as the record of what that deploy carried;
delete the table once it stops being useful history.

| Shipped 2026-07-28 | Where |
|---|---|
| Supervisor counts RESULTS, not activity: `progress_policy` (armed/exempt/undeclared) per child, `supervisor_progress_idle()`, `idle_ticks`, `child_headroom`. `SUPERVISOR_CAP` 64→128 (the registry was exactly full — the next subsystem to register would have run unsupervised) | `lib/util/{src,include/util}/supervisor.c,h`, `check-supervisor-progress-declared` |
| Per-index COVERAGE: `floor`, `coverage`, `catalog_index_emptiness_is_meaningful()`, `dumpstate catalog_coverage`. Answers "this index is empty — does that mean anything?" without a `COUNT(*)` (3.5 s on the live node) | `lib/storage/src/catalog_completeness.c`, `app/conditions/src/catalog_lag_exceeded.c` |
| Live-node freshness in `make agent-doctor`, plus a fix to a greedy JSON extraction that had been reporting a nested runtime value as the build's own identity | `tools/dev/agent-doctor.sh` |
| `check-doc-claims` — bind a prose claim to a machine predicate in an HTML comment; 52 bound claims across 135 docs. `check-doc-counts` widened from 4 tracked numbers to 8 | `tools/lint/check_doc_claims.sh` |
| The declared service contract (`zcl.service_binding.v1`): manifest, ZSLP token gate on the CORRECT ledger with as-of-height semantics, lifecycle state machine, `app.service.*` commands | `lib/kernel/src/service_binding.c`, `app/services/src/service_token_gate.c` |
| ZCODE slices 1–13 (signed release envelope, 10 GiB CAS store, publish/search, contributor identity + ZNAM pointers, declarative recipe, external verifier `zclassic23-package-verify`, scoring, simulated rewards/rankings/badges, ratio + anti-spam policy, `zpkgswm` swarm, `/zcode*` site). Slices 14–15 (real ZSLP transfers/badges) remain, owner-gated — full handoff in `docs/work/ZCODE_PLAN.md` §"Current state" | `lib/vcs/`, `config/commands/zcode.def`, `tools/package_verify.c`, `app/controllers/src/zcode_site_controller.c` |
| node.db lock-contention fix (catchup commit cadence, BEGIN IMMEDIATE, poisoned-COMMIT recovery, `node_db_catchup.abort_storm` blocker) | `5930d89fe` |
| Wallet plaintext-mirror elimination (single writer, STATE-G boot scrub to WKS1 envelopes) | `d027c034b` |
| op_return_backfill un-wedged on genesis's fake disk pos (fold zero rows when the body is unreadable; ~100k-line log loop ends on next deploy) | `57d6e6edc` |
| Terminal human-presentation layer (TTY-only; pipes stay byte-identical typed JSON; `ZCL_HUMAN` override) | `tools/command/cli_render.{c,h}` |
| Cost-tiered onion admission (STATIC/CHEAP/EXPENSIVE) + adaptive client puzzle; one admission primitive, the duplicate retired | `lib/net/src/onion_ratelimit.c`, `lib/net/src/puzzle.c` |
| Wallet mutating commands bound to the RPC engine (address new/import/export-key, transaction send, shielded send, rescan, backup-now) and address labels | `docs/API_REFERENCE.md` marks these `ready` |
| Groth16 comb-based verify speedup behind a differential parity oracle | `make check-groth16-parity`, `make bench-groth16-comb` |
| Sapling-tree rebuild seeded from the anchor_kv frontier (the healer for the blocker below) | merged earlier as `82f11c697` |
| Fault-injection and convergence proof harnesses; sync shadow observer; prune-after-seal safety gate; time authority | test groups + `lib/util/src/time_authority.c` |
| `lib/base` — the dependency sink (logging, allocation, the result type). `util/log_macros.h` and `util/result.h` forward to it, so the 733 includers are untouched | `lib/base/` |
| `config/` no longer reachable from `lib/`: the 14 upward symbol references (5 of them bare `extern`, invisible to the include-grep gate) replaced by boot-registered ports | `lib/net/src/net_runtime_port.c`, `lib/storage/src/node_db_runtime.c` |
| Per-file test headers: `test_core.h` + facets, so a node-header edit no longer dirties ~36% of the test build | `lib/test/include/test/` |
| Two ISA paths that had never compiled into a shipped binary — AVX-512 SHA3-512 (missing permutation + a 32-byte over-read) and SHA-NI SHA-256 (now runtime-dispatched with a known-answer self-test) | `lib/crypto/src/` |
| Boot refusals that fire before the log exists now report themselves; the doc they name is guaranteed to exist by `check-error-doc-refs` | `config/src/boot_error.c`, `tools/lint/check_error_doc_refs.sh` |
| **The vault** — one read model over all six asset classes (transparent, shielded, tokens, names, market offers, swaps), each row carrying an evidence grade. Funds locked in a swap HTLC are counted for the first time; `getbalance` still cannot see them | `app/services/src/vault_read.c`, `tools/command/native_vault_command.c`, `z23 vault list` |
| Wallet-wide sweeps for ZSLP balances, ZNAM names, and shielded notes — previously every one of these could only answer per-address | `app/services/src/`, bound into the vault read model |
| Three broken commands fixed, all one defect: a handler returned a bare JSON array or an in-memory-only field, and the command bridge dropped it. `app.swap.list` and the three wallet plan legs now return usable bodies | `swap_controller.c:970`, `wallet_native_handlers.c` |
| The `lib/` module set is declared once in `config/lib_module_order.def` and derived everywhere else — it had been copied into five places, and two of the cross-checks were vacuous | `Makefile:272`, `tools/lint/repo_shape.sh` |
| The code index reads the depfiles the build actually writes (it had been reading a stale flat directory), so the test skip-cache can key on a real include graph: **0 → 677 of 749 groups cacheable** | `lib/codeindex/src/codeindex_deps.c` |
| Compile-epoch re-key on toolchain+flags: a source edit now recompiles 2 TUs instead of 1199 | `Makefile`, `tools/dev/` (pushed `cf63879e8`) |
| Boot-liveness watchdog pump during block-index hydrate + LevelDB load (the long silent window that read as a stall) | `app/services/src/block_index_blocks_hydrate.c` (`2950a8111`) |
| Stale `.failed` bundle marker cleared once the bundle actually installs | `config/src/boot_auto_install_bundle.c` (`eb3e943d7`) |
| `op_return_index` names the snapshot-seed floor instead of a fake stall; `catalog_lag_exceeded` suppressed while the seed floor is the cause | `8181b9dee`, `3eb29dfed` |
| Wipe-to-tip Wedge A: genesis (nVersion=0) exempted from the contextual header-version gate; regression test | `app/jobs/src/validate_headers_validator.c` (`1aa370c7c`, `71f084afe`) |
| Plaintext wallet-key mirror deleted — one encryption-aware writer for the node.db key tables; boot-time WKS1 scrub of legacy plaintext rows, fail-loud | `lib/wallet/src/wallet_sqlite.c`, `app/models/src/wallet_key.c` (`d027c034b`) |
| Wipe-to-tip Wedge B: getheaders serve path falls back to the hash-bound node.db `blocks` row below the snapshot body floor (full Equihash solution); serve refusals no longer poison entries with `BLOCK_FAILED_VALID`; the successor walk advances instead of ending the reply | `lib/net/src/msg_headers.c`, port `storage/node_db_runtime.h` (`44bf0426f`) |
| ZCODE slice 1: signed package release envelope codec (703-byte bounded wire, frozen KAT, SPDX allowlist, low-S secp256k1) | `lib/vcs/package_release.*` (`fb37cc885`) |

In flight on branches/worktrees at push time (`main` at `fb37cc885`):
ZCODE slice 2 staging CAS (`work/zcode-slices`), the end-to-end web UX
design system (`zclassic23-ux`), and the node.db lock-contention fixes
(`zclassic23-dblock`). Program plans: `docs/work/ZCODE_PLAN.md`,
`docs/work/UX_PLAN.md`, `docs/work/NAT_AND_ONION_TRANSPORT.md`.

Deploy policy during the hold window is unchanged: a restart resets the 72h
trailing window, so deploy when the escalator fires anyway, or after
`HOLD_PROVEN`. Do not restart the canonical node for any other reason.

## Verify the cure

| Claim | Evidence file |
|---|---|
| Anchor-refold rebuild applied; revert path retired 2026-07-31 after a week at tip | `~/.local/state/zclassic23-cure/verdict.jsonl`. The pre-install and pre-promotion datadir copies it used to name are deleted — there is no rollback to a pre-refold state now, by decision, not by accident. |
| Tip-holding, externally confirmed | `~/.local/state/zclassic23-slo/uptime-ledger.jsonl` (`gap_vs_oracle`, `ts=`) |
| 72h hold accrual toward `HOLD_PROVEN` | `~/.local/state/zclassic23-slo/hold-ledger.jsonl`; judge: `tools/scripts/slo_hold_judge.sh`; recorder: `zclassic23-hold-certifier.timer` (`make install-hold-certifier`) |
| Peers, RSS, disk growth, Tor, standing blocker | `~/.local/state/zclassic23-slo/uptime-ledger.jsonl` — the same per-sample line now carries `peer_count`, `rss_kb`, `datadir_bytes`, `nrestarts`, `active_enter_ts`, `unit_active_state`, `onion_enabled`, `onion_address`, `blocker_count`, `blocker_primary` |
| EXTERNAL availability (not a loopback dial) | `~/.local/state/zclassic23-public-smoke/availability-ledger.jsonl`; collector `tools/scripts/public_explorer_smoke.sh`; unit `deploy/zclassic23-public-smoke.{service,timer}` |
| Operator interventions, declared and undeclared | `~/.local/state/zclassic23-intervention/intervention-ledger.jsonl`; detector `tools/scripts/intervention_ledger.sh`; declaration front door `tools/scripts/zcl_intervene.sh`; unit `deploy/zclassic23-intervention.{service,timer}` (`make install-intervention-ledger`) |
| Our tip HASH vs genuinely remote peers (off-host block identity) | `~/.local/state/zclassic23-parity/agreement-ledger.jsonl`; recorder `tools/scripts/tip_agreement_probe.sh`; judge `tools/scripts/tip_agreement_judge.sh`; unit `deploy/zclassic23-tip-agreement.{service,timer}` (`make install-tip-agreement`) |

### Reading the availability columns

`reachable` in the uptime ledger is a **loopback** RPC dial from the same
host as the node. It answers "the process is answering", never "a user can
reach the service" — the port forward, TLS, the certificate, the route, and
DNS are all downstream of it and always invisible to it. External
availability is the public-smoke ledger and only that.

`gap_vs_oracle` is a **height delta against the local sibling `zclassicd`**.
It is one network view from one box, and it compares numbers, not blocks:
nothing in the uptime ledger compares a block hash or a state root against
an off-host peer at any cadence. Do not read it as parity.

Block-hash comparison against genuinely remote peers is a **separate**
ledger — `~/.local/state/zclassic23-parity/agreement-ledger.jsonl`, written
by `tools/scripts/tip_agreement_probe.sh` and graded by
`tools/scripts/tip_agreement_judge.sh`. It compares our block hash at a
height against the hash reported there by at least two DISTINCT remote
hosts, and records `agrees` / `disagrees` / `could-not-ask` as three
different states. It does not make `gap_vs_oracle` mean more than it does,
and it is still only the FIRST rung: per-height tip hash, nothing about the
UTXO set root, shielded frontiers, or any state a header does not commit.

Read its verdict, never the raw rows: `make tip-agreement-status`. On this
host on 2026-07-29 that verdict was **`NO_EVIDENCE`** — see the standing
finding below.

**Read `clean_agrees`, not `agrees`.** A sample says `agrees` when our hash
matched the winning cluster at the height it compared. That is not the same
as "no remote host disagrees with us": the recorder also scans every OTHER
height in its window, and a sample is CLEAN only when no rival cluster
meeting the two-host control holds a different block than we do anywhere in
that window, and no height at or below our own tip went unchecked. The
judge grades `clean_agrees`; `contested` and `unverifiable` account for the
difference on the same line. A window whose samples all said `agrees` while
two remote hosts held another block at our tip grades **DISAGREE**, not
PASS — that case is `R12`/`J15` in
`tools/scripts/test_tip_agreement_evidence.sh`.

Two further properties of the judge are enforced rather than merely
documented: its knobs may only be moved in the TIGHTENING direction (a
loosening flag exits 2 at the front door), and the clean samples must span
at least `--min-span-secs` of wall clock, because counting six rows is not
measuring a day.

**Tor-only peer sets cannot satisfy this rung.** `net_addr_to_string`
renders every torv3 peer as the literal `[torv3]`, so all onion peers
collapse to one host key. That is the safe direction — many peers count as
one witness, never the reverse — but it means an onion-only peer set stays
at `could-not-ask` forever. Fixing that needs a per-peer identity in the
observation row, not a looser key in the recorder.

### The peer table only carries our own second server

Measured 2026-07-29, read-only, against the canonical node: inside a
15-minute window exactly **one** remote host was surfacing a learnable tip
hash at all, and it was the operator's own second server — on three
separate connections. A recorder counting distinct
`ip:port` would have called that three independent witnesses; the recorder
counts distinct HOSTS, so it is one, it is below the two-witness control,
and every sample records `could-not-ask`.

So the honest state today is: **off-host tip-hash agreement is not provable
on this host**, and the instrument now says so out loud instead of a number
that looks like parity. The fix is more peers surfacing tip hashes, never a
lower bar. `ZCL_PARITY_EXCLUDE_HOSTS` exists to discard operator-owned
peers explicitly; it can only make the gate harder.

### Zero-intervention claims

A claim that the node ran N days untouched is only checkable against
`~/.local/state/zclassic23-intervention/intervention-ledger.jsonl`:

```bash
tools/scripts/intervention_ledger.sh summary            # whole record
tools/scripts/intervention_ledger.sh summary <epoch>    # since a window start
```

The verdict line is explicit — `FALSE` when any detected change went
undeclared, `UNPROVEN` when the window has neither events nor heartbeats
(which means the detector may not have been running, not that nothing
happened), and otherwise "no unattributed change observed".

Anyone — human or agent — who restarts a unit, edits a drop-in, or replaces
a binary declares it first:

```bash
zcl-intervene "why"                     # declare
zcl-intervene "why" -- systemctl --user restart zclassic23   # declare + do
```

An undeclared change is recorded as `unattributed`, which is the whole
point: it is the line that contradicts the claim. Note that `NRestarts`
alone cannot support the claim — it counts automatic restarts only, a manual
`systemctl restart` RESETS it, and it is blind to a config edit or a binary
swap that does not restart the process.

## Open blockers

- **`sapling_tree_rebuild.fail_closed`** is a known-junk blocker, not
  corruption. When the legacy sapling-tree-checkpoint copy is discarded at
  boot for a root mismatch, the deferred rebuild replays from Sapling
  activation over bodies that do not exist below the cure anchor, so its
  first appended commitment is guaranteed to mismatch. The canonical
  incremental tree (`fold_sapling`, anchor_kv) independently verifies against
  every block header's `hashFinalSaplingRoot` and is healthy. Fix: seed the
  rebuild from the anchor_kv frontier instead of replaying from genesis, and
  reclassify skip-tainted mismatches as DEPENDENCY, not PERMANENT. Until
  fixed, this blocker keeps the escalator's empty-escape set non-empty.
- **Label-splice wedge class** — a NULL `block_hash` in a stale replay
  artifact can freeze H* during live operation, not only as wedge-era
  residue. The escalator's 600-block resnapshot refold self-cures it (crude,
  always-terminating). The merged in-place healer fixes the fault at the
  source; deploy it the next time this class fires.

## Open branches from the 2026-07-28 foundation round

Eleven agents across three workflows. Claims (3 lanes) and the services
CONTRACT (1 lane) are merged and gated; seven branches are not. All seven
forked from that session's start and need a reconcile pass — expect conflicts
in exactly three places every time: the test registry (now isolated in
`tools/dev/test_group_catalog.def`), `LINT_GATES` in the `Makefile`, and the
`<!-- DOC-COUNTS -->` block in `docs/CODEBASE_MAP.md`.

| Branch | What it is | Status |
|---|---|---|
| `lane/crypto-harness` | secp256k1 differential oracle (3 layers), a constant-time work-ratio check, an ECDSA fuzz harness + 46 seeds | **Unreviewed.** Author's own caveat, worth keeping: layer 1 is near-tautological because candidate and reference both bottom out in the vendored archive. Layers 2 (frozen transcript digest) and 3 (external ground truth: scalar 1 → published base point, n−1 → its negation, homomorphism) are the ones with teeth. |
| `lane/crypto-secp` | `lib/zsecp/` — our own field/group/scalar/ECDSA, ~1,800 lines | **Unreviewed, but verified SHADOWED.** Referenced only by the build-order file, a doc, and the code navigator. Touches nothing in `lib/crypto_registry`, `lib/keys`, `core/`, `vendor/`, `app/`, `config/src`. Every signature the node verifies still goes through the vendored archive. **Do not promote without full-history replay agreement.** | <!-- doc-path-ok: lib/zsecp/ exists only on the unmerged lane/crypto-secp branch -->
| `lane/crypto-speed` | The measured gaps: ed25519 windowing, the `blake2b_avx2` OS-register check, `fr_avx512`/`bn254_accel` overclaims | **Unreviewed.** |
| `lane/crypto-bignum` | Variable-width big integers (the missing primitive for later threshold work) | **Unreviewed.** |
| `lane/services-b` | The `notes` worked reference service | **BLOCKED — see below.** |
| `lane/services-c` | `check-service-contract` gate + isolation tests | **Blocked with b** (its gate is what found the blocker). |

### Why the services reference is blocked

`services-c`'s gate found three defects in `services-b`'s reference service.
Two are trivial (a missing `SERVICE-TEST:` marker; a service command calling
the BOOT-ceremony `node_db_open()`, which runs snapshot-staging DELETEs — use
`node_db_open_runtime()`). The third is architectural and is the reason both
branches are held back:

**The reference service's table is created in
`app/models/src/database_migrate_features_v30_up.c` — the central shared
migration.** So adding a service means editing core schema code, which is
exactly the property ("add a service without editing the core") the workflow
existed to establish. The contract, token gate and lifecycle are sound; the
state-ownership half is not demonstrated.

Fix direction: the service creates its own table from its own source, so
`table_is_own_state` in the gate can see a footprint it owns. Do **not**
weaken the gate's collision check to make this pass — that check is derived
from the real schema precisely because the previous hand-written
reserved-prefix list had already gone stale.

## Open branches — work that is finished but did not pass review

Four branches exist because an independent verifier ran the gates and found a
specific defect, not because they ran out of time. Each names what to fix.
Re-verify before trusting any of it; all four forked before the merges above
and need a reconcile pass.

| Branch | What it does | Why it is not in `main` |
|---|---|---|
| `perf/stable-objdir-and-gold-linker` | Stops relocating all 1883 objects on every edit; per-object attestation replaces the whole-tree key. **5x less CPU per edit, independently reproduced.** | Wall time got ~11% WORSE on a 32-core box — the wasted work was hiding in spare cores, and the new per-link verifier costs ~1s. Also: editing a per-object CFLAGS line in the Makefile changes no source file, so the toolkey does not move and a stale object survives — a real regression against the guarantee it replaces. And `check-build-epoch-integrity` can now report PASS while nothing ran (its cache key omits the two new scripts; copy-proven). **Goal achieved differently 2026-07-27 (item 2 below): toolchain+flags epoch key + `BUILD_SYSTEM_ID`, no per-object verifier; all three defects closed. This branch is superseded.** |
| `lane/testcache-soundness-phase0` | Fixes three live soundness bugs in the test skip-cache: `.def` files were absent from the key, the key bound the compiler but not the flags (an `-O1` pass was honoured by the `-O3` gate), and a fresh tree silently produced a header-free key. Toolkeys now differ per profile, proven by `strings` on the binaries. | One of its own new assertions passes on the unmodified code too, so it pins nothing. It also mutates `ZCL_STRESS_TESTS` without restoring it, which suppresses coverage in the sequential runner, and its Makefile-scanning helper reads only the first 256 KB of a 327 KB file. |
| `lane/module-linkgraph-enforcement` | Measures the module graph from the linker (`nm`), declares the rank order in a `config/lib_module_order.def` that exists only on that branch, and adds two gates. Also fixes a real bug: the code index skipped `epochs/`, which is where 100% of live depfiles are, so its include graph was empty. | `check-no-cross-layer-extern` false-fails on a clean tree whenever the only warm object tree is a test tree — proven end-to-end with no env override. The gate docstrings also claim a full `make` arms them; it does not (a full `make` produces zero `.o` files). | <!-- doc-path-ok: config/lib_module_order.def exists only on that unmerged branch -->
| `wf/measure` | Block-fold pipeline instrumentation. | Never reviewed: it wraps every stage, so it needs a deliberate overhead measurement before landing. Its profiling datadir copy (`~/.zclassic-c23-COPY-20260725-001046-fold-profile`, 17 GB) is intentionally left in place — delete it if this lane is abandoned. |

`archive/stash-refold-driver-wip` is older experimental work preserved from a
stash, not a live lane.

## Picked up next — known open items

Ordered by how much they cost the next person. Everything here was found with
evidence and left deliberately, not forgotten.

1. **`core.wallet.utxo.list`: the envelope defect is CLOSED; a different one
   was underneath it.** The `{schema, utxos, count}` wrapper landed in
   `wallet_native_read_bodies.c` and `test_command_registry_catalog.c` drives it
   through the registry on rendered bytes, so that instance of the bare-array
   class is done. The `TOOL_ERROR "RPC listunspent returned an unparseable
   body"` still seen afterwards was **not** that defect: `node_rpc_call`
   returned the *truncated* reply when its deadline fired mid-body (the node
   writes HTTP headers before its handler blocks), and every caller then
   complained about the body's shape instead of about a busy node. Fixed in
   `rpc_client.c` — a timed-out read that does not parse is now named as a
   timeout; pinned by `test_native_api_contract.c` against a real socket that
   sends only headers. This affected **every** native read body, not just this
   leaf.

   The 10 s latency on that command was a **third defect — CLEARED by the
   2026-07-27 05:36 process restart, root cause still unknown.** The previous
   process ran poisoned from ≥2026-07-24 09:00 until the restart: every
   catchup `COMMIT` failed *"cannot commit transaction - SQL statements in
   progress"* (`catchup: initial COMMIT failed — aborting`, 13k+ consecutive
   failures, every ~13–19 s) while other writers logged `database is locked`
   in bursts. Since the restart: zero recurrences, catchup completes 1-block
   passes, `getbalance`/`listunspent` answer in ~0.02 s (first call 3 s cold).

   What is established: that exact error string is emitted only from the
   `db->nVdbeWrite>0` COMMIT guard (`vendor/sqlite3.c:97501`) — i.e. a write <!-- doc-path-ok: vendored sqlite3 amalgamation exists on disk but is git-ignored -->
   VM (INSERT/UPDATE/DELETE, incl. `…RETURNING`) was left in `VDBE_RUN_STATE`
   on the shared node.db handle of the old process. It is **runtime-only
   state**: a fresh boot on a crash copy of the same datadir
   (`ZCL_DB_TXN_TRACE=1` probe, 170 s, isolated ports) showed zero busy
   statements and a clean catchup; the poison is not in the datadir. A
   100 %-persistent RUN write VM points to a thread parked mid-`sqlite3_step`
   (or abandoned between step and reset) on the main handle — not found by
   static audit; the only `RETURNING` writer (`db_app_event_save`,
   `app/models/src/app_event.c:206`) finalizes correctly.

   If it recurs on the CURRENT live binary: the process is poisoned until
   restart, and **`ZCL_DB_TXN_TRACE=1` names the culprit** — a RUN write VM forces
   `txn_state=WRITE`, so the tracer's busy-stmt walk fires every 3 s and logs
   the exact SQL (`lib/util/src/db_txn_trace.c`). Enable it at the next
   owner-gated deploy. On branch `work/db-lock-fixes` (committed there, NOT
   on the live binary) the always-on seatbelt lands instead: a COMMIT
   failing with this exact error class walks the handle's
   `sqlite3_next_stmt` list, logs the offending SQL, and resets the
   abandoned VM, so the caller's ROLLBACK and the next BEGIN/COMMIT work
   without a process restart (`node_db_commit`,
   `app/models/src/database.c`). The same branch caps the catchup batch at
   2000 blocks / 5 s per COMMIT (was one 100k-block transaction holding
   the WAL write lock for minutes), opens every catchup transaction with
   BEGIN IMMEDIATE, restarts a `SQLITE_BUSY_SNAPSHOT` pass with a bound of
   3 whole-walk retries, and parks the catchup worker behind the named
   blocker `node_db_catchup.abort_storm` after 8 consecutive aborts
   instead of re-running forever. The reset unpoisons the handle but does
   not find the bug that abandoned the VM — the recovery's logged SQL (or
   `ZCL_DB_TXN_TRACE=1`) still names it. **Live gdb is unblocked (2026-07-27):** commit
   `f191bbf9c` was rebuilt byte-identical in
   `~/github/zclassic23-dbg-f191bbf9c` (sha256
   `63c8206c…df70d49d`, build-id match) and the matching
   `zclassic23.debug` (CRC `0x5b202eb1`, verified against the live binary's
   `.gnu_debuglink`) is installed at `~/.local/bin/zclassic23.debug` —
   `gdb -p <live-pid>` now resolves full DWARF. Repro note for future
   two-builder proofs: `make worktree-prime` copies `vendor/lib` but NOT
   `vendor/include`; the 135 generated OpenSSL headers + `zconf.h`/`zlib.h`
   must be copied too or `source-identity.sh` mints a different
   `ZCL_BUILD_SOURCE_ID` (84-byte binary diff). Live binary facts: real Tor
   (`vendor/tor` @ `b65701fe`), no `ZCL_WITH_RUST`, GCC 15.2.1.
2. **DONE 2026-07-27 — the compile epoch is re-keyed on toolchain+flags; incremental rebuilds are incremental again.** `zcl_compile_epoch` (`Makefile`, `define zcl_compile_epoch`) no longer binds the whole-tree source id/mutation. The epoch key is now: compiler/toolchain fingerprint + profile name + effective compile flags + effective link flags + `BUILD_SYSTEM_ID` (new `build-epoch-key.sh build-system-id` mode: the root Makefile — every flag variable and per-object override — plus the four epoch driver scripts). A source edit recompiles only make's stale TUs in the STABLE epoch; a Makefile/flags/toolchain edit busts every epoch. Identity freshness is unchanged: every profile's `clientversion.o` depends on `$(BUILD_IDENTITY_STAMP)`, so a source-identity move rebuilds it and relinks every binary (proven: after a one-line edit the dev binary's baked `ZCL_BUILD_SOURCE_ID` updates in the stable epoch dir). Measured (`docs/BENCHMARKS_LOG.md` 2026-07-27): one-line `.c` edit 1199→2 compile invocations, header edit 1199→4, ~35s→~7s CPU per edit; wall ~7s→~6.3s (the floor is parse-time source capture, not compilation). The three defects that sank `perf/stable-objdir-and-gold-linker` are closed: per-object CFLAGS edits move `BUILD_SYSTEM_ID` (proven: dev epoch re-keys, all 1207 dev TUs scheduled); the `check-build-epoch-integrity` cache key now includes the cache driver itself plus every script the probes read (proven: editing an input forces a real ~12.7s rerun, no stale PASS); no per-object verifier was added — the win is make's normal timestamp+depfile incrementality. Known residual vs the old design: the ABA quarantine-by-namespace is gone (a compile racing an edit in the same seconds window can leave a newer-than-source object; publish-time verify-record still refuses the binary). `build-epoch-selftest.sh` was rewritten for the new semantics (stable namespace across A→B→A, all five key inputs bound, retired 7-arg derivation fail-closed, source-bound publish preserved).
3. **A passing test can still be hollow.** The wallet plan bug survived because
   its test asserted on the in-memory reply struct, which was correct, while
   the serializer that the caller actually reads never emitted the field. The
   rewritten test (`lib/test/src/test_native_api_contract.c`) executes through
   `zcl_command_registry_execute_json` and asserts on rendered bytes. Any new
   command test should do the same. **Sibling sweep DONE 2026-07-27:** all 9
   other test files that call `zcl_native_handle_*` directly were checked.
   The architecture limits the blast radius — `serialize_reply`
   (`lib/kernel/src/command_registry.c:1625`) copies `reply.data` wholesale,
   so a per-field drop like the wallet bug is impossible by construction;
   what a never-rendering test CANNOT see is whole-envelope failure
   (`write_bounded_json` budget overflow, `next`-array self-name rejection —
   the actual shipped bug). Narrow hole (never renders):
   `test_offline_datadir_query.c` (top rewrite candidate — rows payload can
   realistically exceed `ZCL_COMMAND_RESULT_BUDGET` → production
   `EXECUTE_FAILED` while the test stays green), `test_code_capsule.c`
   (largest payloads), `test_operator_ux.c` (5 success paths, zero
   rendering), `test_code_impact.c` (minor — already budget-fit renders),
   `test_vault_session.c` / `test_vault_dispatch.c` (low value — asserted
   fields live in generically-serialized portions). Already render-through:
   `test_code_merkle.c`, `test_code_emitter.c`. False alarm:
   `test_rom_fetch.c` (error-only paths; `push_error` is generic).
4. **RESOLVED 2026-07-27 — the `MISSING_ADDRESS` ERROR line is the handler's
   own error-path logging, working as designed.** `test_native_api_contract`
   step 5 deliberately drives `zcl_native_handle_wallet_transaction_send`
   with an empty input object (`test_native_api_contract.c:911-924`) to
   prove the missing-key path fails closed; the handler's `wnh_fail`
   (`app/controllers/src/wallet_native_handlers.c:183`) calls
   `LOG_ERROR(WNH_TAG, "%s: %s (%s)", code, …)` on *every* failure —
   including this intentional one. The pre-rewrite test asserted on an
   in-memory struct without executing the real handler, so it never
   triggered the log. One ERROR line per negative test of an error path is
   the defensive-coding contract doing its job, not a defect. (If the noise
   ever bothers anyone, the fix would be a client-input-vs-internal
   severity split in `wnh_fail` — a style decision, not a bug.)
5. **ZNAM and market write verbs are unrouted.** They are registered `PLANNED`
   with NULL handlers, so the vault can report those classes but cannot act on
   them. The market class is additionally the one vault row graded
   `heuristic_payment_address_match`, because `file_offers` carries no
   ownership marker at all — that column has to exist before the row can be
   exact.
6. **The package library (P1) is not started.** The design is written and
   decided: `docs/P2P_SOURCE_HOSTING.md` items 3–12, plus a publish-time SPDX
   allowlist gate. Two of twelve pieces exist and are tested
   (`lib/vcs/package_manifest.*`, `lib/vcs/package_swarm.*`); the codec has
   never been given a socket. Owner decisions on record: hash-only package
   identity, license enforced mechanically at publish, free distribution by
   default.
7. **The ontology work is paused mid-design**, at `ba4ded785` + `0343defc3`
   (`config/onto/extractors.def` + `tools/lint/onto_shape.sh` are landed and
   green). Three lane designs were returned and saved under
   `~/.claude/plans/`; worktrees `zclassic23-onto-{a,b,c}` exist with no
   commits. Nothing depends on it.
8. **Boot crash-loop on corrupt block-index flat file — root-caused, fix
   landed (ungated, uncommitted).** Evidence: 2026-07-27 04:19 the poisoned
   2d13h process (item 1) was cleanly stopped; every boot for the next hour
   then died to the 2-min systemd watchdog (8 SIGABRTs in `crash_log.txt`,
   each a fresh PID in `main`→`sleep`). Mechanism: the flat file's tip hash
   mapped to height −1 vs the SQLite store
   (`Block index flat: tip hash maps to wrong height (-1 vs SQLite …)`), so
   `rung_taint_load` (`config/src/boot_blkidx_ladder.c:115`) dropped `loaded`
   and set `flat_union_tainted`, forcing the multi-minute blocks-table
   hydrate / LevelDB reload — which pumped NO boot-liveness marker, so the
   watchdog killed the boot at 2 min; the deliberate "healed map persisted
   only at shutdown" guard then re-infected the next boot, sustaining the
   loop until a warm-page-cache boot finally finished in time (~05:34, the
   current healthy process). Fix: `boot_progress_note()` every 4096 rows in
   the hydrate validate/insert/link passes
   (`app/services/src/block_index_blocks_hydrate.c`) and in the LevelDB guts
   walk (`lib/storage/src/block_index_db.c`) — the same primitive the flat
   loader already pumps. The taint guard itself is untouched (persisting
   the union mid-boot would launder the poison record). Regression test:
   `test_block_index_loader.c` §15b asserts >4096 hydrate rows advance
   `boot_progress_marker()`; a `test_chain.c` sibling asserts the same for
   the LevelDB guts walk. Remaining: full
   `make lint && make test-parallel` gate, then owner-gated deploy. If the
   loop ever recurs pre-deploy, the escape is what happened on its own:
   repeat boots until one completes inside the window.

9. **C6 soak can never accrue on the current datadir — the blocker chain is
   structural, not a flag to clear.** Diagnosed read-only 2026-07-27.
   `mvp_gate.sh` hard-gates soak accrual on `security_posture_ok`
   (`tools/mvp_gate.sh:339`): `review_required` → `NOT_MET` regardless of
   uptime. The live posture is `review_required_bootstrap_trust` with
   `next_action=finish_sovereign_refold_and_full_history_validation`
   (`app/controllers/src/agent_security_posture.c:338`), i.e.
   `trusted_state_present || !full_history_validation_complete`. Live
   evidence (`dumpstate chain_evidence_controller`): `snapshot_anchor=-1`,
   `snapshot_evidence.source_class="unknown"`, every verify flag false;
   `dumpstate bg_validation`: `verified_height=-1`, idle, zero sigs/proofs.
   Root cause: the datadir is snapshot-seeded
   (`reducer_trusted_base_height=3195552` in `operatorsnapshot`) — block
   bodies below the seed floor were never downloaded, so genesis-to-tip
   full-history validation is impossible *on this datadir*, which is also
   why the `address_index.below_snapshot_seed` / `txindex` blockers are
   permanent there ("backfill cannot fold at height 0 … no source"). The
   only clearing path is the sovereign cure itself (self-verified-tip-plan:
   fold real bodies from genesis/anchor → CEC `FULLY_VALIDATED` with origin
   `GENESIS_HISTORY` → `trusted_state_present` flips false). Consequences:
   (a) C6's 168h clock has not started and cannot start pre-cure — do not
   read uptime as soak progress; (b) the cure must run copy-proven on a
   datadir copy per the runbook, then the soak window restarts on the
   post-cure datadir; (c) any "just clear the flag" change is a
   gate-weakening — refuse it.
10. **First genuine wipe→tip stopwatch run: STALLED-NAMED at h=0 for the
    full 606s (2026-07-27).** `make mvp-coldstart-to-tip-stopwatch` (empty
    `/tmp` datadir, isolated `$HOME`, `-nolegacyimport`, no bundle/snapshot
    flags, one synced peer) never made progress: H\*=0 against
    network_tip=3195667 in every sample; exit 4. Artifact:
    `build/c3-stopwatch/20260727T080317Z-3413759/`. Named blockers:
    `bootstrap.no_state_source` ("the node is doing full from-genesis IBD"
    — but it didn't), `proof_validate.stale_upstream_hash` (fired 312×:
    holds until script_validate publishes a receipt for the selected
    branch), `sync_rate_below_floor`, and two sticky-escalator rows.
    **DIAGNOSED 2026-07-27 — two independent wedges, either alone pins
    H\*=0 forever (both confirmed in code AND artifacts):**
    **Wedge A (reducer-side):** the synthetic genesis `block_index` entry
    is inserted with `nVersion=0` (never populated,
    `app/services/src/block_index_loader.c:783-793`), so
    `validate_headers_default_validator` terminal-fails height 0
    (`version-too-low`, `validate_headers_validator.c:479-483`;
    `stage-validate_headers.json`: `failed_total=1 first_failed_height=0`).
    `body_fetch` skips h0, `script_validate` publishes `upstream_failed`,
    and `proof_validate` dead-waits on a receipt that can never exist —
    the `stale_upstream_hash` ×312. Fires even with a perfect network.
    Fix: populate the real genesis header fields (the real ZCL genesis IS
    v4 — the live node.db `blocks` row confirms version=4 at h=0), or
    exempt the genesis hash from the version gate (mirroring existing
    exemptions in `check_block.c:301`, `accept_block_header.c:221,319`).
    **Wedge B (network-side, hits every snapshot-seeded SERVER):** the
    hydrated in-memory index carries no Equihash `nSolution`
    (`block_index_blocks_hydrate.c:441-478`), so
    `headers_index_header_servable` (`lib/net/src/msg_headers.c:304-342`)
    builds a header with `nSolutionSize=0` → `invalid-solution` → refuse;
    the node.db `blocks` row HAS the full 1344-byte solution but the serve
    path never consults it. Confirmed in the LIVE peer's own log at
    08:03:26Z: `getheaders: refusing to serve header 0004b371… h=1
    reason=invalid-solution`. Companions: the successor walk re-queries
    the same failed h=1 entry 64× → 0-header reply
    (`msg_headers.c:344-365`), and `msg_headers.c:334-335` sets
    `BLOCK_FAILED_VALID` for what is a data-AVAILABILITY failure (watch
    the persisted-FAILED reconcile on the live peer's next flat-cache
    save). Fix: node.db-blocks fallback in the serve path (pattern:
    `header_from_node_db_block`), no FAILED_VALID for availability, and a
    successor walk that actually advances. The getheaders LOCATOR was NOT
    the bug — `peer_start_h=3195667` is only the peer's advertised
    starting_height for interval math; the wire locator was genesis
    (`msg_headers.c:1213`). The `catchup: final commit missing tip hash`
    loop is a downstream symptom (zero indexed blocks → NULL
    last_indexed_tip), not a cause. **Measurement trap that
    cost one wrong read:** `z23 dumpstate` IGNORES the
    `ZCL_DATADIR`/`ZCL_RPCPORT` env vars — a probe aimed at the stopwatch
    node silently read the live node instead (reported H\*=tip, the live
    node's value). Aim dumpstate probes with explicit flags, or read the
    harness's own samples. The working form (verified against the live
    node): `zclassic23 -datadir=DIR -rpcport=PORT dumpstate <sub>` — the
    RPC cookie is per-datadir, so BOTH flags are needed; env vars only
    affect the separate `zcl-rpc` binary.
    **RESOLVED 2026-07-27 — re-run PASS, 402s wiped-datadir-to-tip.**
    Same harness, same machine, peer=`zclassicd` behind the harness relay
    (`tools/scripts/c3_stopwatch_run_and_record.sh --peer=127.0.0.1:8034
    --budget=1800`, run dir `build/c3-stopwatch/20260727T102606Z-2420093/`,
    verdict pass, exit 0): wiped datadir reached network_tip=3195777 in
    402s wall across 2 boots (one self-respawn by the tip watchdog),
    provable sample to tip, readback clean. Path taken: bundle candidate
    discovered from the peer (h=3056758), installed, projections folded,
    then ~139k bodies ingested from zclassicd at ~800 blk/s. Wedge A
    (genesis exemption) + Wedge B (getheaders node.db fallback) are what
    moved this from STALLED-NAMED h=0 to PASS. Residual observed, not
    blocking: near-tip the node adopted a short fork header branch,
    briefly flipped at_tip→connecting, got 35 `notfound` replies for
    fork-only hashes (neither byte order exists in the live node's
    `blocks` table — verified via `core storage query`), and recovered
    without operator input; one `no-header-solution-backfill-required`
    on-demand validate refusal at the bundle checkpoint h=3056758 fired
    during boot 1 and cleared on the watchdog respawn.
11. **DONE 2026-07-27 — stale `.failed` bundle markers now cleared on
    successful install.** Found in the canonical datadir: a watchdog-killed
    boot (the item-8 crash-loop morning) marked
    `bundles/consensus-state-bundle-3056758.sqlite.failed` at 04:28; a later
    boot installed the bundle successfully (05:37), but nothing cleared the
    marker — and `boot_autodetect_consensus_bundle` skips marked bundles by
    design, so every future autodetect scan (e.g. on a copy-prove datadir
    copy, the recovery doctrine) would silently ignore the GOOD bundle. Fix:
    `boot_auto_install_clear_failed_marker()` (new, exported per the
    `boot_post_install_fold_span_check` testability precedent,
    `config/src/boot_auto_install_bundle.c`) called at both install-success
    branches (autodetect + install-on-next-boot request). Regression test:
    `case_failed_marker_cleared_on_success` in
    `test_consensus_state_install_runtime.c` (marked → skipped, cleared →
    detectable, idempotent/NULL-safe). The live datadir's stale marker can
    be removed by hand at the next owner-gated maintenance window
    (`rm ~/.zclassic-c23/bundles/*.failed` — the bundle beside it is the
    good 05:37 install).
12. **`catalog.op_return_index.lag_exceeded` on the live node is the item-9
    structural class wearing a misleading name.** The blocker says "cursor
    frozen at -1 … backfill service is stalled and must resume" (87 fires,
    age ~2.8h), but the mechanism is the same snapshot-seed floor as
    `address_index.below_snapshot_seed` / `txindex.below_snapshot_seed`:
    `op_return_backfill_run_once` (`app/services/src/
    op_return_backfill_service.c:123`) walks from cursor+1=0 and dies on the
    first height — `active_chain_at(0)` has no `BLOCK_HAVE_DATA` because
    bodies below 3195552 were never downloaded. It can NEVER resume on this
    datadir. Two honest options, not yet picked: (a) teach the backfill to
    start at `reducer_trusted_base_height` on seeded datadirs — but the
    index folds a running digest from genesis, so a mid-chain start
    diverges from any from-genesis peer's digest (the fold is
    order-committed; see the oversize-block comment at
    op_return_backfill_service.c:150-155) — the digest contract must be
    amended deliberately, not hacked; (b) give op_return_index the same
    `below_snapshot_seed` typed blocker the other two indexes have, so the
    live blocker board stops claiming a resumable stall. Until the
    sovereign cure lands, (b) is the truth-preserving move.

Standing pattern behind items 1, 5, and much of the above: **when one fact has
two writable copies, fix it by deleting a copy, never by adding a
reconciliation guard.** Five instances were found this session; four were real
and were collapsed. The fifth (`zslp_balances`) looks exactly like the disease
and is not — it is load-bearing, and `docs/AGENT_TRAPS.md` now says so. Read
that entry before deleting anything that looks obviously dead.

## Where the developer loop actually spends its time

Measured, recorded in [`BENCHMARKS_LOG.md`](BENCHMARKS_LOG.md). Read that before
optimising anything here — two confident hypotheses died against these numbers.

- The bare link over 1883 objects is **0.90s** (`ld.bfd`) / **0.58s** (`ld.gold`).
  It is not the bottleneck, despite `ZCL_DEV_LINKER` resolving to empty on this
  host and the gating lane never referencing it. Both true, both worth ~0.3s.
- ~~The one-file rebuild cost is the compile-epoch churn~~ **FIXED 2026-07-27**
  (item 2 above): the epoch no longer re-keys on source edits, so one edit
  recompiles only the stale TUs. The remaining per-edit wall floor is the
  parse-time source-identity capture + session acquire (~6s), not compilation.
- The remaining large lever is the ~36% of test objects that a node-header edit
  used to dirty; the header split took a real edit from 680 recompiles to 9.

## MVP status

MRS and per-criterion evidence live in [`docs/MVP.md`](MVP.md) and
`z23 milestone` (REST `GET /api/v1/milestone`). Only a run-passing
`make mvp-verify` member moves a ◐ to a ✅ — never hand-bump the count.

## Operational notes

- `-import-complete-shielded` requires the source chainstate's best block to
  equal exactly the target coins-island root — a bind guard, not a bug.
- A `-bootstrapserve` zclassicd pins its on-disk chainstate at the serve
  anchor.
- `chainstate_legacy_reader` reads LevelDB SSTs only; it does not replay a
  non-empty WAL. A non-empty WAL must refuse loudly rather than silently
  drop data.
- `zclassicd invalidateblock` does not persist across restarts in this fork.
- Watchdog-pet starvation under build load (observed 2026-08-02/03, four
  kills in ~2h): every kill had the same signature — SIGABRT exactly 10min
  after service start, while a `-j32` build ran on the host. The node pets
  through boot, then loses the pet race under build load and never re-arms;
  it self-heals on the next quiet window. Dev-lane rule: check
  `systemctl --user is-active zclassic23` before any full build; if
  `activating`, wait or drop to `-j16`; never restart or stop the service
  from a dev lane. The pet starvation itself is open for the node's owning
  lane — it recurs on every heavy push.

## Lanes

| Lane | Datadir | Deploy | Purpose |
|---|---|---|---|
| **live** | `$HOME/.zclassic-c23` | `make deploy` (owner-gated) | Public daily-driver node; restart only for a vetted live deploy. |
| **dev** | `$HOME/.zclassic-c23-dev` | verify/probe only | Isolated build/test lane; public tooling cannot restart or publish to it. |
| **soak** | `$HOME/.zclassic-c23-soak` | deliberate re-baseline | Long-uptime / weekly evidence lane; do not churn during development. |

`z23 agentlanes` / REST `/api/v1/agent` report each lane's
`operator_lane` (`zcl.operator_lane.v1`) and restart policy; prefer that
contract over parsing systemd names. The units declare the same intent with
`-operator-lane=canonical|dev|soak`. `zclassicd` (the C++ reference) runs
co-located — never stop it.

`make deploy-dev`, `make deploy-dev-fast`, and `make agent-deploy-fast` are
Phase-0 contained: every public invocation refuses before service, datadir, or
generation mutation. Build, source verification, simulation, and hermetic
fixture probes stay available.

`make lane-health` is the read-only three-lane status check. It reports systemd
state, RPC reachability, listener state, height, lag from the live lane, peer
count, restart count, memory pressure, role readiness, soak-evidence
eligibility, any `-reindex-chainstate` flag, and the binary-owned
`bootstrapstatus.snapshot_loader` posture (snapshot seed height, active loader
path, `recovery_hint`). `role_ready` answers whether a lane serves its assigned
purpose; the dev lane is not role-ready when its lag exceeds the lane
threshold, even with RPC and listeners up. `soak_eligible=false` means the soak
lane is alive but not earning clean MVP-C6 evidence. It is an observability
check, not automatic failover.

`make lane-recover LANE=dev|soak` is a read-only bounded recovery planner
emitting `zcl.lane_recovery_plan.v1`. Public `--apply` and
`ZCL_LANE_RECOVERY_APPLY=1` refuse before any mutation; `live`, `canonical`,
and `main` are refused outright. Use it after `make lane-health` reports a
recovery hint — it is a planner, never an apply path.

Copy-prove every recovery path on a datadir COPY before live; never live
surgery. Gate on **H\* CLIMB**, never "booted without FATAL." Never weaken a
safety/operator gate. Gate every change with
`tools/scripts/gate-and-report.sh <lintlog> <testlog>` (lint → full link build
→ `test-parallel`, keyed on the `SUITE VERDICT … groups_ran=N groups_failed=N`
line and rejecting a cached run) — not the pipe exit, and not a bare
`grep "ALL TESTS PASSED"`, which also matches `ALL TESTS PASSED (CACHED)`.
Replay any consensus-predicate tightening against real chain history first —
see `docs/CONSENSUS_PARITY_DOCTRINE.md`.

## Pointers

- [`docs/work/FORWARD_PLAN.md`](work/FORWARD_PLAN.md) — the ordered plan.
- [`docs/work/self-verified-tip-plan.md`](work/self-verified-tip-plan.md) — the sovereign-cure design.
- [`docs/work/sovereign-cutover-runbook.md`](work/sovereign-cutover-runbook.md) — owner-gated cutover + revert.
- [`docs/AGENT_TRAPS.md`](AGENT_TRAPS.md) — read before "fixing" anything.
- [`docs/MVP.md`](MVP.md) — the v1 acceptance bar (8 criteria).
- [`docs/FRAMEWORK.md`](FRAMEWORK.md) — canonical architecture reference (§9 is the open-item debt board), off the v1 path.

A map, not the territory: trust the code you read this minute over this
file.
