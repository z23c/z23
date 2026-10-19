<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# MCP workhorse qualification

Observed 2026-10-13. Source base:
`3afa0150d973b7b872540fe9a23a3013c77e9b86`.
This records client connection, source changes and fixtures, not deployment.

## Qualified behavior

- Codex CLI 0.162.1 authenticated to the existing HTTPS gateway using the
  owner-approved OAuth mechanism. Credentials remained client-owned.
- Its temporary app-server client discovered three deployed tools and called
  `steer_brief` with `isError=false`, without model inference. The client was
  stopped afterward. No gateway, service or public listener was added.
- The brief returned 25,234 text bytes with `limit=1`: that parameter bounds
  changes, not the whole snapshot. Compact JSON selection must retain
  freshness, completeness and refusal indicators.
- The source change advertises the existing native `seq`/`attempt`
  selectors, including type, pairing and bounds. It changes no authority.
- The final registered gateway base group, six gateway shards and fleet_steer
  all passed: eight executed groups, zero failures/skips, 38,542 ms test-body
  wall time. All 36 lint-fast gates passed. Independent source review accepted
  the final gateway, fixture and README.
- Thirty pre-reset Linux, Mac and laptop seats were retired in place. Their
  controller/recovery fields and receipts remain. The coordinator then reported
  zero configured seats, not thirty idle workers. This says nothing about
  physical fleet size or independently running sessions.
- The shared workhorse wiki update was read back from a second host.

Final source SHA256:

| File | SHA256 |
|---|---|
| tools/fleet_gateway.c | 3f268986995d66b64604817e1d43adcc03796f872a71dba3af5c4036d91cbdce |
| tests/harness/src/test_fleet_gateway.c | d80c352f5fa743b7c779d1e5039d96c5cf1c0bd691b150146da129aa8768b57d |
| platform/deploy/fleet-gateway/README.md | 6d0a572bffeb1eb9788d7bd875ddb0fe4d69480f2690ede0b8e33a6211f11e21 |

Private logs, patch, hashes and receipts are retained in the operator's
`mcp-workhorse-20261013` evidence directory. Roster recovery is retained in
`mcp-roster-20261013`. Neither directory is an additional task authority.

## Workhorse observations

The initial remote subscription turn's native context confirmed
`gpt-6.1-sol` and low effort. It produced the schema and regression tests.
It made 30 shell reads returning 217,049 bytes. Five exceeded 15 KiB.
Reported cumulative usage was 2,031,637 input tokens, 1,946,240 cached input
and 8,792 output. This is not API-dollar cost or complete accepted-task cost.

Lint rejected the new test's complexity: 22 against a limit of 15. The
threshold and baseline were preserved. A resume without explicit model
selection used the host default Astra model; native context exposed the
mismatch. That turn was interrupted after it split the test. An explicitly
pinned Sol low resume inspected and retained the split. Final cumulative
session counters were 2,536,050 input, 2,341,504 cached input and 10,156 output.
Do not add cumulative totals together. This is mixed-model repair evidence;
per-model repair attribution and complete workflow cost remain unknown.

The worker sandbox made Git metadata read-only. Coordinator-owned claims and
upstream verification remained necessary. One initial test selector was
refused before compilation; another build correctly refused after docs changed
during compilation. All failures remain in the evidence, outside acceptance.

## Next measured improvements and limits

Supply exact symbol excerpts, validator and fixture references, prepared
claims and explicit sandbox responsibilities. Target 4 KiB source reads.
Do not repeat metadata operations after a read-only refusal. Pin and verify
model/effort on every start and resume. Freeze source and docs before builds.
Compare complete accepted-task cost including failures, repair, review and
machines; one trial cannot establish optimality or population reliability.

Fresh controller discovery/admission across the fleet remains unqualified.
Historical seat files must not be revived as current capacity. Exact-selector
gateway deployment remains owner-gated; the production gateway is unchanged.
Live send/evidence task round trips and fleet-wide worker execution were not
qualified by this fixture run.

## Authenticated wiki discovery acceptance

On 2026-10-13, primary Linux checkout source based on
3afa0150d973b7b872540fe9a23a3013c77e9b86 passed the focused acceptance for
authenticated wiki discovery through the existing gateway and native service.

The added MCP tool is wiki_find, mapped only to fleet.steer.wiki-find.
It requires the evidence grant scope and a nonempty query of 1 to 128 UTF-8
bytes. Discovery reuses fleet.wiki.find and returns exact revision IDs,
publishers and signed timestamps under its existing 16 KiB search-payload
budget. Additional steer and MCP envelopes are outside that payload budget.
The caller reads the pinned revision through steer_evidence with type=board
and ref=id. Latest-held selection does not establish globally latest knowledge;
wiki content remains unverified and grants no operating authority.

All commands ran through devbuild --wait, with 28 jobs for focused tests:

| Acceptance | Result | Runner wall time |
| --- | --- | --- |
| fleet_gateway | PASS, partition check only | 0.0 s |
| fleet_gateway_shard_01 | PASS | 1.9 s |
| fleet_gateway_shard_02 | PASS | 0.6 s |
| fleet_gateway_shard_03 | PASS | 0.3 s |
| fleet_gateway_shard_04 | PASS | 0.5 s |
| fleet_gateway_shard_05 | PASS | 0.4 s |
| fleet_gateway_shard_06 | PASS | 0.7 s |
| fleet_board | PASS | 23.4 s |
| fleet_steer | PASS | 7.8 s |
| lint-fast | PASS | Not separately measured |

Each focused behavioral run selected one registered group, with zero failed,
cached, skipped or environment-unobserved groups. The gateway partition check
covers 28 sub-suites across six shards; the partition check alone is not
behavioral acceptance.

The gateway fixtures exercise missing credentials, wrong scope, revocation,
missing/wrong-type/unknown-field query inputs, a valid 128-byte query, and
129-byte ASCII and 130-byte multibyte refusals. Their private datadir has no
RPC cookie, so an authorized valid query reports WIKI_UNAVAILABLE rather than
an invented empty result. The fleet_board fixture separately executes the
native wrapper through the existing in-process RPC test hook, compares exact
signed discovery metadata, fetches that revision through steer evidence,
and checks that the reads add no database mutations.

The first gateway shard run failed two new assertions: missing q produces
handler BAD_INPUT, and the existing native normalizer rejects an empty string.
The final contract is explicitly nonempty; no normalization or grant refusal
was weakened. The first lint run refused stale generated capability inventory.
Canonical docs-api-reference and docs-capability-inventory regeneration
completed before the final lint pass. Failed-run evidence is retained.

Known limit: db_fleet_board_wiki_list currently returns zero for both an empty
store and some storage failures, including statement preparation failure.
This slice preserves that preexisting ambiguity; successful empty discovery
does not qualify storage-error detection. No deployment, live gateway refresh,
peer replication or production wiki mutation was performed.

Qualification logs, status records, before copies, source hashes and the final
patch are retained on z23-r2 under
~/.local/state/storage-plan/2026-10-12-fleet/mcp-wiki-20261013/.
The effective worker model and reasoning effort were not exposed to this
worker and remain UNKNOWN.

## Mixed backend capability and release-gate repair

A running wiki RPC returned matching entries without exact revision IDs,
publisher keys or signed timestamps. The earlier native fixture used a matching
in-process backend and did not qualify this mixed-capability deployment case.
Source acceptance therefore did not establish live wiki discovery readiness.

The wrapper now requires identity_schema equal to zcl.fleet_wiki_revision.v1,
a bounded entries array, canonical 32-byte lowercase hexadecimal revision and
publisher identities, and integer creation/expiration timestamps in order.
Missing capability, including an old backend returning an empty array, yields
WIKI_CAPABILITY_UNAVAILABLE before discovery or exact_read is advertised.
The existing server emits the marker. No latest-by-slug enrichment or second
wiki projection was introduced. The largest fixed search envelope measures
116 bytes within its existing 192-byte reserve.

The fresh source passed fleet_board, fleet_gateway_shard_01 and fleet_steer,
plus the warning-suppression, rebuild-ownership, stray-source, flag-registry and
lint-wiring runtime selftests. Admission/build/test phase wall times were
85 s, 59 s and 12 s for the three groups, respectively; these include work
outside the test body and are not application benchmarks.

The final full lint run completed 219 gates: 217 passed and two rejected the
obsolete gate remaining in the maintained documentation inventory. Removing
that exact inventory row and its obsolete explanation then passed both
check-lint-gate-wiring and check-doc-accuracy. Every retained gate has a
passing observation; this is not a claim that the final documentation ran
through one complete post-repair lint invocation. Clean release qualification
remains required before deployment.

The removed gate banned the acronym MCP in all tracked paths and text.
It had no list of actual retired interfaces; its negative witnesses were
synthetic acronym examples. The explicit current MCP product direction
supersedes that blanket policy. Only its dedicated code, registration,
Makefile/script references, obsolete environment flag and documentation were
removed. Shared helpers and every unrelated gate remain. Native grant and
capability refusal tests remain exact. The initial removal accidentally
deleted a shared git helper; it was restored byte-for-byte before the fresh
qualification. Compiling failures and stale-binary selftest output are retained
and are not qualification of the repaired source.

Evidence for this follow-up is retained on z23-r2 under
~/.local/state/storage-plan/2026-10-12-fleet/mcp-wiki-capability-20261013/.
The running backend still requires its independently qualified update; this
worker performed no deployment or production service change.

## Strict compiler fixture correction

The release suite on 2026-10-13 refused a discarded const qualifier in the
wiki round-trip fixture. The shared RPC-table test pointer now preserves the
const contract already accepted by rpc_table_execute. No cast or warning
suppression was added. The canonical strict test-parallel runner then passed
test_fleet_board: one group executed, zero failures, skips or unobserved
environments; test body 23,765 ms. The initial help invocation returned usage
with exit 2 after compilation and is not runtime test acceptance. Full release
qualification and activation remain separate requirements.

## Gateway workflow guidance and recovered fixture qualification

The gateway initialization response now supplies bounded workflow guidance,
and each existing tool has a descriptive title. Tool names, request schemas,
grant scopes and receiver authority remain unchanged. The guidance distinguishes
configuration, authentication, observed replies and active worker evidence.
It preserves exact-source review, idempotent reconciliation and local policy;
wiki content is knowledge rather than execution authority.

The reviewed three-file proposal has SHA256
64f983a09751e97d72084df33ed228f3d7d69b186ff56a20dca4eb4fb8463978.
On 2026-10-13 it passed the focused gateway shard on macOS: one group,
zero failures, skips or unobserved legs, with a 3,729 ms test body. Complexity,
documentation capability inventory and fast lint also passed there. Its exact
artifact transfer to Linux verified all five handoff files before application
on base 921311736d41e58417b608219b6e0582603a2aac. The same focused shard
passed on Linux: one group, zero failures, skips or unobserved legs, with a
2,124 ms test body. These are functional test observations, not latency
benchmarks or deployment evidence.

The preceding release attempt stopped before deployment: its full suite ran
1,300 groups and failed three because required exact public guest fixtures
were unavailable to the process. Eleven groups were gated, nineteen skip
markers were reported, and one group had unobserved environment-dependent
legs. No threshold was changed. The retained archive was verified before
restoring only the required public kernels; original artifacts were preserved.
With the required fixture environment explicitly provided, independent focused
runs passed guest image admission, GELI volume and FreeBSD ports, each with
zero failures, skips and unobserved legs. These reruns do not replace the
full release gate and do not qualify native fleet SSH or production activation.

## Bounded wiki retrieval and indexed queries

The source now has exact retained-revision body chunks on `fleet wiki read
--id=<revision>`: hex bytes, offsets, total length and signed metadata. Numeric
`signed_scope` and raw `signed_room` preserve the existing codec's version and
signed bytes. Reconstruct the complete post and independently verify its ID and
signature; a chunk alone is a partial observation. A missing, evicted, corrupt
or non-wiki revision refuses. Legacy slug reads retain their full projection.
The intermediate Mac candidate passed the three focused wiki/catalog/gateway
groups without skips; that observation does not qualify the later query changes.

Schema migration 87 adds a SQLite index on `(kind,slug,created_at DESC,id DESC)`
in the existing signed board database. The typed query traverses distinct slugs
with exclusive keyset seeks and preserves newest-verifying revision fallback,
including the rule that a valid plain-text winner suppresses older structured
knowledge. This accelerates revision traversal; it is not a full-text index.
No second ledger, scheduler, retention lease or new publication authority exists.

`fleet wiki find` combines the existing ASCII-insensitive substring `q` with
optional exact `topic` and `applies_to` filters by AND. Continue with `after_slug`
and unchanged filters; observations are latest-held, not a snapshot. Each call
verifies at most 256 revisions. `verification_budget` leaves `blocked_slug`
unresolved without skipping it or claiming absence; unchanged retries need not
make progress. The separate exact slug read retains its existing contract.
Compact results always identify exact revisions; omission flags distinguish
summaries or rule lines left out to fit. Read the exact ID for the full content.
Native responses default to 4096 bytes, honor a 2048-byte minimum and cap at
8192. The evidence-scoped steering wrapper reserves its outer metadata and
requires at least 3072 bytes; it forwards the same optional filters and cursor.
Its gateway tool continues to require a nonempty `q` and the evidence scope.

Qualification measures actual SQLite VM steps and statement launches against
the previous duplicate-history traversal, and checks late-alphabet continuation,
corrupt newest revisions, tied IDs, filter composition, SQL interruption,
migration refusal and serialized response budgets. These source tests are
pending for the combined candidate at this point; no deployment or live plugin
readiness follows from the implementation. The retained plugin preview is an
artifact, not an installed or authenticated runtime.

A later authenticated native MCP observation exposed five tools, including
`wiki_find` and `steer_deliver`; a protected `q=tunnel` lookup succeeded at
observed Unix time 1791937981. The observed caller holds brief/send/evidence,
so visibility supplies neither deliver nor wiki-write authority. Topic,
applicability and cursor extensions above remain local candidate behavior.
A peer reported activation of gateway/CLI commit 9c7adf8 and 46 isolated checks,
with receipt SHA256
5d2f93485f9e69b2ec082ee4b024f59554176504ace2ded914436757d38b376e;
that receipt's bytes have not been independently inspected here. This and one
successful lookup do not establish fleet-wide readiness. Keep brief receive
cursors separate from send acknowledgments and check bounded stream coverage.

Qualification lesson: check the cheap file-size ceiling and lint-fast alongside
complexity and scoped syntax before expensive source-bound builds. The wiki
query was moved into the existing read-only wiki model sibling after the first
final lint exposed the store's hard line limit; earlier runtime PASS remains
intermediate evidence until the exact split is requalified.

Mail evidence reuses the native ref-filtered pull, drains its bounded pages,
and refuses absence unless typed completion and every source establish it.
Work refs select the latest held matching mail, including replies or ACKs;
use versioned refs when earlier evidence bodies must remain distinguishable.
An exact retained row is selected by `stream`, `row_offset`, `seq` and
`row_sha3` together, read through one descriptor-bound complete line, and
refused on any mismatch. The evidence selectors are validated by the node at
runtime; the gateway schema is flat and declares no `oneOf`.

The evidence-scoped `wiki_read` tool exposes the native signed hex chunks
through the existing steering adapter, retaining the outer response budget.
A chunk is a partial projection; reconstruct and verify the complete signed
post before treating its body as verified. Missing, corrupt, wrong-kind and
evicted revisions refuse. Grants must hold evidence scope at dispatch.

The write route requires a separately minted `wiki-write` grant and publishes
PUBLIC knowledge signed by the receiver node and replicated to peers. It binds
attribution and a stable request key to the exact grant, checks current
revocation before retained replay, and compares the receiver-local newest
verified page in one transaction. This is not a distributed global-head claim.
Replay lasts only while the original revision remains retained. Admission does
not cancel commits already in flight. The compact success receipt carries the
actual signed revision identity, body length and SHA3-256; independent
verification still requires exact chunk reconstruction. Unknown outcomes
reconcile with the same request key rather than a new one. Owner approved the
remote wiki-write route on 2026-10-14; direct `fleet.wiki.write` stays
never-remote and no existing grant gains the scope.

`text` is inline UTF-8. `@path` is literal content, not file expansion. Plain
prose is valid wiki content and remains readable by exact id, while `wiki_find`
discovers valid `zcl.fleet_wiki_entry.v1` JSON bodies. A searchable inline body
is:

```json
{"schema":"zcl.fleet_wiki_entry.v1","topic":"kernel","summary":"A bounded boot lesson","lessons":[{"rule":"Check the exact boot transcript","why":"Startup alone does not prove guest behavior","evidence":"An exact accepted test receipt"}],"applies_to":["z23-kernel"],"updated":"2026-10-14T00:00:00Z"}
```

Pass that JSON string as `text`, along with `request_key`, `expected: "absent"`,
`slug` and `title`. Native CLI callers can use JSON input; the global `--format`
flag selects command output and is not an entry-format selector.

`WIKI_CLOCK` means the new revision's signed timestamp is not strictly later
than the newest retained revision of the slug, for example a second write in
the same wall-clock second or a peer revision signed by a later clock. Nothing
was committed. Retry with the same `request_key` and `expected` once this
node's clock is past that revision; only a successful commit retains the
request marker, so a refused attempt does not consume the key.
