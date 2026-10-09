<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# C23 task type catalog

Status: curated coverage proposal, written 2026-10-08. This is documentation,
not runtime routing authority. IDs identify actionable task patterns, not task
instances, canonical task roots, or measured classes. The first 100 rows are
editorial priority coverage based on common implementation surfaces, not an
empirical frequency ranking. All sample counts, accuracy, rework, cost, and
model qualification are `UNKNOWN` until exact task roots, attempts, reviews,
repairs, and acceptance outcomes are joined. No frequency or performance
claims follow from this catalog.

## Selection and escalation

The source defines these C23 prompt kinds: `c23-byte-validator`,
`c23-command-handler`, `c23-model-save`, `c23-regression-fixture`,
`c23-wire-codec`, `c23-cas-operation`, `c23-service-operation`,
`c23-telemetry-field`, `c23-controller-route`, `c23-source-generator`,
`c23-registry-entry`, `c23-context-pack`, `c23-gate-tail`,
`c23-proof-triage`, and
`c23-resource-owner`. Existing kinds `fix-gate`,
`add-test`, `port-arm`, `doc-claim`, and `review` remain. Rows marked
`PROPOSED:<family>` still need a procedure; they are not dispatchable kinds.
The `review` kind returns findings only, each marked as about the change or
about a claim made for it, and never a verdict; rules a gate measures arrive
as supplied facts.
Each kind declares a tier in the same file (`ENGINE_PROMPT_KIND_TIER`). Light
kinds (`c23-context-pack`, `c23-gate-tail`, `c23-proof-triage`) are read-only
or mechanical and a small model can run them; standard kinds write code. The
tier is a floor the dispatcher may exceed, never a schedule.
The compiled selection owner is `engine/composition/prompt_templates.def`,
consumed by `tools/engine_unit.c`. A source entry is not evidence that an
installed runner has been rebuilt or qualified.

Select one procedure per bounded patch. The wire recipe covers explicit
encoding/decoding and structural admission; signature verification and policy
acceptance remain separate obligations. The CAS recipe covers bounded reads,
verified insertion and publication failure handling; it does not supply a
transfer scheduler, garbage collector or index-recovery algorithm. Leave those
catalog rows proposed until their own procedures exist.

### Compact task input

Supply the following task-specific fields with the selected `kind:` header.
Resolve them from the canonical task and claim; this card is a prompt input,
not a replacement task object or coordination ledger.

```text
kind: c23-wire-codec

Outcome: <one externally observable behavior>
Source: <exact candidate/base and owned paths>
Caller: <production entry and existing reusable helper>
Contract: <grammar/version, bounds, ownership and failure output state>
Compatibility: <old bytes/roots and authority that must remain unchanged>
Acceptance: <registered group, golden vector and rejecting boundary case>
```

For CAS, substitute address derivation, byte cap, durability and refusal
contracts. Missing fields require a named refusal before code is proposed.
For service operations, supply transaction ownership, the existing ActiveRecord
lifecycle, authority, invariants and the production caller's failure outputs.
The service exemplar illustrates paired-write transaction ownership; it does
not establish atomic external effects or a generic transaction API. Its
transition caller advances memory and discards persistence status; database
rollback does not imply caller-visible refusal or memory rollback.
For resource ownership, supply borrowed extents and lifetimes, empty writable
output slots, transfer and release obligations, and the exact failure outputs.
The QR renderer has no fallible post-allocation stage; partial acquisition
coverage belongs to its encode-success/render-refusal composition. Release
counts and leak freedom require separate observation.
This is a worker instruction; the prompt composer checks section presence,
not completeness of these task-specific fields.
Load the selected procedure and relevant source capsule, then produce only the
missing behavior. Do not paste the entire catalog into each task. Recipe
selection does not acquire a claim or grant execution or publication authority.

Expand from observed task needs: reuse a matching module first; select a
qualified procedure second; add a narrowly described procedure when neither
fits. Record its source exemplar, required inputs, failure semantics and exact
acceptance. Compare matched root-task cohorts with and without the procedure,
including discovery, implementation, review, repair, rejected attempts and
integration tokens. Report missing usage explicitly. Template coverage and
prompt byte limits are diagnostics, not measured token savings.

Provisional profile for ordinary, bounded source proposals: Sol-low, with the
row's exact verifier mandatory. Luna is appropriate for constrained checks,
independent review, or a narrowly specified repair with a deterministic
oracle. These are starting hypotheses, not measured recommendations. Escalate
when scope, verifier, exact source identity, or candidate continuity is
unclear; when the registered verifier fails; when work crosses protected
consensus, wallet/custody, production-state, or deployment boundaries; or when
an escaped defect is found. Protected authority remains owner-gated regardless
of model. Model selection never weakens acceptance or authorization.

## Catalog row format

`ID | actionable task type / inclusion boundary | kind | verifier`

Each verifier is a required outcome for one instance; use `z23 code tests
<changed-path>` to discover the registered group and run the focused acceptance
for the exact candidate. A verifier description is the contract to assert, not
a claim that a test currently exists. Where the named contract has no focused
registered test, the task includes adding it. Family exemplars below are
tracked source paths checked in this checkout; they orient implementation and
do not imply every row is already implemented there.

## P001–P100: editorial priority coverage

### P001–P025: byte and parser boundaries

Exemplars: `core/modules/validation/src/check_transaction.c`; `tools/jsonq.c`.

| ID | Task type / inclusion | Kind | Verifier |
|---|---|---|---|
| P001 | Reject embedded NUL before a length-delimited text parser sees the buffer | c23-byte-validator | NUL fixture refuses without partial output |
| P002 | Reject overlong UTF-8 in a public text field | c23-byte-validator | overlong sequence fails; valid boundary sequence passes |
| P003 | Validate UTF-8 continuation bytes at the final available byte | c23-byte-validator | truncated multibyte fixture fails safely |
| P004 | Bound a decimal parser before multiply-add overflow | c23-byte-validator | UINT64_MAX passes; next value refuses |
| P005 | Reject a sign on a wire field whose declared grammar is unsigned decimal | c23-byte-validator | negative and plus-prefixed spellings refuse; unsigned boundary values pass |
| P006 | Detect duplicate decoded JSON object keys | c23-byte-validator | literal and escaped duplicate spellings both refuse |
| P007 | Count direct object keys without counting nested descendants | c23-byte-validator | nested same-name fixture leaves direct count unchanged |
| P008 | Refuse a JSON value of the wrong root type | c23-byte-validator | scalar, array, and null roots each refuse |
| P009 | Bound JSON nesting before recursive traversal exhausts stack | c23-byte-validator | depth limit and one-over-limit fixture behave deterministically |
| P010 | Reject malformed JSON string escapes | c23-byte-validator | invalid escape refuses; valid escape decodes exactly |
| P011 | Validate JSON surrogate pairs and reject unpaired surrogates | c23-byte-validator | paired/unpaired Unicode fixtures distinguish correctly |
| P012 | Preserve decoded key byte lengths when keys contain escaped newlines | c23-byte-validator | escaped newline key matches only its exact bytes |
| P013 | Reject trailing non-whitespace after a complete JSON value | c23-byte-validator | trailing token refuses; whitespace suffix passes |
| P014 | Validate hex input for lowercase, even length, and destination capacity | c23-byte-validator | odd, uppercase, and oversized cases refuse |
| P015 | Reject a path component containing an embedded separator or NUL | c23-byte-validator | component boundary fixture refuses without path access |
| P016 | Bound a counted array before allocating element storage | c23-byte-validator | maximum count passes; maximum-plus-one refuses |
| P017 | Guard `count * element_size` before allocation | c23-byte-validator | overflow fixture refuses before allocator call |
| P018 | Validate a caller-provided span against its enclosing buffer | c23-byte-validator | offset-at-end zero span passes; overrun refuses |
| P019 | Refuse a length that cannot fit the downstream API's narrower type | c23-byte-validator | narrowing boundary pair produces exact expected status |
| P020 | Validate a NUL-terminated field's terminator lies within capacity | c23-byte-validator | unterminated full-capacity fixture refuses |
| P021 | Reject duplicate query parameters after percent decoding | c23-byte-validator | encoded aliases collide and are refused |
| P022 | Bound line-oriented input record bytes before parsing | c23-byte-validator | exact cap passes; one extra byte refuses |
| P023 | Distinguish absent, empty, and null JSON fields | c23-byte-validator | three fixtures preserve distinct states |
| P024 | Reject invalid enum text rather than silently selecting enum zero | c23-byte-validator | unknown spelling refuses with explicit error |
| P025 | Preserve byte-for-byte canonicalization across equivalent JSON whitespace | c23-byte-validator | canonical root stable across whitespace-only variants |

### P026–P050: native command and API handlers

Exemplars: `engine/composition/commands/zcode.def`; `tools/command/native_zcode_work_map.c`.

| ID | Task type / inclusion | Kind | Verifier |
|---|---|---|---|
| P026 | Add one typed read-only command with a complete input and output schema | c23-command-handler | catalog lists leaf; schema and response fixture match definition |
| P027 | Add a bounded pagination field with explicit default and maximum | c23-command-handler | zero/default/max/max-plus-one cases are exact |
| P028 | Require an exact content root instead of a mutable alias | c23-command-handler | malformed and missing root refuse; valid root resolves exact object |
| P029 | Return explanatory refusal body for malformed command input | c23-command-handler | every malformed fixture has stable error code and message |
| P030 | Keep a status command read-only while adding an evidence field | c23-command-handler | snapshot before/after proves no persistent state change |
| P031 | Add a plan/commit command pair with a bound plan identity | c23-command-handler | stale plan and mismatched input refuse commit |
| P032 | Require explicit confirmation for an irreversible user-visible mutation | c23-command-handler | omitted/false confirmation refuses without mutation |
| P033 | Add an idempotency key to a retryable command | c23-command-handler | identical retry creates one durable effect |
| P034 | Reject unknown command fields when they could alter authority | c23-command-handler | unknown authority-bearing field refuses, no partial action |
| P035 | Preserve current datadir selection when command input omits it | c23-command-handler | explicit and inherited datadir resolve to expected isolated fixture |
| P036 | Return a continuation token bound to the current exact object root | c23-command-handler | token from another root is refused |
| P037 | Add command-level timeout bounds without changing proof policy | c23-command-handler | below/at/above boundary behavior and cleanup are checked |
| P038 | Make command output stable for the same immutable input | c23-command-handler | repeated response bytes match after volatile fields are excluded |
| P039 | Refuse ambiguous `latest` when multiple roots qualify | c23-command-handler | two-root fixture requires explicit selection |
| P040 | Ensure command handler reports downstream service refusal unchanged | c23-command-handler | injected service failure preserves code and context |
| P041 | Add a typed filter with an allowlisted enum and bounded limit | c23-command-handler | valid filter works; unknown enum and oversized limit refuse |
| P042 | Bind a command response to the candidate root it describes | c23-command-handler | response root equals independently derived candidate root |
| P043 | Keep a preview command free of writes and external execution | c23-command-handler | isolated state and process snapshots remain unchanged |
| P044 | Add a command alias without creating a second behavior path | c23-command-handler | alias and canonical leaf invoke identical handler contract |
| P045 | Surface a missing dependency as unavailable, not success | c23-command-handler | unavailable fixture returns typed non-success and next step |
| P046 | Reject conflicting explicit and inherited workspace paths | c23-command-handler | disagreement refuses rather than choosing one silently |
| P047 | Add bounded diagnostics detail behind an explicit opt-in field | c23-command-handler | default redacts detail; opt-in reveals only documented fields |
| P048 | Keep command response within a declared byte limit | c23-command-handler | maximal fixture is bounded and truncation is explicit |
| P049 | Ensure command validates authorization before resolving mutable target | c23-command-handler | unauthorized fixture performs no target lookup or write |
| P050 | Add a command leaf that delegates policy decisions to its service | c23-command-handler | handler contains no duplicated policy and service result is preserved |

### P051–P075: ActiveRecord models and validation lifecycle

Exemplars: `contexts/commons/models/src/zcode_lane.c`; `engine/models/src/build_fabric.c`.

| ID | Task type / inclusion | Kind | Verifier |
|---|---|---|---|
| P051 | Add model validation for a required nonempty identity field | c23-model-save | empty value fails before save hook or SQL write |
| P052 | Add model validation for a canonical 32-byte root | c23-model-save | wrong length and zero root refuse; valid root persists |
| P053 | Preserve before/after-save callbacks on a new model field | c23-model-save | callback fixture observes exactly one ordered lifecycle |
| P054 | Add a uniqueness rule scoped by owner identity | c23-model-save | same-owner duplicate refuses; other-owner value succeeds |
| P055 | Make model update use expected revision to reject stale writes | c23-model-save | concurrent stale revision refuses without overwrite |
| P056 | Validate enum values before SQL binding | c23-model-save | invalid enum refuses at model boundary |
| P057 | Add a nullable field with explicit absent-versus-empty semantics | c23-model-save | null, empty, and populated round-trip distinctly |
| P058 | Add a bounded integer column and validate before cast | c23-model-save | minimum/maximum persist; out-of-range refuses |
| P059 | Ensure failed model validation leaves the record unchanged | c23-model-save | before/after DB snapshot is identical after refusal |
| P060 | Add a model save path using the required AR lifecycle wrapper | c23-model-save | lifecycle hooks run and direct bypass is absent |
| P061 | Add contextual logging to a database save refusal | c23-model-save | injected SQL failure logs model and operation context |
| P062 | Make model decoding reject truncated persisted blobs | c23-model-save | truncated row reports corruption and yields no partial model |
| P063 | Add an exact-root lookup with deterministic not-found behavior | c23-model-save | hit returns exact root; miss returns typed absence |
| P064 | Prevent an immutable receipt row from being updated in place | c23-model-save | second conflicting save refuses; original bytes remain |
| P065 | Add a model relationship whose foreign root must exist | c23-model-save | absent parent refuses; valid parent binds exact root |
| P066 | Preserve unknown future enum values as unsupported, not default | c23-model-save | future value returns explicit unsupported result |
| P067 | Validate a timestamp against the declared domain and range | c23-model-save | negative and overflow values refuse; valid bound round-trips |
| P068 | Ensure model query ordering is stable for equal timestamps | c23-model-save | tie fixture returns documented root-based order |
| P069 | Add a bounded list query that cannot exceed caller capacity | c23-model-save | limit/capacity mismatch refuses without buffer overrun |
| P070 | Keep model save transaction atomic across parent and child rows | c23-model-save | injected child failure rolls back parent row |
| P071 | Avoid logging secret model fields on validation failure | c23-model-save | captured log excludes secret fixture bytes |
| P072 | Add a schema migration preserving existing receipt roots | c23-model-save | old rows decode unchanged and new schema validates |
| P073 | Reject mutation of a signed identity after record creation | c23-model-save | changed signer/root fails immutable-field validation |
| P074 | Make model deletion refuse when evidence references the row | c23-model-save | referenced row persists; unreferenced fixture follows contract |
| P075 | Verify post-save hooks follow their declared durability contract | c23-model-save | required transactional effects roll back on failure; best-effort projection failure logs while durable save remains successful |

### P076–P100: regression fixtures and acceptance tests

Exemplars: `tests/harness/src/test_build_fabric.c`; `tests/harness/src/test_engine.c`.

| ID | Task type / inclusion | Kind | Verifier |
|---|---|---|---|
| P076 | Add a production-caller regression for integer boundary rejection | c23-regression-fixture | fixed path passes; intended overflow mutation fails |
| P077 | Add a fixture proving the caller actually reaches the hardened branch | c23-regression-fixture | caller-level assertion fails when branch is bypassed |
| P078 | Add a test proving duplicate JSON keys are rejected at admission | c23-regression-fixture | duplicate production input fails before object use |
| P079 | Add an isolation fixture using a unique temporary directory | c23-regression-fixture | test leaves no operator-state files after cleanup |
| P080 | Add deterministic clock injection for an expiry boundary | c23-regression-fixture | exact expiry and one tick on either side are asserted |
| P081 | Add a race fixture with two writers using the same expected revision | c23-regression-fixture | exactly one writer succeeds; loser sees conflict |
| P082 | Add rollback assertion for a failure after the first durable write | c23-regression-fixture | injected second-step failure leaves no partial state |
| P083 | Add a test for restoration of a callback after temporary replacement | c23-regression-fixture | original callback is invoked after fixture scope ends |
| P084 | Add cleanup assertions for every allocated fixture resource | c23-regression-fixture | leak/refcount/temp-file checks pass after both outcomes |
| P085 | Add a mutation-sensitive verifier for exact candidate root binding | c23-regression-fixture | wrong-root mutation fails at production boundary |
| P086 | Register a previously unlisted focused test in the canonical catalog | c23-regression-fixture | `make t-list` lists group and exact runner executes it |
| P087 | Split a broad fixture into independent deterministic cases | c23-regression-fixture | each case is isolated and reports its own assertion count |
| P088 | Add a negative control proving the acceptance rejects a known-invalid wire | c23-regression-fixture | invalid fixture fails for the intended reason only |
| P089 | Add a no-side-effect assertion to a read-only command test | c23-regression-fixture | persistent state hashes match before and after command |
| P090 | Add a fixture for escaped path spelling and canonical root equality | c23-regression-fixture | equivalent canonical input maps to one exact root |
| P091 | Add a concurrent reader/writer fixture for snapshot consistency | c23-regression-fixture | reader observes complete before or after state only |
| P092 | Add a boundary matrix around a declared maximum buffer length | c23-regression-fixture | below/at/above values assert exact result and output size |
| P093 | Add a regression for error-body presence on every native failure path | c23-regression-fixture | injected failures all return nonempty explanatory bodies |
| P094 | Add a test ensuring skipped cases are not reported as passed | c23-regression-fixture | runner summary preserves skipped and failed counts separately |
| P095 | Add a test that verifies exact model/template identity in a receipt | c23-regression-fixture | receipt root re-derives from selected exact identity |
| P096 | Add a test for duplicate retry idempotency after process restart | c23-regression-fixture | restored fixture has one effect and same result root |
| P097 | Add the smallest focused mutation that restores the original defect | c23-regression-fixture | fixed passes, intended mutation fails, restored passes |
| P098 | Add platform-gated behavior test with explicit unavailable outcome | c23-regression-fixture | unsupported platform reports unavailable, never false pass |
| P099 | Add an integration assertion for service refusal through controller response | c23-regression-fixture | exact refusal code and state are preserved end-to-end |
| P100 | Add a fixture proving a local view is rebuilt from immutable evidence | c23-regression-fixture | rebuild yields same rows and ignores corrupt projection cache |

## C101–C500: additional type coverage

These 400 rows widen operation/surface coverage; they are not ranked by
observed frequency. `PROPOSED:<family>` means no dispatchable kind exists.
The same model/escalation hypothesis applies by row: Sol-low for ordinary
bounded proposals, Luna for constrained verification/review, and owner gate for
protected scope. The cited source exemplar is the family anchor, not a claim
that its current code needs the listed change.

### C101–C125: canonical wire encoding and decoding

Exemplars: `contexts/commons/modules/vcs/src/zcode_dev.c`; `contexts/commons/modules/vcs/src/zcode_action_input.c`.

| ID | Task type / inclusion | Kind | Verifier |
|---|---|---|---|
| C101 | Add a version byte to a canonical task wire while preserving old decode | c23-wire-codec | old fixture re-encodes identically; new version round-trips |
| C102 | Reject noncanonical integer width in signed receipt encoding | c23-wire-codec | alternate width fails canonical re-encode check |
| C103 | Add a bounded optional field to candidate wire | c23-wire-codec | absent/present round-trip; over-capacity refuses |
| C104 | Enforce sorted member roots in proof-set encoding | c23-wire-codec | unsorted duplicate fixture refuses; canonical order stable |
| C105 | Add domain-separated root derivation for a new immutable object | c23-wire-codec | cross-domain identical bytes yield distinct roots |
| C106 | Make decoder report consumed byte count and reject suffixes | c23-wire-codec | exact wire consumes all bytes; suffix is rejected |
| C107 | Add cross-field task/candidate root binding validation | c23-wire-codec | mismatched pair refuses before serialization |
| C108 | Reject duplicate root members in a canonical collection | c23-wire-codec | duplicate member refuses without order-dependent result |
| C109 | Bound wire size before allocating nested arrays | c23-wire-codec | one-over-limit input refuses before allocation |
| C110 | Preserve unknown wire version as unsupported, not current version | c23-wire-codec | future-version fixture yields typed unsupported result |
| C111 | Add a canonical lowercase hex projection for a root | c23-wire-codec | uppercase input refuses; projection round-trips exact bytes |
| C112 | Validate a fixed-width public key in a signed object | c23-wire-codec | wrong curve length and all-zero key refuse |
| C113 | Ensure serializer zeroes reserved bytes deterministically | c23-wire-codec | repeated serialization has identical reserved region |
| C114 | Add a wire field whose presence is bound into the object root | c23-wire-codec | absent and explicit zero produce documented distinct/equal roots |
| C115 | Prevent decoder integer overflow while advancing cursor | c23-wire-codec | near-SIZE_MAX offset fixture refuses before pointer arithmetic |
| C116 | Add strict UTF-8 validation to a signed human-readable field | c23-wire-codec | invalid byte sequence refuses before root derivation |
| C117 | Encode a nested acceptance recipe by exact child root | c23-wire-codec | substituted child root fails parent verification |
| C118 | Validate signature bytes before accepting decoded receipt | PROPOSED:wire | altered signature refuses at verification boundary |
| C119 | Add deterministic field ordering to a signed map wire | c23-wire-codec | permutation inputs normalize to one byte sequence |
| C120 | Reject trailing padding that is not part of the canonical format | c23-wire-codec | padded wire refuses; exact-length wire passes |
| C121 | Make a result decoder reject partial final digest bytes | c23-wire-codec | truncated digest at every byte boundary refuses |
| C122 | Add a bounded list count to a work request wire | c23-wire-codec | zero/max counts pass; max-plus-one refuses |
| C123 | Bind proof policy and toolchain roots into action identity | c23-wire-codec | changing either root changes action root |
| C124 | Add explicit absent-value encoding for an optional signer field | c23-wire-codec | absent and zero-key semantics are unambiguous |
| C125 | Add golden vectors for a canonical wire version | c23-wire-codec | source and independent decode agree on bytes and root |

### C126–C150: content-addressed storage and indexes

Exemplars: `contexts/commons/modules/vcs/src/blob_store.c`; `contexts/commons/modules/vcs/src/vcs_object.c`.

| ID | Task type / inclusion | Kind | Verifier |
|---|---|---|---|
| C126 | Verify stored blob bytes against requested root on read | c23-cas-operation | corrupted fixture is refused and not returned |
| C127 | Make duplicate CAS insertion idempotent for identical bytes | c23-cas-operation | second insert preserves one object and same root |
| C128 | Refuse same root with different object bytes | c23-cas-operation | collision fixture reports integrity failure |
| C129 | Bound blob read by caller capacity and declared object size | c23-cas-operation | undersized output refuses without partial disclosure |
| C130 | Recover an interrupted atomic object write | c23-cas-operation | restart exposes either complete object or absence |
| C131 | Add index rebuild from immutable object roots | PROPOSED:cas | clean and rebuilt index return identical exact objects |
| C132 | Keep a stale index from overriding verified CAS bytes | PROPOSED:cas | stale projection is discarded and rederived |
| C133 | Reject path traversal in CAS shard path derivation | PROPOSED:cas | hostile root/path input cannot escape fixture root |
| C134 | Make object deletion refuse while a durable root reference exists | PROPOSED:cas | referenced object remains; unreferenced GC is bounded |
| C135 | Add a content chunk manifest with verified total length | PROPOSED:cas | chunk sum and root mismatch both refuse |
| C136 | Fetch only missing chunks for a known manifest | PROPOSED:cas | present chunks are not requested; assembled root verifies |
| C137 | Detect duplicate chunk indexes in a transfer manifest | PROPOSED:cas | duplicate index refuses before assembly |
| C138 | Add resumable transfer cursor bound to manifest root | PROPOSED:cas | cursor for another root refuses |
| C139 | Ensure temporary CAS files are cleaned after failed verification | c23-cas-operation | injected failure leaves no staged file |
| C140 | Make CAS directory creation safe under concurrent insertion | c23-cas-operation | two writers yield one valid object and no corrupt path |
| C141 | Validate manifest metadata before scheduling chunk downloads | PROPOSED:cas | invalid count/length fails before network request |
| C142 | Add bounded object eviction that preserves pinned roots | PROPOSED:cas | pinned fixture survives quota pressure |
| C143 | Reconcile object references after interrupted index update | PROPOSED:cas | recovery derives references from durable roots |
| C144 | Return explicit not-found separately from corrupt-object status | c23-cas-operation | absent and corrupted fixtures return distinct codes |
| C145 | Prevent symlink substitution in a filesystem-backed CAS read | PROPOSED:cas | symlink fixture is refused under scoped directory handle |
| C146 | Add deterministic inventory of stored root and byte count | PROPOSED:cas | same fixture emits same root ordering and totals |
| C147 | Verify exact root after decompression of a stored object | c23-cas-operation | altered compressed payload fails post-decode root check |
| C148 | Enforce a maximum manifest fanout before recursive traversal | PROPOSED:cas | fanout cap and cap-plus-one are asserted |
| C149 | Keep local SQLite object index rebuildable from verified CAS | PROPOSED:cas | deleting index then rebuilding preserves rooted query results |
| C150 | Add fault injection for disk-full during CAS commit | c23-cas-operation | operation fails with no published partial root |

### C151–C175: service workflows and transaction composition

Exemplars: `engine/services/src/build_fabric_service.c`; `contexts/commons/modules/vcs/src/package_service.c`.

| ID | Task type / inclusion | Kind | Verifier |
|---|---|---|---|
| C151 | Add a service operation that validates all inputs before writes | c23-service-operation | invalid input leaves transaction and files unchanged |
| C152 | Return typed `zcl_result` for each expected refusal branch | c23-service-operation | branch fixtures assert result code and context |
| C153 | Make a multi-model service operation atomic | c23-service-operation | injected second-save failure rolls back first save |
| C154 | Keep remote fetch outside a database transaction | PROPOSED:service | network wait does not retain write transaction |
| C155 | Add idempotent service retry keyed by immutable action root | PROPOSED:service | repeated same action returns prior exact result |
| C156 | Refuse service execution when task and candidate roots disagree | PROPOSED:service | crossed-root fixture yields no writes |
| C157 | Record a service result only after exact receipt verification | PROPOSED:service | invalid receipt cannot create success projection |
| C158 | Separate preview computation from commit behavior | PROPOSED:service | preview path produces no persistent mutation |
| C159 | Add cancellation cleanup to a long-running package workflow | PROPOSED:service | cancel releases locks, temp objects, and worker slots |
| C160 | Make retry policy distinguish transient transport from invalid data | PROPOSED:service | transient retries; invalid root is not retried |
| C161 | Ensure service reports partial remote availability as incomplete | PROPOSED:service | missing-peer fixture is never rendered complete |
| C162 | Add a service-level timeout with explicit partial-result state | PROPOSED:service | timeout returns bounded partial facts and resume identity |
| C163 | Preserve original task identity across repair attempts | PROPOSED:service | repair result references same task and new candidate root |
| C164 | Deduplicate concurrent identical service requests | PROPOSED:service | overlapping requests share action identity and one effect |
| C165 | Avoid holding a model lock while invoking verifier subprocess | PROPOSED:service | test observes lock released before subprocess starts |
| C166 | Bind service receipt to exact verifier policy version | PROPOSED:service | changed policy root changes receipt identity |
| C167 | Add explicit compensation for a reversible service side effect | PROPOSED:service | injected later failure runs compensation exactly once |
| C168 | Keep accepted result immutable when adding display metadata | PROPOSED:service | metadata update does not alter acceptance roots |
| C169 | Propagate structured service errors through nested orchestration | PROPOSED:service | deepest error code survives wrapper chain |
| C170 | Make service status reconstruction read-only | PROPOSED:service | storage snapshot remains unchanged during status call |
| C171 | Add bounded fanout when a service schedules independent children | PROPOSED:service | maximum concurrent children never exceeds policy |
| C172 | Ensure service does not schedule dependent child before prerequisite receipt | PROPOSED:service | withheld prerequisite prevents downstream dispatch |
| C173 | Report all missing evidence roots instead of collapsing to generic failure | PROPOSED:service | multi-missing fixture lists exact roots deterministically |
| C174 | Add recovery from stale lease without treating silence as orphan proof | PROPOSED:service | active lease remains; explicit expired authority is required |
| C175 | Add a service acceptance test across model, receipt, and public response | PROPOSED:service | one fixture traces exact root through all three boundaries |

### C176–C200: thin controllers and user-facing views

Exemplars: `contexts/commons/controllers/src/zcode_site_controller.c`; `contexts/commons/views/src/zcode_view_pages.c`.

| ID | Task type / inclusion | Kind | Verifier |
|---|---|---|---|
| C176 | Add a controller route that delegates policy to one service | c23-controller-route | controller contains no policy branch; service fixture covers decision |
| C177 | Validate route parameters before opening workspace state | c23-controller-route | malformed route has no filesystem effect |
| C178 | Escape task-provided text in an HTML result page | c23-controller-route | script and quote fixture render as inert text |
| C179 | Render missing evidence as unknown rather than zero | PROPOSED:mvc | absent-cost fixture shows `UNKNOWN` for each missing measure |
| C180 | Keep task preview identities visible before run action | PROPOSED:mvc | rendered preview includes task/catalog/action roots |
| C181 | Add a view for selected template and exact template hash | PROPOSED:mvc | response hash matches service-resolved template bytes |
| C182 | Render proof status separately from accepted-work status | PROPOSED:mvc | proven-but-unaccepted fixture has distinct labels |
| C183 | Preserve actionable next step for a blocked work item | PROPOSED:mvc | blocked fixture exposes precise missing precondition |
| C184 | Add accessible labels for task status and cost measures | PROPOSED:mvc | HTML has associated labels and keyboard-visible controls |
| C185 | Bound output when a task contains a very long title or description | c23-controller-route | maximum-size fixture is escaped and response remains bounded |
| C186 | Add pagination to task history using stable exact-root cursor | PROPOSED:mvc | cursor cannot skip/duplicate rows across stable fixture |
| C187 | Prevent cached view from showing a different candidate's result | PROPOSED:mvc | cache key includes candidate root and policy version |
| C188 | Distinguish local projection freshness from source-object availability | PROPOSED:mvc | stale projection visibly triggers rebuild/read-through |
| C189 | Add a view that links each cost component to its source observation | PROPOSED:mvc | displayed total traces to all component receipts |
| C190 | Show reviewer identity separately from proposal model profile | PROPOSED:mvc | fixture asserts separate identities and provenance |
| C191 | Add a confirmation view naming exact root before protected commit | PROPOSED:mvc | confirmation root mismatch refuses submission |
| C192 | Render unavailable platform proof without a success badge | PROPOSED:mvc | unsupported-host fixture labels unavailable explicitly |
| C193 | Add a responsive narrow-screen layout for work preview | PROPOSED:mvc | static viewport checks keep controls and roots readable |
| C194 | Keep public page data free of private host and credential fields | c23-controller-route | secret sentinel is absent from rendered response |
| C195 | Provide a copyable exact-root control without changing root text | PROPOSED:mvc | copied bytes equal canonical lowercase root |
| C196 | Preserve typed service error message in controller response | c23-controller-route | injected refusal is not rewritten as generic success |
| C197 | Add view pagination empty-state that does not imply global absence | PROPOSED:mvc | empty local board explicitly states local scope |
| C198 | Make a view refresh rebuild only derived projection data | PROPOSED:mvc | immutable receipts remain byte-identical after refresh |
| C199 | Add a task compare view keyed by same task and different candidates | PROPOSED:mvc | cross-task candidates cannot be compared as matched pair |
| C200 | Add an end-to-end UX fixture from task choice through exact result review | PROPOSED:mvc | task, template, acceptance, evidence, review and cost roots align |

### C201–C225: consensus and chain validation

Exemplars: `core/consensus/src/check_block.c`; `core/modules/validation/src/check_transaction.c`.

| ID | Task type / inclusion | Kind | Verifier |
|---|---|---|---|
| C201 | Add a boundary vector for a consensus transaction field | PROPOSED:consensus | parity vector matches reference node at boundary values |
| C202 | Preserve consensus predicate while rejecting arithmetic overflow | PROPOSED:consensus | overflow vectors reject; reference-valid vectors unchanged |
| C203 | Add differential fixture for block header validation | PROPOSED:consensus | exact header verdict matches pinned reference corpus |
| C204 | Verify transaction-input allocation bounds without changing consensus admission | PROPOSED:consensus | reference-derived valid boundaries execute safely; reference-invalid sizes and arithmetic overflow refuse with valid verdicts unchanged |
| C205 | Validate coinbase height encoding at activation boundary | PROPOSED:consensus | pre/post-activation vectors match reference behavior |
| C206 | Preserve script error mapping for malformed opcode sequence | PROPOSED:consensus | exact reference error and transaction verdict match |
| C207 | Add regression for duplicate transaction inputs | PROPOSED:consensus | duplicate-spend vectors match reference rejection |
| C208 | Verify target compact encoding edge cases | PROPOSED:consensus | canonical and noncanonical target vectors match reference |
| C209 | Verify serialized block-size admission at the ZClassic limit | PROPOSED:consensus | exact-limit and over-limit vectors match the pinned reference node |
| C210 | Validate contextual timestamp rule against neighboring blocks | PROPOSED:consensus | timestamp window vectors match reference node |
| C211 | Preserve shielded commitment tree append order | PROPOSED:consensus | pinned roots remain byte-identical over fixture sequence |
| C212 | Add malformed Equihash block-header solution parity vectors | PROPOSED:consensus | altered solution vectors match pinned reference validity; valid header corpus remains accepted |
| C213 | Check subsidy halving arithmetic at exact epoch boundary | PROPOSED:consensus | subsidy outputs match reference at boundary heights |
| C214 | Add transaction lock-time semantics vector | PROPOSED:consensus | locktime boundary verdict matches reference corpus |
| C215 | Verify sighash serialization for one supported script mode | PROPOSED:consensus | digest matches independent pinned vector |
| C216 | Verify block admission for duplicate transaction identifiers | PROPOSED:consensus | production admission matches pinned reference verdict and rejection reason |
| C217 | Make validation refusal preserve chain state transactionally | PROPOSED:consensus | invalid block leaves frontier and DB snapshot unchanged |
| C218 | Add activation-height fork-choice comparison fixture | PROPOSED:consensus | chain selection matches reference on both sides of boundary |
| C219 | Validate merkle root mutation and odd-leaf duplication rules | PROPOSED:consensus | all leaf-count vectors match reference roots |
| C220 | Add transparent input prevout and script binding parity vectors | PROPOSED:consensus | altered prevout and script vectors match pinned reference validity |
| C221 | Preserve dependency-respecting transaction order in block assembly | PROPOSED:consensus | child-before-parent fixture refuses or reorders under the assembly contract; produced block passes pinned reference validation |
| C222 | Add reorg rollback fixture crossing one activation boundary | PROPOSED:consensus | old and new branch state match reference replay |
| C223 | Add shielded JoinSplit proof binding parity vectors | PROPOSED:consensus | altered proof public inputs match pinned reference validity |
| C224 | Add fixed-width chain parameter parsing with invalid-network refusal | PROPOSED:consensus | unknown network cannot inherit default parameters |
| C225 | Confirm consensus core changes with full parity acceptance | PROPOSED:consensus | exact reference comparison passes; unit test alone is insufficient |

### C226–C250: wallet and custody state

Exemplars: `contexts/wallet/services/src/wallet_backup_service.c`; `contexts/wallet/services/src/vault_read.c`.

| ID | Task type / inclusion | Kind | Verifier |
|---|---|---|---|
| C226 | Reject wallet export request without explicit owner authorization | PROPOSED:custody | unauthorized fixture exports zero key bytes |
| C227 | Ensure secret key bytes never enter structured diagnostics | PROPOSED:custody | sentinel secret absent from logs, replies, and crash fields |
| C228 | Add atomic wallet transaction update with rollback on storage failure | PROPOSED:custody | injected commit failure restores prior wallet state |
| C229 | Validate derivation path components before key derivation | PROPOSED:custody | malformed and out-of-range paths refuse |
| C230 | Prevent spend creation from an unverified chain tip | PROPOSED:custody | stale/unverified tip fixture cannot create signed spend |
| C231 | Add explicit network identity binding to address decode | PROPOSED:custody | cross-network address is refused, not remapped |
| C232 | Preserve wallet encryption parameters on metadata-only save | PROPOSED:custody | encrypted payload bytes remain unchanged |
| C233 | Reject duplicate wallet key identifiers with different key material | PROPOSED:custody | conflict refuses and original key remains intact |
| C234 | Ensure failed unlock attempt does not leak key-dependent detail | PROPOSED:custody | wrong-key result and timing contract reveal no secret distinction |
| C235 | Add bounded scan cursor bound to wallet and chain roots | PROPOSED:custody | cursor from another wallet or chain refuses |
| C236 | Make wallet backup manifest include exact encrypted object roots | PROPOSED:custody | independent restore recomputes all listed roots |
| C237 | Refuse restore when backup network or schema identity differs | PROPOSED:custody | mismatched identity leaves wallet unopened and unchanged |
| C238 | Guard balance aggregation against signed and unsigned overflow | PROPOSED:custody | maximum and overflow balance fixtures are correct/refused |
| C239 | Ensure address-book display fields cannot affect signing preimage | PROPOSED:custody | metadata mutation preserves signing bytes and tx root |
| C240 | Add a spend confirmation showing exact recipients and fee | PROPOSED:custody | displayed values rederive from exact transaction bytes |
| C241 | Keep private key operation inside the wallet service boundary | PROPOSED:custody | controller/view never receives secret material |
| C242 | Require fresh authorization for key export after idle timeout | PROPOSED:custody | expired session cannot export; renewed authorization can |
| C243 | Add deterministic locked-wallet refusal for signing operation | PROPOSED:custody | locked fixture emits no signature and preserves state |
| C244 | Make wallet database migration copy-first and recoverable | PROPOSED:custody | crash injection restores old DB or complete new DB |
| C245 | Prevent telemetry from counting secret material as task context | PROPOSED:custody | sentinel never appears in prompt/evidence accounting record |
| C246 | Add exact transaction replay prevention to wallet submission queue | PROPOSED:custody | duplicate submit does not create a second spend action |
| C247 | Verify shielded note witness against exact tree root before spend | PROPOSED:custody | stale witness refuses; refreshed witness binds current root |
| C248 | Refuse background wallet scan when custody lock is unavailable | PROPOSED:custody | concurrent lock fixture yields no unsynchronized write |
| C249 | Add an owner-visible audit receipt for a key-management action | PROPOSED:custody | receipt binds actor, action, and result without key bytes |
| C250 | Test wallet recovery with encrypted fixture and no production datadir | PROPOSED:custody | isolated restore verifies funds state without external access |

### C251–C275: P2P transport and protocol handling

Exemplars: `core/modules/net/src/download.c`; `contexts/commons/modules/vcs/src/package_swarm.c`.

| ID | Task type / inclusion | Kind | Verifier |
|---|---|---|---|
| C251 | Reject oversized peer frame before allocating payload | PROPOSED:network | cap-plus-one frame closes/refuses without allocation spike |
| C252 | Validate peer message version before dispatch | PROPOSED:network | unsupported version receives typed refusal |
| C253 | Bound per-peer outstanding request count | PROPOSED:network | saturated peer cannot exceed configured request cap |
| C254 | Add timeout cleanup for incomplete chunk transfer | PROPOSED:network | expired session releases chunks and request slot |
| C255 | Verify received object root before advertising it locally | PROPOSED:network | tampered object is never indexed or advertised |
| C256 | Preserve task-root expectation across swarm pointer resolution | PROPOSED:network | cross-task pointer result is rejected by receiver |
| C257 | Reject replayed signed peer response outside request window | PROPOSED:network | stale response cannot complete fresh request |
| C258 | Add bounded backoff for unavailable peer endpoint | PROPOSED:network | retries stay within attempt and time limits |
| C259 | Keep peer status observation separate from proof acceptance | PROPOSED:network | peer-reported success cannot create accepted receipt |
| C260 | Validate authenticated peer identity against transport session | PROPOSED:network | identity mismatch aborts before object publication |
| C261 | Make partial response pagination resume from exact root cursor | PROPOSED:network | wrong-root cursor refuses and correct cursor has no gap |
| C262 | Prevent duplicate peer advertisements from inflating availability | PROPOSED:network | repeated same signer/root counts once |
| C263 | Add request cancellation cleanup on peer disconnect | PROPOSED:network | disconnect clears pending request and temporary objects |
| C264 | Enforce response byte budget on untrusted peer payload | PROPOSED:network | over-budget peer data is refused before decode |
| C265 | Separate transport receipt from build or test evidence | PROPOSED:network | transport receipt alone leaves proof state unchanged |
| C266 | Add exact-root audit for fetched task wire and context | PROPOSED:network | fetched bytes and derived roots match requested identities |
| C267 | Reject conflicting signed records without last-writer-wins | PROPOSED:network | two valid conflicting records remain distinct and visible |
| C268 | Bound DHT query fanout and result count | PROPOSED:network | query stays within declared request and response caps |
| C269 | Prevent unauthenticated endpoint from consuming long-lived session slot | PROPOSED:network | unauthenticated flood cannot retain session capacity |
| C270 | Retry only missing chunks after transfer interruption | PROPOSED:network | completed chunks are not retransmitted in fixture |
| C271 | Label outbound peer progress with its observational evidence scope | PROPOSED:network | serialized progress identifies its source and cannot encode an acceptance verdict |
| C272 | Add network partition recovery for exact content root lookup | PROPOSED:network | after reconnection exact object is fetched and verified |
| C273 | Preserve query coverage in an empty peer-discovery response | PROPOSED:network | protocol response distinguishes contacted peers, failures and incomplete coverage |
| C274 | Add receive-window bound against unbounded out-of-order chunks | PROPOSED:network | beyond-window chunk refuses without buffer growth |
| C275 | Verify transport cleanup after malformed signed envelope | PROPOSED:network | no peer session, file, or request remains after refusal |

### C276–C300: cryptography and signing

Exemplars: `core/modules/crypto/src/ed25519.c`; `contexts/commons/modules/vcs/src/proof_signature.c`.

| ID | Task type / inclusion | Kind | Verifier |
|---|---|---|---|
| C276 | Add a known-answer hash vector for a domain-separated object root | PROPOSED:crypto | independent implementation agrees on exact digest |
| C277 | Reject noncanonical scalar before signature verification | PROPOSED:crypto | boundary scalars accept/reject per curve contract |
| C278 | Make signature verification distinguish malformed key from bad signature | PROPOSED:crypto | two refusal classes return documented result codes |
| C279 | Add deterministic signature serialization fixture | PROPOSED:crypto | repeated output matches pinned bytes where scheme requires |
| C280 | Validate public-key encoding before cryptographic API call | PROPOSED:crypto | malformed encoding refuses without backend invocation |
| C281 | Prevent secret scalar from appearing in error logging | PROPOSED:crypto | sentinel secret absent from captured diagnostics |
| C282 | Qualify fixed-length secret-tag comparison against timing leakage | PROPOSED:crypto | source and generated-code audit for exact compiler/target plus bounded side-channel experiment; functional mismatch-position tests alone do not prove constant time |
| C283 | Check entropy API failure propagates without weak fallback | PROPOSED:crypto | injected RNG failure produces no key or signature |
| C284 | Verify signature domain separation prevents cross-object reuse | PROPOSED:crypto | signature for one domain fails in another |
| C285 | Bound batch verification input count and allocation | PROPOSED:crypto | count over cap refuses before backend operation |
| C286 | Add a malformed DER or compact signature rejection corpus | PROPOSED:crypto | every malformed fixture rejects deterministically |
| C287 | Preserve cryptographic backend error context without secret bytes | PROPOSED:crypto | failure code retained and sensitive buffers absent |
| C288 | Verify key zeroization on all early-return paths | PROPOSED:crypto | instrumented fixture observes cleared secret buffers |
| C289 | Reject duplicate signer identity in a threshold signature set | PROPOSED:crypto | repeated signer contributes once or set refuses |
| C290 | Add cross-platform vector for endian-sensitive digest input | PROPOSED:crypto | Linux and macOS vector roots are byte-identical |
| C291 | Validate BLS aggregate member ordering and duplicate policy | PROPOSED:crypto | permutations normalize; duplicate signer is rejected |
| C292 | Add Ed25519 invalid-point handling vector | PROPOSED:crypto | invalid point and small-order fixtures refuse |
| C293 | Prevent signature API from accepting implicit zero-length message | PROPOSED:crypto | zero-length behavior is explicit and tested |
| C294 | Add checked buffer sizing for encoded signature output | PROPOSED:crypto | undersized output returns required size without overwrite |
| C295 | Ensure crypto initialization failure blocks dependent operation | PROPOSED:crypto | failed init cannot reach sign/verify backend |
| C296 | Separate key identifier from key authorization decision | PROPOSED:crypto | known key without policy authority is refused |
| C297 | Add tamper test for signed receipt canonical bytes | PROPOSED:crypto | one-byte mutation fails signature and root check |
| C298 | Verify random nonce uniqueness contract for signing mode | PROPOSED:crypto | deterministic test source catches repeated nonce fixture |
| C299 | Add fuzz corpus seed for the public signature decoder | PROPOSED:crypto | seeds run under registered harness without crash |
| C300 | Verify algorithm negotiation cannot downgrade required signature scheme | PROPOSED:crypto | weaker offered scheme is refused by policy fixture |

### C301–C325: chain synchronization and reducer state

Exemplars: `core/modules/sync/src/sync_reduce.c`; `engine/reducer/jobs/src/reducer_frontier.c`.

| ID | Task type / inclusion | Kind | Verifier |
|---|---|---|---|
| C301 | Add bounded header batch admission before chain work scheduling | PROPOSED:sync | oversized batch refused without queue growth |
| C302 | Preserve chain frontier on interrupted block validation | PROPOSED:sync | injected failure leaves frontier root unchanged |
| C303 | Reject sync response whose parent root differs from requested branch | PROPOSED:sync | wrong-parent response cannot advance reducer |
| C304 | Add deterministic tie-break for equal-work candidate tips | PROPOSED:sync | equal-work fixture selects contract-defined branch |
| C305 | Ensure reducer applies one block transaction atomically | PROPOSED:sync | failure at each stage rolls back all state |
| C306 | Bound orphan-block storage by count and bytes | PROPOSED:sync | pressure fixture evicts/refuses per policy |
| C307 | Add restart recovery for a committed chain-state checkpoint | PROPOSED:sync | restart reloads exact frontier and replays no duplicate block |
| C308 | Prevent duplicate block delivery from applying twice | PROPOSED:sync | repeated block leaves state root unchanged after first apply |
| C309 | Validate checkpoint root before pruning prior undo data | PROPOSED:sync | mismatched checkpoint refuses prune |
| C310 | Add reorg fixture with rollback depth at configured bound | PROPOSED:sync | boundary reorg succeeds; over-bound path follows refusal contract |
| C311 | Ensure peer sync progress does not imply local block verification | PROPOSED:sync | reported height cannot alter verified frontier |
| C312 | Separate header availability from fully validated chain state | PROPOSED:sync | header-only fixture is not rendered as serving chain tip |
| C313 | Add backpressure when reducer queue reaches byte limit | PROPOSED:sync | producer is bounded and resumes after drain |
| C314 | Verify database write ordering around reducer checkpoint | PROPOSED:sync | crash points recover either prior or complete new checkpoint |
| C315 | Prevent stale status cache from reporting newer chain height | PROPOSED:sync | stale cache triggers exact frontier reload |
| C316 | Add state-root parity vector after a fixed block sequence | PROPOSED:sync | independent replay yields same final state root |
| C317 | Refuse block application before required chain params are loaded | PROPOSED:sync | missing params fail closed before mutation |
| C318 | Bound peer-provided locator length during sync negotiation | PROPOSED:sync | oversized locator rejected before traversal |
| C319 | Add disconnect recovery preserving verified downloaded blocks | PROPOSED:sync | reconnect resumes from verified exact object roots |
| C320 | Ensure transaction pool revalidation follows reorg state | PROPOSED:sync | included/conflicting transactions update per contract |
| C321 | Avoid blocking chain advancement on package-work activity | PROPOSED:sync | contention fixture proves chain lane retains priority |
| C322 | Add sync stage telemetry with stable stage enum and no inferred completion | PROPOSED:sync | stage transitions follow verified events only |
| C323 | Verify snapshot import against network genesis and frontier roots | PROPOSED:sync | wrong-network and wrong-frontier snapshots refuse |
| C324 | Make snapshot export fail safely when atomic file primitive unavailable | PROPOSED:sync | unsupported host reports unavailable without partial file |
| C325 | Add end-to-end sync acceptance on isolated consenting peers | PROPOSED:sync | receiver independently reaches exact expected chain state |

### C326–C350: platform seams and portability

Exemplars: `engine/composition/platform/macos_capabilities.def`; `core/modules/net/src/download.c`.

| ID | Task type / inclusion | Kind | Verifier |
|---|---|---|---|
| C326 | Add a POSIX implementation behind an existing platform port | PROPOSED:platform | Linux build and focused behavior contract pass |
| C327 | Add a native macOS implementation without Linux VM dependency | PROPOSED:platform | native arm64 build and platform contract pass |
| C328 | Return explicit unavailable for unsupported descriptor execution | PROPOSED:platform | unsupported-host fixture refuses without pathname fallback |
| C329 | Normalize platform error codes into stable product result | PROPOSED:platform | injected OS errors map to documented result enum |
| C330 | Bound platform thread stack use for background scan | PROPOSED:platform | measured stack remains within declared cap under fixture |
| C331 | Add checked conversion for platform file offset width | PROPOSED:platform | maximum representable and overflow values are asserted |
| C332 | Preserve file permissions during atomic replacement | PROPOSED:platform | mode and special bits match declared contract after replace |
| C333 | Prevent symlink traversal in platform directory walk | PROPOSED:platform | symlink escape fixture is rejected |
| C334 | Add platform clock wrapper with monotonic deadline semantics | PROPOSED:platform | wall-clock jump does not extend monotonic timeout |
| C335 | Ensure signal handler uses only async-signal-safe operations | PROPOSED:platform | source audit and signal fixture match allowed contract |
| C336 | Add native filesystem watcher with bounded event queue | PROPOSED:platform | overflow produces explicit rescan requirement |
| C337 | Report capability availability from actual host probe | PROPOSED:platform | mocked unavailable capability is never advertised present |
| C338 | Add compiler feature gate for a C23 facility with fallback | PROPOSED:platform | supported and fallback paths compile with strict flags |
| C339 | Remove platform-specific integer format assumption | PROPOSED:platform | format output matches type on Linux and macOS |
| C340 | Ensure platform temp-file creation is private and collision-safe | PROPOSED:platform | concurrent fixture yields isolated files and cleanup |
| C341 | Add Windows guarded implementation for a shared file contract | PROPOSED:platform | native Windows build and contract test pass |
| C342 | Replace pathname identity check with descriptor-bound object check | PROPOSED:platform | rename/symlink race fixture cannot swap verified object |
| C343 | Add CPU feature dispatch with portable C23 fallback | PROPOSED:platform | forced fallback and accelerated path produce same bytes |
| C344 | Prevent platform thread QoS failure from changing correctness | PROPOSED:platform | QoS refusal preserves function result and logs capability |
| C345 | Bound OS process enumeration and tolerate disappearing process | PROPOSED:platform | race fixture returns partial/typed absence, no crash |
| C346 | Add resource-limit setup with readback verification | PROPOSED:platform | unsupported or failed limit is not claimed enforced |
| C347 | Make directory fsync behavior explicit across platform ports | PROPOSED:platform | crash-recovery fixture matches documented availability |
| C348 | Add a portable secure random source wrapper | PROPOSED:platform | provider failure refuses key generation, no weak fallback |
| C349 | Verify platform dynamic dependency allowlist | PROPOSED:platform | binary audit rejects unexpected non-system dependency |
| C350 | Add a strict C23 compile profile for one platform seam | PROPOSED:platform | compiler uses C23 and all warnings are errors |

### C351–C375: package build, reuse, and reproduction

Exemplars: `contexts/commons/modules/vcs/src/package_build.c`; `contexts/commons/modules/vcs/src/package_reproduce.c`.

| ID | Task type / inclusion | Kind | Verifier |
|---|---|---|---|
| C351 | Reject package manifest path outside declared workspace root | PROPOSED:package | traversal fixture is refused before file open |
| C352 | Verify package file bytes against manifest before build | PROPOSED:package | changed source file fails exact content check |
| C353 | Bound package build CPU, memory, output, and wall time | PROPOSED:package | over-limit fixture terminates with typed limit result |
| C354 | Ensure package build cannot access undeclared network | PROPOSED:package | network probe fails inside bounded execution |
| C355 | Reproduce package from exact source, lock, toolchain, and recipe roots | PROPOSED:package | independent output root matches expected reproducibility contract |
| C356 | Add dependency-lock validation for missing package root | PROPOSED:package | absent dependency refuses before compiler launch |
| C357 | Preserve exact compiler and flags in build action identity | PROPOSED:package | changing either changes derived action root |
| C358 | Keep package metadata inspection separate from bounded build execution | PROPOSED:package | metadata-inspection trace starts no compiler or package process; explicit build has a separate lifecycle action |
| C359 | Add deterministic archive ordering and timestamps | PROPOSED:package | repeated archive bytes are identical |
| C360 | Reject executable bit escalation outside manifest policy | PROPOSED:package | unauthorized mode change fails before install |
| C361 | Verify build receipt binds output root and proof policy | PROPOSED:package | altered output or policy invalidates receipt |
| C362 | Make package install plan refuse file collision by default | PROPOSED:package | collision fixture leaves existing file unchanged |
| C363 | Add rollback for interrupted package installation | PROPOSED:package | crash injection restores old package or complete new package |
| C364 | Reuse an exact cached package artifact only after receiver verification | PROPOSED:package | cache hit is reverified; corrupted cache is rejected |
| C365 | Add a package reproduction fixture on a second native host | PROPOSED:package | second host independently derives matching source/output roots |
| C366 | Keep private workspace paths out of public package metadata | PROPOSED:package | sentinel absolute path absent from serialized package |
| C367 | Enforce license metadata and license-file consistency | PROPOSED:package | mismatch refuses publication with explicit cause |
| C368 | Bound dependency graph traversal and report cycle path | PROPOSED:package | cycle fixture reports exact cycle without unbounded recursion |
| C369 | Verify installed package launch uses accepted artifact root | PROPOSED:package | substituted executable root refuses before launch |
| C370 | Add an uninstall plan that names exact owned files | PROPOSED:package | unrelated sentinel files are not deleted |
| C371 | Separate package verification receipt from user acceptance | PROPOSED:package | verified-only fixture remains unaccepted |
| C372 | Add offline package build using only exact cached dependencies | PROPOSED:package | missing cache object fails without network fallback |
| C373 | Prevent compiler output symlink from escaping build directory | PROPOSED:package | symlink output fixture is refused |
| C374 | Add package release envelope verification for publisher identity | PROPOSED:package | altered signer or sequence is rejected |
| C375 | Measure end-to-end package build and reproduction resource components | PROPOSED:package | receipt reports measured values with unknowns separated |

### C376–C400: diagnostics, telemetry, and observability

Exemplars: `engine/modules/metrics/src/metrics.c`; `contexts/commons/services/src/zcode_telemetry_fill.c`.

| ID | Task type / inclusion | Kind | Verifier |
|---|---|---|---|
| C376 | Add a diagnostic field derived from verified runtime state | c23-telemetry-field | fixture state and emitted field agree exactly |
| C377 | Mark missing telemetry as unknown rather than numeric zero | c23-telemetry-field | absent source produces explicit unknown state |
| C378 | Bind telemetry sample to host, time window, and source root | PROPOSED:telemetry | sample without any identity field is rejected |
| C379 | Prevent counters from wrapping silently at integer maximum | PROPOSED:telemetry | near-limit increment saturates or errors per contract |
| C380 | Add bounded cardinality labels to a runtime metric | c23-telemetry-field | arbitrary task text cannot create unbounded label values |
| C381 | Keep model token usage separate from currency cost | PROPOSED:telemetry | report fields never label tokens as spend |
| C382 | Attribute review and repair effort to the original task root | PROPOSED:telemetry | linked attempt graph includes review and repair rows |
| C383 | Avoid double counting shared-root attempts in rollup | PROPOSED:telemetry | duplicate event fixture contributes once under rule |
| C384 | Report partial-day metrics with explicit observation interval | PROPOSED:telemetry | truncated window is not labeled a full-day total |
| C385 | Add schema version and migration for telemetry event | PROPOSED:telemetry | old/new records decode with explicit version handling |
| C386 | Exclude secret-bearing request fields from telemetry payload | c23-telemetry-field | sentinel is absent after full serialization |
| C387 | Preserve event signer identity alongside immutable result root | PROPOSED:telemetry | unsigned or mismatched signer row is not accepted as evidence |
| C388 | Distinguish attempted, failed, reviewed, accepted, and landed outcomes | PROPOSED:telemetry | one fixture produces distinct stage counts |
| C389 | Make latency measure identify start/stop event definitions | PROPOSED:telemetry | synthetic event pair calculates declared interval only |
| C390 | Surface missing cost components in aggregate denominator | PROPOSED:telemetry | incomplete records remain visible as unknown coverage |
| C391 | Add deterministic export of telemetry rows by exact root | PROPOSED:telemetry | repeated export has stable ordering and bytes |
| C392 | Refuse to combine records from incompatible accounting schemas | PROPOSED:telemetry | mixed-version input requires explicit conversion |
| C393 | Keep local observations distinct from replicated signed receipts | PROPOSED:telemetry | local-only event never appears as peer-verified result |
| C394 | Add anomaly flag for impossible negative duration or token count | c23-telemetry-field | malformed measurement is quarantined from rollup |
| C395 | Recompute rollup from immutable input records after crash | PROPOSED:telemetry | rebuild is deterministic and matches saved projection |
| C396 | Add audit trail for metric correction without rewriting old event | PROPOSED:telemetry | correction links prior root and preserves original bytes |
| C397 | Report exact sample size and excluded-record count per metric | PROPOSED:telemetry | denominator fixture matches hand-calculated inclusion set |
| C398 | Bound metrics response size under large fleet membership | PROPOSED:telemetry | maximum-node fixture stays within response cap |
| C399 | Verify dashboard values against canonical read-only command output | PROPOSED:telemetry | view fields match same-window command evidence |
| C400 | Add a forecast refusal reason when duration history is absent | c23-telemetry-field | no linked duration yields unknown forecast with reason |

### C401–C425: build system, test registration, and native generator

Exemplars: `tools/dev/devloop_app_slice.c`; `tools/dev/devloop_app_scaffold.c`.

| ID | Task type / inclusion | Kind | Verifier |
|---|---|---|---|
| C401 | Add a typed source-slice preview for a recurring native C23 change | c23-source-generator | preview names exact files and registered verifier route |
| C402 | Make generator refuse a destination file collision | c23-source-generator | existing bytes survive collision unchanged |
| C403 | Ensure preview bytes equal materialized bytes | c23-source-generator | hash of preview equals resulting file bytes |
| C404 | Add idempotency for repeated scaffold materialization | c23-source-generator | second run changes no bytes or timestamps unnecessarily |
| C405 | Generate test-group registration with matching source fixture | c23-source-generator | catalog lists group and runner executes generated test |
| C406 | Keep generated output ordinary reviewable C23 source | c23-source-generator | no runtime template dependency appears in output |
| C407 | Add model/service/test scaffold under existing MVC owners | PROPOSED:generator | generated save lifecycle, result handling, and test compile |
| C408 | Add native command scaffold with schema and failure response | PROPOSED:generator | navigator lists leaf and malformed request refuses clearly |
| C409 | Add parser boundary scaffold with cap and overflow checks | PROPOSED:generator | generated cases cover zero, max, and over-limit |
| C410 | Refuse generator selection when ownership map has no source owner | PROPOSED:generator | unknown path yields refusal, no arbitrary file emitted |
| C411 | Bind generator plan to source-map and test-catalog versions | PROPOSED:generator | changed map or catalog invalidates stale plan |
| C412 | Keep generator from emitting consensus-core edits by default | PROPOSED:generator | protected path requires existing owner-authorized task contract |
| C413 | Add cleanup behavior for interrupted multi-file scaffold | PROPOSED:generator | injected failure leaves all-or-none materialization |
| C414 | Generate an explicit unsupported-platform branch with test | PROPOSED:generator | unsupported host returns unavailable rather than false success |
| C415 | Ensure generator creates no duplicate include or symbol registration | PROPOSED:generator | repeated selected slice compiles without duplicate definition |
| C416 | Add a source template for logged typed refusal paths | PROPOSED:generator | generated failure path has result code and context log |
| C417 | Add a template for transactional multi-model save path | PROPOSED:generator | injected failure proves rollback and callback lifecycle |
| C418 | Generate mutation fixture that fails only at production boundary | PROPOSED:generator | helper-only mutation is rejected by acceptance |
| C419 | Add preview UX explaining selected template and verifier | PROPOSED:generator | preview names kind, exact scope, and test group |
| C420 | Make template version explicit in generated task receipt | PROPOSED:generator | receipt contains exact template SHA3 and selection kind |
| C421 | Keep prompt fixed prefix byte-stable for matched cache cohort | PROPOSED:generator | prefix identity stable; task text remains after fixed sections |
| C422 | Add fixture for unknown prompt kind refusal without fallback | PROPOSED:generator | unknown kind exits nonzero with no default prompt selection |
| C423 | Verify C23 mode and warning flags in generated compile command | PROPOSED:generator | captured command selects C23 and warnings-as-errors |
| C424 | Add generated documentation entry for new command schema | PROPOSED:generator | generated API reference includes exact registered command |
| C425 | Confirm native generator extension is consumed by existing build path | PROPOSED:generator | canonical build target compiles generated source and test |

### C426–C450: security policy, capability and authorization

Exemplars: `engine/composition/capability_classes.def`; `engine/composition/module_capabilities.def`.

| ID | Task type / inclusion | Kind | Verifier |
|---|---|---|---|
| C426 | Add a least-privilege capability declaration for one source owner | PROPOSED:security | capability gate matches declared syscall/file use |
| C427 | Remove undeclared filesystem capability from a read-only module | PROPOSED:security | static capability audit reports no write authority |
| C428 | Ensure protected mutation checks authority before side effects | PROPOSED:security | unauthorized fixture produces no observable mutation |
| C429 | Add a typed refusal for absent owner approval | PROPOSED:security | missing approval denies regardless of model profile |
| C430 | Bind approval to exact candidate root and action scope | PROPOSED:security | approval for another root or scope is refused |
| C431 | Enforce capability denial for execution from an inspection-only context | PROPOSED:security | direct execution request under inspection capability is refused even when package bytes are present |
| C432 | Add explicit sandbox capability probe and fail-closed result | PROPOSED:security | unavailable mechanism is not labeled isolated |
| C433 | Enforce path allowlist at open time using descriptor-relative API | PROPOSED:security | rename/symlink race cannot escape root |
| C434 | Reject environment variable override for a protected state path | PROPOSED:security | hostile environment cannot redirect production path |
| C435 | Redact credentials from nested error and telemetry structures | PROPOSED:security | sentinel secret absent from every serialized channel |
| C436 | Add bounded privilege separation for package execution helper | PROPOSED:security | child has only declared descriptors and capabilities |
| C437 | Ensure signature identity alone does not imply accepted computation | PROPOSED:security | signed unsupported evidence remains unaccepted |
| C438 | Prevent local admission observation from becoming global authorization | PROPOSED:security | admission-only fixture cannot authorize protected action |
| C439 | Verify owner decision is required for deployment and custody operation | PROPOSED:security | each protected route refuses absent owner action |
| C440 | Add replay-resistant nonce to an authorization receipt | PROPOSED:security | repeated nonce cannot authorize second action |
| C441 | Bound policy parser behavior for unknown future policy fields | PROPOSED:security | unknown authority field is refused or preserved explicitly |
| C442 | Keep sandbox execution separate from installation and launch | PROPOSED:security | build/test completion cannot trigger install side effect |
| C443 | Add audit event for policy denial without leaking input secrets | PROPOSED:security | denial is attributable; secret sentinel is absent |
| C444 | Make policy version part of exact proof-policy root | PROPOSED:security | policy-byte change changes proof-policy identity |
| C445 | Detect capability declaration drift against source tree | PROPOSED:security | omitted or extra source owner is reported by lint |
| C446 | Ensure cleanup runs after sandbox timeout and process kill | PROPOSED:security | no child, mount, temp file, or lease remains |
| C447 | Reject unsigned peer control message before state transition | PROPOSED:security | invalid signature leaves local state unchanged |
| C448 | Validate authenticated peer identity before accepting replicated object | PROPOSED:security | wrong identity cannot write local projection |
| C449 | Add explicit data-retention bound for diagnostic payload | PROPOSED:security | expired fixture is removed under documented policy |
| C450 | Review a protected-path change with independent exact-candidate proof | PROPOSED:security | review signer differs from candidate author/proposal worker; independent proof and review bind the same candidate source root |

### C451–C475: registry, configuration, errors and lifecycle

Exemplars: `engine/composition/commands/zcode.def`; `engine/composition/roles.def`.

| ID | Task type / inclusion | Kind | Verifier |
|---|---|---|---|
| C451 | Add a command registry leaf without duplicate canonical name | c23-registry-entry | catalog parser accepts one unique leaf |
| C452 | Validate alias target exists and resolves to same behavior | c23-registry-entry | dangling alias fails lint; valid alias schema matches |
| C453 | Add a configuration key with explicit default and validation | PROPOSED:registry | absent/default/invalid inputs produce documented values |
| C454 | Reject unknown configuration enum instead of silently defaulting | PROPOSED:registry | typo fixture returns explanatory refusal |
| C455 | Make configuration reload atomic across dependent settings | PROPOSED:registry | invalid second setting leaves prior config intact |
| C456 | Add a schema compatibility check before opening persisted state | PROPOSED:registry | unsupported schema refuses before writes |
| C457 | Keep error code stable while improving user-facing message | PROPOSED:registry | API contract test preserves code and checks message |
| C458 | Add structured context to an error return in one function | PROPOSED:registry | injected failure identifies operation and exact object |
| C459 | Ensure every allocation failure path returns explanatory result | PROPOSED:registry | allocator fault injection covers each allocation site |
| C460 | Add cleanup label/order for multi-resource function exits | PROPOSED:registry | fault injection at each stage leaves no resource open |
| C461 | Replace magic result integer with owned enum contract | PROPOSED:registry | all call sites compile and enum cases are exhaustive |
| C462 | Add unknown-field compatibility policy to a versioned input schema | PROPOSED:registry | old/new version fixtures follow exact policy |
| C463 | Prevent command schema and implementation parameter drift | PROPOSED:registry | schema-to-handler parity gate detects omitted field |
| C464 | Add deterministic ordering to generated command reference | PROPOSED:registry | regenerated reference has no diff after second run |
| C465 | Ensure registry failure sets native response body and code | PROPOSED:registry | malformed registry fixture returns nonempty error |
| C466 | Add lifecycle shutdown path that drains owned workers | PROPOSED:registry | shutdown waits/terminates per policy and leaves no worker |
| C467 | Make cancellation token propagate through nested service calls | PROPOSED:registry | cancellation reaches child before bounded deadline |
| C468 | Reject double initialization of a singleton-owned resource | PROPOSED:registry | second init returns explicit state error without leak |
| C469 | Add restart-safe cleanup for stale temporary artifacts | PROPOSED:registry | only owned stale artifacts removed; unrelated files remain |
| C470 | Ensure error formatter bounds output and escapes control bytes | PROPOSED:registry | maximal/control input produces valid bounded response |
| C471 | Add compile-time assertion for wire and struct size contract | PROPOSED:registry | strict C23 build catches deliberate size mutation |
| C472 | Replace unchecked narrowing cast at configuration boundary | PROPOSED:registry | signed and width boundary fixtures are exact |
| C473 | Keep API response version explicit during schema evolution | PROPOSED:registry | old client fixture sees supported version behavior |
| C474 | Add a deprecation path that preserves current accepted behavior | c23-registry-entry | old alias warns and still maps to documented target |
| C475 | Remove an obsolete registry entry after caller and test audit | c23-registry-entry | navigator references are absent and replacement route passes |

### C476–C500: distributed work identity, replication and recovery

Exemplars: `contexts/commons/modules/vcs/src/zcode_work_node_state.c`; `contexts/commons/modules/vcs/src/zcode_task_index.c`.

| ID | Task type / inclusion | Kind | Verifier |
|---|---|---|---|
| C476 | Replicate an immutable taxonomy catalog by exact content root | PROPOSED:federation | receiver re-derives root and records source version |
| C477 | Keep local SQL task index rebuildable from verified task wires | PROPOSED:federation | delete/rebuild index yields same exact-root rows |
| C478 | Distinguish task root from mutable local task status projection | PROPOSED:federation | projection update cannot change task root |
| C479 | Replicate candidate source and manifest without trusting sender summary | PROPOSED:federation | receiver hashes all bytes and validates candidate root |
| C480 | Bind action input root to task, candidate, acceptance, and toolchain | PROPOSED:federation | mismatch in any bound field changes/refuses action root |
| C481 | Replicate signed receipt and verify signer and exact action roots | PROPOSED:federation | invalid signer or cross-action receipt is rejected |
| C482 | Keep the local board projection's empty state scoped to observed roots | PROPOSED:federation | view labels its local index and freshness without a global-none claim |
| C483 | Handle duplicate immutable object delivery idempotently | PROPOSED:federation | duplicate transfer yields one byte-identical object |
| C484 | Preserve two conflicting valid signed observations without overwrite | PROPOSED:federation | both roots remain visible with conflict marker |
| C485 | Refuse to merge leases using last-writer-wins timestamps | PROPOSED:federation | concurrent lease fixture requires explicit scope rule |
| C486 | Recover task evidence index after node restart and peer loss | PROPOSED:federation | local rebuild finds verified receipts or marks missing |
| C487 | Resume partial replication without treating partial object as present | PROPOSED:federation | incomplete transfer stays unavailable until root verifies |
| C488 | Bind replicated observation to signer, action, and source time | PROPOSED:federation | missing provenance prevents acceptance as evidence |
| C489 | Keep process-local admission distinct from durable global work result | PROPOSED:federation | admission alone cannot advance accepted state |
| C490 | Reject progress events as inputs to receiver completion admission | PROPOSED:federation | even validly signed progress cannot satisfy the receiving service's completion verifier |
| C491 | Add explicit replication status for catalog version per peer | PROPOSED:federation | absent/stale/current states derive from exact roots |
| C492 | Handle stale catalog version without silently selecting newest local copy | PROPOSED:federation | requested old root resolves exactly or reports unavailable |
| C493 | Ensure publication pointer does not replace immutable object identity | PROPOSED:federation | pointer update leaves prior content root accessible |
| C494 | Validate transport receipt separately from fetched task acceptance | PROPOSED:federation | fetch receipt alone does not mark task accepted |
| C495 | Detect conflicting task metadata sharing an asserted root | PROPOSED:federation | re-derived root mismatch rejects conflicting bytes |
| C496 | Add bounded peer recovery search for a missing exact evidence root | PROPOSED:federation | query stays bounded and absence remains local-scope unknown |
| C497 | Reconcile local projection after receiving a late valid receipt | PROPOSED:federation | rebuilt view includes receipt without rewriting source object |
| C498 | Ensure mutable assignment event names exact lease scope and expiry | PROPOSED:federation | expired/wrong-scope event cannot claim current ownership |
| C499 | Add restart test for replicated catalog, attempts, reviews, and costs | PROPOSED:federation | all present roots verify; missing components remain `UNKNOWN` |
| C500 | Qualify two-node replication and recovery without claiming consensus | PROPOSED:federation | both nodes verify same roots; divergent views remain explicit |

## Data and authority boundary

The private fleet's measured 2,649 grouped item rows and 252 group labels are
ledger grouping counts, not task-type sample counts. The external private fleet
run export provides attempt-level model, effort, verdict, usage, and task-root
links where present. Its item export and outcome rollups use different units.
Frequency ranking
requires exact task-root deduplication and linkage to candidate/base, review,
repair, verifier, and accepted result. Cost per accepted useful task requires
all failed attempts, reviews, repairs, integration, and missing-usage coverage.
Until those joins are measured, empirical frequency, quality, accuracy, and
cost fields for every row remain `UNKNOWN`. The first 100 are a working
coverage queue only; no row is represented as empirically top-ranked.

## MVC and distributed datastore integration brief

The application should follow the existing models/services/controllers/views
ownership: immutable task, candidate, action, context, and receipt roots stay
with the canonical C23 work wires; services perform classification, selected
prompt resolution, and full-workflow accounting; controllers stay thin; views
show task selection, previewed template, acceptance/evidence, exact run result,
review, and known total-cost components. Do not create a parallel ledger.

Existing relevant authorities include `contexts/commons/modules/vcs/include/vcs/zcode_dev.h`,
`zcode_action_input.h`, and `zcode_work_swarm.h`; task/work offer and pull use
exact roots. Signed progress is an untrusted observation, and admission is a
process-local fact. The board is a local seen-set, not a global peer query.
Treat catalog releases as immutable, versioned CAS objects and local SQLite
indexes as derived views over verified objects. Mutable leases and events need
explicit signer, action scope, conflict visibility, and recovery rules; do not
claim global consistency or consensus. Replication/restart/peer-loss acceptance
must verify exact catalog, task, candidate, action, receipt, review, and cost
roots and mark absent evidence unknown.

Proposed first product slice: add the shared classifier/preview/accounting
service under `contexts/commons/services/`; keep the current native work map
and status commands as thin adapters, and make the dapp view consume that same
service. The exact catalog root and selected template hash must flow into the
attempt evidence. Compile-time prompt selection remains owned by
`engine/composition/prompt_templates.def` and `tools/engine_unit.c`; this file
adds no runtime authority. Test template behavior separately from model/task
quality. Model and prompt promotion requires a frozen matched cohort with exact
roots, independent acceptance, escaped-defect and repair tracking, and complete
workflow costs; no target accuracy, price, or savings claim is assigned here.
