<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Muse model selection blocks resident worker execution

At 2026-09-19T19:29:05Z, `dev.agent.worker` claimed the local
`ci-worker-state-2` file job. Its executor receipt reported `refused`, zero
tokens and `Invalid params: session/setModel invalid params: missing field
model`. No candidate work was accepted. The workspace was clean and restored
to commit `89005e52608968f11c24574820726d19e6b4835e`.

The installed Muse Code 1.3.0 stable schema requires
`session/setModel.params.model.modelId`. The adapter sent
`session/setModel.params.modelId`. The adapter now sends the nested selection.
The scripted MSP host rejects the former shape, and the registered
`muse_session` group observes the selected model.

On 2026-09-19, `make -j4 t-fast ONLY=muse_session` ran one group:
`groups_ran=1`, `groups_failed=0`, `self_skips=0`. `make -j4 z23-dev` then
rebuilt the development binary. `make lint-fast` failed in
`check-flag-registry`: five Makefile first-use pointers no longer refer to the
first read of their named flags. Those five references were then updated to
the observed Makefile lines. A second `make lint-fast` passed all 32 gates.

The rebuilt resident worker then claimed two more clean jobs. A requested
model outside the host catalog was refused with `invalid_model` and zero
tokens. A run using the host default model reached `turn/start`, but exceeded
its 16,000-token cap at 21,292 billed tokens; a narrower task exceeded a
50,000-token cap at 54,322 billed tokens. Both receipts say `refused`, carry
no completed candidate or gate proof, and record a clean restored workspace.
The worker has not completed a real coding task through this path.

The 50,000-cap session log records two model completions: raw input/output
counts of 20,959/234 and 33,037/92, with cache-read counts of 9,073 and
20,849. Its only recorded tool name is `read_file`; no edit reached the
workspace. The worker's 54,322 figure is its cap-accounting verdict, not a
measured monetary charge. The installed MSP schema describes
`session/tokenUsage.totalTokens` as the host's counted-once total and says
clients should not derive it again from provider cache counters.

Next check: inspect the two model calls and the context gathered by
`read_file` before increasing the cap again. The local fake-host result
establishes only the request shape.

## Bounded real-worker retries

At 2026-09-19T20:27:00Z, a worker attempt was refused before model use
because its brief omitted the required `muse-workspace` header. The next
attempt used the existing valid brief and a 120,000-token cap. The worker
claimed the job, consumed 122,476 counted tokens in 13 seconds, produced no
candidate diff, and was refused before running the gate. Its workspace was
verified clean at the pinned `b75c7113d9e68e8437c6e24b696dbdb26375a531`
base. The retained Muse trace shows the model reading both complete C files:
the first pair of tool results added 41,175 bytes to the second model input.

At 2026-09-19T20:29:00Z, the brief named only the relevant line ranges. With
a 100,000-token cap, the worker read bounded ranges and produced a verified
candidate diff that changed the production state string from `active` to
`executing` and changed the test title. It had not changed the test assertion
or run the gate when the adapter refused at 111,661 counted tokens after 15
seconds. The diff is preserved in the worker run directory; the workspace was
restored to its exact pinned base. The outcome remains `refused`, not PASS.

The retained trace for that bounded-range attempt records five model requests.
Each request repeats approximately 24,823 bytes of base instructions and
28,827 bytes of run context before task history. The prompt reduced file-read
payloads, but repeated fixed context still dominated the cap. No further
cap increase is justified without measuring a way to reduce or amortize that
context. The partial candidate must be reconciled and independently tested;
it is not eligible for landing from the refused receipt.

The next worker run completed that two-file diff, but the executor refused it
before the gate: the brief's `muse-scope` header named only the production
file, so the test edit was correctly classified outside scope. A queue retry
with two `path` prefixes still failed because the brief's own scope header
remained narrower. After both scope declarations were aligned, another run
retained the same diff but spent its 200,000-token cap before a gate receipt.
No worker run claimed PASS.

The retained two-file diff was independently reconstructed and checked against
the worker candidate (the only byte difference is one trailing blank line in
the stored patch). On the local checkout, `make -j4 t-fast ONLY=dev_ci` ran
one registered group with zero failures and zero skips. `make lint-fast`
passed 32/32 gates. These are local checks of the code, not a worker PASS or
a remote receipt.

## Verified worker liveness in the status view

A queue row can remain `running` after its worker process exits and before
`reap` records the outcome. Claim age alone therefore cannot prove
`executing`. The queue already persists the claimant PID and kernel birth
token for orphan recovery; its status projection now verifies that exact
identity and exposes `owner_liveness` as `running`, `dead`, or `unknown`.
`dev ci` reports a fresh named claim as `executing` only for `running`, a
fresh dead owner as `blocked`, and an unverified owner as `unknown`. Old
claims remain `stale`; zero claims remain `unknown`, not assumed idle. The
registered `dev_ci` group passed 1/1 with zero skips on 2026-09-19, including
the reused-PID and missing-token regressions. This measures local owner
liveness, not completion of the distributed lifecycle.

After the unrelated fast-CI holder released the checkout build lock,
`make -j4 t-fast ONLY=devagent_queue` passed 3/3, with zero skips.
The two line pointers for `ZCL_ENGINE_UNIT_BIN` and
`ZCL_Z23_BIN` were updated to the queue file's new first reads;
`make lint-fast` then passed 32/32 gates. The generated capability inventory
passed `make check-capability-inventory-generated` with 1,500 capabilities
and 1,149 resolved registered roots. These checks cover this local status
slice; they do not grant publication or a remote receipt.

## Parallel gate diagnostic

After the parallel gate build reached `origin/main`, the registered
`devagent_muse_run` group failed its `build-fail reason quotes the build's own
stderr` assertion on an isolated retry. The build still refused and the
stale runner was not consulted; its diagnostic had selected an earlier
printable line. The build diagnostic now selects the first line containing
`error:`, falling back to its previous first-line behavior when none exists.
The fixture prints a preceding line before the compiler-style error. On the
combined source, `make -j4 t-fast ONLY=devagent_muse_run` ran one group with
`groups_failed=0`, `self_skips=0` and a 24.9-second test body.
