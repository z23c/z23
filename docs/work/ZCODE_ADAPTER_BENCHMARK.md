# ZCode adapter benchmark

This is the measured decision record for the Codex adapter experiments. The
native Z23 CLI remains the product surface and the existing ephemeral adapter
remains the control and fallback. This work does not add a general external
tool server, expose the command registry as tools, or create a second
task/candidate authority.

## Frozen baseline

The frozen owner is `zpd_test_twelve_task_benchmark` in
`tests/harness/src/test_zcode_package_dev.c`: twelve exact goals over three synthetic
C23 projects, including two impossible out-of-scope goals. On source
`7d739720138dd8c82d0a691a1d32eab9899c38d4`, the uncached acceptance reported:

```text
tasks=12 projects=3 compiling=10 profile=10 accepted=10 refused=2
context=312/816 bytes model_context_bytes=7093 context_us=27558
elapsed_us=8525352
```

This is a deterministic lifecycle baseline. It does not invoke a model: the
test applies its fixed candidate edits, proves ten admissible tasks, and proves
that both impossible edits fail closed.

## Ephemeral control

`tools/dev/zcode_adapter_benchmark.sh control` exercised the unchanged native
`zcode work start` → `zcode work run --adapter=codex` path for all twelve exact
goals:

```json
{"tasks":12,"tokens":{"state":"unavailable_no_model_request","input":null,"cached_input":null,"output":null},"packet_bytes":0,"tool_output_bytes":{"native":22929,"model":0},"calls":{"native":24,"model_requests":0,"model_tools":0},"retries":0,"elapsed_us":3109963,"scope_errors":0,"verified_success":0,"adapter_unavailable":12}
```

The token fields are unavailable, not zero: the adapter refused before packet
construction or a model request. The fixed executable location is absent on
this host and neither supported one-shot credential variable is present. The
current error combines those independent prerequisites under one
`ADAPTER_UNAVAILABLE` result.

## Packet A/B

`tools/dev/zcode_adapter_benchmark.sh packet-analysis` generated every packet
through the native manual handoff, then derived three non-authoritative views:

```json
{"tasks":12,"packet_bytes":{"full":16933,"index_only":13129,"hybrid":14485,"hybrid_stable":14485},"global_common_prefix_bytes":{"hybrid_current":9,"hybrid_stable":360},"native_tool_calls":24,"native_tool_output_bytes":27649,"elapsed_us":4866855}
```

Definitions are exact and local to the experiment:

- **full** carries path, byte count, digest, and complete content for each of
  the five frozen source files;
- **index-only** carries path, byte count, and digest, with no source content;
- **hybrid** carries that index plus the canonical selected excerpts;
- **hybrid-stable** contains the same values and bytes as hybrid, but orders
  instruction, limits, scope, and dependency fields before task-specific
  context and goal fields.

Index-only is 9.4% smaller than the current selected-excerpt packet and full is
16.9% larger. Stable ordering changes no packet size and increases the global
common prefix from 9 to 360 bytes. This establishes byte-level cache potential,
not a token or success improvement.

## Executing pilots and app-server A/B

The installed Codex CLI is version 0.148.0. A preserved ephemeral index-only
pilot measured 49,857 input, 35,072 cached input, and 1,370 output tokens in
38.870 seconds. A hybrid pilot measured 49,761 input, 35,072 cached input, and
1,029 output tokens in 31.528 seconds. Both reached the model, but every shell
and patch attempt failed before execution with:

```text
bwrap: loopback: Failed RTM_NEWADDR: Operation not permitted
```

The deprecated Landlock compatibility mode was also tested once and refused
because the enforced permission profile requires direct runtime enforcement.
No bypass, network widening, or permission weakening was used.

Those diagnostic pilots used the installed default model before the harness
made the omission visible. Executing arms now fail closed unless
`Z23_ADAPTER_BENCHMARK_MODEL` pins one exact model identifier; the model is
also passed explicitly to app-server and reported with its provider. The
unqualified pilots therefore cannot be used as reproducible comparative
evidence even if their shell had succeeded.

The C23 app-server pilot used a private temporary Codex home containing only a
reference to the existing login, strict config, empty external-tool/plugin
maps, disabled app/plugin/web/image/skill/subagent surfaces, built-in shell
instructions, and one ephemeral thread rooted at one exact candidate. It
pinned `gpt-5.6-sol`
through the protocol and verified provider `openai`. Its integrated result was:

```json
{"tasks":1,"tokens":{"input":9170,"cached_input":7936,"output":94},"packet_bytes":1206,"tool_output_bytes":{"native":2305,"model":0},"calls":{"native":2,"model_requests":1,"model_tools":0},"retries":0,"elapsed_us":28634304,"scope_errors":0,"sandbox_failures":1,"first_pass_success":0,"verified_success":0,"exact_reproduction":0}
```

App-server materially reduced input tokens, but its built-in shell hit the same
`bwrap` failure before a tool-call completion. It therefore has no verified
goal-to-result time and does not qualify for adoption.

## Decision

Adopt none of the three changes yet. No executing arm preserved first-pass
success because this host cannot start Codex's required filesystem sandbox.
Lower packet bytes, a longer common prefix, and lower app-server input tokens
cannot substitute for verified candidate behavior, scope enforcement, or exact
reproduction.

The measured owning-layer continuation is:

1. Add a native adapter readiness view that independently reports exact
   executable binding, credential capability, filesystem sandbox preflight,
   packet readiness, and one obvious next action without exposing their values.
2. Replace the hard-coded executable location with an owner-approved exact
   executable binding (identity, ownership, mode, and source/version), not a
   PATH search.
3. Establish a supported non-interactive credential capability that is never
   copied into a candidate or inherited by model-run commands.
4. Preflight the exact Codex shell sandbox before a model request so this
   environment failure costs zero model tokens.
5. Emit aggregate JSONL adapter metrics from the existing CLI path, then rerun
   all twelve tasks for full, index-only, hybrid, stable-prefix hybrid, and the
   shell-only app-server arm.

Only after those prerequisites are green can one packet/order/transport change
be adopted under the original rule: materially lower uncached tokens or
verified goal-to-result time, with no reduction in first-pass success, scope
safety, or exact reproduction. A general external tool server and a registry
export through that protocol remain explicitly out of scope.

## Bounded readiness repair and freeze

The one permitted follow-up is now the native read-only
`zcode.work.preflight` leaf. It checks the source-bound confined runner and
fixed Codex executable, exactly one credential capability without returning a
value, real filesystem-sandbox startup in a disposable directory, and packet
construction for the exact work item. The runner's preflight mode exits after
the sandbox write probe and reports `model_request_attempted=false`; it cannot
start a model request.

The frozen twelve-task acceptance reported:

```json
{"schema":"zcl.zcode_adapter_preflight_acceptance.v1","tasks":12,"preflight_verified":12,"model_requests":0,"native_tool_calls":24,"native_tool_output_bytes":26146,"elapsed_us":5287630}
```

Reproduce it with `make zcode-adapter-readiness-acceptance`.

On this host the command independently proves that the runner is source-bound,
the filesystem sandbox starts, and an exact packet can be built. It names
`CODEX_EXECUTABLE_UNBOUND` as the single primary blocker because the fixed
owner-approved Codex executable binding is absent; credential capability is
also reported separately as unavailable. No model request is made and the
existing `zcode.work.run` behavior is unchanged.

Adapter and benchmark development is frozen after this repair. The next work
belongs to public-node V1 acceptance: full binaries, real transaction builders,
real P2P, persistent wallet state, application behavior, C3 cold start, and C8
from-genesis parity.
