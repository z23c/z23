/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#ifndef ZCL_TOOLS_NATIVE_COMMAND_H
#define ZCL_TOOLS_NATIVE_COMMAND_H

#include "kernel/command_registry.h"
#include "controllers/native_handler_body.h"
#include "chain/chainparamsbase.h"

/* Every catalog-bound handler, declared from the command .def rows. */
#include "native_command_handlers.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

bool zcl_native_command_is_root(const char *word);

/* The checkout a request runs against: the request context's source root,
 * then ZCL_DEV_SOURCE_ROOT, then the current directory. */
const char *zcl_native_source_root(const struct zcl_command_request *request);

#ifdef ZCL_TESTING
/* Drive the production event-option parser without a separate dev binary.
 * Invalid options print the same error envelope as the streaming CLI and
 * return INVALID; valid options return OK without starting a stream. */
int zcl_native_dev_events_flags_for_test(const char *const *words, size_t count);

/* Exercise one production JSONL stream step with an already-published event.
 * Writes accepted lines to stdout; refused encodings write no bytes and set
 * INTERNAL. The cursor advances past a found event even on refusal. */
bool zcl_native_dev_events_step_for_test(const char *root, int64_t *after,
                                         int *rc);

/* Exercise the next-action builder's parser without a separate CLI binary.
 * parsed must point to fresh storage without owned allocations. Initializes
 * it even for NULL/empty input; caller releases it with json_free(). */
bool zcl_native_next_input_read_for_test(const char *next_input,
                                        struct json_value *parsed);
#endif

/* Resolve argv under a canonical root through the registry and print exactly
 * one bounded JSON document (branch menu, discovery document, common result
 * envelope, or structured unknown-command error). Returns a contract exit code
 * (0..6). A typo under a canonical branch returns the structured unknown-branch
 * error and NEVER falls through to the arbitrary RPC method fallback.
 * datadir/rpc_port target the running node for READ-ONLY bridge leaves. */
int zcl_native_command_main(const char *root_word,
                            const char *const *args, int nargs,
                            const char *datadir, int rpc_port,
                            enum chain_network network,
                            bool datadir_explicit);

/* Actual standalone entry owns signal scope; callable registry/legacy entry
 * never infer ownership. end must also handle a partially failed begin.
 * Runtime storage outlives dispatch; scope restoration precedes output. */
struct zcl_native_standalone_runtime {
    bool (*begin)(void *);
    bool (*end)(void *);
    bool (*cancelled)(void *);
    bool (*reserve_cleanup)(void *, unsigned, struct zcl_command_cleanup_slot **);
    bool (*cleanup)(void *);
    void *context;
};
int zcl_native_command_main_standalone(const char *root_word,
    const char *const *args, int nargs, const char *datadir, int rpc_port,
    enum chain_network network, bool datadir_explicit,
    const struct zcl_native_standalone_runtime *runtime);

/* Network selected by the current one-shot native invocation. Direct
 * in-process callers default to mainnet until command_main selects another
 * network. */
enum chain_network zcl_native_command_network(void);

/* Agent spend-policy presentation (docs/work/agent-spend-policy-design.md,
 * "Minting + presentation"): the value of ZCL_AGENT_SESSION when set and
 * non-empty, NULL otherwise. The argv context builder in native_command.c
 * wires the result into zcl_command_context.agent_session; unset is the
 * explicit local-operator exemption and leaves the omnipotent context
 * byte-identical. Extracted so the presentation rule is unit-testable
 * without driving the whole argv path. */
const char *zcl_native_agent_session_env(void);

/* True only while the current one-shot native invocation is executing an
 * input object read through `--input=-`. Secret-bearing handlers use this to
 * refuse argv/environment transport, whose bytes are visible to process
 * inspection and shell history. False for direct in-process/test dispatch. */
bool zcl_native_input_was_stdin(void);

/* Called by a handler whose stdout carries its own byte stream: the one-shot
 * CLI then prints that call's result envelope (and any field selection) on
 * stderr, never on stdout. Reset at the start of each dispatch. */
void zcl_native_envelope_to_stderr(void);

/* Ensure the one-shot JSON-RPC client (datadir cookie + port) is initialized
 * from the CLI-resolved -datadir/-rpcport. Handlers that call node_rpc_call()
 * or node_rpc_client_datadir() WITHOUT going through the bridge dispatch
 * (e.g. the dev hot-swap handlers) must call this first — the bridge would
 * otherwise leave the client global empty in a fresh CLI process. */
void zcl_native_bridge_ensure_rpc(void);
void zcl_native_overlay_intent_run(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply, const char *rpc_method,
    const char *operation, bool operation_inputs_present);

/* Generic transport binding for READ-ONLY Core/Ops leaves. Resolves the
 * leaf's canonical path to exactly one dispatch: either a transport-neutral
 * body function or, for a pure pass-through leaf, the backing JSON-RPC method
 * directly. The body is wrapped in the common zcl.result.v1 envelope. Bound
 * by engine/composition/src/command_catalog.c. */

/* Run a bridged leaf with an EXPLICIT body function — the reusable core of
 * zcl_native_bridge_command: build args from the request, dispatch the passed
 * `body` (or, when `body` is NULL and the leaf is a pure 1:1 proxy, the
 * backing JSON-RPC method directly), then project the body into the reply
 * envelope. zcl_native_bridge_command is a thin wrapper that supplies
 * zcl_native_bridge_body_for_path(path); a hot-swap generation instead
 * supplies its own freshly-compiled body for an existing body-backed bridge
 * path. Non-bridge paths and ambiguous/missing bindings fail closed with
 * NO_BRIDGE_BINDING. */
void zcl_native_bridge_run(const struct zcl_command_request *request,
                           zcl_native_body_fn body,
                           struct zcl_command_reply *reply);

/* ── hot-swap leaf trampoline ──────────────────────────────────────────
 *
 * Every staged leaf needs a function carrying the command registry's handler
 * signature that forwards to THIS TU's own body through the bridge above.
 * Written out, that wrapper is five lines whose only variables are two names,
 * repeated once per leaf per controller — and each controller carries the set
 * TWICE, once for the Tier-1 (ZCL_HOTSWAP_GEN) block and once for the Tier-2
 * module (ZCL_HOTSWAP_MODULE_GEN) block. That boilerplate is a standing tax on
 * every hot-swap registration, and it pushed two controllers through their
 * file-size ceiling the moment their trampolines landed. Declare it instead:
 *
 *     ZCL_HOTSWAP_TRAMPOLINE(tramp_metrics, zcl_native_metrics_body)
 *
 * (no trailing semicolon). `name` is the symbol the leaf table points at;
 * `body` is this controller's own handler body. Parameters are prefixed so
 * they cannot capture a name used in the body expression.
 *
 * It lives HERE, beside zcl_native_bridge_run, rather than in hotswap.h,
 * because the two generation tiers include different headers — Tier-2 pulls
 * hotswap_module.h, which does not include hotswap.h — and both include this
 * file. Defined in only one of them, the macro silently stops expanding and
 * the call reads as a function declaration: the compiler then reports an
 * "unused parameter" named after your trampoline, which is a confusing way to
 * learn the macro was invisible. */
#define ZCL_HOTSWAP_TRAMPOLINE(name, body)                                   \
    static void name(const struct zcl_command_request *zcl__tramp_request,   \
                     struct zcl_command_reply *zcl__tramp_reply)             \
    {                                                                        \
        zcl_native_bridge_run(zcl__tramp_request, body, zcl__tramp_reply);   \
    }

/* Project a bridged command body into reply->data bounded by request->view
 * (summary|normal|full), request->budget_bytes, request->max_items, and
 * request->cursor, emitting an explicit `_page` descriptor and — when
 * truncated — one structured retrieval next-command. Exposed for golden tests
 * so progressive disclosure can be proven without contacting a node. */
void zcl_native_bridge_project(const struct zcl_command_request *request,
                               const struct json_value *body,
                               struct zcl_command_reply *reply);

/* Keep board lines and signed posts on the same bounded projection page. */
void zcl_native_fleet_board_project_list(
    const struct zcl_command_request *request,
    const struct json_value *body, struct zcl_command_reply *reply);

/* Dispatch lookups. Every bridged leaf resolves to exactly
 * one of the two: a re-homed body function OR a direct JSON-RPC method.
 * Pure lookups — no node contact. The golden catalog test proves the union
 * covers every bridged leaf and never overlaps. */
zcl_native_body_fn zcl_native_bridge_body_for_path(const char *path);
const char *zcl_native_bridge_rpc_for_path(const char *path);

/* dev.ff — the fail-fast edit-loop ladder (`make ff`: compile -> focused
 * tests -> lint-fast, see tools/command/native_dev_command.c). A release
 * build's copy of this function is a `#ifndef ZCL_DEV_BUILD` stub that fails
 * BLOCKED without spawning anything (zcl_devloop_process_run is dev-only
 * linked, see Makefile DEV_ONLY_SRCS). */

/* Typed publication continuation used by zcode.work.publish after it has
 * independently bound an accepted work item to its queued job. Public command
 * handlers remain responsible for parsing their own declared JSON schemas. */
struct zcl_dev_publication_input {
    const char *source_root;
    const char *workspace;
    const char *datadir;
    const char *job_root;
    bool details;
};

void zcl_dev_publication_advance(
    const struct zcl_dev_publication_input *input,
    struct zcl_command_reply *reply);
void zcl_dev_publication_collect(
    const struct zcl_dev_publication_input *input,
    struct zcl_command_reply *reply);
/* dev.vcs.revert — one-command source+binary revert (see
 * tools/command/native_dev_command.c). A release build's copy of this
 * function is a `#ifndef ZCL_DEV_BUILD` stub that fails BLOCKED without
 * touching contexts/commons/modules/vcs/ or spawning anything. */
/* dev.vcs.seal.grant — owner-run ZVCS unseal-token ritual (see
 * tools/command/native_dev_command.c). Mirrors dev.vcs.revert's shape: a
 * release build's copy of this function is a `#ifndef ZCL_DEV_BUILD` stub
 * that fails BLOCKED without touching contexts/commons/modules/vcs/ or spawning anything. */

/* Shared by the plugin leaves: the HOME-based store root. */
bool zcl_native_plugin_root(char *out, size_t cap);
/* ops.mesh.terminal: CLI-only attach bridge (native_mesh_terminal_command.c).
 * The JSON handler is a blocker; the CLI intercept runs the session. */
bool zcl_native_mesh_terminal_try_attach(const char *const *words,
                                         size_t count, size_t consumed,
                                         int *rc);
bool zcl_native_mesh_terminal_write_all(int fd, const uint8_t *buf, size_t len);
#ifdef ZCL_TESTING
void zcl_native_mesh_terminal_test_set_stop(bool stop);
/* True when the raw line discipline the attach client installs, applied to a
 * termios with every flag set, turns off signal generation (so Ctrl-C,
 * Ctrl-Z and Ctrl-\ are bytes for the remote), flow control, line editing,
 * echo, CR mapping and output post-processing, and reads byte by byte. */
bool zcl_native_mesh_terminal_test_raw_is_transparent(void);
#endif
/* ops.mesh.roster, aliased `fleet roster` — this operator's own machines,
 * with every fact labelled by who established it and the in-game assets
 * engine/composition/fleet_airship_rules.def awards for the verified ones.
 * It reads <datadir>/node.db read-only and asks no running node anything. */
struct device_identity;
/* HOST-only full-proposal branch; representation does not prove possession. */
bool zcl_native_device_host_requested(const struct json_value *input);
bool zcl_native_device_host_pairing(const struct json_value *input,
    const struct device_identity *identity, bool commit, struct zcl_command_reply *reply);
bool zcl_native_device_prepare_secret(const struct json_value *input,
    const struct device_identity *identity, struct zcl_command_reply *reply);
#ifdef ZCL_TESTING
/* One-shot fault checkpoints, never a production entropy/configuration input. */
void zcl_native_device_prepare_test_interrupt(unsigned stage);
#endif
/* Exact registered raw CLI dispatch before config/node initialization. */
void zcl_native_device_host_runtime_exit_if_requested(int argc, char **argv);
/* --input-file=<absolute> source: a non-symlink regular file owned by the
 * caller, not group/other writable, 1..capacity-1 bytes with no NUL; one
 * trailing newline is dropped. Linux/macOS; elsewhere refuses. */
bool zcl_native_device_host_input_file_read(const char *path, char *text, size_t capacity, size_t *length);
#if defined(ZCL_TESTING) && (defined(__linux__) || defined(__APPLE__))
/* Runs once between the --input-file read and its stability re-check. */
void zcl_native_device_host_input_file_hook_for_test(void (*hook)(const char *path));
#endif
#if defined(ZCL_TESTING) && defined(__linux__)
bool zcl_native_device_host_package_input_for_test(const struct json_value *input);
bool zcl_native_device_host_package_terminal_for_test(int64_t deadline_ns);
/* Drives installed_wait with one pending SIGHUP whose forward fails; when
 * engine_exits the engine's exit is observable right after. Returns the
 * owner result token. */
const char *zcl_native_device_host_package_hangup_for_test(bool engine_exits);
#endif
/* ops.mesh.device.psk.new (tools/command/native_device_psk_command.c): 32
 * CSPRNG bytes into a NEW 0600 file beneath an owner-private parent. The
 * reply carries only the fingerprint: the first 16 hex of SHA3-256 over a
 * domain label, a NUL and the key. ops.mesh.device.commit shows the same
 * fingerprint for the imported secret_file. */
void zcl_native_device_psk_fingerprint(const uint8_t key[32], char out[17]);
/* ops.mesh.device.pair.status / .renew (tools/command/native_pair_state.c,
 * native_pair_renew.c, native_pair_renew_run.c, native_pair_smoke.c): fleet
 * hash-PSK pairing epochs. status lists every epoch's expiry and PSK
 * fingerprint; renew plans, or with confirm and plan_id creates epoch N+1 by
 * composing the init, psk new, plan, commit and revoke leaves, smokes it and
 * only then retires N. No PSK byte is read, printed or logged. */
/* ops.mesh.device.host.bench (tools/command/native_device_host_bench.c): in-process
 * PSK tunnel throughput over a throwaway paired authority; optional atomic receipt_out. */
#if defined(ZCL_TESTING)
/* Failure injection after the key file exists: bit 0 fails the write, bit 1
 * fails the cleanup unlink. Zero restores normal behavior. */
void zcl_native_device_psk_fault_for_test(unsigned mask);
#endif
/* ops.mesh.device.host.shell (tools/command/native_device_host_shell.c): a
 * raw pre-boot leaf that execv()s a once-resolved absolute ssh with a FIXED argv whose ProxyCommand is
 * this binary's `ops mesh device host client --input-file=<route_input>`.
 * Every interpolated value is charset-checked first because ssh runs
 * ProxyCommand through a shell; dry_run prints the argv as JSON instead. */
#define ZCL_HOST_SHELL_ARGV_MAX 12
struct zcl_native_host_shell_argv {
    char kex[96], proxy[2200], destination[300];
    const char *argv[ZCL_HOST_SHELL_ARGV_MAX + 1];
    size_t argc;
};
/* Pure: no probe, no exec. *refusal names the refused field on false. */
bool zcl_native_device_host_shell_argv(const char *self, const char *user, const char *host,
    const char *route_input, bool mlkem_offered, struct zcl_native_host_shell_argv *out, const char **refusal);
/* dry_run report: argv for the sntrup-only shape, argv_mlkem for the shape
 * used when ssh offers mlkem (may be NULL), the resolved executable, and
 * kex_probe:"skipped" because dry_run executes nothing. */
bool zcl_native_device_host_shell_json(const struct zcl_native_host_shell_argv *plan,
    const struct zcl_native_host_shell_argv *mlkem_plan, const char *executable, struct json_value *out);
/* Offline readiness of the route a shell would use: NULL when the file is a
 * valid client input and its grant is the unrevoked host-forward PSK grant the
 * route approves (root and backend match), live at `now`;
 * otherwise a named refusal. Reads only; nothing is dialed. */
const char *zcl_native_device_host_shell_route_check(const char *route, uint64_t now);
/* Resolve ssh once from a PATH string: the first regular executable file
 * named ssh. Any empty or relative component refuses the whole PATH. */
bool zcl_native_device_host_shell_resolve(const char *path_env, char *out, size_t capacity);
/* Raw entry: validates, resolves ssh, probes `ssh -Q kex` (not on dry_run), then execs. Returns
 * a process exit code only when it does not exec. */
int zcl_native_device_host_shell_run(const struct json_value *input);

/* ── app.service.* — declared services (tools/command/native_service_command.c).
 * `list` and `inspect` read the compile-time zcl.service_binding.v1 catalog
 * and touch nothing else. `access` opens <datadir>/node.db read-only to
 * evaluate one binding's ZSLP token gate at its declared snapshot height.
 * `status` reads the in-process lifecycle registry. */

/* ── code.* — the source-code navigator (tools/command/native_code_command.c
 * plus native_code_guide_command.c for the inner-loop guide). Local,
 * read-only, deterministic leaves backed by the in-binary cognition/modules/codeindex
 * index. Each renders one bounded JSON document (structured array + human
 * one-liners) well within ZCL_COMMAND_RESULT_BUDGET. */
/* code.body — one function's source text from its definition line through its
 * closing brace, read from the checkout and bounded by line and byte caps. */
/* code.capsule — one bounded document composing a symbol's identity, direct
 * callers/callees, in-tree includes of its def file, and the command paths
 * whose registered handler is defined there (config/command_handler_index.h
 * join). Budget-aware self-shrinking: see native_code_command.c. */
/* code.packet — one call that assembles a builder's work packet (verbatim
 * excerpts, covering tests, impact, authority, gates, traps, markdown) from
 * the index-backed code.* readers (tools/command/native_code_packet.c). */
/* code.have — "does this checkout ALREADY DO X?" Ranks capabilities by
 * concept (stemmed terms over symbol names, doc comments, file purposes,
 * paths and groups), reports how many files actually CALL each one, and
 * returns a verdict derived from those same numbers. */
/* code.map — the whole-tree map: maintained source roots (aggregate file
 * counts), app/ shapes, and separate governed-C23, indexed-fixture,
 * all-indexed-C23, and registry-node totals. */
/* code.coverage — reconcile the exact Git-tracked maintained C23/registry
 * manifest with the current verified index generation. */
/* code.owner — the first-hour "whose room is this?" leaf: physical authority,
 * sealed-core flag, context/shape classification, index group, and nearest
 * owning module directory for one repo-relative path. Unindexed paths are
 * UNOWNED, never an error. */
/* code.cost — the proof-price leaf: the focused test route plus the last
 * suite run's measured per-group cost (.cache/test-timing/last-run.json);
 * unmeasured groups say so rather than inventing a number. */
/* code.recent — the churn leaf: bounded newest-first git log for one path
 * since a commit-ish, fail-closed on a bad ref. */
/* code.fetch — the warm-start leaf: verify a published codeindex generation
 * from another checkout against this checkout's sealed source roots and
 * install it, so a fresh worktree skips the cold index build. MUTATE-classed:
 * it writes <root>/.codeindex. Fails closed naming the key and both digests. */
/* code.index.metrics — the published image's own build/size/freshness
 * numbers. Opens an existing store only; never rebuilds. */
/* code.tests — the routing link: which focused test group a change to one file
 * routes to, mirroring `dev test plan` (tools/dev/devloop_plan.c). */
/* code.room — the unified single-room view: composes shape + purpose + group +
 * neighbors + tests/route for one path into one bounded document (palace-design
 * §2). The command→file join is degraded to null (registry stores handler
 * pointers, not symbol names). */
/* code.context-map — generated whole-tree bounded-context and shape coverage,
 * violations, and observed compiler-include coupling. */
/* code.impact — the blast-radius leaf: the reverse-dependency closure of one
 * changed file (codeindex_impact_closure) plus the downstream focused test
 * groups (the same agent_impact_apply_shared_rules() resolver code.tests
 * uses) and two quick depth-1 fan-out numbers (direct_includes,
 * direct_callers). See native_code_command.c for the cap+truncated contract. */
/* code.merkle — the identity leaf: the SHA3-256 Merkle root over the indexed
 * source tree, any directory's subtree root, or one file's leaf digest, plus
 * the direct child subtree roots and what the refresh cost (files re-read,
 * bytes hashed, directory nodes recomputed). Backed by
 * cognition/modules/codeindex/src/codeindex_merkle.c; does not open the symbol index. */
/* code.territory — one module's generated scorecard: the files/bytes it owns,
 * its purpose, the registered groups its files ROUTE to, and — kept strictly
 * apart from routing — how many of its public functions a registered test
 * entry point actually REACHES through the call graph, plus include-edge
 * neighbours both ways and the weak spots. reached + unreached + unknown
 * always equals public_symbols. Backed by lib/territory; the registered
 * catalog (tools/dev) and the changed-file router (app/controllers) are handed
 * in as ports because lib/ sits below both. */
/* code.focus — ranked files a named specialist should work next, from
 * recorded evidence only. `--list` / no specialist lists the X-macro
 * catalog in engine/composition/specialists.def. */
/* code.corpus — honest distance to 100M lines of proven, non-duplicated C23.
 * Two readings kept apart: a live walk of the maintained C23 roots for lines,
 * and the generated capability inventory for what a registered test actually
 * reaches, plus a scope check saying whether those two walks saw the same
 * tree. Backed by cognition/modules/science/science_corpus.c; opens no code index. The
 * reply leads with the UNPROVEN count, which is the point of the leaf. */

/* code.kpi — the build's own numbers, recorded rather than remembered. Reads
 * artifacts the build already writes plus the code index's territory rows,
 * and reports each metric against the most recent PRIOR frame with its
 * direction, verdict and the exact drill-down command. Inputs: `group`
 * (cmd, code, docs, all) and `record`. Only `record=true` appends a frame to
 * <root>/.codeindex/kpi.chainlog; the default opens the ledger read-only. The
 * only code.* leaf that can write, which is why it is classed MUTATE. A metric
 * whose artifact could not be read is UNAVAILABLE and is never rendered as 0.
 * Backed by cognition/modules/kpi. */

/* general — the dispatch brief for one territory (owns / proves / trusts /
 * weak at / refuses), or with no argument the roll-up across every territory
 * ranked by where the evidence is weakest. Every field is generated per call
 * from the code index, the registered test catalog, the shared impact router,
 * and the lint gate wiring; nothing is stored, because a written brief goes
 * stale the way a MAINTAINERS file does.
 *
 * A GENERAL GRANTS NO AUTHORITY. It reports and never decides — no approval,
 * no gate, no veto, no privileged owner. "No referee, no authority — everyone
 * runs a full node" is the project's rule, and metaverse_grant_check() stays
 * the only answer to what anything may do. Do not add an approval path here. */

/* code.provenance.facts — the writer census: every durable named slot (a key in
 * progress_meta / stage_cursor / node_state) with the count of distinct FILES
 * that write it, ranked multi-writer first; with a `key`, each writer as
 * file:line via its write function or SQL verb. Re-derived for each exact
 * source generation and memoized in-process by the code index's sealed content
 * root. See engine/controllers/src/fact_writers.c for the two derivations and
 * controllers/fact_store_writers.def for the manifest that states them. */

/* code.provenance.relations — bounded typed facts about one declaration's
 * identity, source context, registered command execution contract and proof
 * requirements. Runtime observations and receipts remain explicit gaps. */

/* code.provenance.emitter — the reverse direction of every other code leaf:
 * given text the node EMITTED (a blocker id, a dumper subsystem name, a
 * reason/log fragment), return the source site that formatted it, its enclosing
 * function and callers, the .def registry rows that own it, and the proof that
 * covers it. Implemented in tools/command/native_code_emitter_command.c. */

/* Resolve the focused-test proof group for a changed source `path`, mirroring
 * tools/dev/devloop_plan.c:171-185 so `code tests` and `dev test plan` never
 * disagree. When non-NULL, `acc` is filled with the matched shared-rule groups
 * (caller may enumerate acc->groups[0..groups_len]) and `consensus_risk`
 * reports whether the path is a consensus / sealed-core surface. Returns a
 * static string owned by the registry ("consensus_parity" / a shared-rule
 * group / "make_lint_gates"). The live wrapper reads current referrer files
 * and the Windows source table (and may allocate); no node contact. The
 * snapshot overload uses one invocation-owned capture of those same inputs. */
struct agent_impact_acc;
struct agent_impact_snapshot;
const char *zcl_native_code_route_snapshot(const char *path,
    struct agent_impact_acc *acc, bool *consensus_risk,
    const struct agent_impact_snapshot *snapshot);
const char *zcl_native_code_route_for_path(const char *path,
                                           struct agent_impact_acc *acc,
                                           bool *consensus_risk);

/* ── vault.* — what this node owns, and what may act on it
 * (tools/command/native_vault_command.c). The read leaves project the vault
 * read model (services/vault_read.h) through one documented seam and never
 * aggregate anything themselves; an asset class the model cannot answer for is
 * an explicit unavailable row, never an omitted one. The custody leaves hold
 * NO spend logic: vault.send / vault.send-shielded resolve their owning leaf in
 * the live catalog and call the handler function pointer it binds, and the
 * swap settlements call the RPC method the swap controller registers, so the
 * transaction is always the owning path's. `vault.routes` prints that binding
 * table, resolved from the registry at call time. Bound by
 * engine/composition/commands/vault.def. */
struct zcl_present_model_v1;
bool zcl_native_presentation_dumpstate(
    const char *name, const char *key, struct json_value *out);
bool zcl_native_presentation_status_model_from_facts(
    const struct json_value *status, const struct json_value *health,
    const struct json_value *backup, const struct json_value *work,
    struct zcl_present_model_v1 *model, char *why, size_t why_cap);
bool zcl_native_presentation_corpus_model_from_facts(
    const struct json_value *facts, struct zcl_present_model_v1 *model,
    char *why, size_t why_cap);
bool zcl_native_presentation_code_change_model_from_facts(
    const uint8_t *before, size_t before_len,
    const uint8_t *after, size_t after_len, const char *path,
    const char *requested, const char *before_behavior,
    const char *after_behavior, const char *before_blob_hex,
    const char *candidate_blob_hex, const char *candidate_root_hex,
    struct zcl_present_model_v1 *model, char *why, size_t why_cap);
bool zcl_native_presentation_development_model_from_facts(
    const struct json_value *facts, struct zcl_present_model_v1 *model,
    char *why, size_t why_cap);
bool zcl_native_presentation_reproduction_model_from_facts(
    const struct json_value *facts, struct zcl_present_model_v1 *model,
    char *why, size_t why_cap);
bool zcl_native_presentation_publication_confirm_model_from_plan(
    const struct json_value *plan, struct zcl_present_model_v1 *model,
    char *why, size_t why_cap);
bool zcl_native_presentation_release_confirm_model_from_facts(
    const struct json_value *status, const struct json_value *evidence,
    struct zcl_present_model_v1 *model, char identity[65],
    char *why, size_t why_cap);
bool zcl_native_presentation_publication_status_model_from_facts(
    const struct json_value *facts, struct zcl_present_model_v1 *model,
    char *why, size_t why_cap);

/* Shared renderer-neutral handoff used by canonical instrument builders.
 * The model is inert; this helper performs no node read or privileged effect. */
void zcl_native_present_model(
    const struct zcl_present_model_v1 *model, const char *leaf,
    const struct json_value *input, struct zcl_command_reply *reply);

/* vault.session.* — scoped, revocable spend-authority grants for agents
 * (tools/command/native_vault_session_command.c): mint/list/revoke over the
 * agent session service (services/agent_session_service.h). Grants, not
 * custody — no spend logic here either, and the full session token is
 * rendered exactly once (the create commit reply); every later rendering is
 * redacted. Bound by engine/composition/commands/vault.def. */

/* zcode — ZCODE source-package hosting (slice 3: local publication and
 * search). publish plan/commit validate a candidate release against every
 * publication rule (each rejection names the rule) and commit persists
 * through the contexts/commons/modules/vcs store; search/show read the rebuildable package
 * index projection. Bound by engine/composition/commands/zcode.def. */
/* Local publication composition, with the same canonical parse, signature,
 * roots, chunks, replay and policy admission as the native commit leaf.
 * Explicit paths and immutable wire storage remain valid for the whole call.
 * This never forwards to a resident node or bypasses publication validation. */
struct zcl_native_local_publication {
    const char *datadir;
    const char *source_directory;
    const uint8_t *release_wire;
    size_t release_wire_len;
    const uint8_t *manifest_wire;
    size_t manifest_wire_len;
    const uint8_t *recipe_wire;
    size_t recipe_wire_len;
    bool has_day;
    int64_t day;
};
void zcl_native_zcode_local_publication_commit(
    const struct zcl_native_local_publication *publication,
    struct zcl_command_reply *reply);
/* Owner-signed public work cards (tools/command/native_work_command.c),
 * bound by engine/composition/commands/work.def. */
/* The one-file lab (tools/command/native_lab_command.c and
 * native_lab_test_command.c), bound by engine/composition/commands/lab.def. */
/* lab.promote (tools/command/native_lab_promote_command.c). */
/* zcode.node.join (bare alias `join`) — tools/command/native_zcode_node_command.c.
 * Reports the current join posture, detects a local C23 compiler, and writes
 * the join flags into <datadir>/z23.conf. Starts, stops, signals and restarts
 * NOTHING: the service manager owns the node process. */
/* zcode.node.verify — tools/command/native_zcode_node_verify_command.c.
 * Rebuilds the node HERE from a local checkout and byte-compares the result
 * against the artifact the user was handed (by default this process's own
 * executable). It never checks a published hash against the file it was
 * published beside: the comparator in contexts/commons/modules/vcs/node_reproduce.c refuses
 * unless one side is RECEIVED and the other LOCAL_REBUILD. */
/* Test-only seam for the leaf above: substitutes the local rebuild driver so
 * the parse/compare/render path is provable without paying for a
 * whole-program LTO link. Precedent:
 * consensus_state_producer_receipt_test_set_identity(). Returns a process-
 * style status (0 = a receipt was written to out_path). There is deliberately
 * no input field and no environment variable that reaches this — a receipt
 * handed in from outside is the publisher's claim, which is the one thing
 * this command must never accept as evidence. */
typedef int (*zcl_node_verify_driver_fn)(const char *source_dir,
                                         const char *scratch_dir,
                                         const char *out_path,
                                         const char *profile, int jobs);
void zcl_native_node_verify_test_set_driver(zcl_node_verify_driver_fn fn);
bool zcl_native_zcode_workspace_is_explicit_scratch(const char *workspace);
/* Simulation anchor/policy verification report for the ZC23 Living Commons
 * status surfaces (docs/commons/METAVERSE_MVP.md MM4/LC3). `complete` is reported
 * only when the caller pins the immutable policy root, expected epoch/award,
 * active-chain height/MTP and both declared simulation anchors AND every
 * indexed creation attribution re-verifies under them; otherwise a NAMED
 * blocker is carried in context_blocker or first_failure — never a silent
 * `unknown`. All-or-nothing: a partial pin set names its first missing pin. */
struct zcl_native_zcode_anchor_report {
    bool context_bound;
    bool verified;
    int64_t attributions_checked;
    uint8_t first_failure_root[32];
    char first_failure[64];
    char context_blocker[96];
};
bool zcl_native_zcode_anchor_verify_commons(
    const struct json_value *input,
    struct zcl_native_zcode_anchor_report *report);
/* S4: the closed benchmark/reproduction executor (additive leaf in
 * engine/composition/commands/zcode_science.def; handler lives in
 * native_zcode_science_exec_command.c). */
/* S5: local discovery ranking over the rebuildable science projection
 * (additive leaves in engine/composition/commands/zcode_science.def; handlers live in
 * native_zcode_science_discover_command.c). Explanatory only — never read
 * by evidence admission, routing, rewards, or protocol control. */
/* Acceptance-proof glue: operator surface for zcode_science_rebuild (the
 * CAS-authoritative projection rebuild previously reachable only from
 * tests). Handler lives in native_zcode_science_command.c. */
/* G1 carrier: science objects ride the package swarm as one-chunk blobs
 * (vcs/blob_store.h). publish mirrors a committed CAS wire into the
 * package store (blob root = transport address, science root = semantic
 * address, re-derived at admit); fetch schedules the swarm download and
 * admits the bytes (re-derive root, CAS, projection) once local. Handlers
 * live in native_zcode_science_command.c. */
#ifdef ZCL_TESTING
struct zcl_science_pointer_test_observation {
    uint8_t transport_root[32];
    uint8_t publisher_zid[32];
    uint8_t provider_node_id[32];
    uint64_t sequence;
    bool provider_authenticated;
    bool conflicted;
    bool superseded;
};
size_t zcl_native_zcode_science_test_rank_pointers(
    const struct zcl_science_pointer_test_observation *observations,
    size_t count, uint32_t *source_indices, size_t max,
    uint32_t *conflicts_out, uint32_t *superseded_out);
bool zcl_native_zcode_science_test_candidate_allowed(
    const char *datadir, const uint8_t semantic_root[32],
    const uint8_t transport_root[32], const uint8_t publisher_zid[32]);
#endif
void zcl_native_zcode_evidence_exact(
    const char *workspace, const char *datadir, const char *action_id,
    struct zcl_command_reply *reply);
#ifdef ZCL_TESTING
/* Runs after publish commit finds no running node holding the package store
 * and before it takes that store's owner lease, so a test can start an
 * owner inside that window. NULL clears it. */
void zcl_native_zcode_publish_test_before_lease(
    void (*hook)(const char *store_datadir));
#endif

/* ── zcode.release.* — Sovereign Registry v1: sign/verify zid release
 * records (tools/command/native_zcode_release_command.c). Signing is
 * file-based (no swarm distribution). anchor folds the releases dir into
 * the zid anchor-domain tree (digest-sorted canonical order) and stores
 * the leaf set + root in zid_domains/zid_domain_leaves; prove reads that
 * stored leaf set, so a .zid added or removed later cannot silently
 * change what an issued proof means. zcode.domain.* inspects the store. */

/* zcode.proof.walk — the light-client proof-chain walker
 * (tools/command/native_proof_chain_command.c). Reports each rung of the
 * spec's chain independently as passed/failed/not_checked; a walk that ran
 * always returns PASSED because the envelope drops `data` on any other
 * status and the seven-rung report IS the product. */

/* ── zcode.desc.* — signed onion-service descriptors
 * (tools/command/native_zdesc_command.c). Publish stores the signed doc
 * as a content-addressed blob and files it under the BLINDED record key
 * for the current period; verify/resolve check the signature against a
 * CALLER-SUPPLIED master pubkey. Every reply carries
 * chain_anchored:false — nothing here consults the chain. */
void zcl_native_zcode_network_records_exact(
    const char *kind, const char *namespace_name,
    const char *transport_root, bool include_evidence_wires,
    struct zcl_command_reply *reply);
bool zcl_native_zcode_network_genesis(uint8_t out[32]);

/* ── zcode.endpoint.* — signed endpoint records
 * (tools/command/native_zendp_command.c). The chain-bound twin of
 * zcode.desc.*: no key is supplied by the caller on the verify side,
 * the record carries its own and it is resolved against the on-chain
 * identity projection, so every reply carries chain_anchored:true. A
 * record that does not resolve to an ACTIVE anchor is DISCARDED — no
 * file is written and nothing enters any directory. Publication is
 * operator-invoked only: there is no timer, no background publisher,
 * and no flag to enable one. */

/* zcode slice 5 — the decoded declarative build recipe for one package
 * root. Display-only JSON from the canonical recipe wire; the node never
 * compiles or executes downloaded code. */

/* zcode slice 6 — external-verifier attestation quorum for one package
 * root: evaluates the attestations/ dir against the local approved-verifier
 * allowlist (<datadir>/zcode/approved_verifiers) and reports the quorum
 * state with every named rule. The node only READS attestations; they are
 * produced by the separate z23-package-verify program. */

/* zcode attestation import — files a signed third-party ZCLATT wire into
 * <datadir>/zcode/attestations/<attestation-id-hex> (idempotent,
 * tmp+rename). Import validates only the wire's internal consistency and
 * embedded signature; filing is NOT acceptance — the approved-verifier
 * quorum policy applies at evaluation time (zcode package verify). */

/* zcode attestation TRANSPORT — how a signed ZCLATT attestation MOVES.
 * offer admits one locally-filed attestation into the package store as an
 * ordinary BLOB (no new wire message: it is a one-file one-chunk
 * content.v2 carrier under the frozen 'zpkgswm' codec) and returns BOTH
 * ready-to-run zcode network publish inputs — PROVIDER ("ask me for these
 * bytes", the record the fetch path routes on) and POINTER ("that blob
 * attests this package root"). Either alone is a silent no-op at pull
 * time. pull resolves every POINTER for one package root, drives the
 * existing fetch handler per distinct attestation blob, and admits each
 * result with expect_package_root ALWAYS set to the caller's root — that
 * receiver-side binding check, not the publish gate, is what stops a
 * hostile pointer delivering an attestation for another package. Pulling
 * is not accepting: the approved-verifier quorum is applied later by
 * zcode package verify. Bound by engine/composition/commands/zcode.def. */

/* zcode work transport leaves — how a proven accepted solution MOVES
 * between nodes, keyed by the task it solves (native_zcode_work_transport_
 * command.c). offer verifies one held source package reconstructs to a
 * proven accepted work, derives the task root it solves, and returns the
 * two ready-to-run publish inputs (PROVIDER on the package root, POINTER
 * binding task root to it). pull resolves every published work-solution
 * POINTER for one task root, fetches each distinct package, and re-derives
 * each package's own task chain with expect_task_root ALWAYS set — that
 * receiver-side binding check, not the publish gate, is what stops a
 * hostile pointer delivering a solution to a different problem. Pulling is
 * not accepting, and nothing is executed. Bound by engine/composition/commands/
 * zcode.def. */
/* Verify one durable work pull receipt by root (CAS copy or supplied wire). */

/* zcode task transport leaves — how a posted dev task MOVES between nodes
 * so a stranger can pick it up (native_zcode_task_transport_command.c).
 * offer loads one task's three wires from the workspace CAS (task wire,
 * goal preimage, proof policy — each re-hashed against its own address,
 * since raw CAS loads do not verify), binds them into the fixed-layout
 * task-context carrier, admits it to the package store, and returns the
 * two ready-to-run publish inputs (PROVIDER on the context root, POINTER
 * binding task root to it) for the task namespace. pull resolves every
 * task POINTER for one task root, fetches each distinct context, and
 * re-verifies it with expect_task_root ALWAYS set, returning the goal and
 * proof policy a remote agent needs to start work. board lists what this
 * node has seen posted in the task namespace (local seen-set projection,
 * never a peer query), enriching every row whose context is held and
 * verified. The task object is deliberately unsigned: authenticity of a
 * posting is the signed record pair; integrity is the root. Bound by
 * engine/composition/commands/zcode.def. */

/* zcode attestation admit — the third transport leaf, and the one that
 * decouples carriage from the DHT. It admits ONE attestation blob this
 * node ALREADY HOLDS, named directly by its transport root: the bytes are
 * read back out of the package store, re-parsed, their embedded signature
 * re-verified, their id re-derived, and filed. Before it, a node that had
 * fetched the blob had no way to admit it — import wants hex it does not
 * hold, pull wants a working authenticated DHT — so fetched evidence was
 * stranded on every node whose record layer is not up.
 *
 * package_root is OPTIONAL here and MANDATORY on pull. That asymmetry is
 * deliberate: pull resolved the blob FROM a POINTER keyed on a package
 * root, so it is answering a question about one specific package and must
 * bind, or a hostile pointer could deliver an attestation for a DIFFERENT
 * package as evidence about yours. admit is handed a transport root
 * directly, so a caller who IS asking about a package MUST pass
 * package_root — omitting it is the strictly weaker "file these bytes, I
 * am not asking about one package" case, never a safe default. Admitting
 * is not accepting: the quorum belongs to zcode package verify. Bound by
 * engine/composition/commands/zcode.def. */

/* zcode slice 4 — contributor identity + ZNAM pointers. The publisher key
 * is the only identity; ZNAM records resolve through the canonical model
 * with an explicit binding proof. Bound by engine/composition/commands/zcode.def. */

/* zcode slice 7 — bounded deterministic contribution scoring and the
 * reward eligibility gate list. score computes the semantic-line/lineage
 * breakdown from the persisted CAS bytes only (same bytes, same score);
 * eligible evaluates the frozen eight-gate list and names every failed
 * gate. Read-only: settlement is the slice-8 settle handler set below.
 * Bound by engine/composition/commands/zcode.def. */

/* zcode slice 8 — SIMULATED reward settlement (placeholder token id only;
 * never the real ZCODE token, no on-chain payout in v1). queue inspects
 * the daily settlement queue; plan assembles one capped settlement window
 * batch (the only mutation is the plan id); commit settles SIMULATED with
 * durable ledger facts, idempotent against replay (a duplicate is named,
 * never a double-pay); receipt reads the durable evidence of a settled
 * batch. Bound by engine/composition/commands/zcode.def. */

/* zcode slice 9 — the ZCODE Rankings: daily/weekly/monthly/all-time
 * leaderboards ranking EARNED ZCODE SCORE only (never a balance — no
 * balance or transfer record kind exists), a rebuildable projection over
 * the slice-8 reward ledger with pure window arithmetic (the caller
 * passes "today"). Bound by engine/composition/commands/zcode.def. */

/* zcode slice 10 — SIMULATED ZCODE Badges: permanent achievement
 * evidence (canonical binary wire + domain-separated SHA3 id, issuer-
 * signed; SIMULATED ZSLP-based assets only — no real mint, the
 * owner-reviewed real issuance is slice 15). Eligibility derives from
 * the slice-8 ledger, slice-9 rankings, and slice-3 publish history;
 * issuance is plan/commit with the dedup rule (never the same badge
 * twice for the same contributor + achievement period) enforced at plan
 * and re-checked at issue. Bound by engine/composition/commands/zcode.def. */

/* zcode slice 11 — the LOCAL P2P ratio + anti-spam policy surfaces:
 * per-contributor-key verified-bytes accounting and the local ratio
 * (no global ZCODE mint for bandwidth), tier resolution from earned
 * score + local ratio, the frozen policy table, and the store quota
 * pools with the per-tier pin-allowance policy view. Every rejection
 * names the exact rule. Bound by engine/composition/commands/zcode.def. */

/* zcode slice 12 — the authenticated package swarm's operator surface:
 * fetch starts/resumes a swarm download (live node-global engine when a
 * hosting node runs, otherwise the persisted resumable record for the
 * next hosting boot), peers reports the live engine's per-peer view of
 * one root (session pseudo-keys, never contributor identities), offered
 * lists roots peers have ANNOUNCEd this session (no invented replica
 * counts), and pin/unpin are the operator's never-tier-gated PINS-pool
 * path. Every rejection names the exact rule. Bound by
 * engine/composition/commands/zcode.def. */
/* fastobj export/admit — the compile-cache carrier's operator halves
 * (docs/work/WIRE_COMPILE_CACHE.md): export turns a verified cache into
 * ONE ordinary content.v2 carrier inside the store (publish here); admit
 * re-verifies a carrier the store already tracks and reconstructs the
 * cache (consume there). The swarm fetch moves the root between nodes. */

/* zcode package add plan / add commit / rollback / reproduce — the install
 * lifecycle.
 * plan resolves a name-or-root, locks the dependency DAG to immutable
 * package roots and reports what each step's state actually is; commit
 * re-derives that lock, refuses a stale or expired plan, then verifies,
 * builds+tests in the confined worker, re-hashes every artifact, installs
 * atomically and pins. rollback re-activates the previous generation.
 * Nothing installed is ever loaded into this process. Every rejection names
 * the exact rule. Bound by engine/composition/commands/zcode.def. */
/* reproduce re-runs the confined build of one installed package under the
 * standard profile and files the second, distinct build receipt when every
 * committed output is byte-identical (the reproduction fact
 * zcode.package.verify reports). */

/* ops.state — generic subsystem state dump. Dispatches the `dumpstate` RPC
 * method directly. `subsystem` (required) selects the
 * owning module's *_dump_state_json; `key` is subsystem-specific (e.g. a
 * block_index height/hash). Bound by engine/composition/src/command_catalog.c. */

/* ops.statecatalog — the discovery half of ops.state: every dumpstate
 * subsystem the diagnostics registry holds, with its owner file, cost,
 * accepted key forms and owning test. Renders the SAME catalog as the
 * `statecatalog` RPC (diag_rpc_statecatalog) rather than a second copy,
 * and is node-free — the registry is compiled in. `names` is always
 * complete; per-entry metadata is paged by `limit`/`page`, or fetched
 * whole for one `subsystem`. Bound by engine/composition/src/command_catalog.c. */

/* Node-free, bounded classifier for saved refold H* samples. */

/* ops.slo — node-free, bounded fold of the external uptime probe ledger. */

/* core.network.chain_view — the reachable-network chain view (modal tip, max
 * advertised height, our delta, fork clusters) from the node's network_monitor.
 * Reads the running node's network_monitor dumpstate over the read-only RPC.
 * Bound by
 * engine/composition/src/command_catalog.c. */

/* core.network.peers.add — operator-requested P2P edge. A numeric endpoint
 * dials directly; a v3 onion is resolved through its Tor-served directory
 * before the advertised numeric P2P fast path is scheduled. */

/* core.network.census / .node / .versions / .graph — READ-ONLY operator
 * surface over the banked network census + topology stores (node_census,
 * topology_edges, census_observations under <datadir>/peers_projection.db +
 * topology.db). These
 * open the census SQLite files with SQLITE_OPEN_READONLY in the one-shot CLI
 * process; no running node is required and consensus is never touched. When the
 * indexer lane has not yet created a table they degrade gracefully
 * ("census empty: indexer not yet populated"), never error. Every result is
 * bounded (paginated node list, bounded observation/edge history, bounded
 * distribution). Bound by engine/composition/commands/core.def. */

/* Resolved datadir for the one-shot native CLI process (the --datadir value
 * captured by zcl_native_command_main, or "" when none was given). Read-only
 * accessor for handlers that open a datadir-relative store directly. */
const char *zcl_native_command_datadir(void);
int zcl_native_command_rpc_port(void);
bool zcl_native_command_datadir_is_explicit(void);

/* A one-shot native handler which targets a resident node must submit the
 * canonical input to that daemon instead of opening its live node.db. Returns
 * true when a readable datadir cookie caused forwarding (success or named
 * refusal), false for an in-process resident handler or an offline fixture. */
bool zcl_native_forward_live_command(
    const struct zcl_command_request *request, const char *datadir,
    const char *rpc_method, const char *fallback_code,
    const char *fallback_phase, const char *evidence,
    struct zcl_command_reply *reply);

/* Bind the native controller bridge to an explicit node RPC context.  The
 * resident dev host uses this at boot so a hot-loaded controller cannot
 * accidentally replace the live context with the empty one-shot CLI
 * defaults on its first probe. */
void zcl_native_bridge_bind_rpc(const char *datadir, int rpc_port);

/* ── the one read-only <datadir>/node.db open (native_node_db_ro.c) ───
 *
 * A leaf declared READY_READ must NEVER reach node_db_open(): that is the
 * BOOT ceremony. It opens SQLITE_OPEN_READWRITE|SQLITE_OPEN_CREATE (so a
 * typo'd datadir mints a node.db instead of failing), then runs
 * create_schema + node_db_migrate, quarantines the file by rename() when
 * PRAGMA quick_check fails, and DELETEs the snapshot_staging rows. Every
 * one of those is a write to a datadir the caller merely named — and
 * `datadir` defaults to zcl_native_command_datadir(), i.e. the operator's
 * LIVE node. node.db is WAL, so the running node holding it open blocks
 * none of it. Read leaves use the helpers below instead.
 *
 * Contract: SQLITE_OPEN_READONLY only — never CREATE, never READWRITE —
 * plus `PRAGMA query_only=ON` as a second, connection-wide refusal of any
 * write that slips past the open flags, and a bounded busy timeout so a
 * locked WAL gives up instead of parking a cursor. Nothing is created,
 * migrated, schema-initialized, quarantined, renamed or deleted on any
 * path — INCLUDING the <db>-wal and <db>-shm that a read-only connection to
 * a WAL database otherwise materializes and then cannot unlink on close.
 * Both stores under a datadir are WAL, so that is the ordinary case, not an
 * edge: the open is chosen per database state to leave the directory's file
 * set untouched without ever answering from a stale snapshot. The full
 * reasoning, and the measurement behind it, is the block comment at the top
 * of tools/command/native_node_db_ro.c. The `struct node_db` filled in is a
 * borrowed-handle shim (db + open + path, no prepared statements); close it
 * with zcl_native_node_db_close_readonly, never node_db_close.
 *
 * AND THE FRESHNESS CONTRACT OUTLIVES THE OPEN. On the one path that reads a
 * quiescent WAL database as an immutable snapshot, sqlite does not consult a
 * write-ahead log, so a writer attaching after the handle was returned would
 * leave it answering from the database's past. A guard on the connection
 * re-checks that premise at every statement: if the database is written to, or
 * grows a wal-index or a log, further statements FAIL (SQLITE_AUTH, or
 * SQLITE_INTERRUPT for one already in flight) with the reason named in
 * node.log. So a caller gets a fresh answer or an error — never a stale answer
 * that looks fresh. A statement that had already completed was answered before
 * the change and stays valid. */

/* Why a read-only open produced no handle.
 *
 * ABSENT and UNREADABLE are deliberately DISTINCT. A leaf may legitimately
 * treat "this host has no folded chain" as an empty answer, but it must
 * never give that same empty answer when node.db is present and could not
 * be read. Collapsing the two is how "no rows" comes to mean "I could not
 * look" — callers must branch on the status, not on a NULL handle alone. */
enum zcl_node_db_ro_status {
    ZCL_NODE_DB_RO_OK = 0,       /* opened; *db_out is live and read-only */
    ZCL_NODE_DB_RO_NO_DATADIR,   /* no datadir was resolved at all */
    ZCL_NODE_DB_RO_PATH_TOO_LONG,/* <datadir>/node.db does not fit the buffer */
    ZCL_NODE_DB_RO_ABSENT,       /* nothing exists at <datadir>/node.db */
    ZCL_NODE_DB_RO_UNREADABLE,   /* it exists and is not a readable database */
    /* It is a WAL database carrying a non-empty <db>-wal with no <db>-shm
     * beside it. The log holds commits, and the only way to read them is to
     * create the wal-index — which is a write to a datadir the caller merely
     * named. Distinct from UNREADABLE for the same reason ABSENT is: "the
     * file is fine, I would have had to modify your directory to read it" is
     * a different fact from "it is not a database", and it has a different
     * fix (copy the -shm too, or let the owning node recover the log). */
    ZCL_NODE_DB_RO_UNRECOVERED_LOG,
};

struct node_db;
struct sqlite3;

/* Open <datadir>/node.db strictly read-only. On ZCL_NODE_DB_RO_OK, *db_out
 * is the handle and *ndb_out is the borrowed-handle shim; on every other
 * status *db_out is NULL and *ndb_out is zeroed. `path_out` (optional)
 * always receives the resolved path when it fit, so a caller can report
 * exactly which file it could not read. Nothing is reported for the
 * caller — use zcl_native_node_db_require_readonly for that. */
enum zcl_node_db_ro_status zcl_native_node_db_open_readonly(
    const char *datadir, struct sqlite3 **db_out, struct node_db *ndb_out,
    char *path_out, size_t path_size);

/* The same open, for a leaf where no database means no answer: on any
 * non-OK status the reply is filled with a distinct error code
 * (MISSING_DATADIR / DATADIR_PATH_TOO_LONG / NODE_DB_UNAVAILABLE /
 * NODE_DB_UNREADABLE) naming the path, and false is returned so the caller
 * can `return` straight away. `what` names what the leaf was going to read
 * (e.g. "the ZSLP ledger") and appears in the message. */
bool zcl_native_node_db_require_readonly(
    const char *datadir, struct zcl_command_reply *reply, const char *what,
    struct sqlite3 **db_out, struct node_db *ndb_out);

/* Close a handle from either helper and clear the shim. Idempotent. */
void zcl_native_node_db_close_readonly(struct sqlite3 **db,
                                       struct node_db *ndb);

/* The same read-only contract for the OTHER database under a datadir: the
 * KERNEL STORE, <datadir>/consensus.db (or the legacy progress.kv name, when
 * that is what the datadir still carries — the resolution is
 * consensus_db_kernel_store_path's).
 *
 * Use this, never progress_store_open(), from a leaf declared READ.
 * progress_store_open is READWRITE|CREATE, runs the progress.kv rename
 * migration, ensures the kernel schema, and on a failed integrity check
 * rename()s the append-only fact log aside to consensus.db.corrupt-<ts> and
 * installs a fresh empty one. A booting node can re-derive from that; a read
 * leaf pointed at a copied datadir has simply destroyed the thing it was
 * asked about. This open also takes NO part in the process singleton, so an
 * offline-copy read cannot become the process's one open kernel store.
 *
 * `path_out` (optional) receives the resolved path whenever it fits, INCLUDING
 * on ZCL_NODE_DB_RO_ABSENT, so a caller can name the file it did not find.
 * The caller owns *db_out on OK and closes it with sqlite3_close(). */
enum zcl_node_db_ro_status zcl_native_kernel_store_open_readonly(
    const char *datadir, struct sqlite3 **db_out, char *path_out,
    size_t path_size);

/* ops.selftest — node-free registry self-test. Sweeps every catalog leaf for
 * the static
 * well-formedness the registry guarantees (READY ⇒ dispatchable handler +
 * schema/example + read-effect/risk agreement + a bound bridge tool) and
 * reports total/pass/fail/skip + the failing paths. Deterministic and
 * node-independent so the dev-lane deploy verify can gate on fail == 0. */

/* ops.host.gc — host garbage collection over the dev-proof worktree
 * pools. Dry run by default: classifies every registered worktree under
 * each pool, measures what is reclaimable, and names every refusal. With
 * apply, removes exactly the reapable ones through git worktree removal —
 * the engine has no other deletion path (command/host_gc_sweep.h). */

/* ops.host.slo.probe — one external uptime-probe cycle appended to the SLO
 * ledger. ops.host.slo.page — evaluate the ledger and page on a stall.
 * ops.host.slo.judge — trailing-window hold verdict, optionally recorded. */

/* ops.host.build — admit a command to the host build queue and run it in a
 * limited scope (command/build_admit.h). CLI-only: the JSON handler is a
 * blocker because the command's exit status and stdio cannot travel in the
 * envelope; the CLI intercept runs the job and returns that status. */
bool zcl_native_ops_host_build_try_run(const char *const *words, size_t count,
                                       size_t consumed, int *rc);

/* ops.host.jobs — running and queued build jobs, read from /proc/locks. */

/* ops.host.legacy.status / .seed — legacy zclassicd oracle and bootstrap
 * datadirs: identity, lock, RPC height, ports, and the two-phase seed. */
/* Test seam: replaces the loopback legacy RPC of ops.host.legacy.status. */
void zcl_native_legacy_status_set_rpc(char *(*fn)(const char *datadir,
                                                  int rpcport,
                                                  const char *method));

/* ops.release.sign - sign a landed-main fleet release with the ZRS1 hybrid
 * key and write <release_dir>/z23-<commit12>.v2.zid
 * (tools/command/native_ops_release_sign.c). */

/* ops.slot.install - install a checked-out release binary as a slot only
 * when its signed release doc names a pinned owner key and the bytes match
 * the package manifest exactly (tools/command/native_ops_slot_install.c). */

/* ops.slot.activate - move service instances onto an installed slot one at a
 * time through systemd --user drop-ins, with a MainPID exe check, a health
 * check and automatic rollback (tools/command/native_ops_slot_activate.c). */

/* ops.slot.status - read-only: the slot each instance runs, its last-good
 * and the installed slots with sha256 (tools/command/native_ops_slot_status.c). */

/* ops.debug.meaning — node-free field ontology + question index. Answers
 * "what does this telemetry field mean, is this value bad, and which report
 * answers my question" straight out of the binary's static tables, with no
 * RPC and no node state, so it still works on a node that will not start. */

/* ops.debug.backtrace — dump a live backtrace for every thread of the running
 * node. Dispatches the `selfbacktrace` RPC method directly and
 * projects { path, thread_count }. Answers "what is every thread doing right
 * now" where perf/gdb/ptrace are blocked. Bound by engine/composition/commands/ops.def. */

/* ops.debug.bundle — write a one-shot debug bundle (every registered state
 * dumper + build identity + supervisor stall summary) as ONE JSON document
 * to <datadir>/debug-bundle-<utc>.json on the running node. Dispatches the
 * `debugbundle` RPC method directly and projects { path, bytes,
 * subsystems_captured, subsystems_failed }. Bound by engine/composition/commands/ops.def. */

/* ops.explain <topic> — compose one prose-like diagnostic from four surfaces
 * (reducer frontier, blocker registry, condition engine, health/sync RPCs).
 * Topics: sync, blockers, health (table-dispatched, see
 * engine/controllers/src/explain_native_handlers.c). Reply carries data.text +
 * structured fields; the CLI prints text unless --format=json. */

/* ops.profile [seconds] [top_n] — dispatch the `profile` RPC (in-process
 * /proc/self/task sampling) and render the busiest threads + verdict + reducer
 * stage step-EWMA. */

/* ops.debug.version — `z23 version`: the build's version, source id and Tor link. Node-free and read-only. */

/* ops.producer.status --datadir= — read a mint/anchor producer's kernel
 * store (consensus.db, or the legacy progress.kv on a pre-flip datadir;
 * stage cursors + session/receipt lifecycle) and mint-progress.log tail
 * with NO node contact. Read-only. */

/* ops.rom — dispatch the `dumpstate rom_compile` RPC against THIS running
 * node and render its ROM-compilation-fold telemetry (zcl.rom_compile.v1) as
 * rich ASCII: a fold progress bar, a horizontal bar chart of the eight
 * reducer stages' step_us_ewma (the bottleneck stage highlighted), and the
 * layer ladder (ROM checkpoint / sealed segment history / sealed state-seal
 * ring / delta frontier / tip ring), each filled or empty. The structured
 * fields are also returned verbatim in reply->data for machine consumers;
 * the CLI prints data.text unless --format=json. See
 * engine/jobs/src/rom_compile_status.c for the data source (all EXISTING
 * telemetry — no second producer). */

/* Render the CLI UX contract's ONE-LINE status brief: a single line, <=200
 * bytes, stable `key=value` pairs (no JSON braces), from the flat brief body
 * core.status.brief emits (see zcl_native_status_brief_body): hstar, gap,
 * peer_best, sync_state, primary_blocker, blocker_age_s, active_conditions,
 * peer_count, rss_mb. `buf`/`cap` must be at least 256 bytes; the line is
 * always NUL-terminated and never exceeds 200 visible bytes before the
 * terminator. Exposed for test_operator_ux. See docs/dev/NATIVE_COMMAND_INTERFACE.md
 * "CLI UX contract" for the frozen field list. */
struct json_value;
void zcl_native_status_brief_render(const struct json_value *data, char *buf,
                                    size_t cap);
void zcl_native_status_journey_render(const struct json_value *data,
                                      char *buf, size_t cap);
bool zcl_native_status_journey_headline(const struct json_value *data,
                                       const char *datadir, char *buf,
                                       size_t cap);

/* Pick one short, deterministic next-step command from the same brief body
 * (dominant blocker present -> explain it; still behind -> explain sync;
 * otherwise -> a general healthcheck). Never allocates; returns a pointer to
 * a static string. Backs the bare no-arg `z23` entry point and any
 * leaf invoked with --next. */
const char *zcl_native_status_brief_next_command(const struct json_value *data);

/* Select named top-level fields out of a JSON object and render each as one
 * "key=value\n" line (bools -> true/false, ints -> decimal, strings verbatim,
 * null -> "null", real -> "%g", an object/array value -> compact JSON on that
 * same line). `fields_csv` is a comma-separated, whitespace-tolerant list of
 * top-level key names (max 24, no duplicates). Returns true and fills `out`
 * (NUL-terminated, each line ending in '\n') only when every requested name
 * exists in `obj` — never a partial selection. On any unknown/duplicate name,
 * an empty list, or an output overflow, returns false and fills `err` with a
 * short, human-readable reason (naming the bad field and, space permitting,
 * up to 12 of the object's own known top-level keys); `out` is left
 * untouched. This is the ONE implementation `status field=` and
 * `dumpstate ... field=` both call — see docs/dev/NATIVE_COMMAND_INTERFACE.md
 * "CLI UX contract". */
bool zcl_native_render_field_selection(const struct json_value *obj,
                                       const char *fields_csv,
                                       char *out, size_t out_cap,
                                       char *err, size_t err_cap);

/* The one "exactly 64 lowercase hex characters" contract shared by every
 * DHT root, receipt id, and other 32-byte content-addressed key across the
 * native commands: `value` must decode as canonical (lowercase-only) hex
 * to exactly 32 bytes. On success writes the 32 decoded bytes to `out`
 * (skip the decode by passing NULL) and returns true, `err` untouched. On
 * failure fills `err` (when non-NULL and `err_size` > 0) with one
 * canonical, field-named refusal sentence naming `field`, and returns
 * false. Never allocates. Not for a different length/alphabet contract
 * (40, 66, 68, 112, 128, or 396-byte hex, or a decode that accepts
 * uppercase) — those are different contracts with their own messages. */
bool zcl_native_require_hex64(const char *field, const char *value,
                              uint8_t out[32], char *err, size_t err_size);

/* Build the CLI UX contract's unrecognized-command diagnostic (see
 * docs/dev/NATIVE_COMMAND_INTERFACE.md "CLI UX contract"): one typed
 * `error=UNKNOWN_COMMAND detail=... try=...` line, plus (when the existing
 * command-search index returns any hit — reused, never a new fuzzy matcher)
 * a `did you mean: ...` line naming up to 3 candidate paths. Writes into
 * `out` (NUL-terminated, newline after each line) and returns the byte
 * count written (0 on a NULL/empty method or an output overflow — the
 * caller should fall back to a minimal one-liner in that case). Pure:
 * takes the registry explicitly so a test can pass a fixture instead of the
 * live catalog. */
size_t zcl_native_render_unknown_command(
    const struct zcl_command_registry *reg, const char *method, char *out,
    size_t out_cap);

/* core.node.bootstatus / core.node.bootwait — pre-RPC boot observability. Both
 * read <datadir>/boot_status.json directly off disk (util/boot_status.h): no
 * node contact, no RPC. bootstatus returns the current beacon (or BLOCKED when
 * none exists yet); bootwait polls until phase=serving or a bounded timeout.
 * This is the typed replacement for ss/ps/tail node.log boot watching. Bound
 * by engine/composition/src/command_catalog.c. */

/* ── core.epoch.* — the Bounded Node keystone: commit the OP_RETURN
 * catalog digest-chain on-chain per epoch via a ZANC anchor
 * (tools/command/native_epoch_command.c). v1: operator-triggered only, no
 * background service, no auto-broadcast. */

/* core.anchor.compose / inspect — deterministic generic ZANC digest anchors.
 * Composition returns the exact OP_RETURN script and the raw-create input
 * fragment; funding/signing/broadcast remain separate owner-only commands. */

/* ── core.identity.* — sovereign master keys
 * (tools/command/native_identity_command.c). resolve/list read the
 * zid_identities projection straight out of <datadir>/node.db (READONLY,
 * so a stopped or copied datadir answers too); anchor/rotate/revoke build
 * the ZID\0 overlay and prefer the live node's identity_* RPCs, falling
 * back to op_return_hex when nothing answers. Bound by
 * engine/composition/commands/core.def. */

/* Read one master seed file (the zcode network delegate reader): regular,
 * current-user-only 0400/0600, exactly 64 lowercase hex plus an optional
 * newline. Fills out[32] or names the refusal in err. */
bool zcl_native_read_master_seed_file(const char *path, uint8_t out[32],
                                      char *err, size_t err_cap);

/* ── core.zdir.* — the on-chain node directory WRITE path
 * (tools/command/native_zdir_command.c). register/deregister build the
 * `ZDIR` OP_RETURN and prefer the live node's zdir_* RPCs, falling back to
 * op_return_hex when nothing answers. Pre-flight reads the onion_directory
 * projection out of <datadir>/node.db (READONLY) so an unownable or
 * already-retired row is refused before a fee is spent. There is no
 * transfer leaf: ZDIR command byte 3 is reserved and zdir_parse rejects it,
 * so handing a hostname over is deregister-then-register. Bound by
 * engine/composition/commands/core.def. */


/* core.network.onion.vanity (tools/command/native_onion_vanity.c) — search
 * for a v3 onion identity seed whose address begins with a chosen prefix and
 * write the seed (mode 0600, refusing to overwrite) to a caller-named file.
 * Offline: no node, no Tor, no datadir. The seed never appears in the reply. */

/* core.storage.query.offline / core.sync.frontier.offline
 * (tools/command/native_offline_query.c) — the OFFLINE_COPY scope: inspect a
 * STOPPED or COPIED datadir's SQLite stores directly, with NO node contact
 * and NO RPC. `core.storage.query` and `dumpstate reducer_frontier` both
 * require a running node's RPC; these are the same SELECT-only primitives
 * (dbquery_execute, reducer_frontier_compute_hstar) run against an ad hoc
 * handle opened straight at `--datadir=<path>` — the typed replacement for
 * `build/bin/sqlq <db> <SELECT>` (tools/sqlq.c) plus hand-known table names.
 * Bound by engine/composition/src/command_catalog.c. */
/* core.storage.schema.offline — read-only rolling-upgrade/downgrade
 * classification of a datadir's node.db: schema_version,
 * schema_compat_floor, this binary's NODE_DB_MAX_SCHEMA, and the verdict
 * (upgrade/same/downgrade_ok/downgrade_refused) via
 * node_db_schema_report_for_path(), which never creates, migrates, or
 * writes. Answers even when the live node would refuse to boot against the
 * same file — that refusal is exactly what this leaf explains. */
/* The one write-scoped OFFLINE_COPY leaf: retires a FOREIGN
 * consensus_state_producer_session row (one written by a different build)
 * from a STOPPED datadir so the next boot's begin() can insert a fresh
 * session and the exporter requalifies. Refuses when a node answers on the
 * datadir's RPC (retirement is offline) and delegates the ownership decision
 * to consensus_state_producer_session_retire()'s build-identity match. */

/* app.auth.* / app.account.* — the multi-user-server identity surface
 * (engine/controllers/src/account_controller.c), mounted under the `app` root.
 * app.auth.challenge/app.auth.verify are PUBLIC (no capability):
 * challenge/response public-key login. app.account.* manage principals:
 * list/show/whoami are reads, add/role/suspend/unsuspend are the first
 * executable mutating native leaves (OWNER authority). Each renders one bounded
 * JSON document. Bound by engine/composition/commands/accounts.def. */

/* Mutating core.wallet.* leaves
 * (contexts/wallet/controllers/src/wallet_native_handlers.c). Each parses its input and
 * calls the running node's wallet RPC (getnewaddress / importaddress /
 * dumpprivkey / sendtoaddress / z_sendmany / rescanblockchain /
 * walletbackupnow) over the loopback client, then renders one bounded JSON
 * document. address.new / address.import / rescan / backup.now are one-shot
 * mutations (AUTH_OWNER); transaction.send / shielded.send /
 * address.export-key honour the declared CONFIRM_PLAN_COMMIT contract — a
 * first call with no `confirm:true` returns a non-mutating plan plus the
 * exact commit next-action, and only a second call with `confirm:true`
 * broadcasts or reveals. Bound in engine/composition/commands/core.def. */
/* core.wallet.rescan-witnesses — rebuilds the Sapling witnesses a restored
 * shielded note needs before it can be spent (rpc_rescanwitnesses). */

/* The two OFFLINE recovery leaves
 * (contexts/wallet/controllers/src/wallet_restore_native_handlers.c). Unlike every
 * other wallet leaf these call their service in-process instead of a
 * running node, because a user restoring onto a rebuilt machine has no
 * node yet. `core.wallet.restore` merges a backup file into a datadir and
 * REFUSES while a node holds it; `core.wallet.backup.decrypt` turns a
 * WBE1 file back into a readable one. Both are CONFIRM_PLAN_COMMIT. */

/* The two OFFLINE recovery-phrase leaves
 * (contexts/wallet/controllers/src/wallet_recovery_native_handlers.c). `status` says
 * whether a datadir's wallet can be rebuilt from words at all — a wallet
 * created before recovery phrases honestly answers no. `restore` rebuilds a
 * wallet into an empty datadir from the phrase alone (CONFIRM_PLAN_COMMIT;
 * the plan shows the addresses the words open without writing anything).
 * There is no leaf that prints an existing wallet's phrase: only the
 * derived seed is stored, and it cannot be turned back into words. */

/* core.wallet.address.label(.by-label) — the address-book / label surface
 * (contexts/wallet/controllers/src/wallet_label_controller.c). Direct handlers over
 * app_runtime_node_db(): no wallet keystore, no RPC context. `label`
 * sets or clears a label (EFFECT_MUTATE, RISK_APP_WRITE — a plain
 * annotation, not a key or fund mutation); `by-label` reads every address
 * currently carrying a label. Bound in engine/composition/commands/core.def. */

/* Mutating app.* feature leaves
 * (engine/controllers/src/app_write_native_handlers.c). Each proxies one
 * already-complete node RPC over the loopback client — the ZSLP token writes,
 * the ZNAM writes (name_register/update/transfer/renew/set_record/set_text),
 * the ZMSG writes
 * (msg_send/msg_read) and the ZSWP contract mints
 * (swap_initiate/swap_participate) — and renders one bounded JSON document.
 * Every leaf that can move value honours the declared CONFIRM_PLAN_COMMIT
 * contract: a first call with no `confirm:true` returns a non-mutating plan
 * plus the exact commit input, and only a second call with `confirm:true`
 * broadcasts. A backing RPC that succeeds without doing the job (a ZNAM write
 * that answers status="ready" because the node carries no wallet) is reported
 * BLOCKED with mutated=false, never PASSED. Bound in
 * engine/composition/commands/app_features.def. */
/* Per-node marketplace moderation (no network-wide bans, no deletion, no
 * consensus effect): the node's own profile decides what it lists and what
 * it hands out, from its local-only review_state curation marks.
 * engine/controllers/src/market_moderation_native_handler.c. */

/* Store merchant surface (engine/controllers/src/store_native_handlers.c) — the
 * typed writer behind `app.store.list-product` and the catalog read behind
 * `app.store.products`. Both address <datadir>/node.db the way the /store
 * HTTP handler does, so a listing is live on the next request with no
 * restart. Bound by engine/composition/commands/store.def. */

/* app.shop.* — the storefront orchestration
 * (contexts/market/controllers/src/shop_native_handler.c, docs/work/SHOP_COMMAND.md
 * slice B). `init` composes the slice-A persistent onion identity, the
 * wallet at-rest custody probe, the existing store schema/products.json
 * loader, and the directory apps-row announcement into one plan/commit
 * command; `status` renders the same verification block read-only with
 * every unmet prerequisite named. Bound in engine/composition/commands/store.def. */
/* `reputation` (slice C) is the evidence readout for one ZCODE publisher
 * key over <datadir>/zcode: provable facts only, each with its evidence
 * class and counting window; absent evidence reads 'no_record', never a
 * zero (contexts/market/controllers/src/shop_native_reputation.c). */
/* `want.*` (slice D) is the buyer-posted demand board: signed want ads
 * (Ed25519 shop_want.v1, the zswap quote shape with the terms reversed)
 * persisted to the shop_wants projection, browsed under the node's own
 * community content moderation profile, cancelled by the posting key,
 * and curated by the local review mark
 * (contexts/market/controllers/src/shop_native_want.c). Declared terms only — no
 * escrow, no payment channel. */
/* `want.fulfill.*` (slice E) stores signed seller claims bound to
 * independently re-hashed content.v2 CAS bytes and optional re-verified
 * build/fuzz/benchmark receipts. It has no award or value movement. */

/* app.store.* — the BUYING half of the store
 * (contexts/market/controllers/src/store_buyer_native_handlers.c). Each proxies one
 * storebuy_* RPC, because placing an order mints a one-time Sapling payment
 * address and paying it spends, and a typed command runs in a process with
 * neither a wallet nor an open database. The storebuy_* methods report a
 * refusal as a successful call carrying {ok:false, code}; these handlers turn
 * that code back into a typed status, so PROVER_UNAVAILABLE,
 * PAYMENT_NOT_CONFIRMED and HASH_MISMATCH are distinguishable without reading
 * prose. Bound in engine/composition/commands/store.def. */

/* metaverse.property.* — the sovereign-property CATALOG
 * (contexts/commons/controllers/src/metaverse_controller.c). A read-only projection
 * rebuilt at call time over each property kind's own authoritative model
 * (services/property_catalog.h -> contexts/commons/modules/metaverse adapters); it caches no
 * owner, revision, or status, so it cannot become a second ownership
 * truth, and it never opens a handle whose open() rewrites the datadir.
 * Every view states the evidence grade THIS node earned in THIS call.
 * Bound by engine/composition/commands/metaverse.def. */

/* metaverse.space.* — signed read-only sovereign-space objects carried only
 * by the existing CAS/blob/DHT provider substrate. */
/* Internal composition entry point: identical discovery semantics, but the
 * caller owns an absolute monotonic deadline and lookup cancellation. */
void zcl_native_metaverse_space_discover_until(
    const struct zcl_command_request *request, struct zcl_command_reply *reply,
    int64_t deadline_mono_ms, size_t maximum_wire_bytes);
#ifdef ZCL_TESTING
bool zcl_native_metaverse_space_test_admit_allowed(
    const char *datadir, const uint8_t semantic_root[32],
    const uint8_t transport_root[32], const uint8_t pointer_publisher[32],
    const uint8_t manifest_owner[32], bool manifest);
#endif

/* ROM-seed policy/ledger surface (engine/controllers/src/rom_seed_controller.c)
 * — see engine/composition/commands/ops.def `ops.rom_seed.*` and docs/ROM_DELIVERY.md. */

/* utxo mirror operator rebuild (engine/controllers/src/utxo_mirror_controller.c)
 * - see engine/composition/commands/ops.def `ops.recovery.utxo_mirror`. */
#ifdef ZCL_TESTING
/* Force the post-commit success projection to fail (reply-build fault). */
void zcl_utxo_mirror_controller_test_fail_projection(bool fail);
#endif
/* Publish (register) this node's on-disk starter artifacts so a fresh peer's
 * directory listing advertises a usable manifest — see
 * engine/composition/commands/ops.def `ops.debug.rom_seed.publish`. */

/* ROM-fetch engine surface (engine/controllers/src/rom_fetch_controller.c) —
 * see engine/composition/commands/ops.def `ops.debug.rom_fetch.*` and
 * docs/ROM_DELIVERY.md. The fetch leaf downloads + content-verifies bytes
 * only; activation stays with the unified -install-consensus-bundle path. */

/* dev.agent.* — the checkout questions an agent asks most often, answered as
 * one typed envelope so no agent has to compose shell. Deliberately NOT
 * dev-build-only: an agent has the plain `z23` it just built, and a compat
 * leaf redirecting to a second binary is the dead end this branch removes.
 * Handlers in tools/command/native_devagent_command.c and
 * native_devagent_mutate_command.c; they spawn only through platform/modules/util spawn
 * and link none of the dev-only devloop executors. */
#if defined(ZCL_TESTING)
/* Serialize a zero-initialized landing row with text in note or detail.
 * Refusal leaves len_out unchanged; text must fit its selected field.
 * Invalid UTF-8 leaves the entire output buffer unchanged. */
bool zcl_native_dev_land_test_encode_text(const char *text, bool detail,
                                         char *out, size_t cap,
                                         size_t *len_out);
#endif
/* dev.ci — the one read-only screen over this host's CI and landing state
 * (tools/command/native_dev_ci_command.c). Composition only: every fact is
 * read from dev.land, dev.agent.queue and dev.proof.status called
 * in-process. It writes nothing and cancels nothing; the cancel and retry
 * views name the exact sibling command to run. */
/* dev.ship — native preflight and plan of a fleet deploy, phase 1 of
 * retiring tools/ship.sh (tools/command/native_dev_ship.c). */

/* dev.test.fast_plan — the native changed-set plan of tools/agent_fast_ci.sh
 * plan-json (tools/command/native_dev_fast_plan.c). Read-only; its only
 * child process is git. */

/* dev.fleet.know, aliased `dev know` — the fleet fact table, asked by
 * subject. It reads engine/composition/fleet_facts.def as an X-macro paste
 * through cognition/modules/fleetfacts and touches nothing else: no file,
 * no process, no node, no datadir. */

/* dev.agent.* lane discipline — situation, rules, start, done, triage,
 * ceiling, pace, claim, outcomes. One handler per file under tools/command
 * (native_devagent_<leaf>.c) so each can be implemented and reviewed on its
 * own. They run Git only through platform/modules/util spawn and read only
 * the checkout. dev.agent.claim binds in the catalog only under a dev build
 * (it writes a ledger), but it is DECLARED and compiled unconditionally so
 * its registered test group can call it in the ordinary test binary. */

/* dev.agent.orient — the compiled fact table in engine/composition/facts/,
 * listed by topic, returned for one topic, or filtered by substring.
 * Implemented in tools/command/native_dev_orient.c. */

/* The one-line fact-table banner dev.fleet.start and dev.agent.start print,
 * derived from the same compiled table so no second count exists. */
void zcl_dev_orient_banner(char *out, size_t cap);

/* dev.agent.ticketkey — the commuting-ticket key of one test group at one
 * tip (docs/archive/COMMUTING_TICKETS.md). Same one-handler-per-file shape as
 * the lane-discipline leaves above. */
/* dev.agent.queue — typed non-blocking unit dispatch
 * (tools/command/native_devagent_queue.c). Same one-handler-per-file shape
 * as the lane-discipline leaves above. */
/* dev.agent.mail — async post/pull/ack between agents
 * (tools/command/native_devagent_mail.c). Same one-handler-per-file shape
 * as the lane-discipline leaves above. */
/* dev.agent.mail.wait — bounded blocking pull
 * (tools/command/native_devagent_mail_wait.c). */
/* dev.factory — read-only factory waste report over a window
 * (tools/command/native_dev_factory.c). */
/* dev.land.window — two-lander LAND-WINDOW protocol
 * (tools/command/native_dev_land_window.c). */
/* dev.land.receive / dev.land.send — submit from another machine
 * (tools/command/native_dev_land_remote.c). The first two are the narrow
 * entries it borrows from tools/command/native_dev_land.c. */
/* Receive-only: the sending host already ran the precheck, so this entry
 * skips it. Not reachable from any input key. */
void zcl_native_dev_land_submit_received(const struct zcl_command_request *request,
                                struct zcl_command_reply *reply);
int zcl_native_dev_land_git(const char *dir, const char *const *args,
                            char *out, size_t cap, int timeout_ms);
/* dev.agent.worker — resident dev-only queue consumer
 * (tools/command/native_devagent_worker.c). Same one-handler-per-file
 * shape as the lane-discipline leaves above. */
/* dev.agent.receive — resident mail-consuming receiver that turns a
 * directive into a dev.agent.queue row and answers under the same ref
 * (tools/command/native_devagent_receive.c). Same one-handler-per-file
 * shape as the lane-discipline leaves above. */

/* dev.train.* — stacked-lane construction (tools/command/native_dev_train_command.c).
 * One file for all four verbs: build, check, status, drop. Compiled
 * unconditionally (the release build never references these symbols from
 * dev.def, since ZCL_DEV_HANDLER() resolves to NULL there), so the dev.def
 * row and this prototype are unconditional too, matching the dev.agent
 * family above. */

/* dev.train.keep — the unattended keeper
 * (tools/command/native_dev_train_keep.c). Its own file: the four verbs
 * above are hand-driven, this one runs from a timer with no session alive,
 * and one file owns one job. Compiled unconditionally like its siblings. */

/* dev.index.* — local data-source ingest/search
 * (tools/command/native_dev_index_command.c backed by
 * native_dev_index_{catalog,ingest,search}.c). Compiled unconditionally,
 * same reasoning as dev.train.* above. */

/* CLI-only: parses `z23 dev train <verb> --name=... --source=... [...]`
 * into the leaf input object (repeated --source is not representable by the
 * generic --key=value flag parser). Returns false with a reason in `why`
 * for an unknown flag or an overlong name. The caller validates the object
 * and executes the leaf through the ordinary envelope path. */
bool zcl_native_dev_train_cli_input(const char *const *words,
                                    size_t word_count, size_t consumed,
                                    struct json_value *input, char *why,
                                    size_t why_cap);

/* Dev-build-only executors.  The catalog binds these only when
 * ZCL_DEV_BUILD is set; release objects neither reference nor link them. */
#if defined(ZCL_DEV_BUILD) || defined(ZCL_TESTING)
#endif

#ifdef ZCL_DEV_BUILD
/* Both hot-swap commands are hard-contained compatibility entrypoints; probe
 * must not dlopen candidates in the resident node before ELF admission. */
#endif

#if defined(ZCL_DEV_BUILD) || defined(ZCL_TESTING)
#endif

/* ── ops.telemetry.sync.* — the typed sync-domain telemetry leaves
 * (tools/command/native_telemetry_sync_command.c). Pure control: each fills
 * ONE struct sync_snapshot through services/sync_telemetry.h and renders it
 * with telemetry_render() — the single renderer — then, for `stages`/`stage`,
 * projects that already-rendered document into one row per ladder rung. No
 * telemetry field name is spelled here, no health is decided here, and no
 * database or node is contacted. Bound by engine/composition/commands/telemetry/sync.def. */

/* ── ops.telemetry.watch — the resumable change feed
 * (tools/command/native_telemetry_watch_command.c). A CURSOR POLL: it returns
 * the bounded batch of changes recorded after `since` and exits. Declared
 * MODE_STREAM because that is what it is; there is no long-lived dispatch path
 * and this handler does not add one. Bound by
 * engine/composition/commands/telemetry/watch.def. */

/* ── metaverse.agent.* — the confined-agent broker's observation surface
 * (contexts/commons/controllers/src/metaverse_controller.c). Both read one broker
 * DIRECTORY named by the caller and create nothing; the broker itself is a
 * separate confined process, not node state. Bound by
 * engine/composition/commands/metaverse.def. */

/* ── ops.telemetry.runtime.* — the `runtime` telemetry domain
 * (tools/command/native_telemetry_runtime_command.c). Each picks one group of
 * the typed runtime snapshot and hands it to the single render layer; none of
 * them names a field. Bound by engine/composition/commands/telemetry/runtime.def. */

/* ── ops.telemetry.network.* — the network telemetry domain
 * (tools/command/native_telemetry_network_command.c). Four VIEWS of ONE typed
 * snapshot, not four data sources: each handler fills a
 * `struct network_snapshot` through network_dump_state_fill() and hands it to
 * telemetry_render() at its view and group. They touch no node global, decide
 * no health, and name no field. Bound by engine/composition/commands/telemetry/network.def. */

/* ── ops.telemetry.storage.* — the STORAGE telemetry domain
 * (tools/command/native_telemetry_storage_command.c). Each handler picks one
 * view/group token and makes one SELECT-only `dumpstate storage_telemetry`
 * call; the typed snapshot is filled and rendered inside the node by
 * engine/services/src/storage_telemetry_fill.c, because a one-shot CLI process
 * has no initialized storage subsystems to read. Bound by
 * engine/composition/commands/telemetry/storage.def. */

/* ── ops.telemetry.wallet.* — the wallet telemetry domain's two views
 * (tools/command/native_telemetry_wallet_command.c). Both pick the typed
 * wallet snapshot filled by services/wallet_telemetry.h and hand it to the
 * one shared renderer; neither names a field, decides health, or builds a
 * document. Posture only: no key, address or balance can appear in either
 * reply. Bound by engine/composition/commands/telemetry/wallet.def. */

/* ── ops.telemetry.agents.* — the AGENTS telemetry domain
 * (tools/command/native_telemetry_agents_command.c). Each renders one group
 * of the typed agents snapshot filled by agents_dump_state_fill()
 * (engine/services/src/agents_telemetry.h); the field names live only in
 * platform/modules/util/include/util/telemetry/agents_fields.def. Bound by
 * engine/composition/commands/telemetry/agents.def. */

/* ── ops.telemetry.zcode.* — the zcode telemetry domain
 * (tools/command/native_telemetry_zcode_command.c). Picks the typed zcode
 * snapshot and a view and hands both to telemetry_render(); it names no
 * field and decides no health. Field names, units and rules live in
 * util/telemetry/zcode_fields.def; the collector is
 * engine/services/src/zcode_telemetry_fill.c. Bound by
 * engine/composition/commands/telemetry/zcode.def, whose `swarm` and `installs` leaves
 * stay PLANNED and so have no handler here. */

/* ── ops.telemetry.metaverse.* — the typed metaverse telemetry domain
 * (tools/command/native_telemetry_metaverse_command.c). One READY leaf; it
 * renders the compiled-in property-kind vocabulary and its adapter registry,
 * so it needs no datadir and no running node. `market` and `services` stay
 * PLANNED — see engine/composition/commands/telemetry/metaverse.def for why. */

/* metaverse.build.* — durable content-addressed build coordinator ledger. */

/* ── the three WHOLE-NODE rollups
 * (tools/command/native_telemetry_rollup_command.c). They iterate the provider
 * registry rather than naming domains, and fold verdicts from the one shared
 * evaluator with max() over the ordered health enum — they compute no health
 * of their own, so they cannot disagree with the per-domain leaf they point
 * at. `ops.telemetry.alerts.history` stays PLANNED: there is no durable alert
 * feed to read. Bound by engine/composition/commands/telemetry/root.def. */

/* ── the fleet AI message board and wiki
 * (tools/command/native_fleet_board_command.c). Every leaf asks the local
 * running node over the `fleet_board` RPC method and fails closed when none
 * answers; none of them can write a private copy. Bound by
 * engine/composition/commands/fleet_board.def. */
enum {
    /* One board call, JSON-encoded: a wiki page is the largest thing that
     * fits, plus room for the field names around it. */
    FLEET_BOARD_RPC_PARAMS_MAX = 24576,
    /* One rendered board line. A post's text is capped at 2 KiB. */
    FLEET_BOARD_LINE_MAX = 2560,
};
/* One raw board RPC round trip for leaves that read the board themselves
 * (tools/command/native_work_command.c). Fills `reply` on failure. */
bool zcl_native_fleet_board_call(struct json_value *in, struct json_value *body,
                                 struct zcl_command_reply *reply);
/* The same node call zcl_native_handle_fleet_board_post makes (the
 * `fleet_board` RPC method), factored out so another native leaf — a
 * trigger's board_post action — can post a `note` without shelling out to
 * `z23-dev fleet board post` or duplicating the RPC envelope handling.
 * Fails closed with a plain-English `why` when no node answers, exactly
 * like the CLI leaf. */
bool zcl_native_fleet_board_post_note(const char *text, char *why,
                                      size_t why_cap);
/* Read-only composition helper. Uses an absolute monotonic deadline in ms;
 * expired/nonpositive deadlines refuse without a request. Only this helper
 * is capped to FAST; ordinary board leaves retain their generic timeouts. */
void zcl_native_fleet_board_list_until(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply, int64_t deadline_ms);
/* Same search under one absolute monotonic deadline in ms (capped to FAST per
 * request); an expired deadline refuses without a request. */
void zcl_native_fleet_wiki_find_until(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply, int64_t deadline_ms);

/* ── the per-node mind (tools/command/native_mind_command.c). `ask` reads the
 * published index generation and NEVER rebuilds: a stale generation is
 * refused with INDEX_STALE rather than answered, because the resident owns
 * the rebuild and a superseded answer is wrong in a way the caller cannot
 * see. `status --fleet` reads the mind rows peers already delivered inside
 * signed mesh-status receipts and fails closed with no local node. Bound by
 * engine/composition/commands/mind.def. */

/* ── one-paste fleet enrolment
 * (tools/command/native_fleet_enrol_command.c). `fleet invite`, `fleet
 * join`, `fleet admit` and `fleet machines` share one dispatcher because
 * they are four steps of one ceremony over one record set. Unlike the board
 * next door, these leaves ask no node: the computer being enrolled has not
 * got one yet. Bound by engine/composition/commands/fleet_enrol.def; the
 * record formats live in tools/dev/fleet_enrol.h. */

/* ── beta6 bootstrap serve-tree verifier
 * (tools/command/native_dev_beta6_verify.c). Runs the real beta6_bs_arm()
 * preflight against a candidate serve directory in this process only, then
 * disarms; never touches a running node's own armed state. Bound by
 * engine/composition/commands/dev.def. */

/* dev.app.machine.boot (alias dev.machine.boot) — one run of the built-in
 * RISC-V machine on a kernel image
 * and an optional disk (tools/command/native_dev_machine_boot.c). Inputs are
 * opened read-only before the optional transcript is created exclusively. */

/* dev.app.machine.snapshot and dev.app.machine.resume - save a booted guest to
 * a snapshot file and continue one from it
 * (tools/command/native_dev_machine_snapshot.c). */

/* dev.app.machine.data — create, grow and inspect the expandable guest data
 * disks under ~/.z23/guests (tools/command/native_dev_machine_data.c). */

/* dev.app.machine.shell: the same machine with its console on the caller's
 * terminal, or on stdin and stdout as byte streams
 * (tools/command/native_dev_machine_shell.c). Interactive and not repeatable. */
#ifdef ZCL_TESTING
/* Overrides the descriptors the shell leaf takes as console input and output;
 * -1 restores stdin and stdout. */
void zcl_ms_test_fds(int in_fd, int out_fd);
/* Makes the leaf behave as if its input had been read from stdin. */
void zcl_ms_test_input_on_stdin(bool on);
#endif

/* Inert release artifact preparation and local CAS admission. */

#ifdef __cplusplus
}
#endif

#endif /* ZCL_TOOLS_NATIVE_COMMAND_H */
