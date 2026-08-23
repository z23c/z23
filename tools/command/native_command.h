/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#ifndef ZCL_TOOLS_NATIVE_COMMAND_H
#define ZCL_TOOLS_NATIVE_COMMAND_H

#include "kernel/command_registry.h"
#include "controllers/native_handler_body.h"
#include "chain/chainparamsbase.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

bool zcl_native_command_is_root(const char *word);

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
 * by config/src/command_catalog.c. */
void zcl_native_bridge_command(const struct zcl_command_request *request,
                               struct zcl_command_reply *reply);

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

/* Project a bridged command body into reply->data bounded by request->view
 * (summary|normal|full), request->budget_bytes, request->max_items, and
 * request->cursor, emitting an explicit `_page` descriptor and — when
 * truncated — one structured retrieval next-command. Exposed for golden tests
 * so progressive disclosure can be proven without contacting a node. */
void zcl_native_bridge_project(const struct zcl_command_request *request,
                               const struct json_value *body,
                               struct zcl_command_reply *reply);

/* Dispatch lookups. Every bridged leaf resolves to exactly
 * one of the two: a re-homed body function OR a direct JSON-RPC method.
 * Pure lookups — no node contact. The golden catalog test proves the union
 * covers every bridged leaf and never overlaps. */
zcl_native_body_fn zcl_native_bridge_body_for_path(const char *path);
const char *zcl_native_bridge_rpc_for_path(const char *path);

void zcl_native_handle_discover_help(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_discover_search(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_discover_describe(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_discover_schema(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_dev_status(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
/* dev.ff — the fail-fast edit-loop ladder (`make ff`: compile -> focused
 * tests -> lint-fast, see tools/command/native_dev_command.c). A release
 * build's copy of this function is a `#ifndef ZCL_DEV_BUILD` stub that fails
 * BLOCKED without spawning anything (zcl_devloop_process_run is dev-only
 * linked, see Makefile DEV_ONLY_SRCS). */
void zcl_native_handle_dev_ff(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_dev_publication_status(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_dev_publication_advance(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_dev_publication_collect(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_dev_publication_mirror_record(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_dev_verify_change(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_dev_core_boundary(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_dev_app_describe(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_dev_app_plan(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_dev_app_simulate(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_dev_change_plan(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
/* dev.vcs.revert — one-command source+binary revert (see
 * tools/command/native_dev_command.c). A release build's copy of this
 * function is a `#ifndef ZCL_DEV_BUILD` stub that fails BLOCKED without
 * touching lib/vcs/ or spawning anything. */
void zcl_native_handle_dev_vcs_revert(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
/* dev.vcs.seal.grant — owner-run ZVCS unseal-token ritual (see
 * tools/command/native_dev_command.c). Mirrors dev.vcs.revert's shape: a
 * release build's copy of this function is a `#ifndef ZCL_DEV_BUILD` stub
 * that fails BLOCKED without touching lib/vcs/ or spawning anything. */
void zcl_native_handle_dev_vcs_seal_grant(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_app_list(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_transaction_types_list(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_transaction_type_show(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_transaction_type_guide(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_transaction_micro_lab(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_transaction_command(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_transaction_wire_catalog(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zpay_compose(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zpay_inspect(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);

void zcl_native_handle_zses_invite_create(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zses_invite_accept(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_ops_mesh_join(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_ops_mesh_join_status(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);

/* ── app.service.* — declared services (tools/command/native_service_command.c).
 * `list` and `inspect` read the compile-time zcl.service_binding.v1 catalog
 * and touch nothing else. `access` opens <datadir>/node.db read-only to
 * evaluate one binding's ZSLP token gate at its declared snapshot height.
 * `status` reads the in-process lifecycle registry. */
void zcl_native_handle_service_list(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_service_inspect(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_service_access(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_service_status(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);

/* ── code.* — the source-code navigator (tools/command/native_code_command.c
 * plus native_code_guide_command.c for the inner-loop guide). Local,
 * read-only, deterministic leaves backed by the in-binary lib/codeindex
 * index. Each renders one bounded JSON document (structured array + human
 * one-liners) well within ZCL_COMMAND_RESULT_BUDGET. */
void zcl_native_handle_code_guide(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_code_group(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_code_file(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_code_sym(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
/* code.capsule — one bounded document composing a symbol's identity, direct
 * callers/callees, in-tree includes of its def file, and the command paths
 * whose registered handler is defined there (config/command_handler_index.h
 * join). Budget-aware self-shrinking: see native_code_command.c. */
void zcl_native_handle_code_capsule(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_code_change_plan(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_code_refs(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_code_find(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
/* code.map — the whole-tree map: the 9 root groups (aggregate file counts +
 * purposes) and the 8 app/ shapes (direct file counts), plus a total. */
void zcl_native_handle_code_map(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
/* code.tests — the routing link: which focused test group a change to one file
 * routes to, mirroring `dev test plan` (tools/dev/devloop_plan.c). */
void zcl_native_handle_code_tests(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
/* code.room — the unified single-room view: composes shape + purpose + group +
 * neighbors + tests/route for one path into one bounded document (palace-design
 * §2). The command→file join is degraded to null (registry stores handler
 * pointers, not symbol names). */
void zcl_native_handle_code_room(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
/* code.impact — the blast-radius leaf: the reverse-dependency closure of one
 * changed file (codeindex_impact_closure) plus the downstream focused test
 * groups (the same agent_impact_apply_shared_rules() resolver code.tests
 * uses) and two quick depth-1 fan-out numbers (direct_includes,
 * direct_callers). See native_code_command.c for the cap+truncated contract. */
void zcl_native_handle_code_impact(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
/* code.merkle — the identity leaf: the SHA3-256 Merkle root over the indexed
 * source tree, any directory's subtree root, or one file's leaf digest, plus
 * the direct child subtree roots and what the refresh cost (files re-read,
 * bytes hashed, directory nodes recomputed). Backed by
 * lib/codeindex/src/codeindex_merkle.c; does not open the symbol index. */
void zcl_native_handle_code_merkle(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);

/* code.provenance.facts — the writer census: every durable named slot (a key in
 * progress_meta / stage_cursor / node_state) with the count of distinct FILES
 * that write it, ranked multi-writer first; with a `key`, each writer as
 * file:line via its write function or SQL verb. Re-derived for each exact
 * source generation and memoized in-process by the code index's sealed content
 * root. See app/controllers/src/fact_writers.c for the two derivations and
 * controllers/fact_store_writers.def for the manifest that states them. */
void zcl_native_handle_code_facts(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);

/* code.provenance.emitter — the reverse direction of every other code leaf:
 * given text the node EMITTED (a blocker id, a dumper subsystem name, a
 * reason/log fragment), return the source site that formatted it, its enclosing
 * function and callers, the .def registry rows that own it, and the proof that
 * covers it. Implemented in tools/command/native_code_emitter_command.c. */
void zcl_native_handle_code_emitter(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);

/* Resolve the focused-test proof group for a changed source `path`, mirroring
 * tools/dev/devloop_plan.c:171-185 so `code tests` and `dev test plan` never
 * disagree. When non-NULL, `acc` is filled with the matched shared-rule groups
 * (caller may enumerate acc->groups[0..groups_len]) and `consensus_risk`
 * reports whether the path is a consensus / sealed-core surface. Returns a
 * static string owned by the registry ("consensus_parity" / a shared-rule
 * group / "make_lint_gates") — pure, no node contact, no allocation. */
struct agent_impact_acc;
const char *zcl_native_code_route_for_path(const char *path,
                                           struct agent_impact_acc *acc,
                                           bool *consensus_risk);
void zcl_native_handle_app_inspect(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);

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
 * config/commands/vault.def. */
void zcl_native_handle_vault_list(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_vault_show(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_vault_encumbered(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_vault_routes(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_vault_send(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_vault_send_shielded(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_vault_send_token(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_vault_intent_issue(
    const struct zcl_command_request *request, struct zcl_command_reply *reply);
void zcl_native_handle_vault_intent_plan(
    const struct zcl_command_request *request, struct zcl_command_reply *reply);
void zcl_native_handle_vault_intent_fanout_plan(
    const struct zcl_command_request *request, struct zcl_command_reply *reply);
void zcl_native_handle_vault_intent_commit(
    const struct zcl_command_request *request, struct zcl_command_reply *reply);
void zcl_native_handle_vault_intent_submit(
    const struct zcl_command_request *request, struct zcl_command_reply *reply);
void zcl_native_handle_vault_intent_cancel(
    const struct zcl_command_request *request, struct zcl_command_reply *reply);
void zcl_native_handle_vault_intent_status(
    const struct zcl_command_request *request, struct zcl_command_reply *reply);
void zcl_native_handle_vault_intent_list(
    const struct zcl_command_request *request, struct zcl_command_reply *reply);
void zcl_native_handle_qr_show(
    const struct zcl_command_request *request, struct zcl_command_reply *reply);
struct zcl_present_model_v1;
void zcl_native_handle_presentation_show(
    const struct zcl_command_request *request, struct zcl_command_reply *reply);
void zcl_native_handle_presentation_status(
    const struct zcl_command_request *request, struct zcl_command_reply *reply);
void zcl_native_handle_presentation_corpus(
    const struct zcl_command_request *request, struct zcl_command_reply *reply);
void zcl_native_handle_presentation_code_change(
    const struct zcl_command_request *request, struct zcl_command_reply *reply);
void zcl_native_handle_presentation_development(
    const struct zcl_command_request *request, struct zcl_command_reply *reply);
void zcl_native_handle_presentation_reproduction(
    const struct zcl_command_request *request, struct zcl_command_reply *reply);
void zcl_native_handle_presentation_publication_confirm(
    const struct zcl_command_request *request, struct zcl_command_reply *reply);
void zcl_native_handle_presentation_release_confirm(
    const struct zcl_command_request *request, struct zcl_command_reply *reply);
void zcl_native_handle_presentation_publication_status(
    const struct zcl_command_request *request, struct zcl_command_reply *reply);
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
void zcl_native_handle_vault_swap_redeem(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_vault_swap_refund(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);

/* vault.session.* — scoped, revocable spend-authority grants for agents
 * (tools/command/native_vault_session_command.c): mint/list/revoke over the
 * agent session service (services/agent_session_service.h). Grants, not
 * custody — no spend logic here either, and the full session token is
 * rendered exactly once (the create commit reply); every later rendering is
 * redacted. Bound by config/commands/vault.def. */
void zcl_native_handle_vault_session_create(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_vault_session_list(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_vault_session_revoke(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);

/* zcode — ZCODE source-package hosting (slice 3: local publication and
 * search). publish plan/commit validate a candidate release against every
 * publication rule (each rejection names the rule) and commit persists
 * through the lib/vcs store; search/show read the rebuildable package
 * index projection. Bound by config/commands/zcode.def. */
void zcl_native_handle_zcode_package_publish_plan(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_package_publish_commit(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_package_guide(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_package_dev_prepare(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_package_dev_seal(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_source_bundle_create(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_source_capture(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_source_bundle_verify(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_source_bundle_import(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_source_bundle_checkout(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_source_package_checkout(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_project_inspect(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_project_init_plan(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_project_init_commit(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_project_status(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_work_start(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_work_context(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_work_run(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_work_preflight(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_work_status(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_work_review(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_work_accept(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_package_dev_score_plan(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_package_dev_score_commit(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_package_dev_score_show(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_guide(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_toolchain_show(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
bool zcl_native_zcode_workspace_is_explicit_scratch(const char *workspace);
void zcl_native_handle_zcode_commons_status(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_commons_epoch(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_commons_creation_show(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_commons_lineage(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_commons_verify(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_commons_rebuild(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_moderation_policy_list(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_moderation_policy_show(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_moderation_status(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_moderation_service_status(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_commons_economics_status(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_commons_backlog(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_commons_claim_plan(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_commons_claim_commit(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_commons_claim_show(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_commons_corpus_status(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_commons_corpus_show(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_commons_corpus_verify(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_passport_verify(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_passport_plan(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_passport_commit(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_passport_status(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_workspace_plan(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_workspace_verify(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_workspace_status(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_workspace_manifest_plan(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_workspace_manifest_commit(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_commons_corpus_shard_verify(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_commons_corpus_shard_page(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_commons_impact_verify(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_commons_impact_status(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_commons_impact_share(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_commons_shadow_plan(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_commons_shadow_attribution_plan(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_commons_shadow_attribution_commit(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_commons_shadow_epoch_plan(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_commons_shadow_epoch_commit(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_commons_shadow_status(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_commons_shadow_verify(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_commons_shadow_protocol_verify(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_commons_schedule_propose_plan(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_commons_schedule_propose_commit(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_commons_schedule_claim_plan(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_commons_schedule_claim_commit(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_commons_schedule_claim_verify(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_commons_schedule_claim_show(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_reproduction_challenge_plan(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_reproduction_challenge_commit(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_patronage_offer_plan(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_patronage_offer_commit(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_patronage_fund_plan(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_patronage_fund_commit(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_patronage_show(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_patronage_list(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_patronage_settle_plan(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_patronage_settle_commit(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_patronage_refund_plan(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_patronage_refund_commit(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
/* Simulation anchor/policy verification report for the ZC23 Living Commons
 * status surfaces (docs/METAVERSE_MVP.md MM4/LC3). `complete` is reported
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
void zcl_native_handle_zcode_continuity_plan(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_continuity_commit(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_continuity_status(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_package_search(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_package_library(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_create(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_use(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_science_study_plan(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_science_study_commit(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_science_findings_plan(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_science_findings_commit(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_science_study_show(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_science_study_list(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_science_work_plan(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_science_work_commit(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_science_work_status(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_science_work_receipt(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
/* S4: the closed benchmark/reproduction executor (additive leaf in
 * config/commands/zcode_science.def; handler lives in
 * native_zcode_science_exec_command.c). */
void zcl_native_handle_zcode_science_work_execute(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_science_review_submit(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_science_vote_submit(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
/* S5: local discovery ranking over the rebuildable science projection
 * (additive leaves in config/commands/zcode_science.def; handlers live in
 * native_zcode_science_discover_command.c). Explanatory only — never read
 * by evidence admission, routing, rewards, or protocol control. */
void zcl_native_handle_zcode_science_discover(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_science_rank_snapshot(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
/* Acceptance-proof glue: operator surface for zcode_science_rebuild (the
 * CAS-authoritative projection rebuild previously reachable only from
 * tests). Handler lives in native_zcode_science_command.c. */
void zcl_native_handle_zcode_science_rebuild(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
/* G1 carrier: science objects ride the package swarm as one-chunk blobs
 * (vcs/blob_store.h). publish mirrors a committed CAS wire into the
 * package store (blob root = transport address, science root = semantic
 * address, re-derived at admit); fetch schedules the swarm download and
 * admits the bytes (re-derive root, CAS, projection) once local. Handlers
 * live in native_zcode_science_command.c. */
void zcl_native_handle_zcode_science_publish(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_science_fetch(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
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
void zcl_native_handle_yardsale_guide(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_yardsale_seller_arm(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_yardsale_seller_disarm(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_yardsale_seller_status(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_yardsale_buy(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_improve(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_evidence(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_accept(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_lane(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_lane_guide(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_tasks(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_publish_plan(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_publish_commit(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);

/* ── zcode.release.* — Sovereign Registry v1: sign/verify zid release
 * records (tools/command/native_zcode_release_command.c). Signing is
 * file-based (no swarm distribution). anchor folds the releases dir into
 * the zid anchor-domain tree (digest-sorted canonical order) and stores
 * the leaf set + root in zid_domains/zid_domain_leaves; prove reads that
 * stored leaf set, so a .zid added or removed later cannot silently
 * change what an issued proof means. zcode.domain.* inspects the store. */
void zcl_native_handle_zcode_release_sign(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_release_verify(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_release_anchor(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_release_prove(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_domain_list(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_domain_status(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);

/* zcode.proof.walk — the light-client proof-chain walker
 * (tools/command/native_proof_chain_command.c). Reports each rung of the
 * spec's chain independently as passed/failed/not_checked; a walk that ran
 * always returns PASSED because the envelope drops `data` on any other
 * status and the seven-rung report IS the product. */
void zcl_native_handle_proof_chain_walk(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);

/* ── zcode.desc.* — signed onion-service descriptors
 * (tools/command/native_zdesc_command.c). Publish stores the signed doc
 * as a content-addressed blob and files it under the BLINDED record key
 * for the current period; verify/resolve check the signature against a
 * CALLER-SUPPLIED master pubkey. Every reply carries
 * chain_anchored:false — nothing here consults the chain. */
void zcl_native_handle_zdesc_publish(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zdesc_verify(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zdesc_resolve(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_network_delegate(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_network_status(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_network_peers(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_network_find(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_network_find_begin(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_network_find_poll(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_network_find_cancel(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_network_records(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
bool zcl_native_zcode_network_genesis(uint8_t out[32]);
void zcl_native_handle_zcode_network_records_begin(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_network_records_poll(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_network_records_cancel(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_network_providers(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_network_publish(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_network_storage_ack(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_package_source_reproduce(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_network_policy_list(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_network_policy_mutate(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_network_replication(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);

/* ── zcode.endpoint.* — signed endpoint records
 * (tools/command/native_zendp_command.c). The chain-bound twin of
 * zcode.desc.*: no key is supplied by the caller on the verify side,
 * the record carries its own and it is resolved against the on-chain
 * identity projection, so every reply carries chain_anchored:true. A
 * record that does not resolve to an ACTIVE anchor is DISCARDED — no
 * file is written and nothing enters any directory. Publication is
 * operator-invoked only: there is no timer, no background publisher,
 * and no flag to enable one. */
void zcl_native_handle_zendp_publish(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zendp_verify(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zendp_accept(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zendp_resolve(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zendp_list(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_package_show(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);

/* zcode slice 5 — the decoded declarative build recipe for one package
 * root. Display-only JSON from the canonical recipe wire; the node never
 * compiles or executes downloaded code. */
void zcl_native_handle_zcode_package_recipe(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);

/* zcode slice 6 — external-verifier attestation quorum for one package
 * root: evaluates the attestations/ dir against the local approved-verifier
 * allowlist (<datadir>/zcode/approved_verifiers) and reports the quorum
 * state with every named rule. The node only READS attestations; they are
 * produced by the separate zclassic23-package-verify program. */
void zcl_native_handle_zcode_package_verify(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);

/* zcode slice 4 — contributor identity + ZNAM pointers. The publisher key
 * is the only identity; ZNAM records resolve through the canonical model
 * with an explicit binding proof. Bound by config/commands/zcode.def. */
void zcl_native_handle_zcode_contributor_show(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_contributor_packages(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_package_resolve(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);

/* zcode slice 7 — bounded deterministic contribution scoring and the
 * reward eligibility gate list. score computes the semantic-line/lineage
 * breakdown from the persisted CAS bytes only (same bytes, same score);
 * eligible evaluates the frozen eight-gate list and names every failed
 * gate. Read-only: settlement is the slice-8 settle handler set below.
 * Bound by config/commands/zcode.def. */
void zcl_native_handle_zcode_reward_score(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_reward_eligible(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);

/* zcode slice 8 — SIMULATED reward settlement (placeholder token id only;
 * never the real ZCODE token, no on-chain payout in v1). queue inspects
 * the daily settlement queue; plan assembles one capped settlement window
 * batch (the only mutation is the plan id); commit settles SIMULATED with
 * durable ledger facts, idempotent against replay (a duplicate is named,
 * never a double-pay); receipt reads the durable evidence of a settled
 * batch. Bound by config/commands/zcode.def. */
void zcl_native_handle_zcode_reward_queue(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_reward_plan(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_reward_commit(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_reward_receipt(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);

/* zcode slice 9 — the ZCODE Rankings: daily/weekly/monthly/all-time
 * leaderboards ranking EARNED ZCODE SCORE only (never a balance — no
 * balance or transfer record kind exists), a rebuildable projection over
 * the slice-8 reward ledger with pure window arithmetic (the caller
 * passes "today"). Bound by config/commands/zcode.def. */
void zcl_native_handle_zcode_leaderboard_daily(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_leaderboard_weekly(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_leaderboard_monthly(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_leaderboard_all(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);

/* zcode slice 10 — SIMULATED ZCODE Badges: permanent achievement
 * evidence (canonical binary wire + domain-separated SHA3 id, issuer-
 * signed; SIMULATED ZSLP-based assets only — no real mint, the
 * owner-reviewed real issuance is slice 15). Eligibility derives from
 * the slice-8 ledger, slice-9 rankings, and slice-3 publish history;
 * issuance is plan/commit with the dedup rule (never the same badge
 * twice for the same contributor + achievement period) enforced at plan
 * and re-checked at issue. Bound by config/commands/zcode.def. */
void zcl_native_handle_zcode_badge_eligible(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_badge_plan(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_badge_issue(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_contributor_badges(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);

/* zcode slice 11 — the LOCAL P2P ratio + anti-spam policy surfaces:
 * per-contributor-key verified-bytes accounting and the local ratio
 * (no global ZCODE mint for bandwidth), tier resolution from earned
 * score + local ratio, the frozen policy table, and the store quota
 * pools with the per-tier pin-allowance policy view. Every rejection
 * names the exact rule. Bound by config/commands/zcode.def. */
void zcl_native_handle_zcode_seed_status(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_seed_ratio(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_storage_status(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);

/* zcode slice 12 — the authenticated package swarm's operator surface:
 * fetch starts/resumes a swarm download (live node-global engine when a
 * hosting node runs, otherwise the persisted resumable record for the
 * next hosting boot), peers reports the live engine's per-peer view of
 * one root (session pseudo-keys, never contributor identities), offered
 * lists roots peers have ANNOUNCEd this session (no invented replica
 * counts), and pin/unpin are the operator's never-tier-gated PINS-pool
 * path. Every rejection names the exact rule. Bound by
 * config/commands/zcode.def. */
void zcl_native_handle_zcode_package_fetch(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_package_peers(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_package_offered(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_package_pin(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_package_unpin(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_package_checkout(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);

/* zcode package add plan / add commit / rollback — the install lifecycle.
 * plan resolves a name-or-root, locks the dependency DAG to immutable
 * package roots and reports what each step's state actually is; commit
 * re-derives that lock, refuses a stale or expired plan, then verifies,
 * builds+tests in the confined worker, re-hashes every artifact, installs
 * atomically and pins. rollback re-activates the previous generation.
 * Nothing installed is ever loaded into this process. Every rejection names
 * the exact rule. Bound by config/commands/zcode.def. */
void zcl_native_handle_zcode_package_add_plan(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_package_add_commit(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_zcode_package_rollback(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);

/* ops.state — generic subsystem state dump. Dispatches the `dumpstate` RPC
 * method directly. `subsystem` (required) selects the
 * owning module's *_dump_state_json; `key` is subsystem-specific (e.g. a
 * block_index height/hash). Bound by config/src/command_catalog.c. */
void zcl_native_handle_ops_state(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);

/* ops.statecatalog — the discovery half of ops.state: every dumpstate
 * subsystem the diagnostics registry holds, with its owner file, cost,
 * accepted key forms and owning test. Renders the SAME catalog as the
 * `statecatalog` RPC (diag_rpc_statecatalog) rather than a second copy,
 * and is node-free — the registry is compiled in. `names` is always
 * complete; per-entry metadata is paged by `limit`/`page`, or fetched
 * whole for one `subsystem`. Bound by config/src/command_catalog.c. */
void zcl_native_handle_ops_statecatalog(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);

/* core.network.chain_view — the reachable-network chain view (modal tip, max
 * advertised height, our delta, fork clusters) from the node's network_monitor.
 * Reads the running node's network_monitor dumpstate over the read-only RPC.
 * Bound by
 * config/src/command_catalog.c. */
void zcl_native_handle_network_chain_view(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);

/* core.network.peers.add — operator-requested P2P edge. A numeric endpoint
 * dials directly; a v3 onion is resolved through its Tor-served directory
 * before the advertised numeric P2P fast path is scheduled. */
void zcl_native_handle_network_peer_add(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);

/* core.network.census / .node / .versions / .graph — READ-ONLY operator
 * surface over the banked network census + topology stores (node_census,
 * topology_edges, census_observations under <datadir>/peers_projection.db +
 * topology.db). These
 * open the census SQLite files with SQLITE_OPEN_READONLY in the one-shot CLI
 * process; no running node is required and consensus is never touched. When the
 * indexer lane has not yet created a table they degrade gracefully
 * ("census empty: indexer not yet populated"), never error. Every result is
 * bounded (paginated node list, bounded observation/edge history, bounded
 * distribution). Bound by config/commands/core.def. */
void zcl_native_handle_network_census(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_network_node(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_network_versions(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_network_graph(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);

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
void zcl_native_handle_ops_selftest(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);

/* ops.debug.meaning — node-free field ontology + question index. Answers
 * "what does this telemetry field mean, is this value bad, and which report
 * answers my question" straight out of the binary's static tables, with no
 * RPC and no node state, so it still works on a node that will not start. */
void zcl_native_handle_ops_meaning(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);

/* ops.debug.backtrace — dump a live backtrace for every thread of the running
 * node. Dispatches the `selfbacktrace` RPC method directly and
 * projects { path, thread_count }. Answers "what is every thread doing right
 * now" where perf/gdb/ptrace are blocked. Bound by config/commands/ops.def. */
void zcl_native_handle_ops_debug_backtrace(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);

/* ops.debug.bundle — write a one-shot debug bundle (every registered state
 * dumper + build identity + supervisor stall summary) as ONE JSON document
 * to <datadir>/debug-bundle-<utc>.json on the running node. Dispatches the
 * `debugbundle` RPC method directly and projects { path, bytes,
 * subsystems_captured, subsystems_failed }. Bound by config/commands/ops.def. */
void zcl_native_handle_ops_debug_bundle(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);

/* ops.explain <topic> — compose one prose-like diagnostic from four surfaces
 * (reducer frontier, blocker registry, condition engine, health/sync RPCs).
 * Topics: sync, blockers, health (table-dispatched, see
 * app/controllers/src/explain_native_handlers.c). Reply carries data.text +
 * structured fields; the CLI prints text unless --format=json. */
void zcl_native_handle_ops_explain(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);

/* ops.profile [seconds] [top_n] — dispatch the `profile` RPC (in-process
 * /proc/self/task sampling) and render the busiest threads + verdict + reducer
 * stage step-EWMA. */
void zcl_native_handle_ops_profile(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);

/* ops.producer.status --datadir= — read a mint/anchor producer's kernel
 * store (consensus.db, or the legacy progress.kv on a pre-flip datadir;
 * stage cursors + session/receipt lifecycle) and mint-progress.log tail
 * with NO node contact. Read-only. */
void zcl_native_handle_ops_producer_status(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);

/* ops.rom — dispatch the `dumpstate rom_compile` RPC against THIS running
 * node and render its ROM-compilation-fold telemetry (zcl.rom_compile.v1) as
 * rich ASCII: a fold progress bar, a horizontal bar chart of the eight
 * reducer stages' step_us_ewma (the bottleneck stage highlighted), and the
 * layer ladder (ROM checkpoint / sealed segment history / sealed state-seal
 * ring / delta frontier / tip ring), each filled or empty. The structured
 * fields are also returned verbatim in reply->data for machine consumers;
 * the CLI prints data.text unless --format=json. See
 * app/jobs/src/rom_compile_status.c for the data source (all EXISTING
 * telemetry — no second producer). */
void zcl_native_handle_ops_rom(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);

/* Render the CLI UX contract's ONE-LINE status brief: a single line, <=200
 * bytes, stable `key=value` pairs (no JSON braces), from the flat brief body
 * core.status.brief emits (see zcl_native_status_brief_body): hstar, gap,
 * peer_best, sync_state, primary_blocker, blocker_age_s, active_conditions,
 * peer_count, rss_mb. `buf`/`cap` must be at least 256 bytes; the line is
 * always NUL-terminated and never exceeds 200 visible bytes before the
 * terminator. Exposed for test_operator_ux. See docs/NATIVE_COMMAND_INTERFACE.md
 * "CLI UX contract" for the frozen field list. */
struct json_value;
void zcl_native_status_brief_render(const struct json_value *data, char *buf,
                                    size_t cap);
void zcl_native_status_journey_render(const struct json_value *data,
                                      char *buf, size_t cap);

/* Pick one short, deterministic next-step command from the same brief body
 * (dominant blocker present -> explain it; still behind -> explain sync;
 * otherwise -> a general healthcheck). Never allocates; returns a pointer to
 * a static string. Backs the bare no-arg `zclassic23` entry point and any
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
 * `dumpstate ... field=` both call — see docs/NATIVE_COMMAND_INTERFACE.md
 * "CLI UX contract". */
bool zcl_native_render_field_selection(const struct json_value *obj,
                                       const char *fields_csv,
                                       char *out, size_t out_cap,
                                       char *err, size_t err_cap);

/* Build the CLI UX contract's unrecognized-command diagnostic (see
 * docs/NATIVE_COMMAND_INTERFACE.md "CLI UX contract"): one typed
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
 * by config/src/command_catalog.c. */
void zcl_native_handle_core_node_bootstatus(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);

/* ── core.epoch.* — the Bounded Node keystone: commit the OP_RETURN
 * catalog digest-chain on-chain per epoch via a ZANC anchor
 * (tools/command/native_epoch_command.c). v1: operator-triggered only, no
 * background service, no auto-broadcast. */
void zcl_native_handle_core_epoch_status(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_core_epoch_anchor(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_core_epoch_verify(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);

/* core.anchor.compose / inspect — deterministic generic ZANC digest anchors.
 * Composition returns the exact OP_RETURN script and the raw-create input
 * fragment; funding/signing/broadcast remain separate owner-only commands. */
void zcl_native_handle_core_anchor_compose(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_core_anchor_inspect(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);

/* ── core.identity.* — sovereign master keys
 * (tools/command/native_identity_command.c). resolve/list read the
 * zid_identities projection straight out of <datadir>/node.db (READONLY,
 * so a stopped or copied datadir answers too); anchor/rotate/revoke build
 * the ZID\0 overlay and prefer the live node's identity_* RPCs, falling
 * back to op_return_hex when nothing answers. Bound by
 * config/commands/core.def. */
void zcl_native_handle_core_identity_resolve(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_core_identity_list(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_core_identity_anchor(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_core_identity_rotate(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_core_identity_revoke(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);

/* ── core.zdir.* — the on-chain node directory WRITE path
 * (tools/command/native_zdir_command.c). register/deregister build the
 * `ZDIR` OP_RETURN and prefer the live node's zdir_* RPCs, falling back to
 * op_return_hex when nothing answers. Pre-flight reads the onion_directory
 * projection out of <datadir>/node.db (READONLY) so an unownable or
 * already-retired row is refused before a fee is spent. There is no
 * transfer leaf: ZDIR command byte 3 is reserved and zdir_parse rejects it,
 * so handing a hostname over is deregister-then-register. Bound by
 * config/commands/core.def. */
void zcl_native_handle_core_zdir_guide(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_core_zdir_list(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_core_zdir_register(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_core_zdir_deregister(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);

void zcl_native_handle_core_node_bootwait(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);

/* core.storage.query.offline / core.sync.frontier.offline
 * (tools/command/native_offline_query.c) — the OFFLINE_COPY scope: inspect a
 * STOPPED or COPIED datadir's SQLite stores directly, with NO node contact
 * and NO RPC. `core.storage.query` and `dumpstate reducer_frontier` both
 * require a running node's RPC; these are the same SELECT-only primitives
 * (dbquery_execute, reducer_frontier_compute_hstar) run against an ad hoc
 * handle opened straight at `--datadir=<path>` — the typed replacement for
 * `build/bin/sqlq <db> <SELECT>` (tools/sqlq.c) plus hand-known table names.
 * Bound by config/src/command_catalog.c. */
void zcl_native_handle_core_storage_query_offline(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_core_sync_frontier_offline(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);

/* app.auth.* / app.account.* — the multi-user-server identity surface
 * (app/controllers/src/account_controller.c), mounted under the `app` root.
 * app.auth.challenge/app.auth.verify are PUBLIC (no capability):
 * challenge/response public-key login. app.account.* manage principals:
 * list/show/whoami are reads, add/role/suspend/unsuspend are the first
 * executable mutating native leaves (OWNER authority). Each renders one bounded
 * JSON document. Bound by config/commands/accounts.def. */
void zcl_native_handle_auth_challenge(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_auth_verify(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_account_list(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_account_show(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_account_whoami(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_account_add(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_account_role(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_account_suspend(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_account_unsuspend(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);

/* Mutating core.wallet.* leaves
 * (app/controllers/src/wallet_native_handlers.c). Each parses its input and
 * calls the running node's wallet RPC (getnewaddress / importaddress /
 * dumpprivkey / sendtoaddress / z_sendmany / rescanblockchain /
 * walletbackupnow) over the loopback client, then renders one bounded JSON
 * document. address.new / address.import / rescan / backup.now are one-shot
 * mutations (AUTH_OWNER); transaction.send / shielded.send /
 * address.export-key honour the declared CONFIRM_PLAN_COMMIT contract — a
 * first call with no `confirm:true` returns a non-mutating plan plus the
 * exact commit next-action, and only a second call with `confirm:true`
 * broadcasts or reveals. Bound in config/commands/core.def. */
void zcl_native_handle_wallet_address_new(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_wallet_address_import(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_wallet_shielded_address(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_wallet_address_export_key(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_wallet_transaction_send(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_wallet_multisig_compose(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_wallet_raw_create(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_wallet_raw_sign(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_wallet_raw_broadcast(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_wallet_shielded_send(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_wallet_security_status(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_wallet_security_encrypt(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_wallet_security_unlock(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_wallet_security_lock(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_wallet_rescan(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_wallet_backup_now(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
/* core.wallet.rescan-witnesses — rebuilds the Sapling witnesses a restored
 * shielded note needs before it can be spent (rpc_rescanwitnesses). */
void zcl_native_handle_wallet_rescan_witnesses(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);

/* The two OFFLINE recovery leaves
 * (app/controllers/src/wallet_restore_native_handlers.c). Unlike every
 * other wallet leaf these call their service in-process instead of a
 * running node, because a user restoring onto a rebuilt machine has no
 * node yet. `core.wallet.restore` merges a backup file into a datadir and
 * REFUSES while a node holds it; `core.wallet.backup.decrypt` turns a
 * WBE1 file back into a readable one. Both are CONFIRM_PLAN_COMMIT. */
void zcl_native_handle_wallet_restore(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_wallet_backup_decrypt(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);

/* The two OFFLINE recovery-phrase leaves
 * (app/controllers/src/wallet_recovery_native_handlers.c). `status` says
 * whether a datadir's wallet can be rebuilt from words at all — a wallet
 * created before recovery phrases honestly answers no. `restore` rebuilds a
 * wallet into an empty datadir from the phrase alone (CONFIRM_PLAN_COMMIT;
 * the plan shows the addresses the words open without writing anything).
 * There is no leaf that prints an existing wallet's phrase: only the
 * derived seed is stored, and it cannot be turned back into words. */
void zcl_native_handle_wallet_recovery_status(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_wallet_recovery_restore(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);

/* core.wallet.address.label(.by-label) — the address-book / label surface
 * (app/controllers/src/wallet_label_controller.c). Direct handlers over
 * app_runtime_node_db(): no wallet keystore, no RPC context. `label`
 * sets or clears a label (EFFECT_MUTATE, RISK_APP_WRITE — a plain
 * annotation, not a key or fund mutation); `by-label` reads every address
 * currently carrying a label. Bound in config/commands/core.def. */
void zcl_native_handle_wallet_address_label(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_wallet_address_by_label(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);

/* Mutating app.* feature leaves
 * (app/controllers/src/app_write_native_handlers.c). Each proxies one
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
 * config/commands/app_features.def. */
void zcl_native_handle_token_create(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_token_send(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_token_mint(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_token_burn(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_blog_anchor(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_name_register(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_name_update(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_name_transfer(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_name_renew(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_name_set_record(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_name_set_text(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_message_send(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_message_read(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_market_content_register(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
/* Per-node marketplace listing moderation (view filtering only — no
 * network-wide bans, no deletion): the node's own visibility profile plus
 * its local-only review_state curation marks.
 * app/controllers/src/market_moderation_native_handler.c. */
void zcl_native_handle_market_moderation_status(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_market_moderation_guide(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_market_moderation_profile_show(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_market_moderation_profile_set(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_market_moderation_review_set(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_market_purchase_plan(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_market_purchase_guide(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_market_purchase_commit(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_market_purchase_status(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_market_purchase_retrieve(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_market_offer(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_swap_initiate(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_swap_participate(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);

/* Store merchant surface (app/controllers/src/store_native_handlers.c) — the
 * typed writer behind `app.store.list-product` and the catalog read behind
 * `app.store.products`. Both address <datadir>/node.db the way the /store
 * HTTP handler does, so a listing is live on the next request with no
 * restart. Bound by config/commands/store.def. */
void zcl_native_handle_store_list_product(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_store_products(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);

/* app.shop.* — the storefront orchestration
 * (app/controllers/src/shop_native_handler.c, docs/work/SHOP_COMMAND.md
 * slice B). `init` composes the slice-A persistent onion identity, the
 * wallet at-rest custody probe, the existing store schema/products.json
 * loader, and the directory apps-row announcement into one plan/commit
 * command; `status` renders the same verification block read-only with
 * every unmet prerequisite named. Bound in config/commands/store.def. */
void zcl_native_handle_shop_init(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_shop_status(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
/* `reputation` (slice C) is the evidence readout for one ZCODE publisher
 * key over <datadir>/zcode: provable facts only, each with its evidence
 * class and counting window; absent evidence reads 'no_record', never a
 * zero (app/controllers/src/shop_native_reputation.c). */
void zcl_native_handle_shop_reputation(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
/* `want.*` (slice D) is the buyer-posted demand board: signed want ads
 * (Ed25519 shop_want.v1, the zswap quote shape with the terms reversed)
 * persisted to the shop_wants projection, browsed under the node's own
 * community content moderation profile, cancelled by the posting key,
 * and curated by the local review mark
 * (app/controllers/src/shop_native_want.c). Declared terms only — no
 * escrow, no payment channel. */
void zcl_native_handle_shop_want_post(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_shop_want_list(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_shop_want_status(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_shop_want_cancel(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_shop_want_review(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
/* `want.fulfill.*` (slice E) stores signed seller claims bound to
 * independently re-hashed content.v2 CAS bytes and optional re-verified
 * build/fuzz/benchmark receipts. It has no award or value movement. */
void zcl_native_handle_shop_want_fulfill_post(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_shop_want_fulfill_list(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_shop_want_fulfill_status(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_shop_want_fulfill_withdraw(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_shop_want_fulfill_review(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);

/* app.store.* — the BUYING half of the store
 * (app/controllers/src/store_buyer_native_handlers.c). Each proxies one
 * storebuy_* RPC, because placing an order mints a one-time Sapling payment
 * address and paying it spends, and a typed command runs in a process with
 * neither a wallet nor an open database. The storebuy_* methods report a
 * refusal as a successful call carrying {ok:false, code}; these handlers turn
 * that code back into a typed status, so PROVER_UNAVAILABLE,
 * PAYMENT_NOT_CONFIRMED and HASH_MISMATCH are distinguishable without reading
 * prose. Bound in config/commands/store.def. */
void zcl_native_handle_store_catalog(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_store_order(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_store_pay(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_store_purchases(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_store_collect(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);

/* metaverse.property.* — the sovereign-property CATALOG
 * (app/controllers/src/metaverse_controller.c). A read-only projection
 * rebuilt at call time over each property kind's own authoritative model
 * (services/property_catalog.h -> lib/metaverse adapters); it caches no
 * owner, revision, or status, so it cannot become a second ownership
 * truth, and it never opens a handle whose open() rewrites the datadir.
 * Every view states the evidence grade THIS node earned in THIS call.
 * Bound by config/commands/metaverse.def. */
void zcl_native_handle_metaverse_property_list(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_metaverse_property_show(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);

/* metaverse.space.* — signed read-only sovereign-space objects carried only
 * by the existing CAS/blob/DHT provider substrate. */
void zcl_native_handle_metaverse_space_plan(
    const struct zcl_command_request *request, struct zcl_command_reply *reply);
void zcl_native_handle_metaverse_space_commit(
    const struct zcl_command_request *request, struct zcl_command_reply *reply);
void zcl_native_handle_metaverse_space_show(
    const struct zcl_command_request *request, struct zcl_command_reply *reply);
void zcl_native_handle_metaverse_space_status(
    const struct zcl_command_request *request, struct zcl_command_reply *reply);
void zcl_native_handle_metaverse_space_publish(
    const struct zcl_command_request *request, struct zcl_command_reply *reply);
void zcl_native_handle_metaverse_space_discover(
    const struct zcl_command_request *request, struct zcl_command_reply *reply);
/* Internal composition entry point: identical discovery semantics, but the
 * caller owns an absolute monotonic deadline and lookup cancellation. */
void zcl_native_metaverse_space_discover_until(
    const struct zcl_command_request *request, struct zcl_command_reply *reply,
    int64_t deadline_mono_ms, size_t maximum_wire_bytes);
void zcl_native_handle_metaverse_space_scout_plan(
    const struct zcl_command_request *request, struct zcl_command_reply *reply);
void zcl_native_handle_metaverse_space_scout_run(
    const struct zcl_command_request *request, struct zcl_command_reply *reply);
void zcl_native_handle_metaverse_space_scout_show(
    const struct zcl_command_request *request, struct zcl_command_reply *reply);
#ifdef ZCL_TESTING
bool zcl_native_metaverse_space_test_admit_allowed(
    const char *datadir, const uint8_t semantic_root[32],
    const uint8_t transport_root[32], const uint8_t pointer_publisher[32],
    const uint8_t manifest_owner[32], bool manifest);
#endif

/* ROM-seed policy/ledger surface (app/controllers/src/rom_seed_controller.c)
 * — see config/commands/ops.def `ops.rom_seed.*` and docs/ROM_DELIVERY.md. */
void zcl_native_handle_rom_seed_status(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_rom_seed_enable(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_rom_seed_disable(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_rom_seed_artifacts(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
/* Publish (register) this node's on-disk starter artifacts so a fresh peer's
 * directory listing advertises a usable manifest — see
 * config/commands/ops.def `ops.debug.rom_seed.publish`. */
void zcl_native_handle_rom_seed_publish(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);

/* ROM-fetch engine surface (app/controllers/src/rom_fetch_controller.c) —
 * see config/commands/ops.def `ops.debug.rom_fetch.*` and
 * docs/ROM_DELIVERY.md. The fetch leaf downloads + content-verifies bytes
 * only; activation stays with the unified -install-consensus-bundle path. */
void zcl_native_handle_rom_fetch_status(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_rom_fetch_bundle(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);

/* Dev-build-only executors.  The catalog binds these only when
 * ZCL_DEV_BUILD is set; release objects neither reference nor link them. */
#if defined(ZCL_DEV_BUILD) || defined(ZCL_TESTING)
void zcl_native_handle_dev_drive(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
#endif

#ifdef ZCL_DEV_BUILD
void zcl_native_handle_dev_change_apply(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_dev_begin(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_dev_loop_ensure(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_dev_loop_status(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_dev_loop_wait(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_dev_loop_events(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_dev_loop_stop(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_dev_test_run(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_dev_test_story(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_dev_test_sim(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_dev_generation_current(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_dev_generation_history(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_dev_generation_activate(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
/* Both hot-swap commands are hard-contained compatibility entrypoints; probe
 * must not dlopen candidates in the resident node before ELF admission. */
void zcl_native_handle_dev_hotswap_apply(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_dev_hotswap_probe(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
#endif

#if defined(ZCL_DEV_BUILD) || defined(ZCL_TESTING)
void zcl_native_handle_dev_diagnose_latest(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_dev_diagnose_show(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
#endif

/* ── ops.telemetry.sync.* — the typed sync-domain telemetry leaves
 * (tools/command/native_telemetry_sync_command.c). Pure control: each fills
 * ONE struct sync_snapshot through services/sync_telemetry.h and renders it
 * with telemetry_render() — the single renderer — then, for `stages`/`stage`,
 * projects that already-rendered document into one row per ladder rung. No
 * telemetry field name is spelled here, no health is decided here, and no
 * database or node is contacted. Bound by config/commands/telemetry/sync.def. */
void zcl_native_handle_telemetry_sync_summary(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_telemetry_sync_stages(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_telemetry_sync_stage(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);

/* ── ops.telemetry.watch — the resumable change feed
 * (tools/command/native_telemetry_watch_command.c). A CURSOR POLL: it returns
 * the bounded batch of changes recorded after `since` and exits. Declared
 * MODE_STREAM because that is what it is; there is no long-lived dispatch path
 * and this handler does not add one. Bound by
 * config/commands/telemetry/watch.def. */
void zcl_native_handle_telemetry_watch(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);

/* ── metaverse.agent.* — the confined-agent broker's observation surface
 * (app/controllers/src/metaverse_controller.c). Both read one broker
 * DIRECTORY named by the caller and create nothing; the broker itself is a
 * separate confined process, not node state. Bound by
 * config/commands/metaverse.def. */
void zcl_native_handle_metaverse_agent_status(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_metaverse_agent_money(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_metaverse_agent_liquidity(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_metaverse_agent_audit(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);

/* ── ops.telemetry.runtime.* — the `runtime` telemetry domain
 * (tools/command/native_telemetry_runtime_command.c). Each picks one group of
 * the typed runtime snapshot and hands it to the single render layer; none of
 * them names a field. Bound by config/commands/telemetry/runtime.def. */
void zcl_native_handle_ops_telemetry_runtime_services(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_ops_telemetry_runtime_threads(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_ops_telemetry_runtime_resources(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);

/* ── ops.telemetry.network.* — the network telemetry domain
 * (tools/command/native_telemetry_network_command.c). Four VIEWS of ONE typed
 * snapshot, not four data sources: each handler fills a
 * `struct network_snapshot` through network_dump_state_fill() and hands it to
 * telemetry_render() at its view and group. They touch no node global, decide
 * no health, and name no field. Bound by config/commands/telemetry/network.def. */
void zcl_native_handle_telemetry_network_summary(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_telemetry_network_peers(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_telemetry_network_tor(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_telemetry_network_transport(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);

/* ── ops.telemetry.storage.* — the STORAGE telemetry domain
 * (tools/command/native_telemetry_storage_command.c). Each handler picks one
 * view/group token and makes one SELECT-only `dumpstate storage_telemetry`
 * call; the typed snapshot is filled and rendered inside the node by
 * app/services/src/storage_telemetry_fill.c, because a one-shot CLI process
 * has no initialized storage subsystems to read. Bound by
 * config/commands/telemetry/storage.def. */
void zcl_native_handle_telemetry_storage_summary(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_telemetry_storage_database(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_telemetry_storage_disk(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);

/* ── ops.telemetry.wallet.* — the wallet telemetry domain's two views
 * (tools/command/native_telemetry_wallet_command.c). Both pick the typed
 * wallet snapshot filled by services/wallet_telemetry.h and hand it to the
 * one shared renderer; neither names a field, decides health, or builds a
 * document. Posture only: no key, address or balance can appear in either
 * reply. Bound by config/commands/telemetry/wallet.def. */
void zcl_native_handle_telemetry_wallet_summary(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_telemetry_wallet_security(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);

/* ── ops.telemetry.agents.* — the AGENTS telemetry domain
 * (tools/command/native_telemetry_agents_command.c). Each renders one group
 * of the typed agents snapshot filled by agents_dump_state_fill()
 * (app/services/src/agents_telemetry.h); the field names live only in
 * lib/util/include/util/telemetry/agents_fields.def. Bound by
 * config/commands/telemetry/agents.def. */
void zcl_native_handle_ops_telemetry_agents_sessions(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_ops_telemetry_agents_grants(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_ops_telemetry_agents_activity(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);

/* ── ops.telemetry.zcode.* — the zcode telemetry domain
 * (tools/command/native_telemetry_zcode_command.c). Picks the typed zcode
 * snapshot and a view and hands both to telemetry_render(); it names no
 * field and decides no health. Field names, units and rules live in
 * util/telemetry/zcode_fields.def; the collector is
 * app/services/src/zcode_telemetry_fill.c. Bound by
 * config/commands/telemetry/zcode.def, whose `swarm` and `installs` leaves
 * stay PLANNED and so have no handler here. */
void zcl_native_handle_ops_telemetry_zcode_summary(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);

/* ── ops.telemetry.metaverse.* — the typed metaverse telemetry domain
 * (tools/command/native_telemetry_metaverse_command.c). One READY leaf; it
 * renders the compiled-in property-kind vocabulary and its adapter registry,
 * so it needs no datadir and no running node. `market` and `services` stay
 * PLANNED — see config/commands/telemetry/metaverse.def for why. */
void zcl_native_handle_telemetry_metaverse_properties(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);

/* metaverse.build.* — durable content-addressed build coordinator ledger. */
void zcl_native_handle_metaverse_build_plan(
    const struct zcl_command_request *, struct zcl_command_reply *);
void zcl_native_handle_metaverse_build_submit(
    const struct zcl_command_request *, struct zcl_command_reply *);
void zcl_native_handle_metaverse_build_status(
    const struct zcl_command_request *, struct zcl_command_reply *);
void zcl_native_handle_metaverse_build_cancel(
    const struct zcl_command_request *, struct zcl_command_reply *);
void zcl_native_handle_metaverse_build_receipt(
    const struct zcl_command_request *, struct zcl_command_reply *);
void zcl_native_handle_metaverse_build_worker_list(
    const struct zcl_command_request *, struct zcl_command_reply *);
void zcl_native_handle_metaverse_build_worker_approve(
    const struct zcl_command_request *, struct zcl_command_reply *);
void zcl_native_handle_metaverse_build_worker_revoke(
    const struct zcl_command_request *, struct zcl_command_reply *);

/* ── the three WHOLE-NODE rollups
 * (tools/command/native_telemetry_rollup_command.c). They iterate the provider
 * registry rather than naming domains, and fold verdicts from the one shared
 * evaluator with max() over the ordered health enum — they compute no health
 * of their own, so they cannot disagree with the per-domain leaf they point
 * at. `ops.telemetry.alerts.history` stays PLANNED: there is no durable alert
 * feed to read. Bound by config/commands/telemetry/root.def. */
void zcl_native_handle_ops_telemetry_summary(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_ops_telemetry_health(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);
void zcl_native_handle_ops_telemetry_alerts_active(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply);

#ifdef __cplusplus
}
#endif

#endif /* ZCL_TOOLS_NATIVE_COMMAND_H */
