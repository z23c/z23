/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Exact registry-policy gate for the local MCP adapter's z23_run. */

#ifndef ZCL_TOOLS_MCP_POLICY_H
#define ZCL_TOOLS_MCP_POLICY_H

#include "kernel/command_registry.h"
#include "mcp_rpc.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Decide whether the local adapter may dispatch spec with input.
 *
 * A read runs unless its risk is wallet or core recovery or its authority is
 * owner; those refusals apply to reads too, so a misclassified leaf is still
 * refused. This is a LOCAL operator adapter, so the remote class (never
 * remote) is deliberately not consulted. A mutating or destructive command is
 * refused when its risk is wallet or core recovery, its authority is owner or
 * its layer is core. Any other mutating command runs only through a
 * confirmation flow its own contract DECLARES: a plan-commit command runs in
 * plan mode until the caller supplies every declared plan_id / plan_token and
 * (when declared) confirm:true; a commit-style call to a leaf that declares
 * neither plan_id nor plan_token, a plan-commit leaf (other than the paired plan
 * stage) that declares no plan_id, plan_token, confirm or mode input, and an
 * idempotency leaf that declares no idempotency_key are all refused with
 * MUTATION_NO_CONFIRMATION_FLOW. An undeclared key never waives a check. The
 * plan stage is a "<stem>.plan" leaf whose "<stem>.commit" partner is a
 * mutation in the same registry (the registry has no stage field);
 * registry may be NULL, which exempts nothing.
 * Refusal strings are static, except detail, which points at spec->path. */
bool mcp_policy_allows(const struct zcl_command_spec *spec,
                       const struct zcl_command_registry *registry,
                       const struct json_value *input,
                       struct mcp_refusal *why);

/* The fleet collaboration writes `z23 mcp serve --fleet-writes` runs without
 * a plan or confirm flow: fleet.board.post, fleet.wiki.write,
 * fleet.bundle.offer and fleet.bundle.fetch. True only for those exact leaves
 * while each stays an app-write mutation outside the owner authority and the
 * core layer, so a reclassified leaf falls back to mcp_policy_allows. Off by
 * default: a launcher that feeds the agent untrusted text keeps the plain
 * policy. */
bool mcp_policy_fleet_write(const struct zcl_command_spec *spec);

/* The one mutation the dedicated apps_open tool runs without a plan or
 * confirm flow: app.open, while it stays an app-layer app-write mutation
 * outside the owner authority. Named launches use this binary's or the
 * owner's apps.tsv entry and fixed argv. A selected saved image uses the
 * same fixed argv, but app.open must verify the persisted owner adoption or
 * received-trust grant, reject foreign history, and bind the saved version
 * to the requested build record and image. accept_execution requests a run;
 * it cannot create that owner grant. z23_run keeps the plain policy. */
bool mcp_policy_app_open(const struct zcl_command_spec *spec);
/* Dedicated apps_keep only: rechecks persisted copy trust and exact build. */
bool mcp_policy_app_keep(const struct zcl_command_spec *spec);
/* Dedicated apps_adopt only: requests a local, native owner decision. */
bool mcp_policy_app_adopt(const struct zcl_command_spec *spec);
/* Dedicated apps_receive only: requests a local, native owner decision. */
bool mcp_policy_app_receive(const struct zcl_command_spec *spec);
/* Dedicated apps_share only: requests a local, native owner decision. */
bool mcp_policy_app_share(const struct zcl_command_spec *spec);
/* Dedicated kept-name adapter only; generic owner mutations remain refused. */
bool mcp_policy_app_personalize(const struct zcl_command_spec *spec);

/* True when the leaf can return wallet-private data: it declares the wallet
 * request capability, or it is one of the named amount-bearing leaves that do
 * not (metaverse custody reports, agent grant and spend telemetry, store purchases).
 * mcp_policy_allows refuses such read leaves with READ_REFUSED_WALLET_DATA. */
bool mcp_policy_wallet_data(const struct zcl_command_spec *spec);

/* The wallet-data read leaves `z23 mcp serve --wallet-reads` runs: a runnable
 * read-effect leaf for which mcp_policy_wallet_data holds that is neither
 * wallet-risk, core-recovery nor owner authority. Off by default: wallet data
 * lands in the agent transcript and with its model provider, so only the
 * owner opts in. */
bool mcp_policy_wallet_read(const struct zcl_command_spec *spec);

#ifdef __cplusplus
}
#endif

#endif
