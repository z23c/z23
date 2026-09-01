/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Agent-session RPC surface — the node-side owner of the agent_sessions
 * store (docs/work/agent-spend-policy-design.md).
 *
 * Why an RPC at all: the two dispatch choke points that enforce an agent's
 * spend policy (the kernel's zcl_command_registry_execute_json and the
 * vault's vault_dispatch) both run in the short-lived CLI process, which
 * never boots the node and therefore has no open node.db. Reaching the store
 * from there by opening node.db a second time would put a second writer on
 * the running node's database — the cloned-ledger failure this codebase
 * exists to avoid, and a write-lock hazard against a node holding the tip.
 * So the node stays the single writer and everyone else asks it: one RPC
 * method, `agentsession`, with mint/list/revoke/authorize/release actions.
 * The CLI-side caller is controllers/agent_session_client.h.
 *
 * Registered from boot_services.c like every other RPC family. */

#ifndef ZCL_CONTROLLERS_AGENT_SESSION_CONTROLLER_H
#define ZCL_CONTROLLERS_AGENT_SESSION_CONTROLLER_H

struct rpc_table;

/* Register the `agentsession` method. Not safe-mode: it reads and writes an
 * app-layer table, so it needs a fully-booted node_db. */
void register_agent_session_rpc_commands(struct rpc_table *t);

#endif
