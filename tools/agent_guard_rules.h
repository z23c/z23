/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 *
 * z23-agent-guard rule engine interface (tools/agent_guard_rules.c). */

#ifndef AGENT_GUARD_RULES_H
#define AGENT_GUARD_RULES_H

#define R_DATADIR "guard.datadir"
#define R_REINDEX "guard.reindex_flag"
#define R_PYTHON "guard.python"
#define R_IDENT "guard.git_identity"
#define R_SPEND "guard.spend_or_key_export"
#define R_HOST "guard.host_config"
#define R_PUSH "guard.git_push"
#define R_DBHELP "guard.devbuild_help"

/* Each returns the refused rule name, or NULL when the call is allowed. */
const char *ag_eval_bash(const char *cmd);
const char *ag_eval_path(const char *tool, const char *path, const char *content);

#endif
