/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: let the one front-door name `z23` hand a developer command to the
 * z23-dev installed beside it. Interactive CLI only; see the .c file. */

#ifndef ZCL_TOOLS_NATIVE_COMMAND_HANDOFF_H
#define ZCL_TOOLS_NATIVE_COMMAND_HANDOFF_H

#include "kernel/command_registry.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Arm the handoff with this process's original argv. Only the interactive CLI
 * entry (cli_main) calls it; an unarmed process (RPC server, MCP, node, any
 * in-process caller) never hands off. */
void zcl_native_handoff_arm(int argc, char *const *argv);

/* If `spec` has no handler in this binary, names a "z23-dev ..." compat
 * target, and a trusted z23-dev sits in this executable's own directory,
 * replace the process with it, passing the original argv words unchanged.
 * Returns only when no handoff happened (nothing armed, opted out, sibling
 * absent or untrusted, or exec failed); the caller then refuses as usual. */
void zcl_native_handoff_try(const struct zcl_command_spec *spec);

#ifdef ZCL_TESTING
/* Look for the sibling in `dir` instead of the running executable's own
 * directory. NULL restores the real lookup. */
void zcl_native_handoff_set_dir_for_test(const char *dir);
#endif

#ifdef __cplusplus
}
#endif

#endif
