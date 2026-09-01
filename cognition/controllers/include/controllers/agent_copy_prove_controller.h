/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * agentcopyprove — native agent contract that kicks off
 * tools/repro_on_copy.sh (the existing copy-prove H*-CLIMB harness) in
 * the background against a throwaway datadir COPY and returns
 * immediately. Never reimplements the harness; never touches a live
 * datadir. See docs/CODEBASE_MAP.md "copy-prove" and tools/repro_on_copy.sh.
 *
 * Poll a run via the diagnostics registry primitive:
 *   z23 dumpstate agent_copy_prove <slug>
 * See CLAUDE.md "Adding state introspection". Reentrant-safe.
 */
#ifndef ZCL_CONTROLLERS_AGENT_COPY_PROVE_H
#define ZCL_CONTROLLERS_AGENT_COPY_PROVE_H

#include <stdbool.h>

struct json_value;

bool rpc_agent_copy_prove(const struct json_value *params, bool help,
                          struct json_value *result);

bool agent_copy_prove_dump_state_json(struct json_value *out,
                                      const char *key);

#endif /* ZCL_CONTROLLERS_AGENT_COPY_PROVE_H */
