/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * agenttest — native agent contract that runs ONE allowlisted test surface
 * (a compiled test_parallel group, or a checked-in chaos scenario under
 * tools/sim/scenarios/) in the background via tools/agent_test_runner.sh
 * and returns immediately. Cloned end-to-end from the agentcopyprove pattern
 * (cognition/controllers/src/agent_copy_prove_controller.c) — see that file's
 * header for the async-by-design rationale.
 *
 * Poll a run via the diagnostics registry primitive:
 *   z23 dumpstate agent_test <kind>-<name>
 * See CLAUDE.md "Adding state introspection". Reentrant-safe.
 */
#ifndef ZCL_CONTROLLERS_AGENT_TEST_H
#define ZCL_CONTROLLERS_AGENT_TEST_H

#include <stdbool.h>

struct json_value;

bool rpc_agent_test(const struct json_value *params, bool help,
                    struct json_value *result);

bool agent_test_dump_state_json(struct json_value *out, const char *key);

#endif /* ZCL_CONTROLLERS_AGENT_TEST_H */
