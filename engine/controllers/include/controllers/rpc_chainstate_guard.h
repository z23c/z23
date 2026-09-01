#ifndef ZCL_CONTROLLERS_RPC_CHAINSTATE_GUARD_H
#define ZCL_CONTROLLERS_RPC_CHAINSTATE_GUARD_H

#include <stdbool.h>

struct json_value;
struct main_state;

bool rpc_chainstate_lookup_ready(const struct main_state *ms);
bool rpc_require_chainstate_lookup_ready(const struct main_state *ms,
                                         struct json_value *result,
                                         const char *method,
                                         const char *operation);

#endif
