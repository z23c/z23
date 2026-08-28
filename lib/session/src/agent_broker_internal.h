/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Share broker response and receipt helpers across implementation units. */
#ifndef ZCL_SESSION_AGENT_BROKER_INTERNAL_H
#define ZCL_SESSION_AGENT_BROKER_INTERNAL_H

#include "session/agent_broker.h"
#include "base/format_attribute.h"

void resp_init(struct mvap_response *response,
               const struct mvap_request *request, int32_t status);
void resp_body(struct mvap_response *response, const char *format, ...)
    ZCL_PRINTF_LIKE(2, 3);

#if !defined(_WIN32)
void broker_receipt(struct agent_broker_session *session,
                    const struct mvap_request *request,
                    struct mvap_response *response, const char *detail,
                    const uint8_t action_receipt_id[32]);
void broker_replay_receipt(struct agent_broker_session *session,
                           const struct mvap_request *request,
                           const struct mvap_response *response,
                           const struct agent_idem_slot *slot);
#endif

#endif
