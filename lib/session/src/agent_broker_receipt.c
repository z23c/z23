/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Format broker responses and tamper-evident execution receipts. */
#include "agent_broker_internal.h"

#include "base/hex.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

void resp_init(struct mvap_response *response,
               const struct mvap_request *request, int32_t status)
{
    memset(response, 0, sizeof(*response));
    response->verb = request ? request->verb : MVAP_VERB_NONE;
    response->request_id = request ? request->request_id : 0;
    response->version = request ? request->version : 0;
    response->status = status;
}

void resp_body(struct mvap_response *response, const char *format, ...)
{
    va_list arguments;
    va_start(arguments, format);
    int written = vsnprintf(response->body, sizeof(response->body), format,
                            arguments);
    va_end(arguments);
    if (written < 0)
        response->body[0] = '\0';
}

#if !defined(_WIN32)
static const char *session_principal(const struct agent_broker_session *session)
{
    return (session->authority && session->authority->bound)
               ? session->authority->principal
               : "";
}

static const char *session_grant_id(const struct agent_broker_session *session)
{
    return (session->authority && session->authority->bound)
               ? session->authority->canonical_grant_id
               : "";
}

static void receipt_common(struct agent_receipt *receipt,
                           const struct agent_broker_session *session,
                           const struct mvap_request *request,
                           const struct mvap_response *response)
{
    receipt->receipt_version = 3;
    (void)snprintf(receipt->money_snapshot_status,
                   sizeof(receipt->money_snapshot_status), "UNKNOWN");
    receipt->verb = request->verb;
    receipt->request_id = request->request_id;
    receipt->status = response->status;
    receipt->value_zats = request->value_zats;
    memcpy(receipt->property_id, request->property_id, MVAP_PROPERTY_ID_LEN);
    (void)snprintf(receipt->principal, sizeof(receipt->principal), "%s",
                   session_principal(session));
    (void)snprintf(receipt->grant_id, sizeof(receipt->grant_id), "%s",
                   session_grant_id(session));
    receipt->peer = session->peer;
}

void broker_receipt(struct agent_broker_session *session,
                    const struct mvap_request *request,
                    struct mvap_response *response, const char *detail,
                    const uint8_t action_receipt_id[32])
{
    if (!session->audit || !session->audit->open)
        return;
    struct agent_receipt receipt = {0};
    receipt_common(&receipt, session, request, response);
    if (action_receipt_id)
        memcpy(receipt.action_receipt_id, action_receipt_id, 32);
    (void)snprintf(receipt.detail, sizeof(receipt.detail), "%s",
                   detail ? detail : "");
    if (agent_audit_append(session->audit, &receipt)) {
        memcpy(response->receipt_id, receipt.id, MVAP_RECEIPT_ID_LEN);
        session->receipts_written++;
    }
}

void broker_replay_receipt(struct agent_broker_session *session,
                           const struct mvap_request *request,
                           const struct mvap_response *response,
                           const struct agent_idem_slot *slot)
{
    if (!session->audit || !session->audit->open || !slot)
        return;
    struct agent_receipt receipt = {0};
    receipt_common(&receipt, session, request, response);
    memcpy(receipt.action_receipt_id, slot->action_receipt_id, 32);
    char first[65];
    zcl_hex_encode(slot->resp.receipt_id, MVAP_RECEIPT_ID_LEN, first);
    (void)snprintf(receipt.detail, sizeof(receipt.detail),
                   "REPLAYED request_id=%u: executed nothing; "
                   "first_receipt=%s", request->request_id, first);
    (void)agent_audit_append(session->audit, &receipt);
}
#endif
