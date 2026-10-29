/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "conversation.h"
#include "json/json.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

int main(void)
{
    struct zapp_conversation_snapshot s = {0};
    char out[ZAPP_CONVERSATION_CAP];
    memcpy(s.sync_status, "Node running; status did not answer. Sync progress is unknown.",
           sizeof("Node running; status did not answer. Sync progress is unknown."));
    assert(zapp_conversation_format(&s, "a \"quote\"\nnext", out, sizeof(out)));
    char *json = strchr(out, '\n');
    struct json_value root = {0};
    assert(json && json_read(&root, json + 1, strlen(json + 1)));
    assert(root.type == JSON_OBJ && json_size(&root) == 5);
    assert(json_get(&root, "sync_status") && json_get(&root, "balance") &&
           json_get(&root, "balance_stale") && json_get(&root, "node_running") &&
           json_get(&root, "question"));
    assert(!strcmp(json_get_str(json_get(&root, "question")), "a \"quote\"\nnext"));
    assert(!strcmp(json_get_str(json_get(&root, "balance")), "unavailable"));
    assert(!json_get_bool(json_get(&root, "balance_stale")));
    json_free(&root);
    s.balance_known = s.balance_stale = true;
    memcpy(s.balance, "Total: 1 ZCL (may be stale)", sizeof("Total: 1 ZCL (may be stale)"));
    assert(zapp_conversation_format(&s, "balance?", out, sizeof(out)));
    json = strchr(out, '\n');
    assert(json_read(&root, json + 1, strlen(json + 1)));
    assert(json_get_bool(json_get(&root, "balance_stale")));
    assert(!strcmp(json_get_str(json_get(&root, "balance")), s.balance));
    json_free(&root);
    assert(!zapp_conversation_format(&s, "", out, sizeof(out)));
    assert(!zapp_conversation_format(&s, "\xff", out, sizeof(out)));
    assert(!zapp_conversation_format(&s, "question", out, 10));
    char long_question[16001]; memset(long_question, 'a', 16000); long_question[16000] = 0;
    assert(!zapp_conversation_format(&s, long_question, out, sizeof(out)));
    memset(s.sync_status, 'x', sizeof(s.sync_status));
    assert(!zapp_conversation_format(&s, "question", out, sizeof(out)));
    puts("conversation tests passed");
    return 0;
}
