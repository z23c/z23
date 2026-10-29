/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "conversation.h"
#include "json/json.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static void expect_turn(const struct json_value *turns, size_t i, const char *q, const char *a)
{
    const struct json_value *turn = json_at(turns, i);
    assert(turn && turn->type == JSON_ARR && json_size(turn) == 2);
    assert(!strcmp(json_get_str(json_at(turn, 0)), q) && !strcmp(json_get_str(json_at(turn, 1)), a));
}

static void history_basic_cases(void)
{
    static struct zapp_history h;
    struct json_value turns = {0};
    assert(zapp_history_json(&h, &turns) && turns.type == JSON_ARR && json_size(&turns) == 0);
    json_free(&turns);
    assert(zapp_history_append(&h, "hi", "hello") && zapp_history_append(&h, "and now?", "still fine"));
    assert(!zapp_history_append(&h, "", "x") && !zapp_history_append(&h, "x", "") &&
           !zapp_history_append(&h, "\xff", "x") && !zapp_history_append(NULL, "x", "y"));
    char big[ZAPP_HISTORY_CAP / 2]; memset(big, 'b', sizeof(big) - 1); big[sizeof(big) - 1] = 0;
    assert(!zapp_history_append(&h, "q", big));
    assert(zapp_history_json(&h, &turns) && json_size(&turns) == 2);
    expect_turn(&turns, 0, "hi", "hello"); expect_turn(&turns, 1, "and now?", "still fine");
    json_free(&turns);
    h.used = 3;
    assert(!zapp_history_json(&h, &turns));
    json_free(&turns);
}

/* Thirty-two small exchanges fill the turn limit; the next append first trims to sixteen. */
static void history_turn_cases(void)
{
    static struct zapp_history h;
    struct json_value turns = {0};
    assert(zapp_history_append(&h, "first", "dropped"));
    for (int i = 1; i < ZAPP_HISTORY_TURNS; i++) assert(zapp_history_append(&h, "q", "a"));
    assert(h.turns == 32 && zapp_history_json(&h, &turns) && json_size(&turns) == 32);
    json_free(&turns);
    assert(zapp_history_append(&h, "last", "one") && h.turns == 17);
    assert(zapp_history_json(&h, &turns) && json_size(&turns) == 17);
    expect_turn(&turns, 0, "q", "a"); expect_turn(&turns, 16, "last", "one");
    json_free(&turns);
}

/* Large exchanges trim by bytes to half the capacity; what remains is an unchanged prefix. */
static void history_byte_cases(void)
{
    static struct zapp_history h;
    struct json_value turns = {0};
    char mid[1200]; memset(mid, 'm', sizeof(mid) - 1); mid[sizeof(mid) - 1] = 0;
    assert(zapp_history_append(&h, "one", mid) && zapp_history_append(&h, "two", mid) &&
           zapp_history_append(&h, "three", mid));
    assert(zapp_history_append(&h, "four", mid) && h.turns == 2 && h.used == 2411);
    assert(zapp_history_json(&h, &turns) && json_size(&turns) == 2);
    expect_turn(&turns, 0, "three", mid); expect_turn(&turns, 1, "four", mid);
    json_free(&turns);
    char before[ZAPP_HISTORY_CAP]; size_t kept = h.used;
    memcpy(before, h.text, kept);
    assert(zapp_history_append(&h, "five", mid) && h.turns == 3 && !memcmp(before, h.text, kept));
}

int main(void)
{
    history_basic_cases(); history_turn_cases(); history_byte_cases();
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
