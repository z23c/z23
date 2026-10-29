/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "conversation.h"
#include "json/json.h"
#include "base/cleanse.h"
#include "zutf8/zutf8.h"
#include <stdio.h>
#include <string.h>

static bool valid_snapshot(const struct zapp_conversation_snapshot *s, const char *question)
{
    return s && question && question[0] &&
        memchr(s->sync_status, 0, sizeof(s->sync_status)) &&
        memchr(s->balance, 0, sizeof(s->balance)) &&
        strlen(question) <= 16000 && zutf8_validate(question) &&
        zutf8_validate(s->sync_status) && zutf8_validate(s->balance);
}

static bool push_snapshot(struct json_value *root, const struct zapp_conversation_snapshot *s)
{
    return json_push_kv_bool(root, "running", s->node_running) &&
        json_push_kv_str(root, "sync_status", s->sync_status) &&
        json_push_kv_str(root, "balance", s->balance_known ? s->balance : "unavailable") &&
        json_push_kv_bool(root, "balance_stale", s->balance_known && s->balance_stale);
}

/* The phone's node is labelled apart from the fleet hosts and the question comes last: with the
 * question inside the node data, the chat model often answered fleet questions about this node. */
bool zapp_conversation_format(const struct zapp_conversation_snapshot *s,
                              const char *question, char *out, size_t cap)
{
    static const char label[] = "This phone's own node, which is not one of the fleet hosts: ";
    if (!out || !cap) return false;
    out[0] = 0;
    if (!valid_snapshot(s, question)) return false;
    struct json_value root = {0};
    json_set_object(&root);
    size_t used = sizeof(label) - 1;
    bool ok = push_snapshot(&root, s) && cap > used;
    if (ok) {
        memcpy(out, label, used);
        size_t n = json_write(&root, out + used, cap - used);
        ok = n < cap - used;
        used += ok ? n : 0;
    }
    int tail = ok ? snprintf(out + used, cap - used, "\n\nQuestion: %s", question) : -1;
    ok = tail >= 0 && (size_t)tail < cap - used && used + (size_t)tail <= 16000;
    json_cleanse_strings(&root);
    json_free(&root);
    if (!ok) out[0] = 0;
    return ok;
}

static void drop_oldest(struct zapp_history *h)
{
    size_t q = strlen(h->text) + 1, n = q + strlen(h->text + q) + 1;
    memmove(h->text, h->text + n, h->used - n);
    memory_cleanse(h->text + h->used - n, n);
    h->used -= n; h->turns--;
}

bool zapp_history_append(struct zapp_history *h, const char *question, const char *answer)
{
    size_t q = question ? strlen(question) + 1 : 0, a = answer ? strlen(answer) + 1 : 0;
    if (!h || q < 2 || a < 2 || q + a > sizeof(h->text) / 2 ||
        !zutf8_validate(question) || !zutf8_validate(answer)) return false;
    if (h->used + q + a > sizeof(h->text) || h->turns >= ZAPP_HISTORY_TURNS)
        while (h->turns && (h->used > sizeof(h->text) / 2 || h->turns > ZAPP_HISTORY_TURNS / 2))
            drop_oldest(h);
    memcpy(h->text + h->used, question, q);
    memcpy(h->text + h->used + q, answer, a);
    h->used += q + a; h->turns++;
    return true;
}

static bool push_turn(struct json_value *out, const char *question, const char *answer)
{
    struct json_value turn = {0}, q = {0}, a = {0};
    json_set_array(&turn); json_set_str(&q, question); json_set_str(&a, answer);
    bool ok = json_push_back(&turn, &q) && json_push_back(&turn, &a) && json_push_back(out, &turn);
    json_cleanse_strings(&q); json_free(&q); json_cleanse_strings(&a); json_free(&a);
    json_cleanse_strings(&turn); json_free(&turn);
    return ok;
}

bool zapp_history_json(const struct zapp_history *h, struct json_value *out)
{
    if (!h || !out || h->used > sizeof(h->text) || h->turns > ZAPP_HISTORY_TURNS) return false;
    json_set_array(out);
    size_t at = 0;
    for (size_t i = 0; i < h->turns; i++) {
        const char *q = h->text + at, *end = h->text + h->used;
        const char *q_end = memchr(q, 0, (size_t)(end - q));
        const char *a = q_end ? q_end + 1 : end;
        const char *a_end = a < end ? memchr(a, 0, (size_t)(end - a)) : NULL;
        if (!a_end || !push_turn(out, q, a)) return false;
        at = (size_t)(a_end - h->text) + 1;
    }
    return at == h->used;
}
/* Length of the longest run of whole exchanges in text that fits in room bytes. */
static size_t whole_exchanges(const char *text, size_t room)
{
    for (size_t at = room; at > 0; at--)
        if (text[at - 1] == '\n' && !strncmp(text + at, "\nYou: ", 6)) return at;
    return 0;
}
void zapp_transcript_prepend(char *text, size_t cap, const char *question, const char *answer)
{
    if (!text || !cap || !question || !answer) return;
    int n = snprintf(NULL, 0, "You: %s\n\nZ23: %s\n", question, answer);
    if (n < 0 || (size_t)n + 1 >= cap) {
        size_t keep = strlen(answer) < cap - 1 ? strlen(answer) : cap - 1;
        while (keep && ((unsigned char)answer[keep] & 0xC0) == 0x80) keep--;
        memcpy(text, answer, keep); text[keep] = 0; return;
    }
    size_t used = strlen(text), room = cap - 1 - (size_t)n - 1;
    size_t keep = used <= room ? used : whole_exchanges(text, room);
    size_t at = (size_t)n + (keep ? 1 : 0);
    memmove(text + at, text, keep); text[at + keep] = 0;
    snprintf(text, (size_t)n + 1, "You: %s\n\nZ23: %s\n", question, answer);
    text[n] = keep ? '\n' : 0;
}
