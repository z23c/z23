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

/* Parses the node JSON between the label and the question; returns the question text. */
static const char *format_parts(const char *out, struct json_value *node)
{
    static const char label[] = "This phone's own node, which is not one of the fleet hosts: ";
    const char *question = strstr(out, "\n\nQuestion: ");
    assert(!strncmp(out, label, sizeof(label) - 1) && question);
    const char *json = out + sizeof(label) - 1;
    assert(json_read(node, json, (size_t)(question - json)) && node->type == JSON_OBJ && json_size(node) == 4);
    return question + 12;
}
static void format_cases(void)
{
    struct zapp_conversation_snapshot s = {0};
    char out[ZAPP_CONVERSATION_CAP];
    memcpy(s.sync_status, "Node running; status did not answer. Sync progress is unknown.",
           sizeof("Node running; status did not answer. Sync progress is unknown."));
    assert(zapp_conversation_format(&s, "a \"quote\"\nnext", out, sizeof(out)));
    struct json_value node = {0};
    assert(!strcmp(format_parts(out, &node), "a \"quote\"\nnext"));
    assert(!json_get_bool(json_get(&node, "running")) && !json_get_bool(json_get(&node, "balance_stale")));
    assert(!strcmp(json_get_str(json_get(&node, "balance")), "unavailable"));
    assert(!strcmp(json_get_str(json_get(&node, "sync_status")), s.sync_status));
    json_free(&node);
    s.balance_known = s.balance_stale = s.node_running = true;
    memcpy(s.balance, "Total: 1 ZCL (may be stale)", sizeof("Total: 1 ZCL (may be stale)"));
    assert(zapp_conversation_format(&s, "balance?", out, sizeof(out)));
    assert(!strcmp(format_parts(out, &node), "balance?"));
    assert(json_get_bool(json_get(&node, "running")) && json_get_bool(json_get(&node, "balance_stale")));
    assert(!strcmp(json_get_str(json_get(&node, "balance")), s.balance));
    json_free(&node);
    size_t used = (size_t)(strstr(out, "\n\nQuestion: ") - out);
    assert(!zapp_conversation_format(&s, "balance?", out, used + 12) && !out[0]);
    assert(!zapp_conversation_format(&s, "balance?", out, used + 20) && !out[0]);
    assert(zapp_conversation_format(&s, "balance?", out, used + 21));
    assert(!zapp_conversation_format(&s, "", out, sizeof(out)) && !out[0]);
    assert(!zapp_conversation_format(&s, "\xff", out, sizeof(out)));
    assert(!zapp_conversation_format(&s, "question", out, 10) && !out[0]);
    assert(!zapp_conversation_format(&s, "question", out, 140) && !out[0]);
    char long_question[16001]; memset(long_question, 'a', 16000); long_question[16000] = 0;
    assert(!zapp_conversation_format(&s, long_question, out, sizeof(out)) && !out[0]);
    memset(s.sync_status, 'x', sizeof(s.sync_status));
    assert(!zapp_conversation_format(&s, "question", out, sizeof(out)));
}

/* The newest exchange comes first; whole older exchanges are dropped when the buffer is full. */
static void transcript_cases(void)
{
    char text[56] = "";
    zapp_transcript_prepend(text, sizeof(text), "a", "b");
    assert(!strcmp(text, "You: a\n\nZ23: b\n"));
    zapp_transcript_prepend(text, sizeof(text), "c", "d");
    assert(!strcmp(text, "You: c\n\nZ23: d\n\nYou: a\n\nZ23: b\n"));
    zapp_transcript_prepend(text, sizeof(text), "e", "f");
    assert(!strcmp(text, "You: e\n\nZ23: f\n\nYou: c\n\nZ23: d\n\nYou: a\n\nZ23: b\n"));
    zapp_transcript_prepend(text, sizeof(text), "g", "h");
    assert(!strcmp(text, "You: g\n\nZ23: h\n\nYou: e\n\nZ23: f\n\nYou: c\n\nZ23: d\n"));
    zapp_transcript_prepend(text, sizeof(text), "a longer question", "drops all older ones");
    assert(!strcmp(text, "You: a longer question\n\nZ23: drops all older ones\n"));
    char small[8] = "old";
    zapp_transcript_prepend(small, sizeof(small), "q", "caf\xc3\xa9 au lait");
    assert(!strcmp(small, "caf\xc3\xa9 a"));
    zapp_transcript_prepend(small, 5, "q", "caf\xc3\xa9");
    assert(!strcmp(small, "caf"));
    zapp_transcript_prepend(NULL, sizeof(small), "q", "a");
}

#define MUTED "<font color=\"#6B716D\">"
#define FADED "<br><br><small><font color=\"#8A8F8B\">"
static void html_of(const char *transcript, char *out, size_t cap)
{
    assert(zapp_transcript_html(transcript, out, cap));
    assert(!strstr(out, "You:") && !strstr(out, "Z23:"));
}
/* The newest answer is plain, the question muted, and earlier exchanges small and muted. */
static void html_cases(void)
{
    char out[512];
    html_of("You: q\n\nZ23: a\n", out, sizeof(out));
    assert(!strcmp(out, MUTED "q</font><br>a"));
    html_of("You: q2\n\nZ23: a2\n\nYou: q1\n\nZ23: a1\n", out, sizeof(out));
    assert(!strcmp(out, MUTED "q2</font><br>a2" FADED "q1<br>a1</font></small>"));
    html_of("You: <b>&\"\n\nZ23: x < y > z\n", out, sizeof(out));
    assert(!strcmp(out, MUTED "&lt;b&gt;&amp;&quot;</font><br>x &lt; y &gt; z"));
    html_of("You: q\n\nZ23: one\ntwo\n\nthree\n", out, sizeof(out));
    assert(!strcmp(out, MUTED "q</font><br>one<br>two<br><br>three"));
    html_of("You: \xc3\x9c" "bersicht \xc2\xb7 3 302 068\n\nZ23: \xc3\x9c" "ber \xc2\xb7 ok\n", out, sizeof(out));
    assert(!strcmp(out, MUTED "\xc3\x9c" "bersicht \xc2\xb7 3 302 068</font><br>\xc3\x9c" "ber \xc2\xb7 ok"));
    assert(zapp_transcript_html("hello <i> & more\nline", out, sizeof(out)));
    assert(!strcmp(out, "hello &lt;i&gt; &amp; more<br>line"));
    const char *two = "You: q2\n\nZ23: a2\n\nYou: q1\n\nZ23: a1\n";
    size_t newest = strlen(MUTED "q2</font><br>a2");
    assert(zapp_transcript_html(two, out, newest + 1) && !strcmp(out, MUTED "q2</font><br>a2"));
    assert(!zapp_transcript_html(two, out, newest) && out[0] == 0);
    assert(!zapp_transcript_html("", out, sizeof(out)) && !zapp_transcript_html(NULL, out, sizeof(out)));
    assert(!zapp_transcript_html("plain text", out, 5) && out[0] == 0);
}
int main(void)
{
    history_basic_cases(); history_turn_cases(); history_byte_cases(); format_cases(); transcript_cases(); html_cases();
    puts("conversation tests passed");
    return 0;
}
