/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: dev.agent.orient — answer, from the compiled fact table, what this
 *          checkout already knows, so a reader does not re-derive it.
 *
 * ── CONTRACT (this file is the whole implementation) ──────────────────────
 *
 * WHY. Owner directive, 2026-09-05: "always be building things you need to
 * know into z23 so you don't have to burn tokens to learn in the future."
 * The maps an AI reader needs most — the landing path, the board protocol,
 * the lint system, test routing — were being re-derived from source by each
 * reader that needed them and thrown away with that reader's context. Every
 * one of those maps is now a row in engine/composition/facts/, carrying the
 * path it was read from and a literal anchor that a lint gate re-proves on
 * every commit. This leaf is the only renderer of that table.
 *
 * SOURCE. Include "../../engine/composition/facts/index.def" with
 * ZCL_FACT_TOPIC(topic, blurb) and ZCL_FACT(topic, key, claim, path, anchor)
 * defined locally, as many times as convenient. Nothing is read from disk at
 * query time and no process is run; the table is compiled in and its row
 * order is the report order.
 *
 * INPUT (zcl.dev_orient_input.v1) — both keys optional
 *   topic  string. A declared ZCL_FACT_TOPIC id. Present -> only that
 *          topic's rows. Absent and with no `query` -> the topic listing.
 *   query  string. A case-insensitive substring matched against each row's
 *          key, claim and path. Present -> matching rows across every topic,
 *          or within `topic` when both are given.
 *
 * OUTPUT (zcl.dev_orient.v1) on ok=true
 *   leaf          "dev.agent.orient"
 *   source        "engine/composition/facts/index.def"
 *   mode          "topics" | "topic" | "query"
 *   topic         echoed when `topic` was given
 *   query         echoed when `query` was given
 *   topics        array of {topic, blurb, rows} — ALWAYS present and always
 *                 complete, so one call names every topic that exists even
 *                 when the caller asked about one of them.
 *   facts         array of {topic, key, claim, path, anchor} in table order.
 *                 Empty in "topics" mode.
 *   count         elements in facts
 *   matched       rows that matched before the row cap was applied
 *   truncated     true when matched > count
 *   total_rows    every row in the table
 *   total_topics  every topic in the table
 *   lines         the human view: one string per element of facts, shaped
 *                 "key  claim  - path @anchor"; in "topics" mode, one per
 *                 topic, shaped "topic  <n> rows  blurb".
 *
 * FAILURE. A `topic` that is not a declared ZCL_FACT_TOPIC id is ok=false,
 * status "UNKNOWN_TOPIC", naming the value and the declared topics. An empty
 * match set for a `query` is ok=true with count 0 — "nothing is known about
 * this yet" is a true and useful answer, and is not the same as a bad topic.
 *
 * PROCESS RULE. This leaf runs no process and opens no file. It needs no
 * capability beyond the dev-state read every sibling dev.agent read leaf
 * declares.
 */

#include "command/native_command.h"

#include "json/json.h"

#include <stddef.h>
#include <stdio.h>
#include <string.h>

#define DVO_LEAF "dev.agent.orient"
#define DVO_SOURCE "engine/composition/facts/index.def"

/* Rows returned in one reply. The whole table is far larger than any single
 * answer should be; a caller who wants more narrows the query. */
#define DVO_ROW_CAP 80

/* One human line: key + claim + path + anchor plus the separators. */
#define DVO_LINE_MAX 512

struct dvo_topic {
    const char *topic;
    const char *blurb;
};

static const struct dvo_topic dvo_topics[] = {
#define ZCL_FACT_TOPIC(topic_, blurb_) {topic_, blurb_},
#define ZCL_FACT(topic_, key_, claim_, path_, anchor_)
#include "../../engine/composition/facts/index.def"
#undef ZCL_FACT
#undef ZCL_FACT_TOPIC
};
#define DVO_TOPIC_COUNT (sizeof(dvo_topics) / sizeof(dvo_topics[0]))

/* ASCII-lowercasing substring test. The table is ASCII by gate, so this is
 * exact rather than an approximation of a locale-aware search. */
static char dvo_lower(char c)
{
    return (c >= 'A' && c <= 'Z') ? (char)(c - 'A' + 'a') : c;
}

static bool dvo_contains(const char *haystack, const char *needle)
{
    size_t nlen;

    if (!haystack || !needle)
        return false;
    nlen = strlen(needle);
    if (nlen == 0)
        return true;
    for (const char *h = haystack; *h; h++) {
        size_t i = 0;
        while (i < nlen && h[i] && dvo_lower(h[i]) == dvo_lower(needle[i]))
            i++;
        if (i == nlen)
            return true;
    }
    return false;
}

static bool dvo_known_topic(const char *topic)
{
    for (size_t i = 0; i < DVO_TOPIC_COUNT; i++) {
        if (strcmp(dvo_topics[i].topic, topic) == 0)
            return true;
    }
    return false;
}

static const char *dvo_input_str(const struct zcl_command_request *request,
                                 const char *key)
{
    const struct json_value *v;

    if (!request || !request->input)
        return NULL;
    v = json_get(request->input, key);
    if (!v || v->type != JSON_STR)
        return NULL;
    if (!json_get_str(v) || !json_get_str(v)[0])
        return NULL;
    return json_get_str(v);
}

static void dvo_push_line(struct json_value *lines, const char *text)
{
    struct json_value s;

    json_init(&s);
    json_set_str(&s, text);
    (void)json_push_back(lines, &s);
    json_free(&s);
}

void zcl_native_handle_dev_orient(const struct zcl_command_request *request,
                                  struct zcl_command_reply *reply)
{
    const char *topic = NULL;
    const char *query = NULL;
    const char *mode;
    struct json_value topics, facts, lines, row;
    long long total_rows = 0;
    long long matched = 0;
    long long emitted = 0;

    if (!reply)
        return;

    (void)json_push_kv_str(&reply->data, "leaf", DVO_LEAF);

    topic = dvo_input_str(request, "topic");
    query = dvo_input_str(request, "query");

    if (topic && !dvo_known_topic(topic)) {
        char msg[512];
        char known[320];
        size_t used = 0;

        known[0] = '\0';
        for (size_t i = 0; i < DVO_TOPIC_COUNT; i++) {
            int w = snprintf(known + used, sizeof(known) - used, "%s%s",
                             used == 0 ? "" : ", ", dvo_topics[i].topic);
            if (w < 0 || (size_t)w >= sizeof(known) - used)
                break;
            used += (size_t)w;
        }
        (void)snprintf(msg, sizeof(msg),
                       "unknown topic \"%s\"; declared topics: %s", topic,
                       known);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_FAILED, "UNKNOWN_TOPIC",
                               "resolve", false, false, msg,
                               "tools/command/native_dev_orient.c");
        return;
    }

    mode = query ? "query" : (topic ? "topic" : "topics");

    json_init(&topics);
    json_set_array(&topics);
    json_init(&facts);
    json_set_array(&facts);
    json_init(&lines);
    json_set_array(&lines);
    json_init(&row);

    /* Pass one: per-topic row counts, so the listing is derived from the
     * rows themselves and can never disagree with them. */
    for (size_t i = 0; i < DVO_TOPIC_COUNT; i++) {
        long long rows = 0;

#define ZCL_FACT_TOPIC(topic_, blurb_)
#define ZCL_FACT(topic_, key_, claim_, path_, anchor_)                       \
    if (strcmp(topic_, dvo_topics[i].topic) == 0)                            \
        rows++;
#include "../../engine/composition/facts/index.def"
#undef ZCL_FACT
#undef ZCL_FACT_TOPIC

        total_rows += rows;
        json_set_object(&row);
        (void)json_push_kv_str(&row, "topic", dvo_topics[i].topic);
        (void)json_push_kv_str(&row, "blurb", dvo_topics[i].blurb);
        (void)json_push_kv_int(&row, "rows", rows);
        (void)json_push_back(&topics, &row);

        if (strcmp(mode, "topics") == 0) {
            char line[DVO_LINE_MAX];
            (void)snprintf(line, sizeof(line), "%-16s %3lld rows  %s",
                           dvo_topics[i].topic, rows, dvo_topics[i].blurb);
            dvo_push_line(&lines, line);
        }
    }

    /* Pass two: the rows this call asked for. */
    if (strcmp(mode, "topics") != 0) {
#define ZCL_FACT_TOPIC(topic_, blurb_)
#define ZCL_FACT(topic_, key_, claim_, path_, anchor_)                       \
    do {                                                                     \
        bool want = (!topic || strcmp(topic, topic_) == 0) &&                \
                    (!query || dvo_contains(key_, query) ||                  \
                     dvo_contains(claim_, query) ||                          \
                     dvo_contains(path_, query));                            \
        if (want) {                                                          \
            matched++;                                                       \
            if (emitted < DVO_ROW_CAP) {                                     \
                char line[DVO_LINE_MAX];                                     \
                json_set_object(&row);                                       \
                (void)json_push_kv_str(&row, "topic", topic_);               \
                (void)json_push_kv_str(&row, "key", key_);                   \
                (void)json_push_kv_str(&row, "claim", claim_);               \
                (void)json_push_kv_str(&row, "path", path_);                 \
                (void)json_push_kv_str(&row, "anchor", anchor_);             \
                (void)json_push_back(&facts, &row);                          \
                (void)snprintf(line, sizeof(line), "%s  %s  - %s @%s", key_, \
                               claim_, path_, anchor_);                      \
                dvo_push_line(&lines, line);                                 \
                emitted++;                                                   \
            }                                                                \
        }                                                                    \
    } while (0);
#include "../../engine/composition/facts/index.def"
#undef ZCL_FACT
#undef ZCL_FACT_TOPIC
    }

    json_free(&row);

    (void)json_push_kv_str(&reply->data, "source", DVO_SOURCE);
    (void)json_push_kv_str(&reply->data, "mode", mode);
    if (topic)
        (void)json_push_kv_str(&reply->data, "topic", topic);
    if (query)
        (void)json_push_kv_str(&reply->data, "query", query);
    (void)json_push_kv(&reply->data, "topics", &topics);
    (void)json_push_kv(&reply->data, "facts", &facts);
    (void)json_push_kv_int(&reply->data, "count", emitted);
    (void)json_push_kv_int(&reply->data, "matched", matched);
    (void)json_push_kv_bool(&reply->data, "truncated", matched > emitted);
    (void)json_push_kv_int(&reply->data, "total_rows", total_rows);
    (void)json_push_kv_int(&reply->data, "total_topics",
                           (int64_t)DVO_TOPIC_COUNT);
    (void)json_push_kv(&reply->data, "lines", &lines);

    json_free(&topics);
    json_free(&facts);
    json_free(&lines);

    reply->status = ZCL_COMMAND_STATUS_PASSED;
}

/* The one-line orientation banner every agent-facing start leaf prints, so
 * the fact table announces itself instead of waiting to be discovered.
 * Derived from the same compiled table as the leaf above; there is no second
 * count to keep in step. */
void zcl_dev_orient_banner(char *out, size_t cap)
{
    long long rows = 0;

    if (!out || cap == 0)
        return;

#define ZCL_FACT_TOPIC(topic_, blurb_)
#define ZCL_FACT(topic_, key_, claim_, path_, anchor_) rows++;
#include "../../engine/composition/facts/index.def"
#undef ZCL_FACT
#undef ZCL_FACT_TOPIC

    (void)snprintf(out, cap,
                   "%lld rows in %zu topics - z23-dev dev agent orient "
                   "<topic> | --query=<substring>",
                   rows, DVO_TOPIC_COUNT);
}
