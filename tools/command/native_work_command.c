/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Read owner-signed public work cards from the node's board.
 *
 * `work list` and `work show` are read-only views over board posts of kind
 * `need` in public room `work`. A card is trusted only when the post's signing
 * host key equals the owner key. State is never stored: it derives from the
 * `claim` and `result` posts whose `ref` names the card. The board is reached
 * through the existing fleet_board RPC call; no board storage is read here. */
#include "command/native_command.h"
#include "command/work_card.h"

#include "json/json.h"
#include "kernel/command_registry.h"

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

enum {
    WORK_LIST_DEFAULT = 10,
    WORK_LIST_MAX = 16,
    WORK_REJECTED_MAX = 8,
    WORK_EVIDENCE_MAX = 4,
    WORK_TEXT_PREVIEW = 160,
    WORK_BOARD_FETCH = 256,
};

enum work_state { WORK_OPEN, WORK_CLAIMED, WORK_SUBMITTED, WORK_DONE };

static const char *const k_work_room = "work";

static const char *work_state_name(enum work_state state)
{
    switch (state) {
    case WORK_DONE: return "done";
    case WORK_SUBMITTED: return "submitted";
    case WORK_CLAIMED: return "claimed";
    default: return "open";
    }
}

static void work_fail(struct zcl_command_reply *reply, const char *code,
                      const char *phase, const char *message)
{
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                           ZCL_COMMAND_EXIT_INVALID, code, phase, false,
                           false, message, "work.cards");
}

static const char *work_input_str(const struct zcl_command_request *request,
                                  const char *key)
{
    const struct json_value *v =
        request->input ? json_get(request->input, key) : NULL;
    return v && v->type == JSON_STR ? json_get_str(v) : NULL;
}

/* Copy at most `max` bytes without cutting a UTF-8 sequence. */
static void work_preview(const char *s, char out[WORK_TEXT_PREVIEW + 1])
{
    size_t n = s ? strlen(s) : 0;
    if (n > WORK_TEXT_PREVIEW) {
        n = WORK_TEXT_PREVIEW;
        while (n > 0 && ((unsigned char)s[n] & 0xC0) == 0x80)
            n--;
    }
    if (n)
        memcpy(out, s, n);
    out[n] = '\0';
}

/* Public board posts of one kind in room `work`. A non-NULL `host` also
 * restricts the query to posts that key signed, so they cannot be crowded out
 * of the newest-256 window by other keys. */
static bool work_query(const char *kind, const char *host,
                       struct json_value *body,
                       struct zcl_command_reply *reply)
{
    struct json_value in;
    json_init(&in);
    json_set_object(&in);
    bool ok = json_push_kv_str(&in, "op", "list") &&
              json_push_kv_str(&in, "kind", kind) &&
              json_push_kv_str(&in, "scope", "public") &&
              json_push_kv_str(&in, "room", k_work_room) &&
              json_push_kv_int(&in, "limit", WORK_BOARD_FETCH);
    if (ok && host)
        ok = json_push_kv_str(&in, "host", host);
    if (!ok) {
        json_free(&in);
        work_fail(reply, "WORK_ALLOC", "prepare",
                  "the board request could not be built");
        return false;
    }
    ok = zcl_native_fleet_board_call(&in, body, reply);
    json_free(&in);
    return ok;
}

/* The trusted owner key: the `owner` input, else the key pinned in the source.
 * This node's own board key is never a default. */
static bool work_owner(const struct zcl_command_request *request,
                       char owner[WORK_KEY_HEX + 1],
                       struct zcl_command_reply *reply)
{
    enum work_owner_status s = work_owner_resolve(
        work_input_str(request, "owner"), WORK_OWNER_BOARD_KEY, owner);
    if (s == WORK_OWNER_BAD)
        work_fail(reply, "BAD_OWNER", "normalize",
                  "owner must be a 64-character host public key in hex");
    else if (s == WORK_OWNER_REQUIRED)
        work_fail(reply, "OWNER_REQUIRED", "normalize",
                  "no owner key is pinned in this build; pass "
                  "owner=<64-hex host key of the card owner>");
    return s == WORK_OWNER_OK;
}

/* Results in room `work`: every result the owner key signed, fetched by host
 * so they always arrive, then other keys' results from the newest window. */
static bool work_results(const char *owner, struct json_value *merged,
                         struct zcl_command_reply *reply)
{
    struct json_value mine, others, posts;
    json_init(&mine);
    json_init(&others);
    json_init(&posts);
    json_set_array(&posts);
    bool ok = work_query("result", owner, &mine, reply) &&
              work_query("result", NULL, &others, reply);
    const struct json_value *a = json_get(&mine, "posts");
    const struct json_value *b = json_get(&others, "posts");
    for (size_t i = 0; ok && i < json_size(a); i++)
        ok = json_push_back(&posts, json_at(a, i));
    for (size_t i = 0; ok && i < json_size(b); i++)
        if (strcmp(json_get_str(json_get(json_at(b, i), "host")), owner) != 0)
            ok = json_push_back(&posts, json_at(b, i));
    json_set_object(merged);
    ok = ok && json_push_kv(merged, "posts", &posts);
    json_free(&mine);
    json_free(&others);
    json_free(&posts);
    if (!ok)
        work_fail(reply, "WORK_ALLOC", "prepare", "the result list could not be built");
    return ok;
}

/* True when a post references `id` and was signed by the owner key exactly
 * when `by_owner` says so. */
static bool work_refs(const struct json_value *posts, const char *id,
                      const char *owner, bool by_owner)
{
    for (size_t i = 0; i < json_size(posts); i++) {
        const struct json_value *p = json_at(posts, i);
        bool is_owner = strcmp(json_get_str(json_get(p, "host")), owner) == 0;
        if (strcmp(json_get_str(json_get(p, "ref")), id) == 0 &&
            is_owner == by_owner)
            return true;
    }
    return false;
}

/* open; claimed by any key; submitted by a result from any other key; done only
 * by a result the owner key signed. */
static enum work_state work_state_of(const char *id, const char *owner,
                                     const struct json_value *claims,
                                     const struct json_value *results)
{
    const struct json_value *rp = json_get(results, "posts");
    if (work_refs(rp, id, owner, true))
        return WORK_DONE;
    if (work_refs(rp, id, owner, false))
        return WORK_SUBMITTED;
    return work_refs(json_get(claims, "posts"), id, owner, true) ||
                   work_refs(json_get(claims, "posts"), id, owner, false)
               ? WORK_CLAIMED : WORK_OPEN;
}

/* Posts of one kind from the node that reference `id`, newest first, as short
 * rows, plus how many there are in all. */
static bool work_evidence(const struct json_value *body, const char *id,
                          struct json_value *rows, int64_t *total)
{
    const struct json_value *posts = json_get(body, "posts");
    json_set_array(rows);
    *total = 0;
    for (size_t i = 0; i < json_size(posts); i++) {
        const struct json_value *p = json_at(posts, i);
        if (strcmp(json_get_str(json_get(p, "ref")), id) != 0)
            continue;
        (*total)++;
        if (json_size(rows) >= WORK_EVIDENCE_MAX)
            continue;
        char text[WORK_TEXT_PREVIEW + 1];
        work_preview(json_get_str(json_get(p, "text")), text);
        struct json_value row;
        json_init(&row);
        json_set_object(&row);
        bool ok = json_push_kv_str(&row, "id", json_get_str(json_get(p, "id"))) &&
                  json_push_kv_str(&row, "host", json_get_str(json_get(p, "host"))) &&
                  json_push_kv_str(&row, "agent", json_get_str(json_get(p, "agent"))) &&
                  json_push_kv_int(&row, "created_at", json_get_int(json_get(p, "created_at"))) &&
                  json_push_kv_str(&row, "text", text) &&
                  json_push_back(rows, &row);
        json_free(&row);
        if (!ok)
            return false;
    }
    return true;
}

static bool work_row(struct json_value *rows, const char *id,
                     const struct work_card *card, enum work_state state)
{
    char outcome[WORK_TEXT_PREVIEW + 1];
    work_preview(card->outcome, outcome);
    struct json_value row;
    json_init(&row);
    json_set_object(&row);
    bool ok = json_push_kv_str(&row, "id", id) &&
              json_push_kv_str(&row, "name", card->name) &&
              json_push_kv_str(&row, "level", work_card_level_name(card->level)) &&
              json_push_kv_str(&row, "outcome", outcome) &&
              json_push_kv_str(&row, "state", work_state_name(state)) &&
              json_push_back(rows, &row);
    json_free(&row);
    return ok;
}

static bool work_reject(struct json_value *rejected, const char *id,
                        enum work_card_reason reason)
{
    if (json_size(rejected) >= WORK_REJECTED_MAX)
        return true;
    struct json_value row;
    json_init(&row);
    json_set_object(&row);
    bool ok = json_push_kv_str(&row, "id", id) &&
              json_push_kv_str(&row, "reason", work_card_reason_code(reason)) &&
              json_push_back(rejected, &row);
    json_free(&row);
    return ok;
}

/* True for a need post in room `work` signed by the owner key. */
static bool work_owned_need(const struct json_value *post, const char *owner)
{
    return strcmp(json_get_str(json_get(post, "kind")), "need") == 0 &&
           strcmp(json_get_str(json_get(post, "room")), k_work_room) == 0 &&
           strcmp(json_get_str(json_get(post, "host")), owner) == 0;
}

struct work_listing {
    struct json_value rows;
    struct json_value rejected;
    int64_t rejected_total;
    enum work_card_level want;
    size_t limit;
    const char *owner;
};

static bool work_list_one(struct work_listing *out, const struct json_value *post,
                          const struct json_value *claims,
                          const struct json_value *results)
{
    struct work_card card;
    const char *id = json_get_str(json_get(post, "id"));
    const char *text = json_get_str(json_get(post, "text"));
    enum work_card_reason reason =
        work_card_validate(text, strlen(text), &card);
    if (reason != WORK_CARD_OK) {
        out->rejected_total++;
        return work_reject(&out->rejected, id, reason);
    }
    if ((out->want != WORK_CARD_LEVEL_NONE && card.level != out->want) ||
        json_size(&out->rows) >= out->limit)
        return true;
    return work_row(&out->rows, id, &card, work_state_of(id, out->owner, claims, results));
}

static bool work_list_build(struct work_listing *out, const char *owner,
                            const struct json_value *needs,
                            const struct json_value *claims,
                            const struct json_value *results)
{
    const struct json_value *posts = json_get(needs, "posts");
    out->owner = owner;
    json_set_array(&out->rows);
    json_set_array(&out->rejected);
    for (size_t i = 0; i < json_size(posts); i++) {
        const struct json_value *post = json_at(posts, i);
        if (work_owned_need(post, owner) &&
            !work_list_one(out, post, claims, results))
            return false;
    }
    return true;
}

static bool work_list_inputs(const struct zcl_command_request *request,
                             struct work_listing *out,
                             struct zcl_command_reply *reply)
{
    const char *level = work_input_str(request, "level");
    const struct json_value *limit =
        request->input ? json_get(request->input, "limit") : NULL;
    out->want = WORK_CARD_LEVEL_NONE;
    out->limit = WORK_LIST_DEFAULT;
    if (level && level[0] &&
        (out->want = work_card_level_from_name(level)) == WORK_CARD_LEVEL_NONE) {
        work_fail(reply, "BAD_LEVEL", "normalize",
                  "level must be haiku, sonnet or opus");
        return false;
    }
    if (limit && limit->type == JSON_INT && json_get_int(limit) > 0)
        out->limit = json_get_int(limit) > WORK_LIST_MAX
                         ? WORK_LIST_MAX : (size_t)json_get_int(limit);
    return true;
}

static void work_list_publish(struct work_listing *l, const char *owner,
                              struct zcl_command_reply *reply)
{
    bool ok = json_push_kv_str(&reply->data, "owner", owner) &&
              json_push_kv_int(&reply->data, "returned", (int64_t)json_size(&l->rows)) &&
              json_push_kv(&reply->data, "cards", &l->rows) &&
              json_push_kv_int(&reply->data, "rejected_count", l->rejected_total) &&
              json_push_kv(&reply->data, "rejected", &l->rejected);
    if (!ok) {
        work_fail(reply, "WORK_ALLOC", "serialize",
                  "the work card list could not be built");
        return;
    }
    (void)zcl_command_reply_add_next(reply, "work.show", "{}",
                                     "read one card whole with its claims and results");
}

void zcl_native_handle_work_list(const struct zcl_command_request *request,
                                 struct zcl_command_reply *reply)
{
    struct work_listing l;
    char owner[WORK_KEY_HEX + 1];
    struct json_value needs, claims, results;
    memset(&l, 0, sizeof(l));
    json_init(&l.rows);
    json_init(&l.rejected);
    json_init(&needs);
    json_init(&claims);
    json_init(&results);
    if (work_list_inputs(request, &l, reply) && work_owner(request, owner, reply) &&
        work_query("need", owner, &needs, reply) &&
        work_query("claim", NULL, &claims, reply) &&
        work_results(owner, &results, reply)) {
        if (work_list_build(&l, owner, &needs, &claims, &results))
            work_list_publish(&l, owner, reply);
        else
            work_fail(reply, "WORK_ALLOC", "serialize",
                      "the work card list could not be built");
    }
    json_free(&l.rows);
    json_free(&l.rejected);
    json_free(&needs);
    json_free(&claims);
    json_free(&results);
}

static bool work_show_load(const char *id, const char *owner,
                           struct json_value *post,
                           struct zcl_command_reply *reply)
{
    struct json_value in;
    json_init(&in);
    json_set_object(&in);
    bool ok = json_push_kv_str(&in, "op", "show") &&
              json_push_kv_str(&in, "id", id) &&
              zcl_native_fleet_board_call(&in, post, reply);
    json_free(&in);
    if (ok && !work_owned_need(post, owner)) {
        work_fail(reply, "NOT_A_WORK_CARD", "execute",
                  "that post is not a need in room work signed by the owner key");
        return false;
    }
    return ok;
}

static bool work_show_publish(struct zcl_command_reply *reply, const char *id,
                              const char *owner, const char *text,
                              const struct json_value *claims,
                              const struct json_value *results)
{
    struct json_value card, claim_rows, result_rows;
    int64_t claim_total, result_total;
    json_init(&card);
    json_init(&claim_rows);
    json_init(&result_rows);
    bool ok = json_read(&card, text, strlen(text)) &&
              work_evidence(claims, id, &claim_rows, &claim_total) &&
              work_evidence(results, id, &result_rows, &result_total) &&
              json_push_kv_str(&reply->data, "id", id) &&
              json_push_kv_str(&reply->data, "owner", owner) &&
              json_push_kv_str(&reply->data, "state",
                  work_state_name(work_state_of(id, owner, claims, results))) &&
              json_push_kv(&reply->data, "card", &card) &&
              json_push_kv_int(&reply->data, "claim_count", claim_total) &&
              json_push_kv(&reply->data, "claims", &claim_rows) &&
              json_push_kv_int(&reply->data, "result_count", result_total) &&
              json_push_kv(&reply->data, "results", &result_rows);
    json_free(&card);
    json_free(&claim_rows);
    json_free(&result_rows);
    return ok;
}

void zcl_native_handle_work_show(const struct zcl_command_request *request,
                                 struct zcl_command_reply *reply)
{
    char id[WORK_KEY_HEX + 1], owner[WORK_KEY_HEX + 1];
    struct json_value post, claims, results;
    struct work_card card;
    json_init(&post);
    json_init(&claims);
    json_init(&results);
    if (!work_card_hex64(work_input_str(request, "id"), id)) {
        work_fail(reply, "BAD_ID", "normalize",
                  "usage: work show <id> — id is a 64-character board post id");
    } else if (work_owner(request, owner, reply) &&
               work_show_load(id, owner, &post, reply)) {
        const char *text = json_get_str(json_get(&post, "text"));
        enum work_card_reason reason =
            work_card_validate(text, strlen(text), &card);
        if (reason != WORK_CARD_OK)
            work_fail(reply, work_card_reason_code(reason), "validate",
                      "the owner-signed card does not satisfy zcl.work_card.v1");
        else if (work_query("claim", NULL, &claims, reply) &&
                 work_results(owner, &results, reply) &&
                 !work_show_publish(reply, id, owner, text, &claims, &results))
            work_fail(reply, "WORK_ALLOC", "serialize",
                      "the work card could not be built");
    }
    json_free(&post);
    json_free(&claims);
    json_free(&results);
}
