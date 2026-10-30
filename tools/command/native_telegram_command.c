/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: ops.telegram.status / send / inbox / configure. One bot, one
 * owner chat, text only; the token never reaches argv, output, logs or errors. */
#include "command/native_command.h"
#include "command/native_telegram.h"
#include "base/cleanse.h"
#include "base/safe_alloc.h"
#include "platform/process_lock.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if !defined(_WIN32)
#include <errno.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

#define TG_SEND_BODY_MAX (112u * 1024u)
#define TG_INBOX_LIMIT 10
#define TG_INBOX_TEXT_MAX 3000u
#define TG_INBOX_BUDGET 10000u
#define TG_WAIT_MAX 50

static void tg_fail(struct zcl_command_reply *reply, enum zcl_command_exit exit_code,
                    const char *code, const char *phase, bool retryable, bool mutated,
                    const char *message, const char *hint)
{
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED, exit_code, code, phase, retryable,
                           mutated, message, hint);
}

static bool tg_load(struct zcl_command_reply *reply, struct tg_config *cfg)
{
    char path[TG_PATH_MAX];
    enum tg_load state = tg_credentials_path(path, sizeof(path)) ? tg_credentials_load(path, cfg)
                                                                 : TG_LOAD_MISSING;
    if (state == TG_LOAD_OK)
        return true;
    if (state == TG_LOAD_NOT_PRIVATE)
        tg_fail(reply, ZCL_COMMAND_EXIT_DENIED, "TELEGRAM_CREDENTIALS_NOT_PRIVATE", "credentials",
                false, false,
                "the credentials file must be a regular file owned by you with no group or world access",
                "chmod 600 ~/.config/z23/telegram.env");
    else if (state == TG_LOAD_INVALID)
        tg_fail(reply, ZCL_COMMAND_EXIT_INVALID, "TELEGRAM_CREDENTIALS_INVALID", "credentials",
                false, false, "the credentials file does not hold a valid bot token and chat id",
                "TELEGRAM_BOT_TOKEN=<id>:<secret> and TELEGRAM_CHAT_ID=<number>, one per line");
    else
        tg_fail(reply, ZCL_COMMAND_EXIT_BLOCKED, "TELEGRAM_NOT_CONFIGURED", "credentials", false,
                false, "no Telegram credentials are configured on this host",
                "z23 telegram configure < telegram.env");
    return false;
}

static void tg_api_fail(struct zcl_command_reply *reply, enum tg_api kind, const char *desc,
                        const char *phase, bool mutated)
{
    char message[160];
    switch (kind) {
    case TG_API_CONFLICT:
        tg_fail(reply, ZCL_COMMAND_EXIT_BLOCKED, "POLLER_CONFLICT", phase, true, mutated,
                "another host or process is polling this bot; Telegram allows one getUpdates consumer per token",
                "stop the other poller or choose one host to receive");
        break;
    case TG_API_RATE_LIMITED:
        tg_fail(reply, ZCL_COMMAND_EXIT_TRANSIENT, "TELEGRAM_RATE_LIMITED", phase, true, mutated,
                "Telegram asked this client to slow down", "retry after a short delay");
        break;
    case TG_API_UNAUTHORIZED:
        tg_fail(reply, ZCL_COMMAND_EXIT_DENIED, "TELEGRAM_UNAUTHORIZED", phase, false, mutated,
                "Telegram rejected the bot token", "z23 telegram configure < telegram.env");
        break;
    case TG_API_REJECTED:
        snprintf(message, sizeof(message), "Telegram refused the request: %s", desc);
        tg_fail(reply, ZCL_COMMAND_EXIT_FAILED, "TELEGRAM_REJECTED", phase, false, mutated, message,
                "check the chat id and that the user has started the bot");
        break;
    default:
        tg_fail(reply, ZCL_COMMAND_EXIT_FAILED, "TELEGRAM_BAD_RESPONSE", phase, true, mutated,
                "Telegram returned an answer this client could not parse", "retry");
        break;
    }
}

static void tg_unreachable(struct zcl_command_reply *reply, const char *phase, bool mutated)
{
    tg_fail(reply, ZCL_COMMAND_EXIT_TRANSIENT, "TELEGRAM_UNREACHABLE", phase, true, mutated,
            "api.telegram.org did not answer through curl", "check network access and that curl is installed");
}

/* One Bot API call. On success *doc holds the envelope (caller frees). */
static bool tg_api(struct zcl_command_reply *reply, const struct tg_config *cfg,
                   const char *method, const char *body, int timeout_s, const char *phase,
                   struct json_value *doc)
{
    struct tg_response response;
    char desc[160];
    json_init(doc);
    if (!tg_call(cfg->token, method, body, timeout_s, &response)) {
        tg_unreachable(reply, phase, false);
        return false;
    }
    enum tg_api kind = tg_api_parse(&response, cfg->token, doc, desc, sizeof(desc));
    tg_response_free(&response);
    if (kind != TG_API_OK) {
        tg_api_fail(reply, kind, desc, phase, false);
        json_free(doc);
        return false;
    }
    return true;
}

static void tg_internal(struct zcl_command_reply *reply, const char *phase)
{
    tg_fail(reply, ZCL_COMMAND_EXIT_INTERNAL, "TELEGRAM_INTERNAL", phase, false, false,
            "the reply could not be built within its bounds", "retry");
}

static bool tg_poll_lock_path(char *out, size_t cap)
{
    char dir[TG_PATH_MAX];
    return tg_state_dir(dir, sizeof(dir)) && snprintf(out, cap, "%s/poll.lock", dir) < (int)cap;
}

/* ── status ──────────────────────────────────────────────────────────── */

static bool tg_lock_held(void)
{
    char path[TG_PATH_MAX + 16];
    struct platform_process_lock lock;
    platform_process_lock_init(&lock);
    if (!tg_poll_lock_path(path, sizeof(path)))
        return false;
    if (!platform_process_lock_try_acquire(&lock, path, true))
        return true;
    platform_process_lock_release(&lock);
    return false;
}

static bool tg_status_emit(struct zcl_command_reply *reply, const struct tg_config *cfg,
                           const struct json_value *me)
{
    const struct json_value *result = json_get(me, "result");
    struct json_value bot = {0};
    json_set_object(&reply->data);
    json_set_object(&bot);
    bool ok = json_push_kv_int(&bot, "id", json_get_int(json_get(result, "id"))) &&
              json_push_kv_str(&bot, "username", json_get_str(json_get(result, "username"))) &&
              json_push_kv_str(&bot, "name", json_get_str(json_get(result, "first_name")));
    ok = ok && json_push_kv_str(&reply->data, "schema", "zcl.telegram.status.v1") &&
         json_push_kv_bool(&reply->data, "credentials_private", true) &&
         json_push_kv_bool(&reply->data, "chat_configured", cfg->has_chat) &&
         json_push_kv_int(&reply->data, "allow_count",
                          (int64_t)cfg->allow_count + (cfg->has_chat ? 1 : 0)) &&
         json_push_kv_bool(&reply->data, "poll_lock_held", tg_lock_held()) &&
         json_push_kv(&reply->data, "bot", &bot);
    json_free(&bot);
    return ok;
}

void zcl_native_handle_ops_telegram_status(const struct zcl_command_request *request,
                                           struct zcl_command_reply *reply)
{
    struct tg_config cfg;
    struct json_value me;
    (void)request;
    if (!reply || !tg_load(reply, &cfg))
        return;
    if (tg_api(reply, &cfg, "getMe", "{}", 20, "get_me", &me)) {
        if (!tg_status_emit(reply, &cfg, &me))
            tg_internal(reply, "status");
        json_free(&me);
    }
    memory_cleanse(&cfg, sizeof(cfg));
}

/* ── send ────────────────────────────────────────────────────────────── */

struct tg_send_in {
    const char *text;
    const char *key;
    int64_t chat_id;
    char hash[TG_HASH_HEX];
};

static const char *tg_input_str(const struct zcl_command_request *request, const char *key)
{
    const struct json_value *v = request->input ? json_get(request->input, key) : NULL;
    if (!v || v->type != JSON_STR)
        return NULL;
    return json_get_str(v);
}

static bool tg_send_parse(const struct zcl_command_request *request, struct zcl_command_reply *reply,
                          struct tg_send_in *in)
{
    const struct json_value *chat = request->input ? json_get(request->input, "chat_id") : NULL;
    memset(in, 0, sizeof(*in));
    in->text = tg_input_str(request, "text");
    in->key = tg_input_str(request, "idempotency_key");
    if (chat && chat->type == JSON_INT)
        in->chat_id = json_get_int(chat);
    size_t len = in->text ? strlen(in->text) : 0;
    if (len == 0 || len > TG_TEXT_MAX || !tg_utf8_valid(in->text, len)) {
        tg_fail(reply, ZCL_COMMAND_EXIT_INVALID, "TELEGRAM_BAD_TEXT", "normalize", false, false,
                "text must be non-empty UTF-8 of at most 12000 bytes", "z23 telegram send --text=<text>");
        return false;
    }
    if (in->key && !tg_key_valid(in->key)) {
        tg_fail(reply, ZCL_COMMAND_EXIT_INVALID, "TELEGRAM_BAD_KEY", "normalize", false, false,
                "idempotency_key must be 1..64 characters of letters, digits and . _ : -",
                "z23 telegram send --idempotency_key=<key>");
        return false;
    }
    return true;
}

/* The chat must be an allowlisted id: a bot answers its owner, not strangers. */
static bool tg_send_target(struct zcl_command_reply *reply, const struct tg_config *cfg,
                           struct tg_send_in *in)
{
    if (in->chat_id == 0)
        in->chat_id = cfg->chat_id;
    if (in->chat_id == 0 || !tg_allowed(cfg, in->chat_id)) {
        tg_fail(reply, ZCL_COMMAND_EXIT_DENIED, "TELEGRAM_CHAT_NOT_ALLOWED", "target", false, false,
                "the chat is not TELEGRAM_CHAT_ID or listed in TELEGRAM_ALLOW_FROM",
                "add the id to TELEGRAM_ALLOW_FROM and run z23 telegram configure");
        return false;
    }
    return true;
}

static bool tg_send_chunk(struct zcl_command_reply *reply, const struct tg_config *cfg,
                          int64_t chat_id, const char *text, size_t len, bool mutated,
                          int64_t *message_id)
{
    struct json_value doc, req = {0};
    char *chunk = zcl_malloc(len + 1, "telegram.chunk");
    char *body = zcl_malloc(TG_SEND_BODY_MAX, "telegram.body");
    bool ok = false;
    if (chunk && body) {
        memcpy(chunk, text, len);
        chunk[len] = '\0';
        json_set_object(&req);
        ok = json_push_kv_int(&req, "chat_id", chat_id) && json_push_kv_str(&req, "text", chunk) &&
             json_write(&req, body, TG_SEND_BODY_MAX) < TG_SEND_BODY_MAX;
    }
    json_free(&req);
    if (!ok) {
        tg_internal(reply, "send");
    } else if (tg_api(reply, cfg, "sendMessage", body, 30, "send", &doc)) {
        *message_id = json_get_int(json_get(json_get(&doc, "result"), "message_id"));
        json_free(&doc);
    } else {
        ok = false;
        reply->error.mutated = mutated;
    }
    free(chunk);
    free(body);
    return ok;
}

static bool tg_send_all(struct zcl_command_reply *reply, const struct tg_config *cfg,
                        const struct tg_send_in *in, struct json_value *ids)
{
    size_t len = strlen(in->text), at = 0;
    json_set_array(ids);
    while (at < len) {
        size_t n = tg_chunk_len(in->text + at, len - at);
        struct json_value id = {0};
        int64_t message_id = 0;
        if (n == 0 || !tg_send_chunk(reply, cfg, in->chat_id, in->text + at, n, at > 0, &message_id))
            return false;
        json_set_int(&id, message_id);
        if (!json_push_back(ids, &id)) {
            tg_internal(reply, "send");
            return false;
        }
        at += n;
    }
    return true;
}

static bool tg_send_emit(struct zcl_command_reply *reply, int64_t chat_id, struct json_value *ids,
                         bool duplicate)
{
    json_set_object(&reply->data);
    reply->error.mutated = !duplicate;
    return json_push_kv_str(&reply->data, "schema", "zcl.telegram.send.v1") &&
           json_push_kv_int(&reply->data, "chat_id", chat_id) &&
           json_push_kv_int(&reply->data, "chunks", (int64_t)json_size(ids)) &&
           json_push_kv_bool(&reply->data, "duplicate", duplicate) &&
           json_push_kv(&reply->data, "message_ids", ids);
}

/* A repeated idempotency_key returns the first send's ids and sends nothing. */
static bool tg_send_duplicate(struct zcl_command_reply *reply, const char *dir,
                              const struct tg_send_in *in)
{
    int64_t first = 0, count = 0;
    struct json_value ids = {0};
    enum tg_sent seen = in->key ? tg_sent_lookup(dir, in->key, in->hash, &first, &count) : TG_SENT_NONE;
    if (seen == TG_SENT_NONE)
        return false;
    if (seen == TG_SENT_DIFFERENT) {
        tg_fail(reply, ZCL_COMMAND_EXIT_INVALID, "IDEMPOTENCY_KEY_REUSED", "idempotency", false, false,
                "idempotency_key was already used for a different chat or text",
                "use a new idempotency_key for a different message");
        return true;
    }
    json_set_array(&ids);
    for (int64_t i = 0; i < count; i++) {
        struct json_value id = {0};
        json_set_int(&id, first + i);
        (void)json_push_back(&ids, &id);
    }
    if (!tg_send_emit(reply, in->chat_id, &ids, true))
        tg_internal(reply, "send");
    json_free(&ids);
    return true;
}

static void tg_send_run(struct zcl_command_reply *reply, const struct tg_config *cfg,
                        struct tg_send_in *in)
{
    char dir[TG_PATH_MAX];
    struct json_value ids = {0};
    bool have_dir = tg_state_dir(dir, sizeof(dir));
    tg_request_hash(in->chat_id, in->text, in->hash);
    if (in->key && !have_dir) {
        tg_internal(reply, "state");
        return;
    }
    if (have_dir && tg_send_duplicate(reply, dir, in))
        return;
    if (tg_send_all(reply, cfg, in, &ids)) {
        int64_t first = json_size(&ids) ? json_get_int(json_at(&ids, 0)) : 0;
        if (in->key && !tg_sent_record(dir, in->key, in->hash, first, (int64_t)json_size(&ids)))
            tg_internal(reply, "state");
        else if (!tg_send_emit(reply, in->chat_id, &ids, false))
            tg_internal(reply, "send");
    }
    json_free(&ids);
}

void zcl_native_handle_ops_telegram_send(const struct zcl_command_request *request,
                                         struct zcl_command_reply *reply)
{
    struct tg_send_in in;
    struct tg_config cfg;
    if (!reply || !request)
        return;
    if (!tg_send_parse(request, reply, &in) || !tg_load(reply, &cfg))
        return;
    const char *why = tg_secret_refusal(in.text, cfg.token);
    if (why) {
        tg_fail(reply, ZCL_COMMAND_EXIT_DENIED, "TELEGRAM_SECRET_REFUSED", "guard", false, false, why,
                "send a description of the result, never keys, seeds or tokens");
    } else if (tg_send_target(reply, &cfg, &in)) {
        tg_send_run(reply, &cfg, &in);
    }
    memory_cleanse(&cfg, sizeof(cfg));
}

/* ── inbox ───────────────────────────────────────────────────────────── */

struct tg_inbox {
    struct json_value list;
    size_t bytes;
    int64_t dropped;
    int64_t next_offset;
    bool more;
};

static size_t tg_text_cut(const char *text, size_t len)
{
    if (len <= TG_INBOX_TEXT_MAX)
        return len;
    size_t cut = TG_INBOX_TEXT_MAX;
    while (cut > 0 && ((unsigned char)text[cut] & 0xC0) == 0x80)
        cut--;
    return cut;
}

static bool tg_inbox_item(struct json_value *item, int64_t update_id, const struct json_value *msg,
                          size_t *bytes)
{
    const struct json_value *from = json_get(msg, "from");
    bool plain = json_get(msg, "text") != NULL;
    const char *text = json_get_str(json_get(msg, plain ? "text" : "caption"));
    char shown[TG_INBOX_TEXT_MAX + 1];
    size_t len = strlen(text), cut = tg_text_cut(text, len);
    memcpy(shown, text, cut);
    shown[cut] = 0;
    *bytes += cut + 160;
    json_set_object(item);
    return json_push_kv_int(item, "update_id", update_id) &&
           json_push_kv_int(item, "message_id", json_get_int(json_get(msg, "message_id"))) &&
           json_push_kv_int(item, "from_id", json_get_int(json_get(from, "id"))) &&
           json_push_kv_str(item, "username", json_get_str(json_get(from, "username"))) &&
           json_push_kv_int(item, "date", json_get_int(json_get(msg, "date"))) &&
           json_push_kv_str(item, "kind", plain ? "text" : "other") &&
           json_push_kv_str(item, "text", shown) && json_push_kv_bool(item, "truncated", cut < len);
}

/* Direct messages from an allowlisted user only; everything else is dropped. */
static bool tg_inbox_wanted(const struct tg_config *cfg, const struct json_value *msg)
{
    const struct json_value *from = json_get(msg, "from");
    const char *type = json_get_str(json_get(json_get(msg, "chat"), "type"));
    return msg && from && !strcmp(type, "private") &&
           tg_allowed(cfg, json_get_int(json_get(from, "id")));
}

/* Offsets only move forward: an update needs an integer id of at least next_offset - 1
 * and below INT64_MAX, else it is skipped and counted as dropped. */
static bool tg_update_id(const struct tg_inbox *box, const struct json_value *update, int64_t *id)
{
    const struct json_value *v = json_get(update, "update_id");
    if (!v || v->type != JSON_INT)
        return false;
    *id = json_get_int(v);
    return *id < INT64_MAX && *id >= box->next_offset - 1;
}

static bool tg_inbox_take(struct tg_inbox *box, const struct tg_config *cfg,
                          const struct json_value *update)
{
    const struct json_value *msg = json_get(update, "message");
    int64_t update_id = 0;
    struct json_value item = {0};
    if (!tg_update_id(box, update, &update_id)) {
        box->dropped++;
        return true;
    }
    if (msg && tg_inbox_wanted(cfg, msg)) {
        if (box->bytes >= TG_INBOX_BUDGET && json_size(&box->list) > 0) {
            box->more = true;
            return false;
        }
        bool ok = tg_inbox_item(&item, update_id, msg, &box->bytes) && json_push_back(&box->list, &item);
        json_free(&item);
        if (!ok)
            return false;
    } else {
        box->dropped++;
    }
    box->next_offset = update_id + 1;
    return true;
}

static bool tg_inbox_emit(struct zcl_command_reply *reply, struct tg_inbox *box)
{
    json_set_object(&reply->data);
    return json_push_kv_str(&reply->data, "schema", "zcl.telegram.inbox.v1") &&
           json_push_kv_int(&reply->data, "count", (int64_t)json_size(&box->list)) &&
           json_push_kv_int(&reply->data, "dropped", box->dropped) &&
           json_push_kv_bool(&reply->data, "more", box->more) &&
           json_push_kv_int(&reply->data, "next_offset", box->next_offset) &&
           json_push_kv(&reply->data, "messages", &box->list);
}

static bool tg_inbox_request(char *body, size_t cap, int64_t offset, int64_t wait_s)
{
    struct json_value req = {0}, allowed = {0}, kind = {0};
    json_set_object(&req);
    json_set_array(&allowed);
    json_set_str(&kind, "message");
    bool ok = json_push_back(&allowed, &kind) && json_push_kv_int(&req, "offset", offset) &&
              json_push_kv_int(&req, "timeout", wait_s) && json_push_kv_int(&req, "limit", TG_INBOX_LIMIT) &&
              json_push_kv(&req, "allowed_updates", &allowed) && json_write(&req, body, cap) < cap;
    json_free(&req);
    json_free(&allowed);
    json_free(&kind);
    return ok;
}

static void tg_inbox_poll(struct zcl_command_reply *reply, const struct tg_config *cfg,
                          const char *dir, int64_t wait_s)
{
    char body[256];
    int64_t offset = 0;
    struct json_value doc;
    struct tg_inbox box = {0};
    if (!tg_offset_load(dir, cfg->token, &offset) || !tg_inbox_request(body, sizeof(body), offset, wait_s)) {
        tg_internal(reply, "state");
        return;
    }
    if (!tg_api(reply, cfg, "getUpdates", body, (int)wait_s + 15, "poll", &doc))
        return;
    const struct json_value *updates = json_get(&doc, "result");
    box.next_offset = offset;
    json_set_array(&box.list);
    for (size_t i = 0; updates && i < json_size(updates); i++) {
        if (!tg_inbox_take(&box, cfg, json_at(updates, i)))
            break;
    }
    json_free(&doc);
    if (box.next_offset != offset && !tg_offset_store(dir, cfg->token, box.next_offset))
        tg_internal(reply, "state");
    else if (!tg_inbox_emit(reply, &box))
        tg_internal(reply, "inbox");
    json_free(&box.list);
}

void zcl_native_handle_ops_telegram_inbox(const struct zcl_command_request *request,
                                          struct zcl_command_reply *reply)
{
    struct tg_config cfg;
    char dir[TG_PATH_MAX], lock_path[TG_PATH_MAX + 16];
    struct platform_process_lock lock;
    const struct json_value *wait = request && request->input ? json_get(request->input, "wait_s") : NULL;
    int64_t wait_s = wait && wait->type == JSON_INT ? json_get_int(wait) : 0;
    if (!reply || !tg_load(reply, &cfg))
        return;
    platform_process_lock_init(&lock);
    if (wait_s < 0 || wait_s > TG_WAIT_MAX)
        tg_fail(reply, ZCL_COMMAND_EXIT_INVALID, "TELEGRAM_BAD_WAIT", "normalize", false, false,
                "wait_s must be 0..50", "z23 telegram inbox --wait_s=30");
    else if (!cfg.has_chat && cfg.allow_count == 0)
        tg_fail(reply, ZCL_COMMAND_EXIT_BLOCKED, "TELEGRAM_NO_ALLOWLIST", "allowlist", false, false,
                "no TELEGRAM_CHAT_ID or TELEGRAM_ALLOW_FROM user is configured", "z23 telegram configure < telegram.env");
    else if (!tg_state_dir(dir, sizeof(dir)) || !tg_poll_lock_path(lock_path, sizeof(lock_path)))
        tg_internal(reply, "state");
    else if (!platform_process_lock_try_acquire(&lock, lock_path, true))
        tg_fail(reply, ZCL_COMMAND_EXIT_TRANSIENT, "POLL_LOCKED", "lock", true, false,
                "another process on this host is polling this bot", "wait for it to finish");
    else
        tg_inbox_poll(reply, &cfg, dir, wait_s);
    platform_process_lock_release(&lock);
    memory_cleanse(&cfg, sizeof(cfg));
}

/* ── configure ───────────────────────────────────────────────────────── */

#if !defined(_WIN32)
static bool tg_ensure_parent(const char *path)
{
    char dir[TG_PATH_MAX], *slash;
    snprintf(dir, sizeof(dir), "%s", path);
    slash = strrchr(dir, '/');
    if (!slash || slash == dir)
        return true;
    *slash = '\0';
    char *up = strrchr(dir, '/');
    if (up && up != dir) {
        *up = '\0';
        if (mkdir(dir, 0700) != 0 && errno != EEXIST)
            return false;
        *up = '/';
    }
    return mkdir(dir, 0700) == 0 || errno == EEXIST;
}

/* 1 when stdin was read, 0 for a terminal, -1 on error. */
static int tg_read_stdin(char *text, size_t cap)
{
    size_t used = 0;
    if (isatty(STDIN_FILENO))
        return 0;
    for (;;) {
        ssize_t n = used + 1 < cap ? read(STDIN_FILENO, text + used, cap - 1 - used) : 0;
        if (n < 0)
            return -1;
        if (n == 0)
            break;
        used += (size_t)n;
    }
    text[used] = '\0';
    return 1;
}
#else
static bool tg_ensure_parent(const char *path)
{
    (void)path;
    return false;
}

static int tg_read_stdin(char *text, size_t cap)
{
    (void)text;
    (void)cap;
    return -1;
}
#endif

void tg_configure_text(const char *text, struct zcl_command_reply *reply)
{
    struct tg_config cfg;
    char path[TG_PATH_MAX];
    if (!tg_parse_env(text, &cfg) || !cfg.has_chat) {
        tg_fail(reply, ZCL_COMMAND_EXIT_INVALID, "TELEGRAM_CREDENTIALS_INVALID", "normalize", false,
                false, "stdin must hold TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID, one per line",
                "z23 telegram configure < telegram.env");
        return;
    }
    if (!tg_credentials_path(path, sizeof(path)) || !tg_ensure_parent(path) ||
        !tg_atomic_write_private(path, text, strlen(text))) {
        tg_fail(reply, ZCL_COMMAND_EXIT_FAILED, "TELEGRAM_CONFIGURE_FAILED", "write", false, false,
                "the credentials file could not be written", "check that ~/.config/z23 is writable");
    } else {
        json_set_object(&reply->data);
        reply->error.mutated = true;
        if (!json_push_kv_str(&reply->data, "schema", "zcl.telegram.configure.v1") ||
            !json_push_kv_bool(&reply->data, "written", true) ||
            !json_push_kv_str(&reply->data, "mode", "0600") ||
            !json_push_kv_int(&reply->data, "allow_count", (int64_t)cfg.allow_count + 1))
            tg_internal(reply, "configure");
    }
    memory_cleanse(&cfg, sizeof(cfg));
}

void zcl_native_handle_ops_telegram_configure(const struct zcl_command_request *request,
                                              struct zcl_command_reply *reply)
{
    char text[4097];
    (void)request;
    if (!reply)
        return;
    int got = tg_read_stdin(text, sizeof(text));
    if (got == 1)
        tg_configure_text(text, reply);
    else if (got == 0)
        tg_fail(reply, ZCL_COMMAND_EXIT_INVALID, "TELEGRAM_CONFIGURE_NEEDS_STDIN", "normalize", false,
                false, "pipe the credentials in on stdin; they are never accepted as arguments",
                "z23 telegram configure < telegram.env");
    else
        tg_fail(reply, ZCL_COMMAND_EXIT_FAILED, "TELEGRAM_CONFIGURE_FAILED", "read", false, false,
                "stdin could not be read", "z23 telegram configure < telegram.env");
    memory_cleanse(text, sizeof(text));
}
