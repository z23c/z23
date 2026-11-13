/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: durable batch retention and typed Telegram transport evidence. */
#include "contrib_inbox_telegram.h"
#include "platform/directory_transaction.h"
#include "json/json.h"
#include "base/hex.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>

enum { CI_TELEGRAM_BATCH_MAX = 1024 * 1024 };

bool ci_telegram_group_parse(const char *text, int64_t *group)
{
    if (!text || !group) return false;
    char *end, canonical[32];
    errno = 0;
    long long n = strtoll(text, &end, 10);
    int length = snprintf(canonical, sizeof canonical, "%lld", n);
    if (errno || end == text || *end || n >= 0 || length <= 0 ||
        (size_t)length >= sizeof canonical || strcmp(text, canonical)) return false;
    *group = (int64_t)n;
    return true;
}

static bool ci_tg_success(const char *wire, struct json_value *root)
{
    if (!wire || !json_read(root, wire, strlen(wire))) return false;
    const struct json_value *ok = json_get(root, "ok");
    return ok && ok->type == JSON_BOOL && json_get_bool(ok);
}

static bool ci_tg_integer_is(const struct json_value *data, const char *key, int64_t expected)
{
    const struct json_value *value = json_get(data, key);
    return value && value->type == JSON_INT && json_get_int(value) == expected;
}

bool ci_telegram_send_confirmed(const char *wire, int64_t group)
{
    struct json_value root = {0};
    bool ok = ci_tg_success(wire, &root);
    const struct json_value *data = json_get(&root, "data"), *ids = json_get(data, "message_ids");
    ok = ok && !strcmp(json_get_str(json_get(data, "schema")), "zcl.telegram.send.v1") &&
        ci_tg_integer_is(data, "chat_id", group) && ids && ids->type == JSON_ARR && json_size(ids) > 0;
    for (size_t i = 0; ok && i < json_size(ids); ++i) {
        const struct json_value *id = json_at(ids, i);
        ok = id && id->type == JSON_INT && json_get_int(id) > 0;
    }
    json_free(&root);
    return ok;
}

bool ci_telegram_ack_confirmed(const char *wire, int64_t bot, int64_t next)
{
    struct json_value root = {0};
    bool ok = ci_tg_success(wire, &root);
    const struct json_value *data = json_get(&root, "data");
    ok = ok && !strcmp(json_get_str(json_get(data, "schema")), "zcl.telegram.inbox.v1") &&
        ci_tg_integer_is(data, "bot_id", bot) && ci_tg_integer_is(data, "count", 0) &&
        ci_tg_integer_is(data, "next_offset", next);
    json_free(&root);
    return ok;
}

bool ci_telegram_prepare_state(const char *state)
{
    char parent[4096];
    if (!state || strlen(state) >= sizeof parent) return false;
    memcpy(parent, state, strlen(state) + 1);
    char *leaf = strrchr(parent, '/');
    if (!leaf || leaf == parent || !leaf[1]) return false;
    *leaf++ = 0;
    struct platform_directory_transaction dir;
    platform_directory_transaction_init(&dir);
    bool ok = platform_directory_transaction_bootstrap_child(parent, leaf, true, &dir) == PLATFORM_DIRECTORY_OK;
    platform_directory_transaction_close(&dir);
    return ok;
}

static bool ci_tg_unchanged(const struct platform_directory_child_info *a,
                            const struct platform_directory_child_info *b)
{
    return a->current_user_only && b->current_user_only &&
        a->link_count == 1 && b->link_count == 1 && a->size == b->size &&
        a->volume == b->volume && a->file_low == b->file_low && a->file_high == b->file_high &&
        a->modified_seconds == b->modified_seconds && a->modified_nanoseconds == b->modified_nanoseconds &&
        a->changed_seconds == b->changed_seconds && a->changed_nanoseconds == b->changed_nanoseconds;
}

/* Re-read exactly, and reject an object changed during comparison. */
static bool ci_tg_matches(struct platform_directory_child *file,
                          const char *wire, size_t length)
{
    struct platform_directory_child_info before, after;
    if (!platform_directory_child_info(file, &before) || !before.current_user_only ||
        before.link_count != 1 || before.size != length) return false;
    unsigned char buf[4096];
    for (size_t at = 0; at < length;) {
        size_t n = length - at < sizeof buf ? length - at : sizeof buf;
        if (!platform_directory_child_read_exact(file, buf, n, at) ||
            memcmp(buf, wire + at, n) != 0) return false;
        at += n;
    }
    return platform_directory_child_info(file, &after) && ci_tg_unchanged(&before, &after);
}

/* A replay is acknowledged only after a fresh content and durability check. */
static bool ci_tg_verify(struct platform_directory_transaction *dir,
                         struct platform_directory_child *file,
                         const char *wire, size_t length)
{
    return ci_tg_matches(file, wire, length) && platform_directory_child_flush(file) &&
           platform_directory_transaction_flush(dir);
}

static bool ci_tg_existing(struct platform_directory_transaction *dir,
                           const char *wire, size_t length)
{
    struct platform_directory_child file;
    platform_directory_child_init(&file);
    bool ok = platform_directory_child_open(dir, "inbox.json", &file) &&
        ci_tg_verify(dir, &file, wire, length);
    platform_directory_child_close(&file);
    return ok;
}

static bool ci_tg_stage(struct platform_directory_transaction *dir,
                        const char *wire, size_t length)
{
    char leaf[64];
    int n = snprintf(leaf, sizeof leaf, ".inbox.%ld.tmp", (long)getpid());
    if (n <= 0 || (size_t)n >= sizeof leaf) return false;
    struct platform_directory_child stage;
    platform_directory_child_init(&stage);
    bool created = false;
    enum platform_directory_result opened = platform_directory_child_open_result(
        dir, leaf, true, true, &stage, &created);
    bool ok = opened == PLATFORM_DIRECTORY_OK;
    if (ok && created) ok = platform_directory_child_write_exact(&stage, wire, length, 0);
    if (ok) ok = ci_tg_matches(&stage, wire, length);
    enum platform_directory_result moved = PLATFORM_DIRECTORY_INVALID;
    if (ok) moved = platform_directory_child_move_between(dir, &stage, dir, "inbox.json", true);
    platform_directory_child_close(&stage);
    if (moved == PLATFORM_DIRECTORY_EXISTS) return ci_tg_existing(dir, wire, length);
    /* OUTCOME_UNKNOWN and all other failures leave names for reconciliation. */
    return moved == PLATFORM_DIRECTORY_OK;
}

static bool ci_tg_retain_dir(struct platform_directory_transaction *dir,
                             const char *wire, size_t length)
{
    struct platform_directory_child existing;
    platform_directory_child_init(&existing);
    enum platform_directory_result found = platform_directory_child_open_result(
        dir, "inbox.json", false, false, &existing, NULL);
    bool ok = false;
    if (found == PLATFORM_DIRECTORY_OK) ok = ci_tg_verify(dir, &existing, wire, length);
    platform_directory_child_close(&existing);
    if (found == PLATFORM_DIRECTORY_MISSING) ok = ci_tg_stage(dir, wire, length);
    return ok;
}

bool ci_telegram_retain(const char *state, const char *receipt,
                        const char *wire, size_t length)
{
    uint8_t receipt_bytes[32];
    if (!state || !state[0] || !wire || !length || length > CI_TELEGRAM_BATCH_MAX ||
        !zcl_hex_decode_lower(receipt, receipt_bytes, sizeof receipt_bytes)) return false;
    char batch[80];
    int n = snprintf(batch, sizeof batch, "tg-batch-%s", receipt);
    if (n <= 0 || (size_t)n >= sizeof batch) return false;
    struct platform_directory_transaction root, units, dir;
    platform_directory_transaction_init(&root);
    platform_directory_transaction_init(&units);
    platform_directory_transaction_init(&dir);
    bool ok = platform_directory_transaction_open(&root, state) &&
        platform_directory_transaction_open_child(&root, "units", true, &units) == PLATFORM_DIRECTORY_OK &&
        platform_directory_transaction_flush(&root) &&
        platform_directory_transaction_open_child(&units, batch, true, &dir) == PLATFORM_DIRECTORY_OK &&
        platform_directory_transaction_flush(&units);
    if (ok) ok = ci_tg_retain_dir(&dir, wire, length);
    platform_directory_transaction_close(&dir);
    platform_directory_transaction_close(&units);
    platform_directory_transaction_close(&root);
    return ok;
}
