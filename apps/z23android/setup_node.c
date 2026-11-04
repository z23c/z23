/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "setup_node.h"
#include "base/cleanse.h"
#include "json/json.h"
#include <stdio.h>
#include <string.h>

void sun_init(struct sun *node, const struct sun_runner *runner, const char *datadir)
{
    memset(node, 0, sizeof(*node));
    node->runner = *runner;
    snprintf(node->datadir, sizeof(node->datadir), "%s", datadir ? datadir : "");
}

/* The parsed reply of a command: {"ok":true,"data":{...}} or {"ok":false,"error":{"code":...}}. The node's log lines share the
 * stream, so the reply is the one line that starts an object and reads as a whole object with an "ok" flag, alone or with
 * everything after it. Two such lines, or none, are no reply: a stray object must neither stand in for the reply nor hide it,
 * and a result that cannot be read leaves the wallet unknown, never absent. */
struct reply {
    struct json_value root;
    bool parsed;
    bool ok;
    const struct json_value *data;
    const char *code;
};
/* Reads the object that starts at line into root; false, with root empty, when it is not a whole object with an "ok" flag. */
static bool reply_object(struct json_value *root, const char *line)
{
    size_t rest = strlen(line), own = strcspn(line, "\n");
    if (!json_read(root, line, rest) && !json_read(root, line, own)) return false;
    const struct json_value *ok = json_get(root, "ok");
    if (ok && ok->type == JSON_BOOL) return true;
    json_cleanse_strings(root);
    json_free(root);
    return false;
}
static void reply_read(struct reply *r, const char *text)
{
    memset(r, 0, sizeof(*r));
    unsigned found = 0;
    for (const char *line = text; line; line = strchr(line, '\n'), line = line ? line + 1 : NULL) {
        struct json_value root;
        if (line[0] != '{' || !reply_object(&root, line)) continue;
        if (found++ == 0) {
            r->root = root;
        } else {
            json_cleanse_strings(&root);
            json_free(&root);
        }
    }
    if (found != 1) {
        if (found) { json_cleanse_strings(&r->root); json_free(&r->root); }
        memset(r, 0, sizeof(*r));
        return;
    }
    r->parsed = true;
    r->ok = json_get_bool(json_get(&r->root, "ok"));
    r->data = json_get(&r->root, "data");
    const struct json_value *code = json_get(json_get(&r->root, "error"), "code");
    r->code = code && code->type == JSON_STR ? json_get_str(code) : NULL;
}
static void reply_free(struct reply *r)
{
    json_cleanse_strings(&r->root);
    json_free(&r->root);
    memset(r, 0, sizeof(*r));
}
static const char *text_of(const struct json_value *obj, const char *key)
{
    const struct json_value *v = json_get(obj, key);
    return v && v->type == JSON_STR ? json_get_str(v) : NULL;
}
static bool flag_of(const struct json_value *obj, const char *key)
{
    const struct json_value *v = json_get(obj, key);
    return v && v->type == JSON_BOOL && json_get_bool(v);
}
static bool hex_hash(const char *text)
{
    size_t n = 0;
    for (; text && text[n]; ++n)
        if (!((text[n] >= '0' && text[n] <= '9') || (text[n] >= 'a' && text[n] <= 'f'))) return false;
    return n == SUN_HASH_HEX;
}

/* ---- requests ---- */

static bool passphrase_valid(const char *p)
{
    size_t n = 0;
    for (; p && p[n]; ++n)
        if (!((p[n] >= '0' && p[n] <= '9') || (p[n] >= 'a' && p[n] <= 'f'))) return false;
    return n == SUN_PASSPHRASE_HEX;
}
/* The request object of both commands: the datadir and the passphrase. */
static bool request_base(struct json_value *doc, const struct sun *node, const char *passphrase)
{
    json_set_object(doc);
    return json_push_kv_str(doc, "datadir", node->datadir) && json_push_kv_str(doc, "passphrase", passphrase);
}
static void doc_wipe(struct json_value *doc)
{
    json_cleanse_strings(doc);
    json_free(doc);
}
static bool push_birthday(struct json_value *doc, const struct sun_birthday *b)
{
    struct json_value object = {0};
    json_set_object(&object);
    bool ok = json_push_kv_int(&object, "height", b->height) && json_push_kv_str(&object, "hash", b->hash) &&
              json_push_kv(doc, "birthday", &object);
    json_free(&object);
    return ok;
}
static bool write_request(struct json_value *doc, char *out, size_t cap)
{
    size_t n = json_write(doc, out, cap);
    doc_wipe(doc);
    return n > 0 && n < cap;
}

/* ---- replies ---- */

static enum sun_result result_of(const struct reply *r)
{
    static const struct { const char *code; enum sun_result result; } table[] = {
        {"DATADIR_LOCKED", SUN_NODE_RUNNING}, {"WALLET_ALREADY_PRESENT", SUN_ALREADY_PRESENT},
        {"INVALID_PHRASE", SUN_INVALID_PHRASE}, {"NODE_DB_UNREADABLE", SUN_STORAGE},
        {"PASSPHRASE_TOO_SHORT", SUN_REFUSED}, {"MISSING_PHRASE", SUN_REFUSED}, {"MISSING_DATADIR", SUN_REFUSED},
        {"BIRTHDAY_CONFLICT", SUN_REFUSED}, {"NOT_RUN", SUN_NOT_RUN}, {"BAD_BIRTHDAY", SUN_REFUSED}, {"STDIN_REQUIRED", SUN_REFUSED}, {"WALLET_AT_REST_UNDECIDED", SUN_REFUSED},
    };
    if (!r->parsed || r->ok || !r->code) return SUN_UNKNOWN;
    for (size_t i = 0; i < sizeof(table) / sizeof(table[0]); ++i)
        if (!strcmp(r->code, table[i].code)) return table[i].result;
    return SUN_UNKNOWN;
}
static void read_birthday(const struct json_value *data, struct sun_birthday *out)
{
    const struct json_value *h = json_get(data, "birthday_height");
    const char *hash = text_of(data, "birthday_hash");
    memset(out, 0, sizeof(*out));
    if (!flag_of(data, "birthday_recorded") || !h || h->type != JSON_INT || json_get_int(h) <= 0 || !hex_hash(hash)) return;
    out->known = true;
    out->height = json_get_int(h);
    memcpy(out->hash, hash, SUN_HASH_HEX + 1);
}
/* A created wallet whose phrase cannot be read is unknown: it may exist and its words cannot be shown again. */
static enum sun_result created_from(const struct reply *r, struct sun_created *out)
{
    if (!r->parsed || !r->ok || !r->data) return result_of(r);
    if (!zapp_words_parse(text_of(r->data, "phrase"), &out->words)) return SUN_UNKNOWN;
    read_birthday(r->data, &out->birthday);
    return SUN_OK;
}

enum sun_result sun_create(const struct sun *node, const char *passphrase, struct sun_created *out)
{
    char input[SUN_INPUT_MAX], text[SUN_REPLY_MAX];
    struct json_value doc = {0};
    struct reply r;
    memset(out, 0, sizeof(*out));
    if (!passphrase_valid(passphrase) || !node->datadir[0]) return SUN_REFUSED;
    bool built = request_base(&doc, node, passphrase);
    if (!built) doc_wipe(&doc);
    if (!built || !write_request(&doc, input, sizeof(input))) { memory_cleanse(input, sizeof(input)); return SUN_REFUSED; }
    text[0] = 0;
    (void)node->runner.run(node->runner.ctx, "create", input, SUN_CREATE_TIMEOUT_MS, text, sizeof(text));
    memory_cleanse(input, sizeof(input));
    reply_read(&r, text);
    enum sun_result result = created_from(&r, out);
    if (result != SUN_OK) memory_cleanse(out, sizeof(*out));
    reply_free(&r);
    memory_cleanse(text, sizeof(text));
    return result;
}

static bool restore_request(const struct sun *node, const struct zapp_words *words, const char *passphrase,
                            const struct sun_birthday *birthday, bool at_tip, char *input, size_t cap)
{
    char phrase[ZAPP_WORDS_MAX * (ZAPP_WORD_LETTERS + 1)];
    struct json_value doc = {0};
    if (!zapp_words_join(words, phrase, sizeof(phrase))) return false;
    bool ok = request_base(&doc, node, passphrase) && json_push_kv_str(&doc, "phrase", phrase) &&
              json_push_kv_bool(&doc, "confirm", true) && json_push_kv_bool(&doc, "shielded_only", true) &&
              (!birthday || !birthday->known || push_birthday(&doc, birthday)) &&
              (!at_tip || json_push_kv_bool(&doc, "birthday_at_local_tip", true));
    memory_cleanse(phrase, sizeof(phrase));
    if (!ok) { doc_wipe(&doc); return false; }
    return write_request(&doc, input, cap);
}

static enum sun_result restore_call(const struct sun *node, const struct zapp_words *words, const char *passphrase,
                                     const struct sun_birthday *birthday, bool at_tip, struct sun_restored *out)
{
    char input[SUN_INPUT_MAX], text[SUN_REPLY_MAX];
    struct reply r;
    memset(out, 0, sizeof(*out));
    if (!passphrase_valid(passphrase) || !node->datadir[0]) return SUN_REFUSED;
    if (!restore_request(node, words, passphrase, birthday, at_tip, input, sizeof(input))) { memory_cleanse(input, sizeof(input)); return SUN_REFUSED; }
    text[0] = 0;
    (void)node->runner.run(node->runner.ctx, "restore", input, SUN_RESTORE_TIMEOUT_MS, text, sizeof(text));
    memory_cleanse(input, sizeof(input));
    reply_read(&r, text);
    enum sun_result result = r.parsed && r.ok && r.data && flag_of(r.data, "recovered") ? SUN_OK : result_of(&r);
    if (result == SUN_OK) {
        out->birthday_recorded = flag_of(r.data, "birthday_recorded");
        out->birthday_rejected = flag_of(r.data, "birthday_rejected");
    }
    reply_free(&r);
    memory_cleanse(text, sizeof(text));
    return result;
}

enum sun_result sun_restore(const struct sun *node, const struct zapp_words *words, const char *passphrase,
                            const struct sun_birthday *birthday, struct sun_restored *out)
{
    return restore_call(node, words, passphrase, birthday, false, out);
}
enum sun_result sun_restore_at_tip(const struct sun *node, const struct zapp_words *words, const char *passphrase, struct sun_restored *out)
{
    return restore_call(node, words, passphrase, NULL, true, out);
}

enum sun_result sun_new_phrase(const struct sun *node, struct zapp_words *out)
{
    char text[SUN_REPLY_MAX];
    struct reply r;
    memset(out, 0, sizeof(*out));
    text[0] = 0;
    (void)node->runner.run(node->runner.ctx, "newphrase", "{}", SUN_QUERY_TIMEOUT_MS, text, sizeof(text));
    reply_read(&r, text);
    bool made = r.parsed && r.ok && r.data && zapp_words_parse(text_of(r.data, "phrase"), out);
    enum sun_result result = made ? SUN_OK : r.parsed && !r.ok ? result_of(&r) : SUN_NOT_RUN;
    if (result != SUN_OK) memory_cleanse(out, sizeof(*out));
    reply_free(&r);
    memory_cleanse(text, sizeof(text));
    return result;
}

bool sun_block_hash(const struct sun *node, int64_t height, char hash[SUN_HASH_HEX + 1])
{
    char params[48], text[SUN_REPLY_MAX];
    struct json_value root = {0};
    hash[0] = 0;
    if (height <= 0 || snprintf(params, sizeof(params), "[%lld]", (long long)height) >= (int)sizeof(params)) return false;
    text[0] = 0;
    bool ran = node->runner.run(node->runner.ctx, "blockhash", params, SUN_QUERY_TIMEOUT_MS, text, sizeof(text));
    const char *result = NULL;
    if (ran && json_read(&root, text, strlen(text))) result = text_of(&root, "result");
    bool ok = hex_hash(result);
    if (ok) memcpy(hash, result, SUN_HASH_HEX + 1);
    json_free(&root);
    return ok;
}

bool sun_chain_tip(const struct sun *node, int64_t *headers, int64_t *blocks)
{
    char text[SUN_REPLY_MAX];
    struct json_value root = {0};
    *headers = *blocks = 0;
    text[0] = 0;
    bool ran = node->runner.run(node->runner.ctx, "chaininfo", "[]", SUN_QUERY_TIMEOUT_MS, text, sizeof(text));
    const struct json_value *result = ran && json_read(&root, text, strlen(text)) ? json_get(&root, "result") : NULL;
    const struct json_value *h = json_get(result, "headers"), *b = json_get(result, "blocks");
    bool ok = h && b && h->type == JSON_INT && b->type == JSON_INT;
    if (ok) { *headers = json_get_int(h); *blocks = json_get_int(b); }
    json_free(&root);
    return ok;
}

/* What an ok reply of `core wallet recovery status` says (contexts/wallet/controllers/src/wallet_recovery_native_handlers.c:109-112
 * and :249, at commit 5822e3f535): wallet_already_present is keys_before > 0 or a seed row; seed_state is "none" only when the wallet database holds no
 * seed. Only an empty database with no keys is "no wallet". */
static enum sun_probe probe_of_ok(const struct json_value *data)
{
    const struct json_value *state = json_get(data, "seed_state"), *keys = json_get(data, "keys_before"), *present = json_get(data, "wallet_already_present");
    if (!present || present->type != JSON_BOOL) return SUN_PROBE_UNKNOWN;
    if (json_get_bool(present)) return SUN_PROBE_PRESENT;
    bool empty = state && state->type == JSON_STR && !strcmp(json_get_str(state), "none") && keys && keys->type == JSON_INT && json_get_int(keys) == 0;
    return empty ? SUN_PROBE_NONE : SUN_PROBE_UNKNOWN;
}

/* The read-only status of the wallet at the datadir; the node must not hold it (DATADIR_LOCKED). On a failed reply NO_NODE_DB is
 * the only "no wallet" (handler :220); NO_WALLET means the wallet could not be read (:241) and is not an answer. WALLET_LOCKED (:272)
 * and WALLET_SEED_UNUSABLE (:287) mean a seed exists. */
enum sun_probe sun_wallet_probe(const struct sun *node)
{
    static const struct { const char *code; enum sun_probe probe; } table[] = {
        {"WALLET_LOCKED", SUN_PROBE_PRESENT}, {"WALLET_SEED_UNUSABLE", SUN_PROBE_PRESENT}, {"NO_NODE_DB", SUN_PROBE_NONE},
    };
    char input[SUN_INPUT_MAX], text[SUN_REPLY_MAX];
    struct json_value doc = {0};
    struct reply r;
    enum sun_probe probe = SUN_PROBE_UNKNOWN;
    json_set_object(&doc);
    bool built = json_push_kv_str(&doc, "datadir", node->datadir);
    size_t n = built ? json_write(&doc, input, sizeof(input)) : 0;
    json_free(&doc);
    if (!built || n == 0 || n >= sizeof(input)) return SUN_PROBE_UNKNOWN;
    text[0] = 0;
    (void)node->runner.run(node->runner.ctx, "status", input, SUN_QUERY_TIMEOUT_MS, text, sizeof(text));
    reply_read(&r, text);
    if (r.parsed && r.ok) probe = probe_of_ok(r.data);
    for (size_t i = 0; r.parsed && !r.ok && r.code && i < sizeof(table) / sizeof(table[0]); ++i)
        if (!strcmp(r.code, table[i].code)) probe = table[i].probe;
    reply_free(&r);
    return probe;
}
