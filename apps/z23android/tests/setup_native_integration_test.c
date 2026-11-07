/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#define _GNU_SOURCE
#include "setup_node.h"
#include "operations.h"
#include "base/cleanse.h"
#include "json/json.h"
#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define TEST_PASS "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

static bool run_setup(void *ctx, const char *op, const char *input, unsigned timeout,
                      char *out, size_t cap)
{
    return zapp_wallet_setup_run(ctx, op, input, timeout, out, cap);
}

static void init_runtime(struct zapp_runtime *r, const char *root, const char *binary)
{
    memset(r, 0, sizeof(*r));
    assert(pthread_mutex_init(&r->mutex, NULL) == 0);
    zapp_nodelog_init(&r->log, NULL, NULL);
    assert(snprintf(r->executable, sizeof(r->executable), "%s", binary) < (int)sizeof(r->executable));
    assert(snprintf(r->files, sizeof(r->files), "%s", root) < (int)sizeof(r->files));
    assert(snprintf(r->directory, sizeof(r->directory), "%s/node", root) < (int)sizeof(r->directory));
    assert(snprintf(r->state_root, sizeof(r->state_root), "%s/state", root) < (int)sizeof(r->state_root));
    assert(snprintf(r->temporary_root, sizeof(r->temporary_root), "%s/tmp", root) < (int)sizeof(r->temporary_root));
    assert(mkdir(r->directory, 0700) == 0 && mkdir(r->state_root, 0700) == 0 && mkdir(r->temporary_root, 0700) == 0);
}

static bool reply_error_code(const char *output, const char *expected)
{
    unsigned matches = 0;
    bool locked = false;
    for (const char *line = output; line; line = strchr(line, 10), line = line ? line + 1 : NULL) {
        struct json_value result = {0};
        if (*line != 123) continue;
        if (!json_read(&result, line, strcspn(line, "\n"))) {
            json_cleanse_strings(&result); json_free(&result); continue;
        }
        const struct json_value *ok = json_get(&result, "ok");
        if (ok && ok->type == JSON_BOOL) {
            const struct json_value *code = json_get(json_get(&result, "error"), "code");
            locked = !json_get_bool(ok) && code && code->type == JSON_STR && json_get_str(code)[0] &&
                     (!expected || !strcmp(json_get_str(code), expected));
            ++matches;
        }
        json_cleanse_strings(&result); json_free(&result);
    }
    return matches == 1 && locked;
}

static bool locked_status_is_safe(struct sun *node, struct zapp_runtime *r,
                                  const struct zapp_words *words)
{
    char input[1400], output[SUN_REPLY_MAX], phrase[ZAPP_WORDS_MAX * (ZAPP_WORD_LETTERS + 1)];
    struct json_value request = {0};
    json_set_object(&request);
    bool ok = json_push_kv_str(&request, "datadir", node->datadir) &&
        json_write(&request, input, sizeof(input)) > 0 && zapp_words_join(words, phrase, sizeof(phrase));
    json_free(&request);
    if (!ok) return false;
    output[0] = 0;
    (void)zapp_wallet_setup_run(r, "status", input, SUN_QUERY_TIMEOUT_MS, output, sizeof(output));
    ok = reply_error_code(output, "WALLET_LOCKED") && !strstr(output, phrase) && !strstr(output, TEST_PASS);
    memory_cleanse(phrase, sizeof(phrase)); memory_cleanse(input, sizeof(input)); memory_cleanse(output, sizeof(output));
    return ok;
}

static bool malformed_nonce_refused(struct sun *node, struct zapp_runtime *r,
                                    const struct zapp_words *words)
{
    char input[SUN_INPUT_MAX], output[SUN_REPLY_MAX], phrase[ZAPP_WORDS_MAX * (ZAPP_WORD_LETTERS + 1)];
    struct json_value doc = {0};
    if (!zapp_words_join(words, phrase, sizeof(phrase))) return false;
    json_set_object(&doc);
    bool built = json_push_kv_str(&doc, "datadir", node->datadir) &&
        json_push_kv_str(&doc, "passphrase", TEST_PASS) && json_push_kv_str(&doc, "phrase", phrase) &&
        json_push_kv_bool(&doc, "confirm", true) && json_push_kv_bool(&doc, "shielded_only", true) &&
        json_push_kv_str(&doc, "creation_nonce", "bad");
    size_t length = built ? json_write(&doc, input, sizeof(input)) : 0;
    json_cleanse_strings(&doc); json_free(&doc);
    bool ok = length > 0 && length < sizeof(input);
    output[0] = 0;
    if (ok) (void)zapp_wallet_setup_run(r, "restore", input, SUN_RESTORE_TIMEOUT_MS, output, sizeof(output));
    ok = ok && reply_error_code(output, NULL) && !strstr(output, phrase) && !strstr(output, TEST_PASS);
    memory_cleanse(phrase, sizeof(phrase)); memory_cleanse(input, sizeof(input)); memory_cleanse(output, sizeof(output));
    return ok;
}

static bool response_error_mutated(const char *output)
{
    unsigned matches = 0; bool refused = false;
    for (const char *line = output; line; line = strchr(line, 10), line = line ? line + 1 : NULL) {
        struct json_value result = {0};
        if (*line != 123) continue;
        if (!json_read(&result, line, strcspn(line, "\n"))) {
            json_cleanse_strings(&result); json_free(&result); continue;
        }
        const struct json_value *ok = json_get(&result, "ok");
        if (ok && ok->type == JSON_BOOL) {
            const struct json_value *mutated = json_get(json_get(&result, "error"), "mutated");
            refused = !json_get_bool(ok) && mutated && mutated->type == JSON_BOOL && json_get_bool(mutated);
            ++matches;
        }
        json_cleanse_strings(&result); json_free(&result);
    }
    return matches == 1 && refused;
}

static bool second_prepare_refused(struct sun *node, struct zapp_runtime *r)
{
    char input[SUN_INPUT_MAX], output[SUN_REPLY_MAX]; struct json_value doc = {0};
    json_set_object(&doc);
    bool built = json_push_kv_str(&doc, "datadir", node->datadir) && json_push_kv_bool(&doc, "prepare", true);
    size_t length = built ? json_write(&doc, input, sizeof(input)) : 0;
    json_free(&doc); output[0] = 0;
    if (length == 0 || length >= sizeof(input)) return false;
    (void)zapp_wallet_setup_run(r, "create", input, SUN_CREATE_TIMEOUT_MS, output, sizeof(output));
    bool refused = response_error_mutated(output);
    memory_cleanse(input, sizeof(input)); memory_cleanse(output, sizeof(output));
    return refused;
}

static bool wrong_cancel_refused(struct sun *node, struct zapp_runtime *r, const char *nonce)
{
    char input[SUN_INPUT_MAX], output[SUN_REPLY_MAX]; struct json_value doc = {0};
    json_set_object(&doc);
    bool built = json_push_kv_str(&doc, "datadir", node->datadir) &&
        json_push_kv_str(&doc, "cancel_nonce", nonce) && json_push_kv_bool(&doc, "confirm", true);
    size_t length = built ? json_write(&doc, input, sizeof(input)) : 0;
    json_free(&doc); output[0] = 0;
    if (length == 0 || length >= sizeof(input)) return false;
    (void)zapp_wallet_setup_run(r, "create", input, SUN_CREATE_TIMEOUT_MS, output, sizeof(output));
    bool refused = response_error_mutated(output);
    memory_cleanse(input, sizeof(input)); memory_cleanse(output, sizeof(output));
    return refused;
}

static void run_flow(struct sun *node, struct zapp_runtime *runtime)
{
    struct zapp_words words = {0}; struct sun_restored first = {0}, retry = {0};
    char nonce[65], current[65], wrong[65];
    assert(sun_prepare_creation(node, &words, nonce) == SUN_OK);
    assert(sun_creation_status(node, current) == SUN_CREATION_PREPARED && !strcmp(nonce, current));
    assert(second_prepare_refused(node, runtime));
    assert(sun_creation_status(node, current) == SUN_CREATION_PREPARED && !strcmp(nonce, current));
    memcpy(wrong, nonce, sizeof(wrong)); wrong[0] = wrong[0] == '0' ? '1' : '0';
    assert(wrong_cancel_refused(node, runtime, wrong));
    assert(sun_creation_status(node, current) == SUN_CREATION_PREPARED && !strcmp(nonce, current));
    assert(sun_commit_creation(node, &words, TEST_PASS, wrong, &retry) != SUN_OK);
    assert(malformed_nonce_refused(node, runtime, &words));
    assert(sun_creation_status(node, current) == SUN_CREATION_PREPARED && !strcmp(nonce, current));
    assert(sun_commit_creation(node, &words, TEST_PASS, nonce, &first) == SUN_OK);
    assert(locked_status_is_safe(node, runtime, &words));
    assert(sun_creation_status(node, current) == SUN_CREATION_COMMITTED && !strcmp(nonce, current));
    assert(sun_commit_creation(node, &words, TEST_PASS, nonce, &retry) == SUN_OK);
    assert(!strcmp(first.first_shielded_address, retry.first_shielded_address));
    assert(first.birthday_recorded == retry.birthday_recorded && first.birthday_rejected == retry.birthday_rejected);
    assert(sun_commit_creation(node, &words, TEST_PASS, "bad", &retry) == SUN_REFUSED);
    assert(sun_creation_status(node, current) == SUN_CREATION_COMMITTED && !strcmp(nonce, current));
    zapp_words_cleanse(&words); memory_cleanse(&first, sizeof(first)); memory_cleanse(&retry, sizeof(retry));
}

int main(int argc, char **argv)
{
    assert(argc == 3 && argv[1][0] == '/' && argv[2][0] == '/');
    struct zapp_runtime runtime; init_runtime(&runtime, argv[1], argv[2]);
    struct sun_runner runner = {&runtime, run_setup}; struct sun node;
    sun_init(&node, &runner, runtime.directory);
    run_flow(&node, &runtime);
    pthread_mutex_destroy(&runtime.mutex);
    puts("setup native integration: ok");
    return 0;
}
