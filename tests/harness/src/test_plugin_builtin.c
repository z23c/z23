/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: prove the built-in one-shot plugins (interface 2) built from the
 * commons packages. Each binary under build/plugins/builtin/ (made by the
 * Makefile from contexts/commons/apps/) is packed, installed and switched
 * into an isolated store, then called through plugin.call with a fixed stdin;
 * the stdout must match exactly. A tampered executable is refused before it
 * runs. Every plugin is signed with a generated key under a temporary HOME;
 * the real ~/.z23 is never read. */

#include "test/test_core.h"

#include "command/native_command.h"
#include "json/json.h"
#include "plugin/plugin_store.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define PBI_DIR "build/plugins/builtin"

#if !defined(__linux__)
int test_plugin_builtin(void)
{
    printf("\n=== Built-in plugin tests ===\n");
    printf("  skipped: one-shot plugins run on Linux only\n");
    return 0;
}
#else

struct pbi_env {
    char base[PATH_MAX], home[PATH_MAX], root[PATH_MAX], dist[PATH_MAX];
    char old_home[PATH_MAX];
    char generation[PLUGIN_HEX_SHA3_512 + 1];
};

static bool pbi_call(void (*handler)(const struct zcl_command_request *, struct zcl_command_reply *),
                     const char *input_json, struct zcl_command_reply *reply)
{
    struct json_value input;
    json_init(&input);
    bool ok = json_read(&input, input_json, strlen(input_json));
    struct zcl_command_request request = { .input = &input, .view = "normal" };
    zcl_command_reply_init(reply, "zcl.plugin_test.v1");
    if (ok)
        handler(&request, reply);
    json_free(&input);
    return ok;
}

static bool pbi_join(char *out, size_t cap, const char *a, const char *b)
{
    int n = snprintf(out, cap, "%s/%s", a, b);
    return n > 0 && (size_t)n < cap;
}

static bool pbi_keys(const struct pbi_env *e, const char *public_key)
{
    char path[PATH_MAX];
    FILE *f = pbi_join(path, sizeof(path), e->root, "publisher_keys") ? fopen(path, "wb") : NULL;
    bool ok = f && fprintf(f, "%s\n", public_key) > 0;
    if (f)
        ok = fclose(f) == 0 && ok;
    return ok && chmod(path, 0600) == 0;
}

/* Temporary HOME with a store, a generated key, and the key listed. */
static bool pbi_env_open(struct pbi_env *e)
{
    char dot[PATH_MAX], key[PATH_MAX], in[2 * PATH_MAX], pub[65];
    struct zcl_command_reply r;
    const char *home = getenv("HOME");
    memset(e, 0, sizeof(*e));
    snprintf(e->old_home, sizeof(e->old_home), "%s", home ? home : "");
    if (!test_mkdtemp(e->base, sizeof(e->base), "plugin_builtin") ||
        !pbi_join(e->home, sizeof(e->home), e->base, "home") || mkdir(e->home, 0700) != 0 ||
        !pbi_join(dot, sizeof(dot), e->home, ".z23") || mkdir(dot, 0700) != 0 ||
        !pbi_join(e->root, sizeof(e->root), dot, "plugins") || mkdir(e->root, 0700) != 0 ||
        !pbi_join(e->dist, sizeof(e->dist), e->base, "dist") ||
        !pbi_join(key, sizeof(key), e->base, "publisher.key") || setenv("HOME", e->home, 1) != 0)
        return false;
    snprintf(in, sizeof(in), "{\"key\":\"%s\"}", key);
    if (!pbi_call(zcl_native_handle_plugin_keygen, in, &r))
        return false;
    snprintf(pub, sizeof(pub), "%s", r.exit_code == ZCL_COMMAND_EXIT_OK
                                         ? json_get_str(json_get(&r.data, "public_key")) : "");
    zcl_command_reply_free(&r);
    return pub[0] && pbi_keys(e, pub);
}

static void pbi_env_close(struct pbi_env *e)
{
    if (e->old_home[0])
        (void)setenv("HOME", e->old_home, 1);
    if (e->base[0])
        (void)test_rm_rf_recursive(e->base);
}

/* Pack the built binary of name at interface 2, install it and make it
 * current. The generation of the installed image is kept in e. */
static bool pbi_publish(struct pbi_env *e, const char *name)
{
    char in[4 * PATH_MAX], key[PATH_MAX], manifest[PATH_MAX];
    struct zcl_command_reply r;
    if (!pbi_join(key, sizeof(key), e->base, "publisher.key"))
        return false;
    snprintf(in, sizeof(in), "{\"exe\":\"%s/%s\",\"name\":\"%s\",\"version\":\"1.0.0\",\"key\":\"%s\","
             "\"dir\":\"%s\",\"interface\":2}", PBI_DIR, name, name, key, e->dist);
    if (!pbi_call(zcl_native_handle_plugin_pack, in, &r) || r.exit_code != ZCL_COMMAND_EXIT_OK)
        return false;
    snprintf(manifest, sizeof(manifest), "%s", json_get_str(json_get(&r.data, "manifest")));
    zcl_command_reply_free(&r);
    snprintf(in, sizeof(in), "{\"manifest\":\"%s\"}", manifest);
    if (!pbi_call(zcl_native_handle_plugin_install, in, &r) || r.exit_code != ZCL_COMMAND_EXIT_OK)
        return false;
    snprintf(e->generation, sizeof(e->generation), "%s", json_get_str(json_get(&r.data, "generation")));
    zcl_command_reply_free(&r);
    snprintf(in, sizeof(in), "{\"name\":\"%s\",\"generation\":\"%s\"}", name, e->generation);
    if (!pbi_call(zcl_native_handle_plugin_switch, in, &r))
        return false;
    bool ok = r.exit_code == ZCL_COMMAND_EXIT_OK;
    zcl_command_reply_free(&r);
    return ok;
}

/* Flip the last byte of the installed executable, which only the hash check
 * can notice, so a refusal proves the call stopped before it ran. */
static bool pbi_tamper(const struct pbi_env *e, const char *name)
{
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/%s/generations/%s/%s", e->root, name, e->generation, name);
    if (chmod(path, 0755) != 0)
        return false;
    FILE *f = fopen(path, "r+b");
    int c;
    bool ok = f && fseek(f, -1, SEEK_END) == 0 && (c = fgetc(f)) != EOF &&
              fseek(f, -1, SEEK_END) == 0 && fputc(c ^ 1, f) != EOF;
    if (f)
        ok = fclose(f) == 0 && ok;
    return ok;
}

static int pbi_case_outputs(void)
{
    int failures = 0;
    struct pbi_env e;
    bool ready = pbi_env_open(&e);
    TEST_CASE("zhexenc prints the lowercase hex of its stdin") {
        struct zcl_command_reply r;
        ASSERT(ready);
        ASSERT(pbi_publish(&e, "zhexenc"));
        ASSERT(pbi_call(zcl_native_handle_plugin_call, "{\"name\":\"zhexenc\",\"stdin\":\"abc\\n\"}", &r));
        ASSERT_EQ(r.exit_code, ZCL_COMMAND_EXIT_OK);
        const struct json_value *run = json_get(&r.data, "run");
        ASSERT_EQ(json_get_int(json_get(run, "exit_code")), 0);
        ASSERT_STR_EQ(json_get_str(json_get(run, "stdout")), "6162630a\n");
        ASSERT_STR_EQ(json_get_str(json_get(&r.data, "name")), "zhexenc");
        ASSERT_STR_EQ(json_get_str(json_get(&r.data, "version")), "1.0.0");
        zcl_command_reply_free(&r);
    } TEST_END
    pbi_env_close(&e);
    return failures;
}

static int pbi_case_crc(void)
{
    int failures = 0;
    struct pbi_env e;
    bool ready = pbi_env_open(&e);
    TEST_CASE("zcrc32 prints the CRC-32 of its stdin") {
        struct zcl_command_reply r;
        ASSERT(ready);
        ASSERT(pbi_publish(&e, "zcrc32"));
        ASSERT(pbi_call(zcl_native_handle_plugin_call, "{\"name\":\"zcrc32\",\"stdin\":\"123456789\"}", &r));
        ASSERT_EQ(r.exit_code, ZCL_COMMAND_EXIT_OK);
        const struct json_value *run = json_get(&r.data, "run");
        ASSERT_EQ(json_get_int(json_get(run, "exit_code")), 0);
        ASSERT_STR_EQ(json_get_str(json_get(run, "stdout")), "cbf43926\n");
        zcl_command_reply_free(&r);
    } TEST_END
    pbi_env_close(&e);
    return failures;
}

static int pbi_case_tamper(void)
{
    int failures = 0;
    struct pbi_env e;
    bool ready = pbi_env_open(&e);
    TEST_CASE("a tampered built-in plugin is refused before it runs") {
        struct zcl_command_reply r;
        ASSERT(ready);
        ASSERT(pbi_publish(&e, "zhexenc"));
        ASSERT(pbi_tamper(&e, "zhexenc"));
        ASSERT(pbi_call(zcl_native_handle_plugin_call, "{\"name\":\"zhexenc\",\"stdin\":\"abc\"}", &r));
        ASSERT_STR_EQ(r.error.code, "PLUGIN_EXE_HASH");
        ASSERT(json_get(&r.data, "run") == NULL);
        zcl_command_reply_free(&r);
    } TEST_END
    pbi_env_close(&e);
    return failures;
}

int test_plugin_builtin(void)
{
    int failures = 0;
    printf("\n=== Built-in plugin tests ===\n");
    failures += pbi_case_outputs();
    failures += pbi_case_crc();
    failures += pbi_case_tamper();
    return failures;
}
#endif
