/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: prove one-shot plugins (interface 2): pack, install and switch
 * accept interface 2, plugin.call runs the verified executable once through
 * the lab's confined runner and returns its stdout and exit status, a
 * tampered executable is refused before it runs, and plugin.run and
 * plugin.call each refuse the other's interface; plugin.publisher creates the store,
 * appends once, refuses malformed keys and insecure directories, and runs the
 * keygen to call chain. Every plugin is signed with a
 * generated key under a temporary HOME; the real ~/.z23 is never read. */

#include "test/test_core.h"

#include "command/native_command.h"
#include "json/json.h"
#include "plugin/plugin_store.h"

#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define PCT_FIXTURE "build/fixtures/plugin_call_upper"

#if !defined(__linux__)
int test_plugin_call(void)
{
    int failures = 0;
    printf("\n=== Plugin call tests ===\n");
    TEST_CASE("plugin.call refuses by name off Linux") {
        struct zcl_command_reply r;
        struct json_value in;
        json_init(&in);
        ASSERT(json_read(&in, "{\"name\":\"upper\"}", 16));
        struct zcl_command_request request = { .input = &in, .view = "normal" };
        zcl_command_reply_init(&r, "zcl.plugin_test.v1");
        zcl_native_handle_plugin_call(&request, &r);
        ASSERT_STR_EQ(r.error.code, "PLUGIN_RUN_PLATFORM");
        zcl_command_reply_free(&r);
        json_free(&in);
    } TEST_END
    return failures;
}
#else

struct pct_env {
    char base[PATH_MAX], home[PATH_MAX], root[PATH_MAX], dist[PATH_MAX];
    char old_home[PATH_MAX];
    char generation[PLUGIN_HEX_SHA3_512 + 1];
};

static bool pct_call(void (*handler)(const struct zcl_command_request *, struct zcl_command_reply *),
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

static bool pct_join(char *out, size_t cap, const char *a, const char *b)
{
    int n = snprintf(out, cap, "%s/%s", a, b);
    return n > 0 && (size_t)n < cap;
}

static bool pct_keys(const struct pct_env *e, const char *public_key)
{
    char path[PATH_MAX];
    FILE *f = pct_join(path, sizeof(path), e->root, "publisher_keys") ? fopen(path, "wb") : NULL;
    bool ok = f && fprintf(f, "%s\n", public_key) > 0;
    if (f)
        ok = fclose(f) == 0 && ok;
    return ok && chmod(path, 0600) == 0;
}

/* Temporary HOME with a store, a generated key, and the key listed. */
static bool pct_env_open(struct pct_env *e)
{
    char dot[PATH_MAX], key[PATH_MAX], in[2 * PATH_MAX], pub[65];
    struct zcl_command_reply r;
    const char *home = getenv("HOME");
    memset(e, 0, sizeof(*e));
    snprintf(e->old_home, sizeof(e->old_home), "%s", home ? home : "");
    if (!test_mkdtemp(e->base, sizeof(e->base), "plugin_call") ||
        !pct_join(e->home, sizeof(e->home), e->base, "home") || mkdir(e->home, 0700) != 0 ||
        !pct_join(dot, sizeof(dot), e->home, ".z23") || mkdir(dot, 0700) != 0 ||
        !pct_join(e->root, sizeof(e->root), dot, "plugins") || mkdir(e->root, 0700) != 0 ||
        !pct_join(e->dist, sizeof(e->dist), e->base, "dist") ||
        !pct_join(key, sizeof(key), e->base, "publisher.key") || setenv("HOME", e->home, 1) != 0)
        return false;
    snprintf(in, sizeof(in), "{\"key\":\"%s\"}", key);
    if (!pct_call(zcl_native_handle_plugin_keygen, in, &r))
        return false;
    snprintf(pub, sizeof(pub), "%s", r.exit_code == ZCL_COMMAND_EXIT_OK
                                         ? json_get_str(json_get(&r.data, "public_key")) : "");
    zcl_command_reply_free(&r);
    return pub[0] && pct_keys(e, pub);
}

static void pct_env_close(struct pct_env *e)
{
    if (e->old_home[0])
        (void)setenv("HOME", e->old_home, 1);
    if (e->base[0])
        (void)test_rm_rf_recursive(e->base);
}

/* Pack the fixture as name at the given interface, install it and make it
 * current. interface 0 omits the input so the default applies. */
static bool pct_publish(struct pct_env *e, const char *name, int interface)
{
    char in[4 * PATH_MAX], key[PATH_MAX], manifest[PATH_MAX], iface[32] = "";
    struct zcl_command_reply r;
    if (interface)
        snprintf(iface, sizeof(iface), ",\"interface\":%d", interface);
    if (!pct_join(key, sizeof(key), e->base, "publisher.key"))
        return false;
    snprintf(in, sizeof(in), "{\"exe\":\"%s\",\"name\":\"%s\",\"version\":\"1.2.3\",\"key\":\"%s\","
             "\"dir\":\"%s\"%s}", PCT_FIXTURE, name, key, e->dist, iface);
    if (!pct_call(zcl_native_handle_plugin_pack, in, &r) || r.exit_code != ZCL_COMMAND_EXIT_OK)
        return false;
    snprintf(manifest, sizeof(manifest), "%s", json_get_str(json_get(&r.data, "manifest")));
    zcl_command_reply_free(&r);
    snprintf(in, sizeof(in), "{\"manifest\":\"%s\"}", manifest);
    if (!pct_call(zcl_native_handle_plugin_install, in, &r) || r.exit_code != ZCL_COMMAND_EXIT_OK)
        return false;
    snprintf(e->generation, sizeof(e->generation), "%s", json_get_str(json_get(&r.data, "generation")));
    zcl_command_reply_free(&r);
    snprintf(in, sizeof(in), "{\"name\":\"%s\",\"generation\":\"%s\"}", name, e->generation);
    if (!pct_call(zcl_native_handle_plugin_switch, in, &r))
        return false;
    bool ok = r.exit_code == ZCL_COMMAND_EXIT_OK;
    zcl_command_reply_free(&r);
    return ok;
}

static int pct_case_upper(void)
{
    int failures = 0;
    struct pct_env e;
    bool ready = pct_env_open(&e);
    TEST_CASE("plugin.call runs an interface 2 plugin once with stdin and returns stdout") {
        struct zcl_command_reply r;
        char hash[PLUGIN_HEX_SHA3_512 + 1];
        ASSERT(ready);
        ASSERT(pct_publish(&e, "upper", 2));
        ASSERT(pct_call(zcl_native_handle_plugin_call, "{\"name\":\"upper\",\"stdin\":\"abc\\n\"}", &r));
        ASSERT_EQ(r.exit_code, ZCL_COMMAND_EXIT_OK);
        const struct json_value *run = json_get(&r.data, "run");
        ASSERT_STR_EQ(json_get_str(json_get(run, "stdout")), "ABC\n");
        ASSERT_EQ(json_get_int(json_get(run, "exit_code")), 0);
        ASSERT_EQ(json_get_int(json_get(run, "signal")), 0);
        ASSERT_STR_EQ(json_get_str(json_get(&r.data, "name")), "upper");
        ASSERT_STR_EQ(json_get_str(json_get(&r.data, "version")), "1.2.3");
        ASSERT(json_get(&r.data, "elapsed_ms") != NULL);
        ASSERT_EQ(plugin_hash_file(PCT_FIXTURE, hash), PLUGIN_OK);
        ASSERT_STR_EQ(json_get_str(json_get(&r.data, "sha3_512")), hash);
        zcl_command_reply_free(&r);
    } TEST_END
    pct_env_close(&e);
    return failures;
}

/* Flip the last byte of the installed executable: a section header byte the
 * loader never reads, so only the hash check can stop the call. */
static bool pct_tamper(const struct pct_env *e, const char *name)
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

static int pct_case_tamper(void)
{
    int failures = 0;
    struct pct_env e;
    bool ready = pct_env_open(&e);
    TEST_CASE("plugin.call refuses a tampered executable before it runs") {
        struct zcl_command_reply r;
        ASSERT(ready);
        ASSERT(pct_publish(&e, "upper", 2));
        ASSERT(pct_tamper(&e, "upper"));
        ASSERT(pct_call(zcl_native_handle_plugin_call, "{\"name\":\"upper\",\"stdin\":\"abc\"}", &r));
        ASSERT_STR_EQ(r.error.code, "PLUGIN_EXE_HASH");
        ASSERT(json_get(&r.data, "run") == NULL);
        zcl_command_reply_free(&r);
    } TEST_END
    pct_env_close(&e);
    return failures;
}

static int pct_case_interface(void)
{
    int failures = 0;
    struct pct_env e;
    bool ready = pct_env_open(&e);
    TEST_CASE("plugin.run refuses interface 2 and plugin.call refuses interface 1") {
        struct zcl_command_reply r;
        ASSERT(ready);
        ASSERT(pct_publish(&e, "oneshot", 2));
        ASSERT(pct_publish(&e, "daemon", 0));
        ASSERT(pct_call(zcl_native_handle_plugin_run, "{\"name\":\"oneshot\",\"seconds\":1}", &r));
        ASSERT_STR_EQ(r.error.code, "PLUGIN_INTERFACE");
        zcl_command_reply_free(&r);
        ASSERT(pct_call(zcl_native_handle_plugin_call, "{\"name\":\"daemon\",\"stdin\":\"abc\"}", &r));
        ASSERT_STR_EQ(r.error.code, "PLUGIN_INTERFACE");
        ASSERT(json_get(&r.data, "run") == NULL);
        zcl_command_reply_free(&r);
    } TEST_END
    pct_env_close(&e);
    return failures;
}

static int pct_case_versions(void)
{
    int failures = 0;
    struct pct_env e;
    bool ready = pct_env_open(&e);
    TEST_CASE("pack and manifest parsing accept interface 1 and 2 and refuse any other") {
        static const char fmt[] = "{\"schema\":\"z23.plugin.v1\",\"name\":\"x\",\"version\":\"1.0.0\","
            "\"interface_version\":%d,\"sha3_512\":\"%0128d\",\"capabilities\":[]}";
        struct zcl_command_reply r;
        struct plugin_manifest m;
        char in[4 * PATH_MAX], key[PATH_MAX], text[512];
        ASSERT(ready);
        ASSERT(pct_join(key, sizeof(key), e.base, "publisher.key"));
        snprintf(in, sizeof(in), "{\"exe\":\"%s\",\"name\":\"x\",\"version\":\"1.0.0\",\"key\":\"%s\","
                 "\"dir\":\"%s\",\"interface\":3}", PCT_FIXTURE, key, e.dist);
        ASSERT(pct_call(zcl_native_handle_plugin_pack, in, &r));
        ASSERT_STR_EQ(r.error.code, "PLUGIN_ARGUMENT");
        zcl_command_reply_free(&r);
        for (int v = 0; v <= 3; v++) {
            int n = snprintf(text, sizeof(text), fmt, v, 0);
            ASSERT_EQ(plugin_manifest_parse(text, (size_t)n, &m),
                      (v == 1 || v == 2) ? PLUGIN_OK : PLUGIN_ERR_MANIFEST_INVALID);
        }
    } TEST_END
    pct_env_close(&e);
    return failures;
}

/* Temporary HOME with no ~/.z23: plugin.publisher must create the store itself. */
static bool pct_env_bare(struct pct_env *e)
{
    const char *home = getenv("HOME");
    memset(e, 0, sizeof(*e));
    snprintf(e->old_home, sizeof(e->old_home), "%s", home ? home : "");
    return test_mkdtemp(e->base, sizeof(e->base), "plugin_keys") &&
           pct_join(e->home, sizeof(e->home), e->base, "home") && mkdir(e->home, 0700) == 0 &&
           pct_join(e->root, sizeof(e->root), e->home, ".z23/plugins") &&
           pct_join(e->dist, sizeof(e->dist), e->base, "dist") &&
           setenv("HOME", e->home, 1) == 0;
}

/* Generate the publisher key; the public key goes to pub, the reply's first
 * next entry to next. */
static bool pct_keygen(const struct pct_env *e, char pub[65], struct zcl_command_next *next)
{
    char in[2 * PATH_MAX], key[PATH_MAX];
    struct zcl_command_reply r;
    if (!pct_join(key, sizeof(key), e->base, "publisher.key"))
        return false;
    snprintf(in, sizeof(in), "{\"key\":\"%s\"}", key);
    if (!pct_call(zcl_native_handle_plugin_keygen, in, &r))
        return false;
    bool ok = r.exit_code == ZCL_COMMAND_EXIT_OK && r.next_count == 1;
    if (ok) {
        snprintf(pub, 65, "%s", json_get_str(json_get(&r.data, "public_key")));
        *next = r.next[0];
    }
    zcl_command_reply_free(&r);
    return ok;
}

static bool pct_keys_call(const char *key, struct zcl_command_reply *r)
{
    char in[160];
    snprintf(in, sizeof(in), "{\"key\":\"%s\"}", key);
    return pct_call(zcl_native_handle_plugin_publisher, in, r);
}

static int pct_mode(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0 ? (int)(st.st_mode & 0777) : -1;
}

static bool pct_slurp(const char *path, char *out, size_t cap)
{
    FILE *f = fopen(path, "rb");
    size_t n = f ? fread(out, 1, cap - 1, f) : 0;
    bool ok = f && !ferror(f);
    if (f)
        fclose(f);
    out[n] = '\0';
    return ok;
}

static int pct_case_keys(void)
{
    int failures = 0;
    struct pct_env e;
    bool ready = pct_env_bare(&e);
    TEST_CASE("plugin.publisher creates a private store, appends once and reports a repeat") {
        char pub[65], dot[PATH_MAX], file[PATH_MAX], before[256], after[256], expect[80];
        struct zcl_command_next next;
        struct zcl_command_reply r;
        ASSERT(ready);
        ASSERT(pct_keygen(&e, pub, &next));
        snprintf(expect, sizeof(expect), "{\"key\":\"%s\"}", pub);
        ASSERT_STR_EQ(next.command, "plugin.publisher");
        ASSERT_STR_EQ(next.input_json, expect);
        ASSERT(pct_join(dot, sizeof(dot), e.home, ".z23"));
        ASSERT(pct_join(file, sizeof(file), e.root, "publisher_keys"));
        ASSERT(pct_keys_call(pub, &r));
        ASSERT_EQ(r.exit_code, ZCL_COMMAND_EXIT_OK);
        ASSERT(!json_get_bool(json_get(&r.data, "already_listed")));
        ASSERT(r.error.mutated);
        zcl_command_reply_free(&r);
        ASSERT_EQ(pct_mode(dot), 0700);
        ASSERT_EQ(pct_mode(e.root), 0700);
        ASSERT_EQ(pct_mode(file), 0600);
        ASSERT(pct_slurp(file, before, sizeof(before)));
        snprintf(expect, sizeof(expect), "%s\n", pub);
        ASSERT_STR_EQ(before, expect);
        ASSERT(pct_keys_call(pub, &r));
        ASSERT_EQ(r.exit_code, ZCL_COMMAND_EXIT_OK);
        ASSERT(json_get_bool(json_get(&r.data, "already_listed")));
        ASSERT(!r.error.mutated);
        zcl_command_reply_free(&r);
        ASSERT(pct_slurp(file, after, sizeof(after)));
        ASSERT_STR_EQ(after, before);
    } TEST_END
    pct_env_close(&e);
    return failures;
}

static int pct_case_keys_refusals(void)
{
    int failures = 0;
    struct pct_env e;
    bool ready = pct_env_bare(&e);
    TEST_CASE("plugin.publisher refuses a malformed key and an insecure store and writes nothing") {
        static const char *const bad[] = {
            "", "abc", "0000000000000000000000000000000000000000000000000000000000000000f",
            "ABCDEF0000000000000000000000000000000000000000000000000000000000",
            "zz00000000000000000000000000000000000000000000000000000000000000" };
        static const char good[] =
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
        char dot[PATH_MAX], file[PATH_MAX];
        struct zcl_command_reply r;
        ASSERT(ready);
        ASSERT(pct_join(dot, sizeof(dot), e.home, ".z23"));
        ASSERT(pct_join(file, sizeof(file), e.root, "publisher_keys"));
        for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
            ASSERT(pct_keys_call(bad[i], &r));
            ASSERT_STR_EQ(r.error.code, "PLUGIN_ARGUMENT");
            zcl_command_reply_free(&r);
        }
        ASSERT(access(dot, F_OK) != 0);
        ASSERT_EQ(mkdir(dot, 0700), 0);
        ASSERT_EQ(mkdir(e.root, 0700), 0);
        ASSERT_EQ(chmod(e.root, 0777), 0);
        ASSERT(pct_keys_call(good, &r));
        ASSERT_STR_EQ(r.error.code, "PLUGIN_KEYS_INSECURE");
        zcl_command_reply_free(&r);
        ASSERT(access(file, F_OK) != 0);
        ASSERT_EQ(chmod(e.root, 0700), 0);
        ASSERT_EQ(chmod(dot, 0770), 0);
        ASSERT(pct_keys_call(good, &r));
        ASSERT_STR_EQ(r.error.code, "PLUGIN_KEYS_INSECURE");
        zcl_command_reply_free(&r);
        ASSERT(access(file, F_OK) != 0);
        ASSERT_EQ(pct_mode(dot), 0770);
    } TEST_END
    pct_env_close(&e);
    return failures;
}

static int pct_case_keys_empty(void)
{
    int failures = 0;
    struct pct_env e;
    bool ready = pct_env_bare(&e);
    TEST_CASE("plugin.publisher treats an existing empty key file as zero keys and appends") {
        static const char good[] =
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
        char dot[PATH_MAX], file[PATH_MAX], after[256], expect[80];
        struct zcl_command_reply r;
        ASSERT(ready);
        ASSERT(pct_join(dot, sizeof(dot), e.home, ".z23"));
        ASSERT(pct_join(file, sizeof(file), e.root, "publisher_keys"));
        ASSERT_EQ(mkdir(dot, 0700), 0);
        ASSERT_EQ(mkdir(e.root, 0700), 0);
        int fd = open(file, O_WRONLY | O_CREAT | O_EXCL, 0600);
        ASSERT(fd >= 0);
        ASSERT_EQ(close(fd), 0);
        ASSERT(pct_keys_call(good, &r));
        ASSERT_EQ(r.exit_code, ZCL_COMMAND_EXIT_OK);
        ASSERT(!json_get_bool(json_get(&r.data, "already_listed")));
        ASSERT(r.error.mutated);
        zcl_command_reply_free(&r);
        ASSERT(pct_slurp(file, after, sizeof(after)));
        snprintf(expect, sizeof(expect), "%s\n", good);
        ASSERT_STR_EQ(after, expect);
        ASSERT_EQ(pct_mode(file), 0600);
    } TEST_END
    pct_env_close(&e);
    return failures;
}

static int pct_case_keys_chain(void)
{
    int failures = 0;
    struct pct_env e;
    bool ready = pct_env_bare(&e);
    TEST_CASE("keygen, publisher, pack, install, switch and call run end to end with no hand edits") {
        char pub[65], input[4 * PATH_MAX];
        struct zcl_command_next next;
        struct zcl_command_reply r;
        ASSERT(ready);
        ASSERT(pct_keygen(&e, pub, &next));
        snprintf(input, sizeof(input),
                 "{\"exe\":\"%s\",\"name\":\"upper\",\"version\":\"1.2.3\","
                 "\"key\":\"%s/publisher.key\",\"dir\":\"%s\",\"interface\":2}",
                 PCT_FIXTURE, e.base, e.dist);
        ASSERT(pct_call(zcl_native_handle_plugin_pack, input, &r));
        ASSERT_EQ(r.exit_code, ZCL_COMMAND_EXIT_OK);
        zcl_command_reply_free(&r);
        snprintf(input, sizeof(input), "{\"manifest\":\"%s/upper.plugin.json\"}", e.dist);
        ASSERT(pct_call(zcl_native_handle_plugin_install, input, &r));
        ASSERT_EQ(r.exit_code, ZCL_COMMAND_EXIT_INVALID);
        ASSERT_STR_EQ(r.error.code, "PLUGIN_NO_KEYS");
        ASSERT(!r.error.mutated);
        ASSERT(strstr(r.error.next_action, "z23 plugin publisher ") != NULL);
        ASSERT(strstr(r.error.next_action, "retry the requested operation") != NULL);
        zcl_command_reply_free(&r);
        ASSERT(pct_keys_call(pub, &r));
        ASSERT_EQ(r.exit_code, ZCL_COMMAND_EXIT_OK);
        zcl_command_reply_free(&r);
        ASSERT(pct_publish(&e, "upper", 2));
        ASSERT(pct_call(zcl_native_handle_plugin_call, "{\"name\":\"upper\",\"stdin\":\"abc\\n\"}", &r));
        ASSERT_EQ(r.exit_code, ZCL_COMMAND_EXIT_OK);
        ASSERT_STR_EQ(json_get_str(json_get(json_get(&r.data, "run"), "stdout")), "ABC\n");
        zcl_command_reply_free(&r);
    } TEST_END
    pct_env_close(&e);
    return failures;
}

int test_plugin_call(void)
{
    int failures = 0;
    printf("\n=== Plugin call tests ===\n");
    failures += pct_case_upper();
    failures += pct_case_tamper();
    failures += pct_case_interface();
    failures += pct_case_versions();
    failures += pct_case_keys();
    failures += pct_case_keys_refusals();
    failures += pct_case_keys_empty();
    failures += pct_case_keys_chain();
    return failures;
}
#endif
