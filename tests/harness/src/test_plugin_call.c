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
#include "command/lab.h"
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
    char old_lab[PATH_MAX] = "", base[PATH_MAX], path[PATH_MAX];
    const char *old = getenv("Z23_LAB_DIR");
    bool had_old = old != NULL;
    if (old) snprintf(old_lab, sizeof(old_lab), "%s", old);
    TEST_CASE("plugin.call runs an interface 2 plugin once with stdin and returns stdout") {
        struct zcl_command_reply r;
        char hash[PLUGIN_HEX_SHA3_512 + 1];
        ASSERT(ready);
        ASSERT(pct_publish(&e, "upper", 2));
        ASSERT(pct_join(base, sizeof(base), e.base, "lab-only-run"));
        ASSERT_EQ(mkdir(base, 0700), 0);
        ASSERT(pct_join(path, sizeof(path), base, "run"));
        ASSERT_EQ(mkdir(path, 0700), 0);
        ASSERT_EQ(setenv("Z23_LAB_DIR", base, 1), 0);
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
        ASSERT(pct_join(path, sizeof(path), base, "cc"));
        ASSERT(access(path, F_OK) != 0);
        ASSERT(pct_join(path, sizeof(path), base, "receipts"));
        ASSERT(access(path, F_OK) != 0);
        ASSERT(pct_join(path, sizeof(path), base, "zcc"));
        ASSERT(access(path, F_OK) != 0);
        ASSERT(pct_join(path, sizeof(path), base, "run"));
        ASSERT_EQ(rmdir(path), 0);
        FILE *block = fopen(path, "wb");
        ASSERT(block != NULL);
        ASSERT_EQ(fclose(block), 0);
        size_t runs = lab_run_count();
        ASSERT(pct_call(zcl_native_handle_plugin_call, "{\"name\":\"upper\"}", &r));
        ASSERT_STR_EQ(r.error.code, "PLUGIN_IO");
        ASSERT_EQ(lab_run_count(), runs);
        zcl_command_reply_free(&r);
    } TEST_END
    if (had_old) (void)setenv("Z23_LAB_DIR", old_lab, 1);
    else (void)unsetenv("Z23_LAB_DIR");
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

/* Run one `plugin <args>` CLI word list through the real argv normalizer and
 * copy what it printed to stdout into out. Returns the exit code, or -1 when
 * the capture itself failed. */
static int pct_cli_root(const char *root, const char *const *args, int nargs,
                        const char *datadir, char *out, size_t cap)
{
    FILE *tmp = tmpfile();
    int rc = -1;
    if (!tmp)
        return -1;
    fflush(stdout);
    int saved = dup(fileno(stdout));
    if (saved >= 0 && dup2(fileno(tmp), fileno(stdout)) >= 0) {
        rc = zcl_native_command_main(root, args, nargs, datadir, 0,
                                     CHAIN_MAIN, true);
        fflush(stdout);
        (void)dup2(saved, fileno(stdout));
    }
    if (saved >= 0)
        close(saved);
    rewind(tmp);
    size_t n = fread(out, 1, cap - 1, tmp);
    out[n] = '\0';
    fclose(tmp);
    return rc;
}

static int pct_cli(const char *const *args, int nargs, const char *datadir,
                   char *out, size_t cap)
{
    return pct_cli_root("plugin", args, nargs, datadir, out, cap);
}

/* A bare `key=value` word is the named input when the leaf declares the
 * key, exactly like --key=value; every other word stays positional; a
 * declared key that is repeated is refused like a repeated flag; and
 * --K=K=v is the documented way to pass a value that begins with `K=`. */
static int pct_case_cli_named(void)
{
    int failures = 0;
    struct pct_env e;
    bool ready = pct_env_open(&e);
    char out[8192], base[PATH_MAX], path[PATH_MAX];
    const char *old = getenv("Z23_LAB_DIR");
    char old_lab[PATH_MAX] = "";
    bool had_old = old != NULL;
    if (old) snprintf(old_lab, sizeof(old_lab), "%s", old);
    TEST_CASE("plugin call and status accept declared key=value words as named inputs") {
        ASSERT(ready);
        ASSERT(pct_publish(&e, "upper", 2));
        ASSERT(pct_join(base, sizeof(base), e.base, "lab-only-run"));
        ASSERT_EQ(mkdir(base, 0700), 0);
        ASSERT(pct_join(path, sizeof(path), base, "run"));
        ASSERT_EQ(mkdir(path, 0700), 0);
        ASSERT_EQ(setenv("Z23_LAB_DIR", base, 1), 0);
        const char *named[] = {"call", "name=upper", "stdin=abc"};
        ASSERT_EQ(pct_cli(named, 3, e.base, out, sizeof(out)), ZCL_COMMAND_EXIT_OK);
        ASSERT(strstr(out, "ABC") != NULL);
        const char *dashed[] = {"call", "--name=upper", "--stdin=abc"};
        ASSERT_EQ(pct_cli(dashed, 3, e.base, out, sizeof(out)), ZCL_COMMAND_EXIT_OK);
        ASSERT(strstr(out, "ABC") != NULL);
        /* An undeclared key stays positional: `nokey=1` is the plugin name. */
        const char *undeclared[] = {"status", "nokey=1"};
        ASSERT(pct_cli(undeclared, 2, e.base, out, sizeof(out)) != ZCL_COMMAND_EXIT_OK);
        ASSERT(strstr(out, "PLUGIN_NOT_INSTALLED") != NULL && strstr(out, "nokey=1") != NULL);
        /* A repeated declared key is refused as a repeated --key is. */
        const char *twice[] = {"call", "name=upper", "stdin=a", "stdin=b"};
        ASSERT(pct_cli(twice, 4, e.base, out, sizeof(out)) != ZCL_COMMAND_EXIT_OK);
        ASSERT(strstr(out, "duplicate input key 'stdin'") != NULL);
        /* name= names the plugin, not the literal word `name=nope`. */
        const char *status[] = {"status", "name=nope"};
        ASSERT(pct_cli(status, 2, e.base, out, sizeof(out)) != ZCL_COMMAND_EXIT_OK);
        ASSERT(strstr(out, "PLUGIN_NOT_INSTALLED") != NULL);
        ASSERT(strstr(out, "name=nope") == NULL);
        /* --K=K=v keeps the whole word as the value. */
        const char *literal[] = {"status", "--name=name=nope"};
        ASSERT(pct_cli(literal, 2, e.base, out, sizeof(out)) != ZCL_COMMAND_EXIT_OK);
        ASSERT(strstr(out, "name=nope") != NULL);
    } TEST_END
    if (had_old) (void)setenv("Z23_LAB_DIR", old_lab, 1);
    else (void)unsetenv("Z23_LAB_DIR");
    pct_env_close(&e);
    return failures;
}

/* The bare key=value rule: a declared key is named only when every
 * positional slot is filled or the next open slot is that key; otherwise the
 * word is free text for the open slot. A `--input` JSON object that already
 * carries the key makes the two readings observable: named is a duplicate. */
static int pct_case_cli_slots(void)
{
    int failures = 0;
    struct pct_env e;
    bool ready = pct_env_open(&e);
    char out[8192];
    TEST_CASE("bare key=value is free text while its positional slot is open") {
        ASSERT(ready);
        /* ops.logs slot is `pattern`: `level=error` stays the pattern. */
        const char *free_text[] = {"logs", "--input={\"level\":\"warn\"}", "level=error"};
        (void)pct_cli_root("ops", free_text, 3, e.base, out, sizeof(out));
        ASSERT(strstr(out, "duplicate input key") == NULL);
        ASSERT(strstr(out, "TOO_MANY_ARGS") == NULL);
        /* Pattern filled, then a declared key: the key is named (it was
         * TOO_MANY_ARGS before); with the key already given it is a duplicate. */
        const char *after[] = {"logs", "error", "level=warn"};
        (void)pct_cli_root("ops", after, 3, e.base, out, sizeof(out));
        ASSERT(strstr(out, "TOO_MANY_ARGS") == NULL);
        const char *dup[] = {"logs", "--input={\"level\":\"warn\"}", "error", "level=info"};
        ASSERT(pct_cli_root("ops", dup, 4, e.base, out, sizeof(out)) != ZCL_COMMAND_EXIT_OK);
        ASSERT(strstr(out, "duplicate input key 'level'") != NULL);
        /* Two free words still overflow the single slot, as before. */
        const char *many[] = {"logs", "a", "b"};
        (void)pct_cli_root("ops", many, 3, e.base, out, sizeof(out));
        ASSERT(strstr(out, "TOO_MANY_ARGS") != NULL);
        /* fleet board post slots are kind,text: scope= is text while text is open. */
        const char *board[] = {"board", "post", "--input={\"scope\":\"fleet\"}", "note", "scope=x"};
        (void)pct_cli_root("fleet", board, 5, e.base, out, sizeof(out));
        ASSERT(strstr(out, "duplicate input key") == NULL);
        /* text= is the next open slot, so it is named; scope= after it too. */
        const char *text[] = {"board", "post", "--input={\"text\":\"z\"}", "note", "text=hi"};
        ASSERT(pct_cli_root("fleet", text, 5, e.base, out, sizeof(out)) != ZCL_COMMAND_EXIT_OK);
        ASSERT(strstr(out, "duplicate input key 'text'") != NULL);
        const char *scope[] = {"board", "post", "--input={\"scope\":\"fleet\"}", "note", "text=hi", "scope=x"};
        ASSERT(pct_cli_root("fleet", scope, 6, e.base, out, sizeof(out)) != ZCL_COMMAND_EXIT_OK);
        ASSERT(strstr(out, "duplicate input key 'scope'") != NULL);
    } TEST_END
    pct_env_close(&e);
    return failures;
}

static int pct_case_cli_mixed(void)
{
    int failures = 0;
    struct pct_env e;
    bool ready = pct_env_open(&e);
    char out[8192];
    TEST_CASE("bare declared key mixed with a positional, --input and field= keep the dashed meaning") {
        ASSERT(ready);
        /* positional fills `name`, so a bare name= is a second name. */
        const char *mixed[] = {"status", "nope", "name=other"};
        ASSERT(pct_cli(mixed, 3, e.base, out, sizeof(out)) != ZCL_COMMAND_EXIT_OK);
        ASSERT(strstr(out, "duplicate input key 'name'") != NULL);
        /* --input plus a bare key conflicts exactly like the dashed form. */
        const char *bare[] = {"status", "--input={\"name\":\"a\"}", "name=b"};
        const char *dash[] = {"status", "--input={\"name\":\"a\"}", "--name=b"};
        char out2[8192];
        ASSERT(pct_cli(bare, 3, e.base, out, sizeof(out)) != ZCL_COMMAND_EXIT_OK);
        ASSERT(pct_cli(dash, 3, e.base, out2, sizeof(out2)) != ZCL_COMMAND_EXIT_OK);
        ASSERT(strstr(out, "duplicate input key 'name'") != NULL);
        ASSERT(strstr(out2, "duplicate input key 'name'") != NULL);
        /* field= stays the field selector and never an input (its error goes to stderr, not the plugin name). */
        const char *field[] = {"status", "field=foo"};
        ASSERT(pct_cli(field, 2, e.base, out, sizeof(out)) != ZCL_COMMAND_EXIT_OK);
        ASSERT(strstr(out, "field=foo") == NULL && strstr(out, "PLUGIN_NOT_INSTALLED") == NULL);
        /* plugin dev: dir is the open slot, so name= is free text there and
         * named once dir is given. */
        const char *dev_free[] = {"dev", "name=zzz"};
        (void)pct_cli(dev_free, 2, e.base, out, sizeof(out));
        ASSERT(strstr(out, "duplicate input key") == NULL);
        const char *dev_dup[] = {"dev", "--input={\"name\":\"a\"}", "./d", "name=b"};
        ASSERT(pct_cli(dev_dup, 4, e.base, out, sizeof(out)) != ZCL_COMMAND_EXIT_OK);
        ASSERT(strstr(out, "duplicate input key 'name'") != NULL);
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
    failures += pct_case_cli_named();
    failures += pct_case_cli_slots();
    failures += pct_case_cli_mixed();
    return failures;
}
#endif
