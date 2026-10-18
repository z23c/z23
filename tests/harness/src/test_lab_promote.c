/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: lab.promote. A lab file that passes its cases becomes a signed
 * interface 2 plugin that plugin.call runs with the same output; a failing
 * case, a release image that disagrees with the sanitized build, or a missing
 * key refuses with a stable code and leaves the output directory empty. Every
 * key and store lives under a temporary HOME; the real ~/.z23 is never read. */

#include "test/test_core.h"

#include "command/native_command.h"
#include "json/json.h"
#include "plugin/plugin_store.h"

#include <dirent.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define LP_UPPER "tests/fixtures/lab/upper.c"
#define LP_MODE "tests/fixtures/lab/build_mode.c"
#define LP_CASES_OK \
    "[{\"name\":\"lower\",\"stdin\":\"abc\\n\",\"expect_stdout\":\"ABC\\n\"}," \
    "{\"name\":\"mixed\",\"stdin\":\"Hello, z23\\n\",\"expect_stdout\":\"HELLO, Z23\\n\"}]"

typedef void (*lp_handler)(const struct zcl_command_request *, struct zcl_command_reply *);

#if !defined(__linux__)
int test_lab_promote(void)
{
    int failures = 0;
    printf("\n=== Lab promote tests ===\n");
    TEST_CASE("lab.promote refuses by name off Linux") {
        struct zcl_command_reply r;
        struct json_value in;
        const char *text = "{\"file\":\"" LP_UPPER "\",\"cases\":" LP_CASES_OK
                           ",\"name\":\"upper\",\"version\":\"1.0.0\",\"key\":\"k\"}";
        json_init(&in);
        ASSERT(json_read(&in, text, strlen(text)));
        struct zcl_command_request request = { .input = &in };
        zcl_command_reply_init(&r, "zcl.lab_promote.v1");
        zcl_native_handle_lab_promote(&request, &r);
        ASSERT_STR_EQ(r.error.code, "LAB_UNSUPPORTED");
        zcl_command_reply_free(&r);
        json_free(&in);
    } TEST_END
    return failures;
}
#else

struct lp_env {
    char base[PATH_MAX], home[PATH_MAX], root[PATH_MAX], dist[PATH_MAX], key[PATH_MAX];
    char old_home[PATH_MAX];
};

static bool lp_call(lp_handler handler, const char *input_json, struct zcl_command_reply *reply)
{
    struct json_value input;
    json_init(&input);
    bool ok = json_read(&input, input_json, strlen(input_json));
    struct zcl_command_request request = { .input = &input, .view = "normal" };
    zcl_command_reply_init(reply, "zcl.lab_promote_test.v1");
    if (ok)
        handler(&request, reply);
    json_free(&input);
    return ok;
}

static bool lp_join(char *out, size_t cap, const char *a, const char *b)
{
    int n = snprintf(out, cap, "%s/%s", a, b);
    return n > 0 && (size_t)n < cap;
}

static bool lp_trust(const struct lp_env *e, const char *public_key)
{
    char path[PATH_MAX];
    FILE *f = lp_join(path, sizeof(path), e->root, "trusted_keys") ? fopen(path, "wb") : NULL;
    bool ok = f && fprintf(f, "%s\n", public_key) > 0;
    if (f)
        ok = fclose(f) == 0 && ok;
    return ok && chmod(path, 0600) == 0;
}

/* Directories of one environment; dist is named but not created. */
static bool lp_env_dirs(struct lp_env *e, char lab[PATH_MAX])
{
    char dot[PATH_MAX];
    return test_mkdtemp(e->base, sizeof(e->base), "lab_promote") &&
           lp_join(e->home, sizeof(e->home), e->base, "home") && mkdir(e->home, 0700) == 0 &&
           lp_join(dot, sizeof(dot), e->home, ".z23") && mkdir(dot, 0700) == 0 &&
           lp_join(e->root, sizeof(e->root), dot, "plugins") && mkdir(e->root, 0700) == 0 &&
           lp_join(lab, PATH_MAX, e->base, "lab") && mkdir(lab, 0700) == 0 &&
           lp_join(e->dist, sizeof(e->dist), e->base, "dist") &&
           lp_join(e->key, sizeof(e->key), e->base, "publisher.key");
}

/* Temporary HOME and lab state, a generated key, and the key trusted. */
static bool lp_env_open(struct lp_env *e)
{
    char lab[PATH_MAX], in[2 * PATH_MAX], pub[65];
    struct zcl_command_reply r;
    const char *home = getenv("HOME");
    memset(e, 0, sizeof(*e));
    snprintf(e->old_home, sizeof(e->old_home), "%s", home ? home : "");
    if (!lp_env_dirs(e, lab) || setenv("HOME", e->home, 1) != 0 ||
        setenv("Z23_LAB_DIR", lab, 1) != 0)
        return false;
    snprintf(in, sizeof(in), "{\"key\":\"%s\"}", e->key);
    if (!lp_call(zcl_native_handle_plugin_keygen, in, &r))
        return false;
    snprintf(pub, sizeof(pub), "%s", r.exit_code == ZCL_COMMAND_EXIT_OK
                                         ? json_get_str(json_get(&r.data, "public_key")) : "");
    zcl_command_reply_free(&r);
    return pub[0] && lp_trust(e, pub);
}

static void lp_env_close(struct lp_env *e)
{
    if (e->old_home[0])
        (void)setenv("HOME", e->old_home, 1);
    (void)unsetenv("Z23_LAB_DIR");
    if (e->base[0])
        (void)test_rm_rf_recursive(e->base);
}

static void lp_promote(const struct lp_env *e, const char *file, const char *cases,
                       struct zcl_command_reply *reply)
{
    char in[4 * PATH_MAX + 1024];
    snprintf(in, sizeof(in), "{\"file\":\"%s\",\"cases\":%s,\"name\":\"upper\",\"version\":\"1.0.0\","
             "\"key\":\"%s\",\"dir\":\"%s\"}", file, cases, e->key, e->dist);
    (void)lp_call(zcl_native_handle_lab_promote, in, reply);
}

/* Entries in dir, or -1 when it cannot be opened. */
static int lp_entries(const char *dir)
{
    DIR *d = opendir(dir);
    int n = 0;
    if (!d)
        return -1;
    for (struct dirent *de = readdir(d); de; de = readdir(d))
        n += strcmp(de->d_name, ".") != 0 && strcmp(de->d_name, "..") != 0;
    closedir(d);
    return n;
}

static const char *lp_str(const struct json_value *d, const char *key)
{
    const struct json_value *v = json_get(d, key);
    return v && v->type == JSON_STR ? json_get_str(v) : "";
}

static bool lp_install_and_switch(const char *manifest, struct zcl_command_reply *r)
{
    char in[2 * PATH_MAX];
    snprintf(in, sizeof(in), "{\"manifest\":\"%s\"}", manifest);
    if (!lp_call(zcl_native_handle_plugin_install, in, r) || r->exit_code != ZCL_COMMAND_EXIT_OK)
        return false;
    snprintf(in, sizeof(in), "{\"name\":\"upper\",\"generation\":\"%s\"}",
             lp_str(&r->data, "generation"));
    zcl_command_reply_free(r);
    if (!lp_call(zcl_native_handle_plugin_switch, in, r))
        return false;
    bool ok = r->exit_code == ZCL_COMMAND_EXIT_OK;
    zcl_command_reply_free(r);
    return ok;
}

static int lp_case_roundtrip(void)
{
    int failures = 0;
    struct lp_env e;
    bool ready = lp_env_open(&e);
    TEST_CASE("lab.promote signs a file that passes its cases and plugin.call returns the cases' output") {
        struct zcl_command_reply p, c;
        char manifest[PATH_MAX], sig[PATH_MAX], next[PATH_MAX + 64], sha[PLUGIN_HEX_SHA3_512 + 1];
        ASSERT(ready);
        lp_promote(&e, LP_UPPER, LP_CASES_OK, &p);
        ASSERT_EQ(p.exit_code, ZCL_COMMAND_EXIT_OK);
        ASSERT_EQ(json_get_int(json_get(&p.data, "cases_passed")), 2);
        ASSERT(strstr(lp_str(&p.data, "release_command"), "-static-pie") != NULL);
        ASSERT(strstr(lp_str(&p.data, "release_command"), "-O2") != NULL);
        ASSERT(strstr(lp_str(&p.data, "release_command"), "-fsanitize") == NULL);
        snprintf(manifest, sizeof(manifest), "%s", lp_str(&p.data, "manifest"));
        snprintf(sig, sizeof(sig), "%s", lp_str(&p.data, "signature"));
        snprintf(next, sizeof(next), "z23 plugin install --manifest=%s", manifest);
        snprintf(sha, sizeof(sha), "%s", lp_str(&p.data, "release_sha3_512"));
        ASSERT_STR_EQ(lp_str(&p.data, "next"), next);
        ASSERT_EQ(access(manifest, R_OK), 0);
        ASSERT_EQ(access(sig, R_OK), 0);
        ASSERT_EQ(lp_entries(e.dist), 3);
        ASSERT(lp_install_and_switch(manifest, &c));
        ASSERT(lp_call(zcl_native_handle_plugin_call, "{\"name\":\"upper\",\"stdin\":\"abc\\n\"}", &c));
        ASSERT_EQ(c.exit_code, ZCL_COMMAND_EXIT_OK);
        ASSERT_STR_EQ(lp_str(json_get(&c.data, "run"), "stdout"), "ABC\n");
        ASSERT_STR_EQ(lp_str(&c.data, "sha3_512"), sha);
        ASSERT_STR_EQ(lp_str(&c.data, "generation"), lp_str(&p.data, "generation"));
        zcl_command_reply_free(&c);
        zcl_command_reply_free(&p);
    } TEST_END
    lp_env_close(&e);
    return failures;
}

static int lp_case_failed_case(void)
{
    int failures = 0;
    struct lp_env e;
    bool ready = lp_env_open(&e);
    TEST_CASE("lab.promote refuses a failing case and writes nothing") {
        struct zcl_command_reply p;
        ASSERT(ready);
        ASSERT_EQ(mkdir(e.dist, 0700), 0);
        lp_promote(&e, LP_UPPER,
                   "[{\"name\":\"ok\",\"stdin\":\"a\\n\",\"expect_stdout\":\"A\\n\"},"
                   "{\"name\":\"wrong\",\"stdin\":\"b\\n\",\"expect_stdout\":\"b\\n\"}]", &p);
        ASSERT_STR_EQ(p.error.code, "LAB_PROMOTE_CASES_FAILED");
        ASSERT(strstr(p.error.message, "1 of 2 cases failed") != NULL);
        ASSERT_EQ(lp_entries(e.dist), 0);
        zcl_command_reply_free(&p);
    } TEST_END
    lp_env_close(&e);
    return failures;
}

static int lp_case_disagree(void)
{
    int failures = 0;
    struct lp_env e;
    bool ready = lp_env_open(&e);
    TEST_CASE("lab.promote refuses a release image that disagrees with the sanitized build") {
        struct zcl_command_reply p;
        ASSERT(ready);
        ASSERT_EQ(mkdir(e.dist, 0700), 0);
        lp_promote(&e, LP_MODE, "[{\"name\":\"mode\",\"expect_stdout\":\"asan\\n\"}]", &p);
        ASSERT_STR_EQ(p.error.code, "LAB_PROMOTE_RELEASE_DISAGREES");
        ASSERT(strstr(p.error.message, "1 of 1 cases") != NULL);
        ASSERT_EQ(lp_entries(e.dist), 0);
        zcl_command_reply_free(&p);
    } TEST_END
    lp_env_close(&e);
    return failures;
}

static int lp_case_no_key(void)
{
    int failures = 0;
    struct lp_env e;
    bool ready = lp_env_open(&e);
    TEST_CASE("lab.promote without a key refuses before running anything") {
        struct zcl_command_reply p;
        char in[4 * PATH_MAX];
        ASSERT(ready);
        snprintf(in, sizeof(in), "{\"file\":\"" LP_UPPER "\",\"cases\":" LP_CASES_OK
                 ",\"name\":\"upper\",\"version\":\"1.0.0\",\"dir\":\"%s\"}", e.dist);
        ASSERT(lp_call(zcl_native_handle_lab_promote, in, &p));
        ASSERT_STR_EQ(p.error.code, "LAB_BAD_INPUT");
        ASSERT(access(e.dist, F_OK) != 0);
        zcl_command_reply_free(&p);
    } TEST_END
    lp_env_close(&e);
    return failures;
}

int test_lab_promote(void)
{
    int failures = 0;
    printf("\n=== Lab promote tests ===\n");
    failures += lp_case_roundtrip();
    failures += lp_case_failed_case();
    failures += lp_case_disagree();
    failures += lp_case_no_key();
    return failures;
}
#endif
