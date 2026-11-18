/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: lab.promote and the one-call plugin.dev source loop. A lab file that
 * passes its cases becomes a signed interface 2 plugin that plugin.call runs
 * with the same output; failed proofs leave the output or current generation
 * unchanged. Every key and store lives under a temporary HOME; the real
 * ~/.z23 is never read. */

#include "test/test_core.h"

#include "base/safe_alloc.h"
#include "config/command_catalog.h"
#include "command/native_command.h"
#include "command/lab_priv.h"
#include "json/json.h"
#include "plugin/plugin_dev.h"
#include "plugin/plugin_store.h"

#include <errno.h>
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

static bool lp_invoke(lp_handler handler, const struct zcl_command_spec *spec,
                      const char *input_json, struct zcl_command_reply *reply)
{
    struct json_value input;
    json_init(&input);
    bool ok = json_read(&input, input_json, strlen(input_json));
    if (ok && spec)
        ok = zcl_command_registry_input_validate(spec, &input, NULL, 0);
    struct zcl_command_request request = { .spec = spec, .input = &input, .view = "normal" };
    zcl_command_reply_init(reply, "zcl.lab_promote_test.v1");
    if (ok)
        handler(&request, reply);
    json_free(&input);
    return ok;
}

static bool lp_call(lp_handler handler, const char *input_json, struct zcl_command_reply *reply)
{
    return lp_invoke(handler, NULL, input_json, reply);
}

static bool lp_join(char *out, size_t cap, const char *a, const char *b)
{
    int n = snprintf(out, cap, "%s/%s", a, b);
    return n > 0 && (size_t)n < cap;
}

static bool lp_keys(const struct lp_env *e, const char *public_key)
{
    char path[PATH_MAX];
    FILE *f = lp_join(path, sizeof(path), e->root, "publisher_keys") ? fopen(path, "wb") : NULL;
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

/* Temporary HOME and lab state, a generated key, and the key listed. */
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
    return pub[0] && lp_keys(e, pub);
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

/* The staged manifest must match the generation that completed proof. */
static bool lp_mismatched_generation_refused(const struct lp_env *e,
                                            const struct json_value *receipt)
{
    struct plugin_dev_result res = { .steps_done = 2 };
    struct plugin_manifest current;
    char exe[PATH_MAX];
    snprintf(res.name, sizeof(res.name), "upper");
    snprintf(res.public_key, sizeof(res.public_key), "%s", lp_str(receipt, "public_key"));
    snprintf(res.manifest_path, sizeof(res.manifest_path), "%s", lp_str(receipt, "manifest"));
    snprintf(res.generation, sizeof(res.generation), "%s", lp_str(receipt, "generation"));
    res.generation[0] = res.generation[0] == '0' ? '1' : '0';
    return plugin_dev_activate(e->root, &res) == PLUGIN_ERR_MANIFEST_INVALID &&
           res.failed == PLUGIN_DEV_STEP_INSTALL &&
           plugin_store_current(e->root, res.name, &current, exe, sizeof(exe)) == PLUGIN_ERR_NO_GENERATION;
}

static bool lp_manifest_hash_is(const char *path, const char *digest)
{
    char bytes[4096];
    struct plugin_manifest manifest;
    FILE *f = fopen(path, "rb");
    if (!f) return false;
    size_t n = fread(bytes, 1, sizeof(bytes), f);
    bool ok = !ferror(f) && n < sizeof(bytes) &&
              plugin_manifest_parse(bytes, n, &manifest) == PLUGIN_OK &&
              strcmp(manifest.exe_sha3, digest) == 0;
    fclose(f);
    return ok;
}


static int lp_case_pack_receipt_allocation(void)
{
    int failures = 0;
    struct lp_env e;
    bool ready = lp_env_open(&e);
    TEST_CASE("plugin.pack reports a receipt allocation failure after writing") {
        char input[2 * PATH_MAX + 512];
        struct json_value in;
        struct zcl_command_reply r;
        ASSERT(ready);
        snprintf(input, sizeof(input),
                 "{\"exe\":\"" LP_UPPER "\",\"name\":\"upper\",\"version\":\"1.0.0\","
                 "\"key\":\"%s\",\"dir\":\"%s\"}", e.key, e.dist);
        json_init(&in);
        ASSERT(json_read(&in, input, strlen(input)));
        struct zcl_command_request request = { .input = &in };
        zcl_command_reply_init(&r, "zcl.plugin_pack.v1");
        zcl_alloc_fault_fail_next("json_copy_str");
        zcl_native_handle_plugin_pack(&request, &r);
        bool hit = zcl_alloc_fault_armed_label() == NULL;
        zcl_alloc_fault_clear();
        ASSERT(hit);
        ASSERT_STR_EQ(r.error.code, "PLUGIN_IO");
        ASSERT(r.error.mutated);
        ASSERT(strstr(r.error.evidence, "upper.plugin.json") != NULL);
        ASSERT_EQ(lp_entries(e.dist), 3);
        ASSERT(json_is_null(&r.data));
        zcl_command_reply_free(&r);
        json_free(&in);
    } TEST_END
    lp_env_close(&e);
    return failures;
}


static int lp_case_roundtrip(void)
{
    int failures = 0;
    struct lp_env e;
    bool ready = lp_env_open(&e);
    TEST_CASE("lab.promote signs a file that passes its cases and plugin.call returns the cases' output") {
        struct zcl_command_reply p, c;
        char manifest[PATH_MAX], sig[PATH_MAX], sha[PLUGIN_HEX_SHA3_512 + 1];
        ASSERT(ready);
        unsigned hashes_before = plugin_fs_test_hash_count();
        lp_promote(&e, LP_UPPER, LP_CASES_OK, &p);
        ASSERT_EQ(plugin_fs_test_hash_count() - hashes_before, 1u);
        ASSERT_EQ(p.exit_code, ZCL_COMMAND_EXIT_OK);
        ASSERT_EQ(json_get_int(json_get(&p.data, "cases_passed")), 2);
        ASSERT(strstr(lp_str(&p.data, "release_command"), "-static-pie") != NULL);
        ASSERT(strstr(lp_str(&p.data, "release_command"), "-O2") != NULL);
        ASSERT(strstr(lp_str(&p.data, "release_command"), "-fsanitize") == NULL);
        snprintf(manifest, sizeof(manifest), "%s", lp_str(&p.data, "manifest"));
        snprintf(sig, sizeof(sig), "%s", lp_str(&p.data, "signature"));
        snprintf(sha, sizeof(sha), "%s", lp_str(&p.data, "release_sha3_512"));
        ASSERT(json_get(&p.data, "next") == NULL);
        ASSERT_EQ(p.next_count, 1);
        ASSERT_STR_EQ(p.next[0].command, "plugin.install");
        ASSERT(strstr(p.next[0].input_json, manifest) != NULL);
        ASSERT_EQ(access(manifest, R_OK), 0);
        ASSERT(lp_manifest_hash_is(manifest, sha));
        ASSERT_EQ(access(sig, R_OK), 0);
        ASSERT_EQ(lp_entries(e.dist), 3);
        ASSERT(lp_mismatched_generation_refused(&e, &p.data));
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
                   "{\"name\":\"wrong-猫猫猫猫猫猫猫猫\",\"stdin\":\"b\\n\",\"expect_stdout\":\"b\\n\"}]", &p);
        ASSERT_STR_EQ(p.error.code, "LAB_PROMOTE_CASES_FAILED");
        ASSERT(strstr(p.error.message, "1 of 2 cases failed") != NULL);
        ASSERT(strstr(p.error.message, "wrong-猫猫猫猫猫猫...") != NULL);
        ASSERT(strstr(p.error.next_action, "z23 lab show ") == p.error.next_action);
        ASSERT_EQ(strlen(p.error.evidence), 128);
        ASSERT(strstr(p.error.message, "line 1") != NULL);
        ASSERT_EQ(lp_entries(e.dist), 0);
        zcl_command_reply_free(&p);
    } TEST_END
    lp_env_close(&e);
    return failures;
}

static int lp_case_compile_failed(void)
{
    int failures = 0;
    struct lp_env e;
    bool ready = lp_env_open(&e);
    TEST_CASE("lab.promote reports the first compiler error") {
        struct zcl_command_reply p;
        char path[PATH_MAX];
        ASSERT(ready);
        ASSERT_EQ(mkdir(e.dist, 0700), 0);
        ASSERT(lp_join(path, sizeof(path), e.base, "invalid.c"));
        FILE *f = fopen(path, "wb");
        ASSERT(f != NULL);
        ASSERT(fputs("int main(void) { return missing_value; }\n", f) >= 0);
        ASSERT_EQ(fclose(f), 0);
        lp_promote(&e, path, "[{\"name\":\"mode\"}]", &p);
        ASSERT_STR_EQ(p.error.code, "LAB_PROMOTE_CASES_FAILED");
        ASSERT(strstr(p.error.message, "1 of 1 cases failed") != NULL);
        ASSERT(strstr(p.error.message, "line 1") != NULL);
        ASSERT(strstr(p.error.message, "col 25") != NULL);
        ASSERT(strstr(p.error.message, "compiler error: line 1") != NULL);
        ASSERT(strstr(p.error.message, "missing_value") != NULL);
        ASSERT_EQ(strlen(p.error.evidence), 128);
        ASSERT(strstr(p.error.next_action, "z23 lab show ") == p.error.next_action);
        ASSERT_EQ(lp_entries(e.dist), 0);
        zcl_command_reply_free(&p);
    } TEST_END
    lp_env_close(&e);
    return failures;
}

static int lp_case_release_compile_failed(void)
{
    int failures = 0;
    struct lp_env e;
    bool ready = lp_env_open(&e);
    TEST_CASE("lab.promote reports the release compiler error after a warning") {
        struct zcl_command_reply p;
        char path[PATH_MAX];
        ASSERT(ready);
        ASSERT_EQ(mkdir(e.dist, 0700), 0);
        ASSERT(lp_join(path, sizeof(path), e.base, "release-fail.c"));
        FILE *f = fopen(path, "wb");
        ASSERT(f != NULL);
        ASSERT(fputs("#if defined(__has_feature)\n"
                     "#if __has_feature(address_sanitizer)\n"
                     "#define GOOD 1\n"
                     "#endif\n"
                     "#endif\n"
                     "#if !defined(__SANITIZE_ADDRESS__) && !defined(GOOD)\n"
                     "#pragma GCC diagnostic warning \"-Wcpp\"\n"
                     "#warning informational_release_warning\n"
                     "#error actual_release_failure\n"
                     "#endif\n"
                     "int main(void) { return 0; }\n", f) >= 0);
        ASSERT_EQ(fclose(f), 0);
        lp_promote(&e, path, "[{\"name\":\"ok\"}]", &p);
        ASSERT_STR_EQ(p.error.code, "LAB_PROMOTE_BUILD_FAILED");
        ASSERT_STR_EQ(p.error.phase, "build");
        ASSERT(strstr(p.error.message, "actual_release_failure") != NULL);
        ASSERT(strstr(p.error.message, "line 9") != NULL);
        ASSERT(strstr(p.error.message, "informational_release_warning") == NULL);
        ASSERT(p.error.evidence[0] != 0);
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
        ASSERT(strstr(p.error.message, "mode") != NULL);
        ASSERT(p.error.evidence[0] != 0);
        ASSERT(strstr(p.error.message, "line 1") != NULL);
        ASSERT_EQ(lp_entries(e.dist), 0);
        zcl_command_reply_free(&p);
    } TEST_END
    lp_env_close(&e);
    return failures;
}

static int lp_case_capture_allocation(void)
{
    int failures = 0;
    struct lp_env e;
    bool ready = lp_env_open(&e);
    TEST_CASE("lab.promote reports a release case capture allocation failure and writes nothing") {
        struct zcl_command_reply p;
        ASSERT(ready);
        ASSERT_EQ(mkdir(e.dist, 0700), 0);
        /* First compile and run sanitized cases, then compile and run release cases. */
        zcl_alloc_fault_fail_nth("lab.out", 4);
        lp_promote(&e, LP_UPPER, LP_CASES_OK, &p);
        bool hit = zcl_alloc_fault_armed_label() == NULL;
        zcl_alloc_fault_clear();
        ASSERT(hit);
        ASSERT_STR_EQ(p.error.code, "LAB_ALLOC");
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

static bool lp_long_binary(const char *base, const char *binary, char path[PATH_MAX])
{
    static const char segment[] = "workspace_abcdefghijklmnopqrstuvwxyz_abcdefghijklmnopqrstuvwxyz";
    if (snprintf(path, PATH_MAX, "%s", base) >= PATH_MAX)
        return false;
    while (strlen(path) <= 1024) {
        size_t n = strlen(path);
        if (snprintf(path + n, PATH_MAX - n, "/%s", segment) >= (int)(PATH_MAX - n) ||
            mkdir(path, 0700) != 0)
            return false;
    }
    size_t n = strlen(path);
    return snprintf(path + n, PATH_MAX - n, "/fixture") < (int)(PATH_MAX - n) &&
           link(binary, path) == 0;
}

static bool lp_long_cleanup(const char *base, char path[PATH_MAX])
{
    bool ok = unlink(path) == 0;
    char *slash = strrchr(path, '/');
    while (slash && (size_t)(slash - path) > strlen(base)) {
        *slash = '\0';
        if (rmdir(path) != 0)
            ok = false;
        slash = strrchr(path, '/');
    }
    return ok;
}

static int lp_case_source_snapshot(void)
{
    int failures = 0;
    struct lp_env e;
    bool ready = lp_env_open(&e);
    TEST_CASE("promotion test and release use loaded bytes after the source path changes") {
        struct lab_ctx ctx;
        struct zcl_command_reply r;
        struct json_value input;
        char path[PATH_MAX], long_binary[PATH_MAX], in[PATH_MAX + 512];
        const char *source = "#include <stdio.h>\nint main(void) { puts(\"snapshot\"); return 0; }\n";
        ASSERT(ready);
        ASSERT(lp_join(path, sizeof(path), e.base, "snapshot.c"));
        FILE *f = fopen(path, "wb");
        ASSERT(f != NULL);
        ASSERT(fputs(source, f) >= 0);
        ASSERT_EQ(fclose(f), 0);
        zcl_command_reply_init(&r, "zcl.lab_test.v1");
        ASSERT(lab_ctx_open(&ctx, path, &r));
        /* A real edit after loading must not change either compilation. */
        f = fopen(path, "wb");
        ASSERT(f != NULL);
        ASSERT(fputs("this is not C\n", f) >= 0);
        ASSERT_EQ(fclose(f), 0);
        snprintf(in, sizeof(in), "{\"file\":\"%s\",\"fresh\":true,\"cases\":["
                 "{\"name\":\"snapshot\",\"expect_stdout\":\"snapshot\\n\"}]}", path);
        json_init(&input);
        ASSERT(json_read(&input, in, strlen(in)));
        struct zcl_command_request rq = { .input = &input };
        lab_test_context(&rq, &ctx, &r, NULL);
        ASSERT_EQ(r.exit_code, ZCL_COMMAND_EXIT_OK);
        ASSERT_EQ(json_get_int(json_get(&r.data, "passed")), 1);
        ASSERT_EQ(json_get_int(json_get(&r.data, "failed")), 0);
        struct lab_compile *rel = calloc(1, sizeof(*rel));
        ASSERT(rel != NULL);
        lab_compile_release(&ctx.dirs, &ctx.tc, &ctx.src, "snapshot-release", rel);
        ASSERT(rel->ok);
        size_t passed = 0, failed = 0;
        zcl_alloc_fault_fail_nth("lab.text", 1);
        enum lab_check check = lab_cases_check(&rq, &ctx, rel->binary, LAB_TIMEOUT_DEFAULT_MS,
                                               LAB_MEM_DEFAULT_MB, &passed, &failed, NULL);
        bool unused_row_alloc = zcl_alloc_fault_armed_label() != NULL;
        zcl_alloc_fault_clear();
        ASSERT_EQ(check, LAB_CHECK_RAN);
        ASSERT(unused_row_alloc);
        ASSERT_EQ(passed, 1);
        ASSERT_EQ(failed, 0);
        ASSERT(lp_long_binary(e.base, rel->binary, long_binary));
        zcl_alloc_fault_fail_nth("lab.compile", 1);
        check = lab_cases_check(&rq, &ctx, long_binary, LAB_TIMEOUT_DEFAULT_MS,
                                LAB_MEM_DEFAULT_MB, &passed, &failed, NULL);
        bool unused_compile_alloc = zcl_alloc_fault_armed_label() != NULL;
        zcl_alloc_fault_clear();
        bool removed_long = lp_long_cleanup(e.base, long_binary);
        ASSERT_EQ(check, LAB_CHECK_RAN);
        ASSERT(unused_compile_alloc);
        ASSERT(removed_long);
        ASSERT_EQ(passed, 1);
        ASSERT_EQ(failed, 0);
        lab_compile_cleanup(&ctx.dirs, "snapshot-release");
        free(rel);
        json_free(&input);
        lab_ctx_close(&ctx);
        zcl_command_reply_free(&r);
    } TEST_END
    lp_env_close(&e);
    return failures;
}

static int lp_case_cases_snapshot(void)
{
    int failures = 0;
    struct lp_env e;
    bool ready = lp_env_open(&e);
    TEST_CASE("promotion retains exact case file bytes before either build") {
        struct zcl_command_reply r;
        struct json_value input;
        struct lab_case_snapshot cases;
        char path[PATH_MAX], in[PATH_MAX + 64];
        ASSERT(ready);
        ASSERT(lp_join(path, sizeof(path), e.base, "cases.json"));
        FILE *f = fopen(path, "wb");
        ASSERT(f != NULL);
        ASSERT(fputs("  " LP_CASES_OK "\n", f) >= 0);
        ASSERT_EQ(fclose(f), 0);
        snprintf(in, sizeof(in), "{\"cases\":\"%s\"}", path);
        json_init(&input);
        ASSERT(json_read(&input, in, strlen(in)));
        struct zcl_command_request rq = { .input = &input };
        zcl_command_reply_init(&r, "zcl.lab_test.v1");
        /* A file snapshot needs its input buffer, but no execution-row array. */
        zcl_alloc_fault_fail_nth("lab.cases", 2);
        bool captured = lab_cases_snapshot(&rq, &cases, &r);
        zcl_alloc_fault_clear();
        ASSERT(captured);
        json_free(&input);
        ASSERT_EQ(unlink(path), 0);
        ASSERT_EQ(cases.value->type, JSON_STR);
        ASSERT_STR_EQ(json_get_str(cases.value), "  " LP_CASES_OK "\n");
        free(cases.file_text);
        json_free(&cases.parsed);
        zcl_command_reply_free(&r);
    } TEST_END
    lp_env_close(&e);
    return failures;
}

static int lp_case_snapshot_no_copy(void)
{
    int failures = 0;
    TEST_CASE("validation does not copy an inline case string") {
        struct json_value input;
        struct lab_case_snapshot cases;
        struct zcl_command_reply r;
        const char *text = "{\"cases\":\"[{\\\"name\\\":\\\"one\\\"}]\"}";
        json_init(&input);
        ASSERT(json_read(&input, text, strlen(text)));
        struct zcl_command_request rq = { .input = &input };
        zcl_command_reply_init(&r, "zcl.lab_test.v1");
        zcl_alloc_fault_fail_next("json_copy_str");
        bool captured = lab_cases_snapshot(&rq, &cases, &r);
        bool armed = zcl_alloc_fault_armed_label() != NULL;
        zcl_alloc_fault_clear();
        ASSERT(captured && armed);
        free(cases.file_text);
        json_free(&cases.parsed);
        json_free(&input);
        zcl_command_reply_free(&r);
    } TEST_END
    return failures;
}

static int lp_case_invalid_before_key(void)
{
    int failures = 0;
    struct lp_env e;
    bool ready = lp_env_open(&e);
    TEST_CASE("plugin.dev rejects invalid case inputs before creating a key") {
        struct zcl_command_reply r;
        char dir[PATH_MAX], key[PATH_MAX], cases[PATH_MAX], input[4 * PATH_MAX + 512];
        ASSERT(ready);
        ASSERT(lp_join(dir, sizeof dir, e.base, "upper"));
        ASSERT_EQ(mkdir(dir, 0700), 0);
        ASSERT(lp_join(key, sizeof key, e.base, "new.key"));
        ASSERT(lp_join(cases, sizeof cases, e.base, "invalid.json"));
        FILE *f = fopen(cases, "wb");
        ASSERT(f != NULL);
        ASSERT(fputs("[{\"name\":\"bad\",\"expect_exit\":999}]", f) >= 0);
        ASSERT_EQ(fclose(f), 0);
        const char *forms[] = { "[{\"name\":\"bad\",\"expect_exit\":999}]", NULL, "" };
        for (size_t i = 0; i < 3; i++) {
            char field[PATH_MAX + 64];
            if (i == 1) snprintf(field, sizeof field, ",\"cases\":\"%s\"", cases);
            else if (i == 0) snprintf(field, sizeof field, ",\"cases\":%s", forms[i]);
            else field[0] = 0;
            snprintf(input, sizeof input, "{\"dir\":\"%s\",\"file\":\"%s\",\"key\":\"%s\"%s}", dir, LP_UPPER, key, field);
            ASSERT(lp_call(zcl_native_handle_plugin_dev, input, &r));
            ASSERT_STR_EQ(r.error.code, "LAB_BAD_CASES");
            ASSERT(!r.error.mutated);
            ASSERT(access(key, F_OK) != 0);
            zcl_command_reply_free(&r);
        }
        snprintf(input, sizeof input, "{\"dir\":\"%s\",\"file\":\"%s\",\"key\":\"%s\",\"version\":\"bad\"}", dir, LP_UPPER, key);
        ASSERT(lp_call(zcl_native_handle_plugin_dev, input, &r));
        ASSERT_STR_EQ(r.error.code, "PLUGIN_VERSION");
        ASSERT(!r.error.mutated);
        zcl_command_reply_free(&r);
        snprintf(input, sizeof input, "{\"dir\":\"%s\",\"file\":\"%s\",\"key\":\"%s\",\"mem_mb\":0,\"cases\":[]}", dir, LP_UPPER, key);
        ASSERT(lp_call(zcl_native_handle_plugin_dev, input, &r));
        ASSERT_STR_EQ(r.error.code, "LAB_BAD_INPUT");
        ASSERT(!r.error.mutated);
        ASSERT(access(key, F_OK) != 0);
        zcl_command_reply_free(&r);
    } TEST_END
    lp_env_close(&e);
    return failures;
}

struct lp_file_probe { const char *path; bool armed; };

static bool lp_remove_cases_ready(void *context, struct zcl_command_reply *reply)
{
    (void)reply;
    struct lp_file_probe *probe = context;
    probe->armed = zcl_alloc_fault_armed_label() != NULL;
    zcl_alloc_fault_clear();
    return unlink(probe->path) == 0;
}

static int lp_case_ready_snapshot(void)
{
    int failures = 0;
    struct lp_env e;
    bool ready = lp_env_open(&e);
    TEST_CASE("promotion keeps its case snapshot across the ready callback") {
        static const char original[] = "  " LP_CASES_OK "\n";
        char path[PATH_MAX], output[PATH_MAX], in[4 * PATH_MAX + 512];
        struct json_value input;
        struct zcl_command_reply r;
        ASSERT(ready);
        ASSERT(lp_join(path, sizeof path, e.base, "ready-cases.json"));
        FILE *f = fopen(path, "wb");
        ASSERT(f != NULL);
        ASSERT(fputs(original, f) >= 0);
        ASSERT_EQ(fclose(f), 0);
        snprintf(in, sizeof in, "{\"file\":\"%s\",\"cases\":\"%s\",\"name\":\"upper\",\"version\":\"1.0.0\",\"key\":\"%s\",\"dir\":\"%s\",\"include-source\":true}", LP_UPPER, path, e.key, e.dist);
        json_init(&input);
        ASSERT(json_read(&input, in, strlen(in)));
        struct zcl_command_request request = { .input = &input };
        zcl_command_reply_init(&r, "zcl.lab_promote.v1");
        size_t before = lab_cases_test_parse_count();
        struct lp_file_probe probe = { .path = path };
        zcl_alloc_fault_fail_nth("json_copy_str", 2);
        lab_promote_with_ready(&request, lp_remove_cases_ready, &probe, &r);
        zcl_alloc_fault_clear();
        ASSERT(probe.armed);
        ASSERT_EQ(lab_cases_test_parse_count() - before, 1);
        ASSERT_EQ(r.exit_code, ZCL_COMMAND_EXIT_OK);
        ASSERT_EQ(json_get_int(json_get(&r.data, "cases_passed")), 2);
        ASSERT(lp_join(output, sizeof output, e.dist, "cases.json"));
        f = fopen(output, "rb");
        ASSERT(f != NULL);
        char bytes[sizeof original];
        size_t n = fread(bytes, 1, sizeof bytes, f);
        ASSERT_EQ(fclose(f), 0);
        ASSERT_EQ(n, sizeof original - 1);
        ASSERT(memcmp(bytes, original, n) == 0);
        zcl_command_reply_free(&r);
        json_free(&input);
    } TEST_END
    lp_env_close(&e);
    return failures;
}

static bool lp_change_cases_ready(void *context, struct zcl_command_reply *reply)
{
    (void)reply;
    struct json_value *input = context;
    for (size_t i = 0; i < input->num_children; i++) {
        if (strcmp(input->keys[i], "cases") == 0) {
            json_set_null(&input->children[i]);
            return true;
        }
    }
    return false;
}

struct lp_copy_probe {
    struct json_value *input;
    bool armed;
};

static bool lp_copy_probe_ready(void *context, struct zcl_command_reply *reply)
{
    struct lp_copy_probe *probe = context;
    probe->armed = zcl_alloc_fault_armed_label() != NULL;
    zcl_alloc_fault_clear();
    return lp_change_cases_ready(probe->input, reply);
}

static int lp_case_ready_values(void)
{
    int failures = 0;
    struct lp_env e;
    bool ready = lp_env_open(&e);
    TEST_CASE("promotion preserves array, inline and file cases before ready") {
        ASSERT(ready);
        for (size_t form = 0; form < 3; form++) {
            char in[4 * PATH_MAX + 1024], path[PATH_MAX], encoded[PATH_MAX + 1024];
            struct json_value input, inline_cases;
            struct zcl_command_reply r;
            json_init(&inline_cases);
            if (form == 1) json_set_str(&inline_cases, LP_CASES_OK);
            if (form == 2) {
                ASSERT(lp_join(path, sizeof(path), e.base, "no-export-cases.json"));
                FILE *f = fopen(path, "wb");
                ASSERT(f != NULL);
                ASSERT(fputs(LP_CASES_OK, f) >= 0);
                ASSERT_EQ(fclose(f), 0);
                json_set_str(&inline_cases, path);
            }
            if (form) {
                ASSERT_EQ(inline_cases.type, JSON_STR);
                ASSERT(json_write(&inline_cases, encoded, sizeof encoded) < sizeof encoded);
            }
            snprintf(in, sizeof in, "{\"file\":\"%s\",\"cases\":%s,\"name\":\"upper\",\"version\":\"1.0.0\",\"key\":\"%s\",\"dir\":\"%s\"}", LP_UPPER, form ? encoded : LP_CASES_OK, e.key, e.dist);
            json_free(&inline_cases);
            json_init(&input);
            ASSERT(json_read(&input, in, strlen(in)));
            struct zcl_command_request request = { .input = &input };
            zcl_command_reply_init(&r, "zcl.lab_promote.v1");
            size_t before = lab_cases_test_parse_count();
            if (form) {
                struct lp_copy_probe probe = { .input = &input };
                /* The first json_copy_str forwards file; the second was cases. */
                zcl_alloc_fault_fail_nth("json_copy_str", 2);
                lab_promote_with_ready(&request, lp_copy_probe_ready, &probe, &r);
                zcl_alloc_fault_clear();
                ASSERT(probe.armed);
            } else {
                lab_promote_with_ready(&request, lp_change_cases_ready, &input, &r);
            }
            ASSERT_EQ(lab_cases_test_parse_count() - before, form ? 1 : 0);
            ASSERT_EQ(r.exit_code, ZCL_COMMAND_EXIT_OK);
            ASSERT_EQ(json_get_int(json_get(&r.data, "cases_passed")), 2);
            ASSERT(json_is_null(json_get(&input, "cases")));
            zcl_command_reply_free(&r);
            json_free(&input);
        }
    } TEST_END
    lp_env_close(&e);
    return failures;
}

static bool lp_dev_source(const char *dir, const char *file, const char *cases,
                          struct zcl_command_reply *r)
{
    char in[4 * PATH_MAX + 1024];
    snprintf(in, sizeof(in), "{\"dir\":\"%s\",\"file\":\"%s\",\"cases\":%s,"
             "\"interface\":2,\"sanitize\":true,\"mem_mb\":256,\"timeout_ms\":5000,\"include-source\":true}",
             dir, file, cases);
    const struct zcl_command_spec *spec =
        zcl_command_registry_find(zcl_command_catalog(), "plugin.dev", NULL);
    return spec && lp_invoke(spec->handler, spec, in, r);
}

static bool lp_promote_export(const struct lp_env *e, const char *name,
                              struct zcl_command_reply *reply)
{
    char input[4 * PATH_MAX + 1024];
    int n = snprintf(input, sizeof(input),
                     "{\"file\":\"" LP_UPPER "\",\"cases\":%s,\"name\":\"%s\","
                     "\"version\":\"1.0.0\",\"key\":\"%s\",\"dir\":\"%s\","
                     "\"include-source\":true}", LP_CASES_OK, name, e->key, e->dist);
    return n > 0 && (size_t)n < sizeof(input) &&
           lp_call(zcl_native_handle_lab_promote, input, reply);
}

static bool lp_text_is(const char *path, const char *expected)
{
    char bytes[256];
    FILE *f = fopen(path, "rb");
    if (!f) return false;
    size_t n = fread(bytes, 1, sizeof(bytes), f);
    bool ok = !ferror(f) && n == strlen(expected) && memcmp(bytes, expected, n) == 0;
    return fclose(f) == 0 && ok;
}

static int lp_case_compiler_sidecar(void)
{
    int failures = 0;
    struct lp_env e;
    bool ready = lp_env_open(&e);
    TEST_CASE("source export owns only its marked compiler-name sidecar") {
        char path[PATH_MAX];
        struct zcl_command_reply r;
        ASSERT(ready);
        ASSERT(lab_compiler_name_valid("upper.c"));
        ASSERT(!lab_compiler_name_valid("-option.c"));
        ASSERT(!lab_compiler_name_valid("../other.c"));
        ASSERT_EQ(mkdir(e.dist, 0700), 0);
        ASSERT(lp_join(path, sizeof(path), e.dist, LAB_COMPILER_NAME_FILE));
        FILE *f = fopen(path, "wb");
        ASSERT(f != NULL);
        ASSERT(fputs("caller data", f) >= 0);
        ASSERT_EQ(fclose(f), 0);
        ASSERT(lp_promote_export(&e, "upper", &r));
        ASSERT_EQ(r.exit_code, ZCL_COMMAND_EXIT_OK);
        zcl_command_reply_free(&r);
        ASSERT(lp_text_is(path, "caller data"));
        ASSERT(lp_promote_export(&e, "alias", &r));
        ASSERT_STR_EQ(r.error.code, "LAB_PROMOTE_EXPORT_FAILED");
        zcl_command_reply_free(&r);
        ASSERT(lp_text_is(path, "caller data"));
        ASSERT_EQ(unlink(path), 0);
        ASSERT(lp_promote_export(&e, "alias", &r));
        ASSERT_EQ(r.exit_code, ZCL_COMMAND_EXIT_OK);
        zcl_command_reply_free(&r);
        ASSERT(lp_text_is(path, LAB_COMPILER_NAME_MARKER "upper.c"));
        ASSERT(lp_promote_export(&e, "upper", &r));
        ASSERT_EQ(r.exit_code, ZCL_COMMAND_EXIT_OK);
        zcl_command_reply_free(&r);
        ASSERT(access(path, F_OK) != 0 && errno == ENOENT);
    } TEST_END
    lp_env_close(&e);
    return failures;
}


static int lp_case_export_borrow(void)
{
    int failures = 0;
    struct lp_env e;
    bool ready = lp_env_open(&e);
    TEST_CASE("plugin.dev exports exact case file without another allocation") {
        static const char original[] = "  " LP_CASES_OK "\n";
        char dir[PATH_MAX], path[PATH_MAX], cases[PATH_MAX + 4], output[PATH_MAX];
        struct zcl_command_reply r;
        ASSERT(ready);
        ASSERT(lp_join(dir, sizeof dir, e.base, "upper"));
        ASSERT_EQ(mkdir(dir, 0700), 0);
        ASSERT(lp_join(path, sizeof path, e.base, "cases.json"));
        FILE *f = fopen(path, "wb");
        ASSERT(f != NULL);
        ASSERT(fputs(original, f) >= 0);
        ASSERT_EQ(fclose(f), 0);
        ASSERT(snprintf(cases, sizeof cases, "\"%s\"", path) > 0);
        zcl_alloc_fault_fail_next("lab.promote.cases");
        bool called = lp_dev_source(dir, LP_UPPER, cases, &r);
        bool armed = zcl_alloc_fault_armed_label() != NULL;
        zcl_alloc_fault_clear();
        ASSERT(called);
        ASSERT_EQ(r.exit_code, ZCL_COMMAND_EXIT_OK);
        ASSERT(armed);
        ASSERT(lp_join(output, sizeof output, dir, "dist/cases.json"));
        f = fopen(output, "rb");
        ASSERT(f != NULL);
        char bytes[sizeof original];
        size_t n = fread(bytes, 1, sizeof bytes, f);
        ASSERT_EQ(fclose(f), 0);
        ASSERT_EQ(n, sizeof original - 1);
        ASSERT(memcmp(bytes, original, n) == 0);
        zcl_command_reply_free(&r);
        zcl_alloc_fault_fail_next("lab.promote.cases");
        called = lp_dev_source(dir, LP_UPPER, LP_CASES_OK, &r);
        bool fired = zcl_alloc_fault_armed_label() == NULL;
        zcl_alloc_fault_clear();
        ASSERT(called && fired);
        ASSERT_STR_EQ(r.error.code, "LAB_PROMOTE_EXPORT_FAILED");
        ASSERT(r.error.mutated);
        zcl_command_reply_free(&r);
    } TEST_END
    lp_env_close(&e);
    return failures;
}

/* plugin.call upper on "abc\n": its stdout, or "?" when the call did not succeed. */
static void lp_call_upper(char out[32], char generation[PLUGIN_HEX_SHA3_512 + 1])
{
    struct zcl_command_reply c;
    snprintf(out, 32, "?");
    generation[0] = '\0';
    if (!lp_call(zcl_native_handle_plugin_call, "{\"name\":\"upper\",\"stdin\":\"abc\\n\"}", &c))
        return;
    if (c.exit_code == ZCL_COMMAND_EXIT_OK) {
        snprintf(out, 32, "%s", lp_str(json_get(&c.data, "run"), "stdout"));
        snprintf(generation, PLUGIN_HEX_SHA3_512 + 1, "%s", lp_str(&c.data, "generation"));
    }
    zcl_command_reply_free(&c);
}

static bool lp_name_op(lp_handler h, const char *in, struct zcl_command_reply *r)
{
    bool ok = lp_call(h, in, r) && r->exit_code == ZCL_COMMAND_EXIT_OK;
    zcl_command_reply_free(r);
    return ok;
}

/* One source file becomes a proved, signed and current generation in one call. */
static bool lp_develop(const char *dir, const char *file, const char *cases,
                       char gen[PLUGIN_HEX_SHA3_512 + 1], int64_t *seq)
{
    struct zcl_command_reply r;
    if (!lp_dev_source(dir, file, cases, &r))
        return false;
    const struct json_value *proof = json_get(&r.data, "proof");
    bool ok = r.exit_code == ZCL_COMMAND_EXIT_OK && r.next_count == 0 &&
              json_size(json_get(&r.data, "steps")) == 5u && proof &&
              json_get_int(json_get(proof, "cases_passed")) > 0 &&
              strlen(lp_str(proof, "lab_root")) == PLUGIN_HEX_SHA3_512 &&
              strlen(lp_str(proof, "release_sha3_512")) == PLUGIN_HEX_SHA3_512;
    if (ok) {
        snprintf(gen, PLUGIN_HEX_SHA3_512 + 1, "%s", lp_str(&r.data, "generation"));
        *seq = json_get_int(json_get(&r.data, "sequence"));
    }
    zcl_command_reply_free(&r);
    return ok;
}

/* The store holds count generations, each with a signature, current on cur. */
static bool lp_store_is(const struct lp_env *e, size_t count, const char *cur, const char *gens[2])
{
    struct plugin_info *infos = NULL;
    size_t n = 0;
    bool ok = plugin_store_list(e->root, &infos, &n) == PLUGIN_OK && n == 1 &&
              infos[0].generation_count == count && strcmp(infos[0].current, cur) == 0;
    if (infos)
        plugin_store_list_free(infos, n);
    for (int i = 0; ok && i < 2; i++) {
        char sig[2 * PATH_MAX];
        snprintf(sig, sizeof(sig), "%s/upper/generations/%s/upper.plugin.sig", e->root, gens[i]);
        ok = access(sig, R_OK) == 0;
    }
    return ok;
}

/* The agent loop: dev, call, edit, dev, call (no restart), failed gates, rollback, switch. */
static int lp_case_hotswap(void)
{
    int failures = 0;
    struct lp_env e;
    bool ready = lp_env_open(&e);
    TEST_CASE("plugin dev hot-swaps: the next plugin.call runs the edited program, rollback restores") {
        struct zcl_command_reply r;
        char dir[PATH_MAX], out[32], seen[PLUGIN_HEX_SHA3_512 + 1];
        char g1[PLUGIN_HEX_SHA3_512 + 1], g2[PLUGIN_HEX_SHA3_512 + 1], in[1024];
        int64_t seq = 0;
        ASSERT(ready);
        ASSERT(lp_join(dir, sizeof(dir), e.base, "upper"));
        ASSERT_EQ(mkdir(dir, 0700), 0);
        /* Generation 1: build, prove and activate the source in one call. */
        static const char case_bytes[] = "  " LP_CASES_OK "\n";
        char case_path[PATH_MAX], case_arg[PATH_MAX + 3], packed_cases[PATH_MAX];
        ASSERT(lp_join(case_path, sizeof(case_path), e.base, "development-cases.json"));
        FILE *case_file = fopen(case_path, "wb");
        ASSERT(case_file != NULL);
        ASSERT(fputs(case_bytes, case_file) >= 0);
        ASSERT_EQ(fclose(case_file), 0);
        snprintf(case_arg, sizeof(case_arg), "\"%s\"", case_path);
        ASSERT(lp_develop(dir, LP_UPPER, case_arg, g1, &seq));
        ASSERT(lp_join(packed_cases, sizeof(packed_cases), dir, "dist/cases.json"));
        case_file = fopen(packed_cases, "rb");
        ASSERT(case_file != NULL);
        char exported[sizeof(case_bytes)];
        size_t exported_len = fread(exported, 1, sizeof(exported), case_file);
        ASSERT_EQ(fclose(case_file), 0);
        ASSERT_EQ(exported_len, sizeof(case_bytes) - 1);
        ASSERT(memcmp(exported, case_bytes, exported_len) == 0);
        ASSERT_EQ(seq, 1);
        lp_call_upper(out, seen);
        ASSERT_STR_EQ(out, "ABC\n");
        ASSERT_STR_EQ(seen, g1);
        /* Edit: the source becomes the reverser. Same process, no restart. */
        ASSERT(lp_develop(dir, "tests/fixtures/lab/rev.c",
                          "[{\"name\":\"rev\",\"stdin\":\"abc\\n\",\"expect_stdout\":\"cba\\n\"}]",
                          g2, &seq));
        ASSERT_EQ(seq, 2);
        ASSERT(strcmp(g1, g2) != 0);
        lp_call_upper(out, seen);
        ASSERT_STR_EQ(out, "cba\n");
        ASSERT_STR_EQ(seen, g2);
        ASSERT(lp_store_is(&e, 2, g2, (const char *[2]){ g1, g2 }));
        /* The same one-call path refuses failed cases and compiler errors. */
        char unsanitized[PATH_MAX + 1024];
        snprintf(unsanitized, sizeof(unsanitized), "{\"dir\":\"%s\",\"file\":\"%s\","
                 "\"cases\":%s,\"sanitize\":false}", dir, LP_UPPER, LP_CASES_OK);
        ASSERT(lp_call(zcl_native_handle_plugin_dev, unsanitized, &r));
        ASSERT_STR_EQ(r.error.code, "LAB_PROMOTE_SANITIZER_REQUIRED");
        ASSERT(r.exit_code != ZCL_COMMAND_EXIT_OK);
        zcl_command_reply_free(&r);
        ASSERT(lp_store_is(&e, 2, g2, (const char *[2]){ g1, g2 }));
        const char *bad_files[] = { "null", "42", "{}", "[]", "true", "\"\"" };
        for (size_t i = 0; i < sizeof(bad_files) / sizeof(bad_files[0]); i++) {
            char malformed[PATH_MAX + 128];
            snprintf(malformed, sizeof(malformed), "{\"dir\":\"%s\",\"file\":%s}",
                     dir, bad_files[i]);
            ASSERT(lp_call(zcl_native_handle_plugin_dev, malformed, &r));
            ASSERT_EQ(r.exit_code, ZCL_COMMAND_EXIT_INVALID);
            ASSERT_STR_EQ(r.error.code, "PLUGIN_ARGUMENT");
            ASSERT(!r.error.mutated);
            zcl_command_reply_free(&r);
            ASSERT(lp_store_is(&e, 2, g2, (const char *[2]){ g1, g2 }));
        }
        ASSERT(lp_dev_source(dir, "tests/fixtures/lab/rev.c",
                             "[{\"name\":\"wrong\",\"stdin\":\"abc\\n\",\"expect_stdout\":\"ABC\\n\"}]", &r));
        ASSERT_STR_EQ(r.error.code, "LAB_PROMOTE_CASES_FAILED");
        zcl_command_reply_free(&r);
        ASSERT(lp_dev_source(dir, "tests/fixtures/lab/compile_error.c", LP_CASES_OK, &r));
        ASSERT(r.exit_code != ZCL_COMMAND_EXIT_OK);
        ASSERT_STR_EQ(r.error.code, "LAB_PROMOTE_CASES_FAILED");
        zcl_command_reply_free(&r);
        lp_call_upper(out, seen);
        ASSERT_STR_EQ(out, "cba\n");
        ASSERT_STR_EQ(seen, g2);
        ASSERT(lp_store_is(&e, 2, g2, (const char *[2]){ g1, g2 }));
        /* Rollback restores generation 1; switch returns to generation 2. */
        ASSERT(lp_name_op(zcl_native_handle_plugin_rollback, "{\"name\":\"upper\"}", &r));
        lp_call_upper(out, seen);
        ASSERT_STR_EQ(out, "ABC\n");
        ASSERT_STR_EQ(seen, g1);
        snprintf(in, sizeof(in), "{\"name\":\"upper\",\"generation\":\"%s\"}", g2);
        ASSERT(lp_name_op(zcl_native_handle_plugin_switch, in, &r));
        lp_call_upper(out, seen);
        ASSERT_STR_EQ(out, "cba\n");
        ASSERT_STR_EQ(seen, g2);
    } TEST_END
    lp_env_close(&e);
    return failures;
}

int test_lab_promote(void)
{
    int failures = 0;
    printf("\n=== Lab promote tests ===\n");
    failures += lp_case_roundtrip();
    failures += lp_case_pack_receipt_allocation();
    failures += lp_case_hotswap();
    failures += lp_case_invalid_before_key();
    failures += lp_case_ready_snapshot();
    failures += lp_case_ready_values();
    failures += lp_case_export_borrow();
    failures += lp_case_compiler_sidecar();
    failures += lp_case_failed_case();
    failures += lp_case_compile_failed();
    failures += lp_case_release_compile_failed();
    failures += lp_case_disagree();
    failures += lp_case_capture_allocation();
    failures += lp_case_no_key();
    failures += lp_case_source_snapshot();
    failures += lp_case_cases_snapshot();
    failures += lp_case_snapshot_no_copy();
    return failures;
}
#endif
