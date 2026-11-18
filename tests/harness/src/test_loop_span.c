/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: one span token discovered, rebuilt as a leaf, admitted by
 * plugin.dev, and proved. The second pass reuses those records.
 * Provider token counters are not on this host and stay unknown.
 */

#include "test/test_core.h"
#include "test/testcache.h"

#include "base/hex.h"
#include "command/native_command.h"
#include "controllers/loop_span.h"
#include "dev/dev_proof_receipt.h"
#include "dev/devloop.h"
#include "json/json.h"
#include "plugin/plugin_dev.h"
#include "sha3/sha3.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <unistd.h>

extern int code_commands_for_symbol(const char *symbol_name,
                                    const char **out, int cap);
extern enum plugin_status plugin_verify_generation(const char *root,
                                                   const char *name,
                                                   const char *generation);

struct ls_obs {
    char root[PATH_MAX];
    char work[PATH_MAX];
    char cache[PATH_MAX];
    char exe[PATH_MAX];
    char exe_a[PATH_MAX];
    char exe_b[PATH_MAX];
    char store_a[PATH_MAX];
    char plan[16384];
    char cache_key[65];
    char cache_key2[65];
    char artifact_sha[65];
    char head[41];
    char inputs[65];
    char inputs_bad[65];
    char generation[PLUGIN_HEX_SHA3_512 + 1];
    char sha3[PLUGIN_HEX_SHA3_512 + 1];
    char receipt_hex[ZCL_DEV_PROOF_WIRE_BYTES * 2 + 1];
    uint8_t source_digest[32];
    size_t plan_len;
    uint64_t discovery_us;
    uint64_t discovery_bytes;
    uint64_t build1_us;
    uint64_t plugin_us;
    uint64_t build2_us;
    uint64_t test_us;
    uint64_t test_bytes;
    uint64_t lint_us;
    uint64_t admit_us;
    uint64_t pass2_discovery_us;
    uint64_t pass2_discovery_bytes;
    uint64_t pass2_test_us;
    uint64_t pass2_test_bytes;
    uint32_t token;
    uint32_t hs_cc;
    uint32_t hs_ld;
    uint32_t cc1;
    uint32_t ld1;
    uint32_t cc2;
    uint32_t ld2;
    int source_reads;
    int pass2_source_reads;
    int groups_ran;
    int groups_cached;
    int pass2_groups_ran;
    int pass2_groups_cached;
    int pass2_hash_reads;
    int pass2_memo_hits;
    int warm_hit;
    int dev_steps;
    char route[64];
    char route2[64];
    char tree_prior[65];
    char tree_now[65];
};

static struct ls_obs g_obs;
static char g_records[8192];
static char g_old_cache[4096];
static char g_old_process[16];
static int g_had_cache;
static int g_had_process;
static struct zcl_devloop_process_result *g_proc;

static struct zcl_devloop_process_result *ls_proc(void)
{
    if (!g_proc)
        g_proc = calloc(1, sizeof(*g_proc));
    return g_proc;
}

static bool ls_now(uint64_t *out)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
        return false;
    *out = (uint64_t)ts.tv_sec * 1000000ull + (uint64_t)ts.tv_nsec / 1000ull;
    return true;
}

static bool ls_join(char *out, size_t cap, const char *a, const char *b)
{
    int n = snprintf(out, cap, "%s/%s", a, b);
    return n > 0 && (size_t)n < cap;
}

static bool ls_invoke(void (*fn)(const struct zcl_command_request *,
                                 struct zcl_command_reply *),
                      const char *text, struct zcl_command_reply *reply,
                      const char *schema)
{
    struct json_value in;
    struct zcl_command_request req;
    zcl_command_reply_init(reply, schema);
    json_init(&in);
    memset(&req, 0, sizeof req);
    if (!json_read(&in, text, strlen(text))) {
        json_free(&in);
        zcl_command_reply_free(reply);
        return false;
    }
    req.input = &in;
    fn(&req, reply);
    json_free(&in);
    return true;
}

static bool ls_field(const struct zcl_command_reply *reply, const char *key,
                     const char *want)
{
    const struct json_value *v = json_get(&reply->data, key);
    return v && v->type == JSON_STR && strcmp(json_get_str(v), want) == 0;
}

static bool ls_add_file(struct ls_obs *o, const char *rel, int digest_it)
{
    char path[PATH_MAX];
    FILE *f;
    struct sha3_256_ctx ctx;
    unsigned char buf[4096];
    size_t n;
    int nw = snprintf(path, sizeof path, "%s/%s", o->root, rel);
    if (nw <= 0 || (size_t)nw >= sizeof path)
        return false;
    f = fopen(path, "rb");
    if (!f)
        return false;
    sha3_256_init(&ctx);
    while ((n = fread(buf, 1, sizeof buf, f)) > 0) {
        sha3_256_write(&ctx, buf, n);
        o->discovery_bytes += n;
    }
    if (ferror(f)) {
        fclose(f);
        return false;
    }
    fclose(f);
    o->source_reads++;
    if (digest_it)
        sha3_256_finalize(&ctx, o->source_digest);
    return true;
}

static bool ls_discover_files(struct ls_obs *o)
{
    uint64_t t0 = 0;
    uint64_t t1 = 0;
    if (!ls_now(&t0))
        return false;
    if (!ls_add_file(o, "engine/controllers/src/loop_span_controller.c", 1) ||
        !ls_add_file(o, "engine/controllers/include/controllers/loop_span.h", 0) ||
        !ls_add_file(o, "tests/harness/fixtures/loop_span_plugin.c", 0))
        return false;
    if (!ls_now(&t1))
        return false;
    o->discovery_us = t1 - t0;
    zcl_hex_encode(o->source_digest, sizeof o->source_digest, o->inputs);
    return o->source_reads == 3 && o->inputs[0];
}

static bool ls_owner(void)
{
    struct zcl_command_reply reply;
    const struct json_value *exists;
    bool ok;
    if (!ls_invoke(zcl_native_handle_code_owner,
                   "{\"path\":\"engine/controllers/src/loop_span_controller.c\"}",
                   &reply, "zcl.code_owner.v1"))
        return false;
    exists = json_get(&reply.data, "exists");
    ok = reply.status == ZCL_COMMAND_STATUS_PASSED && exists &&
         exists->type == JSON_BOOL && json_get_bool(exists) &&
         ls_field(&reply, "authority", "engine") &&
         ls_field(&reply, "shape", "controllers");
    if (!ok)
        printf("code_owner status=%d\n", (int)reply.status);
    else
        printf("code_owner authority=engine shape=controllers exists=1\n");
    zcl_command_reply_free(&reply);
    return ok;
}

static bool ls_symbol(void)
{
    const char *paths[4] = {0};
    int n = code_commands_for_symbol("zcl_native_handle_loop_span", paths, 4);
    if (n != 1 || !paths[0] || strcmp(paths[0], "dev.loop.span") != 0) {
        printf("code_symbol count=%d\n", n);
        return false;
    }
    printf("code_symbol leaf=dev.loop.span\n");
    return true;
}

static bool ls_route_into(char *out, size_t cap)
{
    struct zcl_command_reply reply;
    const struct json_value *route;
    bool ok;
    if (!ls_invoke(zcl_native_handle_code_tests,
                   "{\"path\":\"engine/controllers/src/loop_span_controller.c\"}",
                   &reply, "zcl.code_tests.v1"))
        return false;
    route = json_get(&reply.data, "route");
    ok = reply.status == ZCL_COMMAND_STATUS_PASSED && route &&
         route->type == JSON_STR &&
         snprintf(out, cap, "%s", json_get_str(route)) > 0;
    if (!ok)
        printf("code_tests status=%d\n", (int)reply.status);
    else
        printf("code_tests route=%s\n", out);
    zcl_command_reply_free(&reply);
    return ok && strcmp(out, "loop_span") == 0;
}

static bool ls_span_reply(struct zcl_command_reply *reply)
{
    struct json_value in;
    struct zcl_command_request req;
    zcl_command_reply_init(reply, "zcl.loop_span.v1");
    json_init(&in);
    memset(&req, 0, sizeof req);
    if (!json_read(&in, "{\"text\":\"span\"}", 15)) {
        json_free(&in);
        zcl_command_reply_free(reply);
        return false;
    }
    req.input = &in;
    zcl_native_handle_loop_span(&req, reply);
    json_free(&in);
    return true;
}

static bool ls_direct(struct ls_obs *o)
{
    struct zcl_command_reply reply;
    const struct json_value *token;
    uint64_t t0 = 0;
    uint64_t t1 = 0;
    uint32_t folded = zcl_loop_span_token(ZCL_LOOP_SPAN_TEXT, 4);
    if (folded != ZCL_LOOP_SPAN_SPEC || !ls_now(&t0))
        return false;
    if (!ls_span_reply(&reply))
        return false;
    token = json_get(&reply.data, "token");
    if (!ls_now(&t1)) {
        zcl_command_reply_free(&reply);
        return false;
    }
    o->token = folded;
    o->test_us = t1 - t0;
    if (reply.status != ZCL_COMMAND_STATUS_PASSED || !token ||
        token->type != JSON_INT || json_get_int(token) != (int64_t)folded) {
        zcl_command_reply_free(&reply);
        return false;
    }
    zcl_command_reply_free(&reply);
    printf("direct_token token=%u\n", folded);
    return true;
}

static bool ls_plan(struct ls_obs *o)
{
    char path[PATH_MAX];
    FILE *f;
    size_t n;
    int nw = snprintf(path, sizeof path, "%s/build/hotswap-fast/flags.env", o->root);
    if (nw <= 0 || (size_t)nw >= sizeof path)
        return false;
    f = fopen(path, "r");
    if (!f) {
        printf("resident action plan absent\n");
        return false;
    }
    n = fread(o->plan, 1, sizeof o->plan - 1, f);
    if (ferror(f) || !feof(f)) {
        printf("resident action plan unread size=%zu cap=%zu\n", n,
               sizeof o->plan);
        fclose(f);
        return false;
    }
    fclose(f);
    o->plan[n] = 0;
    o->plan_len = n;
    if (strstr(o->plan, "-flto") || !strstr(o->plan, "HOTSWAP_MODULE_LDFLAGS=")) {
        printf("module_ldflags lto=1\n");
        return false;
    }
    printf("module_ldflags lto=0\n");
    return true;
}

static bool ls_cache_on(const char *dir)
{
    const char *old = getenv("ZCL_DEV_ARTIFACT_CACHE");
    g_had_cache = old && old[0];
    if (g_had_cache && strlen(old) >= sizeof g_old_cache)
        return false;
    if (g_had_cache)
        memcpy(g_old_cache, old, strlen(old) + 1);
    return setenv("ZCL_DEV_ARTIFACT_CACHE", dir, 1) == 0;
}

static void ls_cache_off(void)
{
    if (g_had_cache)
        setenv("ZCL_DEV_ARTIFACT_CACHE", g_old_cache, 1);
    else
        unsetenv("ZCL_DEV_ARTIFACT_CACHE");
}

/* ZCL_TESTING refuses zcl_devloop_process_run until the fixture opts in.
 * The value 1 enables the real fork/exec path. It is not a compiler stub;
 * that stub also requires ZCL_DEVLOOP_TEST_FORCE_CACHE_COPY. */
static bool ls_process_on(void)
{
    const char *old = getenv("ZCL_DEVLOOP_TEST_PROCESS");
    g_had_process = old && old[0];
    if (g_had_process && strlen(old) >= sizeof g_old_process)
        return false;
    if (g_had_process)
        memcpy(g_old_process, old, strlen(old) + 1);
    return setenv("ZCL_DEVLOOP_TEST_PROCESS", "1", 1) == 0;
}

static void ls_process_off(void)
{
    if (g_had_process)
        setenv("ZCL_DEVLOOP_TEST_PROCESS", g_old_process, 1);
    else
        unsetenv("ZCL_DEVLOOP_TEST_PROCESS");
}

static bool ls_swap_call(struct ls_obs *o,
                         struct zcl_devloop_hotswap_build_receipt *rec,
                         uint64_t *us)
{
    struct zcl_devloop_process_result *proc = ls_proc();
    char why[256];
    uint64_t t0 = 0;
    uint64_t t1 = 0;
    bool ok;
    if (!proc || !ls_now(&t0))
        return false;
    memset(rec, 0, sizeof *rec);
    why[0] = 0;
    ok = zcl_devloop_hotswap_build(
        o->root, "engine/controllers/src/loop_span_controller.c", rec, proc, why,
        sizeof why);
    if (!ok || !ls_now(&t1)) {
        printf("hotswap refused %s\n", why);
        if (proc && proc->output_len)
            printf("hotswap output %.*s\n",
                   proc->output_len > 400 ? 400 : (int)proc->output_len,
                   proc->output);
        return false;
    }
    if (strcmp(rec->source_tu, "engine/controllers/src/loop_span_controller.c") != 0) {
        printf("hotswap source_tu %s\n", rec->source_tu);
        return false;
    }
    *us = t1 - t0;
    return true;
}

static bool ls_swap_cold(struct ls_obs *o)
{
    struct zcl_devloop_hotswap_build_receipt rec;
    uint64_t us = 0;
    if (!ls_swap_call(o, &rec, &us))
        return false;
    if (rec.compiler_processes == 0 || rec.linker_processes != 1 ||
        rec.artifact_cache_hit) {
        printf("cold compiler=%u linker=%u hit=%d\n", rec.compiler_processes,
               rec.linker_processes, (int)rec.artifact_cache_hit);
        return false;
    }
    o->build1_us = us;
    o->hs_cc = rec.compiler_processes;
    o->hs_ld = rec.linker_processes;
    snprintf(o->cache_key, sizeof o->cache_key, "%s", rec.artifact_cache_key);
    snprintf(o->artifact_sha, sizeof o->artifact_sha, "%s", rec.artifact_sha256);
    printf("leaf_rebuild pass=1 compiler_processes=%u linker_processes=%u "
           "whole_graph_links=0 lto=0 cache_hit=0\n",
           rec.compiler_processes, rec.linker_processes);
    if (!o->cache_key[0] || !o->artifact_sha[0]) {
        printf("cold key=%d sha=%d cache_key_miss=%s action_root_miss=%s "
               "detail=%s\n",
               o->cache_key[0] != 0, o->artifact_sha[0] != 0,
               rec.cache_key_miss, rec.action_root_miss,
               rec.action_root_miss_detail);
        return false;
    }
    return true;
}

static bool ls_swap_warm(struct ls_obs *o)
{
    struct zcl_devloop_hotswap_build_receipt rec;
    uint64_t us = 0;
    if (!ls_swap_call(o, &rec, &us))
        return false;
    if (rec.compiler_processes != 0 || rec.linker_processes != 0 ||
        !rec.artifact_cache_hit ||
        strcmp(rec.artifact_cache_key, o->cache_key) != 0) {
        printf("warm compiler=%u linker=%u hit=%d miss=%s\n",
               rec.compiler_processes, rec.linker_processes,
               (int)rec.artifact_cache_hit, rec.cache_key_miss);
        return false;
    }
    o->build2_us = us;
    o->warm_hit = rec.artifact_cache_hit ? 1 : 0;
    o->cc2 = rec.compiler_processes;
    o->ld2 = rec.linker_processes;
    snprintf(o->cache_key2, sizeof o->cache_key2, "%s", rec.artifact_cache_key);
    printf("leaf_rebuild pass=2 compiler_processes=%u linker_processes=%u "
           "whole_graph_links=0 lto=0 cache_hit=%d\n",
           o->cc2, o->ld2, o->warm_hit);
    return true;
}

static bool ls_mkdir(const char *path);

static bool ls_cc(struct ls_obs *o)
{
    struct zcl_devloop_process_result *proc = ls_proc();
    char dir[PATH_MAX];
    const char *argv[] = {
        "/usr/bin/cc", "-std=c23", "-O2", "-Wall", "-Wextra", "-Werror",
        "-I", "engine/controllers/include", "-o", o->exe,
        "tests/harness/fixtures/loop_span_plugin.c", NULL};
    uint64_t t0 = 0;
    uint64_t t1 = 0;
    if (!proc || !ls_join(dir, sizeof dir, o->work, "plug") || !ls_mkdir(dir) ||
        !ls_join(o->exe, sizeof o->exe, dir, "loopspan") || !ls_now(&t0))
        return false;
    if (!zcl_devloop_process_run(o->root, argv, 120000, proc) || proc->exit_code != 0) {
        printf("plugin_cc exit=%d %s\n", proc->exit_code, proc->output);
        return false;
    }
    if (!ls_now(&t1))
        return false;
    o->plugin_us = t1 - t0;
    o->cc1 = o->hs_cc + 1;
    o->ld1 = o->hs_ld + 1;
    printf("plugin_cc compiler_processes=1 linker_processes=1\n");
    return true;
}

static bool ls_mkdir(const char *path)
{
    if (mkdir(path, 0700) == 0)
        return true;
    return errno == EEXIST && chmod(path, 0700) == 0;
}

static bool ls_copy_field(char *dst, size_t cap, const struct json_value *v)
{
    const char *s;
    if (!v || v->type != JSON_STR)
        return false;
    s = json_get_str(v);
    return s && snprintf(dst, cap, "%s", s) < (int)cap && dst[0] != 0;
}

static bool ls_dev_call(const char *dir, const char *key, struct zcl_command_reply *reply)
{
    char text[PATH_MAX * 2];
    int n = snprintf(text, sizeof text,
                     "{\"dir\":\"%s\",\"name\":\"loopspan\",\"version\":\"1.0.0\","
                     "\"key\":\"%s\",\"cap\":[\"clock\"],\"interface\":2}",
                     dir, key);
    if (n < 0 || (size_t)n >= sizeof text)
        return false;
    return ls_invoke(zcl_native_handle_plugin_dev, text, reply, "zcl.plugin_dev.v1");
}

static bool ls_dev_take(struct ls_obs *o, const struct zcl_command_reply *reply,
                        char *manifest, size_t manifest_cap, char *pub, size_t pub_cap)
{
    const struct json_value *steps = json_get(&reply->data, "steps");
    const struct json_value *cur = json_get(&reply->data, "current");
    if (reply->exit_code != ZCL_COMMAND_EXIT_OK) {
        printf("plugin_dev %s\n", reply->error.code);
        return false;
    }
    if (!steps || steps->type != JSON_ARR || !cur || !json_get_bool(cur))
        return false;
    o->dev_steps = (int)json_size(steps);
    if (o->dev_steps != 5)
        return false;
    if (!ls_copy_field(o->generation, sizeof o->generation,
                       json_get(&reply->data, "generation")) ||
        !ls_copy_field(manifest, manifest_cap, json_get(&reply->data, "manifest")) ||
        !ls_copy_field(pub, pub_cap, json_get(&reply->data, "public_key")))
        return false;
    printf("plugin_dev name=loopspan steps=%d generation=%s\n",
           o->dev_steps, o->generation);
    return true;
}

static bool ls_home_on(char *saved, size_t cap, int *had, const char *home)
{
    const char *old = getenv("HOME");
    *had = old != NULL;
    if (*had && snprintf(saved, cap, "%s", old) >= (int)cap)
        return false;
    return setenv("HOME", home, 1) == 0;
}

static void ls_home_off(const char *saved, int had)
{
    if (had)
        (void)setenv("HOME", saved, 1);
    else
        (void)unsetenv("HOME");
}

static bool ls_same_hash(const char *path, const char *want)
{
    char hex[PLUGIN_HEX_SHA3_512 + 1];
    if (plugin_hash_file(path, hex) != PLUGIN_OK)
        return false;
    return strcmp(hex, want) == 0;
}

static bool ls_exe_path(char *out, size_t cap, const char *root, const char *gen)
{
    int n = snprintf(out, cap, "%s/loopspan/generations/%s/loopspan", root, gen);
    return n > 0 && (size_t)n < cap;
}

/* Store B installs the manifest plugin.dev already packed. It does not pack. */
static bool ls_second_store(struct ls_obs *o, const char *manifest, const char *pub)
{
    struct plugin_manifest left;
    struct plugin_manifest right;
    char store_b[PATH_MAX];
    int listed = 0;
    int present = 0;
    if (plugin_store_current(o->store_a, "loopspan", &left, o->exe_a,
                             sizeof o->exe_a) != PLUGIN_OK)
        return false;
    if (strcmp(left.generation, o->generation) != 0)
        return false;
    if (!ls_join(store_b, sizeof store_b, o->work, "store-b") || !ls_mkdir(store_b))
        return false;
    if (plugin_store_add_key(store_b, pub, &listed) != PLUGIN_OK ||
        plugin_store_install(store_b, manifest, &right, &present) != PLUGIN_OK)
        return false;
    if (strcmp(left.generation, right.generation) != 0 ||
        strcmp(left.exe_sha3, right.exe_sha3) != 0)
        return false;
    if (!ls_exe_path(o->exe_b, sizeof o->exe_b, store_b, right.generation))
        return false;
    if (!ls_same_hash(o->exe_a, left.exe_sha3) || !ls_same_hash(o->exe_b, right.exe_sha3))
        return false;
    snprintf(o->sha3, sizeof o->sha3, "%s", left.exe_sha3);
    printf("plugin_admit sha3_512=%s\n", o->sha3);
    printf("second_store sha3_512=%s match=1\n", right.exe_sha3);
    return plugin_verify_generation(o->store_a, "loopspan", o->generation) == PLUGIN_OK &&
           plugin_verify_generation(store_b, "loopspan", o->generation) == PLUGIN_OK;
}

static bool ls_launch(struct ls_obs *o)
{
    struct zcl_devloop_process_result *proc = ls_proc();
    const char *argv[] = {o->exe_b, "span", NULL};
    char want[64];
    char first[128];
    uint64_t t0 = 0;
    uint64_t t1 = 0;
    if (!proc || !ls_now(&t0))
        return false;
    snprintf(want, sizeof want, "token=%u\n", o->token);
    if (!zcl_devloop_process_run(o->root, argv, 30000, proc) || proc->exit_code != 0)
        return false;
    snprintf(first, sizeof first, "%s", proc->output);
    if (strcmp(first, want) != 0)
        return false;
    if (!zcl_devloop_process_run(o->root, argv, 30000, proc) || proc->exit_code != 0)
        return false;
    if (!ls_now(&t1) || strcmp(proc->output, first) != 0)
        return false;
    o->test_us += t1 - t0;
    printf("launch_1 %s", first);
    printf("launch_2 %s", proc->output);
    printf("admitted_exe=%s\n", o->exe_b);
    {
        struct stat st;
        if (stat(o->exe_b, &st) != 0 || st.st_size <= 0)
            return false;
        o->test_bytes = (uint64_t)st.st_size;
    }
    o->groups_ran = 1;
    o->groups_cached = 0;
    return true;
}

static bool ls_flip(const char *path)
{
    FILE *f;
    int byte;
    if (chmod(path, 0600) != 0)
        return false;
    f = fopen(path, "r+b");
    if (!f)
        return false;
    if (fseek(f, -1, SEEK_END) != 0 || (byte = fgetc(f)) < 0 ||
        fseek(f, -1, SEEK_END) != 0 || fputc(byte ^ 1, f) == EOF) {
        fclose(f);
        return false;
    }
    return fclose(f) == 0;
}

static bool ls_tamper(struct ls_obs *o)
{
    enum plugin_status status;
    if (!ls_flip(o->exe_a))
        return false;
    status = plugin_verify_generation(o->store_a, "loopspan", o->generation);
    printf("tamper %s\n", status == PLUGIN_ERR_EXE_HASH ? "PLUGIN_ERR_EXE_HASH"
                                                        : plugin_status_code(status));
    return status == PLUGIN_ERR_EXE_HASH;
}

static bool ls_refuse(void)
{
    struct zcl_command_reply reply;
    bool ok;
    if (!ls_invoke(zcl_native_handle_plugin_call, "{\"name\":\"loopspan\"}", &reply,
                   "zcl.plugin_call.v1"))
        return false;
    /* macOS refuses a confined call before any store lookup. Linux looks the
     * name up after HOME is restored, so the temp install is not current. */
#if defined(__linux__)
    ok = strcmp(reply.error.code, "PLUGIN_NOT_INSTALLED") == 0;
#else
    ok = strcmp(reply.error.code, "PLUGIN_RUN_PLATFORM") == 0;
#endif
    printf("plugin_call %s\n", reply.error.code);
    zcl_command_reply_free(&reply);
    return ok;
}

static bool ls_lint(struct ls_obs *o, struct zcl_devloop_process_result *proc)
{
    const char *argv[] = {"build/bin/z23-lint", "check-hotswap-swappable-shape", NULL};
    uint64_t t0 = 0;
    uint64_t t1 = 0;
    if (!ls_now(&t0))
        return false;
    if (!zcl_devloop_process_run(o->root, argv, 180000, proc) || proc->exit_code != 0) {
        printf("lint exit=%d %s\n", proc->exit_code, proc->output);
        return false;
    }
    if (!ls_now(&t1))
        return false;
    o->lint_us = t1 - t0;
    printf("lint_hotswap_shape ok\n");
    return true;
}

static void ls_root(uint8_t out[32], const char *label, const void *data, size_t n)
{
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    sha3_256_write(&ctx, (const unsigned char *)label, strlen(label));
    if (n)
        sha3_256_write(&ctx, data, n);
    sha3_256_finalize(&ctx, out);
}

static void ls_dim(struct zcl_dev_proof_dimension *dim, uint32_t selected,
                   const uint8_t *root)
{
    memset(dim, 0, sizeof *dim);
    dim->selected = selected;
    dim->ran = selected;
    if (selected && root)
        memcpy(dim->receipt_root, root, 32);
}

static bool ls_head(struct ls_obs *o)
{
    struct zcl_devloop_process_result *proc = ls_proc();
    const char *argv[] = {"git", "rev-parse", "HEAD", NULL};
    size_t n;
    if (!proc || !zcl_devloop_process_run(o->root, argv, 30000, proc) ||
        proc->exit_code != 0) {
        printf("head exit=%d %s\n", proc ? proc->exit_code : -1,
               proc ? proc->output : "");
        return false;
    }
    n = strcspn(proc->output, "\n");
    if (n != 40 || n >= sizeof o->head)
        return false;
    memcpy(o->head, proc->output, 40);
    o->head[40] = 0;
    return true;
}

static bool ls_seal(struct ls_obs *o, const char *lint, size_t lint_len)
{
    struct zcl_dev_acceptance_receipt_v1 receipt;
    uint8_t wire[ZCL_DEV_PROOF_WIRE_BYTES];
    uint8_t root[32];
    char why[128];
    char token_text[16];
    memset(&receipt, 0, sizeof receipt);
    if (!zcl_dev_proof_oid_decode(o->head, receipt.local_commit,
                                  &receipt.local_commit_len) ||
        !zcl_dev_proof_oid_decode(o->head, receipt.remote_base,
                                  &receipt.remote_base_len))
        return false;
    ls_root(receipt.source_root, "source", o->source_digest, sizeof o->source_digest);
    ls_root(receipt.source_cas_root, "source-cas", o->source_digest,
            sizeof o->source_digest);
    ls_root(receipt.mutation_root, "mutation", o->inputs, strlen(o->inputs));
    ls_root(receipt.changed_set_root, "changed", "engine/controllers/src/loop_span_controller.c",
            strlen("engine/controllers/src/loop_span_controller.c"));
    ls_root(receipt.impact_policy_root, "impact", "loop_span", 9);
    ls_root(receipt.compiler_root, "compiler", o->plan, o->plan_len);
    ls_root(receipt.flags_root, "flags", o->plan, o->plan_len);
    ls_root(receipt.environment_root, "environment", o->plan, o->plan_len);
    ls_root(receipt.build_graph_root, "build-graph", o->artifact_sha,
            strlen(o->artifact_sha));
    ls_dim(&receipt.dimensions[ZCL_DEV_PROOF_GENERATED], 0, NULL);
    ls_root(root, "compile", o->artifact_sha, strlen(o->artifact_sha));
    ls_dim(&receipt.dimensions[ZCL_DEV_PROOF_COMPILE], 1, root);
    ls_root(root, "lint", lint, lint_len);
    ls_dim(&receipt.dimensions[ZCL_DEV_PROOF_LINT], 1, root);
    snprintf(token_text, sizeof token_text, "%u", o->token);
    ls_root(root, "test", token_text, strlen(token_text));
    ls_dim(&receipt.dimensions[ZCL_DEV_PROOF_TEST], 1, root);
    receipt.policy_version = ZCL_DEV_PROOF_POLICY_VERSION;
    receipt.complete = 1;
    receipt.created_unix = (uint64_t)time(NULL);
    receipt.elapsed_ms = o->lint_us / 1000ull;
    if (!zcl_dev_proof_receipt_child_set_root(&receipt, receipt.child_set_root))
        return false;
    if (!zcl_dev_proof_receipt_seal(&receipt)) {
        printf("receipt seal failed\n");
        return false;
    }
    if (!zcl_dev_proof_receipt_admit(&receipt, o->head, o->head, NULL, NULL, why,
                                     sizeof why)) {
        printf("receipt admit %s\n", why);
        return false;
    }
    if (!zcl_dev_proof_receipt_serialize(&receipt, wire))
        return false;
    zcl_hex_encode(wire, sizeof wire, o->receipt_hex);
    printf("receipt admitted\n");
    return true;
}

static const struct json_value *ls_dec(const struct zcl_command_reply *reply,
                                       const char *work)
{
    const struct json_value *arr = json_get(&reply->data, "decisions");
    size_t i;
    if (!arr || arr->type != JSON_ARR)
        return NULL;
    for (i = 0; i < arr->num_children; i++) {
        const struct json_value *one = &arr->children[i];
        const struct json_value *name = json_get(one, "work");
        if (name && name->type == JSON_STR && strcmp(json_get_str(name), work) == 0)
            return one;
    }
    return NULL;
}

static bool ls_match(const struct json_value *decision, const char *action, int start)
{
    const struct json_value *got = decision ? json_get(decision, "action") : NULL;
    const struct json_value *flag = decision ? json_get(decision, "start") : NULL;
    if (!got || got->type != JSON_STR || strcmp(json_get_str(got), action) != 0)
        return false;
    if (!flag || flag->type != JSON_BOOL)
        return false;
    return json_get_bool(flag) == (start != 0);
}

static bool ls_reason(const struct json_value *decision, const char *reason)
{
    const struct json_value *why;
    if (!reason)
        return true;
    why = json_get(decision, "reason");
    return why && why->type == JSON_STR && strcmp(json_get_str(why), reason) == 0;
}

static bool ls_expect(const char *records, const char *work, const char *action,
                      int start, const char *reason)
{
    struct json_value rec;
    struct json_value in;
    struct zcl_command_request req;
    struct zcl_command_reply reply;
    const struct json_value *decision;
    bool ok = false;
    json_init(&rec);
    json_init(&in);
    memset(&req, 0, sizeof req);
    if (json_read(&rec, records, strlen(records)) && rec.type == JSON_ARR) {
        json_set_object(&in);
        if (json_push_kv(&in, "records", &rec)) {
            req.input = &in;
            zcl_command_reply_init(&reply, "zcl.dev_loop_measure.v1");
            zcl_native_handle_dev_loop_measure(&req, &reply);
            decision = ls_dec(&reply, work);
            ok = reply.status == ZCL_COMMAND_STATUS_PASSED && decision &&
                 ls_match(decision, action, start) && ls_reason(decision, reason);
            if (!ok)
                printf("measure %s want %s start=%d status=%d\n", work, action, start,
                       (int)reply.status);
            zcl_command_reply_free(&reply);
        }
    }
    json_free(&rec);
    json_free(&in);
    return ok;
}

static bool ls_no_repair(const char *records)
{
    struct json_value rec;
    struct json_value in;
    struct zcl_command_request req;
    struct zcl_command_reply reply;
    bool ok = false;
    json_init(&rec);
    json_init(&in);
    memset(&req, 0, sizeof req);
    if (json_read(&rec, records, strlen(records)) && rec.type == JSON_ARR) {
        json_set_object(&in);
        if (json_push_kv(&in, "records", &rec)) {
            req.input = &in;
            zcl_command_reply_init(&reply, "zcl.dev_loop_measure.v1");
            zcl_native_handle_dev_loop_measure(&req, &reply);
            ok = reply.status == ZCL_COMMAND_STATUS_PASSED &&
                 ls_dec(&reply, "failure") == NULL;
            zcl_command_reply_free(&reply);
        }
    }
    json_free(&rec);
    json_free(&in);
    return ok;
}

static bool ls_tokens_null(const char *records)
{
    struct json_value rec;
    struct json_value in;
    struct zcl_command_request req;
    struct zcl_command_reply reply;
    const struct json_value *tokens = NULL;
    bool ok = false;
    json_init(&rec);
    json_init(&in);
    memset(&req, 0, sizeof req);
    if (json_read(&rec, records, strlen(records)) && rec.type == JSON_ARR) {
        json_set_object(&in);
        if (json_push_kv(&in, "records", &rec)) {
            const struct json_value *classes;
            req.input = &in;
            zcl_command_reply_init(&reply, "zcl.dev_loop_measure.v1");
            zcl_native_handle_dev_loop_measure(&req, &reply);
            classes = json_get(&reply.data, "classes");
            if (classes)
                tokens = json_get(json_get(classes, "repeated_discovery"), "tokens");
            ok = tokens && tokens->type == JSON_NULL;
            zcl_command_reply_free(&reply);
        }
    }
    json_free(&rec);
    json_free(&in);
    return ok;
}

static bool ls_i64(const struct json_value *obj, const char *key, int64_t *out)
{
    const struct json_value *v = obj ? json_get(obj, key) : NULL;
    if (!v || v->type != JSON_INT)
        return false;
    *out = json_get_int(v);
    return true;
}

/* One code.provenance.merkle call. The build object is that call's own cost. */
static bool ls_merkle_once(uint64_t *us, int *files_read, uint64_t *bytes,
                           char *tree, size_t cap)
{
    struct zcl_command_reply reply;
    const struct json_value *build;
    const struct json_value *root;
    int64_t nfiles = 0;
    int64_t nbytes = 0;
    uint64_t t0 = 0;
    uint64_t t1 = 0;
    bool ok;
    if (!ls_now(&t0) ||
        !ls_invoke(zcl_native_handle_code_merkle,
                   "{\"path\":\"engine/controllers/src/loop_span_controller.c\"}",
                   &reply, "zcl.code_merkle.v1"))
        return false;
    build = json_get(&reply.data, "build");
    root = json_get(&reply.data, "tree_root");
    ok = reply.status == ZCL_COMMAND_STATUS_PASSED && build && root &&
         root->type == JSON_STR && strlen(json_get_str(root)) == 64 &&
         ls_i64(build, "files_read", &nfiles) &&
         ls_i64(build, "bytes_read", &nbytes) && nfiles >= 0 && nbytes >= 0 &&
         snprintf(tree, cap, "%s", json_get_str(root)) > 0;
    if (!ok)
        printf("code_merkle status=%d\n", (int)reply.status);
    zcl_command_reply_free(&reply);
    if (!ok || !ls_now(&t1))
        return false;
    *us = t1 - t0;
    *files_read = (int)nfiles;
    *bytes = (uint64_t)nbytes;
    return true;
}

/* The runner's group entry is test_<catalog name>. A cacheable miss is the
 * group that just ran; storing that key is the same PASS the runner records. */
static bool ls_probe_store(struct testcache *tc, const struct testcache_probe *probe)
{
    if (!probe->cacheable || !probe->key_valid) {
        printf("test_probe pass1 refused cacheable=%d key=%d reason=%s\n",
               (int)probe->cacheable, (int)probe->key_valid, probe->reason);
        return false;
    }
    if (probe->hit)
        return true;
    if (!testcache_store_pass(tc, probe->key)) {
        printf("test_probe store refused\n");
        return false;
    }
    printf("test_probe store pass=1\n");
    return true;
}

/* Two probes of test_loop_span on one handle. The second probe's stats are
 * only what that call read after the counter reset. */
static bool ls_probe_tests(struct ls_obs *o)
{
    struct testcache *tc;
    struct testcache_probe probe;
    struct testcache_stats stats;
    uint64_t t0 = 0;
    uint64_t t1 = 0;
    printf("testcache_open begin\n");
    fflush(stdout);
    tc = testcache_open(o->root);
    if (!tc) {
        printf("testcache open refused\n");
        return false;
    }
    testcache_stats_reset(tc);
    testcache_probe_group(tc, "test_loop_span", &probe);
    testcache_stats(tc, &stats);
    printf("test_probe pass1 hit=%d cacheable=%d file_hash_reads=%llu reason=%s\n",
           (int)probe.hit, (int)probe.cacheable,
           (unsigned long long)stats.file_hash_reads, probe.reason);
    fflush(stdout);
    if (!ls_probe_store(tc, &probe)) {
        testcache_close(tc);
        return false;
    }
    testcache_stats_reset(tc);
    if (!ls_now(&t0)) {
        testcache_close(tc);
        return false;
    }
    testcache_probe_group(tc, "test_loop_span", &probe);
    if (!ls_now(&t1)) {
        testcache_close(tc);
        return false;
    }
    testcache_stats(tc, &stats);
    testcache_close(tc);
    o->pass2_test_us = t1 - t0;
    o->pass2_test_bytes = stats.sha3_content_bytes;
    o->pass2_hash_reads = (int)stats.file_hash_reads;
    o->pass2_memo_hits = (int)stats.file_hash_memo_hits;
    o->pass2_groups_cached = (probe.cacheable && probe.hit) ? 1 : 0;
    o->pass2_groups_ran = o->pass2_groups_cached ? 0 : 1;
    printf("test_probe pass2 hit=%d cacheable=%d groups_ran=%d groups_cached=%d "
           "file_hash_reads=%d memo_hits=%d bytes=%llu reason=%s\n",
           (int)probe.hit, (int)probe.cacheable, o->pass2_groups_ran,
           o->pass2_groups_cached, o->pass2_hash_reads, o->pass2_memo_hits,
           (unsigned long long)o->pass2_test_bytes, probe.reason);
    fflush(stdout);
    return o->pass2_groups_cached == 1;
}

static bool ls_window_same(const struct ls_obs *o)
{
    int n = snprintf(
        g_records, sizeof g_records,
        "["
        "{\"schema\":\"zcl.code_guide_brief.v1\",\"question\":\"loop-span\","
        "\"tree\":\"%s\",\"prior_question\":\"loop-span\",\"prior_tree\":\"%s\","
        "\"elapsed_ms\":%llu},"
        "{\"schema\":\"zcl.hotswap_build_receipt.v1\",\"artifact_cache_key\":\"%s\","
        "\"prior_artifact_cache_key\":\"%s\",\"artifact_cache_hit\":%s,"
        "\"build_total_us\":%llu},"
        "{\"schema\":\"zcl.agent_fast_plan.v1\",\"test_groups\":\"%s\","
        "\"prior_test_groups\":\"%s\",\"elapsed_ms\":%llu},"
        "{\"schema\":\"zcl.dev_cycle.v1\",\"status\":\"passed\","
        "\"proof_scope\":\"source_wide_compile_tests_lint_fast\","
        "\"proof_inputs_sha3\":\"%s\",\"prior_proof_inputs_sha3\":\"%s\","
        "\"receipt_hex\":\"%s\",\"local_commit\":\"%s\",\"remote_base\":\"%s\","
        "\"elapsed_ms\":0}"
        "]",
        o->tree_now, o->tree_prior,
        (unsigned long long)(o->pass2_discovery_us / 1000ull),
        o->cache_key2, o->cache_key, o->warm_hit ? "true" : "false",
        (unsigned long long)o->build2_us, o->route2, o->route,
        (unsigned long long)(o->pass2_test_us / 1000ull), o->inputs, o->inputs,
        o->receipt_hex, o->head, o->head);
    return n > 0 && (size_t)n < sizeof g_records;
}

static bool ls_window_changed(const struct ls_obs *o)
{
    int n = snprintf(
        g_records, sizeof g_records,
        "["
        "{\"schema\":\"zcl.dev_cycle.v1\",\"status\":\"passed\","
        "\"proof_scope\":\"source_wide_compile_tests_lint_fast\","
        "\"proof_inputs_sha3\":\"%s\",\"prior_proof_inputs_sha3\":\"%s\","
        "\"receipt_hex\":\"%s\",\"local_commit\":\"%s\",\"remote_base\":\"%s\","
        "\"elapsed_ms\":%llu}"
        "]",
        o->inputs_bad, o->inputs, o->receipt_hex, o->head, o->head,
        (unsigned long long)(o->lint_us / 1000ull));
    return n > 0 && (size_t)n < sizeof g_records;
}

static bool ls_replay_discover(struct ls_obs *o)
{
    int files_a = 0;
    int files_b = 0;
    uint64_t bytes_a = 0;
    uint64_t us_a = 0;
    printf("code_merkle pass2 begin\n");
    fflush(stdout);
    if (!ls_owner() || !ls_symbol() ||
        !ls_route_into(o->route2, sizeof o->route2))
        return false;
    if (!ls_merkle_once(&us_a, &files_a, &bytes_a, o->tree_prior,
                        sizeof o->tree_prior))
        return false;
    printf("code_merkle pass2a files_read=%d bytes_read=%llu\n", files_a,
           (unsigned long long)bytes_a);
    fflush(stdout);
    if (!ls_merkle_once(&o->pass2_discovery_us, &files_b, &o->pass2_discovery_bytes,
                        o->tree_now, sizeof o->tree_now))
        return false;
    o->pass2_source_reads = files_b;
    printf("code_merkle pass2 files_read=%d bytes_read=%llu tree_match=%d\n",
           files_b, (unsigned long long)o->pass2_discovery_bytes,
           strcmp(o->tree_prior, o->tree_now) == 0);
    fflush(stdout);
    return files_b == 0 && strcmp(o->tree_prior, o->tree_now) == 0;
}

static bool ls_replay_decisions(void)
{
    if (!ls_expect(g_records, "discovery", "reused", 0, NULL) ||
        !ls_expect(g_records, "build", "reused", 0, NULL) ||
        !ls_expect(g_records, "test", "reused", 0, NULL) ||
        !ls_expect(g_records, "safety_proof", "satisfied", 0, "admitted_receipt"))
        return false;
    return ls_no_repair(g_records) && ls_tokens_null(g_records);
}

static bool ls_replay(struct ls_obs *o)
{
    if (!ls_swap_warm(o) || !ls_replay_discover(o) || !ls_probe_tests(o) ||
        !ls_window_same(o))
        return false;
    if (!ls_replay_decisions())
        return false;
    printf("pass2 discovery_reused build_reused tests_reused repair_rounds=0\n");
    return true;
}

static bool ls_safety_change(struct ls_obs *o)
{
    snprintf(o->inputs_bad, sizeof o->inputs_bad, "%s", o->inputs);
    o->inputs_bad[63] = (char)(o->inputs_bad[63] == '0' ? '1' : '0');
    if (!ls_window_changed(o))
        return false;
    if (!ls_expect(g_records, "safety_proof", "required", 1, "different_input"))
        return false;
    printf("safety_change required=yes reason=different_input\n");
    return true;
}

static void ls_print_sec(uint64_t us)
{
    printf("%llu.%06llu", (unsigned long long)(us / 1000000ull),
           (unsigned long long)(us % 1000000ull));
}

static void ls_ledger(const struct ls_obs *o)
{
    printf("pass=1\n");
    printf("discovery seconds=");
    ls_print_sec(o->discovery_us);
    printf(" bytes=%llu tokens=unknown source_reads=%d\n",
           (unsigned long long)o->discovery_bytes, o->source_reads);
    printf("build seconds=");
    ls_print_sec(o->build1_us + o->plugin_us);
    printf(" bytes=%llu tokens=unknown compiler_processes=%u linker_processes=%u\n",
           (unsigned long long)(o->discovery_bytes + o->plan_len), o->cc1, o->ld1);
    printf("admit seconds=");
    ls_print_sec(o->admit_us);
    printf(" path=plugin_dev steps=%d tokens=unknown\n", o->dev_steps);
    printf("tests seconds=");
    ls_print_sec(o->test_us);
    printf(" bytes=%llu tokens=unknown groups_ran=%d groups_cached=%d\n",
           (unsigned long long)o->test_bytes, o->groups_ran, o->groups_cached);
    printf("repair seconds=0.000000 bytes=0 tokens=unknown rounds=0\n");
    printf("safety_proof satisfied=yes receipt=admitted\n");
    printf("pass=2\n");
    printf("discovery seconds=");
    ls_print_sec(o->pass2_discovery_us);
    printf(" bytes=%llu tokens=unknown source_reads=%d",
           (unsigned long long)o->pass2_discovery_bytes, o->pass2_source_reads);
    if (o->pass2_source_reads == 0)
        printf(" eliminated=repeated_discovery");
    printf("\n");
    printf("build seconds=");
    ls_print_sec(o->build2_us);
    printf(" bytes=0 tokens=unknown compiler_processes=%u linker_processes=%u",
           o->cc2, o->ld2);
    if (o->cc2 == 0 && o->ld2 == 0)
        printf(" eliminated=redundant_builds");
    printf("\n");
    printf("tests seconds=");
    ls_print_sec(o->pass2_test_us);
    printf(" bytes=%llu tokens=unknown groups_ran=%d groups_cached=%d "
           "file_hash_reads=%d memo_hits=%d",
           (unsigned long long)o->pass2_test_bytes, o->pass2_groups_ran,
           o->pass2_groups_cached, o->pass2_hash_reads, o->pass2_memo_hits);
    if (o->pass2_groups_ran == 0)
        printf(" eliminated=unnecessary_tests");
    printf("\n");
    printf("repair seconds=0.000000 bytes=0 tokens=unknown rounds=0 eliminated=repair_rounds\n");
    printf("safety_proof satisfied=yes receipt=admitted\n");
    printf("safety_change required=yes reason=different_input\n");
    fflush(stdout);
}

static bool ls_prepare(struct ls_obs *o)
{
    if (!getcwd(o->root, sizeof o->root))
        return false;
    if (!ls_discover_files(o) || !ls_owner() || !ls_symbol() ||
        !ls_route_into(o->route, sizeof o->route) ||
        !ls_direct(o) || !ls_plan(o) || !ls_head(o))
        return false;
    if (snprintf(o->cache, sizeof o->cache, "%s/build/loop-span-cache-XXXXXX",
                 o->root) >= (int)sizeof o->cache ||
        snprintf(o->work, sizeof o->work, "%s/build/loop-span-XXXXXX", o->root) >=
            (int)sizeof o->work)
        return false;
    if (!mkdtemp(o->cache) || !mkdtemp(o->work))
        return false;
    return ls_cache_on(o->cache);
}

static bool ls_prove(struct ls_obs *o)
{
    struct zcl_devloop_process_result *proc = ls_proc();
    if (!proc || !ls_lint(o, proc))
        return false;
    return ls_seal(o, proc->output, proc->output_len ? proc->output_len
                                                     : strlen(proc->output));
}

/* One plugin.dev call admits the executable. HOME is the temp store only. */
static bool ls_admit(struct ls_obs *o, char *manifest, size_t manifest_cap,
                     char *pub, size_t pub_cap)
{
    char home[PATH_MAX];
    char dir[PATH_MAX];
    char key[PATH_MAX];
    char saved[PATH_MAX];
    struct zcl_command_reply reply;
    int had = 0;
    uint64_t t0 = 0;
    uint64_t t1 = 0;
    bool ok;
    if (!ls_join(home, sizeof home, o->work, "home") || !ls_mkdir(home) ||
        !ls_join(dir, sizeof dir, o->work, "plug") ||
        !ls_join(key, sizeof key, o->work, "publisher.key") ||
        !ls_join(o->store_a, sizeof o->store_a, home, ".z23/plugins") ||
        !ls_now(&t0) || !ls_home_on(saved, sizeof saved, &had, home))
        return false;
    ok = ls_dev_call(dir, key, &reply);
    ls_home_off(saved, had);
    if (!ok)
        return false;
    ok = ls_dev_take(o, &reply, manifest, manifest_cap, pub, pub_cap);
    zcl_command_reply_free(&reply);
    if (!ok || !ls_second_store(o, manifest, pub) || !ls_now(&t1)) {
        if (o->dev_steps != 5) {
            printf("regression plugin_dev steps=%d required=5\n", o->dev_steps);
            fflush(stdout);
        }
        return false;
    }
    o->admit_us = t1 - t0;
    printf("admit path=plugin_dev seconds=");
    ls_print_sec(o->admit_us);
    printf(" steps=%d\n", o->dev_steps);
    fflush(stdout);
    if (o->dev_steps == 5)
        return true;
    printf("regression plugin_dev steps=%d required=5\n", o->dev_steps);
    fflush(stdout);
    return false;
}

static bool ls_run(void)
{
    struct ls_obs *o = &g_obs;
    char manifest[PATH_MAX];
    char pub[PLUGIN_HEX_PUBLIC_KEY + 1];
    bool ok;
    memset(o, 0, sizeof *o);
    ok = ls_process_on() && ls_prepare(o);
    if (ok)
        ok = ls_swap_cold(o) && ls_cc(o);
    if (ok)
        ok = ls_admit(o, manifest, sizeof manifest, pub, sizeof pub) &&
             ls_launch(o) && ls_tamper(o) && ls_refuse();
    if (ok)
        ok = ls_prove(o) && ls_replay(o) && ls_safety_change(o);
    if (ok)
        ls_ledger(o);
    ls_cache_off();
    ls_process_off();
    free(g_proc);
    g_proc = NULL;
    return ok;
}

int test_loop_span(void)
{
    int failures = 0;
    TEST_CASE("loop span is discovered, swapped, admitted, and proved") {
        ASSERT(ls_run());
    } TEST_END
    return failures;
}
