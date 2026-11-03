/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_mcp_plugin_call - the MCP adapter's z23_run reaches plugin.call.
 * A fixture one-shot plugin (interface 2) is packed, installed and switched in
 * a temporary HOME; `z23 mcp serve` then runs under that HOME. plugin.call must
 * return the plugin's output through z23_run, and plugin.install, which writes
 * a generation, must be refused because it declares no plan_id and is owner
 * authority.
 *
 * make t-fast-exact ONLY=mcp_plugin_call */

#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif

#include "test/test_core.h"

#include "command/native_command.h"
#include "json/json.h"
#include "plugin/plugin_store.h"

#if defined(__linux__)
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#define MPC_BIN "build/bin/z23-dev"
#define MPC_FIXTURE "build/fixtures/plugin_call_upper"
#define MPC_OUT 65536

struct mpc_env {
    char base[PATH_MAX], home[PATH_MAX], root[PATH_MAX], dist[PATH_MAX];
    char old_home[PATH_MAX], manifest[PATH_MAX];
};

typedef void (*mpc_handler)(const struct zcl_command_request *, struct zcl_command_reply *);

static bool mpc_call(mpc_handler handler, const char *input_json, struct zcl_command_reply *reply)
{
    struct json_value input;
    json_init(&input);
    bool ok = json_read(&input, input_json, strlen(input_json));
    struct zcl_command_request request = { .input = &input, .view = "normal" };
    zcl_command_reply_init(reply, "zcl.mcp_plugin_test.v1");
    if (ok)
        handler(&request, reply);
    json_free(&input);
    return ok;
}

static bool mpc_join(char *out, size_t cap, const char *a, const char *b)
{
    int n = snprintf(out, cap, "%s/%s", a, b);
    return n > 0 && (size_t)n < cap;
}

static bool mpc_write_key(const struct mpc_env *e, const char *public_key)
{
    char path[PATH_MAX];
    FILE *f = mpc_join(path, sizeof(path), e->root, "publisher_keys") ? fopen(path, "wb") : NULL;
    bool ok = f && fprintf(f, "%s\n", public_key) > 0;
    if (f)
        ok = fclose(f) == 0 && ok;
    return ok && chmod(path, 0600) == 0;
}

/* Temporary HOME with a store and a generated, listed publisher key. */
static bool mpc_env_open(struct mpc_env *e)
{
    char dot[PATH_MAX], key[PATH_MAX], in[2 * PATH_MAX], pub[65];
    struct zcl_command_reply r;
    const char *home = getenv("HOME");
    memset(e, 0, sizeof(*e));
    snprintf(e->old_home, sizeof(e->old_home), "%s", home ? home : "");
    if (!test_mkdtemp(e->base, sizeof(e->base), "mcp_plugin_call") ||
        !mpc_join(e->home, sizeof(e->home), e->base, "home") || mkdir(e->home, 0700) != 0 ||
        !mpc_join(dot, sizeof(dot), e->home, ".z23") || mkdir(dot, 0700) != 0 ||
        !mpc_join(e->root, sizeof(e->root), dot, "plugins") || mkdir(e->root, 0700) != 0 ||
        !mpc_join(e->dist, sizeof(e->dist), e->base, "dist") ||
        !mpc_join(key, sizeof(key), e->base, "publisher.key") || setenv("HOME", e->home, 1) != 0)
        return false;
    snprintf(in, sizeof(in), "{\"key\":\"%s\"}", key);
    if (!mpc_call(zcl_native_handle_plugin_keygen, in, &r))
        return false;
    snprintf(pub, sizeof(pub), "%s", r.exit_code == ZCL_COMMAND_EXIT_OK
                                         ? json_get_str(json_get(&r.data, "public_key")) : "");
    zcl_command_reply_free(&r);
    return pub[0] && mpc_write_key(e, pub);
}

static void mpc_env_close(struct mpc_env *e)
{
    if (e->old_home[0])
        (void)setenv("HOME", e->old_home, 1);
    if (e->base[0])
        (void)test_rm_rf_recursive(e->base);
}

/* Pack the fixture as "upper" (interface 2), install it, make it current. */
static bool mpc_publish(struct mpc_env *e)
{
    char in[4 * PATH_MAX], key[PATH_MAX], gen[PLUGIN_HEX_SHA3_512 + 1];
    struct zcl_command_reply r;
    if (!mpc_join(key, sizeof(key), e->base, "publisher.key"))
        return false;
    snprintf(in, sizeof(in), "{\"exe\":\"%s\",\"name\":\"upper\",\"version\":\"1.2.3\","
             "\"key\":\"%s\",\"dir\":\"%s\",\"interface\":2}", MPC_FIXTURE, key, e->dist);
    if (!mpc_call(zcl_native_handle_plugin_pack, in, &r) || r.exit_code != ZCL_COMMAND_EXIT_OK)
        return false;
    snprintf(e->manifest, sizeof(e->manifest), "%s", json_get_str(json_get(&r.data, "manifest")));
    zcl_command_reply_free(&r);
    snprintf(in, sizeof(in), "{\"manifest\":\"%s\"}", e->manifest);
    if (!mpc_call(zcl_native_handle_plugin_install, in, &r) || r.exit_code != ZCL_COMMAND_EXIT_OK)
        return false;
    snprintf(gen, sizeof(gen), "%s", json_get_str(json_get(&r.data, "generation")));
    zcl_command_reply_free(&r);
    snprintf(in, sizeof(in), "{\"name\":\"upper\",\"generation\":\"%s\"}", gen);
    if (!mpc_call(zcl_native_handle_plugin_switch, in, &r))
        return false;
    bool ok = r.exit_code == ZCL_COMMAND_EXIT_OK;
    zcl_command_reply_free(&r);
    return ok;
}

/* Run the adapter once: requests from reqfile on stdin, replies to outfile. */
static bool mpc_serve(const struct mpc_env *e, const char *reqfile, const char *outfile)
{
    char home_env[PATH_MAX + 8], bin[PATH_MAX];
    char *envp[] = {home_env, (char *)"PATH=/usr/bin:/bin:/usr/local/bin",
                    (char *)"ZCL_CLI_TEST_NO_SERVICE_LOOKUP=1", NULL};
    char *const args[] = {bin, (char *)"mcp", (char *)"serve", NULL};
    int status = 0;
    snprintf(home_env, sizeof(home_env), "HOME=%s", e->home);
    if (!realpath(MPC_BIN, bin))
        return false;
    pid_t pid = fork();
    if (pid < 0)
        return false;
    if (pid == 0) {
        int in = open(reqfile, O_RDONLY);
        int out = open(outfile, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        int err = open("/dev/null", O_WRONLY);
        if (in < 0 || out < 0 || err < 0 || dup2(in, STDIN_FILENO) < 0 ||
            dup2(out, STDOUT_FILENO) < 0 || dup2(err, STDERR_FILENO) < 0)
            _exit(126);
        execve(bin, args, envp);
        _exit(127);
    }
    return waitpid(pid, &status, 0) == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

static bool mpc_slurp(const char *path, char *out, size_t cap)
{
    FILE *f = fopen(path, "rb");
    size_t n = f ? fread(out, 1, cap - 1, f) : 0;
    bool ok = f && !ferror(f);
    if (f)
        fclose(f);
    out[n] = '\0';
    return ok;
}

static bool mpc_requests(const struct mpc_env *e, const char *reqfile)
{
    FILE *f = fopen(reqfile, "wb");
    if (!f)
        return false;
    fputs("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{"
          "\"protocolVersion\":\"2025-06-18\",\"capabilities\":{},\"clientInfo\":"
          "{\"name\":\"mcp-test-client\",\"version\":\"1\"}}}\n"
          "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n"
          "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{"
          "\"name\":\"z23_run\",\"arguments\":{\"path\":\"plugin.call\",\"input\":"
          "{\"name\":\"upper\",\"stdin\":\"qzx\"}}}}\n", f);
    fprintf(f, "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":{"
               "\"name\":\"z23_run\",\"arguments\":{\"path\":\"plugin.install\","
               "\"input\":{\"manifest\":\"%s\"}}}}\n", e->manifest);
    fprintf(f, "{\"jsonrpc\":\"2.0\",\"id\":4,\"method\":\"tools/call\",\"params\":{"
               "\"name\":\"z23_run\",\"arguments\":{\"path\":\"plugin.switch\","
               "\"input\":{\"name\":\"upper\",\"generation\":\"x\"}}}}\n");
    return fclose(f) == 0;
}

/* Isolate the reply to request id from the other lines. */
static bool mpc_reply(const char *all, const char *id_tag, char *line, size_t cap)
{
    const char *p = strstr(all, id_tag);
    if (!p)
        return false;
    while (p > all && p[-1] != '\n')
        p--;
    const char *end = strchr(p, '\n');
    size_t n = end ? (size_t)(end - p) : strlen(p);
    if (n >= cap)
        return false;
    memcpy(line, p, n);
    line[n] = '\0';
    return true;
}

static int mpc_case_run(void)
{
    int failures = 0;
    struct mpc_env e;
    bool ready = mpc_env_open(&e);
    TEST_CASE("z23_run runs plugin.call directly and refuses plugin.install and switch") {
        char req[PATH_MAX + 16], out[PATH_MAX + 16], *all = malloc(MPC_OUT), line[MPC_OUT];
        ASSERT(all != NULL);
        ASSERT(ready);
        ASSERT(mpc_publish(&e));
        ASSERT(mpc_join(req, sizeof(req), e.base, "requests.jsonl"));
        ASSERT(mpc_join(out, sizeof(out), e.base, "replies.jsonl"));
        ASSERT(mpc_requests(&e, req));
        ASSERT(mpc_serve(&e, req, out));
        ASSERT(mpc_slurp(out, all, MPC_OUT));
        ASSERT(mpc_reply(all, "\"id\":2,", line, sizeof(line)));
        if (strstr(line, "PLUGIN_RUN_PLATFORM") || strstr(line, "LAB_UNCONFINED") ||
            strstr(line, "LAB_UNSUPPORTED")) {
            printf("mcp_plugin_call: SKIP (confined execution unavailable on this host)\n");
        } else {
            ASSERT(strstr(line, "\"isError\":false") != NULL);
            ASSERT(strstr(line, "QZX") != NULL);
        }
        ASSERT(mpc_reply(all, "\"id\":3,", line, sizeof(line)));
        ASSERT(strstr(line, "\"isError\":true") != NULL);
        ASSERT(strstr(line, "MUTATION_REFUSED_OWNER_AUTHORITY") != NULL);
        ASSERT(mpc_reply(all, "\"id\":4,", line, sizeof(line)));
        ASSERT(strstr(line, "MUTATION_REFUSED_OWNER_AUTHORITY") != NULL);
        free(all);
    } TEST_END
    mpc_env_close(&e);
    return failures;
}
#endif

int test_mcp_plugin_call(void)
{
    int failures = 0;
    printf("\n=== MCP plugin call tests ===\n");
#if !defined(__linux__)
    printf("mcp_plugin_call: SKIP (Linux only)\n");
#else
    struct stat st;
    if (stat(MPC_BIN, &st) != 0 || stat(MPC_FIXTURE, &st) != 0) {
        printf("mcp_plugin_call: SKIP (%s or %s missing)\n", MPC_BIN, MPC_FIXTURE);
        return 0;
    }
    failures += mpc_case_run();
#endif
    printf("=== mcp_plugin_call: %d failures ===\n", failures);
    return failures;
}
