/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#if !defined(_WIN32)
#define _GNU_SOURCE
#endif
#include "devloop.h"
#include "test_group_catalog.h"

#include "config/command_catalog.h"
#include "kernel/command_registry.h"
#include "platform/directory_compat.h"
#include "platform/os_proc.h"
#include "platform/positioned_file.h"
#include "platform/state_root.h"
#include "platform/watcher_lease.h"
#include "platform/watcher_record.h"
#include "platform/watcher_store.h"

#if !defined(_WIN32)
#include <fcntl.h>
#endif
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if !defined(_WIN32)
#include <sys/stat.h>
#include <unistd.h>
#endif

bool zcl_devloop_is_method(const char *method)
{
    return method && strcmp(method, "dev") == 0;
}

static const char *source_root(void)
{
    const char *root = getenv("ZCL_DEV_SOURCE_ROOT");
    return root && root[0] ? root : ".";
}

static int print_menu(const char *path)
{
    char body[32768];
    size_t n = zcl_devloop_menu_json(path, body, sizeof(body));
    if (n == 0) {
        fprintf(stderr, "[devloop] menu response exceeded its bound\n");
        return 1;
    }
    printf("%s\n", body);
    return strstr(body, "\"error\"") ? 1 : 0;
}

static bool menu_path(char out[512], const char **args, int start, int nargs)
{
    size_t pos = 0;
    int n = snprintf(out, 512, "dev");
    if (n <= 0)
        return false;
    pos = (size_t)n;
    for (int i = start; i < nargs; i++) {
        const char *part = args[i];
        if (!part || !part[0])
            continue;
        if (strncmp(part, "dev.", 4) == 0 && i == start) {
            n = snprintf(out, 512, "%s", part);
            if (n <= 0 || n >= 512)
                return false;
            pos = (size_t)n;
            continue;
        }
        if (strchr(part, '/') || strstr(part, ".."))
            return false;
        n = snprintf(out + pos, 512 - pos, ".%s", part);
        if (n <= 0 || (size_t)n >= 512 - pos)
            return false;
        pos += (size_t)n;
    }
    return true;
}

static int run_focused(const char *group)
{
#ifndef ZCL_DEV_BUILD
    (void)group;
    fprintf(stderr, "[devloop] focused execution requires a dev build\n");
    return 2;
#else
    char full_group[ZCL_TEST_GROUP_FULL_MAX];
    if (!group || !group[0] ||
        strspn(group, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_") != strlen(group) ||
        !zcl_test_group_resolve_exact(group, full_group)) {
        fprintf(stderr, "[devloop] focused: invalid exact group\n");
        return 2;
    }
    char root[PATH_MAX], bin[PATH_MAX], selector[256];
    if (!platform_directory_canonical_real(source_root(), root,
                                            sizeof(root))) {
        fprintf(stderr, "[devloop] focused: source root unavailable\n");
        return 2;
    }
#if defined(_WIN32)
    snprintf(bin, sizeof(bin), "%s/build/bin/test_parallel_fast.exe", root);
#else
    snprintf(bin, sizeof(bin), "%s/build/bin/test_parallel_fast", root);
#endif
    snprintf(selector, sizeof(selector), "--exact=%s", full_group);
#if defined(_WIN32)
    struct platform_positioned_file runner;
    platform_positioned_file_init(&runner);
    if (!platform_positioned_file_open(&runner, bin) ||
        !platform_positioned_file_is_executable(&runner)) {
        platform_positioned_file_close(&runner);
        fprintf(stderr, "[devloop] focused: prebuilt runner unavailable\n");
        return 2;
    }
    platform_positioned_file_close(&runner);
    fprintf(stderr,
            "[devloop] focused: native handle-bound runner execution is "
            "unavailable\n");
    return 2;
#else
    int runner_fd = open(bin, O_RDONLY);
    struct stat runner_stat;
    if (runner_fd < 0 || fstat(runner_fd, &runner_stat) != 0 ||
        !S_ISREG(runner_stat.st_mode) ||
        !(runner_stat.st_mode & (S_IXUSR | S_IXGRP | S_IXOTH))) {
        if (runner_fd >= 0)
            close(runner_fd);
        fprintf(stderr, "[devloop] focused: prebuilt runner unavailable\n");
        return 2;
    }
    struct dev_source_record source = {0};
    char why[192] = {0};
    enum zcl_dev_source_admission source_admission =
        zcl_dev_executable_source_admit(root, runner_fd, bin, &source,
                                        why, sizeof(why));
    if (source_admission <= ZCL_DEV_SOURCE_ADMISSION_STALE) {
        close(runner_fd);
        fprintf(stderr, "[devloop] focused: %s runner: %s\n",
                source_admission == ZCL_DEV_SOURCE_ADMISSION_STALE
                    ? "stale" : "unavailable",
                why[0] ? why : "run make test_parallel_fast");
        return 2;
    }
    const char *argv[] = { bin, selector, NULL };
    struct zcl_devloop_process_result result;
    if (!zcl_devloop_process_run_fd(root, runner_fd, argv, 300000, &result)) {
        close(runner_fd);
        return 1;
    }
    close(runner_fd);
    if (!zcl_dev_source_mutation_verify(root, &source, why, sizeof(why))) {
        fprintf(stderr, "[devloop] focused: source epoch superseded: %s\n",
                why);
        return 1;
    }
    bool ok = result.exit_code == 0 && !result.timed_out &&
              result.term_signal == 0;
    printf("{\"schema\":\"zcl.dev_focused_test.v1\",\"status\":\"%s\","
           "\"group\":\"%s\",\"source_admission\":\"%s\","
           "\"source_cas_sha3\":\"%s\",\"source_cas_authority\":\"shadow\","
           "\"elapsed_ms\":%lld,\"exit_code\":%d}\n",
           ok ? "passed" : "failed", full_group,
           zcl_dev_source_admission_name(source_admission),
           source.cas_present ? source.cas_root_sha3 : "",
           (long long)result.elapsed_ms, result.exit_code);
    if (!ok && result.output_len)
        fprintf(stderr, "%s\n", result.output);
    return ok ? 0 : 1;
#endif
#endif
}

static int plan_files(const char **args, int start, int nargs)
{
    char body[16384];
    const char *const *files = args + start;
    size_t count = nargs > start ? (size_t)(nargs - start) : 0;
    size_t n = zcl_devloop_plan_json(files, count, body, sizeof(body));
    if (n == 0) {
        fprintf(stderr, "[devloop] plan: invalid or oversized file set\n");
        return 2;
    }
    printf("%s\n", body);
    return 0;
}

int zcl_devloop_cli_main(const char **args, int nargs)
{
    if (nargs <= 0)
        return print_menu("dev");

    if (strcmp(args[0], "status") == 0 && nargs == 1)
        return zcl_devloop_print_status();
    if (strcmp(args[0], "app") == 0 && nargs == 3 &&
        strcmp(args[1], "describe") == 0)
        return zcl_devloop_app_describe(source_root(), args[2]);
    if (strcmp(args[0], "app") == 0 && nargs == 4 &&
        strcmp(args[1], "plan") == 0)
        return zcl_devloop_app_plan(source_root(), args[2], args[3]);
    if (strcmp(args[0], "app") == 0 && (nargs == 3 || nargs == 4) &&
        strcmp(args[1], "simulate") == 0) {
        uint64_t seed = UINT64_C(0x534f4349414c0001);
        if (nargs == 4) {
            char *end = NULL;
            seed = strtoull(args[3], &end, 0);
            if (!end || *end)
                return 2;
        }
        return zcl_devloop_app_simulate(args[2], seed);
    }
    if (strcmp(args[0], "core") == 0 && nargs == 2 &&
        strcmp(args[1], "boundary") == 0) {
        printf("{\"schema\":\"zcl.core_app_boundary.v1\","
               "\"rule\":\"core_owns_truth_apps_consume_capabilities\","
               "\"core\":[\"consensus\",\"validation\",\"chain_mutation\","
               "\"wallet_keys\",\"raw_storage\",\"sockets\",\"boot\"],"
               "\"apps\":[\"resources\",\"signed_events\",\"services\","
               "\"projections\",\"web\",\"onion\",\"znam\",\"p2p_topics\"],"
               "\"core_change\":\"guarded_reload\","
               "\"app_change\":\"simulate_then_atomic_publish\"}\n");
        return 0;
    }
    if (strcmp(args[0], "change") == 0 && nargs >= 2 &&
        strcmp(args[1], "plan") == 0)
        return plan_files(args, 2, nargs);
    if (strcmp(args[0], "change") == 0 && nargs >= 2 &&
        strcmp(args[1], "cycle") == 0) {
        const char *const *files = args + 2;
        size_t count = nargs > 2 ? (size_t)(nargs - 2) : 0;
        return zcl_devloop_run_cycle(source_root(), files, count);
    }
    if (strcmp(args[0], "loop") == 0 && nargs >= 2 &&
        strcmp(args[1], "watch") == 0)
        return zcl_devloop_watch(nargs >= 3 ? args[2] : source_root());
    if (strcmp(args[0], "loop") == 0 && nargs == 2 &&
        strcmp(args[1], "heartbeat") == 0)
        return zcl_devloop_print_status();
    if (strcmp(args[0], "test") == 0 && nargs == 2 &&
        strcmp(args[1], "sim") == 0)
        return zcl_devloop_run_sim(source_root());
    if (strcmp(args[0], "test") == 0 && nargs == 3 &&
        strcmp(args[1], "focused") == 0)
        return run_focused(args[2]);
    if (strcmp(args[0], "diagnose") == 0 && nargs == 2 &&
        strcmp(args[1], "latest") == 0)
        return zcl_devloop_print_status();
    if ((strcmp(args[0], "search") == 0 && nargs >= 2) ||
        (strcmp(args[0], "diagnose") == 0 && nargs >= 3 &&
         strcmp(args[1], "search") == 0)) {
        int qi = strcmp(args[0], "search") == 0 ? 1 : 2;
        char query[512] = {0};
        size_t pos = 0;
        for (int i = qi; i < nargs; i++) {
            int n = snprintf(query + pos, sizeof(query) - pos, "%s%s",
                             pos ? " " : "", args[i]);
            if (n <= 0 || (size_t)n >= sizeof(query) - pos)
                return 2;
            pos += (size_t)n;
        }
        char body[16384];
        size_t n = zcl_devloop_menu_search_json(query, body, sizeof(body));
        if (n == 0)
            return 2;
        printf("%s\n", body);
        return 0;
    }

    int start = strcmp(args[0], "help") == 0 ? 1 : 0;

    /* Registry-driven fail-closed: a leaf the registry marks PLANNED has no
     * executable handler here. Resolve the longest registered dev path and, if
     * it is a planned leaf, block with exit 3 instead of printing a menu that
     * would imply the command works. */
    const char *words[64];
    size_t wc = 0;
    words[wc++] = "dev";
    for (int i = start; i < nargs && wc < 64; i++)
        words[wc++] = args[i];
    size_t consumed = 0;
    bool was_alias = false;
    char invoked[ZCL_COMMAND_MAX_PATH];
    const struct zcl_command_spec *spec = zcl_command_registry_resolve_words(
        zcl_command_catalog(), words, wc, &consumed, &was_alias, invoked,
        sizeof(invoked));
    if (spec && spec->mode != ZCL_COMMAND_MODE_BRANCH &&
        spec->availability == ZCL_COMMAND_PLANNED) {
        printf("{\"schema\":\"zcl.result.v1\",\"command\":\"%s\",\"ok\":false,"
               "\"status\":\"blocked\",\"exit_code\":3,"
               "\"error\":{\"code\":\"COMMAND_PLANNED\",\"message\":"
               "\"command is declared but not implemented\",\"evidence\":\"%s\"},"
               "\"next\":[{\"command\":\"discover.describe\",\"input\":"
               "{\"path\":\"%s\"},\"reason\":"
               "\"inspect availability and replacement\"}]}\n",
               spec->path,
               spec->availability_reason ? spec->availability_reason : "",
               spec->path);
        return 3;
    }

    char path[512];
    if (!menu_path(path, args, start, nargs)) {
        fprintf(stderr, "[devloop] help: invalid tree path\n");
        return 2;
    }
    return print_menu(path);
}

#if !defined(_WIN32)
static bool worker_lease_stopped(void *opaque)
{ return platform_watcher_lease_wait_stop(opaque, 0); }
#endif

#if defined(_WIN32)
struct worker_store_context {
    struct platform_watcher_lease *lease;
    struct platform_watcher_store store;
    struct platform_watcher_record record;
    struct platform_watcher_record_identity identity;
    char record_leaf[96];
    bool stopping_published;
};

static bool worker_store_publish(struct worker_store_context *ctx,
                                 enum platform_watcher_state state)
{
    char encoded[PLATFORM_WATCHER_RECORD_ENCODED_MAX];
    size_t length = 0;
    ctx->record.state = state;
    const struct platform_watcher_record_identity *expected =
        ctx->identity.size ? &ctx->identity : NULL;
    return platform_watcher_record_serialize(&ctx->record, encoded,
                                              sizeof(encoded), &length) &&
           platform_watcher_store_publish(&ctx->store, ctx->record_leaf,
                                           encoded, length, expected,
                                           &ctx->identity) ==
               PLATFORM_WATCHER_STORE_OK;
}

static bool worker_store_stopped(void *opaque)
{
    struct worker_store_context *ctx = opaque;
    bool stopped = platform_watcher_lease_wait_stop(ctx->lease, 0);
    if (stopped && !ctx->stopping_published) {
        ctx->stopping_published = worker_store_publish(
            ctx, PLATFORM_WATCHER_STATE_STOPPING);
    }
    return stopped;
}
#endif

int zcl_devloop_watch_worker_main(uintptr_t inherited, const char *root,
                                  const char *mode, const char image_sha256[65])
{
#ifndef ZCL_DEV_BUILD
    (void)inherited; (void)root; (void)mode; (void)image_sha256;
    return 2;
#else
    char canonical[PATH_MAX], image[PATH_MAX];
    struct platform_watcher_lease lease;
    platform_watcher_lease_init(&lease);
    enum zcl_devloop_publish_mode publish_mode;
    if (!root || !mode ||
        !platform_directory_canonical_real(root, canonical, sizeof(canonical)) ||
        !os_proc_exe_path(image, sizeof(image)) ||
        !platform_watcher_lease_accept(&lease, inherited, canonical, image,
                                       image_sha256))
        return 2;
    if (strcmp(mode, "verify") == 0)
        publish_mode = ZCL_DEVLOOP_PUBLISH_VERIFY_ONLY;
    else if (strcmp(mode, "auto") == 0)
        publish_mode = ZCL_DEVLOOP_PUBLISH_APPLY;
    else
        { platform_watcher_lease_close(&lease); return 2; }
#if defined(_WIN32)
    struct platform_watcher_accepted_binding accepted;
    struct worker_store_context ownership = {.lease = &lease};
    char state_root[PATH_MAX], workspace[65], lock_leaf[96];
    platform_watcher_store_init(&ownership.store);
    uint64_t pid = os_proc_current_pid(), start_token = 0;
    if (!platform_watcher_lease_binding(&lease, &accepted) ||
        !os_proc_pid_start_token(pid, &start_token) ||
        !platform_state_root(state_root, sizeof(state_root)) ||
        !zcl_devloop_workspace_id(canonical, workspace) ||
        snprintf(lock_leaf, sizeof(lock_leaf), "watch-%s.lock", workspace) <= 0 ||
        snprintf(ownership.record_leaf, sizeof(ownership.record_leaf),
                 "watch-%s.record", workspace) <= 0 ||
        platform_watcher_store_open(&ownership.store, state_root) !=
            PLATFORM_WATCHER_STORE_OK ||
        platform_watcher_store_try_acquire(&ownership.store, lock_leaf, true) !=
            PLATFORM_WATCHER_STORE_OK) {
        platform_watcher_store_close(&ownership.store);
        platform_watcher_lease_close(&lease);
        return 2;
    }
    ownership.record = (struct platform_watcher_record){
        .version = PLATFORM_WATCHER_RECORD_VERSION,
        .pid = pid, .start_token = start_token,
        .mode = publish_mode == ZCL_DEVLOOP_PUBLISH_APPLY
                    ? PLATFORM_WATCHER_MODE_AUTO
                    : PLATFORM_WATCHER_MODE_VERIFY,
        .root_identity = {accepted.root_volume, accepted.root_low,
                          accepted.root_high},
        .image_identity = {accepted.image_volume, accepted.image_low,
                           accepted.image_high},
        .image_size = accepted.image_size,
        .state = PLATFORM_WATCHER_STATE_STARTING};
    memcpy(ownership.record.nonce, accepted.nonce,
           sizeof(ownership.record.nonce));
    memcpy(ownership.record.canonical_root, accepted.canonical_root,
           sizeof(ownership.record.canonical_root));
    memcpy(ownership.record.canonical_image, accepted.canonical_image,
           sizeof(ownership.record.canonical_image));
    memcpy(ownership.record.image_sha256, accepted.image_sha256,
           sizeof(ownership.record.image_sha256));
    if (!worker_store_publish(&ownership, PLATFORM_WATCHER_STATE_STARTING) ||
        !worker_store_publish(&ownership, PLATFORM_WATCHER_STATE_READY)) {
        if (ownership.identity.size)
            (void)platform_watcher_store_retire_exact(
                &ownership.store, ownership.record_leaf,
                &ownership.identity);
        platform_watcher_store_close(&ownership.store);
        platform_watcher_lease_close(&lease);
        return 2;
    }
    int rc = zcl_devloop_watch_mode_until(canonical, publish_mode,
                                           worker_store_stopped, &ownership);
    if (!ownership.stopping_published)
        ownership.stopping_published = worker_store_publish(
            &ownership, PLATFORM_WATCHER_STATE_STOPPING);
    (void)platform_watcher_store_retire_exact(
        &ownership.store, ownership.record_leaf, &ownership.identity);
    platform_watcher_store_close(&ownership.store);
#else
    int rc = zcl_devloop_watch_mode_until(canonical, publish_mode,
                                           worker_lease_stopped, &lease);
#endif
    platform_watcher_lease_close(&lease);
    return rc == 0 ? 0 : 1;
#endif
}
