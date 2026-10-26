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

#if defined(ZCL_DEV_BUILD)
static bool focused_group_resolved(const char *group,
                                  char full_group[ZCL_TEST_GROUP_FULL_MAX])
{
    return group && group[0] &&
        strspn(group, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_") == strlen(group) &&
        zcl_test_group_resolve_exact(group, full_group);
}

#if defined(_WIN32)
static int focused_win32_runner_blocked(const char *bin)
{
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
}
#else
static int focused_posix_runner_fd(const char *bin)
{
    int runner_fd = open(bin, O_RDONLY);
    struct stat runner_stat;
    if (runner_fd < 0 || fstat(runner_fd, &runner_stat) != 0 ||
        !S_ISREG(runner_stat.st_mode) ||
        !(runner_stat.st_mode & (S_IXUSR | S_IXGRP | S_IXOTH))) {
        if (runner_fd >= 0)
            close(runner_fd);
        return -1;
    }
    return runner_fd;
}

static int focused_posix_source_gate(const char *root, int runner_fd,
                                    const char *bin,
                                    struct dev_source_record *source,
                                    char *why, size_t why_len,
                                    enum zcl_dev_source_admission *admission)
{
    enum zcl_dev_source_admission source_admission =
        zcl_dev_executable_source_admit(root, runner_fd, bin, source,
                                        why, why_len);
    if (source_admission <= ZCL_DEV_SOURCE_ADMISSION_STALE) {
        close(runner_fd);
        fprintf(stderr, "[devloop] focused: %s runner: %s\n",
                source_admission == ZCL_DEV_SOURCE_ADMISSION_STALE
                    ? "stale" : "unavailable",
                why[0] ? why : "run make test_parallel_fast");
        return 2;
    }
    *admission = source_admission;
    return 0;
}

static int focused_posix_report(const char *root,
                               const struct dev_source_record *source,
                               char *why, size_t why_len,
                               enum zcl_dev_source_admission source_admission,
                               const char *full_group,
                               const struct zcl_devloop_process_result *result)
{
    if (!zcl_dev_source_mutation_verify(root, source, why, why_len)) {
        fprintf(stderr, "[devloop] focused: source epoch superseded: %s\n",
                why);
        return 1;
    }
    bool ok = result->exit_code == 0 && !result->timed_out &&
              result->term_signal == 0;
    printf("{\"schema\":\"zcl.dev_focused_test.v1\",\"status\":\"%s\","
           "\"group\":\"%s\",\"source_admission\":\"%s\","
           "\"source_cas_sha3\":\"%s\",\"source_cas_authority\":\"shadow\","
           "\"elapsed_ms\":%lld,\"exit_code\":%d}\n",
           ok ? "passed" : "failed", full_group,
           zcl_dev_source_admission_name(source_admission),
           source->cas_present ? source->cas_root_sha3 : "",
           (long long)result->elapsed_ms, result->exit_code);
    if (!ok && result->output_len)
        fprintf(stderr, "%s\n", result->output);
    return ok ? 0 : 1;
}

static int focused_posix_run(const char *root, const char *bin,
                             const char *selector, const char *full_group)
{
    int runner_fd = focused_posix_runner_fd(bin);
    if (runner_fd < 0) {
        fprintf(stderr, "[devloop] focused: prebuilt runner unavailable\n");
        return 2;
    }
    struct dev_source_record source = {0};
    char why[192] = {0};
    enum zcl_dev_source_admission source_admission =
        ZCL_DEV_SOURCE_ADMISSION_ERROR;
    int admitted = focused_posix_source_gate(root, runner_fd, bin, &source,
                                             why, sizeof(why),
                                             &source_admission);
    if (admitted != 0)
        return admitted;
    const char *argv[] = { bin, selector, NULL };
    struct zcl_devloop_process_result result;
    if (!zcl_devloop_process_run_fd(root, runner_fd, argv, 300000, &result)) {
        close(runner_fd);
        return 1;
    }
    close(runner_fd);
    return focused_posix_report(root, &source, why, sizeof(why),
                                source_admission, full_group, &result);
}
#endif

static int run_focused_dev(const char *group)
{
    char full_group[ZCL_TEST_GROUP_FULL_MAX];
    if (!focused_group_resolved(group, full_group)) {
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
    return focused_win32_runner_blocked(bin);
#else
    return focused_posix_run(root, bin, selector, full_group);
#endif
}
#endif

static int run_focused(const char *group)
{
#ifndef ZCL_DEV_BUILD
    (void)group;
    fprintf(stderr, "[devloop] focused execution requires a dev build\n");
    return 2;
#else
    return run_focused_dev(group);
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

enum devloop_cli_kind {
    DEVLOOP_CLI_STATUS,
    DEVLOOP_CLI_APP_DESCRIBE,
    DEVLOOP_CLI_APP_PLAN,
    DEVLOOP_CLI_APP_SIMULATE,
    DEVLOOP_CLI_CORE_BOUNDARY,
    DEVLOOP_CLI_CHANGE_PLAN,
    DEVLOOP_CLI_CHANGE_CYCLE,
    DEVLOOP_CLI_LOOP_WATCH,
    DEVLOOP_CLI_TEST_SIM,
    DEVLOOP_CLI_TEST_FOCUSED
};

struct devloop_cli_route {
    const char *verb;
    const char *sub;
    int min_args;
    int max_args;
    enum devloop_cli_kind kind;
};

static int devloop_cli_app_simulate(const char **args, int nargs)
{
    uint64_t seed = UINT64_C(0x534f4349414c0001);
    if (nargs == 4) {
        char *end = NULL;
        seed = strtoull(args[3], &end, 0);
        if (!end || *end)
            return 2;
    }
    return zcl_devloop_app_simulate(args[2], seed);
}

static int devloop_cli_core_boundary(void)
{
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

static int devloop_cli_change_cycle(const char **args, int nargs)
{
    const char *const *files = args + 2;
    size_t count = nargs > 2 ? (size_t)(nargs - 2) : 0;
    return zcl_devloop_run_cycle(source_root(), files, count);
}

static int devloop_cli_loop_watch(const char **args, int nargs)
{
    return zcl_devloop_watch(nargs >= 3 ? args[2] : source_root());
}

static int devloop_cli_run_kind(enum devloop_cli_kind kind,
                               const char **args, int nargs)
{
    switch (kind) {
    case DEVLOOP_CLI_STATUS:
        return zcl_devloop_print_status();
    case DEVLOOP_CLI_APP_DESCRIBE:
        return zcl_devloop_app_describe(source_root(), args[2]);
    case DEVLOOP_CLI_APP_PLAN:
        return zcl_devloop_app_plan(source_root(), args[2], args[3]);
    case DEVLOOP_CLI_APP_SIMULATE:
        return devloop_cli_app_simulate(args, nargs);
    case DEVLOOP_CLI_CORE_BOUNDARY:
        return devloop_cli_core_boundary();
    case DEVLOOP_CLI_CHANGE_PLAN:
        return plan_files(args, 2, nargs);
    case DEVLOOP_CLI_CHANGE_CYCLE:
        return devloop_cli_change_cycle(args, nargs);
    case DEVLOOP_CLI_LOOP_WATCH:
        return devloop_cli_loop_watch(args, nargs);
    case DEVLOOP_CLI_TEST_SIM:
        return zcl_devloop_run_sim(source_root());
    case DEVLOOP_CLI_TEST_FOCUSED:
        return run_focused(args[2]);
    }
    return 2;
}

static int devloop_cli_route_matches(const struct devloop_cli_route *route,
                                    const char **args, int nargs)
{
    if (strcmp(args[0], route->verb) != 0)
        return 0;
    if (route->max_args < 0) {
        if (nargs < route->min_args)
            return 0;
    } else if (nargs < route->min_args || nargs > route->max_args) {
        return 0;
    }
    if (!route->sub)
        return 1;
    return nargs >= 2 && strcmp(args[1], route->sub) == 0;
}

static int devloop_cli_try_route(const char **args, int nargs, int *status)
{
    static const struct devloop_cli_route routes[] = {
        { "status", NULL, 1, 1, DEVLOOP_CLI_STATUS },
        { "app", "describe", 3, 3, DEVLOOP_CLI_APP_DESCRIBE },
        { "app", "plan", 4, 4, DEVLOOP_CLI_APP_PLAN },
        { "app", "simulate", 3, 4, DEVLOOP_CLI_APP_SIMULATE },
        { "core", "boundary", 2, 2, DEVLOOP_CLI_CORE_BOUNDARY },
        { "change", "plan", 2, -1, DEVLOOP_CLI_CHANGE_PLAN },
        { "change", "cycle", 2, -1, DEVLOOP_CLI_CHANGE_CYCLE },
        { "loop", "watch", 2, -1, DEVLOOP_CLI_LOOP_WATCH },
        { "loop", "heartbeat", 2, 2, DEVLOOP_CLI_STATUS },
        { "test", "sim", 2, 2, DEVLOOP_CLI_TEST_SIM },
        { "test", "focused", 3, 3, DEVLOOP_CLI_TEST_FOCUSED },
        { "diagnose", "latest", 2, 2, DEVLOOP_CLI_STATUS },
    };
    for (size_t i = 0; i < sizeof routes / sizeof routes[0]; i++) {
        if (devloop_cli_route_matches(&routes[i], args, nargs)) {
            *status = devloop_cli_run_kind(routes[i].kind, args, nargs);
            return 1;
        }
    }
    return 0;
}

static int devloop_cli_is_search(const char **args, int nargs)
{
    if (strcmp(args[0], "search") == 0 && nargs >= 2)
        return 1;
    return strcmp(args[0], "diagnose") == 0 && nargs >= 3 &&
           strcmp(args[1], "search") == 0;
}

static int devloop_cli_search(const char **args, int nargs)
{
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

static int devloop_cli_menu_or_planned(const char **args, int nargs)
{
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

int zcl_devloop_cli_main(const char **args, int nargs)
{
    if (nargs <= 0)
        return print_menu("dev");
    int status = 0;
    if (devloop_cli_try_route(args, nargs, &status))
        return status;
    if (devloop_cli_is_search(args, nargs))
        return devloop_cli_search(args, nargs);
    return devloop_cli_menu_or_planned(args, nargs);
}

/* Stop predicate for the POSIX watch worker. Guard matches its ONE caller
 * exactly (the ZCL_DEV_BUILD arm of zcl_devloop_watch_worker_main, non-Win32
 * branch); guarding on !_WIN32 alone left it defined with no caller in a
 * release build, which clang reports as an unused function. */
#if defined(ZCL_DEV_BUILD) && !defined(_WIN32)
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

#if defined(ZCL_DEV_BUILD) && defined(_WIN32)
static int watch_worker_win32_acquire(struct worker_store_context *ownership,
                                     struct platform_watcher_lease *lease,
                                     struct platform_watcher_accepted_binding *accepted,
                                     const char *canonical, char *workspace,
                                     char *lock_leaf, size_t lock_leaf_len,
                                     char *state_root, size_t state_root_len,
                                     uint64_t *pid_out, uint64_t *start_token_out)
{
    uint64_t pid = os_proc_current_pid();
    uint64_t start_token = 0;
    int ready = platform_watcher_lease_binding(lease, accepted) &&
        os_proc_pid_start_token(pid, &start_token) &&
        platform_state_root(state_root, state_root_len) &&
        zcl_devloop_workspace_id(canonical, workspace) &&
        snprintf(lock_leaf, lock_leaf_len, "watch-%s.lock", workspace) > 0 &&
        snprintf(ownership->record_leaf, sizeof(ownership->record_leaf),
                 "watch-%s.record", workspace) > 0 &&
        platform_watcher_store_open(&ownership->store, state_root) ==
            PLATFORM_WATCHER_STORE_OK &&
        platform_watcher_store_try_acquire(&ownership->store, lock_leaf, true) ==
            PLATFORM_WATCHER_STORE_OK;
    *pid_out = pid;
    *start_token_out = start_token;
    return ready;
}

static int watch_worker_win32_mark_ready(struct worker_store_context *ownership,
                                        enum zcl_devloop_publish_mode publish_mode,
                                        const struct platform_watcher_accepted_binding *accepted,
                                        uint64_t pid, uint64_t start_token)
{
    ownership->record = (struct platform_watcher_record){
        .version = PLATFORM_WATCHER_RECORD_VERSION,
        .pid = pid, .start_token = start_token,
        .mode = publish_mode == ZCL_DEVLOOP_PUBLISH_APPLY
                    ? PLATFORM_WATCHER_MODE_AUTO
                    : PLATFORM_WATCHER_MODE_VERIFY,
        .root_identity = {accepted->root_volume, accepted->root_low,
                          accepted->root_high},
        .image_identity = {accepted->image_volume, accepted->image_low,
                           accepted->image_high},
        .image_size = accepted->image_size,
        .state = PLATFORM_WATCHER_STATE_STARTING};
    memcpy(ownership->record.nonce, accepted->nonce,
           sizeof(ownership->record.nonce));
    memcpy(ownership->record.canonical_root, accepted->canonical_root,
           sizeof(ownership->record.canonical_root));
    memcpy(ownership->record.canonical_image, accepted->canonical_image,
           sizeof(ownership->record.canonical_image));
    memcpy(ownership->record.image_sha256, accepted->image_sha256,
           sizeof(ownership->record.image_sha256));
    if (!worker_store_publish(ownership, PLATFORM_WATCHER_STATE_STARTING) ||
        !worker_store_publish(ownership, PLATFORM_WATCHER_STATE_READY)) {
        if (ownership->identity.size)
            (void)platform_watcher_store_retire_exact(
                &ownership->store, ownership->record_leaf,
                &ownership->identity);
        return 0;
    }
    return 1;
}

static int watch_worker_win32_run(struct platform_watcher_lease *lease,
                                 const char *canonical,
                                 enum zcl_devloop_publish_mode publish_mode)
{
    struct platform_watcher_accepted_binding accepted;
    struct worker_store_context ownership = {.lease = lease};
    char state_root[PATH_MAX], workspace[65], lock_leaf[96];
    platform_watcher_store_init(&ownership.store);
    uint64_t pid = 0, start_token = 0;
    if (!watch_worker_win32_acquire(&ownership, lease, &accepted, canonical,
                                    workspace, lock_leaf, sizeof(lock_leaf),
                                    state_root, sizeof(state_root),
                                    &pid, &start_token)) {
        platform_watcher_store_close(&ownership.store);
        platform_watcher_lease_close(lease);
        return 2;
    }
    if (!watch_worker_win32_mark_ready(&ownership, publish_mode, &accepted,
                                      pid, start_token)) {
        platform_watcher_store_close(&ownership.store);
        platform_watcher_lease_close(lease);
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
    platform_watcher_lease_close(lease);
    return rc == 0 ? 0 : 1;
}
#endif

#if defined(ZCL_DEV_BUILD)
static int watch_worker_lease_accepted(struct platform_watcher_lease *lease,
                                      uintptr_t inherited, const char *root,
                                      const char *mode, char *canonical,
                                      size_t canonical_len, char *image,
                                      size_t image_len,
                                      const char image_sha256[65])
{
    return root && mode &&
        platform_directory_canonical_real(root, canonical, canonical_len) &&
        os_proc_exe_path(image, image_len) &&
        platform_watcher_lease_accept(lease, inherited, canonical, image,
                                      image_sha256);
}

static int watch_worker_mode_code(const char *mode,
                                 enum zcl_devloop_publish_mode *publish_mode)
{
    if (strcmp(mode, "verify") == 0) {
        *publish_mode = ZCL_DEVLOOP_PUBLISH_VERIFY_ONLY;
        return 1;
    }
    if (strcmp(mode, "auto") == 0) {
        *publish_mode = ZCL_DEVLOOP_PUBLISH_APPLY;
        return 1;
    }
    return 0;
}

static int watch_worker_main_dev(uintptr_t inherited, const char *root,
                                const char *mode,
                                const char image_sha256[65])
{
    char canonical[PATH_MAX], image[PATH_MAX];
    struct platform_watcher_lease lease;
    platform_watcher_lease_init(&lease);
    enum zcl_devloop_publish_mode publish_mode;
    if (!watch_worker_lease_accepted(&lease, inherited, root, mode, canonical,
                                     sizeof(canonical), image, sizeof(image),
                                     image_sha256))
        return 2;
    if (!watch_worker_mode_code(mode, &publish_mode)) {
        platform_watcher_lease_close(&lease);
        return 2;
    }
#if defined(_WIN32)
    return watch_worker_win32_run(&lease, canonical, publish_mode);
#else
    int rc = zcl_devloop_watch_mode_until(canonical, publish_mode,
                                           worker_lease_stopped, &lease);
    platform_watcher_lease_close(&lease);
    return rc == 0 ? 0 : 1;
#endif
}
#endif

int zcl_devloop_watch_worker_main(uintptr_t inherited, const char *root,
                                  const char *mode, const char image_sha256[65])
{
#ifndef ZCL_DEV_BUILD
    (void)inherited; (void)root; (void)mode; (void)image_sha256;
    return 2;
#else
    return watch_worker_main_dev(inherited, root, mode, image_sha256);
#endif
}
