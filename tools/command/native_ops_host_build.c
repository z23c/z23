/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: ops.host.build and ops.host.jobs — admit a heavy command to the
 *          host build queue and run it in a limited scope, and list the
 *          running and queued jobs.
 *
 * WHY `ops`, NOT `dev`. Build admission is an operator duty on every host
 * the fleet runs, including machines that carry the release binary and no
 * checkout, so the leaves live where `ops.host.gc` lives
 * (engine/composition/commands/README.md).
 *
 * ops.host.build streams the command's stdio and returns the command's own
 * exit status, which a JSON envelope cannot carry, so it is a CLI intercept
 * like ops.mesh.terminal; the JSON handler is a blocker. The engine is
 * command/build_admit.h.
 */

#include "command/native_command.h"
#include "command/build_admit.h"

#include "base/safe_alloc.h"
#include "json/json.h"
#include "platform/os_proc.h"
#include "kernel/command_registry.h"
#include "util/spawn.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef __linux__
enum { OHB_MIN_CPUS = 8, OHB_LSCPU_MAX = 65536, OHB_MAX_ZCC_MB = 8192,
       OHB_MEM_KIB = 24u * 1024u * 1024u };

static bool ohb_abs_env(const char *name)
{
    const char *v = getenv(name);
    return v && v[0] == '/';
}

static bool ohb_path(char *out, size_t cap, const char *base, const char *tail)
{
    int n = snprintf(out, cap, "%s/%s", base, tail);
    return n > 0 && (size_t)n < cap;
}

/* State and scratch locations follow XDG, falling back to $HOME. */
static bool ohb_locations(struct ba_config *cfg)
{
    const char *home = getenv("HOME");
    char base[BA_PATH_MAX];
    if (!home || home[0] != '/' || strlen(home) >= sizeof(cfg->disk_path))
        return false;
    (void)snprintf(cfg->disk_path, sizeof(cfg->disk_path), "%s", home);
    if (ohb_abs_env("XDG_STATE_HOME"))
        (void)snprintf(base, sizeof(base), "%s", getenv("XDG_STATE_HOME"));
    else if (!ohb_path(base, sizeof(base), home, ".local/state"))
        return false;
    if (!ohb_path(cfg->state_dir, sizeof(cfg->state_dir), base, "development"))
        return false;
    if (ohb_abs_env("XDG_CACHE_HOME"))
        (void)snprintf(base, sizeof(base), "%s", getenv("XDG_CACHE_HOME"));
    else if (!ohb_path(base, sizeof(base), home, ".cache"))
        return false;
    return ohb_path(cfg->scratch_root, sizeof(cfg->scratch_root), base,
                    "development-builds");
}

static unsigned ohb_env_uint(const char *name, unsigned min, unsigned max,
                             unsigned fallback)
{
    const char *v = getenv(name);
    char *end = NULL;
    unsigned long n;
    if (!v || !v[0])
        return fallback;
    n = strtoul(v, &end, 10);
    return (*end || n < min || n > max) ? fallback : (unsigned)n;
}

static void ohb_defaults(struct ba_config *cfg)
{
    memset(cfg, 0, sizeof(*cfg));
    (void)snprintf(cfg->scope_launcher, sizeof(cfg->scope_launcher),
                   "systemd-run");
    cfg->lanes = ohb_env_uint("DEVBUILD_Z23_LANES", 1, BA_MAX_LANES,
                              BA_MAX_LANES);
    cfg->reserve_gib = ba_reserve_gib_from_env();
    cfg->need_mem_kib = OHB_MEM_KIB;
    cfg->poll_ms = 1000;
    cfg->zcc_max_mb = ohb_env_uint("ZCC_MAX_MB", 1, OHB_MAX_ZCC_MB,
                                   OHB_MAX_ZCC_MB);
    cfg->wait = true;
    cfg->keep_scratch = getenv("DEVBUILD_KEEP_SCRATCH") &&
                        strcmp(getenv("DEVBUILD_KEEP_SCRATCH"), "1") == 0;
    cfg->tmpdir_set = getenv("TMPDIR") && getenv("TMPDIR")[0];
    cfg->priority = getenv("DEVBUILD_PRIORITY") &&
                    strcmp(getenv("DEVBUILD_PRIORITY"), "land") == 0;
}

/* Reserve at least eight online CPUs, then take every logical CPU after the
 * first two physical cores as the build set. */
static bool ohb_cpu_plan(struct ba_config *cfg)
{
    static const char *const argv[] = { "lscpu", "-b", "-p=CPU,CORE,SOCKET",
                                        NULL };
    char *text;
    bool ok;
    if (sysconf(_SC_NPROCESSORS_ONLN) < OHB_MIN_CPUS) {
        (void)fprintf(stderr, "devbuild requires at least eight online CPUs\n");
        return false;
    }
    text = zcl_malloc(OHB_LSCPU_MAX, "build_lscpu");
    if (!text)
        return false;
    ok = zcl_spawn_capture(argv, text, OHB_LSCPU_MAX, 10000) == 0 &&
         ba_cpu_plan_parse(text, cfg->cpu_list, sizeof(cfg->cpu_list),
                           &cfg->cpu_workers);
    free(text);
    if (!ok)
        (void)fprintf(stderr, "devbuild: no build CPU set could be planned\n");
    return ok;
}

static bool ohb_in_scope(void)
{
    char dir[BA_PATH_MAX];
    return os_proc_cgroup_dir(dir, sizeof(dir)) &&
           strstr(dir, "/development.slice/") != NULL;
}

/* A command already inside a build scope runs under that budget. */
static int ohb_reuse_scope(const char *const *cmd, int argc)
{
    const char *active = getenv("DEVBUILD_ACTIVE");
    char **argv = zcl_calloc((size_t)argc + 1u, sizeof(*argv), "build_argv");
    if (!argv)
        return 71;
    for (int i = 0; i < argc; i++)
        argv[i] = (char *)cmd[i];
    (void)fprintf(stderr, "devbuild: reusing enclosing %s budget\n",
                  active && active[0] ? active : "exclusive");
    execvp(argv[0], argv);
    (void)fprintf(stderr, "devbuild: cannot execute %s: %s\n", argv[0],
                  strerror(errno));
    free(argv);
    return 127;
}

static bool ohb_is_landing(const char *const *cmd, int argc)
{
    for (int i = 0; i + 1 < argc; i++)
        if (strcmp(cmd[i], "dev") == 0 && strcmp(cmd[i + 1], "land") == 0)
            return true;
    return false;
}

struct ohb_args {
    bool plan;
    const char *state_dir;
    const char *scratch_root;
    long reserve_gib; /* -1: keep the default */
    bool no_wait;
    size_t first;     /* index of the command's first word */
};

/* `--flag value` and `--flag=value`; sets *skip to the words consumed. */
static const char *ohb_value(const char *const *w, size_t i, size_t count,
                             const char *flag, size_t *skip)
{
    size_t n = strlen(flag);
    if (strncmp(w[i], flag, n) != 0)
        return NULL;
    if (w[i][n] == '=') {
        *skip = 1;
        return w[i] + n + 1;
    }
    if (w[i][n] == '\0' && i + 1 < count) {
        *skip = 2;
        return w[i + 1];
    }
    return NULL;
}

static bool ohb_parse(const char *const *w, size_t count, size_t from,
                      struct ohb_args *a)
{
    size_t i = from, skip = 0;
    const char *v;
    memset(a, 0, sizeof(*a));
    a->reserve_gib = -1;
    for (; i < count; i += skip) {
        skip = 1;
        if (strcmp(w[i], "--") == 0) {
            i++;
            break;
        } else if (strcmp(w[i], "--wait") == 0) {
            a->no_wait = false;
        } else if (strcmp(w[i], "--no-wait") == 0) {
            a->no_wait = true;
        } else if (strcmp(w[i], "--plan") == 0) {
            a->plan = true;
        } else if ((v = ohb_value(w, i, count, "--reserve-gib", &skip))) {
            char *end = NULL;
            a->reserve_gib = strtol(v, &end, 10);
            if (*end || a->reserve_gib < 0)
                return false;
        } else if ((v = ohb_value(w, i, count, "--state-dir", &skip))) {
            a->state_dir = v;
        } else if ((v = ohb_value(w, i, count, "--scratch-root", &skip))) {
            a->scratch_root = v;
        } else {
            break;
        }
    }
    a->first = i;
    return true;
}

static void ohb_apply(struct ba_config *cfg, const struct ohb_args *a)
{
    if (a->state_dir)
        (void)snprintf(cfg->state_dir, sizeof(cfg->state_dir), "%s",
                       a->state_dir);
    if (a->scratch_root)
        (void)snprintf(cfg->scratch_root, sizeof(cfg->scratch_root), "%s",
                       a->scratch_root);
    if (a->reserve_gib >= 0)
        cfg->reserve_gib = (unsigned)a->reserve_gib;
    cfg->wait = !a->no_wait;
}

static int ohb_run(const char *const *w, size_t count, size_t consumed)
{
    struct ba_config cfg;
    struct ohb_args a;
    int argc;
    ohb_defaults(&cfg);
    if (!ohb_parse(w, count, consumed, &a) || !ohb_locations(&cfg)) {
        (void)fprintf(stderr, "devbuild: invalid options or HOME unset\n");
        return BA_EXIT_USAGE;
    }
    ohb_apply(&cfg, &a);
    argc = (int)(count - a.first);
    if (!a.plan && argc <= 0) {
        (void)fprintf(stderr, "Usage: z23 ops host build [--no-wait] "
                      "[--plan] [--reserve-gib N] -- COMMAND [ARGS...]\n");
        return BA_EXIT_USAGE;
    }
    if (!a.plan && ohb_in_scope())
        return ohb_reuse_scope(w + a.first, argc);
    if (!ohb_cpu_plan(&cfg))
        return BA_EXIT_DEFERRED;
    if (a.plan) {
        (void)printf("project=z23 cpus=%s cpu_quota=%u%% memory_max=24G "
                     "reserve=%uGiB\n", cfg.cpu_list, cfg.cpu_workers * 100u,
                     cfg.reserve_gib);
        return 0;
    }
    cfg.priority = cfg.priority || ohb_is_landing(w + a.first, argc);
    return ba_run(&cfg, w + a.first, argc);
}

#endif /* __linux__ */

#ifndef _WIN32
bool zcl_native_ops_host_build_try_run(const char *const *words, size_t count,
                                       size_t consumed, int *rc)
{
#ifdef __linux__
    *rc = ohb_run(words, count, consumed);
#else
    (void)words;
    (void)count;
    (void)consumed;
    (void)fprintf(stderr, "HOST_BUILD_PLATFORM_UNAVAILABLE: native host build "
                  "admission requires Linux; use the installed host admission rail\n");
    *rc = BA_EXIT_DEFERRED;
#endif
    return true;
}
#endif

void zcl_native_handle_ops_host_build(const struct zcl_command_request *request,
                                      struct zcl_command_reply *reply)
{
    (void)request;
#ifndef __linux__
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_BLOCKED,
        ZCL_COMMAND_EXIT_BLOCKED, "HOST_BUILD_PLATFORM_UNAVAILABLE", "platform",
        false, false, "Native host build admission requires Linux; use the "
        "installed host admission rail.", "ops.host.build");
#else
    zcl_command_reply_fail(
        reply, ZCL_COMMAND_STATUS_BLOCKED, ZCL_COMMAND_EXIT_BLOCKED,
        "BUILD_CLI_ONLY", "dispatch", false, false,
        "a build streams its command's output and returns the command's own "
        "exit status; run it as z23 ops host build -- COMMAND [ARGS...]",
        "ops.host.build");
#endif
}

void zcl_native_handle_ops_host_jobs(const struct zcl_command_request *request,
                                     struct zcl_command_reply *reply)
{
    (void)request;
    if (!reply)
        return;
#ifndef __linux__
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_BLOCKED,
        ZCL_COMMAND_EXIT_BLOCKED, "HOST_BUILD_PLATFORM_UNAVAILABLE", "platform",
        false, false, "Native host job observation requires Linux procfs; "
        "no queue observation is available on this platform.", "ops.host.jobs");
#else
    struct ba_config cfg;
    ohb_defaults(&cfg);
    if (!ohb_locations(&cfg) || !ba_status(cfg.state_dir, &reply->data)) {
        zcl_command_reply_fail(
            reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
            "host_jobs.observation_failed", "observe",
            false, false,
            "host build observation could not be completed: check state "
            "path resolution, allocation, or bounded record-scan failures",
            "ops.host.jobs");
        return;
    }
    reply->status = ZCL_COMMAND_STATUS_PASSED;
#endif
}
