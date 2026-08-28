/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * dev_activation_ops.c — the REAL service-action ops for the native dev-lane
 * activation engine: exec `systemctl --user ...` through the fixed-argv runner
 * zcl_devloop_process_run(), and query the service's running image through the
 * platform process authority. Every entry point here
 * does process exec, so the whole TU is confined to ZCL_DEV_BUILD and is absent
 * from both the release binary and the (ZCL_TESTING) test harness — tests drive
 * a fake ops vtable instead. Symbol absence from release is proven by
 * tools/lint/check_release_no_dev_symbols.sh.
 */

#define _GNU_SOURCE

#include "dev_activation.h"
#include "dev_activation_internal.h"

#ifdef ZCL_DEV_BUILD

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "devloop.h"
#include "platform/os_proc.h"

/* The default ops treat the request as their context so service/process calls
 * can read unit / datadir / rpcport / repo_root. */

static int dev_run_argv(const char *cwd, const char *const argv[],
                        int timeout_ms, struct zcl_devloop_process_result *out)
{
    if (!zcl_devloop_process_run(cwd, argv, timeout_ms, out))
        return -1;
    if (out->timed_out || out->term_signal != 0)
        return -1;
    return out->exit_code;
}

static int dev_op_daemon_reload(void *ctx);

static int dev_op_prepare(void *ctx)
{
    const struct dev_activation_request *req = ctx;
    const char *home = getenv("HOME");
    if (!home || !home[0] || !req || !req->repo_root || !req->unit)
        return -1;

    char unit_dir[PATH_MAX];
    char source[PATH_MAX];
    char target[PATH_MAX];
    int n1 = snprintf(unit_dir, sizeof(unit_dir),
                      "%s/.config/systemd/user", home);
    int n2 = snprintf(source, sizeof(source), "%s/deploy/%s",
                      req->repo_root, req->unit);
    int n3 = snprintf(target, sizeof(target), "%s/%s", unit_dir, req->unit);
    if (n1 <= 0 || (size_t)n1 >= sizeof(unit_dir) ||
        n2 <= 0 || (size_t)n2 >= sizeof(source) ||
        n3 <= 0 || (size_t)n3 >= sizeof(target))
        return -1;

    const char *mkdir_argv[] = { "mkdir", "-p", "--", unit_dir, NULL };
    struct zcl_devloop_process_result mkdir_res = {0};
    if (dev_run_argv(req->repo_root, mkdir_argv, 30000, &mkdir_res) != 0)
        return -1;

    const char *install_argv[] = {
        "install", "-m", "0644", "--", source, target, NULL
    };
    struct zcl_devloop_process_result install_res = {0};
    if (dev_run_argv(req->repo_root, install_argv, 30000, &install_res) != 0)
        return -1;

    return dev_op_daemon_reload(ctx);
}

static int dev_op_stop(void *ctx)
{
    const struct dev_activation_request *req = ctx;
    const char *argv[] = { "systemctl", "--user", "stop", req->unit, NULL };
    struct zcl_devloop_process_result res = {0};
    return dev_run_argv(req->repo_root, argv,
                        DEV_ACTIVATION_STOP_START_TIMEOUT_S * 1000, &res);
}

static int dev_op_start(void *ctx)
{
    const struct dev_activation_request *req = ctx;
    const char *argv[] = { "systemctl", "--user", "start", req->unit, NULL };
    struct zcl_devloop_process_result res = {0};
    return dev_run_argv(req->repo_root, argv,
                        DEV_ACTIVATION_STOP_START_TIMEOUT_S * 1000, &res);
}

static int dev_op_daemon_reload(void *ctx)
{
    const struct dev_activation_request *req = ctx;
    const char *argv[] = { "systemctl", "--user", "daemon-reload", NULL };
    struct zcl_devloop_process_result res = {0};
    return dev_run_argv(req->repo_root, argv, 30000, &res);
}

static int dev_op_reset_failed(void *ctx)
{
    const struct dev_activation_request *req = ctx;
    const char *argv[] = { "systemctl", "--user", "reset-failed", req->unit,
                           NULL };
    struct zcl_devloop_process_result res = {0};
    (void)dev_run_argv(req->repo_root, argv, 30000, &res);
    return 0; /* best-effort, mirrors the shell's `|| true` */
}

static int dev_op_active(void *ctx)
{
    const struct dev_activation_request *req = ctx;
    const char *argv[] = { "systemctl", "--user", "is-active", "--quiet",
                           req->unit, NULL };
    struct zcl_devloop_process_result res = {0};
    return dev_run_argv(req->repo_root, argv, 30000, &res);
}

static int dev_op_main_pid(void *ctx, long *pid_out)
{
    const struct dev_activation_request *req = ctx;
    const char *argv[] = { "systemctl", "--user", "show", req->unit, "-p",
                           "MainPID", "--value", NULL };
    struct zcl_devloop_process_result res = {0};
    if (dev_run_argv(req->repo_root, argv, 30000, &res) != 0)
        return -1;
    *pid_out = strtol(res.output, NULL, 10);
    return 0;
}

static int dev_op_running_exe(void *ctx, long pid, char *out, size_t out_sz)
{
    (void)ctx;
    if (pid <= 0)
        return -1;
    char target[PATH_MAX];
    if (!os_proc_pid_exe_path((uint64_t)pid, target, sizeof(target)))
        return -1;
    char canon[PATH_MAX];
    if (!dev_activation_canon(target, canon, sizeof(canon)))
        return -1;
    int n = snprintf(out, out_sz, "%s", canon);
    return (n > 0 && (size_t)n < out_sz) ? 0 : -1;
}

static int dev_op_preflight(void *ctx, const char *cand_bin,
                            const char *source_id_sha256)
{
    const struct dev_activation_request *req = ctx;
    struct zcl_devloop_process_result res = {0};
    const char *ab[] = { cand_bin, "agentbuild", NULL };
    /* Source identity walks the complete tracked epoch.  A cold, busy build
     * host has measured just beyond the old 30s edge even though the exact
     * same candidate returns in ~11s warm; preflight then quarantined healthy
     * generations.  This is setup-only and still bounded well below the
     * activation intent expiry. */
    if (dev_run_argv(req->repo_root, ab, 90000, &res) != 0)
        return -1;
    if (!strstr(res.output, "zcl.agent_build.v2"))
        return -1;
    char observed[65];
    if (!dev_activation_json_first_string(res.output, "source_id_sha256",
                                          observed, sizeof(observed)) ||
        !dev_activation_source_id_valid(observed))
        return -1;
    if (!source_id_sha256 ||
        strcmp(observed, source_id_sha256) != 0)
        return -1;
    /* Native registry self-test is the resident command-catalog proof
     * preflight seam: a deterministic, node-free well-formedness sweep of the
     * command catalog. Fail closed unless the candidate reports fail == 0. */
    char portbuf[16];
    snprintf(portbuf, sizeof(portbuf), "-rpcport=%d", req->rpcport);
    char ddbuf[PATH_MAX];
    snprintf(ddbuf, sizeof(ddbuf), "-datadir=%s", req->datadir);
    struct zcl_devloop_process_result st = {0};
    const char *sv[] = { cand_bin, ddbuf, portbuf, "ops", "selftest", NULL };
    if (dev_run_argv(req->repo_root, sv, 30000, &st) != 0)
        return -1;
    if (!strstr(st.output, "\"mode\":\"registry\"") ||
        !strstr(st.output, "\"fail\":0"))
        return -1;
    return 0;
}

static int dev_op_source_epoch_cas(void *ctx)
{
    const struct dev_activation_request *req = ctx;
    if (!dev_activation_source_id_valid(req->source_identity))
        return -1;
    char tool[PATH_MAX];
    int n = snprintf(tool, sizeof(tool), "%s/tools/dev/source-identity.sh",
                     req->repo_root);
    if (n <= 0 || (size_t)n >= sizeof(tool))
        return -1;
    const char *verify_source[] = {
        tool, "verify", req->source_identity, NULL
    };
    const char *verify_record[] = {
        tool, "verify-record", req->source_identity, "1",
        req->source_mutation, NULL
    };
    const char *const *argv =
        req->source_mutation && req->source_mutation[0]
            ? verify_record : verify_source;
    struct zcl_devloop_process_result res = {0};
    return dev_run_argv(req->repo_root, argv, 30000, &res);
}

static int dev_op_activation_probe(void *ctx, const char *gen_id,
                                   const char *expected_source_id_sha256)
{
    const struct dev_activation_request *req = ctx;
    char cli[PATH_MAX];
    snprintf(cli, sizeof(cli), "%s/build/bin/zclassic-cli", req->repo_root);
    char portbuf[16];
    snprintf(portbuf, sizeof(portbuf), "-rpcport=%d", req->rpcport);
    char ddbuf[PATH_MAX];
    snprintf(ddbuf, sizeof(ddbuf), "-datadir=%s", req->datadir);
    struct zcl_devloop_process_result res = {0};
    const char *hv[] = { cli, ddbuf, portbuf, "getblockcount", NULL };
    if (dev_run_argv(req->repo_root, hv, 12000, &res) != 0)
        return -1;
    const char *av[] = { cli, ddbuf, portbuf, "agent", NULL };
    if (dev_run_argv(req->repo_root, av, 12000, &res) != 0)
        return -1;
    /* The node produces zcl.public_status.v3; v2 is still a fully readable
     * document, so an older binary under probe is not a failure here. */
    if (!strstr(res.output, "zcl.public_status.v3") &&
        !strstr(res.output, "zcl.public_status.v2"))
        return -1;
    char observed[65];
    if (!dev_activation_source_id_valid(expected_source_id_sha256) ||
        !dev_activation_json_first_string(res.output, "source_id_sha256",
                                          observed, sizeof(observed)) ||
        !dev_activation_source_id_valid(observed) ||
        strcmp(observed, expected_source_id_sha256) != 0)
        return -1;
    (void)gen_id;
    return 0;
}

void dev_activation_default_ops(const struct dev_activation_request *req,
                                struct dev_activation_ops *out)
{
    memset(out, 0, sizeof(*out));
    out->service_prepare = dev_op_prepare;
    out->service_stop = dev_op_stop;
    out->service_start = dev_op_start;
    out->service_daemon_reload = dev_op_daemon_reload;
    out->service_reset_failed = dev_op_reset_failed;
    out->service_active = dev_op_active;
    out->service_main_pid = dev_op_main_pid;
    out->running_exe = dev_op_running_exe;
    out->preflight = dev_op_preflight;
    out->source_epoch_cas = dev_op_source_epoch_cas;
    out->activation_probe = dev_op_activation_probe;
    out->ctx = (void *)req;
}

#endif /* ZCL_DEV_BUILD */
