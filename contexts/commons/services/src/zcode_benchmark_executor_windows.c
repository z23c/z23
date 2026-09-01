/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: fail closed until Windows benchmark confinement is qualified. */

#include "services/zcode_benchmark_executor.h"

#if defined(_WIN32)

static struct zcl_result zcode_benchmark_windows_refusal(void)
{
    return ZCL_ERR(
        -1,
        "zcode benchmark execution is disabled on Windows until restricted "
        "tokens, Job Objects, low-integrity isolation, resource limits, and "
        "network denial pass adversarial qualification");
}

struct zcl_result zcode_benchmark_executor_sandbox_selfcheck(
    const char *bench_dir)
{
    (void)bench_dir;
    return zcode_benchmark_windows_refusal();
}

struct zcl_result zcode_benchmark_executor_run(
    const struct zcode_benchmark_execute_request *req,
    struct zcode_benchmark_run_out *out)
{
    (void)req;
    (void)out;
    return zcode_benchmark_windows_refusal();
}

struct zcl_result zcode_benchmark_executor_admit(
    struct node_db *ndb, const char *workspace,
    const struct zcode_benchmark_run_out *run, bool confirm, int64_t now,
    struct zcode_benchmark_execute_out *out)
{
    (void)ndb;
    (void)workspace;
    (void)run;
    (void)confirm;
    (void)now;
    (void)out;
    return zcode_benchmark_windows_refusal();
}

struct zcl_result zcode_benchmark_execute(
    struct node_db *ndb, const struct zcode_benchmark_execute_request *req,
    struct zcode_benchmark_execute_out *out)
{
    (void)ndb;
    (void)req;
    (void)out;
    return zcode_benchmark_windows_refusal();
}

struct zcl_result zcode_benchmark_executor_verify_receipt(
    const char *workspace, const char *result_root_hex)
{
    (void)workspace;
    (void)result_root_hex;
    return zcode_benchmark_windows_refusal();
}

#else
typedef int zcode_benchmark_executor_windows_not_built;
#endif
