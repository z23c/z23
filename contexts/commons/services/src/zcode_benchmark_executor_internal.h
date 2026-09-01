/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Purpose: the S4 benchmark executor's private cross-TU bound — the path
 * buffer size its confined-run and sandbox-canary paths share.
 *
 * zcode_benchmark_executor.c owns the confined run, admission, and receipt
 * verification; zcode_benchmark_sandbox_selfcheck.c owns the escape-suite
 * canaries. The split happened when the combined file passed its shape
 * ceiling. Nothing outside those two translation units may include this
 * header — the public contract is services/zcode_benchmark_executor.h.
 */

#ifndef ZCL_SERVICES_ZCODE_BENCHMARK_EXECUTOR_INTERNAL_H
#define ZCL_SERVICES_ZCODE_BENCHMARK_EXECUTOR_INTERNAL_H

#define EXEC_PATH_MAX 4096

#endif /* ZCL_SERVICES_ZCODE_BENCHMARK_EXECUTOR_INTERNAL_H */
