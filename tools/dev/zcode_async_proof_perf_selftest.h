/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Sandbox proof of the async proof performance report. */

#ifndef ZCL_ZCODE_ASYNC_PROOF_PERF_SELFTEST_H
#define ZCL_ZCODE_ASYNC_PROOF_PERF_SELFTEST_H

/* Drives tools/dev/zcode_async_proof_perf_report.sh (or
 * ZCL_PERF_REPORT_UNDER_TEST when that is set) on synthetic logs.
 * 0 and the PASS line when every accounting check holds. 1 otherwise.
 * report_path is the fallback script; the env value wins when set. */
int zcl_zcode_async_proof_perf_selftest(const char *report_path);

#endif
