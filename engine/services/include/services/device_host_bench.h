/* purpose: Declare the in-process PSK tunnel throughput benchmark shared by the ops leaf and the bridge test. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZCL_SERVICES_DEVICE_HOST_BENCH_H
#define ZCL_SERVICES_DEVICE_HOST_BENCH_H
#include "base/result.h"
#include "platform/temp_directory.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

enum { DEVICE_HOST_BENCH_MIB_MAX = 512, DEVICE_HOST_BENCH_REPEATS_MAX = 5 };

struct device_host_bench_run {
    double forward_mib_s, reverse_mib_s;
    uint64_t records, full_acquisitions, cached_acquisitions;
};
struct device_host_bench_result {
    size_t mib;
    unsigned repeats;
    struct device_host_bench_run runs[DEVICE_HOST_BENCH_REPEATS_MAX];
    /* The private temp profile root the run used; it is removed before return. */
    char profile_root[PLATFORM_TEMP_PATH_MAX];
    bool profile_removed;
};

/* Run `repeats` full duplex transfers of `mib` MiB per direction through the
 * real receiver/client PSK bridge pair over in-process sockets, with a
 * throwaway paired authority in a private temp directory. The operator's real
 * pairing profile is never opened. Failure is a refusal, never a partial
 * measurement; the temp profile is removed on every path. */
struct zcl_result device_host_bench_run(size_t mib, unsigned repeats, struct device_host_bench_result *out);

/* Median of the per-run values (mean of the two middle values when even). */
double device_host_bench_median(const double *values, size_t count);
#endif
