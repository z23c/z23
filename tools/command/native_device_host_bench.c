/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * Purpose: typed in-process PSK tunnel throughput benchmark leaf. */
#define _GNU_SOURCE
#include "command/native_command.h"
#include "services/device_host_bench.h"
#include "platform/clock.h"
#include "util/authority_receipt.h"
#include "util/clientversion.h"
#include "util/log_macros.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>

static void bench_refuse(struct zcl_command_reply *reply, enum zcl_command_exit exit_code, const char *code,
    bool mutated, const char *message)
{
    LOG_ERROR("native.device.host.bench", "%s", message);
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED, exit_code, code, "host_bench", false, mutated,
        message, "mib 1..512, repeats 1..5, optional absolute receipt_out path");
}
/* Absent keys take the default; a present key must already be the bounded integer
 * the registry admitted, re-checked here so a direct handler call cannot widen it. */
static bool bench_int(const struct json_value *input, const char *key, int64_t fallback, int64_t lo, int64_t hi, int64_t *out)
{
    const struct json_value *value = input ? json_get(input, key) : NULL;
    *out = fallback;
    if (!value) return true;
    if (value->type != JSON_INT) return false;
    *out = json_get_int(value);
    return *out >= lo && *out <= hi;
}
static bool bench_push_reals(struct json_value *object, const char *key, const double *values, size_t count)
{
    struct json_value array, item;
    json_init(&array); json_set_array(&array);
    bool ok = true;
    for (size_t i = 0; i < count && ok; ++i) {
        json_init(&item); json_set_real(&item, values[i]);
        ok = json_push_back(&array, &item);
        json_free(&item);
    }
    ok = ok && json_push_kv(object, key, &array);
    json_free(&array);
    return ok;
}
static bool bench_build_flags(struct json_value *object)
{
    struct json_value flags;
    json_init(&flags); json_set_object(&flags);
    bool optimized = false, ndebug = false, testing = false, sanitizer = false;
#ifdef __OPTIMIZE__
    optimized = true;
#endif
#ifdef NDEBUG
    ndebug = true;
#endif
#ifdef ZCL_TESTING
    testing = true;
#endif
#if defined(__SANITIZE_ADDRESS__) || defined(__SANITIZE_THREAD__) || defined(__SANITIZE_UNDEFINED__)
    sanitizer = true;
#endif
#ifdef __VERSION__
    const char *compiler = __VERSION__;
#else
    const char *compiler = "unknown";
#endif
    bool ok = json_push_kv_bool(&flags, "optimized", optimized) && json_push_kv_bool(&flags, "ndebug", ndebug) &&
        json_push_kv_bool(&flags, "zcl_testing", testing) && json_push_kv_bool(&flags, "sanitizer", sanitizer) &&
        json_push_kv_str(&flags, "compiler", compiler) && json_push_kv(object, "build_flags", &flags);
    json_free(&flags);
    return ok;
}
static double bench_load1(void)
{
    double load[3];
#if defined(__linux__) || defined(__APPLE__)
    if (getloadavg(load, 3) >= 1) return load[0];
#else
    (void)load;
#endif
    return -1.0;
}
static bool bench_ratio(struct json_value *data, const char *key, uint64_t full, uint64_t cached, uint64_t records)
{
    struct json_value ratio;
    json_init(&ratio); json_set_object(&ratio);
    bool ok = json_push_kv_real(&ratio, "full", records ? (double)full / (double)records : 0.0) &&
        json_push_kv_real(&ratio, "cached", records ? (double)cached / (double)records : 0.0) &&
        json_push_kv(data, key, &ratio);
    json_free(&ratio);
    return ok;
}
/* acquisitions_per_record divides by the 4 KiB-equivalent count; acquisitions_per_sealed_record by the
 * DATA records actually sealed, which is what the guard cost really amortises over. */
static bool bench_per_record(struct json_value *data, const struct device_host_bench_result *bench)
{
    uint64_t full = 0, cached = 0, records = 0, sealed = 0;
    for (unsigned i = 0; i < bench->repeats; ++i) {
        full += bench->runs[i].full_acquisitions; cached += bench->runs[i].cached_acquisitions;
        records += bench->runs[i].records; sealed += bench->runs[i].sealed_records;
    }
    return bench_ratio(data, "acquisitions_per_record", full, cached, records) &&
        bench_ratio(data, "acquisitions_per_sealed_record", full, cached, sealed);
}
static bool bench_provenance(struct json_value *data, const struct device_host_bench_result *bench)
{
    int64_t wall_ms = clock_now_wall_ms();
    time_t seconds = (time_t)(wall_ms / 1000);
    struct tm utc; char stamp[32] = "";
    if (gmtime_r(&seconds, &utc)) (void)strftime(stamp, sizeof(stamp), "%Y-%m-%dT%H:%M:%SZ", &utc);
    return bench_build_flags(data) && json_push_kv_str(data, "source_id_sha256", zcl_build_source_id_sha256()) &&
        json_push_kv_real(data, "host_load1", bench_load1()) &&
        json_push_kv_bool(data, "profile_removed", bench->profile_removed) &&
        json_push_kv_str(data, "timestamp", stamp) && json_push_kv_int(data, "timestamp_unix_ms", wall_ms);
}
static bool bench_build(struct json_value *data, const struct device_host_bench_result *bench)
{
    double forward[DEVICE_HOST_BENCH_REPEATS_MAX], reverse[DEVICE_HOST_BENCH_REPEATS_MAX];
    for (unsigned i = 0; i < bench->repeats; ++i) {
        forward[i] = bench->runs[i].forward_mib_s; reverse[i] = bench->runs[i].reverse_mib_s;
    }
    json_set_object(data);
    return json_push_kv_str(data, "schema", "zcl.tunnel_bench.v1") && json_push_kv_int(data, "mib", (int64_t)bench->mib) &&
        json_push_kv_int(data, "repeats", bench->repeats) &&
        json_push_kv_real(data, "forward_mib_s", device_host_bench_median(forward, bench->repeats)) &&
        json_push_kv_real(data, "reverse_mib_s", device_host_bench_median(reverse, bench->repeats)) &&
        bench_push_reals(data, "forward_runs_mib_s", forward, bench->repeats) &&
        bench_push_reals(data, "reverse_runs_mib_s", reverse, bench->repeats) &&
        json_push_kv_int(data, "records", (int64_t)bench->runs[0].records) &&
        json_push_kv_int(data, "sealed_records", (int64_t)bench->runs[0].sealed_records) &&
        bench_per_record(data, bench) && bench_provenance(data, bench);
}

/* tmp -> fsync -> rename -> fsync(dir) beside the named leaf; the parent must already exist. */
static bool bench_write_receipt(const struct json_value *data, const char *path)
{
    char text[4096], directory[1024];
    size_t length = json_write(data, text, sizeof(text));
    const char *slash = strrchr(path, '/');
    size_t directory_length = slash == path ? 1 : (size_t)(slash - path);
    if (length == 0 || length >= sizeof(text) || !slash[1] || directory_length >= sizeof(directory)) return false;
    memcpy(directory, path, directory_length);
    directory[directory_length] = '\0';
    return authority_receipt_write_atomic(directory, slash + 1, (const uint8_t *)text, length, NULL, 0);
}

void zcl_native_handle_ops_mesh_device_host_bench(const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    if (!request || !reply) return;
    int64_t mib, repeats;
    if (!bench_int(request->input, "mib", 64, 1, DEVICE_HOST_BENCH_MIB_MAX, &mib) ||
        !bench_int(request->input, "repeats", 3, 1, DEVICE_HOST_BENCH_REPEATS_MAX, &repeats)) {
        bench_refuse(reply, ZCL_COMMAND_EXIT_INVALID, "TUNNEL_BENCH_INPUT_REFUSED", false, "mib must be 1..512 and repeats 1..5");
        return;
    }
    const struct json_value *out_value = request->input ? json_get(request->input, "receipt_out") : NULL;
    const char *receipt_out = out_value ? (out_value->type == JSON_STR ? json_get_str(out_value) : "") : NULL;
    if (receipt_out && (!receipt_out[0] || receipt_out[0] != '/')) {
        bench_refuse(reply, ZCL_COMMAND_EXIT_INVALID, "TUNNEL_BENCH_RECEIPT_PATH_REFUSED", false, "receipt_out must be an absolute file path");
        return;
    }
    struct device_host_bench_result bench;
    struct zcl_result run = device_host_bench_run((size_t)mib, (unsigned)repeats, &bench);
    if (!run.ok) {
        bench_refuse(reply, ZCL_COMMAND_EXIT_FAILED, "TUNNEL_BENCH_FAILED", false, run.message);
        return;
    }
    if (!bench_build(&reply->data, &bench)) {
        bench_refuse(reply, ZCL_COMMAND_EXIT_INTERNAL, "TUNNEL_BENCH_REPLY_FAILED", false, "benchmark result could not be built");
        return;
    }
    if (receipt_out) {
        if (!bench_write_receipt(&reply->data, receipt_out)) {
            bench_refuse(reply, ZCL_COMMAND_EXIT_FAILED, "TUNNEL_BENCH_RECEIPT_WRITE_FAILED", false, "receipt_out could not be written atomically");
            return;
        }
        reply->error.mutated = true;
    }
}
