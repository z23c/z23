/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: fleet.vitals.read - measure THIS machine now and say so.
 *
 * Read-only and local. It shares fleet.vitals.sample's measurement
 * (zcl_fleet_host_snapshot) and adds only what a table needs: the 5 and 15
 * minute load, disk total and used. It appends no ledger row and writes no
 * file. A fact this platform cannot give is JSON null, never zero.
 *
 * OUTPUT (zcl.fleet_vitals_read.v1)
 *   schema, host (hostname, at most 64 bytes), cpus, load1_centi,
 *   load5_centi, load15_centi, mem_total_mib, mem_avail_mib, mem_used_mib,
 *   disk_total_mib, disk_used_mib, disk_free_mib (the home filesystem; free
 *   is what an unprivileged user may use, used is total minus free),
 *   uptime_s (whole-machine uptime; null where the platform cannot say). */

/* Z23_TOOL_V1
{
  "profile": "readonly-local-v1",
  "path": "fleet.vitals.read",
  "parent": "fleet.vitals",
  "handler": "zcl_native_handle_fleet_vitals_read",
  "summary": "Measure this box now: load, memory, disk and uptime",
  "semantics": [
    "Measures this machine once through the same platform seam that ",
    "fleet.vitals.sample uses and reports load 1/5/15, cpu count, memory ",
    "total/available/used, home-filesystem disk total/used/free and uptime. ",
    "A fact this platform cannot measure is null, never zero. It appends no ",
    "ledger row, writes no file and contacts no peer."
  ],
  "input_schema": "zcl.command.empty_input.v1",
  "output_schema": "zcl.fleet_vitals_read.v1",
  "input_keys": [],
  "example": "z23 fleet vitals read",
  "tags": ["fleet", "vitals", "read", "load", "memory", "disk"],
  "authority": "operator",
  "budget_bytes": 4096,
  "latency": "instant",
  "cost": "tiny",
  "test_group": "fleet_vitals_read"
}
*/

#define _DEFAULT_SOURCE 1 /* getloadavg */

#include "command/native_command.h"
#include "command/native_fleet.h"

#include "json/json.h"
#include "platform/disk_space.h"
#include "platform/os_proc.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if !defined(_WIN32)
#include <unistd.h>
#endif

#define MIB UINT64_C(1048576)

static void vitals_home(char *out, size_t cap)
{
    const char *home = getenv("HOME");
    if (home && home[0] == '/' && strlen(home) < cap)
        snprintf(out, cap, "%s", home);
    else
        snprintf(out, cap, "%s", "/");
}

static void vitals_load(struct zcl_fleet_vitals_now *out)
{
    out->load5_centi = out->load15_centi = -1;
#if !defined(_WIN32)
    double avg[3];
    if (getloadavg(avg, 3) == 3 && avg[1] >= 0 && avg[2] >= 0) {
        out->load5_centi = (int64_t)(avg[1] * 100.0);
        out->load15_centi = (int64_t)(avg[2] * 100.0);
    }
#endif
}

void zcl_fleet_vitals_measure(struct zcl_fleet_vitals_now *out)
{
    char home[512];
    int64_t v[ZCL_FLEET_HOST_N];
    bool p[ZCL_FLEET_HOST_N];
    memset(out, 0, sizeof *out);
    vitals_home(home, sizeof home);
    zcl_fleet_host_snapshot(home, v, p);
    out->cpus = p[1] ? v[1] : -1;
    out->load1_centi = p[0] ? v[0] : -1;
    vitals_load(out);
    out->mem_total_mib = p[4] ? v[4] : -1;
    out->mem_used_mib = p[3] ? v[3] : -1;
    out->mem_avail_mib = p[3] && p[4] ? v[4] - v[3] : -1;
    out->uptime_s = os_proc_system_uptime_seconds();
    out->jobs_running = out->jobs_queued = -1;
    out->disk_total_mib = out->disk_used_mib = out->disk_free_mib = -1;
    uint64_t avail = 0, total = 0;
    if (platform_disk_space(home, &avail, &total) && total >= avail) {
        out->disk_total_mib = (int64_t)(total / MIB);
        out->disk_free_mib = (int64_t)(avail / MIB);
        out->disk_used_mib = (int64_t)((total - avail) / MIB);
    }
#if !defined(_WIN32)
    if (gethostname(out->host, sizeof out->host) != 0)
        out->host[0] = '\0';
    out->host[sizeof out->host - 1] = '\0';
#endif
}

void zcl_fleet_vitals_measure_queue(struct zcl_fleet_vitals_now *out)
{
    int64_t running = 0, queued = 0;
    out->jobs_running = out->jobs_queued = -1;
    if (zcl_native_ops_host_queue_depth(&running, &queued)) {
        out->jobs_running = running;
        out->jobs_queued = queued;
    }
}

static bool vitals_push(struct json_value *obj, const char *key, int64_t value)
{
    if (value >= 0)
        return json_push_kv_int(obj, key, value);
    struct json_value null = {0};
    json_set_null(&null);
    bool ok = json_push_kv(obj, key, &null);
    json_free(&null);
    return ok;
}

static bool vitals_queue_json(struct json_value *data, const struct zcl_fleet_vitals_now *now)
{
    return vitals_push(data, "uptime_s", now->uptime_s) &&
           vitals_push(data, "jobs_running", now->jobs_running) &&
           vitals_push(data, "jobs_queued", now->jobs_queued);
}

void zcl_native_handle_fleet_vitals_read(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    (void)request;
    if (!reply)
        return;
    zcl_command_reply_init(reply, "zcl.fleet_vitals_read.v1");
    struct zcl_fleet_vitals_now now;
    zcl_fleet_vitals_measure(&now);
    zcl_fleet_vitals_measure_queue(&now);
    bool ok = json_push_kv_str(&reply->data, "schema", "zcl.fleet_vitals_read.v1") &&
              json_push_kv_str(&reply->data, "host", now.host) &&
              vitals_push(&reply->data, "cpus", now.cpus) &&
              vitals_push(&reply->data, "load1_centi", now.load1_centi) &&
              vitals_push(&reply->data, "load5_centi", now.load5_centi) &&
              vitals_push(&reply->data, "load15_centi", now.load15_centi) &&
              vitals_push(&reply->data, "mem_total_mib", now.mem_total_mib) &&
              vitals_push(&reply->data, "mem_avail_mib", now.mem_avail_mib) &&
              vitals_push(&reply->data, "mem_used_mib", now.mem_used_mib) &&
              vitals_push(&reply->data, "disk_total_mib", now.disk_total_mib) &&
              vitals_push(&reply->data, "disk_used_mib", now.disk_used_mib) &&
              vitals_push(&reply->data, "disk_free_mib", now.disk_free_mib) &&
              vitals_queue_json(&reply->data, &now);
    if (!ok) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_FAILED, "VITALS_READ_ALLOC",
                               "read", false, false,
                               "the reading could not be built", "");
        return;
    }
    reply->status = ZCL_COMMAND_STATUS_PASSED;
    reply->exit_code = ZCL_COMMAND_EXIT_OK;
}
