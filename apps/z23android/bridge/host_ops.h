/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef Z23_ANDROID_HOST_OPS_H
#define Z23_ANDROID_HOST_OPS_H
#include "fleet_probe.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* The only actions the phone can request, each mapped to one fixed command on a configured host:
 * errors   z23 ops logs, a read-only tail of recent ERROR lines
 * plan     z23 ops node restart, which changes nothing and returns a plan id
 * confirm  z23 ops node restart with that plan id and confirm, run only for the plan issued here. */
enum zapp_ops_action { ZAPP_OPS_ERRORS, ZAPP_OPS_PLAN, ZAPP_OPS_CONFIRM };
enum { ZAPP_OPS_HOSTS = 16, ZAPP_OPS_PLAN_ID = 32, ZAPP_OPS_PLAN_TTL_S = 280 };

/* Runs command on host and copies its output to out; false when the host did not answer. */
typedef bool (*zapp_ops_exec)(const struct zapp_fleet_host *host, const char *command, int timeout_ms,
                              char *out, size_t cap, void *ctx);
struct zapp_ops {
    zapp_ops_exec exec;
    void *ctx;
    struct { char id[ZAPP_OPS_PLAN_ID + 1]; int64_t issued; } plans[ZAPP_OPS_HOSTS]; /* One per host. */
};
/* Parses "<action> <label>" or "confirm <label> <plan id>" against the configured hosts. The label
 * must equal a configured label and the plan id must be 32 lowercase hex digits; nothing else
 * reaches a command. Returns the host, or NULL when the request is refused. */
const struct zapp_fleet_host *zapp_ops_parse(const struct zapp_fleet_host *hosts, size_t count,
                                             const char *scope, enum zapp_ops_action *action,
                                             char plan_id[ZAPP_OPS_PLAN_ID + 1]);
/* Handles one request at unix time now. Writes {"host","action","text"[,"plan_id"]} on success or
 * {"host","error"} when refused or failed. A plan id is accepted once, for its host, within its
 * lifetime; a confirm spends it whether or not the restart then succeeds. False only when out is
 * too small. At most ZAPP_OPS_HOSTS hosts. */
bool zapp_ops_handle(struct zapp_ops *ops, const struct zapp_fleet_host *hosts, size_t count,
                     const char *scope, int64_t now, char *out, size_t cap);
#endif
