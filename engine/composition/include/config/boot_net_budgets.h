/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Network-buffer budget boot adapter — declares the RAM-class env defaults
 * for the peer-path totals bounded in core/modules/net/src/net.c
 * (ZCL_MAX_SENDBUFFER_TOTAL_BYTES / ZCL_MAX_RECVBUFFER_TOTAL_BYTES) and the
 * boot_services.c entry point that registers the net_budgets service.
 * See engine/composition/src/boot_net_budgets.c for the decision table. */

#ifndef ZCL_BOOT_NET_BUDGETS_H
#define ZCL_BOOT_NET_BUDGETS_H

#include <stdbool.h>
#include <stdint.h>

#include "util/hw_profile.h"

struct boot_svc_ctx;

#ifdef __cplusplus
extern "C" {
#endif

/* Peer-path total byte budgets per RAM class. LOW 128 MiB send / 64 MiB
 * recv; MEDIUM 256 MiB / 128 MiB; HIGH refuses (kernel/core defaults stand,
 * byte-identical behavior). */
struct boot_net_budgets {
    int64_t send_total_bytes;
    int64_t recv_total_bytes;
};

/* Pure per-class decision — no env reads, no hardware probing. Returns
 * true and fills *out for LOW and MEDIUM; returns false for HIGH (and
 * refuses a NULL out), leaving *out untouched. */
bool boot_net_budgets_for_class(enum hw_profile_ram_class cls,
                                struct boot_net_budgets *out);

/* Sets each budget env var ONLY when it is absent, so an explicit operator
 * env always wins (an empty value counts as present, matching net.c's own
 * env parse, which ignores empty). HIGH sets nothing and returns true;
 * a failed setenv logs and returns false. */
bool boot_net_budgets_apply_class(enum hw_profile_ram_class cls);

/* Registers the net_budgets service on svc->service_kernel (before the
 * mempool_limits adapter's start_all, so the kernel starts it first and the
 * defaults are in place before peers or admission run). Returns false (with
 * a FATAL message already printed) on register failure — app_init_services
 * must abort boot in that case. */
bool boot_start_net_budgets_service(struct boot_svc_ctx *svc);

#ifdef __cplusplus
}
#endif

#endif /* ZCL_BOOT_NET_BUDGETS_H */
