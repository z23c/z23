/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Mempool-limits boot adapter — declares the single entry point boot_services.c
 * calls from app_init_services to register and start the mempool_limits
 * service. See engine/composition/src/boot_mempool_limits.c for the pure-relocation
 * rationale (same pattern as boot_msg_callbacks.h / boot_background_workers.h). */

#ifndef ZCL_BOOT_MEMPOOL_LIMITS_H
#define ZCL_BOOT_MEMPOOL_LIMITS_H

#include "config/boot_internal.h"

/* Registers the mempool_limits service on svc->service_kernel (if
 * svc->db_service is present) and starts every service registered on that
 * kernel. Returns false (with a FATAL message already printed) on register
 * or start failure — app_init_services must abort boot in that case. */
bool boot_start_mempool_limits_service(struct boot_svc_ctx *svc);

#endif
