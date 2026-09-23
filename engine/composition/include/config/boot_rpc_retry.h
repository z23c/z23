/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Retry an independently failed RPC listener without restarting sibling
 * frontends or claiming readiness before a listening socket exists. */
#ifndef ZCL_CONFIG_BOOT_RPC_RETRY_H
#define ZCL_CONFIG_BOOT_RPC_RETRY_H

#include <stdbool.h>
#include <stdint.h>

struct zcl_service_kernel;

#define BOOT_RPC_START_FAILED_BLOCKER "rpc.start_failed"
#define BOOT_RPC_START_FAILED_OWNER "rpc_http"

void boot_rpc_retry_arm(struct zcl_service_kernel *kernel);
void boot_rpc_retry_disarm(struct zcl_service_kernel *kernel);
bool boot_rpc_retry_failed(void);
bool boot_rpc_retry_due(int64_t now_us);
bool boot_rpc_retry_attempt(int64_t now_us);
bool boot_rpc_retry_recovered(void);

#endif
