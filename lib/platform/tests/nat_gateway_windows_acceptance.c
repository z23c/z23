/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Windows acceptance for NAT default-gateway discovery (GetBestRoute2 arm of
 * nat_get_gateway()). This is the platform seam the NAT-PMP/UPnP client aims
 * at; proving it returns a non-zero IPv4 gateway on a real Windows host is the
 * first step of inbound-P2P hole-punch readiness. */
#if defined(_WIN32)

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include "base/log_level.h"
#include "net/nat.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

enum zcl_log_level zcl_log_level_get(void) { return ZCL_LOG_OFF; }
void zcl_log_emit_at(enum zcl_log_level level, const char *fmt, ...)
{
    (void)level;
    (void)fmt;
}

int main(void)
{
    uint8_t gw[4] = {0};
    if (!nat_get_gateway(gw)) {
        fputs("nat_gateway_acceptance: FAIL: nat_get_gateway() returned false\n",
              stderr);
        return 1;
    }
    if (gw[0] == 0 && gw[1] == 0 && gw[2] == 0 && gw[3] == 0) {
        fputs("nat_gateway_acceptance: FAIL: gateway is 0.0.0.0\n", stderr);
        return 1;
    }
    printf("nat_gateway_acceptance: PASS: gateway=%u.%u.%u.%u\n",
           (unsigned)gw[0], (unsigned)gw[1], (unsigned)gw[2], (unsigned)gw[3]);
    return 0;
}

#else
typedef int nat_gateway_windows_acceptance_not_built;
#endif
