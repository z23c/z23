/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: portable acceptance for the log-level seam -- parses a level
 * name, sets the process level, and emits one record through
 * zcl_log_emit_at(). Runs natively on POSIX as well as Windows. */
#include "base/log_level.h"

#include <stdio.h>

int main(void)
{
    enum zcl_log_level parsed = ZCL_LOG_OFF;
    if (!zcl_log_level_from_string("warn", &parsed) ||
        parsed != ZCL_LOG_WARN)
        return 1;
    zcl_log_level_set(ZCL_LOG_ALL);
    zcl_log_emit_at(ZCL_LOG_INFO, "log_level_acceptance marker");
    fputc('\n', stderr);
    puts("log_level_acceptance: PASS");
    return 0;
}
