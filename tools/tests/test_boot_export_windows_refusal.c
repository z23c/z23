/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: proves boot_export_consensus_bundle() honours its documented
 * TERMINAL contract (config/include/config/boot.h) and never returns. It is
 * called with the datadir from argv[1]; the trailing `return 3` is reachable
 * only if that contract was broken. */
#include "config/boot.h"
#include "base/log_level.h"

enum zcl_log_level zcl_log_level_get(void)
{
    return ZCL_LOG_ALL;
}

int main(int argc, char **argv)
{
    if (argc != 2)
        return 2;
    boot_export_consensus_bundle(NULL, NULL, argv[1]);
    return 3;
}
