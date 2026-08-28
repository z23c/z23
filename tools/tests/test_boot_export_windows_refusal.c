/* Copyright 2026 Rhett Creighton - Apache License 2.0 */
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
