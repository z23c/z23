/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Host entry for service pid and active-state discovery. */

#include "service_args.h"

#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
    char value[256];
    int rc;
    if (argc == 2 && strcmp(argv[1], "--selftest") == 0)
        return zcl_service_args_selftest();
    if (argc != 4 || (strcmp(argv[1], "pid") != 0 &&
                      strcmp(argv[1], "active-state") != 0)) {
        fprintf(stderr,
                "usage: service-args {pid|active-state} UNIT PLIST | --selftest\n");
        return 2;
    }
    rc = strcmp(argv[1], "pid") == 0
             ? zcl_service_query_pid(argv[2], argv[3], value, sizeof value)
             : zcl_service_query_active(argv[2], argv[3], value, sizeof value);
    if (rc != 0)
        return 1;
    printf("%s\n", value);
    return 0;
}
