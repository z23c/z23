/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Host entry for the node Tor stamp. */

#include "tor_stamp.h"

#include <stdio.h>
#include <string.h>

static int ts_usage(void)
{
    fprintf(stderr,
            "usage: tor-stamp require-full NODE [CONTEXT]\n"
            "       tor-stamp write-sidecar NODE\n"
            "       tor-stamp show NODE\n");
    return 2;
}

static int ts_cli_require(int argc, char **argv)
{
    const char *context = NULL;
    if (argc < 3)
        return ts_usage();
    if (argc >= 4)
        context = argv[3];
    return zcl_tor_require_full(argv[2], context) == 0 ? 0 : 1;
}

static int ts_cli_write(int argc, char **argv)
{
    if (argc < 3)
        return ts_usage();
    return zcl_tor_write_stamp_sidecar(argv[2]) == 0 ? 0 : 1;
}

static int ts_cli_show(int argc, char **argv)
{
    char stamp[8];
    if (argc < 3)
        return ts_usage();
    if (zcl_tor_stamp(argv[2], stamp, sizeof stamp) != 0)
        return 1;
    printf("%s\n", stamp);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 2)
        return ts_usage();
    if (strcmp(argv[1], "require-full") == 0)
        return ts_cli_require(argc, argv);
    if (strcmp(argv[1], "write-sidecar") == 0)
        return ts_cli_write(argc, argv);
    if (strcmp(argv[1], "show") == 0)
        return ts_cli_show(argc, argv);
    return ts_usage();
}
