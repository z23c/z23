/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Host entry for the agent baseline pin. */

#include "agent_baseline.h"

#include <stddef.h>

int main(int argc, char **argv)
{
    char **files = argv;
    int n = 0;
    if (argc > 1) {
        files = argv + 1;
        n = argc - 1;
    }
    return zcl_agent_baseline(NULL, n, files);
}
