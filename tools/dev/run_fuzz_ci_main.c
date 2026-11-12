/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Host entry for the fuzz-ci slot runner. */

#include "run_fuzz_ci.h"

#include <stddef.h>

int main(int argc, char **argv)
{
    if (argc < 1 || argv == NULL)
        return 1;
    return zcl_run_fuzz_ci(argc - 1, argv + 1);
}
