/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Host entry for `make attestation-flight-acceptance`. */

#include "attestation_flight.h"
#include "dev_script_dir.h"

#include <stdio.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

int main(void)
{
#if defined(_WIN32)
    fprintf(stderr, "attestation-flight-acceptance: unavailable on Windows\n");
    return 2;
#else
    char dir[PATH_MAX];
    if (zcl_dev_script_dir(dir, sizeof dir) != 0) {
        fprintf(stderr,
                "attestation-flight-acceptance: cannot locate tools/dev\n");
        return 2;
    }
    return zcl_attestation_flight_launch(dir);
#endif
}
