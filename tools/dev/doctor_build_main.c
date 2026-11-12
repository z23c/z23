/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Host entry for `make doctor-build`. Always exits 0. */

#include "doctor_build.h"

#include <unistd.h>

int main(void)
{
    return zcl_doctor_build(STDOUT_FILENO);
}
