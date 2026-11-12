/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Host entry for the read-only Git hook status report. */

#include "hooks_status.h"

#include <stddef.h>

int main(void)
{
    return zcl_hooks_status(NULL);
}
