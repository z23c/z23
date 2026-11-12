/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Host entry for stable-release containment. */

#include "release_containment.h"

int main(int argc, char **argv)
{
    return zcl_release_invoke(argc, argv);
}
