/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Host entry for one-command simnet capsule replay. */

#include "simnet_replay_capsule.h"

int main(int argc, char **argv)
{
    return zcl_simnet_replay_capsule(argc, argv);
}
