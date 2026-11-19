/* purpose: standalone build/bin/peer_chain_recovery entry point */
/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "multicall.h"

int main(int argc, char **argv)
{
    return peer_chain_recovery_main(argc, argv);
}
