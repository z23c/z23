/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: the entry point of z23-lab-peer's "shadow" subcommand
 * (tools/lab_peer_shadow.c), called from main in tools/lab_peer.c.
 */
#ifndef LAB_PEER_SHADOW_H
#define LAB_PEER_SHADOW_H

/* argv[1] is "shadow". Returns the process exit status. */
int lab_peer_shadow_main(int argc, char **argv);

#endif
