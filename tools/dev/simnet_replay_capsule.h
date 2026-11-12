/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Replay wire_sweep seeds named by saved capsule filenames. */

#ifndef ZCL_SIMNET_REPLAY_CAPSULE_H
#define ZCL_SIMNET_REPLAY_CAPSULE_H

/* argv is the shell's argv: program, capsule path, wire_sweep binary,
 * optional artifact directory. 0 when every matched seed passes. 1 when a
 * replay fails or no seed name matches. 2 on usage or a missing input. */
int zcl_simnet_replay_capsule(int argc, char **argv);

#endif
