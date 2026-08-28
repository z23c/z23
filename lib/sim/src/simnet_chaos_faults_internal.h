/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Purpose: the chaos-fault injectors' private cross-TU contract — the four
 * shared result-note/pacing helpers that the three chaos-fault translation
 * units hand back and forth.
 *
 * simnet_chaos_faults.c owns faults (a)-(f) and (n)-(p): the stage-log,
 * segment, supervisor, condition and progress.kv fixtures.
 * simnet_chaos_faults_rom.c owns the ROM-artifact fixture family and faults
 * (g)-(i). simnet_chaos_faults_download.c owns faults (j)-(m), the
 * download/peer-behaviour matrix. The split happened when the combined file
 * passed the 800-line shape ceiling. These four declarations are all that
 * crosses those seams, so they live here and nowhere else — nothing outside
 * those three translation units may include this header.
 */

#ifndef ZCL_SIM_SIMNET_CHAOS_FAULTS_INTERNAL_H
#define ZCL_SIM_SIMNET_CHAOS_FAULTS_INTERNAL_H

#include "sim/simnet_chaos_faults.h"

#include <stdint.h>

/* Format a single-line outcome note into `out->note`. Defined in
 * simnet_chaos_faults.c. */
void chaos_note(struct chaos_fault_result *out, const char *fmt, ...);

/* Zero a sync-fault capsule and stamp its seed / sentinel heights. Defined
 * in simnet_chaos_faults_rom.c. */
void sfm_capsule_init(struct sync_fault_capsule *out, uint64_t seed);

/* chaos_note() for a sync-fault capsule — writes into the embedded
 * base.note. Defined in simnet_chaos_faults_rom.c. */
void sfm_note(struct sync_fault_capsule *out, const char *fmt, ...);

#ifdef ZCL_TESTING
/* Sleep `ms` milliseconds. Only the ZCL_TESTING-only fault bodies use it, so
 * it is declared under the same guard as its definition in
 * simnet_chaos_faults.c. */
void chaos_sleep_ms(int ms);
#endif /* ZCL_TESTING */

#endif /* ZCL_SIM_SIMNET_CHAOS_FAULTS_INTERNAL_H */
