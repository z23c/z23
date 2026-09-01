/* zdogfix — internal fixed-point helpers for zdogfight: brad16 trig on
 * a quarter-wave table and floor-semantics Q1.15 scaling. Not part of
 * the public API; shared between the library sources and the tests.
 *
 * Apache-2.0 licensed.
 */
#ifndef ZDOGFIX_H
#define ZDOGFIX_H

#include <stdint.h>

/* sin/cos of a brad16 angle (65536 == 360 deg), returning Q1.15
 * (32767 == 1.0). Pure integer: 256-entry quarter-wave table plus
 * linear interpolation. */
int16_t zdog_sin(uint16_t brad);
int16_t zdog_cos(uint16_t brad);

/* floor(v / 2^15) for signed v — portable floor semantics, never the
 * implementation-defined arithmetic right shift on negative values. */
int32_t zdog_floor_q15(int64_t v);

#endif /* ZDOGFIX_H */
