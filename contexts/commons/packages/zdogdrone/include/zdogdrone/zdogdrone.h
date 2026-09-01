/* zdogdrone — circling gunner pilot for the zdogfight arena (C23).
 *
 * A deterministic starter pilot: pure integer function of the bounded
 * zdog_obs observation, no state between calls, no randomness, no I/O.
 * Strategy: hold a constant gentle bank to fly a wide circle at cruise
 * throttle; fire whenever the nearest enemy is inside 120 m — the
 * circle strays across the enemy often enough to land hits.
 *
 * Deliberately simple: it is the baseline opponent every other pilot
 * must beat, and the born-red reference for determinism tests.
 *
 * Apache-2.0 licensed.
 */
#ifndef ZDOGDRONE_H
#define ZDOGDRONE_H

#include "zdogfight/zdogfight.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Pure: same observation in -> same controls out, on any machine. */
void zdogdrone_step(const zdog_obs *obs, zdog_ctl *out);

#ifdef __cplusplus
}
#endif

#endif /* ZDOGDRONE_H */
