/* zdogace — pursuit pilot for the zdogfight arena (C23).
 *
 * A deterministic starter pilot: pure integer function of the bounded
 * zdog_obs observation, no state between calls, no randomness, no I/O.
 * Strategy: bank-to-turn pursuit of the nearest enemy — roll toward the
 * lateral bearing error, pitch toward the elevation error, full
 * throttle, fire when roughly aligned and in range.
 *
 * Apache-2.0 licensed.
 */
#ifndef ZDOGACE_H
#define ZDOGACE_H

#include "zdogfight/zdogfight.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Pure: same observation in -> same controls out, on any machine. */
void zdogace_step(const zdog_obs *obs, zdog_ctl *out);

#ifdef __cplusplus
}
#endif

#endif /* ZDOGACE_H */
