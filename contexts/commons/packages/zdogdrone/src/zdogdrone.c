/* zdogdrone — circling gunner pilot implementation. No math at all:
 * a fixed control setting plus a range-gated trigger. Determinism is
 * trivially exact. */
#include "zdogdrone/zdogdrone.h"

void zdogdrone_step(const zdog_obs *obs, zdog_ctl *out)
{
    if (!obs || !out)
        return;

    /* Gentle constant right bank (~20 deg -> steady circle), level
     * pitch, moderate cruise throttle (~55 m/s). */
    out->roll = 8192;
    out->pitch = 0;
    out->throttle = 18000;
    out->fire = 0;

    /* Shoot at anything living inside 120 m; the arena enforces the
     * cooldown, so holding the trigger is safe and exact. */
    if (obs->enemy_valid && obs->dist > 0 && obs->dist < 120000)
        out->fire = 1;
}
