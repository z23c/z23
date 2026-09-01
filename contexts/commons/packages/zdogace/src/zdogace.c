/* zdogace — pursuit pilot implementation. Pure integer math: lateral
 * steering from the 2D cross product of own forward with the relative
 * enemy bearing (no atan2), elevation from the vertical error, all in
 * Q1.15 against the arena's own trig (zdog_sin16/zdog_cos16). */
#include "zdogace/zdogace.h"

static int16_t clamp15(int32_t v)
{
    if (v > 32767) return 32767;
    if (v < -32767) return -32767;
    return (int16_t)v;
}

void zdogace_step(const zdog_obs *obs, zdog_ctl *out)
{
    if (!obs || !out)
        return;
    out->roll = 0;
    out->pitch = 0;
    out->throttle = 16000; /* cruise */
    out->fire = 0;

    if (!obs->enemy_valid)
        return; /* straight cruise, keep scanning */

    out->throttle = 32767;

    /* Own forward in the ground plane (Q1.15). */
    int32_t fx = zdog_sin16(obs->yaw);
    int32_t fz = zdog_cos16(obs->yaw);

    /* Relative bearing normalized to Q1.15 (dist > 0 when valid). */
    int64_t rx = obs->rel_x, rz = obs->rel_z;
    int32_t rxq = 0, rzq = 0;
    if (obs->dist > 0) {
        rxq = (int32_t)((rx * 32767) / (int64_t)obs->dist);
        rzq = (int32_t)((rz * 32767) / (int64_t)obs->dist);
    }
    /* cross = sin(yaw - bearing): cross < 0 means the enemy is to the
     * RIGHT (bearing > yaw), and the sim turns right (yaw increases)
     * when roll is POSITIVE — so steer roll opposite to cross. */
    int32_t cross = (int32_t)((fx * (int64_t)rzq - fz * (int64_t)rxq) >> 15);
    int32_t dot = (int32_t)((fx * (int64_t)rxq + fz * (int64_t)rzq) >> 15);
    out->roll = clamp15(-2 * cross);

    /* Elevation: the sim's forward vertical component is -sin(pitch),
     * so steer pitch toward -(normalized rel_y + sin(own pitch)). */
    int32_t ryq = 0;
    if (obs->dist > 0)
        ryq = (int32_t)(((int64_t)obs->rel_y * 32767) / (int64_t)obs->dist);
    int32_t ep = ryq + zdog_sin16(obs->pitch);
    out->pitch = clamp15(-2 * ep);

    /* Fire when roughly aligned (within ~20 deg) and inside 300 m. */
    if (dot > 31129 && cross > -3000 && cross < 3000 &&
        obs->dist > 0 && obs->dist < 300000)
        out->fire = 1;
}
