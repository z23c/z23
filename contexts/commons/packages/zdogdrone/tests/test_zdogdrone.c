/* zdogdrone tests: born-red determinism + fixed strategy vectors. */
#include <stdio.h>
#include <string.h>

#include "zdogdrone/zdogdrone.h"

static int fails;

#define CHECK(cond)                                                        \
    do {                                                                   \
        if (!(cond)) {                                                     \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            fails++;                                                       \
        }                                                                  \
    } while (0)

static zdog_obs base_obs(void)
{
    zdog_obs o;
    memset(&o, 0, sizeof(o));
    o.tick = 100;
    o.self_index = 1;
    o.num_planes = 4;
    o.x = 12345;
    o.y = 200000;
    o.z = -54321;
    o.yaw = 10000;
    o.speed = 60000;
    o.health = 100;
    o.team = 1;
    o.ticks_left = 35900;
    return o;
}

int main(void)
{
    zdog_obs o = base_obs();
    zdog_ctl a, b;

    /* Born-red determinism: identical observations give byte-identical
     * controls, every time. */
    zdogdrone_step(&o, &a);
    zdogdrone_step(&o, &b);
    CHECK(memcmp(&a, &b, sizeof(a)) == 0);

    /* Baseline posture: gentle right bank, level pitch, cruise. */
    CHECK(a.roll == 8192);
    CHECK(a.pitch == 0);
    CHECK(a.throttle == 18000);
    CHECK(a.fire == 0);

    /* Enemy in range -> trigger held. */
    o.enemy_valid = 1;
    o.dist = 119999;
    zdogdrone_step(&o, &a);
    CHECK(a.fire == 1);

    /* Boundary: exactly 120 m is out of range. */
    o.dist = 120000;
    zdogdrone_step(&o, &a);
    CHECK(a.fire == 0);

    /* Invalid enemy never fires, even with a stale small dist. */
    o.enemy_valid = 0;
    o.dist = 5;
    zdogdrone_step(&o, &a);
    CHECK(a.fire == 0);

    /* NULL safety: no crash, no output contract. */
    zdogdrone_step(NULL, NULL);

    if (fails) {
        fprintf(stderr, "zdogdrone: %d failure(s)\n", fails);
        return 1;
    }
    puts("zdogdrone: ok");
    return 0;
}
