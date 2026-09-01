/* zdogace tests: born-red determinism + pursuit steering sanity. */
#include <stdio.h>
#include <string.h>

#include "zdogace/zdogace.h"

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
    o.tick = 42;
    o.self_index = 0;
    o.num_planes = 4;
    o.x = 0;
    o.y = 200000;
    o.z = 0;
    o.yaw = 0; /* facing +z (north); forward = (sin0, cos0) = (0, 1) */
    o.pitch = 0;
    o.speed = 60000;
    o.health = 100;
    o.team = 0;
    o.ticks_left = 35958;
    return o;
}

int main(void)
{
    zdog_obs o = base_obs();
    zdog_ctl a, b;

    /* Born-red determinism: identical observations give byte-identical
     * controls. */
    o.enemy_valid = 1;
    o.rel_x = 100000;
    o.rel_y = 0;
    o.rel_z = 100000;
    o.dist = 141421;
    zdogace_step(&o, &a);
    zdogace_step(&o, &b);
    CHECK(memcmp(&a, &b, sizeof(a)) == 0);

    /* No enemy: straight cruise, never fires. */
    o.enemy_valid = 0;
    zdogace_step(&o, &a);
    CHECK(a.roll == 0 && a.pitch == 0 && a.fire == 0);
    CHECK(a.throttle == 16000);

    /* Enemy dead ahead at close range: no roll, fires. */
    o.enemy_valid = 1;
    o.rel_x = 0;
    o.rel_y = 0;
    o.rel_z = 100000;
    o.dist = 100000;
    zdogace_step(&o, &a);
    CHECK(a.roll == 0);
    CHECK(a.fire == 1);
    CHECK(a.throttle == 32767);

    /* Lateral steering, sign pinned against the sim convention
     * (positive roll increases yaw, rotating forward from +z toward
     * +x): enemy at +x while facing +z is to the RIGHT -> roll > 0;
     * the mirror bearing gives the mirror control. */
    o.rel_x = 100000;
    o.rel_z = 0;
    o.dist = 100000;
    zdogace_step(&o, &a);
    CHECK(a.roll > 0);
    o.rel_x = -100000;
    zdogace_step(&o, &b);
    CHECK(b.roll < 0);

    /* Elevation, sign pinned against the sim (forward vertical
     * component is -sin(pitch)): enemy above -> pitch < 0 (climb). */
    o.rel_x = 0;
    o.rel_y = 100000;
    o.rel_z = 0;
    o.dist = 100000;
    zdogace_step(&o, &a);
    CHECK(a.pitch < 0);

    /* Aligned but beyond 300 m: hold fire. */
    o.rel_y = 0;
    o.rel_z = 400000;
    o.dist = 400000;
    zdogace_step(&o, &a);
    CHECK(a.fire == 0);

    /* NULL safety. */
    zdogace_step(NULL, NULL);

    if (fails) {
        fprintf(stderr, "zdogace: %d failure(s)\n", fails);
        return 1;
    }
    puts("zdogace: ok");
    return 0;
}
