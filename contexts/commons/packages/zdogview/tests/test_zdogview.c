/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * zdogview tests: replay refusal, integer 3D determinism, pixels do not
 * write match state.
 */
#include "zdogview/zdogview.h"

#include <stdio.h>
#include <string.h>

static int fails;

#define CHECK(cond)                                                            \
    do {                                                                       \
        if (!(cond)) {                                                         \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);    \
            fails++;                                                           \
        }                                                                      \
    } while (0)

static void wr_u32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

static void wr_u64(uint8_t *p, uint64_t v)
{
    wr_u32(p, (uint32_t)v);
    wr_u32(p + 4, (uint32_t)(v >> 32));
}

static void pilot_fire(zdog_ctl *c)
{
    c->roll = 0;
    c->pitch = 0;
    c->throttle = 32767;
    c->fire = 1;
}

/* Record a full match into `buf`. Returns byte length, or 0 on overflow. */
static size_t record_match(uint8_t *buf, size_t cap, uint64_t seed,
                           uint8_t planes)
{
    const unsigned n = 2u * planes;
    if (cap < ZDOGVIEW_HEADER_LEN + ZDOG_STATE_WIRE_MAX)
        return 0;
    memcpy(buf, ZDOGVIEW_REPLAY_MAGIC, ZDOGVIEW_REPLAY_MAGIC_LEN);
    wr_u32(buf + ZDOGVIEW_REPLAY_MAGIC_LEN, ZDOGVIEW_REPLAY_VERSION);
    wr_u64(buf + ZDOGVIEW_REPLAY_MAGIC_LEN + 4u, seed);
    buf[ZDOGVIEW_REPLAY_MAGIC_LEN + 4u + 8u] = planes;
    size_t off = ZDOGVIEW_HEADER_LEN;

    zdog_match m;
    zdog_match_init(&m, seed, planes);
    while (m.phase == ZDOG_PHASE_RUNNING) {
        zdog_ctl ctls[ZDOG_MAX_PLANES] = {{0}};
        for (unsigned i = 0; i < n; i++)
            pilot_fire(&ctls[i]);
        if (off + (size_t)n * ZDOG_CTL_WIRE_LEN + ZDOG_STATE_WIRE_MAX > cap)
            return 0;
        for (unsigned i = 0; i < n; i++) {
            if (zdog_ctl_encode(&ctls[i], buf + off, ZDOG_CTL_WIRE_LEN) !=
                ZDOG_CTL_WIRE_LEN)
                return 0;
            off += ZDOG_CTL_WIRE_LEN;
        }
        zdog_tick(&m, ctls);
    }
    if (zdog_state_encode(&m, buf + off, ZDOG_STATE_WIRE_MAX) !=
        ZDOG_STATE_WIRE_MAX)
        return 0;
    return off + ZDOG_STATE_WIRE_MAX;
}

int main(void)
{
    static uint8_t replay[1200000];
    const size_t n = record_match(replay, sizeof(replay), 42, 2);
    CHECK(n > ZDOGVIEW_HEADER_LEN + ZDOG_STATE_WIRE_MAX);

    zdogview_verified v;
    CHECK(zdogview_verify(replay, n, &v) == ZDOGVIEW_OK);
    CHECK(v.reason == NULL);
    CHECK(v.final_m.phase == ZDOG_PHASE_DONE);
    CHECK(v.recorded_ticks == v.final_m.tick);

    static uint8_t tamper[1200000];
    memcpy(tamper, replay, n);
    tamper[n - 1u] ^= 1u;
    zdogview_verified bad;
    CHECK(zdogview_verify(tamper, n, &bad) == ZDOGVIEW_MISMATCH);
    CHECK(bad.reason != NULL);
    CHECK(strcmp(bad.reason, "final-state") == 0);

    replay[0] = 'X';
    CHECK(zdogview_verify(replay, n, &bad) == ZDOGVIEW_MISMATCH);
    CHECK(strcmp(bad.reason, "header-magic") == 0);
    replay[0] = 'Z';

    zdog_match m;
    CHECK(zdogview_seek(replay, n, &v, 0, &m) == ZDOGVIEW_OK);
    CHECK(m.tick == 0);
    CHECK(zdogview_seek(replay, n, &v, v.recorded_ticks, &m) == ZDOGVIEW_OK);
    CHECK(m.phase == ZDOG_PHASE_DONE);
    const uint64_t checksum = zdog_state_checksum(&m);
    CHECK(checksum == zdog_state_checksum(&v.final_m));

    static zdogview_frame a, b;
    zdogview_render(&m, &a);
    zdogview_render(&m, &b);
    CHECK(memcmp(a.rgb, b.rgb, sizeof(a.rgb)) == 0);

    unsigned painted = 0, sky = 0;
    for (unsigned i = 0; i < sizeof(a.rgb); i += 3u) {
        if (a.rgb[i] == 8 && a.rgb[i + 1u] == 11 && a.rgb[i + 2u] == 18)
            sky++;
        else
            painted++;
    }
    CHECK(painted > 100);
    CHECK(sky > 100);

    /* Rendering must not mutate match state. */
    CHECK(zdog_state_checksum(&m) == checksum);

    static zdogview_frame s1, s2, s3;
    zdogview_render_scene(&m, v.seed, v.kills, v.num_kills, &s1);
    zdogview_render_scene(&m, v.seed, v.kills, v.num_kills, &s2);
    CHECK(memcmp(s1.rgb, s2.rgb, sizeof(s1.rgb)) == 0);
    zdogview_render_scene(&m, v.seed ^ 1u, v.kills, v.num_kills, &s3);
    CHECK(memcmp(s1.rgb, s3.rgb, sizeof(s1.rgb)) != 0);
    CHECK(zdog_state_checksum(&m) == checksum);
    unsigned scene_city = 0;
    for (unsigned i = 0; i < sizeof(s1.rgb); i += 3u) {
        if (s1.rgb[i] == 27 && s1.rgb[i + 1u] == 32 && s1.rgb[i + 2u] == 44)
            scene_city++;
        if (s1.rgb[i] == 34 && s1.rgb[i + 1u] == 42 && s1.rgb[i + 2u] == 58)
            scene_city++;
    }
    CHECK(scene_city > 10);

    if (fails) {
        fprintf(stderr, "zdogview: %d failure(s)\n", fails);
        return 1;
    }
    puts("zdogview: ok");
    return 0;
}
