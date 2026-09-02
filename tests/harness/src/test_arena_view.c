/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Hosted 1280x720 arena picture: Inter HUD, PNG export, font refusal,
 * non-ASCII label refusal, and unchanged match roots. No raylib.
 */
#include "test/test_core.h"

#include "arena_hud.h"
#include "base/hex.h"
#include "base/serialize_le.h"
#include "presentation/canvas.h"
#include "sha3/sha3.h"
#include "util/png_writer.h"
#include "zdogfight/zdogfight.h"
#include "zdogview/zdogview.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "../../../contexts/commons/packages/zprng/src/zprng.c"
#include "../../../contexts/commons/packages/zdogfight/src/zdogfight.c"
#include "../../../contexts/commons/packages/zdogfight/src/zdogfix.c"
#include "../../../contexts/commons/packages/zdogview/src/zdogview.c"
#include "../../../tools/arena_hud.c"

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

static void sha3_bytes(const uint8_t *data, size_t len, uint8_t out[32])
{
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    sha3_256_write(&ctx, data, len);
    sha3_256_finalize(&ctx, out);
}

int test_arena_view(void);
int test_arena_view(void)
{
    int failures = 0;

    TEST("bundled Inter subsets rasterize Basic Latin") {
        ASSERT(arena_hud_fonts_ready());
        ASSERT(zcl_present_canvas_text_width("SCORE", 5u, 16u) > 0u);
        ASSERT(zcl_present_canvas_text_width_strong("Z23", 3u, 22u) > 0u);
        PASS();
    }

    TEST("compose refuses a missing buffer") {
        zdog_match m;
        zdog_match_init(&m, 7, 1);
        arena_hud_in in = { .m = &m, .cam_name = "ISOMETRIC" };
        ASSERT_EQ(arena_hud_compose(&in, NULL), ARENA_HUD_BAD_ARG);
        ASSERT_EQ(arena_hud_compose(NULL, (uint8_t *)1), ARENA_HUD_BAD_ARG);
        PASS();
    }

    TEST("compose refuses a non-ASCII HUD label instead of drawing '?'") {
        zdog_match m;
        zdog_match_init(&m, 7, 1);
        uint8_t *rgb = malloc(ARENA_HUD_RGB_BYTES);
        ASSERT(rgb);
        arena_hud_in in = {
            .m = &m,
            .red_label = "Red",
            .blue_label = "Blue",
            .cam_name = "ISOMETRIC",
            .speed_tag = "x1",
        };
        in.red_label = "Red \xE2\x80\x94 Ace";
        ASSERT_EQ(arena_hud_compose(&in, rgb), ARENA_HUD_FAIL);
        in.red_label = "Red";
        in.blue_label = "Blue\nDrone";
        ASSERT_EQ(arena_hud_compose(&in, rgb), ARENA_HUD_FAIL);
        in.blue_label = "Blue";
        in.cam_name = "ISO\x80METRIC";
        ASSERT_EQ(arena_hud_compose(&in, rgb), ARENA_HUD_FAIL);
        in.cam_name = "ISOMETRIC";
        in.speed_tag = "x1\t";
        ASSERT_EQ(arena_hud_compose(&in, rgb), ARENA_HUD_FAIL);
        in.speed_tag = "x1";
        in.red_label = "Red Ace - zdogace 0.1.1";
        ASSERT(arena_hud_label_ok(in.red_label));
        ASSERT(arena_hud_label_ok(NULL));
        ASSERT(arena_hud_label_ok(""));
        ASSERT(!arena_hud_label_ok("Red \xE2\x80\x94 Ace"));
        ASSERT_EQ(arena_hud_compose(&in, rgb), ARENA_HUD_OK);
        free(rgb);
        PASS();
    }

    static uint8_t replay[1200000];
    const size_t n = record_match(replay, sizeof(replay), 7, 2);
    ASSERT(n > ZDOGVIEW_HEADER_LEN + ZDOG_STATE_WIRE_MAX);

    zdogview_verified v;
    ASSERT_EQ(zdogview_verify(replay, n, &v), ZDOGVIEW_OK);

    uint8_t state[ZDOG_STATE_WIRE_MAX];
    ASSERT(zdog_state_encode(&v.final_m, state, sizeof(state)) ==
           sizeof(state));
    uint8_t replay_root[32], state_root[32];
    sha3_bytes(replay, n, replay_root);
    sha3_bytes(state, sizeof(state), state_root);
    const uint64_t checksum = zdog_state_checksum(&v.final_m);

    TEST("1280x720 Inter HUD is deterministic and does not write match state") {
        uint8_t *a = malloc(ARENA_HUD_RGB_BYTES);
        uint8_t *b = malloc(ARENA_HUD_RGB_BYTES);
        ASSERT(a && b);
        arena_hud_in in = {
            .m = &v.final_m,
            .seed = v.seed,
            .kills = v.kills,
            .num_kills = v.num_kills,
            .replay_root = replay_root,
            .state_root = state_root,
            .recorded_ticks = v.recorded_ticks,
            .red_label = "Red Ace",
            .blue_label = "Blue Drone",
            .cam_name = "ISOMETRIC",
            .speed_tag = "x1",
            .follow = 0,
            .playing = false,
        };
        ASSERT_EQ(arena_hud_compose(&in, a), ARENA_HUD_OK);
        ASSERT_EQ(arena_hud_compose(&in, b), ARENA_HUD_OK);
        ASSERT(memcmp(a, b, ARENA_HUD_RGB_BYTES) == 0);
        ASSERT_EQ(zdog_state_checksum(&v.final_m), checksum);
        unsigned painted = 0;
        for (size_t i = 0; i < ARENA_HUD_RGB_BYTES; i += 3u) {
            if (a[i] != 8 || a[i + 1u] != 11 || a[i + 2u] != 18)
                painted++;
        }
        ASSERT(painted > 10000);
        /* Top-bar Inter HUD is not the sky fill. */
        ASSERT(a[28 * 3] != 8 || a[28 * 3 + 1] != 11);
        free(a);
        free(b);
        PASS();
    }

    TEST("PNG export is a real 1280x720 RGB image") {
        uint8_t *rgb = malloc(ARENA_HUD_RGB_BYTES);
        ASSERT(rgb);
        arena_hud_in in = {
            .m = &v.final_m,
            .seed = v.seed,
            .kills = v.kills,
            .num_kills = v.num_kills,
            .replay_root = replay_root,
            .state_root = state_root,
            .recorded_ticks = v.recorded_ticks,
            .red_label = "Red Ace",
            .blue_label = "Blue Drone",
            .cam_name = "ISOMETRIC",
            .speed_tag = "x1",
            .follow = 0,
            .playing = false,
        };
        ASSERT_EQ(arena_hud_compose(&in, rgb), ARENA_HUD_OK);
        char dir[PATH_MAX];
        test_fmt_tmpdir(dir, sizeof(dir), "arena_view", "png");
        ASSERT_EQ(mkdir(dir, 0700), 0);
        char path[PATH_MAX];
        ASSERT(snprintf(path, sizeof(path), "%s/shot.png", dir) < (int)sizeof(path));
        ASSERT(png_write_rgb(path, rgb, ARENA_HUD_WIDTH, ARENA_HUD_HEIGHT));
        FILE *f = fopen(path, "rb");
        ASSERT(f);
        uint8_t hdr[24];
        ASSERT_EQ(fread(hdr, 1, sizeof(hdr), f), sizeof(hdr));
        fclose(f);
        static const uint8_t sig[8] = { 137, 80, 78, 71, 13, 10, 26, 10 };
        ASSERT(memcmp(hdr, sig, 8) == 0);
        ASSERT(memcmp(hdr + 12, "IHDR", 4) == 0);
        ASSERT_EQ(zcl_read_u32_be(hdr + 16), ARENA_HUD_WIDTH);
        ASSERT_EQ(zcl_read_u32_be(hdr + 20), ARENA_HUD_HEIGHT);
        unlink(path);
        rmdir(dir);
        free(rgb);
        PASS();
    }

_test_next:;
    if (failures == 0)
        printf("test_arena_view: all passed\n");
    else
        printf("test_arena_view: %d FAILED\n", failures);
    return failures;
}
