/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * arena_frame: verify a zdogfight replay, composite the hosted C23
 * 1280x720 scene with Inter HUD, and write a PNG. No raylib. No window.
 *
 * Usage:
 *   arena_frame --replay <file> [--png <out.png>] [--check-only]
 *               [--red-label <text>] [--blue-label <text>] [--tick <n>]
 *
 * Exit: 0 ok; 1 replay mismatch; 2 usage; 4 runtime failure.
 */
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "arena_hud.h"
#include "base/hex.h"
#include "base/safe_alloc.h"
#include "base/serialize_le.h"
#include "sha3/sha3.h"
#include "util/png_writer.h"
#include "zdogfight/zdogfight.h"
#include "zdogview/zdogview.h"

#define AF_LOG "arena_frame"
#define AF_REPLAY_MAGIC "ZDOGREPL"
#define AF_REPLAY_MAGIC_LEN 8u
#define AF_HEADER_LEN (AF_REPLAY_MAGIC_LEN + 4u + 8u + 1u)
#define AF_MAX_REPLAY_BYTES                                                    \
    (AF_HEADER_LEN + (size_t)ZDOG_TICK_LIMIT * ZDOG_MAX_PLANES *               \
                         ZDOG_CTL_WIRE_LEN +                                   \
     (size_t)ZDOG_STATE_WIRE_MAX)

static void af_err(const char *what, const char *detail)
{
    fprintf(stderr, "%s: error: %s%s%s\n", AF_LOG, what, detail ? ": " : "",
            detail ? detail : "");
}

static void af_usage(FILE *out)
{
    fprintf(out,
            "usage:\n"
            "  arena_frame --replay <file>\n"
            "      [--png <out.png>] [--check-only] [--tick <n>]\n"
            "      [--red-label <text>] [--blue-label <text>]\n");
}

static const char *af_winner(uint8_t w)
{
    switch (w) {
    case ZDOG_WINNER_RED:
        return "RED WINS";
    case ZDOG_WINNER_BLUE:
        return "BLUE WINS";
    default:
        return "DRAW";
    }
}

static uint8_t *af_read_file(const char *path, size_t *len_out)
{
    FILE *f = fopen(path, "rb");
    if (!f) {
        af_err("cannot open replay", path);
        return NULL;
    }
    if (fseek(f, 0, SEEK_END) != 0) {
        af_err("fseek failed", path);
        fclose(f);
        return NULL;
    }
    long sz = ftell(f);
    if (sz <= 0 || (unsigned long)sz > AF_MAX_REPLAY_BYTES) {
        af_err("bad replay size (0 or above the replay cap)", path);
        fclose(f);
        return NULL;
    }
    if (fseek(f, 0, SEEK_SET) != 0) {
        af_err("fseek(set) failed", path);
        fclose(f);
        return NULL;
    }
    uint8_t *buf = zcl_malloc((size_t)sz, "arena_frame.replay");
    if (!buf) {
        af_err("malloc failed for replay file", path);
        fclose(f);
        return NULL;
    }
    if (fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
        af_err("short read", path);
        free(buf);
        fclose(f);
        return NULL;
    }
    fclose(f);
    *len_out = (size_t)sz;
    return buf;
}

static void af_sha3(const uint8_t *data, size_t len,
                    uint8_t out[SHA3_256_OUTPUT_SIZE])
{
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    sha3_256_write(&ctx, data, len);
    sha3_256_finalize(&ctx, out);
}

static int af_png_header_ok(const char *path)
{
    FILE *f = fopen(path, "rb");
    if (!f) {
        af_err("cannot re-open PNG", path);
        return ARENA_HUD_FAIL;
    }
    uint8_t hdr[24];
    size_t n = fread(hdr, 1, sizeof(hdr), f);
    fclose(f);
    if (n != sizeof(hdr)) {
        af_err("PNG header short", path);
        return ARENA_HUD_FAIL;
    }
    static const uint8_t sig[8] = { 137, 80, 78, 71, 13, 10, 26, 10 };
    if (memcmp(hdr, sig, 8) != 0) {
        af_err("not a PNG", path);
        return ARENA_HUD_FAIL;
    }
    if (memcmp(hdr + 12, "IHDR", 4) != 0) {
        af_err("PNG missing IHDR", path);
        return ARENA_HUD_FAIL;
    }
    const uint32_t w = zcl_read_u32_be(hdr + 16);
    const uint32_t h = zcl_read_u32_be(hdr + 20);
    if (w != ARENA_HUD_WIDTH || h != ARENA_HUD_HEIGHT) {
        af_err("PNG is not 1280x720", path);
        return ARENA_HUD_FAIL;
    }
    return ARENA_HUD_OK;
}

int main(int argc, char **argv)
{
    const char *replay = NULL;
    const char *png_path = NULL;
    const char *red_label = "Red Ace - zdogace 0.1.1";
    const char *blue_label = "Blue Drone - zdogdrone 0.1.0";
    bool check_only = false;
    bool have_tick = false;
    uint64_t tick = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0) {
            af_usage(stdout);
            return 0;
        }
        if (strcmp(argv[i], "--check-only") == 0) {
            check_only = true;
            continue;
        }
        if (i + 1 >= argc) {
            af_err("missing value for", argv[i]);
            af_usage(stderr);
            return 2;
        }
        if (strcmp(argv[i], "--replay") == 0)
            replay = argv[++i];
        else if (strcmp(argv[i], "--png") == 0)
            png_path = argv[++i];
        else if (strcmp(argv[i], "--red-label") == 0)
            red_label = argv[++i];
        else if (strcmp(argv[i], "--blue-label") == 0)
            blue_label = argv[++i];
        else if (strcmp(argv[i], "--tick") == 0) {
            char *end = NULL;
            tick = strtoull(argv[++i], &end, 10);
            if (!end || *end) {
                af_err("--tick needs a non-negative integer", argv[i]);
                return 2;
            }
            have_tick = true;
        } else {
            af_err("unknown argument", argv[i]);
            af_usage(stderr);
            return 2;
        }
    }
    if (!replay) {
        af_err("missing required argument", "--replay");
        af_usage(stderr);
        return 2;
    }
    if (!arena_hud_label_ok(red_label)) {
        af_err("HUD label is not Basic Latin; glyphs are not invented",
               "--red-label");
        return ARENA_HUD_FAIL;
    }
    if (!arena_hud_label_ok(blue_label)) {
        af_err("HUD label is not Basic Latin; glyphs are not invented",
               "--blue-label");
        return ARENA_HUD_FAIL;
    }

    size_t len = 0;
    uint8_t *buf = af_read_file(replay, &len);
    if (!buf)
        return 4;

    zdogview_verified v;
    const int vrc = zdogview_verify(buf, len, &v);
    if (vrc != ZDOGVIEW_OK) {
        fprintf(stderr, "%s: replay=MISMATCH %s\n", AF_LOG,
                v.reason ? v.reason : "unknown");
        free(buf);
        return vrc == ZDOGVIEW_MISMATCH ? 1 : vrc;
    }

    uint8_t state[ZDOG_STATE_WIRE_MAX];
    if (zdog_state_encode(&v.final_m, state, sizeof(state)) != sizeof(state)) {
        af_err("zdog_state_encode short", "tool bug");
        free(buf);
        return 4;
    }
    uint8_t replay_root[SHA3_256_OUTPUT_SIZE];
    uint8_t state_root[SHA3_256_OUTPUT_SIZE];
    af_sha3(buf, len, replay_root);
    af_sha3(state, sizeof(state), state_root);
    char rr[SHA3_256_OUTPUT_SIZE * 2u + 1u];
    char sr[SHA3_256_OUTPUT_SIZE * 2u + 1u];
    zcl_hex_encode(replay_root, SHA3_256_OUTPUT_SIZE, rr);
    zcl_hex_encode(state_root, SHA3_256_OUTPUT_SIZE, sr);

    zdog_match match;
    const uint64_t at = have_tick ? tick : v.recorded_ticks;
    const int src = zdogview_seek(buf, len, &v, at, &match);
    if (src != ZDOGVIEW_OK) {
        af_err("seek failed", replay);
        free(buf);
        return 4;
    }

    uint8_t *rgb = zcl_malloc(ARENA_HUD_RGB_BYTES, "arena_frame.rgb");
    if (!rgb) {
        af_err("cannot allocate 1280x720 RGB", NULL);
        free(buf);
        return 4;
    }

    arena_hud_in hud = {
        .m = &match,
        .seed = v.seed,
        .kills = v.kills,
        .num_kills = v.num_kills,
        .replay_root = replay_root,
        .state_root = state_root,
        .recorded_ticks = v.recorded_ticks,
        .red_label = red_label,
        .blue_label = blue_label,
        .cam_name = "ISOMETRIC",
        .speed_tag = "x1",
        .follow = 0,
        .playing = match.phase != ZDOG_PHASE_DONE,
    };
    const int hrc = arena_hud_compose(&hud, rgb);
    if (hrc != ARENA_HUD_OK) {
        free(rgb);
        free(buf);
        return hrc;
    }

    if (png_path) {
        if (!png_write_rgb(png_path, rgb, ARENA_HUD_WIDTH, ARENA_HUD_HEIGHT)) {
            af_err("PNG write failed", png_path);
            free(rgb);
            free(buf);
            return 4;
        }
        const int prc = af_png_header_ok(png_path);
        if (prc != ARENA_HUD_OK) {
            free(rgb);
            free(buf);
            return prc;
        }
    }

    printf("verified replay=%s ticks=%llu events=%u score=%u-%u winner=%s "
           "replay_root=%s state_root=%s png=%ux%u fonts=inter view=isometric\n",
           replay, (unsigned long long)v.recorded_ticks, v.num_kills,
           v.final_m.score[0], v.final_m.score[1], af_winner(v.final_m.winner),
           rr, sr, ARENA_HUD_WIDTH, ARENA_HUD_HEIGHT);
    (void)check_only;
    free(rgb);
    free(buf);
    return 0;
}
