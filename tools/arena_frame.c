/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * arena_frame: verify a zdogfight replay, composite the hosted C23
 * 1280x720 scene with Inter HUD, and write a PNG. No raylib. No window.
 *
 * Usage:
 *   arena_frame --replay <file> [--png <out.png>] [--check-only]
 *               [--red-label <text>] [--blue-label <text>] [--tick <n>]
 *
 *   --check-only    verify and print roots; write no PNG
 *
 * Exit: 0 ok; 1 replay mismatch; 2 usage; 4 runtime failure.
 */
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if __has_include("zdogview/zdogview.h")
#include "arena_hud.h"
#include "zdogfight/zdogfight.h"
#include "zdogview/zdogview.h"
#else
/* ZCL_ALL_INCLUDES does not name the arena package roots. These match
 * the headers the arena-frame link includes, so this sweep still typechecks. */
#define ZDOG_MAX_PLANES 8u
#define ZDOG_TICK_LIMIT 36000
#define ZDOG_CTL_WIRE_LEN 7u
#define ZDOG_MAX_SHOTS 64u
#define ZDOG_STATE_WIRE_MAX                                                    \
    (8u + 1u + 1u + 1u + 8u + 32u + ZDOG_MAX_PLANES * 32u +                    \
     ZDOG_MAX_SHOTS * 29u)
#define ZDOG_PHASE_DONE 1
#define ZDOG_WINNER_RED 0
#define ZDOG_WINNER_BLUE 1
#define ZDOGVIEW_OK 0
#define ZDOGVIEW_MISMATCH 1
#define ARENA_HUD_WIDTH 1280u
#define ARENA_HUD_HEIGHT 720u
#define ARENA_HUD_RGB_BYTES (ARENA_HUD_WIDTH * ARENA_HUD_HEIGHT * 3u)
#define ARENA_HUD_OK 0
#define ARENA_HUD_FAIL 4

typedef struct {
    uint64_t tick;
    int32_t x, y, z;
    uint8_t team;
} zdogview_kill;

typedef struct {
    uint32_t score[2];
    uint8_t winner;
    uint8_t phase;
} zdog_match;

typedef struct {
    uint64_t seed;
    uint64_t recorded_ticks;
    zdog_match final_m;
    zdogview_kill kills[1];
    unsigned num_kills;
    const char *reason;
} zdogview_verified;

typedef struct {
    const zdog_match *m;
    uint64_t seed;
    const zdogview_kill *kills;
    unsigned num_kills;
    const uint8_t *replay_root;
    const uint8_t *state_root;
    uint64_t recorded_ticks;
    const char *red_label;
    const char *blue_label;
    const char *cam_name;
    const char *speed_tag;
    unsigned follow;
    bool playing;
} arena_hud_in;

static inline bool arena_hud_label_ok(const char *s)
{
    if (!s)
        return true;
    for (const unsigned char *p = (const unsigned char *)s; *p != 0u; p++) {
        if (*p < 32u || *p > 126u)
            return false;
    }
    return true;
}

int zdogview_verify(const uint8_t *buf, size_t len, zdogview_verified *out);
int zdogview_seek(const uint8_t *buf, size_t len, const zdogview_verified *v,
                  uint64_t tick, zdog_match *out);
size_t zdog_state_encode(const zdog_match *m, uint8_t *out, size_t cap);
int arena_hud_compose(const arena_hud_in *in, uint8_t *rgb);
#endif
#include "base/hex.h"
#include "base/safe_alloc.h"
#include "base/serialize_le.h"
#include "sha3/sha3.h"
#include "util/png_writer.h"

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

struct af_args {
    const char *replay;
    const char *png_path;
    const char *red_label;
    const char *blue_label;
    bool check_only;
    bool have_tick;
    uint64_t tick;
};

struct af_verified {
    zdogview_verified v;
    uint8_t replay_root[SHA3_256_OUTPUT_SIZE];
    uint8_t state_root[SHA3_256_OUTPUT_SIZE];
    char replay_hex[SHA3_256_OUTPUT_SIZE * 2u + 1u];
    char state_hex[SHA3_256_OUTPUT_SIZE * 2u + 1u];
};

static int af_parse_tick_text(const char *text, uint64_t *tick, bool *have_tick)
{
    char *end = NULL;
    *tick = strtoull(text, &end, 10);
    if (!end || *end) {
        af_err("--tick needs a non-negative integer", text);
        return 2;
    }
    *have_tick = true;
    return 0;
}

static int af_apply_valued_flag(struct af_args *a, const char *flag,
                                const char *val)
{
    if (strcmp(flag, "--replay") == 0)
        a->replay = val;
    else if (strcmp(flag, "--png") == 0)
        a->png_path = val;
    else if (strcmp(flag, "--red-label") == 0)
        a->red_label = val;
    else if (strcmp(flag, "--blue-label") == 0)
        a->blue_label = val;
    else if (strcmp(flag, "--tick") == 0)
        return af_parse_tick_text(val, &a->tick, &a->have_tick);
    else {
        af_err("unknown argument", flag);
        af_usage(stderr);
        return 2;
    }
    return 0;
}

/* false: main returns *status. true: a holds the accepted arguments. */
static bool af_parse_args(int argc, char **argv, struct af_args *a, int *status)
{
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0) {
            af_usage(stdout);
            *status = 0;
            return false;
        }
        if (strcmp(argv[i], "--check-only") == 0) {
            a->check_only = true;
            continue;
        }
        if (i + 1 >= argc) {
            af_err("missing value for", argv[i]);
            af_usage(stderr);
            *status = 2;
            return false;
        }
        const int rc = af_apply_valued_flag(a, argv[i], argv[i + 1]);
        if (rc != 0) {
            *status = rc;
            return false;
        }
        i++;
    }
    if (!a->replay) {
        af_err("missing required argument", "--replay");
        af_usage(stderr);
        *status = 2;
        return false;
    }
    if (!arena_hud_label_ok(a->red_label)) {
        af_err("HUD label is not Basic Latin; glyphs are not invented",
               "--red-label");
        *status = ARENA_HUD_FAIL;
        return false;
    }
    if (!arena_hud_label_ok(a->blue_label)) {
        af_err("HUD label is not Basic Latin; glyphs are not invented",
               "--blue-label");
        *status = ARENA_HUD_FAIL;
        return false;
    }
    return true;
}

/* false: buf is freed and main returns *status. true: out is filled. */
static bool af_verify_and_hash(uint8_t *buf, size_t len, struct af_verified *out,
                               int *status)
{
    const int vrc = zdogview_verify(buf, len, &out->v);
    if (vrc != ZDOGVIEW_OK) {
        fprintf(stderr, "%s: replay=MISMATCH %s\n", AF_LOG,
                out->v.reason ? out->v.reason : "unknown");
        free(buf);
        *status = vrc == ZDOGVIEW_MISMATCH ? 1 : vrc;
        return false;
    }

    uint8_t state[ZDOG_STATE_WIRE_MAX];
    if (zdog_state_encode(&out->v.final_m, state, sizeof(state)) !=
        sizeof(state)) {
        af_err("zdog_state_encode short", "tool bug");
        free(buf);
        *status = 4;
        return false;
    }
    af_sha3(buf, len, out->replay_root);
    af_sha3(state, sizeof(state), out->state_root);
    zcl_hex_encode(out->replay_root, SHA3_256_OUTPUT_SIZE, out->replay_hex);
    zcl_hex_encode(out->state_root, SHA3_256_OUTPUT_SIZE, out->state_hex);
    return true;
}

static int af_render_frame(const struct af_args *a, uint8_t *buf, size_t len,
                           const struct af_verified *got)
{
    zdog_match match;
    const uint64_t at = a->have_tick ? a->tick : got->v.recorded_ticks;
    const int src = zdogview_seek(buf, len, &got->v, at, &match);
    if (src != ZDOGVIEW_OK) {
        af_err("seek failed", a->replay);
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
        .seed = got->v.seed,
        .kills = got->v.kills,
        .num_kills = got->v.num_kills,
        .replay_root = got->replay_root,
        .state_root = got->state_root,
        .recorded_ticks = got->v.recorded_ticks,
        .red_label = a->red_label,
        .blue_label = a->blue_label,
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

    if (a->png_path) {
        if (!png_write_rgb(a->png_path, rgb, ARENA_HUD_WIDTH,
                           ARENA_HUD_HEIGHT)) {
            af_err("PNG write failed", a->png_path);
            free(rgb);
            free(buf);
            return 4;
        }
        const int prc = af_png_header_ok(a->png_path);
        if (prc != ARENA_HUD_OK) {
            free(rgb);
            free(buf);
            return prc;
        }
    }

    printf("verified replay=%s ticks=%llu events=%u score=%u-%u winner=%s "
           "replay_root=%s state_root=%s png=%ux%u fonts=inter view=isometric\n",
           a->replay, (unsigned long long)got->v.recorded_ticks, got->v.num_kills,
           got->v.final_m.score[0], got->v.final_m.score[1],
           af_winner(got->v.final_m.winner), got->replay_hex, got->state_hex,
           ARENA_HUD_WIDTH, ARENA_HUD_HEIGHT);
    free(rgb);
    free(buf);
    return 0;
}

int main(int argc, char **argv)
{
    struct af_args a = {
        .replay = NULL,
        .png_path = NULL,
        .red_label = "Red Ace - zdogace 0.1.1",
        .blue_label = "Blue Drone - zdogdrone 0.1.0",
        .check_only = false,
        .have_tick = false,
        .tick = 0,
    };
    int status = 0;
    if (!af_parse_args(argc, argv, &a, &status))
        return status;

    size_t len = 0;
    uint8_t *buf = af_read_file(a.replay, &len);
    if (!buf)
        return 4;

    struct af_verified got;
    if (!af_verify_and_hash(buf, len, &got, &status))
        return status;

    if (a.check_only) {
        printf("verified replay=%s ticks=%llu events=%u score=%u-%u "
               "winner=%s replay_root=%s state_root=%s\n",
               a.replay, (unsigned long long)got.v.recorded_ticks,
               got.v.num_kills, got.v.final_m.score[0], got.v.final_m.score[1],
               af_winner(got.v.final_m.winner), got.replay_hex, got.state_hex);
        free(buf);
        return 0;
    }
    return af_render_frame(&a, buf, len, &got);
}
