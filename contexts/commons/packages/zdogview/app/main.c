/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * zdogview CLI: verify a canonical replay, or render one integer 3D PPM
 * frame. No raylib. File I/O lives here; the library only sees bytes.
 */
#include "zdogview/zdogview.h"

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void zv_err(const char *what, const char *detail)
{
    fprintf(stderr, "zdogview: error: %s%s%s\n", what, detail ? ": " : "",
            detail ? detail : "");
}

static void usage(FILE *out)
{
    fprintf(out,
            "usage:\n"
            "  zdogview verify <replay>\n"
            "  zdogview render <replay> [--tick <n>] --out <file.ppm>\n");
}

#define ZV_MAX_REPLAY_BYTES                                                    \
    (ZDOGVIEW_HEADER_LEN + (size_t)ZDOG_TICK_LIMIT * ZDOG_MAX_PLANES *         \
                               ZDOG_CTL_WIRE_LEN +                             \
     (size_t)ZDOG_STATE_WIRE_MAX)

static uint8_t *read_all(const char *path, size_t *len_out)
{
    FILE *f = fopen(path, "rb");
    if (!f) {
        zv_err("cannot open replay", path);
        return NULL;
    }
    if (fseek(f, 0, SEEK_END) != 0) {
        zv_err("fseek failed", path);
        fclose(f);
        return NULL;
    }
    const long sz = ftell(f);
    if (sz <= 0 || (unsigned long)sz > ZV_MAX_REPLAY_BYTES) {
        zv_err("bad replay size (0 or above the replay cap)", path);
        fclose(f);
        return NULL;
    }
    if (fseek(f, 0, SEEK_SET) != 0) {
        zv_err("fseek(set) failed", path);
        fclose(f);
        return NULL;
    }
    uint8_t *buf = malloc((size_t)sz);
    if (!buf) {
        zv_err("malloc failed", path);
        fclose(f);
        return NULL;
    }
    if (fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
        zv_err("short read", path);
        free(buf);
        fclose(f);
        return NULL;
    }
    fclose(f);
    *len_out = (size_t)sz;
    return buf;
}

static int write_ppm(const char *path, const zdogview_frame *fr)
{
    FILE *f = fopen(path, "wb");
    if (!f) {
        zv_err("cannot write PPM", strerror(errno));
        return ZDOGVIEW_FAIL;
    }
    if (fprintf(f, "P6\n%u %u\n255\n", ZDOGVIEW_WIDTH, ZDOGVIEW_HEIGHT) < 0 ||
        fwrite(fr->rgb, 1, sizeof(fr->rgb), f) != sizeof(fr->rgb)) {
        zv_err("PPM write failed", path);
        fclose(f);
        return ZDOGVIEW_FAIL;
    }
    if (fclose(f) != 0) {
        zv_err("PPM close failed", path);
        return ZDOGVIEW_FAIL;
    }
    return ZDOGVIEW_OK;
}

static const char *winner_name(uint8_t w)
{
    switch (w) {
    case ZDOG_WINNER_RED:
        return "red";
    case ZDOG_WINNER_BLUE:
        return "blue";
    default:
        return "draw";
    }
}

int main(int argc, char **argv)
{
    if (argc < 3) {
        usage(stderr);
        return ZDOGVIEW_BAD_ARG;
    }
    const char *cmd = argv[1];
    const char *replay = argv[2];
    const char *out_path = NULL;
    bool have_tick = false;
    uint64_t tick = 0;

    for (int i = 3; i < argc; i++) {
        if (strcmp(argv[i], "--out") == 0) {
            if (i + 1 >= argc) {
                zv_err("missing value for", "--out");
                return ZDOGVIEW_BAD_ARG;
            }
            out_path = argv[++i];
        } else if (strcmp(argv[i], "--tick") == 0) {
            if (i + 1 >= argc) {
                zv_err("missing value for", "--tick");
                return ZDOGVIEW_BAD_ARG;
            }
            char *end = NULL;
            tick = strtoull(argv[++i], &end, 10);
            if (!end || *end) {
                zv_err("--tick needs a non-negative integer", argv[i]);
                return ZDOGVIEW_BAD_ARG;
            }
            have_tick = true;
        } else if (strcmp(argv[i], "--help") == 0) {
            usage(stdout);
            return 0;
        } else {
            zv_err("unknown argument", argv[i]);
            usage(stderr);
            return ZDOGVIEW_BAD_ARG;
        }
    }

    size_t len = 0;
    uint8_t *buf = read_all(replay, &len);
    if (!buf)
        return ZDOGVIEW_FAIL;

    zdogview_verified v;
    const int rc = zdogview_verify(buf, len, &v);
    if (rc != ZDOGVIEW_OK) {
        fprintf(stderr, "zdogview: replay=MISMATCH %s\n",
                v.reason ? v.reason : "unknown");
        free(buf);
        return rc;
    }

    if (strcmp(cmd, "verify") == 0) {
        printf("verified replay=%s ticks=%llu score=%u-%u winner=%s "
               "state_fnv=%016llx\n",
               replay, (unsigned long long)v.recorded_ticks, v.final_m.score[0],
               v.final_m.score[1], winner_name(v.final_m.winner),
               (unsigned long long)zdog_state_checksum(&v.final_m));
        free(buf);
        return ZDOGVIEW_OK;
    }
    if (strcmp(cmd, "render") == 0) {
        if (!out_path) {
            zv_err("missing required argument", "--out");
            free(buf);
            return ZDOGVIEW_BAD_ARG;
        }
        zdog_match m;
        const uint64_t at = have_tick ? tick : v.recorded_ticks;
        const int src = zdogview_seek(buf, len, &v, at, &m);
        if (src != ZDOGVIEW_OK) {
            zv_err("seek failed", replay);
            free(buf);
            return src;
        }
        zdogview_frame *fr = malloc(sizeof(*fr));
        if (!fr) {
            zv_err("malloc failed for frame", out_path);
            free(buf);
            return ZDOGVIEW_FAIL;
        }
        zdogview_render_scene(&m, v.seed, v.kills, v.num_kills, fr);
        const int wrc = write_ppm(out_path, fr);
        free(fr);
        free(buf);
        return wrc;
    }

    zv_err("unknown command (verify|render)", cmd);
    usage(stderr);
    free(buf);
    return ZDOGVIEW_BAD_ARG;
}
