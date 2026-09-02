/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Polished 1280x720 HUD over a verified zdogview integer scene.
 * Inter Medium / SemiBold subsets rasterize through the existing
 * presentation canvas. Missing fonts refuse; they do not invent glyphs.
 * Non-ASCII labels refuse; they are not drawn as '?'.
 */
#ifndef ARENA_HUD_H
#define ARENA_HUD_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "zdogview/zdogview.h"

#ifdef __cplusplus
extern "C" {
#endif

#define ARENA_HUD_WIDTH 1280u
#define ARENA_HUD_HEIGHT 720u
#define ARENA_HUD_RGB_BYTES (ARENA_HUD_WIDTH * ARENA_HUD_HEIGHT * 3u)
#define ARENA_HUD_ROOT_LEN 32u

#define ARENA_HUD_OK 0
#define ARENA_HUD_BAD_ARG 2
#define ARENA_HUD_FAIL 4

typedef struct {
    const zdog_match *m;
    uint64_t seed;
    const zdogview_kill *kills;
    unsigned num_kills;
    const uint8_t *replay_root; /* ARENA_HUD_ROOT_LEN bytes, or NULL */
    const uint8_t *state_root;
    uint64_t recorded_ticks;
    const char *red_label;
    const char *blue_label;
    const char *cam_name;
    const char *speed_tag;
    unsigned follow;
    bool playing;
} arena_hud_in;

/* True when both bundled Inter subsets rasterize Basic Latin. */
bool arena_hud_fonts_ready(void);

/* True when s is NULL, empty, or only Basic Latin printable (32-126). */
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

/* Fill rgb[ARENA_HUD_RGB_BYTES] with the integer scene plus Inter HUD.
 * Returns ARENA_HUD_OK, ARENA_HUD_BAD_ARG, or ARENA_HUD_FAIL (logged). */
int arena_hud_compose(const arena_hud_in *in, uint8_t *rgb);

#ifdef __cplusplus
}
#endif

#endif /* ARENA_HUD_H */
