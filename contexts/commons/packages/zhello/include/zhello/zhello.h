/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: zhello — the smallest prompt-to-pixel loop in the Commons.
 *
 * The render half of zhello lives here, free of any windowing dependency, so
 * the same frame code runs in an RGFW window on a desk and in a headless
 * `--frames=N` self-test in CI. One C23 source file, one header, no node
 * objects: a reader should be able to hold the whole program in mind.
 */

#ifndef ZHELLO_H
#define ZHELLO_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* RGBA8, always opaque (alpha 0xFF), one row top to bottom, no padding. */
#define ZHELLO_PIXEL_BYTES 4u

/* A pixel canvas the caller owns. zhello never allocates. */
struct zhello_canvas {
	uint8_t *pixels; /* width * height * ZHELLO_PIXEL_BYTES */
	uint32_t width;
	uint32_t height;
};

/* The one animated thing: a square bouncing inside the canvas. */
struct zhello_world {
	double x; /* square centre, canvas pixels */
	double y;
	double vx; /* canvas pixels per second */
	double vy;
	uint64_t frames; /* logical frames stepped so far */
};

#define ZHELLO_SQUARE_SIDE 64u

/* Deterministic starting state for a canvas of the given size. */
void zhello_world_init(struct zhello_world *world, uint32_t width,
		       uint32_t height);

/* Advance the bounce by dt seconds and count one logical frame. */
void zhello_world_step(struct zhello_world *world, uint32_t width,
		       uint32_t height, double dt_seconds);

/* Paint one frame into the canvas. Pure: same world + t_ms, same bytes. */
void zhello_render(const struct zhello_world *world,
		   const struct zhello_canvas *canvas, uint32_t t_ms);

/* FNV-1a over the canvas pixels. Stands in for "the user saw something" in
 * the headless self-test: a frame nobody can fold is a frame nobody drew. */
uint64_t zhello_canvas_digest(const struct zhello_canvas *canvas);

/* Fixed cadence the self-test replays, so a headless run is reproducible. */
#define ZHELLO_TEST_DT_SECONDS (1.0 / 60.0)

/* ── remembering where it was ───────────────────────────────────────────
 *
 * Closing the window and opening it again should carry on, not start over.
 * The state that has to survive is exactly struct zhello_world, and it is
 * written as a CANONICAL little-endian wire rather than as a struct copy:
 * a raw fwrite of the struct would bind this compiler's padding and this
 * host's double layout into a file that another machine is supposed to read
 * back byte for byte. Doubles travel as their IEEE-754 binary64 bit pattern,
 * the same move the rest of the repository makes for integers.
 *
 *   [8  magic "ZHELLOST"]
 *   [2  schema_version = 1]
 *   [8 x][8 y][8 vx][8 vy]   binary64 bit patterns, little-endian
 *   [8  frames]
 *
 * The file belongs in the package's own data directory
 * (<datadir>/zcode/data/<publisher>/<package>), which install, update and
 * rollback all leave alone — so a saved world outlives the version that
 * wrote it. */
#define ZHELLO_STATE_MAGIC "ZHELLOST"
#define ZHELLO_STATE_MAGIC_BYTES 8u
#define ZHELLO_STATE_VERSION 1u
#define ZHELLO_STATE_WIRE_BYTES 50u

/* Write `world` to `path`, replacing whatever was there. False on any I/O
 * failure; a partial file is never left behind on success. */
bool zhello_world_save(const struct zhello_world *world, const char *path);

/* Read `path` into `world`.
 *
 *   present and valid   -> true,  `world` is what was saved
 *   absent              -> false, `*missing` is true: a FIRST RUN, which
 *                          the caller answers with zhello_world_init()
 *   present and damaged -> false, `*missing` is false: a real failure
 *
 * Splitting those two is the whole point. Folding a corrupt file into
 * "start over" is how a person's state disappears with nobody told. */
bool zhello_world_load(struct zhello_world *world, const char *path,
		       bool *missing);

#ifdef __cplusplus
}
#endif

#endif /* ZHELLO_H */
