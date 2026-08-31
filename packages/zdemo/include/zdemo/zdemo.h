/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: zdemo — the smallest prompt-to-pixel loop in the Commons.
 *
 * The render half of zdemo lives here, free of any windowing dependency, so
 * the same frame code runs in an RGFW window on a desk and in a headless
 * `--frames=N` self-test in CI. One C23 source file, one header, no node
 * objects: a reader should be able to hold the whole program in mind.
 */

#ifndef ZDEMO_H
#define ZDEMO_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* RGBA8, always opaque (alpha 0xFF), one row top to bottom, no padding. */
#define ZDEMO_PIXEL_BYTES 4u

/* A pixel canvas the caller owns. zdemo never allocates. */
struct zdemo_canvas {
	uint8_t *pixels; /* width * height * ZDEMO_PIXEL_BYTES */
	uint32_t width;
	uint32_t height;
};

/* The one animated thing: a square bouncing inside the canvas. */
struct zdemo_world {
	double x; /* square centre, canvas pixels */
	double y;
	double vx; /* canvas pixels per second */
	double vy;
	uint64_t frames; /* logical frames stepped so far */
};

#define ZDEMO_SQUARE_SIDE 64u

/* Deterministic starting state for a canvas of the given size. */
void zdemo_world_init(struct zdemo_world *world, uint32_t width,
		       uint32_t height);

/* Advance the bounce by dt seconds and count one logical frame. */
void zdemo_world_step(struct zdemo_world *world, uint32_t width,
		       uint32_t height, double dt_seconds);

/* Paint one frame into the canvas. Pure: same world + t_ms, same bytes. */
void zdemo_render(const struct zdemo_world *world,
		   const struct zdemo_canvas *canvas, uint32_t t_ms);

/* FNV-1a over the canvas pixels. Stands in for "the user saw something" in
 * the headless self-test: a frame nobody can fold is a frame nobody drew. */
uint64_t zdemo_canvas_digest(const struct zdemo_canvas *canvas);

/* Fixed cadence the self-test replays, so a headless run is reproducible. */
#define ZDEMO_TEST_DT_SECONDS (1.0 / 60.0)

#ifdef __cplusplus
}
#endif

#endif /* ZDEMO_H */
