/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: ball — the smallest prompt-to-pixel loop in the Commons.
 *
 * The render half of ball lives here, free of any windowing dependency, so
 * the same frame code runs in an RGFW window on a desk and in a headless
 * `--frames=N` self-test in CI. One C23 source file, one header, no node
 * objects: a reader should be able to hold the whole program in mind.
 */

#ifndef BALL_BALL_H
#define BALL_BALL_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* RGBA8, always opaque (alpha 0xFF), one row top to bottom, no padding. */
#define BALL_PIXEL_BYTES 4u

/* A pixel canvas the caller owns. ball never allocates. */
struct ball_canvas {
	uint8_t *pixels; /* width * height * BALL_PIXEL_BYTES */
	uint32_t width;
	uint32_t height;
};

/* The one animated thing: a square bouncing inside the canvas. */
struct ball_world {
	double x; /* square centre, canvas pixels */
	double y;
	double vx; /* canvas pixels per second */
	double vy;
	uint64_t frames; /* logical frames stepped so far */
};

#define BALL_SQUARE_SIDE 64u

/* Deterministic starting state for a canvas of the given size. */
void ball_world_init(struct ball_world *world, uint32_t width,
		       uint32_t height);

/* Advance the bounce by dt seconds and count one logical frame. */
void ball_world_step(struct ball_world *world, uint32_t width,
		       uint32_t height, double dt_seconds);

/* Paint one frame into the canvas. Pure: same world + t_ms, same bytes. */
void ball_render(const struct ball_world *world,
		   const struct ball_canvas *canvas, uint32_t t_ms);

/* FNV-1a over the canvas pixels. Stands in for "the user saw something" in
 * the headless self-test: a frame nobody can fold is a frame nobody drew. */
uint64_t ball_canvas_digest(const struct ball_canvas *canvas);

/* Fixed cadence the self-test replays, so a headless run is reproducible. */
#define BALL_TEST_DT_SECONDS (1.0 / 60.0)

#ifdef __cplusplus
}
#endif

#endif /* BALL_BALL_H */
