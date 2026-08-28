/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: zdemo's frame painter. No windowing API appears in this file, so
 * the headless self-test exercises exactly what a windowed run draws. */

#include "zdemo/zdemo.h"

#include <string.h>

/* Two palette stops the background gradient travels between, in the same
 * RGBA byte order as the canvas. */
struct zdemo_rgb {
	uint8_t r, g, b;
};

static const struct zdemo_rgb zdemo_stop_a = {0x12, 0x14, 0x28};
static const struct zdemo_rgb zdemo_stop_b = {0x2f, 0x6f, 0x5a};

static double zdemo_wrap01(double v)
{
	double frac = v - (double)(int64_t)v;
	return frac < 0.0 ? frac + 1.0 : frac;
}

static uint8_t zdemo_channel(uint8_t a, uint8_t b, double t)
{
	return (uint8_t)((double)a + ((double)b - (double)a) * t + 0.5);
}

static uint8_t zdemo_clamp_channel(int v)
{
	if (v < 0)
		return 0;
	if (v > 255)
		return 255;
	return (uint8_t)v;
}

void zdemo_world_init(struct zdemo_world *world, uint32_t width,
		       uint32_t height)
{
	memset(world, 0, sizeof(*world));
	world->x = (double)width * 0.25;
	world->y = (double)height * 0.25;
	world->vx = 180.0;
	world->vy = 130.0;
	world->frames = 0;
}

void zdemo_world_step(struct zdemo_world *world, uint32_t width,
		       uint32_t height, double dt_seconds)
{
	const double side = (double)ZDEMO_SQUARE_SIDE;
	const double max_x = (double)width - side;
	const double max_y = (double)height - side;

	world->x += world->vx * dt_seconds;
	world->y += world->vy * dt_seconds;

	if (world->x < 0.0) {
		world->x = -world->x;
		world->vx = -world->vx;
	} else if (world->x > max_x) {
		world->x = 2.0 * max_x - world->x;
		world->vx = -world->vx;
	}
	if (world->y < 0.0) {
		world->y = -world->y;
		world->vy = -world->vy;
	} else if (world->y > max_y) {
		world->y = 2.0 * max_y - world->y;
		world->vy = -world->vy;
	}
	if (world->x < 0.0 || world->x > max_x)
		world->x = max_x * 0.5;
	if (world->y < 0.0 || world->y > max_y)
		world->y = max_y * 0.5;

	world->frames += 1;
}

void zdemo_render(const struct zdemo_world *world,
		   const struct zdemo_canvas *canvas, uint32_t t_ms)
{
	const uint32_t w = canvas->width;
	const uint32_t h = canvas->height;
	uint8_t *pixels = canvas->pixels;

	/* Background: a vertical gradient whose phase drifts with time. */
	const double phase = zdemo_wrap01((double)t_ms / 8000.0);
	uint8_t top_r = zdemo_channel(zdemo_stop_a.r, zdemo_stop_b.r, phase);
	uint8_t top_g = zdemo_channel(zdemo_stop_a.g, zdemo_stop_b.g, phase);
	uint8_t top_b = zdemo_channel(zdemo_stop_a.b, zdemo_stop_b.b, phase);
	uint8_t bot_r = zdemo_channel(zdemo_stop_b.r, zdemo_stop_a.r, phase);
	uint8_t bot_g = zdemo_channel(zdemo_stop_b.g, zdemo_stop_a.g, phase);
	uint8_t bot_b = zdemo_channel(zdemo_stop_b.b, zdemo_stop_a.b, phase);

	for (uint32_t y = 0; y < h; y++) {
		const double t = (h > 1u) ? (double)y / (double)(h - 1u) : 0.0;
		const uint8_t r =
			zdemo_channel(top_r, bot_r, t);
		const uint8_t g =
			zdemo_channel(top_g, bot_g, t);
		const uint8_t b =
			zdemo_channel(top_b, bot_b, t);
		uint8_t *row = pixels + (size_t)y * (size_t)w *
					 ZDEMO_PIXEL_BYTES;
		for (uint32_t x = 0; x < w; x++) {
			uint8_t *px = row + (size_t)x * ZDEMO_PIXEL_BYTES;
			px[0] = r;
			px[1] = g;
			px[2] = b;
			px[3] = 0xFF;
		}
	}

	/* The bouncing square: one solid block plus a two-pixel lit border,
	 * clipped by hand because zdemo has no scissor rect. */
	const int32_t side = (int32_t)ZDEMO_SQUARE_SIDE;
	const int32_t x0 = (int32_t)(world->x + 0.5);
	const int32_t y0 = (int32_t)(world->y + 0.5);
	const uint8_t pulse = zdemo_clamp_channel(
		110 + (int)(70.0 * zdemo_wrap01((double)t_ms / 1200.0)));

	for (int32_t y = y0; y < y0 + side; y++) {
		if (y < 0 || (uint32_t)y >= h)
			continue;
		uint8_t *row = pixels + (size_t)y * (size_t)w *
					 ZDEMO_PIXEL_BYTES;
		for (int32_t x = x0; x < x0 + side; x++) {
			if (x < 0 || (uint32_t)x >= w)
				continue;
			const bool border = (x == x0 || x == x0 + side - 1 ||
					     y == y0 || y == y0 + side - 1);
			uint8_t *px = row + (size_t)x * ZDEMO_PIXEL_BYTES;
			if (border) {
				px[0] = 0xF2;
				px[1] = 0xE8;
				px[2] = 0xD8;
			} else {
				px[0] = (uint8_t)(pulse / 3u);
				px[1] = pulse;
				px[2] = (uint8_t)(pulse / 2u);
			}
			px[3] = 0xFF;
		}
	}
}

uint64_t zdemo_canvas_digest(const struct zdemo_canvas *canvas)
{
	const size_t bytes = (size_t)canvas->width * (size_t)canvas->height *
			     ZDEMO_PIXEL_BYTES;
	uint64_t hash = 1469598103934665603ULL; /* FNV-1a 64 offset basis */
	const uint8_t *p = canvas->pixels;
	for (size_t i = 0; i < bytes; i++) {
		hash ^= p[i];
		hash *= 1099511628211ULL;
	}
	return hash;
}
