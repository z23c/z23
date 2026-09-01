/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: zhello's frame painter. No windowing API appears in this file, so
 * the headless self-test exercises exactly what a windowed run draws. */

#include "zhello/zhello.h"

#include <string.h>

/* Two palette stops the background gradient travels between, in the same
 * RGBA byte order as the canvas. */
struct zhello_rgb {
	uint8_t r, g, b;
};

static const struct zhello_rgb zhello_stop_a = {0x12, 0x14, 0x28};
static const struct zhello_rgb zhello_stop_b = {0x2f, 0x6f, 0x5a};

static double zhello_wrap01(double v)
{
	double frac = v - (double)(int64_t)v;
	return frac < 0.0 ? frac + 1.0 : frac;
}

static uint8_t zhello_channel(uint8_t a, uint8_t b, double t)
{
	return (uint8_t)((double)a + ((double)b - (double)a) * t + 0.5);
}

static uint8_t zhello_clamp_channel(int v)
{
	if (v < 0)
		return 0;
	if (v > 255)
		return 255;
	return (uint8_t)v;
}

void zhello_world_init(struct zhello_world *world, uint32_t width,
		       uint32_t height)
{
	memset(world, 0, sizeof(*world));
	world->x = (double)width * 0.25;
	world->y = (double)height * 0.25;
	world->vx = 180.0;
	world->vy = 130.0;
	world->frames = 0;
}

void zhello_world_step(struct zhello_world *world, uint32_t width,
		       uint32_t height, double dt_seconds)
{
	const double side = (double)ZHELLO_SQUARE_SIDE;
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

void zhello_render(const struct zhello_world *world,
		   const struct zhello_canvas *canvas, uint32_t t_ms)
{
	const uint32_t w = canvas->width;
	const uint32_t h = canvas->height;
	uint8_t *pixels = canvas->pixels;

	/* Background: a vertical gradient whose phase drifts with time. */
	const double phase = zhello_wrap01((double)t_ms / 8000.0);
	uint8_t top_r = zhello_channel(zhello_stop_a.r, zhello_stop_b.r, phase);
	uint8_t top_g = zhello_channel(zhello_stop_a.g, zhello_stop_b.g, phase);
	uint8_t top_b = zhello_channel(zhello_stop_a.b, zhello_stop_b.b, phase);
	uint8_t bot_r = zhello_channel(zhello_stop_b.r, zhello_stop_a.r, phase);
	uint8_t bot_g = zhello_channel(zhello_stop_b.g, zhello_stop_a.g, phase);
	uint8_t bot_b = zhello_channel(zhello_stop_b.b, zhello_stop_a.b, phase);

	for (uint32_t y = 0; y < h; y++) {
		const double t = (h > 1u) ? (double)y / (double)(h - 1u) : 0.0;
		const uint8_t r =
			zhello_channel(top_r, bot_r, t);
		const uint8_t g =
			zhello_channel(top_g, bot_g, t);
		const uint8_t b =
			zhello_channel(top_b, bot_b, t);
		uint8_t *row = pixels + (size_t)y * (size_t)w *
					 ZHELLO_PIXEL_BYTES;
		for (uint32_t x = 0; x < w; x++) {
			uint8_t *px = row + (size_t)x * ZHELLO_PIXEL_BYTES;
			px[0] = r;
			px[1] = g;
			px[2] = b;
			px[3] = 0xFF;
		}
	}

	/* The bouncing square: one solid block plus a two-pixel lit border,
	 * clipped by hand because zhello has no scissor rect. */
	const int32_t side = (int32_t)ZHELLO_SQUARE_SIDE;
	const int32_t x0 = (int32_t)(world->x + 0.5);
	const int32_t y0 = (int32_t)(world->y + 0.5);
	const uint8_t pulse = zhello_clamp_channel(
		110 + (int)(70.0 * zhello_wrap01((double)t_ms / 1200.0)));

	for (int32_t y = y0; y < y0 + side; y++) {
		if (y < 0 || (uint32_t)y >= h)
			continue;
		uint8_t *row = pixels + (size_t)y * (size_t)w *
					 ZHELLO_PIXEL_BYTES;
		for (int32_t x = x0; x < x0 + side; x++) {
			if (x < 0 || (uint32_t)x >= w)
				continue;
			const bool border = (x == x0 || x == x0 + side - 1 ||
					     y == y0 || y == y0 + side - 1);
			uint8_t *px = row + (size_t)x * ZHELLO_PIXEL_BYTES;
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

uint64_t zhello_canvas_digest(const struct zhello_canvas *canvas)
{
	const size_t bytes = (size_t)canvas->width * (size_t)canvas->height *
			     ZHELLO_PIXEL_BYTES;
	uint64_t hash = 1469598103934665603ULL; /* FNV-1a 64 offset basis */
	const uint8_t *p = canvas->pixels;
	for (size_t i = 0; i < bytes; i++) {
		hash ^= p[i];
		hash *= 1099511628211ULL;
	}
	return hash;
}
