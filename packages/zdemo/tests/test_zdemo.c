/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: deterministic known-answer test for the zdemo painter. */
#include "zdemo/zdemo.h"

#include <stdio.h>
#include <string.h>

enum { TEST_WIDTH = 96, TEST_HEIGHT = 96 };

#define CHECK(cond) do { \
	if (!(cond)) { \
		(void)fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
		return 1; \
	} \
} while (0)

int main(void)
{
	static uint8_t pixels_a[TEST_WIDTH * TEST_HEIGHT * ZDEMO_PIXEL_BYTES];
	static uint8_t pixels_b[TEST_WIDTH * TEST_HEIGHT * ZDEMO_PIXEL_BYTES];
	struct zdemo_world world_a;
	struct zdemo_world world_b;
	const struct zdemo_canvas canvas_a = { pixels_a, TEST_WIDTH, TEST_HEIGHT };
	const struct zdemo_canvas canvas_b = { pixels_b, TEST_WIDTH, TEST_HEIGHT };

	zdemo_world_init(&world_a, TEST_WIDTH, TEST_HEIGHT);
	zdemo_world_init(&world_b, TEST_WIDTH, TEST_HEIGHT);
	zdemo_world_step(&world_a, TEST_WIDTH, TEST_HEIGHT, ZDEMO_TEST_DT_SECONDS);
	zdemo_world_step(&world_b, TEST_WIDTH, TEST_HEIGHT, ZDEMO_TEST_DT_SECONDS);
	zdemo_render(&world_a, &canvas_a, 16u);
	zdemo_render(&world_b, &canvas_b, 16u);

	CHECK(world_a.frames == 1u);
	CHECK(memcmp(pixels_a, pixels_b, sizeof pixels_a) == 0);
	for (size_t i = 3u; i < sizeof pixels_a; i += ZDEMO_PIXEL_BYTES)
		CHECK(pixels_a[i] == 0xffu);
	const uint64_t digest = zdemo_canvas_digest(&canvas_a);
	if (digest != UINT64_C(16732952640180923659)) {
		(void)fprintf(stderr, "zdemo KAT digest=%llu\n",
			      (unsigned long long)digest);
		return 1;
	}
	(void)printf("zdemo package test PASS digest=%llu\n",
		     (unsigned long long)digest);
	return 0;
}
