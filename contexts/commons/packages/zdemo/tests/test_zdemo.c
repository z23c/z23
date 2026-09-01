/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: deterministic known-answer test for zdemo's reusable component. */
#include "zdemo/zdemo.h"

#include <float.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>

enum { TEST_WIDTH = 96, TEST_HEIGHT = 96 };

#define CHECK(cond) do { \
	if (!(cond)) { \
		(void)fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
		return 1; \
	} \
} while (0)

static int test_frame_count_parser(void)
{
	static const char *const invalid[] = {
		"", "0", "-1", "+1", "1x", " 1", "1 ",
	};
	char maximum[32];
	char overflow[40];
	unsigned frames = 17u;

	(void)snprintf(maximum, sizeof(maximum), "%u", UINT_MAX);
	(void)snprintf(overflow, sizeof(overflow), "%u0", UINT_MAX);
	for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
		frames = 17u;
		CHECK(!zdemo_parse_frame_count(invalid[i], &frames));
		CHECK(frames == 17u);
	}
	frames = 17u;
	CHECK(!zdemo_parse_frame_count(overflow, &frames));
	CHECK(frames == 17u);
	CHECK(zdemo_parse_frame_count("1", &frames) && frames == 1u);
	CHECK(zdemo_parse_frame_count(maximum, &frames) && frames == UINT_MAX);
	CHECK(!zdemo_parse_frame_count(NULL, &frames));
	CHECK(!zdemo_parse_frame_count("1", NULL));
	return 0;
}

static int test_seconds_parser(void)
{
	static const char *const invalid[] = {
		"", "0", "-1", "nan", "inf", "1x", "1e9999", "1e-9999",
		" 1", "1 ", "0x1p0", ".", "1e",
	};
	char overflow[64];
	double seconds = 17.0;

	(void)snprintf(overflow, sizeof(overflow), "%.*g", DBL_DECIMAL_DIG,
		       DBL_MAX);
	for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
		seconds = 17.0;
		CHECK(!zdemo_parse_seconds(invalid[i], &seconds));
		CHECK(seconds == 17.0);
	}
	seconds = 17.0;
	CHECK(!zdemo_parse_seconds(overflow, &seconds));
	CHECK(seconds == 17.0);
	CHECK(zdemo_parse_seconds(".5", &seconds) && seconds == 0.5);
	CHECK(zdemo_parse_seconds("1e2", &seconds) && seconds == 100.0);
	CHECK(!zdemo_parse_seconds(NULL, &seconds));
	CHECK(!zdemo_parse_seconds("1", NULL));
	return 0;
}

int main(void)
{
	static uint8_t pixels_a[TEST_WIDTH * TEST_HEIGHT * ZDEMO_PIXEL_BYTES];
	static uint8_t pixels_b[TEST_WIDTH * TEST_HEIGHT * ZDEMO_PIXEL_BYTES];
	struct zdemo_world world_a;
	struct zdemo_world world_b;
	const struct zdemo_canvas canvas_a = { pixels_a, TEST_WIDTH, TEST_HEIGHT };
	const struct zdemo_canvas canvas_b = { pixels_b, TEST_WIDTH, TEST_HEIGHT };

	CHECK(test_frame_count_parser() == 0);
	CHECK(test_seconds_parser() == 0);
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
