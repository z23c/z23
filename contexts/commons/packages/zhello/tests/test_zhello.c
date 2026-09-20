/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: deterministic known-answer test for the zhello painter. */
#include "zhello/zhello.h"

#include <stdbool.h>
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
	static uint8_t pixels_a[TEST_WIDTH * TEST_HEIGHT * ZHELLO_PIXEL_BYTES];
	static uint8_t pixels_b[TEST_WIDTH * TEST_HEIGHT * ZHELLO_PIXEL_BYTES];
	struct zhello_world world_a;
	struct zhello_world world_b;
	const struct zhello_canvas canvas_a = { pixels_a, TEST_WIDTH, TEST_HEIGHT };
	const struct zhello_canvas canvas_b = { pixels_b, TEST_WIDTH, TEST_HEIGHT };

	zhello_world_init(&world_a, TEST_WIDTH, TEST_HEIGHT);
	zhello_world_init(&world_b, TEST_WIDTH, TEST_HEIGHT);
	zhello_world_step(&world_a, TEST_WIDTH, TEST_HEIGHT, ZHELLO_TEST_DT_SECONDS);
	zhello_world_step(&world_b, TEST_WIDTH, TEST_HEIGHT, ZHELLO_TEST_DT_SECONDS);
	zhello_render(&world_a, &canvas_a, 16u);
	zhello_render(&world_b, &canvas_b, 16u);

	CHECK(world_a.frames == 1u);
	CHECK(memcmp(pixels_a, pixels_b, sizeof pixels_a) == 0);
	for (size_t i = 3u; i < sizeof pixels_a; i += ZHELLO_PIXEL_BYTES)
		CHECK(pixels_a[i] == 0xffu);
	const uint64_t digest = zhello_canvas_digest(&canvas_a);
	if (digest != UINT64_C(16732952640180923659)) {
		(void)fprintf(stderr, "zhello KAT digest=%llu\n",
			      (unsigned long long)digest);
		return 1;
	}
	/* ── close and reopen ────────────────────────────────────────────
	 *
	 * The claim is not "a file was written". It is that stopping and
	 * starting again lands in the same place as never having stopped,
	 * so it is stated as an equality between two runs. */
	const char *const state_path = "zhello-state.test.tmp";
	(void)remove(state_path);

	/* A first run has no file, and that is not a failure. */
	struct zhello_world fresh;
	bool missing = false;
	CHECK(!zhello_world_load(&fresh, state_path, &missing));
	CHECK(missing);

	/* Run A: thirty steps, then close. */
	struct zhello_world closed;
	zhello_world_init(&closed, TEST_WIDTH, TEST_HEIGHT);
	for (int i = 0; i < 30; i++)
		zhello_world_step(&closed, TEST_WIDTH, TEST_HEIGHT,
				  ZHELLO_TEST_DT_SECONDS);
	CHECK(zhello_world_save(&closed, state_path));

	/* Reopen: every field comes back exactly, bit for bit. A position is
	 * carried as its binary64 pattern precisely so this can be memcmp and
	 * not "close enough". */
	struct zhello_world reopened;
	missing = true;
	CHECK(zhello_world_load(&reopened, state_path, &missing));
	CHECK(!missing);
	CHECK(memcmp(&reopened, &closed, sizeof reopened) == 0);

	/* Thirty more steps after reopening == sixty steps in one sitting. */
	struct zhello_world uninterrupted;
	zhello_world_init(&uninterrupted, TEST_WIDTH, TEST_HEIGHT);
	for (int i = 0; i < 60; i++)
		zhello_world_step(&uninterrupted, TEST_WIDTH, TEST_HEIGHT,
				  ZHELLO_TEST_DT_SECONDS);
	for (int i = 0; i < 30; i++)
		zhello_world_step(&reopened, TEST_WIDTH, TEST_HEIGHT,
				  ZHELLO_TEST_DT_SECONDS);
	CHECK(reopened.frames == 60u);
	CHECK(memcmp(&reopened, &uninterrupted, sizeof reopened) == 0);

	/* A damaged file is refused, never folded into "start over": that is
	 * how a person's state disappears with nobody told. `missing` stays
	 * false, so the caller can tell the two apart. */
	FILE *bad = fopen(state_path, "r+b");
	CHECK(bad != NULL);
	CHECK(fseek(bad, 3, SEEK_SET) == 0);
	CHECK(fputc('X', bad) != EOF);
	CHECK(fclose(bad) == 0);
	struct zhello_world damaged;
	missing = true;
	CHECK(!zhello_world_load(&damaged, state_path, &missing));
	CHECK(!missing);

	/* A file of the right shape but the wrong length is refused too — a
	 * truncated write must not read back as a shorter, valid world. */
	FILE *cut = fopen(state_path, "wb");
	CHECK(cut != NULL);
	CHECK(fwrite(&closed, 1, 4, cut) == 4);
	CHECK(fclose(cut) == 0);
	missing = true;
	CHECK(!zhello_world_load(&damaged, state_path, &missing));
	CHECK(!missing);
	CHECK(remove(state_path) == 0);

	(void)printf("zhello package test PASS digest=%llu\n",
		     (unsigned long long)digest);
	return 0;
}
