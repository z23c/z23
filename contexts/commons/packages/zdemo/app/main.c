/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: zdemo — a native window on screen in under a second, from one
 * `make zdemo` typed after a clone.
 *
 * Two modes:
 *   zdemo                 open a real RGFW window and animate it until Esc,
 *                          close, or `--seconds=N` elapses. Prints one log
 *                          line the moment the first frame is presented.
 *   zdemo --frames=N      headless self-test: same painter, no window, no
 *                          RGFW call at all. Presents N logical frames, prints
 *                          per-frame present times, exits 0. This is the CI
 *                          path: a machine without a WindowServer still proves
 *                          the frame code runs.
 *
 * The windowing backend is the vendored RGFW (Cocoa on macOS, X11 via dynamic
 * loading on Linux, Win32 on Windows) in its software-surface mode: zdemo
 * draws pixels, not triangles, so there is no OpenGL or Metal dependency.
 */

#include "zdemo/zdemo.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* RGFW is private implementation detail of this file. These switches mirror
 * contexts/explorer/modules/presentation/src/presentation.c: software surfaces only, no OpenGL, no
 * IOKit, and on Linux the X11 API is loaded at runtime by the vendored XDL
 * layer instead of becoming a link-time dependency. */
#define RGFW_IMPLEMENTATION
#define RGFW_NO_API
#define RGFW_NO_IOKIT
#if defined(__APPLE__) && defined(__clang__)
/* RGFW has two legacy numeric `_MSC_VER` probes. Do not define that macro on
 * Apple: current SDK headers use its presence to select actual MSVC syntax. */
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wundef"
#elif !defined(_MSC_VER)
/* RGFW probes the MSVC version numerically instead of with defined(). */
#define _MSC_VER 0
#define ZDEMO_UNDEF_MSC_VER
#endif
#if defined(__linux__)
#define RGFW_USE_XDL
#define RGFW_NO_X11_CURSOR
#define RGFW_NO_DPI
#define RGFW_NO_XINPUT2
#define RGFW_NO_X11_XI_PRELOAD
#define XDL_NO_GLX
#define XDL_NO_XRANDR
#endif
#include "RGFW.h"
#if defined(__APPLE__) && defined(__clang__)
#pragma clang diagnostic pop
#elif defined(ZDEMO_UNDEF_MSC_VER)
#undef _MSC_VER
#undef ZDEMO_UNDEF_MSC_VER
#endif

#define ZDEMO_WIDTH 640u
#define ZDEMO_HEIGHT 400u
#define ZDEMO_TARGET_FPS 60

static uint8_t zdemo_pixels[ZDEMO_WIDTH * ZDEMO_HEIGHT *
			     ZDEMO_PIXEL_BYTES];

static double zdemo_now_ms(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (double)ts.tv_sec * 1e3 + (double)ts.tv_nsec / 1e6;
}

/* Wall-clock timestamp for the log lines: the reader of the log wants to know
 * when on the wall the first pixel landed, not only how long it took. */
static void zdemo_wall_stamp(char *out, size_t cap)
{
	struct timespec ts;
	struct tm tm_utc;
	clock_gettime(CLOCK_REALTIME, &ts);
	gmtime_r(&ts.tv_sec, &tm_utc);
	(void)snprintf(out, cap, "%04u-%02u-%02uT%02u:%02u:%02u.%03uZ",
		       (unsigned)(tm_utc.tm_year + 1900),
		       (unsigned)(tm_utc.tm_mon + 1),
		       (unsigned)tm_utc.tm_mday, (unsigned)tm_utc.tm_hour,
		       (unsigned)tm_utc.tm_min, (unsigned)tm_utc.tm_sec,
		       (unsigned)(ts.tv_nsec / 1000000u));
}

static void zdemo_sleep_until(double deadline_ms)
{
	for (;;) {
		const double now = zdemo_now_ms();
		if (now >= deadline_ms)
			return;
		struct timespec ts;
		const double remain_s = (deadline_ms - now) / 1e3;
		ts.tv_sec = (time_t)remain_s;
		ts.tv_nsec = (long)((remain_s - (double)ts.tv_sec) * 1e9);
		(void)nanosleep(&ts, NULL);
	}
}

struct zdemo_options {
	unsigned frames;   /* 0 = run the window until told to stop */
	double seconds;	   /* windowed auto-exit; 0 = none */
	int print_every_frame;
	int show_help;
};

static int zdemo_parse_options(int argc, char **argv,
				struct zdemo_options *opts)
{
	memset(opts, 0, sizeof(*opts));
	opts->print_every_frame = 1;
	for (int i = 1; i < argc; i++) {
		const char *arg = argv[i];
		if (strncmp(arg, "--frames=", 9) == 0) {
			if (!zdemo_parse_frame_count(arg + 9, &opts->frames)) {
				(void)fprintf(stderr,
					      "zdemo: invalid --frames value '%s': "
					      "expected an integer from 1 to %u\n",
					      arg + 9, UINT_MAX);
				return -1;
			}
		} else if (strncmp(arg, "--seconds=", 10) == 0) {
			if (!zdemo_parse_seconds(arg + 10, &opts->seconds)) {
				(void)fprintf(stderr,
					      "zdemo: invalid --seconds value '%s': "
					      "expected a finite positive decimal\n",
					      arg + 10);
				return -1;
			}
		} else if (strcmp(arg, "--quiet") == 0) {
			opts->print_every_frame = 0;
		} else if (strcmp(arg, "--help") == 0) {
			opts->show_help = 1;
			return 0;
		} else {
			(void)fprintf(stderr, "zdemo: unknown option %s\n",
				      arg);
			opts->show_help = 1;
			return 0;
		}
	}
	return 0;
}

/* ── headless self-test ──────────────────────────────────────────────
 * Same painter, same cadence, no window. A frame only counts as presented
 * once its pixels are folded into a digest, so an optimizer (or a refactor)
 * cannot silently skip the work and still print present times.
 */
static int zdemo_selftest(const struct zdemo_options *opts)
{
	struct zdemo_canvas canvas = {
		.pixels = zdemo_pixels,
		.width = ZDEMO_WIDTH,
		.height = ZDEMO_HEIGHT,
	};
	struct zdemo_world world;
	zdemo_world_init(&world, canvas.width, canvas.height);

	const unsigned frames = opts->frames ? opts->frames : 120u;
	const unsigned mid = frames > 1u ? frames / 2u : 0u;
	(void)printf("zdemo selftest: frames=%u size=%ux%u mode=headless\n",
		     frames, canvas.width, canvas.height);

	const double t0 = zdemo_now_ms();
	uint64_t digest_first = 0;
	uint64_t digest_mid = 0;
	double first_present_ms = 0.0;
	uint8_t alpha_ok = 1;

	for (unsigned i = 0; i < frames; i++) {
		zdemo_world_step(&world, canvas.width, canvas.height,
				  ZDEMO_TEST_DT_SECONDS);
		zdemo_render(&world, &canvas,
			      (uint32_t)((double)i * 1000.0 / 60.0));

		const double start = zdemo_now_ms();
		/* "Present" = the frame left this process: fold it. */
		const uint64_t digest = zdemo_canvas_digest(&canvas);
		const double done = zdemo_now_ms();
		if (i == 0) {
			digest_first = digest;
			first_present_ms = done - t0;
		}
		if (i == mid)
			digest_mid = digest;
		for (size_t p = 3u; p < (size_t)canvas.width *
						(size_t)canvas.height *
						ZDEMO_PIXEL_BYTES;
		     p += ZDEMO_PIXEL_BYTES) {
			if (zdemo_pixels[p] != 0xFFu)
				alpha_ok = 0;
		}
		if (opts->print_every_frame) {
			(void)printf("zdemo present frame %u/%u in %.1f us\n",
				     i + 1u, frames, (done - start) * 1e3);
		}
	}
	const double total_ms = zdemo_now_ms() - t0;

	if (frames > 1u && digest_first == digest_mid) {
		(void)fprintf(stderr,
			      "zdemo selftest: FAIL frames did not move "
			      "(digest %llu at frame 0 and frame %u)\n",
			      (unsigned long long)digest_first, mid);
		return 1;
	}
	if (!alpha_ok) {
		(void)fprintf(stderr,
			      "zdemo selftest: FAIL canvas is not opaque\n");
		return 1;
	}

	(void)printf("zdemo selftest: OK frames=%u first_present_ms=%.2f "
		     "total_ms=%.2f digest_first=%llu digest_mid=%llu\n",
		     frames, first_present_ms, total_ms,
		     (unsigned long long)digest_first,
		     (unsigned long long)digest_mid);
	return 0;
}

/* ── the real thing: a window on the desktop ───────────────────────── */
static int zdemo_window(const struct zdemo_options *opts)
{
	struct zdemo_canvas canvas = {
		.pixels = zdemo_pixels,
		.width = ZDEMO_WIDTH,
		.height = ZDEMO_HEIGHT,
	};
	struct zdemo_world world;
	zdemo_world_init(&world, canvas.width, canvas.height);

	char stamp[40];
	zdemo_wall_stamp(stamp, sizeof(stamp));
	const double t0 = zdemo_now_ms();

	RGFW_window *win = RGFW_createWindow(
		"zdemo - Z23 prompt-to-pixel", (i32)0, (i32)0,
		(i32)canvas.width, (i32)canvas.height,
		(RGFW_windowFlags)RGFW_windowCenter);
	if (win == NULL) {
		(void)fprintf(stderr,
			      "zdemo: RGFW_createWindow failed — run "
			      "`zdemo --frames=N` for the headless proof\n");
		return 1;
	}
	const double window_ms = zdemo_now_ms() - t0;
	RGFW_window_setExitKey(win, RGFW_escape);

	RGFW_surface *surface = RGFW_window_createSurface(
		win, canvas.pixels, (i32)canvas.width, (i32)canvas.height,
		RGFW_formatRGBA8);
	if (surface == NULL) {
		(void)fprintf(stderr, "zdemo: RGFW_window_createSurface "
				      "failed\n");
		RGFW_window_close(win);
		return 1;
	}

	RGFW_event event;
	double last_ms = zdemo_now_ms();
	uint64_t frames = 0;
	double first_present_ms = 0.0;
	double present_total_ms = 0.0;
	const double deadline =
		opts->seconds > 0.0 ? t0 + opts->seconds * 1e3 : 0.0;
	double next_frame_ms = last_ms;

	for (;;) {
		while (RGFW_window_checkEvent(win, &event)) {
			if (event.type == RGFW_quit)
				goto presented;
		}
		if (RGFW_window_shouldClose(win))
			goto presented;
		if (deadline != 0.0 && zdemo_now_ms() >= deadline)
			goto presented;

		zdemo_world_step(&world, canvas.width, canvas.height,
				  ZDEMO_TEST_DT_SECONDS);
		zdemo_render(&world, &canvas,
			      (uint32_t)((double)world.frames * 1000.0 /
					 60.0));

		const double present_start = zdemo_now_ms();
		RGFW_window_blitSurface(win, surface);
		const double present_done = zdemo_now_ms();
		present_total_ms += present_done - present_start;

		if (frames == 0) {
			first_present_ms = present_done - t0;
			zdemo_wall_stamp(stamp, sizeof(stamp));
			(void)printf(
				"zdemo %s present frame 0 in %.1f ms "
				"(window created %.1f ms, first present %.1f "
				"ms after launch)\n",
				stamp, present_done - t0, window_ms,
				first_present_ms);
			(void)fflush(stdout);
		}
		frames++;

		next_frame_ms += 1000.0 / (double)ZDEMO_TARGET_FPS;
		zdemo_sleep_until(next_frame_ms);
		last_ms = zdemo_now_ms();
		if (last_ms > next_frame_ms + 1000.0)
			next_frame_ms = last_ms;
	}

presented:;
	const double total_ms = zdemo_now_ms() - t0;
	(void)printf("zdemo closed after %llu frames in %.1f ms "
		     "(first present %.1f ms, mean present %.3f ms)\n",
		     (unsigned long long)frames, total_ms, first_present_ms,
		     frames ? present_total_ms / (double)frames : 0.0);
	RGFW_surface_free(surface);
	RGFW_window_close(win);
	return 0;
}

static void zdemo_print_usage(void)
{
	(void)printf("zdemo — the prompt-to-pixel demo\n"
		     "usage: zdemo [--frames=N] [--seconds=S] [--quiet]\n"
		     "  --frames=N   headless self-test: render N logical "
		     "frames, no window, exit 0\n"
		     "  --seconds=S  windowed run that exits by itself\n"
		     "  --quiet      self-test: skip the per-frame lines\n");
}

int main(int argc, char **argv)
{
	struct zdemo_options opts;
	if (zdemo_parse_options(argc, argv, &opts) != 0)
		return 2;
	if (opts.show_help) {
		zdemo_print_usage();
		return 2;
	}
	return opts.frames ? zdemo_selftest(&opts) : zdemo_window(&opts);
}
