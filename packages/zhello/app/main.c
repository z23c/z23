/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: zhello — a native window on screen in under a second, from one
 * `make zhello` typed after a clone.
 *
 * Two modes:
 *   zhello                 open a real RGFW window and animate it until Esc,
 *                          close, or `--seconds=N` elapses. Prints one log
 *                          line the moment the first frame is presented.
 *   zhello --frames=N      headless self-test: same painter, no window, no
 *                          RGFW call at all. Presents N logical frames, prints
 *                          per-frame present times, exits 0. This is the CI
 *                          path: a machine without a WindowServer still proves
 *                          the frame code runs.
 *
 * The windowing backend is the vendored RGFW (Cocoa on macOS, X11 via dynamic
 * loading on Linux, Win32 on Windows) in its software-surface mode: zhello
 * draws pixels, not triangles, so there is no OpenGL or Metal dependency.
 */

#include "zhello/zhello.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* RGFW is private implementation detail of this file. These switches mirror
 * lib/presentation/src/presentation.c: software surfaces only, no OpenGL, no
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
#define ZHELLO_UNDEF_MSC_VER
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
#elif defined(ZHELLO_UNDEF_MSC_VER)
#undef _MSC_VER
#undef ZHELLO_UNDEF_MSC_VER
#endif

#define ZHELLO_WIDTH 640u
#define ZHELLO_HEIGHT 400u
#define ZHELLO_TARGET_FPS 60

static uint8_t zhello_pixels[ZHELLO_WIDTH * ZHELLO_HEIGHT *
			     ZHELLO_PIXEL_BYTES];

static double zhello_now_ms(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (double)ts.tv_sec * 1e3 + (double)ts.tv_nsec / 1e6;
}

/* Wall-clock timestamp for the log lines: the reader of the log wants to know
 * when on the wall the first pixel landed, not only how long it took. */
static void zhello_wall_stamp(char *out, size_t cap)
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

static void zhello_sleep_until(double deadline_ms)
{
	for (;;) {
		const double now = zhello_now_ms();
		if (now >= deadline_ms)
			return;
		struct timespec ts;
		const double remain_s = (deadline_ms - now) / 1e3;
		ts.tv_sec = (time_t)remain_s;
		ts.tv_nsec = (long)((remain_s - (double)ts.tv_sec) * 1e9);
		(void)nanosleep(&ts, NULL);
	}
}

struct zhello_options {
	unsigned frames;   /* 0 = run the window until told to stop */
	double seconds;	   /* windowed auto-exit; 0 = none */
	int print_every_frame;
	int show_help;
};

static void zhello_parse_options(int argc, char **argv,
				 struct zhello_options *opts)
{
	memset(opts, 0, sizeof(*opts));
	opts->print_every_frame = 1;
	for (int i = 1; i < argc; i++) {
		const char *arg = argv[i];
		if (strncmp(arg, "--frames=", 9) == 0) {
			opts->frames = (unsigned)strtoul(arg + 9, NULL, 10);
		} else if (strncmp(arg, "--seconds=", 10) == 0) {
			opts->seconds = strtod(arg + 10, NULL);
		} else if (strcmp(arg, "--quiet") == 0) {
			opts->print_every_frame = 0;
		} else if (strcmp(arg, "--help") == 0) {
			opts->show_help = 1;
			return;
		} else {
			(void)fprintf(stderr, "zhello: unknown option %s\n",
				      arg);
			opts->show_help = 1;
			return;
		}
	}
}

/* ── headless self-test ──────────────────────────────────────────────
 * Same painter, same cadence, no window. A frame only counts as presented
 * once its pixels are folded into a digest, so an optimizer (or a refactor)
 * cannot silently skip the work and still print present times.
 */
static int zhello_selftest(const struct zhello_options *opts)
{
	struct zhello_canvas canvas = {
		.pixels = zhello_pixels,
		.width = ZHELLO_WIDTH,
		.height = ZHELLO_HEIGHT,
	};
	struct zhello_world world;
	zhello_world_init(&world, canvas.width, canvas.height);

	const unsigned frames = opts->frames ? opts->frames : 120u;
	const unsigned mid = frames > 1u ? frames / 2u : 0u;
	(void)printf("zhello selftest: frames=%u size=%ux%u mode=headless\n",
		     frames, canvas.width, canvas.height);

	const double t0 = zhello_now_ms();
	uint64_t digest_first = 0;
	uint64_t digest_mid = 0;
	double first_present_ms = 0.0;
	uint8_t alpha_ok = 1;

	for (unsigned i = 0; i < frames; i++) {
		zhello_world_step(&world, canvas.width, canvas.height,
				  ZHELLO_TEST_DT_SECONDS);
		zhello_render(&world, &canvas,
			      (uint32_t)((double)i * 1000.0 / 60.0));

		const double start = zhello_now_ms();
		/* "Present" = the frame left this process: fold it. */
		const uint64_t digest = zhello_canvas_digest(&canvas);
		const double done = zhello_now_ms();
		if (i == 0) {
			digest_first = digest;
			first_present_ms = done - t0;
		}
		if (i == mid)
			digest_mid = digest;
		for (size_t p = 3u; p < (size_t)canvas.width *
						(size_t)canvas.height *
						ZHELLO_PIXEL_BYTES;
		     p += ZHELLO_PIXEL_BYTES) {
			if (zhello_pixels[p] != 0xFFu)
				alpha_ok = 0;
		}
		if (opts->print_every_frame) {
			(void)printf("zhello present frame %u/%u in %.1f us\n",
				     i + 1u, frames, (done - start) * 1e3);
		}
	}
	const double total_ms = zhello_now_ms() - t0;

	if (frames > 1u && digest_first == digest_mid) {
		(void)fprintf(stderr,
			      "zhello selftest: FAIL frames did not move "
			      "(digest %llu at frame 0 and frame %u)\n",
			      (unsigned long long)digest_first, mid);
		return 1;
	}
	if (!alpha_ok) {
		(void)fprintf(stderr,
			      "zhello selftest: FAIL canvas is not opaque\n");
		return 1;
	}

	(void)printf("zhello selftest: OK frames=%u first_present_ms=%.2f "
		     "total_ms=%.2f digest_first=%llu digest_mid=%llu\n",
		     frames, first_present_ms, total_ms,
		     (unsigned long long)digest_first,
		     (unsigned long long)digest_mid);
	return 0;
}

/* ── the real thing: a window on the desktop ───────────────────────── */
static int zhello_window(const struct zhello_options *opts)
{
	struct zhello_canvas canvas = {
		.pixels = zhello_pixels,
		.width = ZHELLO_WIDTH,
		.height = ZHELLO_HEIGHT,
	};
	struct zhello_world world;
	zhello_world_init(&world, canvas.width, canvas.height);

	char stamp[40];
	zhello_wall_stamp(stamp, sizeof(stamp));
	const double t0 = zhello_now_ms();

	RGFW_window *win = RGFW_createWindow(
		"zhello - Z23 prompt-to-pixel", (i32)0, (i32)0,
		(i32)canvas.width, (i32)canvas.height,
		(RGFW_windowFlags)RGFW_windowCenter);
	if (win == NULL) {
		(void)fprintf(stderr,
			      "zhello: RGFW_createWindow failed — run "
			      "`zhello --frames=N` for the headless proof\n");
		return 1;
	}
	const double window_ms = zhello_now_ms() - t0;
	RGFW_window_setExitKey(win, RGFW_escape);

	RGFW_surface *surface = RGFW_window_createSurface(
		win, canvas.pixels, (i32)canvas.width, (i32)canvas.height,
		RGFW_formatRGBA8);
	if (surface == NULL) {
		(void)fprintf(stderr, "zhello: RGFW_window_createSurface "
				      "failed\n");
		RGFW_window_close(win);
		return 1;
	}

	RGFW_event event;
	double last_ms = zhello_now_ms();
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
		if (deadline != 0.0 && zhello_now_ms() >= deadline)
			goto presented;

		zhello_world_step(&world, canvas.width, canvas.height,
				  ZHELLO_TEST_DT_SECONDS);
		zhello_render(&world, &canvas,
			      (uint32_t)((double)world.frames * 1000.0 /
					 60.0));

		const double present_start = zhello_now_ms();
		RGFW_window_blitSurface(win, surface);
		const double present_done = zhello_now_ms();
		present_total_ms += present_done - present_start;

		if (frames == 0) {
			first_present_ms = present_done - t0;
			zhello_wall_stamp(stamp, sizeof(stamp));
			(void)printf(
				"zhello %s present frame 0 in %.1f ms "
				"(window created %.1f ms, first present %.1f "
				"ms after launch)\n",
				stamp, present_done - t0, window_ms,
				first_present_ms);
			(void)fflush(stdout);
		}
		frames++;

		next_frame_ms += 1000.0 / (double)ZHELLO_TARGET_FPS;
		zhello_sleep_until(next_frame_ms);
		last_ms = zhello_now_ms();
		if (last_ms > next_frame_ms + 1000.0)
			next_frame_ms = last_ms;
	}

presented:;
	const double total_ms = zhello_now_ms() - t0;
	(void)printf("zhello closed after %llu frames in %.1f ms "
		     "(first present %.1f ms, mean present %.3f ms)\n",
		     (unsigned long long)frames, total_ms, first_present_ms,
		     frames ? present_total_ms / (double)frames : 0.0);
	RGFW_surface_free(surface);
	RGFW_window_close(win);
	return 0;
}

static void zhello_print_usage(void)
{
	(void)printf("zhello — the prompt-to-pixel demo\n"
		     "usage: zhello [--frames=N] [--seconds=S] [--quiet]\n"
		     "  --frames=N   headless self-test: render N logical "
		     "frames, no window, exit 0\n"
		     "  --seconds=S  windowed run that exits by itself\n"
		     "  --quiet      self-test: skip the per-frame lines\n");
}

int main(int argc, char **argv)
{
	struct zhello_options opts;
	zhello_parse_options(argc, argv, &opts);
	if (opts.show_help) {
		zhello_print_usage();
		return 2;
	}
	return opts.frames ? zhello_selftest(&opts) : zhello_window(&opts);
}
