/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * rom_watch_loop — see rom_watch_loop.h. Pure loop control over an injected
 * fetch callback and the pure ASCII renderer; the only I/O is writing rendered
 * frames to the caller's stream and sleeping between them. */

#include "command/rom_watch_loop.h"

#include "command/rom_compile_render.h"
#include "json/json.h"
#include "platform/time_compat.h"

#if !defined(_WIN32)
#include <signal.h>
#endif
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* SIGINT during a watch sets this flag (async-signal-safe: a lone sig_atomic_t
 * store). The loop polls it at every boundary and exits 0 — a Ctrl-C ends the
 * watch, it does not kill the render mid-line. */
#if !defined(_WIN32)
static volatile sig_atomic_t g_rom_watch_interrupted = 0;

static void rom_watch_on_sigint(int sig)
{
    (void)sig;
    g_rom_watch_interrupted = 1;
}
#endif

static bool rom_watch_stopped(const struct rom_watch_opts *opts)
{
#if !defined(_WIN32)
    if (g_rom_watch_interrupted) return true;
#endif
    return opts->stop && opts->stop(opts->stop_ctx);
}

/* Number of physical lines the last frame occupied == its newline count (each
 * rendered line ends in '\n', so after fputs the cursor sits at column 0 of the
 * line past the last content line; moving up this many lands on the first). */
static unsigned rom_watch_count_lines(const char *s)
{
    unsigned n = 0;
    for (; s && *s; s++)
        if (*s == '\n')
            n++;
    return n;
}

int rom_watch_run(rom_watch_fetch_fn fetch, void *ctx,
                  const struct rom_watch_opts *opts)
{
    if (!fetch || !opts)
        return 2; /* invalid usage — caller passed no fetch/opts */

    FILE *stream = opts->stream ? opts->stream : stdout;
    int interval_ms = opts->interval_ms > 0 ? opts->interval_ms : 2000;
    if (interval_ms < 500)
        interval_ms = 500;
    if (interval_ms > 60000)
        interval_ms = 60000;
    int max_iters = opts->max_iters; /* 0 => until interrupted */

    /* Install a transient SIGINT handler; restore the caller's disposition on
     * return. A failure to install is non-fatal — the loop still honors
     * max_iters, it just cannot catch Ctrl-C. */
#if !defined(_WIN32)
    struct sigaction sa, old_sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = rom_watch_on_sigint;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    bool installed = (sigaction(SIGINT, &sa, &old_sa) == 0);
    g_rom_watch_interrupted = 0;
#endif

    unsigned prev_lines = 0;
    bool have_prev = false;
    int iters = 0;

    while (!rom_watch_stopped(opts)) {
        char text[8192];
        char err[256];
        err[0] = '\0';

        struct json_value body;
        json_init(&body);
        bool ok = fetch(ctx, &body, err, sizeof(err));

        /* Redraw in place: rewind over the previous frame, then clear to the
         * end of screen so a shorter frame leaves no stale tail. Only on a TTY
         * (opts->ansi) and never before the first frame is on screen. */
        if (opts->ansi && have_prev && prev_lines > 0)
            fprintf(stream, "\x1b[%uA\x1b[J", prev_lines);

        if (ok) {
            rom_compile_render_ascii(&body, text, sizeof(text));
        } else {
            /* A fetch error is one diagnostic line, not a loop abort — the next
             * poll may well succeed (node still booting, transient RPC). */
            (void)snprintf(text, sizeof(text), "rom watch: fetch failed: %s\n",
                           err[0] ? err : "unknown error");
        }
        json_free(&body);

        fputs(text, stream);
        fflush(stream);
        prev_lines = rom_watch_count_lines(text);
        have_prev = true;

        iters++;
        if (max_iters > 0 && iters >= max_iters)
            break;
        if (rom_watch_stopped(opts))
            break;
        int remaining = interval_ms;
        while (remaining > 0 && !rom_watch_stopped(opts)) {
            int slice = remaining > 50 ? 50 : remaining;
            platform_sleep_ms((uint32_t)slice);
            remaining -= slice;
        }
    }

#if !defined(_WIN32)
    if (installed)
        (void)sigaction(SIGINT, &old_sa, NULL);
#endif
    return 0;
}
