/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * rom_watch_loop — a small, testable watch driver for the ops.rom ASCII
 * display. It repeatedly pulls one zcl.rom_compile.v1 `state` body from an
 * injected fetch callback, renders it via rom_compile_render_ascii, and
 * redraws in place (cursor-up + clear) when writing to a TTY. The fetch source
 * is a closure the caller supplies — the live-node RPC path or the read-only
 * offline composer (rom_compile_offline.h) — so this file has NO node, RPC, or
 * datadir knowledge and a test can drive it with a synthetic fetch that returns
 * hand-built bodies. */

#ifndef ZCL_TOOLS_ROM_WATCH_LOOP_H
#define ZCL_TOOLS_ROM_WATCH_LOOP_H

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

struct json_value;

/* Fetch one zcl.rom_compile.v1 `state` object into `out` (the callee sets it up
 * with json_set_object / json_copy — `out` arrives freshly json_init'd). On
 * failure, return false and write a bounded reason into `err` (NUL-terminated,
 * never longer than `errlen`); the loop renders one diagnostic line and keeps
 * going. `ctx` is the caller's opaque state. */
typedef bool (*rom_watch_fetch_fn)(void *ctx, struct json_value *out,
                                   char *err, size_t errlen);
typedef bool (*rom_watch_stop_fn)(void *ctx);

struct rom_watch_opts {
    int   interval_ms; /* poll cadence; default 2000, clamped to [500, 60000] */
    int   max_iters;   /* stop after N renders; 0 = until interrupted (SIGINT) */
    bool  ansi;        /* in-place cursor-up redraw — only pass true for a TTY */
    FILE *stream;      /* output sink; NULL means stdout */
    rom_watch_stop_fn stop; /* optional hidden/headless-safe stop event poll */
    void *stop_ctx;
};

/* Run the watch loop. Returns 0 on a clean finish (max_iters, stop callback,
 * or POSIX SIGINT).
 * A NULL fetch or opts returns a non-zero invalid-usage code without looping.
 * POSIX installs a transient SIGINT handler and restores it on return.
 * Windows uses only the callback: no console allocation or control handler. */
int rom_watch_run(rom_watch_fetch_fn fetch, void *ctx,
                  const struct rom_watch_opts *opts);

#endif /* ZCL_TOOLS_ROM_WATCH_LOOP_H */
