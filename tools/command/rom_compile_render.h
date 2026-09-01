/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * rom_compile_render — pure ASCII renderer for one zcl.rom_compile.v1 body
 * (the `state` object `dumpstate rom_compile` returns, NOT the outer
 * dumpstate envelope). Backs the `ops.rom` native leaf's human view; the
 * structured JSON stays the machine contract (see
 * engine/jobs/src/rom_compile_status.c). No I/O, no RPC — a test can drive this
 * with a synthetic json_value fixture. */

#ifndef ZCL_TOOLS_ROM_COMPILE_RENDER_H
#define ZCL_TOOLS_ROM_COMPILE_RENDER_H

#include <stddef.h>

struct json_value;

/* Renders a fold progress bar, a horizontal bar chart of the eight reducer
 * stages' step_us_ewma (the bottleneck stage marked), the layer ladder
 * (ROM checkpoint / sealed history / sealed base+receipt / delta / tip ring)
 * as filled/empty blocks, and a shielded_import line (status + resume
 * height; per-pool cursor/blocker/imported-count detail only while a gap is
 * open). Bounded to `cap` bytes, always NUL-terminated (truncates cleanly,
 * never overflows). A NULL/malformed `state` renders a one-line diagnostic
 * instead of crashing. */
void rom_compile_render_ascii(const struct json_value *state, char *out,
                              size_t cap);

#endif /* ZCL_TOOLS_ROM_COMPILE_RENDER_H */
