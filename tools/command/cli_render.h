/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * cli_render — the terminal-lane human presentation layer for the native
 * command registry.
 *
 * PRIME DIRECTIVE: machines get canonical JSON, humans get beauty. This
 * module NEVER changes what a pipe/agent sees — the canonical typed-JSON
 * document is always computed first, byte-identical to before, and only the
 * final print site swaps in one of these renderings when the resolved
 * environment says a human is watching:
 *
 *   human = ZCL_HUMAN=1|true|yes|on forces human, 0|false|no|off forces JSON;
 *           otherwise isatty(stdout).
 *   ansi  = human && NO_COLOR unset && TERM != "dumb".
 *   width = TIOCGWINSZ, else $COLUMNS, else 80 (clamped 40..240).
 *
 * Every renderer degrades to "return 0" (caller prints the canonical JSON)
 * for any document shape it does not recognize — human mode is strictly
 * opt-in per shape, never a guess.
 *
 * The module allocates nothing: callers pass the output buffer. */

#ifndef ZCL_CLI_RENDER_H
#define ZCL_CLI_RENDER_H

#include <stdbool.h>
#include <stddef.h>

struct zcl_cli_render_env {
    bool human;      /* render for a human at all */
    bool ansi;       /* ANSI emphasis allowed (bold/dim/red/green/yellow) */
    int width;       /* terminal columns, 40..240 */
    size_t max_rows; /* table row cap before the "... (N more, ...)" footer */
};

/* Resolve the environment for one output fd (pass fileno(stdout)).
 * Pure: reads isatty/ioctl/getenv only. */
struct zcl_cli_render_env zcl_cli_render_resolve(int fd);

/* Render one canonical JSON document (the exact text the JSON path would
 * print) for a human. Dispatches on the document's own "schema" field:
 *   zcl.command_menu.v1    — branch menu / discover help  → table
 *   zcl.command_search.v1  — discover search              → table
 *   zcl.command_spec.v1    — discover describe            → kv sections
 *   zcl.command_schema.v1  — discover schema              → kv lines
 *   zcl.state_catalog.v2   — statecatalog                 → table
 *   zcl.result.v1 ok=false — any command error envelope   → error block
 *   zcl.result.v1 ok=true  — only when command_path is in the human-render
 *                            leaf allowlist (ops.state, ops.logs) → data tree
 * `command_path` is the resolved registry path (e.g. "ops.state"), may be
 * NULL. Returns bytes written (always < cap, NUL-terminated), or 0 when the
 * shape is not human-rendered — the caller MUST then print the canonical
 * JSON unchanged. */
size_t zcl_cli_render_doc(const char *doc, size_t doc_len,
                          const char *command_path,
                          const struct zcl_cli_render_env *env,
                          char *out, size_t cap);

/* Colorize the frozen ONE-LINE status brief ("k=v k=v ...") for a TTY: dim
 * keys, sync/blocker values tinted. The byte stream is unchanged apart from
 * ANSI escapes; with ansi=false it is a plain copy. Returns bytes written,
 * 0 on overflow (caller prints the plain line). */
size_t zcl_cli_render_brief(const char *line,
                            const struct zcl_cli_render_env *env,
                            char *out, size_t cap);

/* The first-steps line printed under the bare `z23` status: the three verbs
 * a new agent needs. Writes it, newline-terminated, only when env->human;
 * returns bytes written, 0 for machine output or a buffer too small. */
size_t zcl_cli_render_start_hint(const struct zcl_cli_render_env *env,
                                 char *out, size_t cap);

#endif /* ZCL_CLI_RENDER_H */
