/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * `z23 mcp serve`: the local stdio MCP adapter. */

#ifndef ZCL_TOOLS_MCP_SERVE_H
#define ZCL_TOOLS_MCP_SERVE_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Windows refusal for `z23 mcp serve`: a one-line JSON error that names the
 * reason and the working next step (run the same server over ssh on a Linux
 * host, registered with `claude mcp add`). */
#define ZCL_MCP_SERVE_WINDOWS_REFUSAL                                         \
    "{\"ok\":false,\"error\":{\"code\":\"MCP_SERVE_PLATFORM\","               \
    "\"message\":\"z23 mcp serve needs a POSIX host: the stdio MCP adapter "   \
    "is POSIX-only, so this Windows z23 cannot start it. Run the same server " \
    "on a Linux host over ssh instead: claude mcp add --scope user <name> -- " \
    "ssh <host> \\\"cd <checkout> && build/bin/z23 mcp serve "                \
    "--checkout=<checkout>\\\"\"}}\n"

/* argv is the full process argv; argv[1] is "mcp" and argv[2] "serve".
 * Reads newline-delimited JSON-RPC from stdin and writes replies to stdout
 * until EOF; logs go to stderr. Requires --checkout=<git toplevel>; optional
 * --datadir=<dir> and --rpcport=<n> aim node-backed leaves. Returns 0 on EOF,
 * 2 for a refused start (a typed JSON error is printed on stderr). */
int zcl_mcp_serve_main(int argc, char **argv);

/* Test instrumentation, logged only with ZCL_CLI_TEST_NO_SERVICE_LOOKUP=1. */
unsigned zcl_mcp_packet_cache_hits(void);

/* True when argv selects `mcp serve` (argv[1] == "mcp"). */
bool zcl_mcp_serve_selected(int argc, char **argv);

#ifdef __cplusplus
}
#endif

#endif
