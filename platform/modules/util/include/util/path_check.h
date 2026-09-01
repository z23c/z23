/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#ifndef ZCL_UTIL_PATH_CHECK_H
#define ZCL_UTIL_PATH_CHECK_H

#include <stdbool.h>
#include <stddef.h>

/* Defensive input checks for user-supplied path-like strings reaching
 * native / RPC handlers. Auth gates which callers can invoke these
 * handlers; these checks are belt-and-suspenders against malformed
 * input (control chars, oversized strings, NULs slipping through a
 * stray JSON decoder bug).
 *
 * Neither helper attempts to filter `..` segments or absolute paths.
 * Many node features expose operator-chosen filesystem locations on
 * purpose (e.g., `zmarket_offer` announces a file for sale); blocking
 * those would break the feature. Filter only what is never legitimate
 * for a path-shaped argument. */

/* Filesystem-path argument: non-NULL, 1..max_len bytes, no control
 * characters (0x00-0x1F or 0x7F). Returns true if acceptable. */
bool path_check_fs_arg(const char *p, size_t max_len);

/* URL-path argument (e.g., onion probe target): same as fs_arg plus
 * must start with '/' and reject ".." segments that would escape the
 * intended endpoint surface. */
bool path_check_url_arg(const char *p, size_t max_len);

/* Build the canonical node.db path under datadir. Returns buf, or "" for
 * invalid args. */
const char *zcl_node_db_path(char *buf, size_t bufmax, const char *datadir);

#endif
