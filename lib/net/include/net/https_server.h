/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Public HTTPS server for the block explorer.
 * Serves on 0.0.0.0:443 (TLS) + 0.0.0.0:80 (redirect).
 * No authentication — public read-only explorer. */

#ifndef ZCL_NET_HTTPS_SERVER_H
#define ZCL_NET_HTTPS_SERVER_H

#include <stdbool.h>

bool https_server_start(const char *cert_path, const char *key_path,
                         const char *hostname);
bool https_server_start_on_port(const char *cert_path, const char *key_path,
                                const char *hostname, int https_port, int http_port);
void https_server_stop(void);

void https_deferred_set(const char *cert, const char *key, const char *hostname);
void https_deferred_check(void);

/* Diagnostics accessors (reentrant-safe atomic loads). Used by the
 * `explorer` state dumper so an operator can see in one call whether the
 * clearnet HTTPS explorer is actually serving. */
bool https_server_is_running(void);   /* true once the listener bound + workers up */
int  https_server_port(void);         /* bound HTTPS port, or 0 if not running */
bool https_deferred_pending(void);    /* HTTPS start deferred during IBD, not yet up */

#ifdef ZCL_TESTING
#include <stddef.h>
#include <stdint.h>
bool https_server_acme_challenge_filepath_for_testing(const char *root,
                                                      const char *path,
                                                      char *out,
                                                      size_t out_len);
void https_server_handle_http_for_testing(int fd, int64_t deadline_ms);
#endif

#endif
