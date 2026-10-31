/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Seam between the translation units of the public front door.
 * https_server.c owns the listeners, the bounded worker pool and the
 * operator configuration; https_server_cert.c owns the TLS contexts and
 * certificate reload; https_server_redirect.c owns the plain-HTTP port
 * (ACME http-01 passthrough plus the 301 to HTTPS). Nothing outside these
 * files includes this header — the module's public surface stays
 * net/https_server.h. */

#ifndef ZCL_NET_HTTPS_SERVER_INTERNAL_H
#define ZCL_NET_HTTPS_SERVER_INTERNAL_H

#include "platform/socket_compat.h"
#include <stdint.h>

/* Bound the request-header count so an endless-header stream (a slowloris
 * variant) cannot pin a server thread reading lines forever. Legitimate
 * explorer/API clients send well under this. */
#define HTTP_MAX_REQUEST_HEADERS 512

/* The operator's -httpsdomain, or "" when unset. Owned by https_server.c
 * because the start path writes it before any listener thread exists; the
 * redirect reads it to build a Location without a hardcoded host. */
const char *https_server_configured_hostname(void);

/* Serve one accepted plain-HTTP connection and close it. Called from the
 * shared worker pool in https_server.c for queue entries with tls == false. */
void https_server_handle_http_client_fd(platform_socket_t fd,
                                        int64_t deadline_ms);

/* Serve one GET from <datadir>/public-install when that tree exists.
 * Returns true if the request was handled (file served or refused as too
 * large after matching a public-install URL). False means the caller should
 * keep the explorer redirect. */
struct ssl_st;
bool https_server_try_public_install(struct ssl_st *ssl, const char *url);
/* Operator-set front paths (https_server_set_front_paths): the Location for
 * a browser GET /, and for GET/HEAD /start (NULL when /start is not
 * special). */
#define HTTPS_FRONT_PATH_MAX 256
const char *https_front_root_target(void);
const char *https_front_start_target(const char *path);
const char *https_front_home_first(const char *path, bool script_client);
void https_write_redirect(struct ssl_st *ssl, const char *location);

/* The certificate half, https_server_cert.c. Build and acquire return a
 * counted reference the caller drops with SSL_CTX_free. Build makes a new
 * one and touches nothing global; acquire returns the one in service (NULL
 * when none); start_serving takes ownership of a built one, puts it in
 * service and records the watched pair, once per start before any listener
 * exists; retire_all frees every context at stop. */
struct ssl_ctx_st;
struct ssl_ctx_st *https_ssl_ctx_build(const char *cert_path,
                                       const char *key_path);
struct ssl_ctx_st *https_ssl_ctx_acquire(void);
void https_ssl_ctx_start_serving(struct ssl_ctx_st *ctx, const char *cert_path,
                                 const char *key_path);
void https_ssl_ctx_retire_all(void);

#endif /* ZCL_NET_HTTPS_SERVER_INTERNAL_H */
