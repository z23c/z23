/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Seam between the two translation units of the public front door.
 * https_server.c owns TLS, the listeners, the bounded worker pool and the
 * operator configuration; https_server_redirect.c owns the plain-HTTP port
 * (ACME http-01 passthrough plus the 301 to HTTPS). Nothing outside those
 * two files includes this header — the module's public surface stays
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

#endif /* ZCL_NET_HTTPS_SERVER_INTERNAL_H */
