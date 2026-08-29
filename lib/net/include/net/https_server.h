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

/* ── Certificate reload, without a restart ────────────────────────────
 *
 * A Let's Encrypt certificate lasts ninety days and the certificate worker
 * (`zclassic23-acme`) renews it in place by rename(). Before this seam
 * existed the front door read its certificate exactly once, at start, so a
 * renewed certificate was not served until somebody restarted the node —
 * every ninety days, by hand, which is the manual step the whole effort
 * exists to remove.
 *
 * WHAT THE SERVER WATCHES, AND WHY IT IS THE FILE. The trigger is the
 * identity (device, inode, size, mtime) of the certificate pair itself, not
 * a stamp file or a signal. That is the artifact whose change actually
 * matters; it needs no cooperation from whoever wrote it, so it catches the
 * worker's renewal AND an operator hand-replacing a certificate; and it
 * cannot go stale the way a separate notification can. The certificate
 * worker writes the key first and the chain second, both by rename(), so a
 * change to the chain means the matching key is already in place.
 *
 * WHEN IT IS CHECKED. Lazily, on the worker thread, immediately before a TLS
 * context is taken for an accepted connection — the same laziness the
 * TLS-ALPN-01 handoff read uses. A stale certificate harms nobody until
 * someone connects, and the connection that would have seen it triggers the
 * refresh first, so no client is ever served a certificate that was already
 * superseded on disk. The cost is one stat() per connection unless something
 * actually changed. */

/* Name the pair the front door should PREFER and adopt without a restart as
 * soon as it is loadable. Call it with the CA-issued paths even when the
 * server was started on a self-signed placeholder: that is how the first
 * real certificate replaces the placeholder with no restart. Calling this
 * before https_server_start_on_port() is fine and is the intended order; the
 * start path only defaults the watch to the pair it was handed when no watch
 * has been set. */
void https_server_watch_certificate(const char *cert_path, const char *key_path);

/* ── More than one name on one listener ───────────────────────────────
 *
 * Name an ADDITIONAL host this listener answers for, and the certificate
 * pair to present when a client asks for that name in TLS SNI. Everything
 * above stays the default and the fallback: a client that sends no SNI, one
 * that sends a name nobody registered here, and a server with no additional
 * names at all are all served the pair from https_server_watch_certificate()
 * — the handshake always completes, it is never refused over a name.
 *
 * The pair is WATCHED, not merely loaded: it is adopted with no restart the
 * moment it appears or is renewed, on the same trigger and with the same
 * refusals as the default pair, and independently of it. A name whose
 * certificate has not been issued yet costs the other names nothing.
 *
 * Call it before or after the listener starts; calling it again for a name
 * already registered re-points that name at a new pair, and the name keeps
 * serving whatever it had until the new pair loads. `name` must be a plain
 * LDH domain name. Returns false, having changed nothing, when the name is
 * not one, when either path is missing, or when the table is full. */
bool https_server_watch_certificate_for_name(const char *name,
                                             const char *cert_path,
                                             const char *key_path);

/* Look at the watched pair now and swap if it changed. Returns true only
 * when a new pair was actually installed. A pair that does not load, or
 * whose key does not match its certificate, is REFUSED and the running
 * context is left exactly as it was — serving a stale certificate is
 * recoverable, serving a mismatched one is not. A refused pair is not
 * retried until the files change again, so a broken certificate cannot turn
 * into a log flood. */
bool https_server_certificate_refresh(void);

/* Rebuild and swap unconditionally, ignoring what was last seen on disk.
 * Same refusals as above. */
bool https_server_reload_certificate(void);

/* True when the certificate currently being served names itself as its own
 * issuer — i.e. nobody vouched for it. Reported from the certificate the TLS
 * context actually holds, so it is true for the boot placeholder AND for any
 * self-signed certificate an operator dropped in, and it cannot be set or
 * cleared by mistake. */
bool https_server_certificate_is_self_signed(void);

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
#include "platform/socket_compat.h"
bool https_server_acme_challenge_filepath_for_testing(const char *root,
                                                      const char *path,
                                                      char *out,
                                                      size_t out_len);
void https_server_handle_http_for_testing(platform_socket_t fd,
                                          int64_t deadline_ms);
#endif

#endif
