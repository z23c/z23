/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Tor integration for zclassic23.
 *
 * Architecture: Tor is compiled into zclassic23 as a thread (no external
 * binary). Our forked Tor (RhettCreighton/tor, dynhost branch) routes
 * .onion requests directly into our process via C function calls.
 *
 * Dynhost replaces SOCKS for zclassic23 traffic. Requests arrive as C
 * callbacks, not through a SOCKS proxy or app-owned TCP listener.
 *
 * Current Tor bootstrap workaround: torrc opens a localhost-only SocksPort
 * that nothing in zclassic23 connects to. It exists only because the embedded
 * Tor fork currently refuses to bootstrap with no listener. Once dynhost can
 * satisfy that bootstrap check directly, torrc should move to SocksPort 0.
 *
 * Usage:
 *   tor_integration_set_handler(my_handler, my_ctx);
 *   tor_integration_start(datadir, p2p_port);
 *   // .onion address printed to log
 *   tor_integration_stop(); */

#ifndef ZCL_NET_TOR_INTEGRATION_H
#define ZCL_NET_TOR_INTEGRATION_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

/* Request handler callback — dynhost calls this directly.
 * method: HTTP method (GET, POST, etc.)
 * path: URL path (e.g., "/", "/store/product/1")
 * request_data: raw request body (NULL for GET)
 * request_len: body length
 * response: output buffer (caller allocates)
 * response_max: max response size
 * Returns bytes written to response, or 0 for 404. */
typedef size_t (*tor_request_handler_fn)(const char *method,
                                          const char *path,
                                          const uint8_t *request_data,
                                          size_t request_len,
                                          uint8_t *response,
                                          size_t response_max,
                                          void *ctx);

/* Set the request handler before starting Tor. */
void tor_integration_set_handler(tor_request_handler_fn handler, void *ctx);

/* Start embedded Tor with dynhost. Creates .onion address.
 * zclassic23 traffic is handled via C callbacks; see tor_write_torrc() for
 * the temporary localhost-only Tor bootstrap listener. */
bool tor_integration_start(const char *datadir, uint16_t p2p_port);

/* Stop Tor. */
void tor_integration_stop(void);

/* Get .onion address (NULL if not ready). */
const char *tor_integration_get_onion_address(void);

/* Check if the local onion descriptor is published and inbound-reachable. */
bool tor_integration_is_ready(void);

/* Check if dynhost may queue outbound streams. This becomes true as soon as
 * this boot's onion service registration yields an address, intentionally
 * before descriptor publication, so peer circuits pre-warm while HSDir upload
 * completes. It never weakens tor_integration_is_ready() or systemd READY. */
bool tor_integration_is_dial_ready(void);

/* Check if Tor was started (may still be bootstrapping). */
bool tor_integration_is_enabled(void);

/* Snapshot of the onion service's live virtual-port contract. This is the
 * authoritative C23 view of what embedded Tor was asked to expose and what
 * completed registration. Callers must not infer that an arbitrary loopback
 * P2P connection used Tor; combine this with accepted-listener evidence and
 * keep the result labelled as a candidate unless Tor supplied stream ID. */
enum tor_onion_port_map_state {
    TOR_ONION_PORT_MAP_DISABLED = 0,
    TOR_ONION_PORT_MAP_PENDING,
    TOR_ONION_PORT_MAP_INSTALLED,
    TOR_ONION_PORT_MAP_FAILED
};

struct tor_onion_port_map {
    enum tor_onion_port_map_state state;
    bool complete;
    bool persistent_identity;
    int expected_route_count;
    int installed_route_count;
    uint16_t application_virtual_port;
    bool application_route_installed;
    uint16_t p2p_virtual_port;
    uint16_t p2p_target_port;
    bool p2p_route_expected;
    bool p2p_route_installed;
};

void tor_integration_port_map_snapshot(struct tor_onion_port_map *out);
const char *tor_onion_port_map_state_name(
    enum tor_onion_port_map_state state);

/* Write torrc to datadir. We do NOT use SOCKS — dynhost handles
 * everything. A localhost-only SocksPort is opened as a bootstrap
 * workaround (Tor refuses to start without a listener). The port is
 * derived from p2p_port so multiple instances don't collide.
 * Exposed for testing — normally called by tor_integration_start(). */
bool tor_write_torrc(const char *datadir, uint16_t p2p_port);

/* Scan the dynhost log from byte offset scan_from and copy the LAST
 * "ephemeral service created with address:" match into out. dynhost mints
 * a fresh ephemeral service every Tor start and tor.log appends across
 * boots, so callers pass the log size captured at Tor start as scan_from —
 * earlier lines name dead services. Returns false if no match at/after the
 * offset. Exposed for testing — normally driven by read_onion_address(). */
bool tor_log_last_ephemeral_address(const char *log_path, long scan_from,
                                    char *out, size_t out_size);

/* True when THIS boot's tor.log (from scan_from) records a successful
 * onion DESCRIPTOR PUBLICATION / HSDir upload. Hostname-file presence is
 * not enough: a Type=notify first-boot that declares READY on the
 * hostname lets clients dial before HSDirs have the descriptor
 * (docs/work/ONION_DIAL_GAP.md). Exposed for testing — driven by
 * read_onion_address() before g_tor_ready flips. */
bool tor_log_has_descriptor_publication(const char *log_path,
                                        long scan_from);

/* ── Persistent onion identity (-onion-persist / -onion-rotate) ──
 *
 * Default stays ephemeral: dynhost mints a throwaway service every boot.
 * With -onion-persist the node instead keeps a seed-backed identity under
 * <datadir>/tor_data/onion_service/ (identity_seed, mode 0600, plus the
 * standard Tor hostname file) and installs it as the dynhost service, so
 * the .onion address is stable across boots. -onion-rotate (requires
 * -onion-persist) archives the current identity into
 * <datadir>/tor_data/onion_service/archive/ and mints a fresh one on the
 * same boot, logging the old and new addresses. Rotation is deliberate —
 * it never happens without the flag. */

/* Configure identity behavior before tor_integration_start(). rotate
 * without persist is named and ignored. Normally called once by the boot
 * service from app_context; exposed for testing. */
void tor_integration_configure_identity(bool persist, bool rotate);

/* True when -onion-persist is in effect for the next/current boot.
 * Exposed for testing. */
bool tor_integration_persistence_enabled(void);

/* Derive the v3 (prop224) .onion address for a 32-byte ed25519 seed,
 * without any Tor dependency: base32lower(pubkey || checksum || 0x03)
 * where checksum = SHA3-256(".onion checksum" || pubkey || 0x03)[0..1].
 * out receives exactly 56 chars + NUL (out_size must be >= 57); the
 * ".onion" suffix is NOT appended. Exposed for testing. */
bool onion_identity_address_from_seed(const uint8_t seed[32],
                                      char *out, size_t out_size);

/* Load-or-create the persistent identity under
 * <datadir>/tor_data/onion_service/: reads identity_seed when present
 * (a short/corrupt seed is a named refusal, never a silent remint),
 * otherwise mints one from the CSPRNG (mode 0600), then (re)writes the
 * standard hostname file. seed_out receives the 32-byte seed; addr_out
 * (may be NULL) receives the 56-char address without suffix; created_out
 * (may be NULL) is set true when a fresh seed was minted. Pure file/crypto
 * layer — no Tor required. Exposed for testing. */
bool onion_identity_ensure(const char *datadir, uint8_t seed_out[32],
                           char *addr_out, size_t addr_out_size,
                           bool *created_out);

/* Archive the current identity (identity_seed + hostname move to
 * <datadir>/tor_data/onion_service/archive/ (files suffixed with the old
 * address) so the next
 * onion_identity_ensure() mints a fresh one. old_addr_out receives the
 * archived identity's 56-char address without suffix. Returns false (with
 * a named log line) when no persistent identity exists. Exposed for
 * testing. */
bool onion_identity_rotate(const char *datadir, char *old_addr_out,
                           size_t old_addr_size);

/* ── Outbound .onion fetch API ─────────────────────────────── */

/* Callback for onion fetch results. Invoked from Tor's thread —
 * the caller must use atomic flags or mutexes for thread safety. */
typedef void (*tor_fetch_callback_fn)(int status,
                                       const uint8_t *body,
                                       size_t body_len,
                                       void *ctx);

/* Fetch a URL from a .onion address via embedded Tor circuits.
 * No SOCKS — uses dynhost's internal circuit management.
 * Thread-safe: queues the request for Tor's event loop.
 * Returns 0 if queued, -1 if Tor not initialized. */
int tor_integration_fetch_onion(const char *onion_address,
                                 const char *path,
                                 tor_fetch_callback_fn callback,
                                 void *ctx,
                                 int timeout_secs);

/* Thread-safe result structure for blocking callers. */
struct onion_fetch_result {
    _Atomic int complete;   /* 0=pending, 1=done, -1=error */
    int status;
    uint8_t *body;          /* caller must free() */
    size_t body_len;
};

/* Helper: blocking fetch with timeout. Allocates and copies body.
 * Returns 0 on success, -1 on error/timeout. */
int tor_integration_fetch_onion_blocking(const char *onion_address,
                                          const char *path,
                                          struct onion_fetch_result *result,
                                          int timeout_secs);

#endif
