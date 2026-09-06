/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * /install.sh — the source-build installer view. See
 * contexts/commons/views/src/install_sh_view.c for the handler and
 * platform/packaging/install/install_from_source.sh for the served script
 * itself (embedded at build time via
 * contexts/commons/views/include/views/install_script_gen.h). */

#ifndef ZCL_VIEWS_INSTALL_SH_H
#define ZCL_VIEWS_INSTALL_SH_H

#include <stddef.h>
#include <stdint.h>

/* Handle /install.sh — GET returns the full script body, HEAD returns
 * headers only, anything else is refused with 405 (the HTTPS listener
 * already 405s non-GET/HEAD before dispatch; this is the onion listener's
 * own defense, since its PLAIN dispatch forwards every method). Writes a
 * complete raw HTTP/1.1 response into `response` and returns the byte
 * count, or 0 on missing args or an internal sizing failure. */
size_t install_sh_handle_request(const char *method, const char *path,
                                 const uint8_t *body, size_t body_len,
                                 uint8_t *response, size_t response_max);

#endif /* ZCL_VIEWS_INSTALL_SH_H */
