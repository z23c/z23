/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The /observation.json onion mount.
 *
 * Serve path cost: one memcpy out of the sampler's leaf-locked record, then
 * JSON serialization straight into the caller's response buffer. No chain
 * access, no lock beyond that leaf, and no allocation in the request path —
 * the record is sampled on a tick into fixed structs and only SERIALIZED
 * when someone asks. An onion mount is reachable by anyone who knows the
 * address, so the work per request has to be bounded by construction rather
 * than by a rate limit alone.
 */

#include "controllers/observation_site_controller.h"

#include "services/mesh_observation.h"
#include "json/json.h"

#include <stdio.h>
#include <string.h>

size_t observation_site_handle_request(const char *method, const char *path,
                                       const uint8_t *body, size_t body_len,
                                       uint8_t *response, size_t response_max)
{
    (void)body;
    (void)body_len;
    if (!method || !path || !response || response_max < 1024)
        return 0;

    bool head_only = strcmp(method, "HEAD") == 0;
    if (strcmp(method, "GET") != 0 && !head_only) {
        static const char denied[] = "{\"error\":\"method_not_allowed\"}\n";
        return (size_t)snprintf((char *)response, response_max,
            "HTTP/1.1 405 Method Not Allowed\r\n"
            "Content-Type: application/json\r\n"
            "Content-Length: %zu\r\n"
            "Cache-Control: no-store\r\n"
            "Connection: close\r\n\r\n%s",
            sizeof(denied) - 1, denied);
    }

    struct mesh_observation rec;
    /* No sample yet is a REFUSAL to answer, not an empty document. The
     * route's FAILCLOSED contract turns this 0 into a named 503. */
    if (!mesh_observation_snapshot(&rec))
        return 0;

    struct json_value doc = {0};
    json_init(&doc);
    if (!mesh_observation_emit_json(&rec, &doc)) {
        json_free(&doc);
        return 0;
    }

    size_t need = json_write(&doc, NULL, 0);   /* sizing probe */
    char header[192];
    int hdr = snprintf(header, sizeof(header),
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %zu\r\n"
        "Cache-Control: no-store\r\n"
        "Connection: close\r\n\r\n", need);
    if (hdr <= 0 || (size_t)hdr >= sizeof(header)) {
        json_free(&doc);
        return 0;
    }
    if (head_only) {
        json_free(&doc);
        if ((size_t)hdr >= response_max)
            return 0;
        memcpy(response, header, (size_t)hdr);
        return (size_t)hdr;
    }
    /* +1 for the serializer's NUL, which is written but not counted. */
    if ((size_t)hdr + need + 1 > response_max) {
        json_free(&doc);
        return 0;
    }
    memcpy(response, header, (size_t)hdr);
    size_t wrote = json_write(&doc, (char *)response + hdr,
                              response_max - (size_t)hdr);
    json_free(&doc);
    if (wrote != need)
        return 0;
    return (size_t)hdr + wrote;
}
