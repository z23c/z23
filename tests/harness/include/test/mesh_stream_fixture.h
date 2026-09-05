/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Wire-frame builders for the mesh stream primitive's test groups: the
 * exact ZSTRM bytes a peer puts on zpkgswm, composed by hand so a test
 * drives the production decoder rather than the production encoder.
 * Every builder returns the frame length, or 0 when it does not fit.
 * Test-only: nothing in production includes this header.
 */

#ifndef ZCL_TEST_MESH_STREAM_FIXTURE_H
#define ZCL_TEST_MESH_STREAM_FIXTURE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

size_t mesh_stream_test_open_frame(uint64_t stream_id, uint32_t window,
                                   const char *service_name,
                                   const uint8_t *payload, size_t payload_len,
                                   uint8_t *out, size_t out_cap);
size_t mesh_stream_test_data_frame(uint64_t stream_id, const uint8_t *payload,
                                   size_t payload_len, uint8_t *out,
                                   size_t out_cap);
size_t mesh_stream_test_window_frame(uint64_t stream_id, uint32_t credit,
                                     uint8_t *out, size_t out_cap);
size_t mesh_stream_test_close_frame(uint64_t stream_id, uint8_t reason,
                                    const uint8_t *payload, size_t payload_len,
                                    uint8_t *out, size_t out_cap);

/* Read one ZSTRM frame's kind and stream id; false when the bytes are not
 * a ZSTRM frame at all. */
bool mesh_stream_test_read_header(const uint8_t *frame, size_t frame_len,
                                  uint8_t *kind_out, uint64_t *id_out);

#endif /* ZCL_TEST_MESH_STREAM_FIXTURE_H */
