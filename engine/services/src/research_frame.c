/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Accept one research-network frame and refuse a foreign network. */

#include "services/research_frame.h"

#include "base/serialize_le.h"
#include "core/hash.h"
#include "net/protocol.h"

#include <string.h>

static int frame_bounds(const uint8_t *frame, size_t frame_len,
                        uint32_t *payload_len)
{
    uint32_t n;
    if (frame_len < (size_t)MSG_HEADER_SIZE)
        return -3;
    n = zcl_read_u32_le(frame + 16);
    if (n > (uint32_t)MAX_SIZE)
        return -4;
    if (frame_len != (size_t)MSG_HEADER_SIZE + (size_t)n)
        return -4;
    *payload_len = n;
    return 0;
}

static int frame_header(const uint8_t *frame, uint32_t payload_len,
                        const uint8_t message_start[4], struct msg_header *hdr)
{
    memcpy(hdr->pchMessageStart, frame, MESSAGE_START_SIZE);
    memcpy(hdr->pchCommand, frame + MESSAGE_START_SIZE, COMMAND_SIZE);
    hdr->nMessageSize = payload_len;
    hdr->nChecksum = 0;
    if (memcmp(frame, message_start, MESSAGE_START_SIZE) != 0)
        return -5;
    if (!msg_header_is_valid(hdr, message_start))
        return -7;
    return 0;
}

static int frame_checksum(const uint8_t *frame, uint32_t payload_len)
{
    unsigned char dig[SHA256_OUTPUT_SIZE];
    const uint8_t *payload = frame + MSG_HEADER_SIZE;
    const uint8_t *sum = frame + MESSAGE_START_SIZE + COMMAND_SIZE + 4;
    static const uint8_t empty = 0;
    hash256(payload_len ? payload : &empty, payload_len, dig);
    if (memcmp(dig, sum, MESSAGE_START_SIZE) != 0)
        return -6;
    return 0;
}

struct zcl_result research_frame_accept(const uint8_t *frame, size_t frame_len,
                                        const uint8_t message_start[4],
                                        char *command, size_t command_len)
{
    struct msg_header hdr;
    uint32_t payload_len = 0;
    int rc;
    if (!frame || !message_start || !command)
        return ZCL_ERR(-1, "Missing frame");
    if (command_len < (size_t)COMMAND_SIZE + 1)
        return ZCL_ERR(-2, "Frame command refused");
    rc = frame_bounds(frame, frame_len, &payload_len);
    if (rc)
        return ZCL_ERR(rc, "Frame length refused");
    rc = frame_header(frame, payload_len, message_start, &hdr);
    if (rc == -5)
        return ZCL_ERR(-5, "Foreign network frame refused");
    if (rc)
        return ZCL_ERR(rc, "Frame header refused");
    if (frame_checksum(frame, payload_len))
        return ZCL_ERR(-6, "Frame checksum refused");
    msg_header_get_command(&hdr, command, command_len);
    return ZCL_OK;
}
