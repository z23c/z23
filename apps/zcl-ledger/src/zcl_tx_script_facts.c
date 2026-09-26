/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include "zcl_tx_script_facts.h"
#include "zcl_tx_review.h"

#include <string.h>

typedef struct {
    const uint8_t *wire;
    size_t length;
    size_t offset;
} cursor;

static bool take(cursor *input, uint64_t count, const uint8_t **bytes) {
    if (count > input->length - input->offset) return false;
    *bytes = input->wire + input->offset;
    input->offset += (size_t)count;
    return true;
}

static bool compact_size(cursor *input, uint64_t *value) {
    const uint8_t *bytes;
    if (!take(input, 1, &bytes)) return false;
    if (*bytes < 0xfd) { *value = *bytes; return true; }
    unsigned width = *bytes == 0xfd ? 2 : *bytes == 0xfe ? 4 : 8;
    if (!take(input, width, &bytes)) return false;
    *value = 0;
    for (unsigned i = 0; i < width; ++i)
        *value |= (uint64_t)bytes[i] << (8 * i);
    return true;
}

static bool script(cursor *input, const uint8_t **bytes, size_t *length) {
    uint64_t count;
    if (!compact_size(input, &count) || !take(input, count, bytes))
        return false;
    *length = (size_t)count;
    return true;
}

static bool skip_inputs(cursor *input) {
    uint64_t count;
    const uint8_t *bytes;
    size_t length;
    if (!compact_size(input, &count) || count > 65536) return false;
    for (uint64_t i = 0; i < count; ++i)
        if (!take(input, 36, &bytes) || !script(input, &bytes, &length) ||
            !take(input, 4, &bytes)) return false;
    return true;
}

static bool zslp_marker(const uint8_t *script_bytes, size_t length) {
    static const uint8_t marker[] = {'S', 'L', 'P', 0};
    static const uint8_t headers[][5] = {
        {4}, {0x4c, 4}, {0x4d, 4, 0}, {0x4e, 4, 0, 0, 0}
    };
    static const size_t widths[] = {1, 2, 3, 5};
    if (!length || script_bytes[0] != 0x6a) return false;
    for (size_t i = 0; i < sizeof widths / sizeof widths[0]; ++i) {
        size_t prefix = 1 + widths[i];
        if (length >= prefix + sizeof marker &&
            memcmp(script_bytes + 1, headers[i], widths[i]) == 0 &&
            memcmp(script_bytes + prefix, marker, sizeof marker) == 0)
            return true;
    }
    return false;
}

static void record_output(zcl_tx_script_facts *facts, uint64_t index,
                          const uint8_t *bytes, size_t length) {
    if (length == 23 && bytes[0] == 0xa9 && bytes[1] == 0x14 &&
        bytes[22] == 0x87) ++facts->p2sh_outputs;
    if (!length || bytes[0] != 0x6a) return;
    ++facts->op_return_outputs;
    if (index == 0) facts->zslp_marker = zslp_marker(bytes, length);
}

static bool read_outputs(cursor *input, zcl_tx_script_facts *facts) {
    uint64_t count;
    const uint8_t *bytes;
    size_t length;
    if (!compact_size(input, &count) || count > 65536) return false;
    for (uint64_t i = 0; i < count; ++i) {
        if (!take(input, 8, &bytes) || !script(input, &bytes, &length))
            return false;
        record_output(facts, i, bytes, length);
    }
    return true;
}

int zcl_tx_script_facts_parse(const uint8_t *wire, size_t length,
                              zcl_tx_script_facts *facts) {
    if (!facts || zcl_tx_review_parse(wire, length, &(zcl_tx_review){0}) < 0)
        return -1;
    cursor input = {.wire = wire, .length = length, .offset = 8};
    zcl_tx_script_facts parsed = {0};
    if (!skip_inputs(&input) || !read_outputs(&input, &parsed)) return -1;
    *facts = parsed;
    return 0;
}
