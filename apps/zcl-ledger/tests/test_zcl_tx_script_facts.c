/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include "zcl_tx_script_facts.h"

#undef NDEBUG
#include <assert.h>
#include <string.h>

static size_t one_output(uint8_t wire[128], const uint8_t *script,
                         size_t script_length) {
    static const uint8_t header[] = {4, 0, 0, 0x80, 0x85, 0x20, 0x2f, 0x89};
    memset(wire, 0, 128);
    memcpy(wire, header, sizeof header);
    size_t length = sizeof header;
    wire[length++] = 0;
    wire[length++] = 1;
    length += 8;
    wire[length++] = (uint8_t)script_length;
    memcpy(wire + length, script, script_length);
    length += script_length;
    return length + 4 + 4 + 8 + 1 + 1 + 1;
}

static void test_zslp_pushes(void) {
    static const uint8_t headers[][5] = {
        {4}, {0x4c, 4}, {0x4d, 4, 0}, {0x4e, 4, 0, 0, 0}
    };
    static const size_t widths[] = {1, 2, 3, 5};
    for (size_t i = 0; i < 4; ++i) {
        uint8_t script[10] = {0x6a};
        memcpy(script + 1, headers[i], widths[i]);
        memcpy(script + 1 + widths[i], (const uint8_t[]){'S','L','P',0}, 4);
        uint8_t wire[128];
        size_t length = one_output(wire, script, 1 + widths[i] + 4);
        zcl_tx_script_facts facts;
        assert(zcl_tx_script_facts_parse(wire, length, &facts) == 0);
        assert(facts.zslp_marker && facts.op_return_outputs == 1);
        assert(facts.p2sh_outputs == 0);
        script[1 + widths[i]] = 'X';
        length = one_output(wire, script, 1 + widths[i] + 4);
        assert(zcl_tx_script_facts_parse(wire, length, &facts) == 0);
        assert(!facts.zslp_marker && facts.op_return_outputs == 1);
    }
}

static void test_p2sh_and_bounds(void) {
    uint8_t script[23] = {0xa9, 0x14};
    script[22] = 0x87;
    uint8_t wire[128];
    size_t length = one_output(wire, script, sizeof script);
    zcl_tx_script_facts facts;
    assert(zcl_tx_script_facts_parse(wire, length, &facts) == 0);
    assert(facts.p2sh_outputs == 1 && facts.op_return_outputs == 0);
    wire[19 + 22] = 0x88;
    assert(zcl_tx_script_facts_parse(wire, length, &facts) == 0);
    assert(facts.p2sh_outputs == 0);
    assert(zcl_tx_script_facts_parse(wire, length - 1, &facts) < 0);
    assert(zcl_tx_script_facts_parse(wire, length, NULL) < 0);
}

int main(void) {
    test_zslp_pushes();
    test_p2sh_and_bounds();
    return 0;
}
