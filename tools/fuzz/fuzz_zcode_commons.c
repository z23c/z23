/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * fuzz_zcode_commons — libFuzzer harness for every canonical parser added by
 * the ZC23 Living Commons foundation. These bytes may arrive from the public
 * ZCODE CAS before their signatures, roots, or cross-object authorities are
 * trusted, so parsing must be total and bounded for every possible input.
 *
 * Byte 0 selects one of ten parsers. The remainder is passed at its exact
 * length. The epoch parser is the only arm that can allocate; it is freed on
 * every success or failure path. ASan+UBSan are supplied by FUZZ_CFLAGS.
 */

#include "vcs/zcode_continuity_policy.h"
#include "vcs/zcode_creation_attribution.h"
#include "vcs/zcode_epoch_creation.h"
#include "vcs/zcode_patronage.h"
#include "vcs/zcode_patronage_funding.h"
#include "vcs/zcode_patronage_settlement.h"
#include "vcs/zcode_shadow_policy.h"
#include "vcs/zcode_reproduction_request.h"
#include "vcs/zcode_seed.h"

#include "base/hex.h"

#include <signal.h>
#include <stddef.h>
#include <stdint.h>

volatile sig_atomic_t g_shutdown_requested = 0;

#define FUZZ_ZCODE_COMMONS_ARMS 10u
#define FUZZ_ZCODE_COMMONS_MAX_INPUT \
    (VCS_ZCODE_EPOCH_CREATION_MAX_WIRE_BYTES + 1u)

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

static bool fuzz_hex_wire_is_space(uint8_t byte)
{
    return byte == ' ' || byte == '\n' || byte == '\r' || byte == '\t';
}

static bool fuzz_hex_wire(const uint8_t *text, size_t text_len,
                          uint8_t *wire, size_t wire_cap, size_t *wire_len)
{
    size_t digits = 0;
    for (size_t i = 0; i < text_len; i++) {
        if (fuzz_hex_wire_is_space(text[i]))
            continue;
        if (zcl_hex_nibble((char)text[i], true) < 0) return false;
        digits++;
    }
    if (digits == 0 || (digits & 1u) != 0 || digits / 2u > wire_cap)
        return false;
    size_t out = 0;
    int high = -1;
    for (size_t i = 0; i < text_len; i++) {
        if (fuzz_hex_wire_is_space(text[i]))
            continue;
        int nibble = zcl_hex_nibble((char)text[i], true);
        if (high < 0) {
            high = nibble;
        } else {
            wire[out++] = (uint8_t)((high << 4) | nibble);
            high = -1;
        }
    }
    *wire_len = out;
    return true;
}

static uint8_t fuzz_select_parser_arm(uint8_t selector)
{
    return selector >= '0' && selector <= '9'
        ? (uint8_t)(selector - '0')
        : (uint8_t)(selector % FUZZ_ZCODE_COMMONS_ARMS);
}

struct fuzz_wire_view {
    const uint8_t *buf;
    size_t len;
};

static struct fuzz_wire_view fuzz_select_wire_or_hex(const uint8_t *wire,
                                                     size_t wire_len,
                                                     const uint8_t *decoded,
                                                     size_t decoded_len,
                                                     bool hex)
{
    if (hex)
        return (struct fuzz_wire_view){ decoded, decoded_len };
    return (struct fuzz_wire_view){ wire, wire_len };
}

static void fuzz_dispatch_parser_arm(uint8_t arm, const uint8_t *wire,
                                     size_t wire_len)
{
    switch (arm) {
    case 0: {
        struct vcs_zcode_creation_attribution_v1 out;
        (void)vcs_zcode_creation_attribution_parse(wire, wire_len, &out);
        break;
    }
    case 1: {
        struct vcs_zcode_epoch_creation_set_v1 out;
        vcs_zcode_epoch_creation_init(&out);
        (void)vcs_zcode_epoch_creation_parse(wire, wire_len, &out);
        vcs_zcode_epoch_creation_free(&out);
        break;
    }
    case 2: {
        struct vcs_zcode_patronage_intent_v1 out;
        (void)vcs_zcode_patronage_intent_parse(wire, wire_len, &out);
        break;
    }
    case 3: {
        struct vcs_zcode_patronage_funding_v1 out;
        (void)vcs_zcode_patronage_funding_parse(wire, wire_len, &out);
        break;
    }
    case 4: {
        struct vcs_zcode_patronage_settlement_v1 out;
        (void)vcs_zcode_patronage_settlement_parse(wire, wire_len, &out);
        break;
    }
    case 5: {
        struct vcs_zcode_continuity_policy_v1 out;
        (void)vcs_zcode_continuity_policy_parse(wire, wire_len, &out);
        break;
    }
    case 6: {
        struct vcs_zcode_approved_reproducer_set_v1 out;
        uint8_t decoded[VCS_ZCODE_APPROVED_REPRODUCER_SET_MAX_WIRE_BYTES];
        size_t decoded_len = 0;
        bool hex = fuzz_hex_wire(wire, wire_len, decoded, sizeof(decoded),
                                 &decoded_len);
        struct fuzz_wire_view view =
            fuzz_select_wire_or_hex(wire, wire_len, decoded, decoded_len,
                                    hex);
        (void)vcs_zcode_approved_reproducer_set_parse(view.buf, view.len,
                                                      &out);
        break;
    }
    case 7: {
        struct vcs_zcode_policy_candidate_v1 out;
        uint8_t decoded[VCS_ZCODE_POLICY_CANDIDATE_WIRE_BYTES];
        size_t decoded_len = 0;
        bool hex = fuzz_hex_wire(wire, wire_len, decoded, sizeof(decoded),
                                 &decoded_len);
        struct fuzz_wire_view view =
            fuzz_select_wire_or_hex(wire, wire_len, decoded, decoded_len,
                                    hex);
        (void)vcs_zcode_policy_candidate_parse(view.buf, view.len, &out);
        break;
    }
    case 8: {
        struct vcs_zcode_reproduction_request_v1 out;
        uint8_t decoded[VCS_ZCODE_REPRODUCTION_REQUEST_WIRE_BYTES];
        size_t decoded_len = 0;
        bool hex = fuzz_hex_wire(wire, wire_len, decoded, sizeof(decoded),
                                 &decoded_len);
        struct fuzz_wire_view view =
            fuzz_select_wire_or_hex(wire, wire_len, decoded, decoded_len,
                                    hex);
        (void)vcs_zcode_reproduction_request_parse(view.buf, view.len, &out);
        break;
    }
    case 9: {
        struct vcs_c23_seed_v1 out;
        uint8_t decoded[VCS_C23_SEED_WIRE_BYTES];
        size_t decoded_len = 0;
        bool hex = fuzz_hex_wire(wire, wire_len, decoded, sizeof(decoded),
                                 &decoded_len);
        struct fuzz_wire_view view =
            fuzz_select_wire_or_hex(wire, wire_len, decoded, decoded_len,
                                    hex);
        (void)vcs_c23_seed_parse(view.buf, view.len, &out);
        break;
    }
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size == 0 || size > FUZZ_ZCODE_COMMONS_MAX_INPUT)
        return 0;

    const uint8_t arm = fuzz_select_parser_arm(data[0]);
    const uint8_t *wire = data + 1;
    const size_t wire_len = size - 1;

    fuzz_dispatch_parser_arm(arm, wire, wire_len);
    return 0;
}
