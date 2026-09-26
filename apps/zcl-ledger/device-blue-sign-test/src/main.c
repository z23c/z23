/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include "os.h"
#include "os_io_seproxyhal.h"
#include "zcl_sign_test.h"

#include <string.h>

#if !defined(__STDC_VERSION__) || __STDC_VERSION__ < 202311L
#error "The Ledger Blue app requires ISO C23"
#endif

unsigned char G_io_seproxyhal_spi_buffer[IO_SEPROXYHAL_BUFFER_SIZE_B];
ux_state_t ux;

typedef struct {
    uint8_t raw[32];
    uint8_t chain[32];
    cx_ecfp_private_key_t private_key;
} key_material;

static key_material secret;
static bool armed;

static void wipe(void *memory, size_t length) {
    volatile uint8_t *bytes = memory;
    for (size_t i = 0; i < length; ++i) bytes[i] = 0;
}

static const bagl_element_t *arm_test(const bagl_element_t *element) {
    (void)element;
    armed = true;
    return NULL;
}

static const bagl_element_t *exit_app(const bagl_element_t *element) {
    (void)element;
    armed = false;
    wipe(&secret, sizeof secret);
    os_sched_exit(0);
    return NULL;
}

static unsigned int app_ui_button(unsigned int mask, unsigned int count) {
    (void)mask;
    (void)count;
    return 0;
}

static const bagl_element_t app_ui[] = {
    {
        .component = {
            .type = BAGL_RECTANGLE, .x = 0, .y = 60, .width = 320,
            .height = 420, .fill = BAGL_FILL,
            .fgcolor = 0xf9f9f9, .bgcolor = 0xf9f9f9
        }
    },
    {
        .component = {
            .type = BAGL_RECTANGLE, .x = 0, .y = 0, .width = 320,
            .height = 60, .fill = BAGL_FILL,
            .fgcolor = 0x1d2028, .bgcolor = 0x1d2028
        }
    },
    {
        .component = {
            .type = BAGL_LABEL, .x = 20, .y = 0, .width = 280,
            .height = 60, .fill = BAGL_FILL, .fgcolor = 0xffffff,
            .bgcolor = 0x1d2028,
            .font_id = BAGL_FONT_OPEN_SANS_LIGHT_14px |
                       BAGL_FONT_ALIGNMENT_MIDDLE
        },
        .text = "ZCL Sign Test"
    },
    {
        .component = {
            .type = BAGL_LABEL, .x = 20, .y = 115, .width = 280,
            .height = 55, .fgcolor = 0x1d2028, .bgcolor = 0xf9f9f9,
            .font_id = BAGL_FONT_OPEN_SANS_LIGHT_16px |
                       BAGL_FONT_ALIGNMENT_CENTER
        },
        .text = "FIXED SELF-TEST ONLY"
    },
    {
        .component = {
            .type = BAGL_LABEL, .x = 20, .y = 185, .width = 280,
            .height = 50, .fgcolor = 0x1d2028, .bgcolor = 0xf9f9f9,
            .font_id = BAGL_FONT_OPEN_SANS_LIGHT_14px |
                       BAGL_FONT_ALIGNMENT_CENTER
        },
        .text = ZCL_SIGN_TEST_PATH
    },
    {
        .component = {
            .type = BAGL_BUTTON | BAGL_FLAG_TOUCHABLE,
            .x = 20, .y = 310, .width = 130, .height = 40,
            .radius = 6, .fill = BAGL_FILL,
            .fgcolor = 0x41ccb4, .bgcolor = 0xf9f9f9,
            .font_id = BAGL_FONT_OPEN_SANS_LIGHT_14px |
                       BAGL_FONT_ALIGNMENT_CENTER |
                       BAGL_FONT_ALIGNMENT_MIDDLE
        },
        .text = "SIGN TEST", .tap = arm_test
    },
    {
        .component = {
            .type = BAGL_BUTTON | BAGL_FLAG_TOUCHABLE,
            .x = 170, .y = 310, .width = 130, .height = 40,
            .radius = 6, .fill = BAGL_FILL,
            .fgcolor = 0x41ccb4, .bgcolor = 0xf9f9f9,
            .font_id = BAGL_FONT_OPEN_SANS_LIGHT_14px |
                       BAGL_FONT_ALIGNMENT_CENTER |
                       BAGL_FONT_ALIGNMENT_MIDDLE
        },
        .text = "EXIT", .tap = exit_app
    }
};

unsigned short io_exchange_al(unsigned char channel, unsigned short tx_len) {
    if ((channel & ~IO_FLAGS) != CHANNEL_SPI) THROW(INVALID_PARAMETER);
    if (tx_len) {
        io_seproxyhal_spi_send(G_io_apdu_buffer, tx_len);
        return 0;
    }
    return io_seproxyhal_spi_recv(G_io_apdu_buffer,
                                 sizeof G_io_apdu_buffer, 0);
}

void io_seproxyhal_display(const bagl_element_t *element) {
    io_seproxyhal_display_default((bagl_element_t *)element);
}

unsigned char io_event(unsigned char channel) {
    (void)channel;
    switch (G_io_seproxyhal_spi_buffer[0]) {
    case SEPROXYHAL_TAG_FINGER_EVENT:
        UX_FINGER_EVENT(G_io_seproxyhal_spi_buffer);
        break;
    case SEPROXYHAL_TAG_BUTTON_PUSH_EVENT:
        UX_BUTTON_PUSH_EVENT(G_io_seproxyhal_spi_buffer);
        break;
    case SEPROXYHAL_TAG_DISPLAY_PROCESSED_EVENT:
        if (!UX_DISPLAYED()) UX_DISPLAYED_EVENT();
        break;
    case SEPROXYHAL_TAG_TICKER_EVENT:
        UX_TICKER_EVENT(G_io_seproxyhal_spi_buffer, (void)0;);
        break;
    default:
        break;
    }
    if (!io_seproxyhal_spi_is_status_sent()) io_seproxyhal_general_status();
    return 1;
}

static uint16_t sign_challenge(unsigned int *length) {
    static const unsigned int path[] = {
        0x8000002c, 0x80000093, 0x80000000, 0, 0
    };
    static const char message[] = ZCL_SIGN_TEST_MESSAGE;
    uint8_t digest[32];
    cx_ecfp_public_key_t public_key;
    if (cx_hash_sha256((const uint8_t *)message, sizeof message - 1,
                       digest) != 32) return 0x6a80;
    os_perso_derive_node_bip32(CX_CURVE_256K1, path, 5,
                                secret.raw, secret.chain);
    cx_ecfp_init_private_key(CX_CURVE_256K1, secret.raw, 32,
                              &secret.private_key);
    wipe(secret.raw, sizeof secret.raw);
    wipe(secret.chain, sizeof secret.chain);
    if (cx_ecfp_generate_pair(CX_CURVE_256K1, &public_key,
                               &secret.private_key, 1) != 0 ||
        public_key.W_len != 65 || public_key.W[0] != 4) return 0x6a80;
    G_io_apdu_buffer[0] = (uint8_t)(2u | (public_key.W[64] & 1u));
    memcpy(G_io_apdu_buffer + 1, public_key.W + 1, 32);
    unsigned int info = 0;
    int signature_length = (cx_ecdsa_sign)(&secret.private_key,
        CX_RND_RFC6979, CX_SHA256, digest, sizeof digest,
        G_io_apdu_buffer + 34, ZCL_SIGN_TEST_MAX_DER, &info);
    if (signature_length < 8 || signature_length > ZCL_SIGN_TEST_MAX_DER)
        return 0x6a80;
    G_io_apdu_buffer[33] = (uint8_t)signature_length;
    *length = 34u + (unsigned int)signature_length;
    return 0x9000;
}

static uint16_t handle_command(unsigned int received, unsigned int *sent) {
    if (received != 5 || G_io_apdu_buffer[4] != 0) return 0x6700;
    if (G_io_apdu_buffer[0] != 0xa5) return 0x6e00;
    if (G_io_apdu_buffer[2] || G_io_apdu_buffer[3]) return 0x6b00;
    if (G_io_apdu_buffer[1] == 0x01) {
        memcpy(G_io_apdu_buffer, (const uint8_t[]){'Z', 'C', 'L', 7, 2}, 5);
        *sent = 5;
        return 0x9000;
    }
    if (G_io_apdu_buffer[1] != 0x20) return 0x6d00;
    if (!armed) return 0x6985;
    armed = false;
    return sign_challenge(sent);
}

static void answer_command(void) {
    volatile unsigned int received = 0;
    volatile unsigned int sent = 0;
    for (;;) {
        volatile uint16_t status = 0x6f00;
        BEGIN_TRY {
            TRY {
                received = io_exchange(CHANNEL_APDU, sent);
                sent = 0;
                unsigned int reply_length = 0;
                status = handle_command(received, &reply_length);
                sent = reply_length;
            }
            CATCH_OTHER(error) {
                status = (error & 0xf000) == 0x6000 ||
                         (error & 0xf000) == 0x9000
                             ? error : (0x6800 | (error & 0x07ff));
                sent = 0;
            }
            FINALLY { wipe(&secret, sizeof secret); }
        }
        END_TRY;
        G_io_apdu_buffer[sent++] = (uint8_t)(status >> 8);
        G_io_apdu_buffer[sent++] = (uint8_t)status;
    }
}

__attribute__((section(".boot"))) int main(void) {
    __asm volatile("cpsie i");
    os_boot();
    UX_INIT();
    BEGIN_TRY {
        TRY {
            io_seproxyhal_init();
            USB_power(0);
            USB_power(1);
            UX_DISPLAY(app_ui, NULL);
            answer_command();
        }
        CATCH_OTHER(error) { (void)error; }
        FINALLY { wipe(&secret, sizeof secret); }
    }
    END_TRY;
    return 0;
}
