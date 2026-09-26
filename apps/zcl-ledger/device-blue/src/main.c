/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include "os.h"
#include "os_io_seproxyhal.h"

#if !defined(__STDC_VERSION__) || __STDC_VERSION__ < 202311L
#error "The Ledger Blue app requires ISO C23"
#endif

unsigned char G_io_seproxyhal_spi_buffer[IO_SEPROXYHAL_BUFFER_SIZE_B];
ux_state_t ux;

static const bagl_element_t *exit_app(const bagl_element_t *element) {
    (void)element;
    os_sched_exit(0);
    return NULL;
}

static unsigned int probe_ui_button(unsigned int button_mask,
                                    unsigned int button_mask_counter) {
    (void)button_mask;
    (void)button_mask_counter;
    return 0;
}

static const bagl_element_t probe_ui[] = {
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
        .text = "ZCL Probe"
    },
    {
        .component = {
            .type = BAGL_LABEL, .x = 20, .y = 125, .width = 280,
            .height = 60, .fgcolor = 0x1d2028, .bgcolor = 0xf9f9f9,
            .font_id = BAGL_FONT_OPEN_SANS_LIGHT_16px |
                       BAGL_FONT_ALIGNMENT_CENTER
        },
        .text = "No keys or signing"
    },
    {
        .component = {
            .type = BAGL_BUTTON | BAGL_FLAG_TOUCHABLE,
            .x = 100, .y = 300, .width = 120, .height = 40,
            .radius = 6, .fill = BAGL_FILL,
            .fgcolor = 0x41ccb4, .bgcolor = 0xf9f9f9,
            .font_id = BAGL_FONT_OPEN_SANS_LIGHT_14px |
                       BAGL_FONT_ALIGNMENT_CENTER |
                       BAGL_FONT_ALIGNMENT_MIDDLE
        },
        .text = "EXIT",
        .overfgcolor = 0x37ae99,
        .overbgcolor = 0xf9f9f9,
        .tap = exit_app
    }
};

unsigned short io_exchange_al(unsigned char channel, unsigned short tx_len) {
    if ((channel & ~IO_FLAGS) != CHANNEL_SPI) THROW(INVALID_PARAMETER);
    if (tx_len != 0) {
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
    case SEPROXYHAL_TAG_DISPLAY_PROCESSED_EVENT:
        if (!UX_DISPLAYED()) UX_DISPLAYED_EVENT();
        break;
    case SEPROXYHAL_TAG_TICKER_EVENT:
        UX_REDISPLAY();
        break;
    default:
        break;
    }
    if (!io_seproxyhal_spi_is_status_sent()) io_seproxyhal_general_status();
    return 1;
}

static void answer_command(void) {
    volatile unsigned int rx = 0;
    volatile unsigned int tx = 0;
    for (;;) {
        volatile unsigned short sw = 0;
        BEGIN_TRY {
            TRY {
                rx = io_exchange(CHANNEL_APDU, tx);
                tx = 0;
                if (rx != 5 || G_io_apdu_buffer[4] != 0) THROW(0x6700);
                if (G_io_apdu_buffer[0] != 0xa5) THROW(0x6e00);
                if (G_io_apdu_buffer[1] != 0x01) THROW(0x6d00);
                if (G_io_apdu_buffer[2] != 0 || G_io_apdu_buffer[3] != 0)
                    THROW(0x6b00);
                G_io_apdu_buffer[0] = 'Z';
                G_io_apdu_buffer[1] = 'C';
                G_io_apdu_buffer[2] = 'L';
                G_io_apdu_buffer[3] = 1;
                G_io_apdu_buffer[4] = 0;
                tx = 5;
                THROW(0x9000);
            }
            CATCH_OTHER(error) {
                sw = (error & 0xf000) == 0x6000 ||
                     (error & 0xf000) == 0x9000
                         ? error : (0x6800 | (error & 0x07ff));
                G_io_apdu_buffer[tx++] = (unsigned char)(sw >> 8);
                G_io_apdu_buffer[tx++] = (unsigned char)sw;
            }
            FINALLY {}
        }
        END_TRY;
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
            UX_DISPLAY(probe_ui, NULL);
            answer_command();
        }
        CATCH_OTHER(error) {
            (void)error;
        }
        FINALLY {}
    }
    END_TRY;
    return 0;
}
