/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Wallet view HTML emit helpers: navigation, QR SVG, headers, footers, and
 * shared page chrome. */

#include "platform/time_compat.h"
#include "controllers/wallet_view_internal.h"
/* CSS is now in contexts/wallet/views/css/wallet.ccss, compiled as CSS_WALLET */
#include "models/contact.h"
#include "models/shared_validators.h"
#include "models/wallet_tx.h"
#include "crypto/sha256.h"
#include "encoding/utilstrencodings.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"

/* HTML emit helpers for wallet view pages. */

/* ── Navigation ────────────────────────────────────────────── */

size_t wv_emit_nav(uint8_t *buf, size_t max, const char *active) {
    struct { const char *href; const char *label; } tabs[] = {
        { "/wallet",         "Home"    },
        { "/wallet/send",    "Send"    },
        { "/wallet/receive", "Receive" },
        { "/wallet/history", "History" },
        { "/wallet/node",    "Node"    },
    };
    int n = snprintf((char *)buf, max, "<nav class='nav' role='navigation'>");
    if (n < 0 || (size_t)n >= max) return 0;
    size_t off = (size_t)n;
    for (int i = 0; i < 5 && off < max; i++) {
        bool is_active = (strcmp(tabs[i].href, active) == 0);
        int w = snprintf((char *)buf + off, max - off,
            "<a href='%s'%s>%s</a>",
            tabs[i].href,
            is_active ? " class='active'" : "",
            tabs[i].label);
        if (w > 0 && (size_t)w < max - off) off += (size_t)w;
    }
    int w = snprintf((char *)buf + off, max - off, "</nav>");
    if (w > 0 && (size_t)w < max - off) off += (size_t)w;
    return off;
}

/* ── QR Code Generator (Byte Mode, Version 5-L) ───────────── */

#define QR_N 37

static uint8_t gf_exp_table[256];
static uint8_t gf_log_table[256];
static bool    gf_initialized = false;

static void gf_init(void) {
    if (gf_initialized) return;
    int v = 1;
    for (int i = 0; i < 255; i++) {
        gf_exp_table[i] = (uint8_t)v;
        gf_log_table[v] = (uint8_t)i;
        v <<= 1;
        if (v >= 256) v ^= 0x11d;
    }
    gf_exp_table[255] = gf_exp_table[0];
    gf_initialized = true;
}

static uint8_t gf_mul(uint8_t a, uint8_t b) {
    if (a == 0 || b == 0) return 0;
    return gf_exp_table[(gf_log_table[a] + gf_log_table[b]) % 255];
}

static void rs_encode(const uint8_t *data, int data_len,
                      uint8_t *ecc, int ecc_len) {
    gf_init();

    uint8_t gen[32];
    memset(gen, 0, sizeof(gen));
    gen[0] = 1;
    for (int i = 0; i < ecc_len; i++) {
        uint8_t alpha_i = gf_exp_table[i];
        for (int j = ecc_len; j >= 1; j--) {
            gen[j] = gen[j - 1] ^ gf_mul(gen[j], alpha_i);
        }
        gen[0] = gf_mul(gen[0], alpha_i);
    }

    uint8_t rem[32];
    memset(rem, 0, sizeof(rem));
    for (int i = 0; i < data_len; i++) {
        uint8_t lead = data[i] ^ rem[ecc_len - 1];
        for (int j = ecc_len - 1; j >= 1; j--)
            rem[j] = rem[j - 1] ^ gf_mul(lead, gen[j]);
        rem[0] = gf_mul(lead, gen[0]);
    }
    for (int i = 0; i < ecc_len; i++)
        ecc[i] = rem[ecc_len - 1 - i];
}

typedef struct {
    uint8_t bits[256];
    int     count;
} qr_bitbuf;

static void bb_append(qr_bitbuf *bb, uint32_t val, int nbits) {
    for (int i = nbits - 1; i >= 0 && bb->count < (int)sizeof(bb->bits) * 8; i--) {
        int byte_idx = bb->count / 8;
        int bit_idx  = 7 - (bb->count % 8);
        if ((val >> i) & 1)
            bb->bits[byte_idx] |= (uint8_t)(1 << bit_idx);
        bb->count++;
    }
}

#define QR_DATA_CW 108
#define QR_ECC_CW  26
#define QR_TOTAL_CW (QR_DATA_CW + QR_ECC_CW)

static int qr_encode_bytes(const char *str, uint8_t *codewords) {
    size_t len = strlen(str);
    if (len > 106)
        LOG_ERR("wallet_view", "qr_encode_bytes: input too long (%zu > 106)", len);

    qr_bitbuf bb;
    memset(&bb, 0, sizeof(bb));

    bb_append(&bb, 0x4, 4);
    bb_append(&bb, (uint32_t)len, 8);

    for (size_t i = 0; i < len; i++)
        bb_append(&bb, (uint32_t)(uint8_t)str[i], 8);

    int data_bits = QR_DATA_CW * 8;
    int pad_bits = data_bits - bb.count;
    if (pad_bits > 4) pad_bits = 4;
    if (pad_bits > 0) bb_append(&bb, 0, pad_bits);

    if (bb.count % 8 != 0)
        bb_append(&bb, 0, 8 - (bb.count % 8));

    int bytes_filled = bb.count / 8;
    bool toggle = false;
    while (bytes_filled < QR_DATA_CW) {
        bb_append(&bb, toggle ? 0x11 : 0xEC, 8);
        bytes_filled++;
        toggle = !toggle;
    }

    memcpy(codewords, bb.bits, QR_DATA_CW);
    return 0;
}

static void qr_place_finder(uint8_t m[QR_N][QR_N], int row, int col) {
    for (int dr = -1; dr <= 7; dr++) {
        for (int dc = -1; dc <= 7; dc++) {
            int r = row + dr, c = col + dc;
            if (r < 0 || r >= QR_N || c < 0 || c >= QR_N) continue;
            bool is_border = (dr == -1 || dr == 7 || dc == -1 || dc == 7);
            bool is_outer  = (dr == 0 || dr == 6 || dc == 0 || dc == 6);
            bool is_inner  = (dr >= 2 && dr <= 4 && dc >= 2 && dc <= 4);
            m[r][c] = (is_border) ? 0 : (is_outer || is_inner) ? 1 : 0;
        }
    }
}

static void qr_place_alignment(uint8_t m[QR_N][QR_N]) {
    int cr = 30, cc = 30;
    for (int dr = -2; dr <= 2; dr++) {
        for (int dc = -2; dc <= 2; dc++) {
            bool is_edge = (dr == -2 || dr == 2 || dc == -2 || dc == 2);
            bool is_center = (dr == 0 && dc == 0);
            m[cr + dr][cc + dc] = (is_edge || is_center) ? 1 : 0;
        }
    }
}

static void qr_place_timing(uint8_t m[QR_N][QR_N]) {
    for (int i = 8; i < QR_N - 8; i++) {
        m[6][i] = (i % 2 == 0) ? 1 : 0;
        m[i][6] = (i % 2 == 0) ? 1 : 0;
    }
}

static void qr_place_format(uint8_t m[QR_N][QR_N]) {
    uint16_t fmt = 0x77C4;
    static const int hpos_r[] = {8,8,8,8,8,8,8,8,8};
    static const int hpos_c[] = {0,1,2,3,4,5,7,8,24};
    for (int i = 0; i <= 5; i++)
        m[8][i] = (fmt >> (14 - i)) & 1;
    m[8][7] = (fmt >> 8) & 1;
    m[8][8] = (fmt >> 7) & 1;
    m[7][8] = (fmt >> 6) & 1;
    for (int i = 0; i <= 4; i++)
        m[5 - i][8] = (fmt >> (5 - i)) & 1;

    for (int i = 0; i < 7; i++)
        m[8][QR_N - 1 - i] = (fmt >> i) & 1;

    for (int i = 0; i < 7; i++)
        m[QR_N - 7 + i][8] = (fmt >> (6 - i)) & 1;

    m[QR_N - 8][8] = 1;

    (void)hpos_r; (void)hpos_c;
}

static bool qr_is_function(int r, int c) {
    if (r <= 8 && c <= 8) return true;
    if (r <= 8 && c >= QR_N - 8) return true;
    if (r >= QR_N - 8 && c <= 8) return true;
    if (r == 6 || c == 6) return true;
    if (r >= 28 && r <= 32 && c >= 28 && c <= 32) return true;
    return false;
}

static void qr_place_data(uint8_t m[QR_N][QR_N], const uint8_t *bits, int nbits) {
    int bit_idx = 0;
    for (int right = QR_N - 1; right >= 1; right -= 2) {
        if (right == 6) right = 5;
        bool upward = ((QR_N - 1 - right) / 2) % 2 == 0;
        for (int cnt = 0; cnt < QR_N; cnt++) {
            int row = upward ? (QR_N - 1 - cnt) : cnt;
            for (int dx = 0; dx <= 1; dx++) {
                int col = right - dx;
                if (col < 0) continue;
                if (qr_is_function(row, col)) continue;
                if (bit_idx < nbits) {
                    int byte_i = bit_idx / 8;
                    int bit_i  = 7 - (bit_idx % 8);
                    m[row][col] = (bits[byte_i] >> bit_i) & 1;
                }
                bit_idx++;
            }
        }
    }
}

static void qr_apply_mask(uint8_t m[QR_N][QR_N]) {
    for (int r = 0; r < QR_N; r++)
        for (int c = 0; c < QR_N; c++)
            if (!qr_is_function(r, c) && ((r + c) % 2 == 0))
                m[r][c] ^= 1;
}

size_t wv_emit_qr_svg(uint8_t *buf, size_t max, size_t off,
                       const char *data, int module_size) {
    if (!data || strlen(data) == 0 || strlen(data) > 106) return off;

    uint8_t data_cw[QR_DATA_CW];
    if (qr_encode_bytes(data, data_cw) != 0) return off;

    uint8_t ecc_cw[QR_ECC_CW];
    rs_encode(data_cw, QR_DATA_CW, ecc_cw, QR_ECC_CW);

    uint8_t all_cw[QR_TOTAL_CW];
    memcpy(all_cw, data_cw, QR_DATA_CW);
    memcpy(all_cw + QR_DATA_CW, ecc_cw, QR_ECC_CW);

    uint8_t m[QR_N][QR_N];
    memset(m, 0, sizeof(m));

    qr_place_finder(m, 0, 0);
    qr_place_finder(m, 0, QR_N - 7);
    qr_place_finder(m, QR_N - 7, 0);
    qr_place_alignment(m);
    qr_place_timing(m);
    qr_place_format(m);
    qr_place_data(m, all_cw, QR_TOTAL_CW * 8);
    qr_apply_mask(m);
    qr_place_format(m);

    int quiet = 4;
    int total = QR_N + quiet * 2;
    int px = total * module_size;

    APPEND(off, buf, max,
        "<div class='qr-wrap'>"
        "<svg xmlns='http://www.w3.org/2000/svg' width='%d' height='%d' "
        "viewBox='0 0 %d %d' style='margin:0 auto;display:block'>",
        px, px, total, total);

    APPEND(off, buf, max,
        "<rect width='%d' height='%d' fill='white'/>", total, total);

    for (int r = 0; r < QR_N; r++) {
        for (int c = 0; c < QR_N; c++) {
            if (m[r][c] && off + 80 < max) {
                APPEND(off, buf, max,
                    "<rect x='%d' y='%d' width='1' height='1' fill='black'/>",
                    c + quiet, r + quiet);
            }
        }
    }

    APPEND(off, buf, max, "</svg></div>");
    return off;
}

/* ── Page header / footer ──────────────────────────────────── */

size_t wv_emit_header(uint8_t *buf, size_t max, const char *title,
                      const char *active_tab) {
    size_t off = 0;
    APPEND(off, buf, max,
        "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n"
        "Connection: close\r\n\r\n"
        "<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<title>%s</title><style>%s</style></head><body>",
        title, CSS_WALLET);
    off += wv_emit_nav(buf + off, max - off, active_tab);
    APPEND(off, buf, max, "<main>");
    return off;
}

void wv_emit_footer(uint8_t *buf, size_t max, size_t *off) {
    APPEND(*off, buf, max, "</main>");
    APPEND(*off, buf, max,
        "<div id='sbar' class='status-bar'>"
        "<span style='color:#34d399;font-weight:700'>ZCL23</span>"
        "<span id='sb-h'>Block --</span>"
        "<span id='sb-p'>0 peers</span>"
        "<span id='sb-m'>0 tx</span>"
        "</div>"
        "<script>"
        "(function(){"
        "var u='zcl://node/api/wallet/pulse';"
        "function up(){"
        "fetch(u).then(function(r){return r.json()}).then(function(d){"
        "var h=document.getElementById('sb-h');"
        "var p=document.getElementById('sb-p');"
        "var m=document.getElementById('sb-m');"
        "if(h)h.textContent='Block '+d.height;"
        "if(p)p.textContent=d.peers+' peers';"
        "if(m)m.textContent=d.mempool+' tx';"
        "if(window._dashUpdate)window._dashUpdate(d);"
        "}).catch(function(){});}"
        "up();setInterval(up,5000);"
        "})();"
        "</script>"
        "</body></html>");
}
