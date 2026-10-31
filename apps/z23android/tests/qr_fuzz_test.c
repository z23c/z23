/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
/* Fuzzes the path a camera frame takes in the wallet: quirc decodes the frame, then scan.c and
 * payment_code.c read the payload. decode_frame() below is a copy of camera.c's, which needs the NDK. */
#include "payment_code.h"
#include "qrcodegen.h"
#include "quirc.h"
#include "scan.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define SEED 0x5A23F0C0DEULL
#define DEFAULT_ITERATIONS 2000u
#define MAX_ITERATIONS 10000000ull
/* The camera's frame size (apps/z23android/camera.c WIDTH and HEIGHT). */
#define FRAME_W 1280
#define FRAME_H 960
/* A decode slower than this fails the run, so a slowdown in quirc cannot pass as a slow pass. */
#define DECODE_LIMIT_MS 2000L
#define RESULT_CAP 4096
#define VALUE_CAP 512
#define TEXT_CAP (2 * ZAPP_PAY_INPUT_MAX + 256)
#define QR_DATA_MAX 2000
#define ZS_LEN 78
#define T1_LEN 35
#define CORPUS_N 14
#define CONTROL_ZAT 150000000ULL
#define HEX64 "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

struct stats {
    size_t texts, frames, pristine, pristine_decoded, decoded, refused, paid;
};

static uint64_t rng_state = SEED;
static char zs_addr[ZS_LEN + 1], t1_addr[T1_LEN + 1];
static char corpus[CORPUS_N][TEXT_CAP];
static size_t corpus_len[CORPUS_N];
static uint8_t qr_work[qrcodegen_BUFFER_LEN_MAX];
static uint8_t qr_code[qrcodegen_BUFFER_LEN_MAX];
static uint8_t frame_pixels[FRAME_W * FRAME_H];

[[noreturn]] static void fail(const char *what)
{
    fprintf(stderr, "qr-fuzz FAIL: %s\n", what);
    exit(1);
}

static uint64_t next_random(void)
{
    uint64_t x = rng_state;
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    rng_state = x;
    return x * 0x2545F4914F6CDD1DULL;
}
static size_t below(size_t n) { return n ? (size_t)(next_random() % n) : 0; }
static unsigned char nonzero_byte(void) { return (unsigned char)(1 + below(255)); }

static size_t iterations_from_env(void)
{
    const char *text = getenv("QR_FUZZ_ITERATIONS");
    if (!text || !*text) return DEFAULT_ITERATIONS;
    char *end = NULL;
    unsigned long long v = strtoull(text, &end, 10);
    if (*end || v == 0 || v > MAX_ITERATIONS) fail("QR_FUZZ_ITERATIONS must be 1 to 10000000");
    return (size_t)v;
}

static void make_addresses(void)
{
    memcpy(zs_addr, "zs1", 3);
    memset(zs_addr + 3, 'q', ZS_LEN - 3);
    zs_addr[ZS_LEN] = 0;
    memcpy(t1_addr, "t1", 2);
    memset(t1_addr + 2, 'A', T1_LEN - 2);
    t1_addr[T1_LEN] = 0;
}

/* Valid shapes, near-misses and the refusals payment_code.c names, as the seed for mutation. */
static void make_corpus(void)
{
    snprintf(corpus[0], TEXT_CAP, "zclassic:%s?amount=1.5&label=Shop", zs_addr);
    snprintf(corpus[1], TEXT_CAP, "zclassic:%s?amount=0.00000001&message=Tea", zs_addr);
    snprintf(corpus[2], TEXT_CAP, "zclassic:%s?amount=21000000.00000001", zs_addr);
    snprintf(corpus[3], TEXT_CAP, "zclassic:%s?memo=aGVsbG8&req-x=1", zs_addr);
    snprintf(corpus[4], TEXT_CAP, "zclassic:%s?amount=1&amount.1=2", t1_addr);
    snprintf(corpus[5], TEXT_CAP, "zclassic:%s?amount=1.5&amount=2", zs_addr);
    snprintf(corpus[6], TEXT_CAP, "zclassic:%s?label=%%E2%%80%%AE", zs_addr);
    snprintf(corpus[7], TEXT_CAP, "%s", t1_addr);
    snprintf(corpus[8], TEXT_CAP, "%s", zs_addr);
    snprintf(corpus[9], TEXT_CAP, "zclassic:%s?amount=1e3", zs_addr);
    snprintf(corpus[10], TEXT_CAP, "zclassic:%s?memo=aGk&amount=0.5", t1_addr);
    snprintf(corpus[11], TEXT_CAP, "z23:pair:");
    snprintf(corpus[12], TEXT_CAP, "z23:author:%s", HEX64);
    snprintf(corpus[13], TEXT_CAP, "ZCLASSIC:%s?amount=2", zs_addr);
    for (size_t i = 0; i < CORPUS_N; ++i) corpus_len[i] = strlen(corpus[i]);
}

/* Changes a NUL-terminated text of n bytes in place, keeping it NUL-terminated and nonzero inside. */
static size_t mutate_text(char *text, size_t n, size_t cap)
{
    for (size_t ops = 1 + below(6); ops > 0; --ops) {
        switch (below(4)) {
        case 0:
            if (n) text[below(n)] = (char)nonzero_byte();
            break;
        case 1: {
            if (n + 2 > cap) break;
            size_t at = below(n + 1);
            memmove(text + at + 1, text + at, n - at + 1);
            text[at] = (char)nonzero_byte();
            ++n;
            break;
        }
        case 2:
            if (n) {
                size_t at = below(n);
                memmove(text + at, text + at + 1, n - at);
                --n;
            }
            break;
        default:
            n = below(n + 1);
            text[n] = 0;
            break;
        }
    }
    return n;
}

static size_t random_text(char *text)
{
    size_t p = 0;
    if (below(2)) {
        memcpy(text, "zclassic:", 9);
        p = 9;
    }
    /* One text in sixteen is long enough to hit the input-length refusal. */
    size_t body = below(16) == 0 ? below(TEXT_CAP - 1 - p) : below(300);
    for (size_t i = 0; i < body; ++i) text[p + i] = (char)nonzero_byte();
    text[p + body] = 0;
    return p + body;
}

static size_t corpus_text(char *text)
{
    size_t i = below(CORPUS_N);
    memcpy(text, corpus[i], corpus_len[i] + 1);
    if (below(4) == 0) return corpus_len[i];
    return mutate_text(text, corpus_len[i], TEXT_CAP);
}

static size_t make_text(char *text)
{
    return below(3) == 0 ? random_text(text) : corpus_text(text);
}

/* What classify promises about its kind and value, given what the parser says about the same text. */
static void check_value(enum zapp_scan_kind kind, const char *value, size_t cap, enum zapp_pay_refusal why)
{
    if ((unsigned)kind > ZAPP_SCAN_PAY_REFUSED) fail("classify returned an unknown kind");
    if (!memchr(value, 0, cap)) fail("classify value is not NUL-terminated within cap");
    if (kind == ZAPP_SCAN_PAY && why != ZAPP_PAY_OK) fail("classify accepted a payment the parser refuses");
    if (kind == ZAPP_SCAN_PAY_REFUSED && why == ZAPP_PAY_OK) fail("classify refused a payment the parser accepts");
    if ((kind == ZAPP_SCAN_PAY || kind == ZAPP_SCAN_UNREADABLE) && value[0])
        fail("a payment or secret-shaped payload returned a value");
}
/* What the parser promises about an accepted payment: its buffers and its address as written in the input. */
static void check_payment(const char *s, const struct zapp_payment *pay)
{
    if (!memchr(pay->address, 0, sizeof pay->address)) fail("parsed address is not NUL-terminated");
    if (!strstr(s, pay->address)) fail("parsed address is not in the input");
    if (!memchr(pay->label, 0, sizeof pay->label) || !memchr(pay->message, 0, sizeof pay->message))
        fail("parsed label or message is not NUL-terminated");
    if (pay->memo_len > ZAPP_PAY_MEMO_MAX) fail("parsed memo is longer than its buffer");
    if (pay->kind == ZAPP_PAY_PUBLIC && pay->memo_len) fail("a memo was accepted on a public address");
    if (pay->has_amount && pay->amount_zat > ZAPP_PAY_MAX_ZAT) fail("an accepted amount is above the cap");
}
/* Runs one text through classify and the parser, and checks what each promises about its output. */
static void check_text(const char *s, struct stats *st)
{
    char value[VALUE_CAP];
    size_t cap = 1 + below(VALUE_CAP);
    enum zapp_scan_kind kind = zapp_scan_classify(s, value, cap);
    struct zapp_payment pay;
    enum zapp_pay_refusal why = zapp_scan_payment(s, &pay);
    st->texts++;
    check_value(kind, value, cap, why);
    if (why == ZAPP_PAY_OK) check_payment(s, &pay);
    if (kind == ZAPP_SCAN_PAY) st->paid++;
    if (kind == ZAPP_SCAN_PAY_REFUSED) st->refused++;
}

/* Fills qr_code with the code for data, byte mode at the lowest correction level. */
static bool encode(const char *data, size_t n)
{
    if (n == 0 || n > QR_DATA_MAX) return false;
    memcpy(qr_work, data, n);
    return qrcodegen_encodeBinary(qr_work, n, qr_code, qrcodegen_Ecc_LOW, 1, 40, qrcodegen_Mask_AUTO, true);
}

/* Draws qr_code centred on a white camera frame, dark modules black, as large as the height allows. */
static void draw_code(void)
{
    int size = qrcodegen_getSize(qr_code);
    int scale = FRAME_H / (size + 8);
    int origin_x = (FRAME_W - size * scale) / 2;
    int origin_y = (FRAME_H - size * scale) / 2;
    memset(frame_pixels, 0xff, sizeof frame_pixels);
    for (int y = 0; y < size * scale; ++y)
        for (int x = 0; x < size * scale; ++x)
            if (qrcodegen_getModule(qr_code, x / scale, y / scale))
                frame_pixels[(origin_y + y) * FRAME_W + origin_x + x] = 0;
}

/* Salt-and-pepper noise, a random rectangle of noise, a band inverted, or nothing. */
static void mutate_frame(void)
{
    switch (below(4)) {
    case 0: {
        for (size_t k = 0, n = 1 + below(256); k < n; ++k) frame_pixels[below(FRAME_W * FRAME_H)] = (uint8_t)next_random();
        break;
    }
    case 1: {
        size_t x0 = below(FRAME_W), y0 = below(FRAME_H), w = 1 + below(96), h = 1 + below(96);
        for (size_t y = y0; y < FRAME_H && y < y0 + h; ++y)
            for (size_t x = x0; x < FRAME_W && x < x0 + w; ++x) frame_pixels[y * FRAME_W + x] = (uint8_t)next_random();
        break;
    }
    case 2: {
        size_t y0 = below(FRAME_H), band = 1 + below(32);
        for (size_t y = y0; y < FRAME_H && y < y0 + band; ++y)
            for (size_t x = 0; x < FRAME_W; ++x) frame_pixels[y * FRAME_W + x] = (uint8_t)(255 - frame_pixels[y * FRAME_W + x]);
        break;
    }
    default:
        break;
    }
}

/* Fixed case: three 7-px finder patterns with 1-px modules, 800 px apart. That grid is version 196, past
 * quirc_version_db, and used to index the table before the version range check (identify.c fitness_all). */
static void draw_finder(int x0, int y0)
{
    for (int dy = 0; dy < 7; ++dy)
        for (int dx = 0; dx < 7; ++dx) {
            bool dark = dx == 0 || dx == 6 || dy == 0 || dy == 6 || (dx >= 2 && dx <= 4 && dy >= 2 && dy <= 4);
            frame_pixels[(y0 + dy) * FRAME_W + x0 + dx] = dark ? 0 : 255;
        }
}
static void craft_version_db_frame(void)
{
    memset(frame_pixels, 0xff, sizeof frame_pixels);
    draw_finder(100, 100);
    draw_finder(900, 100);
    draw_finder(100, 900);
}

/* A copy of decode_frame() in camera.c: the first code that decodes to non-empty text without NUL bytes. */
static bool decode_frame(const struct quirc *qr, char *result, size_t cap)
{
    for (int i = 0; i < quirc_count(qr); ++i) {
        struct quirc_code code; struct quirc_data data;
        quirc_extract(qr, i, &code);
        if (!quirc_decode(&code, &data) && data.payload_len > 0 &&
            (size_t)data.payload_len < cap && !memchr(data.payload, 0, (size_t)data.payload_len)) {
            memcpy(result, data.payload, (size_t)data.payload_len);
            result[data.payload_len] = 0; return true;
        }
    }
    return false;
}

/* Milliseconds on the wall clock; timespec_get is the portable call under -std=c23. */
static long now_ms(void)
{
    struct timespec ts;
    if (timespec_get(&ts, TIME_UTC) != TIME_UTC) fail("timespec_get");
    return (long)ts.tv_sec * 1000L + ts.tv_nsec / 1000000L;
}

/* Feeds frame_pixels through quirc the way camera.c's frame() does, minus the AImage plane copy. A decode
 * that runs past DECODE_LIMIT_MS fails the run. */
static bool scan_frame(struct quirc *qr, char *result, size_t cap)
{
    int w, h;
    uint8_t *dst = quirc_begin(qr, &w, &h);
    if (!dst || w != FRAME_W || h != FRAME_H) fail("quirc_begin returned an unexpected buffer");
    memcpy(dst, frame_pixels, sizeof frame_pixels);
    long start = now_ms();
    quirc_end(qr);
    bool decoded = decode_frame(qr, result, cap);
    if (now_ms() - start > DECODE_LIMIT_MS) fail("a frame took longer than the decode limit");
    return decoded;
}

/* Positive control: an unmodified code must decode to its exact payload, or the run could pass by decoding nothing. */
static void positive_control(struct quirc *qr, struct stats *st)
{
    char control[TEXT_CAP], result[RESULT_CAP];
    snprintf(control, sizeof control, "zclassic:%s?amount=1.5&label=Shop", zs_addr);
    if (!encode(control, strlen(control))) fail("positive control did not encode");
    draw_code();
    if (!scan_frame(qr, result, sizeof result)) fail("positive control did not decode");
    if (strcmp(result, control)) fail("positive control decoded to other bytes");
    struct zapp_payment pay;
    if (zapp_scan_payment(result, &pay) != ZAPP_PAY_OK || !pay.has_amount || pay.amount_zat != CONTROL_ZAT)
        fail("positive control payload did not parse to its amount");
    check_text(result, st);
    /* stderr is unbuffered and flushed here, so an abort in the iterations cannot lose this line. */
    fprintf(stderr, "qr-fuzz positive control: decoded exact payload, %zu bytes, amount %llu zat\n",
            strlen(control), (unsigned long long)pay.amount_zat);
    fflush(stderr);
}

static void iteration(struct quirc *qr, struct stats *st)
{
    char text[TEXT_CAP], result[RESULT_CAP];
    size_t n = make_text(text);
    check_text(text, st);
    if (!encode(text, n)) return;
    st->frames++;
    draw_code();
    bool pristine = below(4) == 0;
    if (pristine) st->pristine++;
    else mutate_frame();
    if (!scan_frame(qr, result, sizeof result)) return;
    st->decoded++;
    if (pristine) {
        st->pristine_decoded++;
        if (strlen(result) != n || memcmp(result, text, n)) fail("a pristine frame decoded to other bytes");
    }
    check_text(result, st);
}

int main(void)
{
    size_t iterations = iterations_from_env();
    printf("qr-fuzz seed=0x%llx iterations=%zu\n", (unsigned long long)SEED, iterations);
    make_addresses();
    make_corpus();
    struct quirc *qr = quirc_new();
    if (!qr) fail("quirc_new");
    if (quirc_resize(qr, FRAME_W, FRAME_H) < 0) fail("quirc_resize");
    struct stats st = {0};
    positive_control(qr, &st);
    /* The fixed crafted frame runs every time, under the same decode time limit. It has no expected payload. */
    char crafted[RESULT_CAP];
    craft_version_db_frame();
    (void)scan_frame(qr, crafted, sizeof crafted);
    /* QR_FUZZ_TRACE names each iteration on stderr, so a sanitizer report can be traced to its iteration. */
    bool trace = getenv("QR_FUZZ_TRACE") != NULL;
    for (size_t i = 0; i < iterations; ++i) {
        if (trace) fprintf(stderr, "qr-fuzz iteration %zu\n", i);
        iteration(qr, &st);
    }
    quirc_destroy(qr);
    /* Every pristine code must decode to its bytes: a change that breaks version 10 and up shows here. */
    if (st.pristine_decoded != st.pristine) fail("a pristine frame failed to decode");
    printf("qr-fuzz texts=%zu frames=%zu pristine_decoded=%zu/%zu decoded=%zu paid=%zu refused=%zu\n",
           st.texts, st.frames, st.pristine_decoded, st.pristine, st.decoded, st.paid, st.refused);
    printf("qr-fuzz PASS iterations=%zu\n", iterations);
    return 0;
}
