/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "voice.h"
#include <string.h>

static bool space(unsigned char c)
{
    return c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\v' || c == '\f';
}
/* Lowercases ASCII text, collapses whitespace and drops trailing punctuation. */
static bool normalize(const char *text, char normalized[64])
{
    size_t used = 0; bool gap = false;
    for (; *text; ++text) {
        unsigned char c = (unsigned char)*text;
        if (space(c)) { gap = used != 0; continue; }
        if (c >= 128 || used + (gap ? 1u : 0u) + 1 >= 64) return false;
        if (gap) normalized[used++] = ' ';
        gap = false;
        normalized[used++] = (char)(c >= 'A' && c <= 'Z' ? c + ('a' - 'A') : c);
    }
    while (used && (normalized[used - 1] == '?' || normalized[used - 1] == '.' || normalized[used - 1] == '!')) --used;
    while (used && normalized[used - 1] == ' ') --used;
    normalized[used] = 0;
    return true;
}
enum zapp_voice_intent zapp_voice_interpret(const char *text)
{
    char normalized[64];
    if (!text || !normalize(text, normalized)) return ZAPP_VOICE_UNKNOWN;
    static const struct { const char *phrase; enum zapp_voice_intent intent; } phrases[] = {
        {"status", ZAPP_VOICE_STATUS}, {"node status", ZAPP_VOICE_STATUS},
        {"the node status", ZAPP_VOICE_STATUS}, {"note status", ZAPP_VOICE_STATUS},
        {"is my node synced", ZAPP_VOICE_STATUS}, {"check status", ZAPP_VOICE_STATUS},
        {"balance", ZAPP_VOICE_BALANCE}, {"what is my balance", ZAPP_VOICE_BALANCE},
        {"start node", ZAPP_VOICE_START}, {"start the node", ZAPP_VOICE_START},
        {"stop node", ZAPP_VOICE_STOP}, {"stop the node", ZAPP_VOICE_STOP}
    };
    for (size_t i = 0; i < sizeof(phrases) / sizeof(phrases[0]); ++i)
        if (!strcmp(normalized, phrases[i].phrase)) return phrases[i].intent;
    return ZAPP_VOICE_UNKNOWN;
}
static uint16_t read16(const unsigned char *p)
{
    return (uint16_t)((uint16_t)p[0] | (uint16_t)((uint16_t)p[1] << 8));
}
static uint32_t read32(const unsigned char *p)
{
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}
static void write16(unsigned char *p, uint16_t n)
{
    p[0] = (unsigned char)n; p[1] = (unsigned char)(n >> 8);
}
static void write32(unsigned char *p, uint32_t n)
{
    for (unsigned i = 0; i < 4; ++i) p[i] = (unsigned char)(n >> (8 * i));
}
bool zapp_voice_wav_encode(const int16_t *samples, size_t count,
    unsigned char *wav, size_t capacity, size_t *size)
{
    if (!size) return false;
    *size = 0;
    if (!samples || !wav || !count || count > ZAPP_VOICE_CAPTURE_SAMPLES || capacity < 44 + count * 2) return false;
    memcpy(wav, "RIFF", 4); write32(wav + 4, (uint32_t)(36 + count * 2));
    memcpy(wav + 8, "WAVEfmt ", 8); write32(wav + 16, 16);
    write16(wav + 20, 1); write16(wav + 22, 1); write32(wav + 24, ZAPP_VOICE_CAPTURE_RATE);
    write32(wav + 28, ZAPP_VOICE_CAPTURE_RATE * 2); write16(wav + 32, 2); write16(wav + 34, 16);
    memcpy(wav + 36, "data", 4); write32(wav + 40, (uint32_t)(count * 2));
    for (size_t i = 0; i < count; ++i) write16(wav + 44 + i * 2, (uint16_t)samples[i]);
    *size = 44 + count * 2; return true;
}
static bool format(const unsigned char *p, size_t size, uint32_t *rate)
{
    if (size != 16 || read16(p) != 1 || read16(p + 2) != 1 || read16(p + 12) != 2 || read16(p + 14) != 16) return false;
    *rate = read32(p + 4);
    return *rate >= 16000 && *rate <= 48000 && read32(p + 8) == *rate * 2;
}
struct wav_parts { const unsigned char *data; size_t bytes; uint32_t rate; };
static bool chunks(const unsigned char *wav, size_t size, struct wav_parts *parts)
{
    bool have_format = false;
    for (size_t at = 12; at < size;) {
        if (size - at < 8) return false;
        size_t bytes = read32(wav + at + 4), available = size - at - 8;
        if (bytes > available || (bytes & 1u) > available - bytes) return false;
        if (!memcmp(wav + at, "fmt ", 4)) {
            if (have_format || !format(wav + at + 8, bytes, &parts->rate)) return false;
            have_format = true;
        } else if (!memcmp(wav + at, "data", 4)) {
            if (!have_format || parts->data || !bytes || bytes % 2) return false;
            parts->data = wav + at + 8; parts->bytes = bytes;
        }
        at += 8 + bytes + (bytes & 1u);
    }
    return have_format && parts->data;
}
static bool riff_header(const unsigned char *wav, size_t size)
{
    return wav && size >= 44 && size <= ZAPP_VOICE_WAV_BYTES && !memcmp(wav, "RIFF", 4) &&
        !memcmp(wav + 8, "WAVE", 4) && read32(wav + 4) == size - 8;
}
bool zapp_voice_wav_decode(const unsigned char *wav, size_t size,
    int16_t *samples, size_t capacity, size_t *count, uint32_t *rate)
{
    if (count) *count = 0;
    if (rate) *rate = 0;
    if (!samples || !count || !rate || !riff_header(wav, size)) return false;
    struct wav_parts parts = {0};
    if (!chunks(wav, size, &parts)) return false;
    size_t n = parts.bytes / 2;
    if (n > capacity || n > parts.rate * ZAPP_VOICE_MAX_SECONDS) return false;
    for (size_t i = 0; i < n; ++i) {
        uint16_t bits = read16(parts.data + i * 2);
        int32_t value = bits <= INT16_MAX ? (int32_t)bits : (int32_t)bits - 65536;
        samples[i] = (int16_t)value;
    }
    *count = n; *rate = parts.rate; return true;
}
void zapp_endpoint_init(struct zapp_endpoint *e)
{
    *e = (struct zapp_endpoint){.floor = UINT32_MAX};
}
bool zapp_endpoint_update(struct zapp_endpoint *e, const int16_t *frame, size_t count)
{
    if (!e || !frame || !count) return false;
    uint64_t sum = 0;
    for (size_t i = 0; i < count; ++i) sum += (uint64_t)(frame[i] < 0 ? -(int32_t)frame[i] : frame[i]);
    uint32_t level = (uint32_t)(sum / count);
    e->frames++;
    if (level && level < e->floor) e->floor = level;
    if (level > e->peak) e->peak = level;
    uint64_t relative = e->floor == UINT32_MAX ? 0 : (uint64_t)e->floor * 4;
    uint64_t threshold = relative > 150 ? relative : 150;
    if (level >= threshold) { e->voiced++; e->quiet = 0; }
    else if (e->voiced >= 2) e->quiet++;
    else e->voiced = 0;
    if (e->voiced >= 2) e->speech = true;
    return e->speech && e->quiet >= 8;
}
/* Last sentence end within cap, else last clause end, else 0. */
static size_t phrase_end(const char *text, size_t cap)
{
    size_t end = 0, clause = 0;
    for (size_t i = 0; i < cap; ++i) {
        bool boundary = text[i + 1] == ' ' || text[i + 1] == 0;
        if (boundary && strchr(".!?", text[i])) end = i + 1;
        else if (boundary && strchr(",;:", text[i])) clause = i + 1;
    }
    return end ? end : clause;
}
size_t zapp_voice_chunk(const char *text, size_t cap)
{
    size_t n = text ? strlen(text) : 0;
    if (n <= cap) return n;
    size_t end = phrase_end(text, cap);
    if (end) return end;
    for (end = cap; end > 0 && text[end] != ' '; --end) {}
    if (!end) for (end = cap; end > 0 && ((unsigned char)text[end] & 0xc0) == 0x80; --end) {}
    return end ? end : cap;
}
