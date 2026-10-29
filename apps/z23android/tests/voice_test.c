/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "voice.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void put32(unsigned char *p, uint32_t n)
{
    for (unsigned i = 0; i < 4; ++i) p[i] = (unsigned char)(n >> (8 * i));
}
static void intents(void)
{
    assert(zapp_voice_interpret(" \tWhAt IS my BALANCE?!\n") == ZAPP_VOICE_BALANCE);
    assert(zapp_voice_interpret("status") == ZAPP_VOICE_STATUS);
    assert(zapp_voice_interpret("THE NODE STATUS") == ZAPP_VOICE_STATUS);
    assert(zapp_voice_interpret("NOTE STATUS") == ZAPP_VOICE_STATUS);
    assert(zapp_voice_interpret("note status stop node") == ZAPP_VOICE_UNKNOWN);
    assert(zapp_voice_interpret("node\n status.") == ZAPP_VOICE_STATUS);
    assert(zapp_voice_interpret("is my node synced?") == ZAPP_VOICE_STATUS);
    assert(zapp_voice_interpret("check status!") == ZAPP_VOICE_STATUS);
    assert(zapp_voice_interpret("status ?") == ZAPP_VOICE_STATUS);
    assert(zapp_voice_interpret("balance") == ZAPP_VOICE_BALANCE);
    assert(zapp_voice_interpret("start node") == ZAPP_VOICE_START);
    assert(zapp_voice_interpret("start the node") == ZAPP_VOICE_START);
    assert(zapp_voice_interpret("stop node") == ZAPP_VOICE_STOP);
    assert(zapp_voice_interpret("stop the node") == ZAPP_VOICE_STOP);
    const char *unknown[] = {NULL, "", " \t", "?", "status then stop node", "start node and send money",
        "spend balance", "do not stop node", "balance; stop node", "status? stop node", "st\xc3\xa1tus"};
    for (size_t i = 0; i < sizeof(unknown) / sizeof(unknown[0]); ++i)
        assert(zapp_voice_interpret(unknown[i]) == ZAPP_VOICE_UNKNOWN);
    char long_text[100]; memset(long_text, 'a', sizeof(long_text) - 1); long_text[99] = 0;
    assert(zapp_voice_interpret(long_text) == ZAPP_VOICE_UNKNOWN);
}
static void invalid(const unsigned char *wav, size_t size)
{
    int16_t out[8]; size_t count = 99; uint32_t rate = 99;
    assert(!zapp_voice_wav_decode(wav, size, out, 8, &count, &rate));
    assert(count == 0 && rate == 0);
}
static void codec(void)
{
    int16_t input[] = {INT16_MIN, -1, 0, 1, INT16_MAX}, output[5];
    unsigned char wav[80], copy[80]; size_t size, count; uint32_t rate;
    assert(zapp_voice_wav_encode(input, 5, wav, sizeof(wav), &size) && size == 54);
    assert(wav[44] == 0 && wav[45] == 128 && wav[46] == 255 && wav[47] == 255);
    assert(zapp_voice_wav_decode(wav, size, output, 5, &count, &rate));
    assert(count == 5 && rate == 16000 && !memcmp(input, output, sizeof(input)));
    for (size_t i = 0; i < size; ++i) invalid(wav, i);
    memcpy(copy, wav, size); copy[0] = 'X'; invalid(copy, size);
    memcpy(copy, wav, size); copy[22] = 2; invalid(copy, size);
    memcpy(copy, wav, size); copy[34] = 8; invalid(copy, size);
    memcpy(copy, wav, size); copy[28] ^= 1; invalid(copy, size);
    memcpy(copy, wav, size); put32(copy + 40, UINT32_MAX); invalid(copy, size);
    memcpy(copy, wav, size); put32(copy + 40, 9); invalid(copy, size);
    memcpy(copy, wav, size); memcpy(copy + 36, "JUNK", 4); invalid(copy, size);
    memcpy(copy, wav, size); memcpy(copy + 12, "data", 4); invalid(copy, size);
    memcpy(copy, wav, size); memcpy(copy + 36, "fmt ", 4); invalid(copy, size);
    assert(!zapp_voice_wav_decode(wav, size, output, 4, &count, &rate));
    assert(!zapp_voice_wav_encode(input, 0, copy, sizeof(copy), &count) && count == 0);
    assert(!zapp_voice_wav_encode(input, 5, copy, 53, &count) && count == 0);
    /* An odd ancillary chunk needs its alignment byte, even at end of file. */
    memcpy(copy, wav, size); memcpy(copy + size, "JUNK", 4); put32(copy + size + 4, 1);
    copy[size + 8] = 7; copy[size + 9] = 0; put32(copy + 4, (uint32_t)(size + 2));
    assert(zapp_voice_wav_decode(copy, size + 10, output, 5, &count, &rate));
    put32(copy + 4, (uint32_t)(size + 1)); invalid(copy, size + 9);
    memcpy(copy, wav, size); memcpy(copy + size, "data", 4); put32(copy + size + 4, 2);
    put32(copy + 4, (uint32_t)(size + 2)); invalid(copy, size + 10);
    memcpy(copy, wav, size); put32(copy + 24, 48000); put32(copy + 28, 96000);
    assert(zapp_voice_wav_decode(copy, size, output, 5, &count, &rate) && rate == 48000);
    put32(copy + 24, 48001); put32(copy + 28, 96002); invalid(copy, size);
}
static void limits(void)
{
    size_t n = ZAPP_VOICE_CAPTURE_SAMPLES, bytes = 44 + n * 2, count = 0; uint32_t rate;
    int16_t *samples = calloc(ZAPP_VOICE_PLAYBACK_SAMPLES + 1, sizeof(*samples));
    unsigned char *wav = calloc(44 + (ZAPP_VOICE_PLAYBACK_SAMPLES + 1) * 2, 1);
    assert(samples && wav);
    assert(zapp_voice_wav_encode(samples, n, wav, bytes, &count) && count == bytes);
    assert(zapp_voice_wav_decode(wav, bytes, samples, n, &count, &rate) && count == n);
    assert(!zapp_voice_wav_encode(samples, n + 1, wav, bytes + 2, &count));
    put32(wav + 4, (uint32_t)(bytes - 8 + 2)); put32(wav + 40, (uint32_t)(n * 2 + 2));
    assert(!zapp_voice_wav_decode(wav, bytes + 2, samples, n + 1, &count, &rate));
    n = ZAPP_VOICE_PLAYBACK_SAMPLES; bytes = 44 + n * 2;
    put32(wav + 24, 48000); put32(wav + 28, 96000);
    put32(wav + 4, (uint32_t)(bytes - 8)); put32(wav + 40, (uint32_t)(n * 2));
    assert(zapp_voice_wav_decode(wav, bytes, samples, n, &count, &rate) && count == n);
    put32(wav + 4, (uint32_t)(bytes - 6)); put32(wav + 40, (uint32_t)(n * 2 + 2));
    assert(!zapp_voice_wav_decode(wav, bytes + 2, samples, n + 1, &count, &rate));
    free(wav); free(samples);
}
static bool feed(struct zapp_endpoint *e, int16_t amplitude, unsigned frames)
{
    static int16_t frame[ZAPP_VOICE_FRAME];
    bool ended = false;
    for (size_t i = 0; i < ZAPP_VOICE_FRAME; ++i) frame[i] = (int16_t)(i % 2 ? amplitude : -amplitude);
    for (unsigned f = 0; f < frames; ++f) ended = zapp_endpoint_update(e, frame, ZAPP_VOICE_FRAME);
    return ended;
}
static void endpoint_speech(void)
{
    struct zapp_endpoint e; zapp_endpoint_init(&e);
    assert(!feed(&e, 60, 5) && !feed(&e, 3000, 1) && !feed(&e, 60, 20) && !e.speech);
    assert(!feed(&e, 3000, 6) && e.speech && !feed(&e, 60, 7) && !feed(&e, 3000, 1));
    assert(!feed(&e, 60, 7) && feed(&e, 60, 1));
}
static void endpoint_floor(void)
{
    struct zapp_endpoint e; zapp_endpoint_init(&e);
    assert(!feed(&e, 0, 3) && e.floor == UINT32_MAX && !feed(&e, 10, 5) && e.floor == 10);
    assert(!feed(&e, 149, 4) && !e.speech && !feed(&e, 150, 2) && e.speech);
    assert(e.peak == 150 && e.frames == 14);
    assert(!zapp_endpoint_update(&e, NULL, 1) && !zapp_endpoint_update(&e, (int16_t[1]){0}, 0));
}
static void endpoint(void)
{
    endpoint_speech();
    endpoint_floor();
}
static void chunks(void)
{
    assert(zapp_voice_chunk(NULL, 10) == 0 && zapp_voice_chunk("", 10) == 0);
    assert(zapp_voice_chunk("Short answer.", 80) == 13);
    const char *two = "First sentence here. Second one is longer than the cap allows.";
    assert(zapp_voice_chunk(two, 30) == 20);
    assert(zapp_voice_chunk("no stops in this long run of words", 12) == 11);
    assert(zapp_voice_chunk("one, two three four five", 12) == 4);
    assert(zapp_voice_chunk("A b. c, d e f g", 9) == 4);
    assert(zapp_voice_chunk("v1.2 is the release number here", 10) == 7);
    assert(zapp_voice_chunk("\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9", 5) == 4);
}
int main(void)
{
    intents(); codec(); limits(); endpoint(); chunks(); puts("voice tests passed"); return 0;
}
