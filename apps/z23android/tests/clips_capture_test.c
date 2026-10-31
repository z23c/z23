/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "clip_capture.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static void time_cap(void)
{
    assert(!zapp_clip_time_up(0) && !zapp_clip_time_up(59999));
    assert(zapp_clip_time_up(60000) && zapp_clip_time_up(61000));
}

static void thermal_gate(void)
{
    for (int status = 0; status <= 3; ++status) {
        enum zapp_pace pace = ZAPP_PACE_NORMAL;
        assert(zapp_clip_thermal_track(&pace, status));
    }
    for (int status = 4; status <= 6; ++status) {
        enum zapp_pace pace = ZAPP_PACE_NORMAL;
        assert(!zapp_clip_thermal_track(&pace, status) && pace == ZAPP_PACE_PAUSE);
    }
    assert(!zapp_clip_thermal_stops(0) && !zapp_clip_thermal_stops(3));
    assert(zapp_clip_thermal_stops(4) && zapp_clip_thermal_stops(6));
}

/* Status 4, then 3: the node stays paused, so recording stays refused until the status falls below 3. */
static void thermal_latch(void)
{
    enum zapp_pace pace = ZAPP_PACE_NORMAL;
    assert(zapp_clip_thermal_track(&pace, 3) && pace == ZAPP_PACE_GENTLE);
    assert(!zapp_clip_thermal_track(&pace, 4));
    assert(!zapp_clip_thermal_track(&pace, 3) && pace == ZAPP_PACE_PAUSE);
    assert(!zapp_clip_thermal_track(&pace, 3));
    assert(zapp_clip_thermal_track(&pace, 2) && pace == ZAPP_PACE_GENTLE);
    assert(zapp_clip_thermal_track(&pace, 3) && !zapp_clip_thermal_track(&pace, 5));
    assert(!zapp_clip_thermal_track(&pace, 3) && zapp_clip_thermal_track(&pace, 0));
}

/* A pace that is not known starts at pause: status 3 does not reopen recording, status 2 does. */
static void thermal_unknown(void)
{
    enum zapp_pace pace = ZAPP_CLIP_PACE_UNKNOWN;
    assert(!zapp_clip_thermal_track(&pace, 3) && !zapp_clip_thermal_track(&pace, 3));
    assert(zapp_clip_thermal_track(&pace, 2));
    pace = ZAPP_CLIP_PACE_UNKNOWN;
    assert(zapp_clip_thermal_track(&pace, 0) && zapp_clip_thermal_track(&pace, 3));
}

/* The camera stays closed until the first Record tap, also on a screen recreated with the same extra. */
static void camera_gate(void)
{
    struct zapp_clip_camera_gate gate;
    zapp_clip_gate_init(&gate);
    assert(!zapp_clip_gate_may_open(&gate));
    zapp_clip_gate_pause(&gate);
    assert(!zapp_clip_gate_may_open(&gate));
    assert(!zapp_clip_gate_tap(&gate, false));
    assert(zapp_clip_gate_may_open(&gate));
    assert(zapp_clip_gate_tap(&gate, true));
    zapp_clip_gate_pause(&gate);
    assert(zapp_clip_gate_may_open(&gate));
    zapp_clip_gate_wait(&gate);
    assert(!zapp_clip_gate_may_open(&gate));
    zapp_clip_gate_init(&gate);
    assert(!zapp_clip_gate_may_open(&gate));
}

static void clip_span(void)
{
    assert(zapp_clip_sample_end_us(false, 1000000) == 1000000 + 1024 * 1000000 / 48000);
    assert(zapp_clip_sample_end_us(true, 1000000) == 1000000 + 1000000 / 30);
    assert(zapp_clip_span_ms(1000, 5001000) == 5000 && zapp_clip_span_ms(250000, 1250000) == 1000);
    assert(zapp_clip_span_ms(0, 60000000) == 60000 && zapp_clip_span_ms(0, 60400000) == 60000);
    assert(zapp_clip_span_ms(0, 59999499) == 59999 && zapp_clip_span_ms(0, 61000000) == 60000);
    assert(zapp_clip_span_ms(0, 1499) == 1 && zapp_clip_span_ms(0, 1500) == 2);
    assert(zapp_clip_span_ms(-1, 5000000) == 0 && zapp_clip_span_ms(5, 5) == 0 && zapp_clip_span_ms(9, 5) == 0);
}

static void rotation(void)
{
    assert(zapp_clip_rotation_hint(90) == 90 && zapp_clip_rotation_hint(270) == 270);
    assert(zapp_clip_rotation_hint(0) == 0 && zapp_clip_rotation_hint(180) == 180);
    assert(zapp_clip_rotation_hint(-90) == 270 && zapp_clip_rotation_hint(450) == 90);
    assert(zapp_clip_rotation_hint(360) == 0 && zapp_clip_rotation_hint(80) == 90 && zapp_clip_rotation_hint(44) == 0);
}

static struct zapp_codec_info codec(const char *name, bool encoder, bool hardware, bool avc)
{
    struct zapp_codec_info info = {.encoder = encoder, .hardware = hardware, .avc = avc};
    snprintf(info.name, sizeof(info.name), "%s", name);
    return info;
}

static void encoder_choice(void)
{
    struct zapp_codec_info pixel[] = {
        codec("c2.android.avc.encoder", true, false, true), codec("c2.qti.hevc.encoder", true, true, false),
        codec("c2.qti.avc.decoder", false, true, true), codec("c2.qti.avc.encoder", true, true, true),
    };
    assert(zapp_clip_pick_encoder(pixel, 4) == 3);
    assert(zapp_clip_pick_encoder(pixel, 3) == -1);
    assert(zapp_clip_pick_encoder(pixel, 0) == -1 && zapp_clip_pick_encoder(NULL, 4) == -1);
    assert(zapp_clip_pick_encoder(pixel, 1) == -1);
}

static void stream_size(void)
{
    const int32_t exact[] = {0x22, 1920, 1080, 0, 0x22, 854, 480, 0, 0x22, 640, 480, 0};
    int w = 0, h = 0;
    assert(zapp_clip_pick_size(exact, 12, &w, &h) && w == 854 && h == 480);
    const int32_t near[] = {0x22, 1280, 720, 0, 0x22, 640, 480, 0, 0x22, 800, 480, 0, 0x23, 854, 480, 0, 0x22, 854, 480, 1};
    assert(zapp_clip_pick_size(near, 20, &w, &h) && w == 800 && h == 480);
    const int32_t none[] = {0x22, 640, 480, 0, 0x22, 480, 854, 0, 0x23, 854, 480, 0};
    assert(!zapp_clip_pick_size(none, 12, &w, &h) && !zapp_clip_pick_size(NULL, 0, &w, &h));
    assert(!zapp_clip_pick_size(exact, 3, &w, &h));
}

static void bitrate(void)
{
    assert(zapp_clip_bitrate_kbps(100000, 1000) == 800);
    assert(zapp_clip_bitrate_kbps(6500000, 60000) == 866);
    assert(zapp_clip_bitrate_kbps(100, 0) == 0);
}

int main(void)
{
    time_cap();
    thermal_gate();
    thermal_latch();
    thermal_unknown();
    camera_gate();
    clip_span();
    rotation();
    encoder_choice();
    stream_size();
    bitrate();
    puts("clips_capture_test ok");
    return 0;
}
