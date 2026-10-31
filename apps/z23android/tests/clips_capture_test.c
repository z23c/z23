/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "clip_capture.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static void profile_numbers(void)
{
    const struct zapp_clip_profile *p = &zapp_clip_profile;
    assert(p->coded_width == 854 && p->coded_height == 480);
    assert(p->fps == 30 && p->video_bps == 800000 && p->keyframe_seconds == 2);
    assert(p->audio_rate == 48000 && p->audio_channels == 1 && p->audio_bps == 64000);
    assert(p->max_ms == 60000);
    assert(!zapp_clip_time_up(0) && !zapp_clip_time_up(59999));
    assert(zapp_clip_time_up(60000) && zapp_clip_time_up(61000));
}

static void thermal_gate(void)
{
    for (int status = 0; status <= 3; ++status) assert(zapp_clip_thermal_allows(ZAPP_PACE_NORMAL, status));
    for (int status = 4; status <= 6; ++status) assert(!zapp_clip_thermal_allows(ZAPP_PACE_NORMAL, status));
    assert(zapp_clip_thermal_allows(ZAPP_PACE_GENTLE, 3));
    assert(!zapp_clip_thermal_allows(ZAPP_PACE_PAUSE, 3));
    assert(zapp_clip_thermal_allows(ZAPP_PACE_PAUSE, 2));
    assert(!zapp_clip_thermal_stops(0) && !zapp_clip_thermal_stops(3));
    assert(zapp_clip_thermal_stops(4) && zapp_clip_thermal_stops(6));
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
    profile_numbers();
    thermal_gate();
    rotation();
    encoder_choice();
    stream_size();
    bitrate();
    puts("clips_capture_test ok");
    return 0;
}
