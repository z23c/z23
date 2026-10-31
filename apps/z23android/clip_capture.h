/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZAPP_CLIP_CAPTURE_H
#define ZAPP_CLIP_CAPTURE_H
#include "thermal.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Default profile of the short-video spec, section 3.2. The camera delivers landscape frames, so the
 * encoder is configured at coded_width x coded_height and the file carries a rotation hint that
 * makes players show it as 480 x 854 portrait. */
struct zapp_clip_profile {
    int coded_width, coded_height;
    int fps, video_bps, keyframe_seconds;
    int audio_rate, audio_channels, audio_bps;
    int64_t max_ms;
};
extern const struct zapp_clip_profile zapp_clip_profile;

#define ZAPP_CLIP_NO_ENCODER "This phone has no hardware video encoder, so it cannot record clips."
#define ZAPP_CLIP_TOO_HOT "The phone is too hot to record. Let it cool down and try again."

struct zapp_codec_info {
    char name[64];
    bool encoder, hardware, avc;
};

/* Index of the first hardware AVC encoder, or -1: recording never falls back to a software encode. */
int zapp_clip_pick_encoder(const struct zapp_codec_info *list, size_t count);

/* Whether recording may start: refused when the thermal status holds the pace at pause. */
bool zapp_clip_thermal_allows(enum zapp_pace previous, int thermal_status);

/* Whether a recording in progress must stop and keep its file: critical thermal status (4) or above. */
bool zapp_clip_thermal_stops(int thermal_status);

/* Whether elapsed_ms has reached the 60 s cap. */
bool zapp_clip_time_up(int64_t elapsed_ms);

/* Rotation in degrees clockwise for the muxer: the sensor orientation of a rear camera held upright,
 * snapped to 0, 90, 180 or 270. */
int zapp_clip_rotation_hint(int sensor_orientation);

/* Picks the camera stream size from ACAMERA_SCALER_AVAILABLE_STREAM_CONFIGURATIONS quadruples
 * (format, width, height, is_input): the profile size when offered, else the closest landscape
 * output of aspect 1.6 to 1.9 in the private-format list. */
bool zapp_clip_pick_size(const int32_t *configs, size_t count, int *width, int *height);

/* Average bitrate of bytes over duration_ms in kbit/s, 0 for an empty duration. */
int64_t zapp_clip_bitrate_kbps(int64_t bytes, int64_t duration_ms);

#ifdef __ANDROID__
#include <android/native_window.h>
#include <jni.h>

/* Lists the codecs of the device through MediaCodecList and returns how many fit in list. */
size_t zapp_clip_list_codecs(JNIEnv *env, struct zapp_codec_info *list, size_t cap);

/* The Android thermal status 0 to 6 from PowerManager, or -1 when it cannot be read. */
int zapp_clip_thermal_status(JNIEnv *env, jobject activity);

/* Battery charge in percent from BatteryManager, or -1 when it cannot be read. */
int zapp_clip_battery_percent(JNIEnv *env, jobject activity);

struct zapp_clip_recorder;

/* Opens the rear camera onto the preview window. Fails with a sentence for the person in error. */
struct zapp_clip_recorder *zapp_clip_recorder_open(ANativeWindow *preview, const char *encoder,
                                                   char *error, size_t error_cap);

/* Starts recording MPEG-4 to path with sound. The camera keeps showing the preview. */
bool zapp_clip_recorder_start(struct zapp_clip_recorder *r, const char *path, char *error, size_t error_cap);

/* Milliseconds recorded so far; recording ends by itself at the cap, see zapp_clip_recorder_running. */
int64_t zapp_clip_recorder_elapsed_ms(const struct zapp_clip_recorder *r);
bool zapp_clip_recorder_running(const struct zapp_clip_recorder *r);

/* Ends the recording and closes the file. Returns the duration in milliseconds, or 0 and no file
 * when nothing playable was written. */
int64_t zapp_clip_recorder_stop(struct zapp_clip_recorder *r);

/* Stops any recording, closes the camera and frees the recorder. */
void zapp_clip_recorder_close(struct zapp_clip_recorder *r);
#endif
#endif
