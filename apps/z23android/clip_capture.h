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

/* Whether the camera may open. It stays closed until the person taps Record: a fresh screen (also one
 * recreated with the same launch extra) waits, and a pause only keeps waiting when no tap happened yet. */
struct zapp_clip_camera_gate {
    bool waiting, tapped;
};
void zapp_clip_gate_init(struct zapp_clip_camera_gate *gate);
bool zapp_clip_gate_may_open(const struct zapp_clip_camera_gate *gate);
/* A Record tap. Returns whether recording starts now: only when the camera is already open, so the first
 * tap opens the preview and the next one records. */
bool zapp_clip_gate_tap(struct zapp_clip_camera_gate *gate, bool camera_open);
void zapp_clip_gate_pause(struct zapp_clip_camera_gate *gate);
void zapp_clip_gate_wait(struct zapp_clip_camera_gate *gate); /* the camera failed or was lost: wait for the next tap */

/* The pace to start from when the node's pace is not known: pause, so recording is refused until the
 * status is below 3. */
#define ZAPP_CLIP_PACE_UNKNOWN ZAPP_PACE_PAUSE

/* Advances *pace with the node's thermal hysteresis and returns whether recording may start. Once the
 * pace is pause (status 4 or above) it stays pause until the status drops below 3, so a status of 3
 * right after 4 still refuses. */
bool zapp_clip_thermal_track(enum zapp_pace *pace, int thermal_status);

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

/* End of a sample on the recording clock: its presentation time plus one frame (video) or one AAC
 * frame of 1024 samples (audio). */
int64_t zapp_clip_sample_end_us(bool video, int64_t pts_us);

/* Duration of a clip in milliseconds: the span from its first sample to the end of its last, rounded to a
 * millisecond and never above the 60 s cap; 0 when there is no first sample or no span. */
int64_t zapp_clip_span_ms(int64_t first_us, int64_t end_us);

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

/* Milliseconds recorded so far. Recording ends by itself at the cap. */
int64_t zapp_clip_recorder_elapsed_ms(const struct zapp_clip_recorder *r);

/* True from a successful start until the worker has finished the file. */
bool zapp_clip_recorder_running(const struct zapp_clip_recorder *r);

/* Asks a recording to end. It returns at once; the worker closes the file and
 * zapp_clip_recorder_running then turns false. */
void zapp_clip_recorder_request_stop(struct zapp_clip_recorder *r);

/* Waits up to timeout_ms for the worker to finish; true when it has. */
bool zapp_clip_recorder_wait(const struct zapp_clip_recorder *r, int timeout_ms);

/* After running turned false: the duration in milliseconds, or 0 and no file when nothing playable
 * was written. Call it once per recording. */
int64_t zapp_clip_recorder_collect(struct zapp_clip_recorder *r);

/* The sentence for the person when the last recording failed, or an empty string. */
const char *zapp_clip_recorder_message(const struct zapp_clip_recorder *r);

/* Whether the camera was taken by another app or stopped; the recorder must then be closed and reopened. */
bool zapp_clip_recorder_camera_lost(const struct zapp_clip_recorder *r);

/* Whether a recorder is still writing the file at path. */
bool zapp_clip_recorder_path_owned(const char *path);

/* Frees the recorder and closes the camera. A recording still running is told to stop and a background
 * thread finishes and frees it, so the call does not wait for the worker. */
void zapp_clip_recorder_close(struct zapp_clip_recorder *r);
#endif
#endif
