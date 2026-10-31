<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Pixel 3 clip capture and playback - 2026-10-30

Local recording and playback of short clips on a Pixel 3 with the
`org.z23.voicepreview.clips` preview build of `apps/z23android`. The work
stopped here by the owner's decision; the list of what was not verified is at
the end.

## Builds and environment

- Device: Pixel 3 (blueline), LineageOS 22.2-20261026-NIGHTLY, SoC SDM845.
- Build A: commit `a0c5e05be6` (rebased as `c4ed114eb5`). Measured 2026-10-30
  22:17-22:48 AST.
- Build B: commit `59ca93310c`. Measured 2026-10-30 23:44-23:55 AST
  (2026-10-31 03:44-03:55 UTC).
- Scene: phone lying flat, rear camera facing a dark surface; picture
  orientation was checked from container metadata only.
- The production node runs on this phone. Thermal status was 2 at the start of
  build B runs, 3 at the end of the 60 s recording and again after the 6 s
  recording, and 4 at 23:52-23:55 while the app was stopped and idle; no cause
  is claimed for that last reading.

## E9 - codecs (build A)

Hardware AVC encoder `c2.qti.avc.encoder` (also `OMX.qcom.video.encoder.avc`,
HEVC and VP8 encoders). Hardware AVC decoder `c2.qti.avc.decoder`
(also `OMX.qcom.video.decoder.avc`). Software `c2.android.avc.encoder` and
`OMX.google.h264.encoder` exist and are not used. Camera 0 did not offer
854x480 for the private format; both builds log `stream 800x480 rotation 90
realtime clock 1`.

## E6 - 60 s recording

Build B, one run, file pulled before saving and checked with `ffprobe`:

| Quantity | Value |
| --- | --- |
| Recording window | 60.002 s on the recording clock; stop at the cap |
| Sidecar duration | 58,816 ms |
| Container duration | 58.816 s (ffprobe) |
| Payload | 6,310,519 bytes, 858 kbit/s |
| File | 6,335,299 bytes, ffprobe bit_rate 861,710 |
| Video | H.264 Main, 800x480, rotation -90, 1752 frames, 30 key frames, stream bit_rate 800,237 |
| Audio | AAC LC 48 kHz mono, 64,027 bit/s, 2757 frames |
| Hash | first 16 hex digits of `openssl dgst -sha3-512` equal the saved clip name `fb8148d65857d52d` |
| Battery | 99% through the run, 100% after |
| Thermal status | 2, then 3 in the sample at 60 s |

Build A, 60 s run: 59.973 s logged, 6,347,597 bytes payload, 846 kbit/s, file
6,372,509 bytes, container 59.2 s, thermal 1, 2 and 3. Shorter build A runs
measured 691 to 792 kbit/s (5.1, 9.6 and 13.3 s).

## Sample times and duration

Build B per-track times from the `clip times us:` log, in microseconds on the
recording clock (the clock starts just before the camera session opens):

| Clip | Audio first | Audio end | Video first | Video end | Stored duration |
| --- | --- | --- | --- | --- | --- |
| 60 s | 1,184,765 | 60,000,764 | 1,301,489 | 59,682,067 | 58,816 ms |
| 6 s | 1,086,040 | 7,123,373 | 1,206,025 | 6,797,662 | 6,037 ms |

In both clips the first sample arrives after more than one second, video starts
about 0.12 s after audio (ffprobe video start_time 0.1167 s for the 60 s clip,
equal to the difference of the two first times), and the stored duration is the
span from the first sample to the last sample end. For the 60 s clip that span
equals the ffprobe container duration. So a clip stopped at the 60 s cap lasts
58.8 s, not 60 s.

The build A log reported 59.973 s against a container of 59.2 s. Build B did
not reproduce that mismatch, and the cause of the build A figure is not
established. A clip whose video starts late was not obtained.

## E11 - 60 s playback

Build B, the 58.816 s clip: 1752 frames rendered, 0 dropped, mean absolute
audio/video drift 5.2 ms, maximum 116.7 ms (start-up), 1 audio underrun at the
end.
Build A, 60.9 s clip: 1784 rendered, 0 dropped, mean 5.2 ms, maximum 149.1 ms,
1 underrun; 9.5 s clip: 228 rendered, 0 dropped, mean 6.1 ms, maximum 97.3 ms.

## E5 - extractor over a read callback (build A)

`AMediaExtractor` over an `AMediaDataSource` plays a muxer-written file whose
`moov` box is last. Read order for an 835,084-byte file: sequential 2 KiB
requests from offset 0 to about 130 KB, back to 0, to the media data at 3336,
a jump to the last 4 KB (`moov` at 830,984), then forward from the first
sample at 3352. A callback that returns -1 at or after end of file makes sample
reads fail (`read on track N failed with error -2147483648`) and the extractor
reports end of stream on the first sample. Returning 0 there works; the
adapter maps -1 to 0.

## Other checks

Build B:
- Empty state: the watch screen with no clips shows "No clips yet. Record one
  first."
- Stop at the cap: the recording stopped by itself at the cap and the worker
  finished the file; the screen collected it 200 ms after the stop (one 200 ms
  tick) and showed the level choice. The main thread was not timed beyond that
  log line.
- Recording interrupted by the Camera app (6 s in): the recorder finished
  within 866 ms of the pause (`clip pause waited 866 ms, finished 1`), the clip
  was kept (6037 ms, 600 KiB) and the level choice was offered on return.
- Camera app over the preview: `dumpsys media.camera` showed this app's client
  disconnect when the Camera app opened and connect again, evicting the Camera
  app, when this app returned; the preview came back. This is the pause path,
  not a camera loss while the screen stayed in front.
- The 60.9 s clip saved by build A is not listed by build B, because the stored
  duration must now be at most 60,000 ms. The other four build A clips and the
  new one were listed (5 clips).

Build A:
- Appending one byte to a saved clip: playback refused with "This clip changed
  after it was saved and will not play."; the file was restored and its hash
  verified.
- Denying camera and microphone permission shows the explanation screen.
- Swipe up/down moved between two clips; tap paused.
- Pressing Home during a 5 s recording stopped it cleanly (5,098 ms) and the
  return showed the level choice.

## Not verified

The work stopped by the owner's decision before these were done:

- Camera loss while the screen stays in front, in the preview and during a
  recording, and the first Record tap after such a loss. No way was found to
  evict the camera from a foreground app, so only the pause path above ran.
- The lost-recording notice after the 2 s pause wait times out (the wait
  finished in 866 ms when tried).
- The thermal refusal on the device; it ran only in host tests (`thermal_latch`,
  `thermal_unknown`).
- Screen-off during recording. It was not tried because the device has a secure
  lock.
- The cause of the build A duration mismatch, and a clip with a late video
  start.
- The main-thread time of the stop at the cap, beyond the 200 ms collect log.
- Picture orientation (dark scene).
- The device builds are not ancestors of the branch tip. Build A is `a0c5e05be6` and
  build B is `59ca93310c`; both were measured before the rebase onto the Home and
  scanning changes and before later fixes (the camera staying closed until the
  first Record tap, the swipe before the surface exists, the complexity splits).
  No device run of the rebased input path (`android_main.c`) is recorded.
- Build B repeats of the permission flow, swipe, tap-pause and tamper
  refusal; those results are build A.
