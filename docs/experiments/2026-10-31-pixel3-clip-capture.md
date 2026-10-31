<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Pixel 3 clip capture and playback - 2026-10-30

Local recording and playback of short clips on a Pixel 3 with the
`org.z23.voicepreview.clips` preview build of `apps/z23android`.

Measurements below come from the first build (commit a0c5e05be6). The build with the
review fixes is re-measured on the phone before this change lands; its numbers
replace these.

## Environment

- Device: Pixel 3 (blueline), LineageOS 22.2-20261026-NIGHTLY, SoC SDM845.
- Date: 2026-10-30 22:17-22:48 AST (2026-10-31 02:17-02:48 UTC).
- Build: Android NDK r30, aarch64, base commit 71757f5a74 plus this change.
- Scene: phone lying flat, rear camera facing a dark surface. Upright
  orientation was therefore checked from container metadata only.

## E9 - codecs

Hardware AVC encoder `c2.qti.avc.encoder` (also `OMX.qcom.video.encoder.avc`,
HEVC and VP8 encoders). Hardware AVC decoder `c2.qti.avc.decoder`
(also `OMX.qcom.video.decoder.avc`). Software `c2.android.avc.encoder` and
`OMX.google.h264.encoder` exist and are not used. The camera (id 0) did not
offer 854x480 for the private format; the 800x480 stream was used, with
rotation 90.

## E6 - 60 s recording

| Quantity | Value |
| --- | --- |
| Duration, sidecar (first build) | 59.973 s |
| Payload | 6,347,597 bytes, 846 kbit/s |
| File | 6,372,509 bytes, container 59.2 s, 861,149 bit/s |
| Video | H.264 Main, 800x480, rotation -90, 29.96 fps, 1760 frames, 30 key frames, 799,995 bit/s |
| Audio | AAC LC 48 kHz mono, 64,027 bit/s |
| Hash | `openssl dgst -sha3-512` equals the file name |
| Battery | 99% throughout |
| Thermal status | 1, then 2, then 3 from about 40 s in the second run |

Shorter runs measured 691 to 792 kbit/s (5.1, 9.6 and 13.3 s). An earlier 60.9 s
run exceeded the cap by 0.9 s because the cap clock started before the camera
session; it now starts when the session opens and samples at or after 60 s are
dropped.

## Open: sidecar duration against container duration

The pulled 60 s file has an audio track of 2775 AAC frames (59.200 s, starting at
0) and a video track that starts 0.1536 s later and ends at 58.89 s; its
container duration is 59.2 s. The log of that run reported 59.973 s as the clip
duration. The cause is not established. The recorder now logs, per track, the
first sample time and the end of the last sample, and the span it stores
(`clip times us: ...`); the next phone run measures them, including a clip whose
video starts late, and this section is then replaced by what they show. The
stored duration is also capped at 60,000 ms, the ceiling of `duration_ms` in
the signed format.

## E11 - 60 s playback

60.9 s clip: 1784 frames rendered, 0 dropped, mean absolute audio/video drift
5.2 ms, maximum 149.1 ms (start-up), one audio underrun at the end.
9.5 s clip: 228 rendered, 0 dropped, mean 6.1 ms, maximum 97.3 ms.

## E5 - extractor over a read callback

`AMediaExtractor` over an `AMediaDataSource` plays a muxer-written file whose
`moov` box is last. Read order for an 835,084-byte file: sequential 2 KiB
requests from offset 0 to about 130 KB, back to 0, to the media data at 3336,
a jump to the last 4 KB (`moov` at 830,984), then forward from the first
sample at 3352. A callback that returns -1 at or after end of file makes sample
reads fail (`read on track N failed with error -2147483648`) and the extractor
reports end of stream on the first sample. Returning 0 there works; the
adapter maps -1 to 0.

## Other checks

- Appending one byte to a saved clip: playback refused with "This clip changed
  after it was saved and will not play."; the file was restored and its hash
  verified.
- Denying camera and microphone permission shows the explanation screen.
- Swipe up/down moved between two clips; tap paused.
- Pressing Home during a 5 s recording stopped it cleanly (5,098 ms) and the
  return showed the level choice.
- Not tested: empty state on the phone.
