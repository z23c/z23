<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Clips: a peer-to-peer short-video network (Design)

Clips is a short-form video network with no central server and no signup.
An author's own node and the machines of that owner's fleet host the
author's videos. Followers' nodes fetch what they follow over the existing
P2P and onion transport, check every chunk by hash and every record by
signature, and play it. The Android app is the first client.

Status: **draft for owner review**. Nothing here is built unless a file or
symbol is cited; where a piece does not exist the text says **new**. Clips
touches neither the sealed `core/` tree nor any consensus predicate.

1. [Purpose and principles](#1-purpose-and-principles)
2. [Data model](#2-data-model)
3. [Media](#3-media)
4. [Network](#4-network)
5. [A flexible API for a changeable UI](#5-a-flexible-api-for-a-changeable-ui)
6. [Safety](#6-safety)
7. [Money, later](#7-money-later)
8. [Phased plan with acceptance tests](#8-phased-plan-with-acceptance-tests)
9. [Open questions and risks](#9-open-questions-and-risks)
10. [Where the code goes](#10-where-the-code-goes)

---

## 1. Purpose and principles

A person records a clip on a phone, it appears on their own machines, and
people who chose to follow them can watch it, with no company in the path.

1. **No central server, no signup.** An identity is a key generated on the
   author's node. There is no directory operator, account database or
   required relay.
2. **The author's node and fleet host the content.** A fleet is one owner's
   machines (intra-fleet). Always-on fleet nodes are the author's home relays
   and pin the author's objects ([4.5](#45-home-relays-and-pinning)).
3. **Verify, never assume.** Every chunk is checked against its SHA3-512 id
   in a manifest, every manifest against the id in a signed record, every
   record against its author's Ed25519 signature and its place in that
   author's hash chain. A peer being reachable proves nothing about the bytes
   it returns, and a signature identifies a key, not the safety or legality of
   content.
4. **Phone health first.** Battery, heat and mobile data limit what the phone
   encodes, fetches, caches and serves. The thermal pace (`normal`, `gentle`,
   `pause`) governs all background work ([4.7](#47-budgets-pace-power-and-link)).
5. **Consent for hosting.** A node stores and serves only what its owner's
   policy allows. Serving other people's clips is off by default. Between
   different owners' fleets (inter-fleet) every peer needs explicit per-peer
   consent. Direct NAT-punched links are opt-in and off by default.
6. **One binary, nested CLI.** Everything is a leaf of `z23 clips ...`, with
   one handler behind the CLI, the app's JSON-RPC, REST and MCP
   ([5.1](#51-one-handler-four-adapters)).

Reused today: signed hash-identified posts (fleet board, `docs/agent/FLEET_BOARD.md`),
the content-addressed package swarm with flag-gated hosting
(`docs/commons/P2P_SOURCE_HOSTING.md`), zid identity documents and signed
endpoint records (`docs/spec/sovereign-identity-layer.md`), embedded Tor onion
streams, the signed fleet roster, the node pace, and the app's NDK camera
code. **New**: the video encoder, muxer, decoder and player, the Clips
records, frames, API and UI.

<!-- claim: symbol-present node_pace_get engine/jobs/src/node_pace.c # the pace word is read by the node -->
<!-- claim: symbol-present zapp_pace_next apps/z23android/thermal.c # the app maps thermal status to a pace -->
<!-- claim: file-present apps/z23android/camera.c # NDK camera code exists for QR scanning -->
<!-- claim: symbol-absent AMediaCodec_createInputSurface apps/z23android # no video encoder exists yet -->
<!-- claim: symbol-absent AMediaMuxer_new apps/z23android # no muxer exists yet -->
<!-- claim: file-absent contexts/clips # the room is not created by this specification -->

---

## 2. Data model

All integers are little-endian. All identifiers are domain-tagged SHA3-512 digests (64 bytes), following the
SHA3-512 delivery direction already used for plugin generations
(`docs/dev/PLUGINS.md`). Clips stores and moves every manifest, chunk,
thumbnail, avatar and list through the one Commons content layer
(`package_store.h`, `zpkgswm`) after its SHA3-512 format version replaces
SHA3-256. Chunk size is set per manifest by `chunk_size_log2`; Clips uses 2^18.
Clips frames are new `zpkgswm` magics: no new command, no second store, no
`core/` edit. Decoders are strict: wrong magic, unknown version, unknown flag,
nonzero reserved byte, a length past its ceiling or trailing bytes is a
refusal. The ZMSG memo decoder refuses wrong magic, unknown version, reserved
flag bits and an over-ceiling length; Clips adds reserved-byte and
trailing-byte refusals (`core/modules/net/include/net/zmsg.h`).

<!-- claim: symbol-present ZMSG_MEMO_LEN core/modules/net/include/net/zmsg.h # the strict-decoder precedent -->

### 2.1 Identity key

- **Author identity** is one Ed25519 public key (32 bytes), generated on the
  author's node into a mode 0600 exclusive-create key file, as `z23 plugin
  keygen` does. It is a Clips key, never a wallet key.
- The wire author id is the raw public key. The display handle is
  `base32(first 10 bytes of SHA3-256("z23.clips.handle.v1" NUL key))`. Human
  names are optional (naming room, `contexts/naming`, or a ZNAM `SET_TEXT key="zid"`
  binding, `contexts/naming/modules/znam/include/znam/znam.h`); nothing in Clips depends on a name resolving.
- **Rotation** uses the zid layer: a master key may be anchored on-chain and
  rotated or revoked by anchored documents
  (`contexts/wallet/modules/zid/include/zid/zid.h`). Phase 1 needs no anchor.
- **Signature schemes.** Version 1 uses Ed25519, a registered scheme the node
  already verifies (`core/modules/crypto_registry/include/crypto_registry/crypto_registry.h`).
  The `alg` header byte lets a hybrid scheme arrive without a flag day.
  ML-DSA-44 exists in the tree only as a parsed SSH host-key type for device
  pairing, so a Clips ML-DSA-44 signer is **new** and reserved (`alg = 2`,
  2420-byte signature). SLH-DSA-SHAKE-128s exists as the second half of the
  hybrid release document (`contexts/wallet/modules/zid/include/zid/zid_hybrid.h`,
  7,856-byte signature); on every 1 KB post it would be wasteful, so it is
  reserved for identity documents (rotation, endorsement).

<!-- claim: file-present contexts/wallet/modules/zid/include/zid/zid.h # the identity document codec -->
<!-- claim: symbol-present CRYPTO_SIG_ED25519 core/modules/crypto_registry/include/crypto_registry/crypto_registry.h # Ed25519 is registered -->
<!-- claim: symbol-present ZRS1_PQ_SIG_SIZE contexts/wallet/modules/zid/include/zid/zid_hybrid.h # the SLH-DSA hybrid exists for release documents -->

### 2.2 Signed record envelope

```
offset  size  field        notes
0       4     magic        "ZCLR"
4       1     version      1
5       1     kind         see 2.3
6       1     lane         0 content chain, 1 social chain
7       1     alg          1 = Ed25519; anything else refused in version 1
8       32    author       Ed25519 public key
40      8     seq          per (author, lane), starts at 1, strictly +1
48      64    prev         record id of seq-1 in this lane; zero at seq 1
112     8     created_at   i64 unix seconds, signer's clock
120     8     stamp        spam stamp (6.4); 0 when unused
128     2     body_len     0..1024
130     N     body         kind-specific
130+N   64    signature    Ed25519 over id
```

- **Record id** = `SHA3-512("z23.clips.record.id.v1" NUL ‖ bytes[0 .. 130+N))`.
  The signature covers the 64-byte id, as the plugin store signs a 64-byte
  SHA3-512 digest. Fixed overhead is 194 bytes; the largest record is
  **1,218 bytes**.
- **Hash chain.** `prev` links each record to its predecessor in the same
  `(author, lane)`. A verifier checks each `prev` against the previous id and
  each `seq` against `+1`.
- **Two lanes.** Lane 0 holds content (posts, profile, tombstones, lists);
  lane 1 holds social acts (reactions, comments, follows, blocks, reports). A
  follower syncs lane 0 to see everything an author published without
  downloading every reaction they ever made.
- **Time.** A `created_at` more than 600 seconds ahead of the verifier's clock
  is deferred. Ordering is by `seq`, never by time.
- **Forks.** Two different records with the same `(author, lane, seq)` are an
  equivocation. A node keeps both as evidence, stops serving that author's
  later records, shows `author_forked` in cards and never silently picks a
  side, following the non-equivocation rule of the identity layer.
- **Deletion.** A tombstone (kind 3) asks holders to drop a record's bytes. It
  cannot force deletion elsewhere; cards report `tombstoned` so a UI can hide
  the item.

### 2.3 Record kinds

| kind | lane | name | body |
|---|---|---|---|
| 1 | 0 | post | clip, caption, tags, reply or reshare links |
| 2 | 0 | profile | name, bio, avatar object, tip address |
| 3 | 0 | tombstone | target id, reason |
| 4 | 0 | list | published block or allow list ([6.2](#62-block-lists-and-local-filters)) |
| 10 | 1 | reaction | target id, code |
| 11 | 1 | comment | target post, parent comment, text |
| 12 | 1 | follow | target author, unfollow flag |
| 13 | 1 | block | target type, target, unblock flag |
| 14 | 1 | report | target id, reason, note |

Kinds 5..9 and 15..255 are reserved and refused in version 1.

**Post (kind 1).**

```
flags         1     bit0 has_manifest, bit1 has_reply_to, bit2 has_reshare_of;
                    bits 3..7 zero; bit0 or bit2 must be set
manifest_id   64    iff bit0: the video manifest (2.4)
reply_to      64    iff bit1: the post this clip answers
reshare_of    64    iff bit2: the post being reshared
caption_len   2     0..500
caption       N     UTF-8 NFC, no control characters except LF
tag_count     1     0..8
tags          ...   each: len u8 (1..32) then bytes [a-z0-9_]
```

Worst case 1 + 3 x 64 + 2 + 500 + 1 + 8 x 33 = 960 bytes, under the 1,024
ceiling. A reply is a clip that answers a post; a reshare points at an
existing post with or without a caption. An author may reshare a post whose
bytes they do not hold; holders are found through the original author.

**Other bodies.**

- *Profile (2):* `name_len u8` (0..48) and name; `bio_len u8` (0..160) and
  bio; `avatar_flag u8` and, if 1, an `avatar_id` (64 bytes); `tip_len u8`
  (0..128, a Sapling address string; 128 matches `ZMSG_MAX_ADDR`) and address.
  A later profile replaces an earlier one by `seq`.
- *Tombstone (3):* `target_id` 64, `reason u8` (1 author_deleted, 2 mistake,
  3 superseded, 4 policy).
- *List (4):* `list_object_id` 64, `entry_count u32` (at most 4000),
  `title_len u8` (0..64) and title, `list_kind u8` (1 block, 2 allow).
- *Reaction (10):* `target_id` 64, `reaction u8` (0 retract, 1 like, 2 laugh,
  3 wow, 4 sad, 5 angry; higher refused).
- *Comment (11):* `target_id` 64 (a post), `parent_id` 64 (zero for top
  level), `text_len u16` (1..280), UTF-8 NFC text.
- *Follow (12):* `target_author` 32, `flags u8` (bit0 unfollow).
- *Block (13):* `target_type u8` (1 author, 2 content id), `target` 64 (an
  author key in the first 32 bytes, rest zero), `flags u8` (bit0 unblock).
- *Report (14):* `target_id` 64, `reason u8` (1 spam, 2 abuse, 3 illegal, 4
  sexual, 5 impersonation, 6 other), `note_len u16` (0..280) and note.

### 2.4 Video manifest

A clip is one content-layer package: metadata, thumbnail, video. Its root is
`manifest_id`; chunk ids are raw SHA3-512. The signed post that names the root
binds it to the author. The store deletes CAS objects that no content manifest
references when it opens, so a chunk outside a package would vanish at restart.
A clip package holds exactly `meta`, `thumb.webp`, `video.mp4`; an avatar or
list package holds one file, `avatar` or `list`. Any other root is refused at
fetch. A followed author could otherwise name a one-file root at path `bundle`,
which the public-shape check accepts by shape alone and a `-packagehost=1`
follower would then offer to strangers. The `meta` file is the "ZCLM" layout
below.

<!-- claim: symbol-present VCS_PACKAGE_PUBLIC_BUNDLE contexts/commons/modules/vcs/src/package_public_shape.c # a one-file bundle is accepted by shape alone -->

```
offset  size  field
0       4     magic            "ZCLM"
4       1     version          1
5       1     container        1 = MP4
6       1     video_codec      1 = H.264; 2 HEVC and 3 AV1 reserved
7       1     audio_codec      0 none, 1 AAC-LC
8       2     width            16..1920
10      2     height           16..1920
12      4     duration_ms      1..60000
16      2     bitrate_kbps     nominal total, 1..8000
18      1     fps              1..60
19      1     rotation         0..3 = 0, 90, 180, 270 degrees clockwise
20      1     chunk_size_log2  18; anything else refused
21      4     total_size       1..25,165,824 (24 MiB)
25      2     chunk_count      1..96, equals ceil(total_size / 262144)
27      64    thumb_id         thumbnail object (2.6)
91      2     thumb_width      16..1080
93      2     thumb_height     16..1920
95      64*k  chunk_ids        k = chunk_count, in order
```

Fixed header 95 bytes; ceiling 95 + 96 x 64 = **6,239 bytes**.

### 2.5 Chunks

Chunks are **262,144 bytes (256 KiB)**, except the last (1 to 262,144 bytes).
Chunk id = raw `SHA3-512(bytes)`. Why 256 KiB:

- *Tor cell overhead does not depend on it.* A relay data cell is 514 bytes
  with 498 payload bytes, about 3.3% overhead at any chunk size; a chunk spans
  527 cells. Chunk size changes retry cost and scheduling, not overhead. This
  assumption is checked by E3.
- *Retry cost.* A circuit failure loses at most one chunk in flight; the 1 MiB
  chunks of the package format would lose four times as much.
- *Start-up.* At the default profile (about 108 KB/s) one chunk is about 2.4
  seconds of media, so playback starts after two chunks ([3.4](#34-playback)).
- *Parallelism and manifest size.* A 6.5 MB clip is 25 chunks, enough to fetch
  from several holders at once; 4 KiB chunks would put 1,600 hashes in a
  manifest.
- *Wire.* One chunk and its framing sit far below the 2 MiB message ceiling
  (`MAX_PROTOCOL_MESSAGE_LENGTH`).

E3 and E4 measure 64, 128, 256 and 512 KiB on the same circuits; the value is
frozen by `chunk_size_log2` and changing it needs a manifest version.

<!-- claim: symbol-present MAX_PROTOCOL_MESSAGE_LENGTH core/modules/net/include/net/net.h # the protocol message ceiling -->

### 2.6 Thumbnail and avatar objects

A thumbnail is one object of at most 32 KiB, a lossy WebP of a usable frame at
most 540 x 960, stored as a file of the clip package; the manifest names it by `thumb_id`, the
raw SHA3-512 of its bytes. An avatar is a one-file package with a 64 KiB
ceiling. Each is fetched with `clipwant`.

## 3. Media

### 3.1 Capture and encoding on Android

The app stays C23 with no Java source: its one Java class (`NodeService`) is
generated by `apps/z23android/dexgen.c`, and its UI is JNI calls into
platform widgets (`apps/z23android/native_ui.c`). Clips adds only NDK C APIs.

```
 Camera     ACameraManager -> ACameraDevice -> ACameraCaptureSession
                 outputs: 1. AImageReader (preview, thumbnail)
                          2. AMediaCodec input Surface (H.264 encoder)
 Microphone AAudio input stream -> AMediaCodec (AAC-LC encoder)
 Muxer      AMediaMuxer, MPEG_4 output, file in app-private storage
 Chunker    split at 262,144 bytes, SHA3-512 each, build manifest and post
 Thumbnail  preview frame -> RGBA -> AndroidBitmap_compress (lossy WebP)
```

- `camera.c` already opens the rear camera, creates an `AImageReader` and
  reads YUV planes for QR scanning. Recording adds the encoder's input surface
  (`AMediaCodec_createInputSurface`, API 26) as a second capture output. The
  encoder, muxer and audio-encode code is **new**.
- Without a hardware AVC encoder the app refuses to record and says why,
  instead of burning CPU on a software encode.
- Camera and microphone permissions are already declared in
  `apps/z23android/AndroidManifest.xml`. Battery and network state reads are
  **new** JNI calls ([4.7](#47-budgets-pace-power-and-link)).
- NDK calls named here exist at API 30 or lower (`AMediaDataSource` 28,
  `AndroidBitmap_compress` 30); the app targets API 35.

<!-- claim: symbol-present AAudio_createStreamBuilder apps/z23android/audio.c # AAudio streams exist in the app -->
<!-- claim: symbol-present RECORD_AUDIO apps/z23android/AndroidManifest.xml # microphone permission is declared -->

### 3.2 Default profile

| Property | Default | Optional | Limit |
|---|---|---|---|
| Container, audio | MP4, AAC-LC 64 kbps, 44.1 or 48 kHz | none | MP4 only |
| Video codec | H.264 Main profile | | AVC only |
| Resolution | 480 x 854 portrait | 720 x 1280 | 1920 per side |
| Frame rate | 30 fps | 24, 60 | 60 |
| Video bitrate | about 800 kbps, constant | 2000 kbps at 720p | 8000 kbps total |
| Keyframe interval | 2 s | | 4 s |
| Duration | up to 60 s | | 60 s |
| Size | about 108 KB/s, 6.5 MB at 60 s | about 15 MB at 60 s | 24 MiB |

- **Tor throughput sets the budget.** Onion circuit throughput varies by
  circuit and hour, and the repository has no measurement of sustained onion
  throughput for large transfers. The default is chosen for modest throughput:
  playback needs about 108 KB/s after a start of two chunks. 720p at about 250
  KB/s is optional. E1 measures the real distribution and this table follows
  it.
- **Effective cap.** The 24 MiB size ceiling, not the bitrate field, bounds
  clips: 60 s fits only up to about 3,300 kbps total, and a higher bitrate
  shortens the permitted duration (`duration_ms` at most 24 MiB x 8 / bitrate).
- **Constant bitrate** keeps size, cache arithmetic and buffering predictable.
- **H.264 only.** It decodes on every supported device. HEVC would save an
  estimated 30 to 40% of bytes but has uneven encoder support; AV1 hardware
  encode is not widely available. Codec ids 2 and 3 are reserved.
- **No server-side transcoding in phase 1.** There is no server. The phone
  encodes once and a relay stores exactly the published bytes, which the
  manifest binds. Several qualities per post is a later post-body change (Q6).

### 3.3 Thumbnails and storage on the phone

The thumbnail comes from a preview frame the capture session already produces
(YUV 4:2:0, converted to RGBA, downscaled, compressed to WebP at quality about
70, at most 32 KiB). The conversion is **new**. The thumbnail id is in the
manifest, so a feed card renders before any video chunk arrives; 20 cards cost
at most about 640 KiB.

After the muxer closes, the node chunks the file, hashes, builds the manifest,
signs the post and writes objects to the Commons package store (staged until verified, atomic
rename, quota, pins that are never evicted, quarantine).
The recording file is deleted only after the store re-reads and verifies every
chunk.

### 3.4 Playback

Flow: UI video card, `AMediaExtractor` over an `AMediaDataSource`,
`AMediaCodec` decoder to a `SurfaceView` surface obtained through JNI,
`AAudio` output; the data source reads from the node over loopback.

- `AMediaDataSource` has `readAt` and `getSize` callbacks (API 28). The app
  maps `readAt` to a ranged request to its own node, which returns bytes only
  after verifying the chunks covering the range. Hash checking stays in the
  node and out of UI code.
- The muxer normally writes the MP4 index at the end. The player requests the
  last chunk first (it holds the index), then chunk 0 forward, so no rewrite is
  needed for fast start. If E5 shows the extractor needs the index first, a
  small C23 "index to front" step runs before chunking; it is **new** and
  deferred until measured.
- Decoder output is released at timestamps, with A/V sync on the audio clock.
  This is **new** and verified live on the Pixel.
- A missing chunk blocks the read up to a deadline (default 8 s), then the
  request fails with 504; the player shows a stall and retries other holders.
  It never plays unverified bytes.

---

## 4. Network

### 4.1 Transports

Clips adds frames to the existing swarm command; it adds no network. Clips
frames move only on Noise sessions, over TCP or onion.

| Path | Transport | Default |
|---|---|---|
| Phone to its own fleet nodes (intra-fleet) | paired stream between roster members | on, owner's machines only |
| Between different owners' nodes (inter-fleet) | P2P over TCP or onion stream, operator-directed peers | refused until the owner grants that peer |
| Onion | embedded Tor streams bridged to the P2P reactor | on for non-fleet peers |
| Direct NAT-punched link | UDP link (`engine/modules/gamelink`) | off, opt-in per peer, phase 4 at earliest |

- Onion endpoints are operator-directed and never gossiped by the base P2P
  layer (`core/modules/net/include/net/onion_stream.h`). Clips follows: peers
  are added by the owner or found through a signed endpoint record for an
  author (ZIDE, `contexts/wallet/modules/zid/include/zid/zendp.h`), never by an
  unsigned scrape.
- The direct link implements only the unreliable datagram profile; ordered
  reliable delivery and hole punching do not exist (`docs/node/GAMELINK.md`),
  so bulk chunk transfer cannot use it yet. Every Clips transfer is TCP or
  onion until then.
- The owner's `clips.transport` policy is `onion` (default for non-fleet
  peers) or `any`.

<!-- claim: file-present core/modules/net/src/onion_stream.c # outbound onion streams exist -->
<!-- claim: file-present core/modules/net/src/onion_directory.c # the onion directory exists -->
<!-- claim: file-present engine/modules/gamelink/src/directlink_channel.c # the datagram link exists -->

### 4.2 Frames

Clips adds no P2P command and no second store. Its frames are new magics inside
the existing `zpkgswm` command, the way blobs, zendp, zdesc and the DHT
already ride it; the command table lives in the sealed message processor, so a
new command would need an unseal. Five frames are **new**; `clipwant` and
`clipdata` are WANT and DATA of ZPSW version 2 (Phase 0): 64-byte root and
hash, one chunk per WANT. Version 1 frames carry a 32-byte root and hash and
the manifest decoder refuses any chunk size but 1 MiB, so they cannot carry
Clips objects. A node starts Clips frames only to fleet or granted peers; a Noise peer without
a grant gets only `clipnot` reason 2. Bodies start
with `version u8` (1) and decode strictly. On a paired stream a 256 KiB chunk
spans 5 frames (`MESH_STREAM_FRAME_MAX`, 64 KiB).

<!-- claim: symbol-present zpkgswm core/modules/net/include/net/msgprocessor.h # swarm frames ride one command -->
<!-- claim: symbol-present MESH_STREAM_FRAME_MAX engine/composition/include/config/mesh_stream.h # paired-stream frame size -->

| frame | direction | body |
|---|---|---|
| `clipsub` (new) | follower to holder | `count u8` (0..64), `flags u8` (bit0 also lane 1), per author `author` 32 and `have_seq u64`. Count 0 clears. At most one per 60 s per peer |
| `clipheads` (new) | holder to subscriber, pushed on change | `count u8` (1..32); per entry `author` 32, `lane u8`, `seq u64`, `head_id` 64 (105 bytes) |
| `clipget` (new) | requester to holder | `req u64`, `author` 32, `lane u8`, `from_seq u64`, `max u8` (1..32) |
| `cliprec` (new) | holder to requester | `req u64`, `count u8` (0..32), per record `len u16` and bytes |
| `clipwant` (ZPSW v2 WANT) | requester to holder | `req u64`, root 64, `kind u8`, `file_index u32`, `chunk_index u32`, hash 64; one chunk per WANT |
| `clipdata` (ZPSW v2 DATA) | holder to requester | the same fields, plus `len u32` and bytes |
| `clipnot` (new) | either | `req u64`, `reason u8`: 1 not held, 2 refused by policy, 3 rate limited, 4 paused, 5 blocked hash, 6 too large |

- `clipheads` is the **head announcement**: per followed author and lane, the
  holder's newest `(seq, head_id)`. A subscriber behind its own head sends
  `clipget` from `seq + 1`.
- A data frame is at most 262,144 plus framing, so one want demands at most
  256 KiB. The caller picks the order of wants, which allows the tail-first read
  of 3.4.
- Counts and lengths are checked before allocation. Over-limit frames are
  dropped or answered with `clipnot`, with rate-limited logging.
- Per-peer byte budgets and request rates use the swarm engine's existing
  accounting (`dumpstate zcode_swarm`); Clips adds no second scheme.

<!-- claim: symbol-present zcode_swarm contexts/commons/controllers/include/controllers/diagnostics_dumpers_zcode.def # the swarm accounting dump -->

### 4.3 Fetch and verify

```
 follower                                              holder (any)
   |-- clipsub [A, have_seq 41] ---------------------------->|
   |<-- clipheads [A, lane 0, seq 44, head 7f3a..] ----------|
   |-- clipget [A, lane 0, from 42, max 3] ----------------->|
   |<-- cliprec [rec42, rec43, rec44] -----------------------|
   |   verify: magic, limits, alg, signature, seq+1,         |
   |           prev == id(previous), clock window            |
   |-- clipwant [manifest 91ab..] --------------------------->|
   |<-- clipdata [manifest] ----------------------------------|
   |   verify: id(manifest) == manifest_id in rec44;          |
   |           limits; chunk_count == ceil(size / 262144)     |
   |-- clipwant [root, chunk 0], [root, chunk 1], ... -> any holder ->|
   |<-- clipdata [chunk i] x N --------------------------------|
   |   verify each: id(chunk) == chunk_ids[i]; store          |
```

1. **Records, then the manifest, then chunks.** Nothing is stored as a clip
   until its record verifies; nothing is requested at scale until its
   manifest verifies.
2. **Verification gates storage.** A chunk whose id differs from the manifest
   is dropped. A peer sending two bad chunks in a session is disconnected and
   rate limited for an hour.
3. **Any holder.** Different chunks may come from different peers. Holders are
   peers that announced the head or answered a `clipwant`; lists of holders are
   advisory.
4. **Provider discovery** beyond connected peers is intended to use the ZCODE
   DHT provider records. Whether their shape fits author heads is Q8; if not, a Clips signed provider record is **new**.
5. **Gaps.** A jump in `seq` triggers a request for the missing records; later
   records stay stored but flagged `chain_gap` until the gap fills.
6. **Resume.** Chunk state is per object; a restart resumes from verified
   chunks.

### 4.4 Reactions, comments and delivery

A reaction or comment is signed by its author, stored in their node (lane 1)
and pushed as `cliprec` to the target author's known holders and relays. The
target author's node verifies it, applies block and rate rules and, if
accepted, serves it in the clip's comment index. Phase 3 adds a `target`
filter to `clipget` (**new**); before it, lane 1 of an author is fetched
whole. A target author hides a comment by a local block or a published list,
never by deleting the commenter's chain.

### 4.5 Home relays and pinning

A home relay is an always-on node in the author's own fleet.

- `z23 clips relay add` (**new**) marks a roster machine as a relay. The
  roster is the existing signed fleet roster
  (`engine/composition/include/config/boot_fleet_roster.h`). The command grants
  no shell or other authority, the posture of `z23 fleet join`.
- The relay subscribes to the owner's author keys over the paired stream with
  the same messages as any peer, verifies as in 4.3 and marks every object
  **pinned**: exempt from eviction and announced as a holder. A relay pins
  only author keys its own operator added on that relay; a key a peer
  subscribes to or pushes is never pinned.
- **Pin audit.** The phone deletes its own chunks only after a relay passes a
  sampled audit: the phone requests a random subset (default 4) of chunk
  indexes and checks each hash. This proves retrievability at one moment, not
  durability.
- Relays also serve the author's followers, subject to the relay's own hosting
  switch. Phase 1 needs only the phone and one relay.

<!-- claim: file-present engine/composition/include/config/boot_fleet_roster.h # the fleet roster exists -->

### 4.6 Follower caches and opt-in serving

- A follower's node **caches** what it fetched for its own owner, within the
  budgets of 4.7.
- The swarm engine exists only with `-packagehost=1`, and its want handler
  takes a peer, but its public-shape check (`vcs_swarm_public_serveable`) takes no peer; it refuses roots outside the closed public shapes, so
  clips would never transfer and adding a shape would offer them to strangers.
  Clips serves through a peer-scoped path in `boot_zcode_swarm_unhosted_frame`,
  independent of `-packagehost`, never as a public shape.
- A node serves non-fleet peers only when its owner enables `-clipshost=1`
  (**new**, off by default). Fleet peers of the same owner are served the
  owner's own author keys without the flag.
- Inter-fleet serving also needs a per-peer grant: `z23 clips peer allow <peer>
  --subscribe --serve` (**new**), stored locally and never gossiped. A peer
  without a grant gets `clipnot` reason 2. A grant names the peer's Noise static key.
  Clips frames move only on a Noise session, over TCP or onion. A source
  address is never an identity. A pushed `cliprec` from a peer without a grant
  is dropped. Noise is opt-in (`-noisetransport`, default off), and the app does
  not pass it when it starts the node (`apps/z23android/operations.c`), so
  Phase 1 adds it.
- Serving is limited to authors the node holds and the owner has not blocked,
  and to objects that pass the safety checks of [6](#6-safety) at store time
  and at serve time.

<!-- claim: symbol-present packagehost engine/composition/src/boot_zcode_swarm.c # package hosting is flag-gated and off by default -->
<!-- claim: symbol-present boot_zcode_swarm_unhosted_frame engine/composition/src/boot_zcode_swarm.c # the pre-hosting frame path -->
<!-- claim: symbol-present vcs_swarm_public_serveable contexts/commons/modules/vcs/src/package_swarm_priv.h # the peer-less public-shape check -->

### 4.7 Budgets: pace, power and link

| Input | Source | State |
|---|---|---|
| Pace `normal`, `gentle`, `pause` | Android thermal status mapped by `zapp_pace_next`, written by the app to the datadir pace file, read by the node (`engine/jobs/include/jobs/node_pace.h`) | in tree |
| Power: `charging`, `battery`, low-battery flag | `BatteryManager` through JNI | **new** |
| Link: `unmetered`, `metered`, `offline` | `ConnectivityManager` through JNI | **new** |

The new inputs follow the pace mechanism: the app writes one word to a small
datadir file and the node reads it at most once per second. A missing file
means `metered` for link and the permissive value for power, so a node never
told otherwise is cautious about data. Today moderate thermal status and above
hold `gentle`, critical and above `pause`, and `pause` is held until the
status falls below severe.

| Pace | Power | Link | Records sync | Chunk prefetch | Serving others |
|---|---|---|---|---|---|
| normal | charging | unmetered | on | newest 5 clips per followed author, to the cache cap | on if enabled |
| normal | battery | unmetered | on | first 2 chunks of the newest 3 clips per author | off |
| normal | low battery | any | heads only | none | off |
| any | any | metered | heads only, 10 KB per hour | none | off |
| gentle | any | unmetered | heads only | none | off |
| pause | any | any | none | none | off |

- **Viewing** a tapped clip is allowed at `normal` and `gentle` on any link,
  with a confirmation on `metered` above 2 MB. At `pause` a fully cached clip
  plays and network fetches do not; the card says why.
- **Recording** is refused at `pause` and critical thermal status, offers 480p
  only at `gentle`, and on reaching critical mid-clip stops cleanly and keeps
  the partial file.
- **Data cap** on mobile data (`clips.data_cap_mb_per_day`) defaults to 0.
- **Cache cap** defaults to 512 MiB (128 MiB to 8 GiB). Prefetch stops below a
  free-space floor (default 2 GiB). Own clips are pinned at publish. The store evicts
  the most-replicated packages first, not the least recently viewed, and the
  free allowance is 256 MiB per week, about 40 clips. Phase 0 sets Clips
  eviction and allowance.
- All limits are defaults in a datadir policy file shown by `z23 clips
  status`; the `clips_policy` test feeds every `(pace, power, link)` triple.

<!-- claim: symbol-present node_pace_gentle_sleep_ms engine/jobs/include/jobs/node_pace.h # gentle pace behavior exists for the reducer -->

---

## 5. A flexible API for a changeable UI

The backend serves typed data; the UI decides how to show it. Cards and feed
recipes come from the backend, layouts are user-editable data. Changing the UI
needs no backend release and changing ordering needs no UI release.

### 5.1 One handler, four adapters

```
              z23 clips feed --recipe=follows-chrono    CLI leaf
 UI / agent   loopback JSON-RPC  clips.feed             what the app calls
              GET /api/v1/clips/feed?recipe=...         REST
              MCP tool clips_feed                       MCP
                          |
                          v
              one controller -> one service -> models
```

- **CLI.** `z23 clips ...` are nested leaves of the one binary, declared in a
  new command bundle under `engine/composition/commands` with typed input and
  output schemas, as every ready leaf must have
  (`engine/composition/commands/README.md`). No scripts, no separate programs.
- **JSON-RPC.** The app calls its node over loopback with the datadir cookie
  (`apps/z23android/rpc.c`); Clips adds methods to that path and no listener.
- **REST.** `/api/v1/clips/*` follows the versioned resource convention
  (`/api/v1/messages`, `/api/v1/names`) of
  `engine/controllers/src/api_controller_app_protocols.c`; Clips registers as
  an application protocol with `rest_resource = "/api/v1/clips"`.
- **MCP.** Catalog leaves reach agents through the MCP gateway
  (`tools/mcp/mcp_rpc.c`) with the same schema, so an agent reads a feed and
  publishes with the cards a person sees. The gateway grants no custody,
  consensus or publication authority beyond the leaf's declared policy.
- **Media bytes** use one route that is not a card: `GET
  /api/v1/clips/posts/{id}/media` with `Range`, returning verified bytes
  ([3.4](#34-playback)). It is served on loopback to the node's own app.

All routes are **new**: `GET .../feed` (`clips feed`, a `zcl.feed_page.v1`),
`GET .../posts/{id}` (`clips show`), `GET .../authors/{key}` (`clips author`),
`GET .../posts/{id}/comments` (`clips comments`), `POST .../publish` (`clips
publish`), `POST .../actions` (`clips act`), `GET` and `PUT .../recipes[/{id}]`
(`clips recipe`), `GET` and `PUT .../layouts[/{id}]` (`clips layout`), `GET
.../schemas` (`clips schemas`) and `GET .../status` (`clips status`).

<!-- claim: symbol-present zapp_rpc_call apps/z23android/rpc.c # the app's loopback call exists -->
<!-- claim: symbol-present rest_resource engine/controllers/src/api_controller_app_protocols.c # the REST registry convention -->
<!-- claim: file-present tools/mcp/mcp_rpc.c # the MCP gateway code exists -->

### 5.2 Cards

A card is a typed, versioned JSON object named in the `zcl.<name>.v1`
convention: `zcl.clip_card.v1`, `zcl.author_card.v1`, `zcl.comment_card.v1`,
`zcl.action_card.v1` and `zcl.feed_page.v1` (cards plus a cursor).

```json
{
  "schema": "zcl.clip_card.v1",
  "id": "9c41...",
  "author": {"key": "ab12...", "handle": "k3m9x2tq4w", "name": "Dana"},
  "created_at": 1790000000,
  "caption": "first light", "tags": ["sunrise"],
  "media": {"manifest_id": "91ab...", "thumb_id": "55de...",
            "width": 480, "height": 854, "duration_ms": 14200,
            "size": 1620000, "state": "complete",
            "url": "/api/v1/clips/posts/9c41.../media"},
  "counts": {"reactions": 12, "comments": 3, "reshares": 1},
  "reply_to": null, "reshare_of": null, "flags": [],
  "actions": [
    {"schema": "zcl.action_card.v1", "id": "react", "label": "Like",
     "method": "clips.act", "args": {"op": "react", "target": "9c41...", "reaction": 1}},
    {"schema": "zcl.action_card.v1", "id": "comment", "label": "Comment",
     "method": "clips.act", "args": {"op": "comment", "target": "9c41..."},
     "needs": ["text"]}
  ],
  "fallback_text": "Dana: first light (14 s)"
}
```

- `media.state` is `complete`, `partial` (with `have` and `need` chunk counts),
  `remote` (manifest known, no chunks), `blocked` or `tombstoned`.
- `flags` may include `author_forked`, `chain_gap`, `hidden_by_filter`,
  `blocked_by_list` and `reported`. A filtered card stays available by id with
  its flag; the UI decides whether to show it.
- `actions` are advertised with argument shapes, so a UI can render an action
  it has never seen as a generic button. An action that moves money has
  `"needs_confirm": true` and is never sent without explicit user confirmation
  ([7](#7-money-later)).
- An unknown card schema renders as its `fallback_text`, never dropped
  silently. Cards contain no secrets, key paths or datadir paths.

### 5.3 Feed recipes

A feed recipe is data that selects and orders cards. A closed registry of C23
evaluators in the node interprets it; it carries no code.

```json
{
  "schema": "zcl.feed_recipe.v1",
  "id": "follows-chrono",
  "title": "People I follow, newest first",
  "source": {"kind": "follows"},
  "filters": [{"op": "exclude_flag", "flag": "hidden_by_filter"},
              {"op": "max_age_days", "value": 14}],
  "order": {"by": "created_at", "direction": "desc"},
  "limit": 20
}
```

- **Sources:** `follows`, `authors` (explicit keys), `fof` (friends of
  friends, `depth` 2, `max_authors` cap, built only from follows the owner can
  see), `topic` (a `tags` list over cached posts), `own` and `cached`.
- **Order functions:** `created_at`, `weighted` (a weighted sum over local
  signals: recency, `reactions_from_follows`, `author_affinity`; never a remote
  score) and `shuffle_seeded`.
- Shipped recipes: `follows-chrono`, `own`, `fof-weighted`, `topic`. Users add,
  edit and delete recipes, which are datadir files.
- **Pluggable ordering beyond the registry** is a signed plugin from the
  existing plugin store (`docs/dev/PLUGINS.md`): a confined executable that
  receives candidate ids and local signals on a pipe and returns a permutation,
  with no keys, network or store access. **New**, phase 4.
- Evaluation uses local data only; missing data appears as a card with
  `media.state = remote`. A cursor from an older recipe revision is refused.

### 5.4 Layout recipes

A layout is a user-editable document naming which card fields to show and how
to arrange them. The app renders it with a closed set of native primitives.

```json
{
  "schema": "zcl.layout_recipe.v1",
  "id": "default",
  "screens": {"feed": {
    "container": "pager_vertical", "card": "clip",
    "children": [
      {"type": "video", "field": "media"},
      {"type": "text", "field": "caption", "style": "body", "max_lines": 3},
      {"type": "row", "children": [
        {"type": "action", "id": "react"},
        {"type": "counter", "field": "counts.comments"},
        {"type": "action", "id": "comment"}]}
    ]}}
}
```

Primitives: containers `pager_vertical`, `list`, `grid`; arrangement `row`,
`column`, `stack`; leaves `video`, `image`, `text`, `counter`, `action`,
`avatar`. A layout references card fields by name and actions by id. It cannot
call arbitrary methods, load URLs or run code.

- The app reads the active layout at start and on change; an invalid or
  unsupported layout falls back to the built-in default and says so.
- Layouts that use only known primitives change the UI with no node or app
  release. A new primitive is an app change, and layouts using it fall back on
  older apps.
- A layout can be shared as a Commons package signed by its publisher. It is
  data and carries no executable authority.
- The app builds screens in code through JNI today
  (`apps/z23android/native_ui.c`). Rendering from a layout is **new**: it
  interprets these primitives into the same platform widgets plus a `video`
  surface.

### 5.5 Schemas, versioning and compatibility

- A schema id names its major version. Within a major version a producer may
  add optional fields and a consumer must ignore unknown fields. Removing a
  field, changing a type or changing a meaning is a new major version.
- A request may send `accept: ["zcl.clip_card.v2", "zcl.clip_card.v1"]`; the
  node answers with the first it supports. While v2 is current, v1 is still
  produced for at least two app releases.
- `GET /api/v1/clips/schemas` lists served ids, and each card carries its
  `schema`, so a UI decides before rendering.
- Wire formats are versioned in their own headers and never changed in place.
- Every card schema has a golden JSON fixture, plus negative tests (an extra
  field accepted, a missing required field refused).

---

## 6. Safety

Clips is public by design. The safety model is local choice plus shared
evidence, not a central moderator.

### 6.1 Each node decides

- A node stores only content for an author the owner follows, an object a
  followed author's record references, or a comment on the owner's own posts.
  Unsolicited content has no path into the store. A post by an unfollowed
  author is fetched only when opened, never prefetched, never served.
- The owner can block an author key or content id, delete any object and unpin
  any object at any time. A deletion removes bytes and adds a local block so
  the object is not fetched again.
- A relay run for others sets its own policy; the protocol imposes none.
- A report (kind 14) is a signed claim by a key that names a target and reason. Recipients store it as evidence and may feed local rules; it proves nothing about the content and never deletes anything automatically.

### 6.2 Block lists and local filters

- **Local filters** (caption and tag words, minimum author age) live in the
  owner's policy file and run at ingest and card build time.
- **Subscribable block lists.** An author or organization publishes a list
  (kind 4): a one-file package `list` of sorted 65-byte entries, one type byte (1
  author key, 2 content id) and 64 bytes, at most 4,000 per object. The owner
  subscribes by `(author key, list title)`; the node fetches the newest list
  record and object, verifies both and merges entries into a local deny set.
- Cards show `blocked_by_list` with the list id. Unsubscribing removes that
  list's entries, and an explicit allow by the owner overrides a list. A list
  is advice the owner chose to follow, not a protocol decision.

### 6.3 Known-illegal content

- Before storing or serving an object, a node checks its id and, for
  thumbnails and keyframes, an optional perceptual hash against every
  configured illegal-content hash list. Each list is matched in its own hash
  algorithm over the whole file, thumbnail and avatar, built from staged chunks
  before leaving staging and again before serving. A match refuses the object (`clipnot`
  reason 5), drops stored copies and records a local block.
- Z23 ships no list; lists come from sources the owner configures, and
  obtaining one from a clearinghouse is a legal matter for the operator.
- Limits, stated plainly: an exact SHA3 id matches only identical bytes, so a
  re-encoded clip has a new id. A perceptual hash of a keyframe catches some
  re-encodes, not all. A C23 perceptual hash is **new** and unevaluated, so
  only exact-id matching is claimed until Q2 reports. These checks reduce risk
  and do not guarantee a node never holds prohibited material.
- A node that enables `-clipshost=1` with no list configured prints a startup
  warning. Operators who serve other people's content carry responsibility for
  it in their jurisdiction; serving only one's own fleet's content avoids that.

### 6.4 Spam limits

1. **No unsolicited ingest** (6.1) removes most spam paths.
2. **Rate limits per author** at ingest, defaults 10 posts per hour and 30 per
   day, 600 social records per day, plus records and bytes per peer per minute.
   Excess is dropped and the peer rate limited. Values are policy, shown by
   `clips status`.
3. **Size limits** of section 2 are checked before allocation.
4. **Proof-of-work stamp (optional).** `stamp` is a nonce such that the leading
   `d` bits of `SHA3-512("z23.clips.stamp.v1" NUL ‖ id ‖ stamp)` are zero. A
   node may require `d` for authors it does not follow, such as commenters on
   its posts; the default is 0. Phone cost at `d = 16` is unmeasured (E8).
5. **ZCL stamp (optional, phase 4, direction only).** The sender pays a small
   shielded amount to the recipient with a memo carrying the record id prefix.
   Only the recipient's wallet sees it, under section 7. **New.**

### 6.5 Privacy and metadata exposure

Tor is the default for non-fleet peers and hides IP addresses from other nodes.
A node also running Noise over TCP shows those peers its address under the same
static key, linking it to its onion sessions: one key serves all transports
(`core/modules/net/include/net/v2_identity.h`). Tor does not hide:

<!-- claim: file-present core/modules/net/include/net/v2_identity.h # one static key serves all transports -->

| Observer | Sees |
|---|---|
| A holder you fetch from | which objects you request and when, your Noise static key |
| A holder you subscribe to | the author keys you follow, in `clipsub` |
| Anyone fetching an author's endpoint record | that the key is served by that onion address |
| Any node holding your records | your posts, reactions and comments, public and linkable by key |
| On-path observer | peer addresses, timing, volume; Clips frames move only on Noise sessions |
| A global network observer | timing and volume correlation on circuits |

- **Follows are local by default.** A follow reaches a holder inside `clipsub`
  so it can push heads, but is not published as kind 12 unless the owner opts
  in. Friends-of-friends works only over follows others published.
- Phase 4 evaluates a blinded subscription: the follower sends
  `SHA3-256("ZCLB" ‖ author ‖ period)` and a holder matches only authors it
  already holds, the pattern of the identity layer's blinded keys. **New**,
  unproven.
- Version 1 has no private or friends-only clips; all content is public to
  anyone with the manifest id. Encrypted clips are outside this specification.
- The app writes no clip content to logcat; logs carry ids truncated to 8 hex
  characters and counts.

<!-- claim: symbol-present noisetransport engine/composition/src/args.c # Noise is an opt-in flag, so Clips requires it -->

---

## 7. Money, later

- **ZCL tips** are optional, phase 4. A profile (kind 2) may carry a Sapling
  address of at most 128 bytes. A tip is a normal wallet action built and
  signed by the wallet broker. Its memo may reference the post by the first 32
  bytes of its id, which fits the 32-byte reply field of the ZMSG memo format;
  the reference is a hint, not proof of intent.
- **Custody.** The Clips key is not a wallet key. Clips code never reads,
  exports or uses a wallet key and never spends; spending goes through the
  wallet room under `docs/node/CUSTODY_MODEL.md`.
- **No spending without explicit user action.** A tip is an action card with
  `needs_confirm: true`. The tip leaf is wallet risk, so MCP refuses it; CLI and REST require
  `"confirm": true`, as `app.messaging.send` does, and the app shows amount
  and destination first.
  Defaults are zero: no automatic or recurring tips, no default amount, a daily
  limit of 0. An MCP caller cannot confirm for the user.
- Tips never affect ranking, visibility or any protocol decision.

---

## 8. Phased plan with acceptance tests

A phase ships when its groups pass and its live checks are recorded with
device, build and date. Groups are `tests/harness/src/test_<group>.c`, run with
`make t-fast ONLY=<group>` (`make t-list` lists them). App tests are
host-compiled units in `apps/z23android/tests/`, run by the app's `make test`.
No test uses a live node, a wallet or a peer outside isolated fixtures.

### Phase 0: content layer

The Commons content layer does not carry Clips objects yet. Today its chunk size
is fixed at 1 MiB (`VCS_PACKAGE_CHUNK_BYTES`, enforced when a manifest is
decoded), its ids are SHA3-256, and swarm frames are version 1 with a 32-byte
root and hash, one chunk per WANT. Phase 0: content.v3 with SHA3-512 ids and
per-manifest chunk size, ZPSW version 2, and a caller-priority fetch for
tail-first playback. The store opens whenever Clips is enabled; opening it
grants no hosting. Today the only opener needs `-packagehost`, so publishing
would fail on a default node. Phase 0 also sets Clips eviction and allowance (the free
allowance is 256 MiB per week, about 40 default clips). Groups:
`zcode_content_v3`, `zcode_swarm_v2`.

<!-- claim: symbol-present VCS_PACKAGE_CHUNK_BYTES contexts/commons/modules/vcs/include/vcs/package_manifest.h # chunk size is fixed at 1 MiB today -->
<!-- claim: symbol-present packagehost engine/composition/src/boot_frontend_services.c # the only store opener is gated on -packagehost -->
<!-- claim: symbol-present VCS_PACKAGE_SWARM_VERSION contexts/commons/modules/vcs/include/vcs/package_swarm.h # swarm frames are version 1 today -->

### Phase 1: my clips on my own fleet

Record on the phone, publish to my node, watch on the phone, pinned on my
servers. One author, one fleet, no other peers. Scope: `-noisetransport` in
the app's node start, records and chain, manifest, Clips use of the package
store, publish service, relay pinning over the paired stream,
own-clips feed, media route, record, publish, my-clips and watch screens.

Groups to add:

- `clips_record`: known-answer vectors, sign and verify, chain `seq` and
  `prev`, every limit at 0, max and max+1, every refusal (magic, version, alg,
  kind, reserved flag, trailing byte, bad signature, time window), fork
  detection.
- `clips_manifest`: codec, `chunk_count` consistency, id recomputation, the
  96-chunk ceiling, refusal of a wrong `chunk_size_log2`.
- `clips_store`: a clip is one package; own clips pinned at publish, eviction
  and allowance settings from Phase 0, recovery of a half-written publish,
  chunks surviving a store restart.
- `clips_publish`: fixtures of 1, 262,144, 262,145 and 6.5 MB bytes, signed
  manifest and post, re-read verification, interrupted publish resumes.
- `clips_wire`: the five frame codecs, round trip, every ceiling, truncation at
  every offset, oversize counts, rate limits.
- `clips_relay`: two isolated datadirs over a local stream; the relay
  subscribes, fetches, verifies and pins; a tampered chunk is rejected; the pin
  audit passes and fails correctly.
- `clips_api`: golden JSON for clip, author and feed-page cards; CLI and
  JSON-RPC return identical results.
- `clips_policy`: the 4.7 table over every `(pace, power, link)` triple.
- App units `clips_capture_test` and `clips_player_test`: profile parameters
  and thermal refusal, ranged-read mapping and deadline.

Live checks on the Pixel:

1. Record 15 s at the default profile; the manifest reports 480p H.264 about
   108 KB/s and a stock player plays the file.
2. Publish. `z23 clips show` reports `complete`; the relay reports the post
   pinned; chain `seq` is continuous over three clips and a restart.
3. With the phone offline, read the clip locally. After a passing pin audit
   delete the phone's chunks and replay: the phone fetches from the relay and
   the played bytes match.
4. Corrupt one chunk on the relay's disk; the phone refuses it, reports a bad
   chunk and never plays unverified bytes.
5. Record 60 s at 480p while logging battery and thermal status; at `gentle`
   and `pause` confirm refusal or 480p-only as 4.7 says.

### Phase 2: follows across consenting nodes

A second owner's node follows an author and watches their clips. Scope:
`clipsub`, `clipheads`, `clipget`, `cliprec`, inter-fleet grants, `-clipshost`,
onion fetch, follow list, follower cache and budgets.

Groups to add: `clips_follow` (subscription, head comparison, sync from
`have_seq`, gaps, fork evidence); `clips_peer_policy` (no grant gives `clipnot`
2, `-clipshost` off serves only own fleet, blocked author or hash never
served); `clips_budget_sync` (prefetch honors pace, power, link and cap on a
simulated clock); `clips_multi_holder` (one clip from two holders, one
corrupt: result verified, corrupt holder penalized).

Live checks: (1) node B follows author A with a grant from both owners and B's
phone plays A's new clip within a measured delay; (2) after A revokes the
grant, B's request gets `clipnot` 2 and A serves no bytes; (3) with A's phone
off, the clip arrives from A's relay; (4) on a metered link the data counter
shows heads only; (5) when pace turns `gentle` during prefetch, chunk prefetch
stops within one pace poll interval.

Open decision: whether onion sessions use a separate Noise static key. Once
Phase 1 enables Noise, the linking described in 6.5 can apply to a phone that
also dials over TCP.

### Phase 3: reactions, comments, recipes and block lists

Scope: lane 1 records, delivery to target authors, comment index, feed recipe
registry, layout renderer, lists, reports, local filters.

Groups to add: `clips_social` (codecs, limits, comment delivery and
acceptance, retract, unfollow); `clips_recipe` (each source and order function
over a fixture graph, unknown op refused, cursor stability); `clips_layout`
(valid and invalid layouts, unknown primitive falls back) and the app unit
`clips_layout_test` (primitive set, fallback); `clips_lists` (list
codec, subscribe and unsubscribe, allow overrides list); `clips_schema_compat`
(unknown fields ignored, missing field refused, `accept` negotiation).

Live checks: (1) a comment from node B appears on A's clip on both phones; (2)
editing a layout file moves the actions above the caption with no app update;
(3) switching among chronological, follows-only and friends-of-friends changes
the order on the Pixel; (4) subscribing to a list that blocks a test author
hides the clips, and unsubscribing restores them.

### Phase 4: discovery and tips

Scope: provider records beyond connected peers, topic discovery, blinded
subscriptions, plugin orderers, perceptual-hash evaluation, ZCL tips, stamps,
optional direct links.

Groups to add: `clips_discovery`, `clips_blinded_sub`, `clips_plugin_order`,
`clips_tip` (confirm required, zero default, broker path only, no key read),
`clips_stamp`. Live checks: discover a test author by topic; send a tip on
fixtures only, after an explicit confirm; measure blinded-subscription cost
against a holder with 10,000 authors.

---

## 9. Open questions and risks

Each unknown has an experiment recorded as a dated file in `docs/experiments`;
a result changes the numbers here in the same commit.

| # | Unknown | Experiment | Informs |
|---|---|---|---|
| E1 | Sustained onion throughput for a 4 MB clip | 50 fetches each of a 4 MB and a 7 MB object from a home relay to the phone over onion at different hours; record first byte, completion time, throughput p10, p50, p90 | default bitrate, 720p, start-up buffer |
| E2 | Phone storage caps | Fill a Pixel's app storage to the floor with fixtures; check eviction order, the floor, and that a recording completes or fails cleanly | cache cap, floor |
| E3 | Chunk size versus Tor cell overhead | One 7 MB object as 64, 128, 256, 512 KiB chunks over the same circuits; compare wire bytes and time | the 3.3% assumption, chunk size |
| E4 | Chunk size versus retry cost | The same sizes with a circuit drop every 30 s | chunk size |
| E5 | `AMediaExtractor` on a moov-last MP4 with tail-first reads | Play 20 fixture clips through the ranged route with injected delay | index-to-front step |
| E6 | Encode power and heat | Record 60 s at 480p, 720p, 1080p; log battery percent and thermal status every 5 s | duration cap, 720p at `gentle` |
| E7 | SHA3-512 rate on the phone | Hash 64 MiB in 256 KiB pieces on the Pixel | verification threading, SHA3-512 for chunks |
| E8 | PoW stamp cost | Time 100 stamps at d = 12, 16, 20 on the Pixel | default stamp policy |
| E9 | Hardware AVC encoders on target devices | Probe the codec list on each Pixel generation the owner has | refusing to record without hardware |
| E10 | Relay fan-out | 1, 10, 100 simulated followers fetch one 7 MB clip through a relay's onion service | relay egress budget |
| E11 | A/V sync in the NDK path | 60 s playback on the audio clock; count dropped frames, measure drift | decoder and render approach |
| E12 | Ingest cost of chain and fork checks | Ingest 100,000 records across 1,000 authors on a relay | store indexes, batching |

Risks and questions, each with its experiment:

- **Q1. Legal exposure for relays.** Serving third-party public content has
  operator risk; the mitigations are the opt-in default and hash lists. No
  experiment resolves it; owner and legal review precede advertising
  `-clipshost`.
- **Q2. Perceptual hashing.** Implement a small C23 keyframe hash, measure
  false-match and miss rates on re-encoded fixture clips, and report both
  before claiming more than exact-id matching.
- **Q3. Discovery without an index.** Simulate 1,000 authors over 100 nodes
  with topic and friends-of-friends recipes; report how many followers find an
  author by each path.
- **Q4. Deletion.** A tombstone is advisory. Measure how long it takes to reach
  a ring of 10 test nodes and how many keep the bytes by policy.
- **Q5. Phone as the only copy.** A phone lost before a pin audit loses the
  clip. Inject a phone loss before the audit and record what is recoverable.
- **Q6. One quality per post.** Measure how often a viewer on the E1
  distribution stalls at the default profile before adding multi-manifest
  posts.
- **Q7. Lists concentrate power.** User-test whether owners can name the
  source of a block from card flags.
- **Q8. Provider records for author heads.** Object transfer, accounting and
  storage are the existing swarm and package store. Open: whether the ZCODE DHT
  provider record shape fits author heads. Attempt the mapping against its
  existing tests; if it does not fit, a Clips provider record is new.
- **Q9. Key loss.** One unanchored Ed25519 key on one node ends the identity
  if lost. Walk a zid rotate-and-revoke fixture through a Clips chain and
  confirm followers accept the successor.
- **Q10. Separate Noise key for onion sessions.** One static key serves all
  transports. Measure what a peer that sees both a TCP and an onion session
  can link, and whether a second key breaks grants or the fleet roster.

---

## 10. Where the code goes

### 10.1 Layout

Clips is a product context. This specification does not create the room: the
tree gate rejects an unlisted room under `contexts/`, so the room appears in
the same commit as its first code and its gate edits (10.2).

```
contexts/clips/
  models/        records, manifests, store rows, subscriptions (ActiveRecord)
  services/      publish, sync, relay, budget policy, feed recipes, safety checks
  controllers/   command handlers, JSON-RPC, REST, frame handlers
  modules/       pure codecs and engines with no I/O: clips_codec, clips_wire,
                 clips_recipe
engine/composition/commands/clips.def       the `z23 clips ...` bundle
apps/z23android/                            capture, encoder, player, clips_ui,
                                            hostenv (power and link words)
tests/harness/src/test_clips_*.c            one registered group per file
```

- Frame codecs are pure modules with no socket, filesystem or clock, the split
  the package swarm uses (`contexts/commons/modules/vcs`). The composition
  adapter that already puts `zpkgswm` on the wire
  (`engine/composition/src/boot_zcode_swarm.c`, inbound routing in
  `boot_zcode_swarm_unhosted_frame`) routes Clips magics to them; objects live in the Commons package store.
- Every controller calls one service. Every application write follows the
  ActiveRecord save lifecycle, checks allocations and logs contextual errors
  (`docs/DEFENSIVE_CODING.md`).

<!-- claim: symbol-present boot_zcode_swarm_unhosted_frame engine/composition/src/boot_zcode_swarm.c # inbound swarm routing happens here -->

### 10.2 Ownership notes for `docs/dev/CODEBASE_MAP.md`

This specification adds no room and does not edit
`docs/dev/CODEBASE_MAP.md`. The architecture-tree gate requires the directories
under `contexts/` to equal `PRODUCT_CONTEXTS` in the `Makefile` (wallet,
explorer, naming, messaging, market, commons), so adding `clips` is one change
set that updates together:

1. `PRODUCT_CONTEXTS` in the `Makefile`;
2. `k_product_contexts` in `tools/lint/lintc/gate_doc_index.c`, which a second
   gate keeps equal to the first;
3. the context table and "ten-context target" wording of
   `docs/dev/CODEBASE_MAP.md`, plus a `z23 code room` entry derived from the
   `clips` command branch;
4. `engine/composition/commands/catalog.def` with the `clips.def` bundle, and
   `make docs-api-reference`;
5. the test impact rules in
   `cognition/controllers/include/controllers/agent_impact_rules.def`;
6. `make check-architecture-tree` and the full `make lint` at the tip.

<!-- claim: symbol-present PRODUCT_CONTEXTS Makefile # the context list the tree gate reads -->
<!-- claim: symbol-present k_product_contexts tools/lint/lintc/gate_doc_index.c # the second list that must match -->
<!-- claim: file-present cognition/controllers/include/controllers/agent_impact_rules.def # test impact rules -->

Placing the first code in `contexts/messaging` avoids items 1 to 3 but mixes a
video store into a room scoped to ZMSG workflows. This specification prefers a
separate room because the store, wire messages and API are a distinct feature;
the owner may overrule it, and nothing else here depends on the choice.

The app links neither `core/` nor `engine/` (`apps/AGENTS.md`), so every Clips
operation reaches the node through the loopback JSON-RPC and media route of
5.1.

