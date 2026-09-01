# zclassic23/codec

Allocation-free reader and writer cursors over caller-owned buffers. The v1
surface covers raw bytes, fixed-width little-endian integers, and bounded
`u16`-length byte/string fields. Errors are sticky; every failed operation is
atomic, and reader finish rejects trailing data.

This deliberately excludes varints, CompactSize, JSON, allocation, overlay
PUSH encoding, and consensus or wallet codecs. It depends only on the exact
`zclassic23/base` root in `zcode-package.json`.
