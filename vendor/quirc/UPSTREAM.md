# quirc source provenance

Upstream: https://github.com/dlbeer/quirc
Commit: 927d680904dc95fdff4cd9d022eb374b438ff8f2

SHA-256 of original upstream files:

- `lib/decode.c`: `d4468c55ecd0d2f905a6813513708005e6d609ef0a3d32a17673313c7552a7c1` <!-- doc-path-ok: upstream repository path -->
- `lib/identify.c`: `ae858d86adcb12db80ad01f6d941cc2247fb5970abf0754f24dca027ede2ba99` <!-- doc-path-ok: upstream repository path -->
- `lib/quirc.c`: `0294b6c56f8c021b256c4c153d70483368164c6cf0cce643e1b6be03ed3585c0` <!-- doc-path-ok: upstream repository path -->
- `lib/quirc.h`: `49660ea710add2d6f304a1323f53190f5a2bf34db4dd160d633db0c3f22bfba5` <!-- doc-path-ok: upstream repository path -->
- `lib/quirc_internal.h`: `e383ed1a0ca70c07b0530d76bfeb6bd5525efda182589f48c978921a9e54676b` <!-- doc-path-ok: upstream repository path -->
- `lib/version_db.c`: `6764aa2f245085080e1e5cefd9dcd59b9727718a0d4606956e0502a57f5dff30` <!-- doc-path-ok: upstream repository path -->
- `LICENSE`: `a70ef3ea032998eead2e2c7573a170a809eae08e3ca134611f707eda5932c8a9`

Patch: `identify.c` marks an unused parameter and casts two nonnegative index comparisons. `quirc.c` casts a nonnegative size comparison. These changes address strict compiler warnings. The ISC license is preserved in `LICENSE`.

Deviation: `quirc.c` skips the `memcpy` in `quirc_resize()` when `min` is zero, because `memcpy` from a null source is undefined in C23 and a fresh `quirc_new()` has a null image, reached through `quirc_resize()` at camera start.

Deviation: `identify.c` `perspective_map()` rounds each coordinate through `coord_round()`, which maps NaN and values beyond plus or minus 2^13 to plus or minus 2^13, because converting an out-of-range float to `int` is undefined; in-range values round as before. Pixel reads are checked against the frame in `read_cell()`, `fitness_cell()` and `find_alignment_pattern()`, which returns early when a point is off the frame. The unchecked callers are the capstone center in `identify.c` (`capstone->center`, used in int arithmetic in `record_qr_grid()`) and the corners written by `quirc_extract()`; they never index pixels, and the 2^13 limit keeps the products of their differences inside int, but that is an argument about bounds, not a proof for every expression. Frames up to 8192 px a side are unaffected.

Deviation: `identify.c` `fitness_all()` reads `quirc_version_db[version]` only after the version range check, so a grid larger than version 40 no longer forms an out-of-range array address.
