# zdogview

Integer 3D view of a verified `zdogfight` replay, in strict C23.

This is the hosted Arena picture: any node can fetch, confined-build, and
independently reproduce the same framebuffer bytes. Same replay in, same
PPM out. No raylib, no OpenGL, no heap in the library, no clock.

The package re-simulates a canonical `ZDOGREPL` stream with the integer
match core and refuses anything whose final state does not re-derive
exactly. It then projects the live match with integer isometric math:
seed-derived city (via `zprng`, the same mix the local viewer uses),
oriented planes, shot tracers, kill bursts, and a score/clock HUD.
Pixels never write match state.

```c
int zdogview_verify(const uint8_t *buf, size_t len, zdogview_verified *out);
int zdogview_seek(const uint8_t *buf, size_t len, const zdogview_verified *v,
                  uint64_t tick, zdog_match *out);
void zdogview_render(const zdog_match *m, zdogview_frame *out);
void zdogview_render_scene(const zdog_match *m, uint64_t seed,
                           const zdogview_kill *kills, unsigned num_kills,
                           zdogview_frame *out);
```

`zdogview verify <replay>` prints the outcome and the package FNV-1a/64
state checksum. `zdogview render <replay> --out frame.ppm` writes one
320×180 P6 PPM of the full scene. A local raylib window is not part of
this package; it is an optional display of the same verified match, and
it composites this framebuffer as the hosted C23 view.

Depends on `zdogfight/zdogfight` and `zprng/zprng`.
Copyright 2026 Rhett Creighton. Apache-2.0.
