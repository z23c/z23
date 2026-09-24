<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# SkyCombat executable package platform boundary

Date: 2026-09-24. Host: AMD Ryzen 7 PRO 8840U, GCC 16.1.1 20260430,
`-std=c23`. The factory executable SHA-256 was
`e59a8c7c42e0fedfaa41e7ad0f4ba12bda179aa90572b2254cbb453ea578c1ca`.
The independent [complete-game build](./2026-09-24-skycombat-fullgame-peer.md)
reproduced the owner's accepted executable locally and rendered on a GCC 14
peer. This experiment tests whether the real Commons factory can admit an
executable with one of the game's required platform link symbols. It changes
neither the verifier's system-library allowlist nor its acceptance gate.

## Native project preflight

`zcode project inspect` on the frozen complete-game source archive refused
`package-metadata: missing zcode-package.json; initialization: build-recipe:
recipe: sources-empty`. A read-only `zcode project init plan` also refused
`build-recipe: recipe: sources-empty`. The ordinary C23 package format requires
root `include/` and `src/` directories; the accepted game has nested app and
vendor paths. Its unchanged Makefile links X11, Xrandr, Xi, Xcursor, GL, libm,
pthread, and dl. A package-shaped representation and a bounded platform build
recipe are still needed before an exact full-game candidate can pass the
Commons journey.

## Executable counterexample

The committed fixture keeps the package metadata, marker library, test, and
recipe identical. Only `app/main.c` changes. One version calls `XOpenDisplay`
and compiles locally with `-lX11` under strict C23 flags. The other calls the
package's marker library and needs no platform library. Both use fresh isolated
publisher keys and store pairs. The script runs the ordinary two-store factory
and checks the verdicts without bypassing a gate:

```bash
make -j8 z23 zclassic23-package-sign zclassic23-package-verify \
  tools/package-factory build/bin/jsonq
tools/dev/skycombat-platform-link-control.sh \
  test-tmp/skycombat-platform-control-20260924 build/bin
```

| Item | X11 program | Plain program |
| --- | --- | --- |
| Program source SHA-256 | `d7ab64d9c19ab22c7e8e2383a90fd1dea40389fadbb9276c17625d4f9200af50` | `d0e423a0683b30d1cf7b0f4a1a9f90362725e64de36edd57e81eddb18da66f71` |
| Package root | `d524a0dbb6019d4a2f39095ea704708912b53182822a0aaed20486d394ff0531` | `82f849ca78fe628d2a799b6f840ac16e59f4cfe0995ba5ee2c3e2b404d153a80` |
| Recipe root | `f2b46cad6b1035b8f82c8e92258e15e95a69ef6e0d4f69bc0ac3f6ec24985443` | Same |
| Factory verdict | `BUILD_NOT_INSTALLABLE: verdict build-fail (test exit 0)` at first `add_commit` | Passed both confined builds, both reproductions, verification, and self-screened admission |
| Two-store reproduced | 0/2 | 2/2, same quick and standard receipt roots |
| Factory wall | 927 ms | 4,371 ms |
| Report SHA-256 | `16cc95a2d0209e58e89c09d7fe3d9912a684aca148c6acbecebc26a52aa8536f` | `4835ede65f0986e0c0336761560956ea157c3fc38eaeac0369b6afe2138c6751` |

The fixture script SHA-256 is
`5c3a774d77b78758b6b9325d2d7db8eab3d0a9d4a76480eab1dfdf969e66651b`.
The plain control's quick receipt root was
`8b80a135dc21c4911fb2ae97322ceffbda1ab0c25474ca7e966fc7ac602a53d1`;
its standard root was
`55d85adb29fdcc6511b87ae84980f5ae8b09dece4f6e13b22457014a67777464`.
The factory reported `durable_hosting=unavailable_offline` even for the
passing control. Its local fast-cache hits speeded repeated confined work but
are not independent-operator reproduction or release acceptance.

The paired result isolates the platform dependency as the cause of this
fixture's build refusal. The factory log exposes the build verdict, not the
child compiler's exact diagnostic. The native project inspector reported no
allowed system libraries for the fixture, and the recipe's current allowlist
has libc, libm, and pthread only. The accepted game needs X11 and OpenGL in
addition. This evidence does not imply that merely adding `-lX11` would make
the full game package safe, portable, or accepted: the complete dependency and
confinement policy still needs its own owner-approved design and proof.

No local node-health before/during samples were taken for this short isolated
control. The earlier factory-under-node-load experiment remains the separate
bounded observation; this run makes no node-health claim. No DEV or full
acceptance receipt was created.

## Release-critical continuation

The SkyCombat and Commons package owners need one exact full-game candidate
whose source-to-executable identity matches the accepted preview and whose
platform dependencies are declared and qualified under receiver policy. The
current aircraft-only `libm` recipe is a separate component control. Until
the complete game can pass its real confined build and local acceptance,
neither that component nor this matched link fixture is a game release.
