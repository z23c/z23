<!-- Copyright 2026 Rhett Creighton - Apache License 2.0 -->

# Windows VCS checkout cross-compilation

## Intent

Remove the five fail-closed Windows placeholders that prevented a Windows node
from storing, traversing, reconstructing, and checking out a verified source
package. Preserve the POSIX behavior and refuse Windows reparse-point traversal.

## Environment

- Local time: `2026-08-29T16:37:45-04:00`
- UTC: `2026-08-29T20:37:45+00:00`
- CPU: AMD Ryzen 7 PRO 8840U with Radeon 780M Graphics
- Cross-compiler: `x86_64-w64-mingw32-gcc (GCC) 16.1.0`

## Method

Each requested translation unit was checked independently. `INCLUDES` contains
the tracked header directories and their public `include` parents.

```bash
INCLUDES=$( {
    rg --files -g '*.h' | sed -n 's|/include/.*|/include|p'
    rg --files -g '*.h' | sed 's|/[^/]*$||'
} | sort -u | sed 's|^|-I|' | tr '\n' ' ')

for FILE in \
    lib/vcs/src/package_store.c \
    lib/vcs/src/package_store_io.c \
    lib/vcs/src/source_package_checkout.c \
    lib/vcs/src/vcs_devloop_mirror.c \
    lib/vcs/src/vcs_walk.c
do
    x86_64-w64-mingw32-gcc -std=c2x -fsyntax-only \
        -D_WIN32_WINNT=0x0A00 -DWINVER=0x0A00 \
        -D_POSIX_C_SOURCE=200809L $INCLUDES "$FILE"
done
```

The same five commands also passed with
`-Wall -Wextra -Werror -pedantic`.

Native regression groups were run through the registered test runner:

```bash
make -j"$(nproc)" t-fast ONLY=zcode_store
make -j"$(nproc)" t-fast ONLY=vcs_core
make -j"$(nproc)" t-fast ONLY=zcode_dev_objects
make -j"$(nproc)" t-fast ONLY=vcs_devloop
```

## Result

All five MinGW C2x checks passed. All four native groups passed with one group
run, zero failures, and zero self-skips per invocation. This proves Windows
compile coverage and unchanged native behavioral contracts. Native Windows
runtime execution was not available in this experiment and is not claimed.
