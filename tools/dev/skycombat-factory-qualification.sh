#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton. Licensed under Apache-2.0.
# Reproduce the SkyCombat aircraft package build boundary in isolated stores.
set -euo pipefail

if [[ $# != 1 ]]; then
    printf 'usage: %s NEW_OUTPUT_DIR\n' "$0" >&2
    exit 2
fi
root=$(cd "$(dirname "$0")/../.." && pwd -P)
output=$(realpath -m "$1")
[[ ! -e $output ]] || { printf 'output exists: %s\n' "$output" >&2; exit 2; }
package="$output/pkg"
mkdir -m 700 -p "$package/include/sky_combat/models" "$package/src" \
    "$package/tests" "$output/bin"
cp "$root/apps/skycombat/src/models/aircraft.c" "$package/src/"
cp "$root/apps/skycombat/include/sky_combat/models/aircraft.h" \
    "$package/include/sky_combat/models/"
cp "$root/vendor/raylib/src/raylib.h" "$root/vendor/raylib/src/raymath.h" \
    "$package/include/"
cp "$root/LICENSE" "$package/LICENSE"
cp "$root/vendor/raylib/LICENSE" "$package/RAYLIB_LICENSE"

cat > "$package/zcode-package.json" <<'EOF'
{
  "schema": 1,
  "name": "qualification/skycombat-aircraft",
  "semver": "0.1.0",
  "language": "c23",
  "license": "Apache-2.0",
  "include_dir": "include",
  "source_dir": "src",
  "dependencies": []
}
EOF
cat > "$package/README.md" <<'EOF'
<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# SkyCombat aircraft qualification

This isolated package copies SkyCombat's aircraft source and public header.
Vendored raylib headers retain their zlib license in RAYLIB_LICENSE.
EOF
cat > "$package/src/raymath_impl.c" <<'EOF'
/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#define RAYMATH_IMPLEMENTATION
#include "raymath.h"
EOF
cat > "$package/tests/test_aircraft.c" <<'EOF'
/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include "sky_combat/models/aircraft.h"
#include <math.h>
#include <stdio.h>

int main(void)
{
    aircraft_t *a = aircraft_create((Vector3){0.0f, 200.0f, 0.0f});
    if (!a) return 1;
    aircraft_update(a, 0.0f, 0.0f, 1.0f);
    const float z = a->position.z;
    aircraft_boost(a, 1.0f);
    const float speed = a->speed;
    a->position.x = WORLD_HALF_SIZE + 1.0f;
    aircraft_wrap_position(a);
    const float x = a->position.x;
    aircraft_destroy(a);
    if (fabsf(z - 60.0f) > 0.001f ||
        fabsf(speed - 110.0f) > 0.001f ||
        fabsf(x - (-WORLD_HALF_SIZE + 1.0f)) > 0.001f) {
        fprintf(stderr, "flight=%.3f boost=%.3f wrap=%.3f\n",
                (double)z, (double)speed, (double)x);
        return 1;
    }
    printf("flight=%.3f boost=%.3f wrap=%.3f\n",
           (double)z, (double)speed, (double)x);
    return 0;
}
EOF

for binary in package-factory zclassic23 zclassic23-package-sign \
    zclassic23-package-verify jsonq; do
    cp "$root/build/bin/$binary" "$output/bin/$binary"
done
sha256sum "$output/bin/"* > "$output/executables.sha256"
sha256sum "$package/src/aircraft.c" \
    "$package/include/sky_combat/models/aircraft.h" \
    "$package/tests/test_aircraft.c" > "$output/source.sha256"
cc -std=c23 -Wall -Wextra -Werror -pedantic -I"$package/include" \
    "$package/src/aircraft.c" "$package/src/raymath_impl.c" \
    "$package/tests/test_aircraft.c" -lm -o "$output/test-aircraft"
"$output/test-aircraft" > "$output/test.log"

"$output/bin/zclassic23-package-sign" --generate "$output/publisher.key" \
    > "$output/publisher.pub"
pubkey=$(cat "$output/publisher.pub")
factory_exit=0
{ TIMEFORMAT='%R %U %S'; time "$output/bin/package-factory" run \
    --package "$package" --publisher-key-file "$output/publisher.key" \
    --publisher-pubkey "$pubkey" --store-a "$output/store-a" \
    --store-b "$output/store-b" --report "$output/report.json" \
    --signer-seed-file "$output/admission.seed" --bin-dir "$output/bin" \
    --fast-cache "$output/cache" > "$output/factory.log" 2>&1; } \
    2> "$output/factory.time" || factory_exit=$?
[[ $factory_exit != 0 && -f $output/report.json ]] || exit 1
[[ $("$output/bin/jsonq" get ok < "$output/report.json") == false ]] || exit 1
grep -q 'BUILD_NOT_INSTALLABLE: verdict build-fail' "$output/factory.log"
sha256sum -c "$output/executables.sha256" > "$output/executables-verified"
printf 'local_test=%s factory_exit=%s report_sha256=%s\n' \
    "$(cat "$output/test.log")" "$factory_exit" \
    "$(sha256sum "$output/report.json" | cut -d' ' -f1)"
