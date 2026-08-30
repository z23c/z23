<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Identity-pinned direct mesh route

## Intent

Allow a paired-machine status request to acquire one direct route without
treating endpoint discovery as authority. No private status frame may leave
until the live Noise static and unique active ZID delegation match the local
pairing.

## Environment

- Local time: `2026-08-29T17:18:49-04:00`
- UTC: `2026-08-29T21:18:49Z`
- CPU: AMD Ryzen 7 PRO 8840U with Radeon 780M Graphics
- Native compiler: `gcc (GCC) 16.1.1 20260430`
- Windows cross-compiler: `x86_64-w64-mingw32-gcc (GCC) 16.1.0`

## Method

The registered behavioral groups ran through the canonical runner:

```bash
make -j"$(nproc)" t-fast ONLY=mesh_route
make -j"$(nproc)" t-fast ONLY=mesh_status_wire
make -j"$(nproc)" t-fast ONLY=command_registry_catalog
make -j"$(nproc)" t-fast ONLY=native_api_contract
make -j"$(nproc)" t-fast ONLY=connman_addnode_fallback
make -j"$(nproc)" t-fast ONLY=zcode_dht_service
make lint-fast
```

Every changed production translation unit was checked independently with
strict MinGW C2x syntax diagnostics. `INCLUDES` contains tracked header
directories and their public `include` parents.

```bash
INCLUDES=$( {
    rg --files -g '*.h' | sed -n 's|/include/.*|/include|p'
    rg --files -g '*.h' | sed 's|/[^/]*$||'
} | sort -u | sed 's|^|-I|' | tr '\n' ' ')

for FILE in \
    config/src/boot_mesh_route.c \
    config/src/boot_zcode_dht_reachability.c \
    config/src/boot_mesh_status_requester.c \
    config/src/boot_mesh_status.c \
    config/src/boot_mesh_status_refresh.c \
    config/src/boot_mesh_status_rpc.c \
    config/src/boot_mesh_machines.c \
    config/src/boot_mesh_machines_rpc.c \
    tools/command/native_mesh_command.c
do
    x86_64-w64-mingw32-gcc -std=c2x -fsyntax-only \
        -Wall -Wextra -Werror -pedantic \
        -D_WIN32_WINNT=0x0A00 -DWINVER=0x0A00 \
        -D_POSIX_C_SOURCE=200809L $INCLUDES "$FILE"
done
```

## Result

`mesh_route` passed seven cases with zero failures and zero skips. It proves
resource deferral consumes no attempt, an admitted route enters the existing
connman queue with Noise required, connecting state does not redial, wrong
Noise identity and plaintext completion fail terminally, a matching Noise
session acquires without another dial, three submissions remain bounded until
the fixed deadline, and abandoned slots are reclaimed. `mesh_status_wire`
passed twelve cases with zero failures and zero skips, preserving pairing,
delegation, session, replay, revocation, fleet, and resource decisions.
The command catalog, native API contract, connman fallback, and ZCODE DHT
service groups each passed with one group run, zero failures, and zero skips.
All 23 `lint-fast` gates passed.

All nine MinGW checks passed. The shared boot header now includes Winsock before
any Windows header, removing the strict cross-compile ordering warning exposed
by this experiment. No native Windows runtime, onion fallback, or independent-
host status receipt was measured, so none is claimed.
