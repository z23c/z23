<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Refused second node preserves the owner's boot beacon

## User behavior

A node that cannot acquire a datadir's single-writer lock exits with
`BOOT_DATADIR_LOCKED`. It must not replace the running node's readiness beacon.
The beacon's `serving` state is useful only when its publisher owns the
datadir.

## Failure and fix

Before the change, `boot_step_select_chain_and_datadir()` initialized the
beacon before attempting `boot_datadir_lock_acquire()`. In a disposable Linux
regtest datadir, a process holding `zclassic23.pid` prevented a second native
node from starting, but the second node still changed `boot_status.json`.
The fixture recorded SHA-256
`18e13cfccee57632b9b55af637d41679b38ad8a3173bd37bd553a898ffb2e83f`
before the attempt and
`06cb2933ea56c29f6e8e32eba5da3eddf0999073531cee87ec54553dd61f2835`
after. The second node exited 1 with `BOOT_DATADIR_LOCKED`.
The failing native executable came from parent candidate
`ef0a55dd12a8a636c2fb93620e2f80b69f6cd164`; its SHA-256 was
`5f08ff7292d96d02b35fa20fa549661be623b3a679b134ecbd17aa12742e539a`.
The saved failure log is `/tmp/z23-boot-owner-parent-fail-before.log`
(SHA-256 `1d6c2329d4d5168be63fb91733085269b9325ae4957ba9cdb63003570a116747`).

`boot_datadir_lock_acquire()` now initializes the beacon only after the lock
and PID record succeed, before storage probes. Rejected callers leave the
existing beacon untouched. The same fixture uses the real `z23` binary and
separate regtest ports; it does not claim chain synchronization or GUI behavior.

## Reproduction

```sh
make -j4 z23 zcl-rpc jsonq
tools/scripts/boot_owner_beacon_regression.sh
make -j4 t-fast ONLY=boot_datadir_lock
```

The regression requires native Linux with GNU `flock`.

## Measured result

On native Linux, the fixed `z23` binary (SHA-256
`c299db85c077a727d2a1e5a517da210fbf54936c13802d3576ff18b3666c77c4`)
passed the same fixture in 1.536 s: the second node refused the lock and the
owner beacon hash remained unchanged. The saved pass log is
`/tmp/z23-boot-owner-pass-after.log` (SHA-256
`086b35f9fe5c02515d2d86238a4cc65035dbcd70bc0f04a0d94db8d9ee1310c7`).
The registered `boot_datadir_lock` group passed 1/1 with zero failures and
zero skips; its final test body took 847 ms under concurrent host load.
`make lint-fast` passed 32/32 gates. The compiler was GCC 16.1.1 on an
AMD Ryzen 7 PRO 8840U, measured 2026-09-23 UTC. This tests native Linux
startup refusal. No macOS, Windows, GUI, or chain-sync result is inferred.
