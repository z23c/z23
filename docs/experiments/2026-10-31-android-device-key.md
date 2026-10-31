<!-- Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 -->

# Android device key and screen protection

Date: 2026-10-31. Source base: `0c02d98643` plus this change. Device: Pixel 3,
API 35, arm64. Package: `org.z23.voicepreview` (debuggable preview, never runs a
node), built with `make preview-apk DEVKEY_PROBE=ON`. Production
`org.z23.nativeapp` was not touched. Thermal status read 2 before every phone
step of the first run.

## What was built

- `device_key.c` (policy and blob file, host-tested), `device_key_jni.c`
  (AndroidKeyStore backend, plain `startActivity` for the credential screen),
  `secure_window.c` (FLAG_SECURE, and native dropping of obscured motion events
  in the app input queue before any screen sees them). No Java class.
- Key: AES-256-GCM, authentication required with a 30 s window (device
  credential or strong biometric), unlocked device required, not invalidated by
  biometric enrollment, StrongBox first, secure hardware as the reported fallback.
- Blob: `ZDK1`, IV length, sealed length, 12 byte IV, 48 byte sealed secret
  (66 bytes), mode 0600, temporary file plus fsync plus `renameat2` with `RENAME_NOREPLACE`
  (never replaces an existing blob; Android forbids `link()` for apps) plus
  directory fsync. The cipher binds the AAD
  `z23.wallet.device-key.v1`.

## Host proof

`make -C apps/z23android test-devkey` (fake keystore behind the function table):
no secure lock screen refuses before any key is created; StrongBox first, with
fallback reported and only for StrongBox being unavailable; a software-only key
this call created is deleted and refused, a key found in the keystore never is;
round trip, blob shape, mode and absence of the secret from the blob;
needs-authentication, invalidated and missing-key results with the caller's
buffer zero; a blob present while the key is gone reports invalidated and no
replacement key is created (the fake keystore gives keys an identity, so a
replacement key fails authentication of the old blob); an invalidated key
reported by the key lookup is passed through; an existing blob never replaced,
including one that appears after the existence check (the fake's seal creates
the path, and the test asserts `exists` and unchanged bytes); truncated,
extended, wrong-magic and tampered blobs corrupt; a failing random source and a
store into a missing directory (an open failure only) leave no file; the Java
exception chain mapping (`zapp_devkey_classify_chain`): an
`UnrecoverableKeyException` is invalidated only without a cause, any chain that
carries a cause or an unrecognised class is an error, and only
`StrongBoxUnavailableException` selects the fallback. The window gate drops
obscured and partially obscured motion events and the rest of their gesture
while protection is on, lets a clean cancel through so a cut gesture disarms,
counts each cut gesture once for the screens to read, keeps a gesture in progress
dropped when protection ends or the window is destroyed, passes everything
otherwise, and a dropped tap arms nothing on a model screen that arms on DOWN and acts on
UP, as the shell does.

Mutants, each of which aborts the tests while the unmutated control passes.
Original fourteen: secret kept on error in wrap, secret kept on error in unwrap,
overwrite, no lock check, missing key not invalidated, mode 0644, software
accepted, StrongBox not tried first, fallback unreported, trailing bytes
accepted, needs-authentication demoted, header lengths unchecked, short-circuited
window calls, window protection never cleared. Added with the review fixes
(eleven): `rename` in place of the no-replace rename, no obscured-event drop, a
cut gesture completing, the gate never armed, prepare before the blob check,
prepare creating a key over an existing blob, invalidated hidden as error, a
found key deleted, a wrapped `UnrecoverableKeyException` read as gone, any
StrongBox failure falling back, an unrecognised chain read as StrongBox
unavailable. Added with the delta review (five): a clean cancel dropped, protection
ending mid-gesture letting the UP through, no count of cut gestures, a count of
every event, and the causeless "Key algorithm unknown" form read as a lost key.
The Java exception classes themselves are matched in
`device_key_jni.c` and are exercised only on a device.

## Phone measurements

| Step | Result |
|---|---|
| `prepare` (create key) | `ok level=strongbox strongbox_fallback=0` |
| `roundtrip` without recent authentication | `needs_authentication`, credential screen shown (window `BiometricPrompt`) |
| Back pressed, retry on resume | `needs_authentication after_confirm`, no blob file created |
| `secure off` screenshot | 89092 bytes, normal content |
| `secure on` screenshot | 14050 bytes, black frame; `dumpsys window` flags show `SECURE` only in this run |

The credential screen itself also screenshots black, so it is not evidence for
the app flag; the `secure off` and `secure on` pair is.

### Review-fix run

Date 2026-10-31, Pixel 3 (API 35), `org.z23.voicepreview` only, thermal status 1
before and after, no node started by the probe. Build: `make preview-apk
DEVKEY_PROBE=ON`, signed with `lnx-cx1-b/build/android-preview/development.keystore`,
NDK `-Werror`.

| Step | Result |
|---|---|
| `store` (production `renameat2` no-replace path with a stand-in keystore) | `store ok first=ok size=66 race=exists size=10 tmp_left=0` |
| `prepare` (key already present) | `ok level=strongbox strongbox_fallback=0` |
| `wrap` without recent authentication | `needs_authentication confirm_started=1`, window `BiometricPrompt` |
| Back pressed, retry on resume | `needs_authentication after_confirm`, no blob file in the app files directory |

The `store` line shows the no-replace store works under the app seccomp filter and
SELinux policy of this device. AOSP `app_neverallows.te` forbids `link()` for apps, which
is why the store no longer uses it; `link()` itself was not tried on the device. A fresh
blob is written (66 bytes), and a blob that appears after the existence check is refused with `exists` and
keeps its 10 bytes, with no temporary file left behind.

## Not proved

- A wrap and unwrap round trip after authentication, including the real
  `renameat2` store of a sealed blob: the owner must enter the PIN or biometric
  on the confirm screen, then the probe retries on resume. Not done in the
  review-fix run because the owner was away.
- Permanent invalidation (removing or changing the lock screen) on a device.
- A causeless `UnrecoverableKeyException` with any message other than "Key algorithm
  unknown" still reads as invalidated; the message text is taken from the review and
  was not observed on a device.
- Obscured-touch dropping on a device: the rule is host-tested and wired into the
  app input queue, but no overlay was driven over a running wallet screen.
- Real exception classes from AndroidKeyStore: the chain mapping is host-tested
  on class kinds, not against live keystore failures, and a lost key (lock
  screen removed) was not produced on the device.
- Java byte arrays are zeroed after use, but earlier copies left by a moving
  garbage collector, the keystore service and binder buffers, and the provider's
  internal cipher state cannot be cleansed from C.
- The preview package carries a different signing key from
  `build/android/recovery/20261029/development.keystore`
  (`INSTALL_FAILED_UPDATE_INCOMPATIBLE`); the lane's
  `lnx-cx1-b/build/android-preview/development.keystore` matched it.
