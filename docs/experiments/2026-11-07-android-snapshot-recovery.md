<!-- Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 -->

# Android snapshot recovery acceptance

The isolated snapshot recovery group exercises the existing precommit pool
rollback, committed pool recovery and guarded install fixtures before and after
the durable marker. Each case waits for the fixture's
handshake, kills its child, then checks the next process's recovered wallet and
install state. It uses synthetic test data and never opens an application or
operator datadir.

<!-- claim: symbol-present test_snapshot_install_recovery tests/harness/src/test_consensus_state_snapshot_install.c # isolated recovery group -->
<!-- claim: symbol-present android-snapshot-recovery-device platform/modules/platform/tests/android_acceptance.mk # explicit Android device test -->

The Android runner is built separately from device dispatch. The runner retains
the fast harness's complete object, header, library and source-epoch checks;
whole-suite executable tools are not required by this focused group. Confirm
its host build-needs selection is empty before dispatch.

```sh
make ZCL_TARGET=android-arm64 android-snapshot-recovery-build
make -f platform/modules/platform/tests/android_acceptance.mk \
  ZCL_TARGET=android-arm64 android-snapshot-recovery-device \
  BIN_DIR=<absolute-runner-directory> BUILD_DIR=<absolute-receipt-directory> \
  ADB=<absolute-adb-path> ANDROID_SERIAL=<serial> EXPECTED_RUNNER_SHA256=<sha256>
```

Use the host's build admission and installed Android NDK. The explicit device
target creates a private directory under `/data/local/tmp`, retains its runner
and group logs on the host, and removes that directory only after all eight
recovery assertions pass. It compares the device runner's SHA-256 to the host
artifact before execution, checks the ELF interpreter, and rejects runtime
dependencies outside the Android system library allowlist before dispatch.
A failed attempt retains its device directory for
inspection. This test does not install an APK or access an existing wallet.
The device target is compile-free. Supply the qualified remote build's runner
and SHA-256; record the corresponding source and build receipt separately.

## Device result

On 2026-11-07T03:51:11Z, a Pixel 3 with Qualcomm SDM845 and Android API 35
ran the exact recovery group using Android NDK r30 Clang 21.0.0 targeting
AArch64 API 35. All eight recovery assertions passed. The cold run completed
in 7.2 seconds with one group run, zero cached groups, failures, self-skips,
unobserved legs or load-flaky results. Exact selection reported one group and
zero execution or cache probes before dispatch. The host build-needs query
for this group returned no external executable requirements.

The tested runner SHA-256 was
`fb1b9d4518d229907060ad94c844b5ef1cb37a7e4fa2f6ebd38567c2dec024a9`;
host and device hashes matched before execution. Its ELF interpreter was
`/system/bin/linker64`, with only `libc.so`, `libm.so` and `libdl.so` dynamic
dependencies. The captured device log SHA-256 was
`529ef74f201df3005d688be6b32c8e4f7d7b56b07198c5502a0eeda85fd0eab4`.

The source was commit `de15463062da7198917a0beab08fc68211950732` plus the
reviewed recovery changes, recorded by source patch SHA-256
`0ed9d4463ea112895fbce331d5b525f3b930b8221089d5d69abd401d2d1176ac`.
The successful build log SHA-256 was
`39a3d5317c19d6054ae85026c6a4f5f73ba29192736304688fd1b90d1b7239e2`.

The first dispatch wrapper rejected its evidence collection after the runner
passed: successful execution had left no child logs in the pulled directory.
All eight assertions and the strict suite verdict were present in the retained
verbose aggregate log. The collector now checks that authoritative log; the
existing device result was independently reviewed without repeating the test.

This proves synthetic interrupted-install recovery on Android. It does not
establish production snapshot trust, live-wallet migration, or final release
qualification. Those require their own source-bound evidence.

## Host build classification

The standalone-tool gate recognizes this runner as Android-only
when a complete top-level Android guard connects the public target,
published binary and candidate rule. Isolated fixtures reject missing or
misbound targets, inactive or unclosed guards, definitions and continued lines.
This declaration check does not replace the Android build and device results.
