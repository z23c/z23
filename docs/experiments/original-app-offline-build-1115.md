<!-- Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 -->

# Original signed app: offline build parent

On 2026-11-15 an automated native UI received a signed app into a fresh
profile and the installed runtime planned and built that received copy. The
share SHA-256 was `6a714436ba1a66b98339cfeddbb68dbdf634fd4dea9d335db6fad663e1cb5cc9`;
the package root was `01c23f95253ea5113c25d9b2f0026b53e1a0e5d4cfff15a186b58ef55cf98e0a`.
The publisher fingerprint, release and parent release were checked against
independent pins in the test. Receive creates a fresh local history version;
this run used `b611cedc88e14018f6eaecd7defb28f543279959fdf984925d6037aad4e26d15`.
The plan and commit both bound that version and the same package, environment,
dependency and closure roots. The commit reported `cache_hit=false`,
`make_ran=true`, `executed=false` and image SHA3-256
`baf203b90f1f4149d93812ebee99695fec709aaacb5913e775fc52032f4ea0de`.
The test loaded the native build record and verified its image binding.

Before each build call, the child closed inherited nonstandard descriptors,
installed `no_new_privs` and a seccomp filter, and verified that IPv4 and IPv6
socket creation returned `ENOSYS`. Socket, socketcall where available, and
io_uring setup were denied across exec and descendants. A sealed system
trampoline launched the installed runtime at its installed path. The existing
supervisor reported clean completion with no children for both calls. The
native compiler confinement remained `landlock`. This proves the observed
build under those restrictions, not a human acceptance or offline preview.

The cold registered test passed one group, with no cached groups or skips, in
60.3 seconds. It used the real installed release and kit, a private disk test
root with trusted ancestors, and an empty private diagnostic directory:

```sh
DEVBUILD_CLASS=normal devbuild --wait make t-fast-exact \
  ONLY=app_seed_skycombat ZCL_TEST_TMPFS=0 \
  T_FAST_EXACT_ARGS="--no-cache --timeout=600"
```

The run also supplied `ZCL_TEST_TMPROOT`, `ZCL_TEST_INSTALLED_APP_BIN_DIR`,
`ZCL_TEST_INSTALLED_APP_KIT_DIR`, `ZCL_TEST_INSTALLED_APP_KIT_SHA3`,
`ZCL_TEST_INSTALLED_APP_ORIGINAL_SHARE`, and
`ZCL_TEST_INSTALLED_APP_EVIDENCE_DIR`. The installed runtime SHA-256 was
`e3b96a4772081f848089d9152d4b9eedb32dfa102d0d9632a8ae6a8c32336f30`, the kit
bundle SHA-256 was `8ccf3982640df89da18ace719375b063b737c5625e7eab63b8f37bc589461890`,
and the kit descriptor SHA3-256 was
`76ef57723456da98bc54935bf13aaa0ea4e05bd53f007a89cd87c4b49a7fe24e`.
The private fixture is retained for separate preview and must be retired by
its owner after that work. Diagnostics are not release assets.

<!-- claim: symbol-present test_app_seed_skycombat tests/harness/src/test_app_seed_skycombat.c # registered integration group -->

## Separate offline preview

A separate earlier fixture, received from the same signed share, built the
same image with fresh local version
`a2b50265f6bd83d32e5055ef52b88d8f8fd9215b98ceb4c903efccd77d7dc7ca`
and record `d24e244b6100e91daa5f2e935aab204ad233ae1854d4f2d6ec3679f16e982715`.
An installed `app.open` bound that version, record and image and exited 0
under a private network and PID namespace. The running executable SHA-256 was
`852e74e5b5fe6b7bd82cbfd8bf4239276213967f434f46e4d1eda69738250c3e`,
matching the built image. The namespace initially contained only loopback and
had no IPv4 or IPv6 routes before and after. The open reply took 6106 ms,
reported readiness at 4406 ms, and reported `budget_exceeded=true`. The preview
used the admitted light class with a 4 GiB memory ceiling; these times are not a
controlled comparison. Afterward, `fuser` reported no holders of the image
(exit 1, empty stdout and stderr).

A separate run of that image completed 120 QA frames and saved a PNG with
SHA-256 `3f3b12dd6678314b56f9de89b887a645be502ee950102dbc2807c5437263e1cf`.
Visual inspection of the virtual-display capture found the green player and
buildings. The open receipt SHA-256 was
`ad9e5491a7bdc83a4358d8e801989bcb380d9344e32c044a15c11fcaf74336cb`.
This is an automated virtual-display observation, not a human UI acceptance;
the final build test above used a different fresh local history and record.
