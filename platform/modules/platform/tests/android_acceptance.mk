# Copyright 2026 Rhett Creighton - Apache License 2.0
# Explicit strict-C23 Android acceptance; normal node builds never run ADB.

ZCL_ANDROID_ACCEPTANCE_GOALS := android-acceptance android-acceptance-device \
    android-snapshot-recovery-device
ADB ?= adb
ANDROID_SERIAL ?=
ZCL_ANDROID_ACCEPTANCE_DIR := build/android
ZCL_ANDROID_ACCEPTANCE_TESTS := thread_join_android_acceptance cpu_affinity_android_acceptance
ZCL_ANDROID_ACCEPTANCE_FLAGS := -std=c23 -Wall -Wextra -Werror -pedantic -pthread

.PHONY: android-acceptance android-acceptance-device android-snapshot-recovery-device
ifeq ($(ZCL_TARGET),android-arm64)
# Compile each explicit invocation so changing the API or compiler cannot
# reuse a test executable from another target in the shared evidence directory.
android-acceptance:
	@mkdir -p $(ZCL_ANDROID_ACCEPTANCE_DIR)
	$(CC) $(ZCL_ANDROID_ACCEPTANCE_FLAGS) -Iplatform/modules/platform/include \
	  platform/modules/platform/tests/thread_join_android_acceptance.c \
	  -o $(ZCL_ANDROID_ACCEPTANCE_DIR)/thread_join_android_acceptance
	$(CC) $(ZCL_ANDROID_ACCEPTANCE_FLAGS) \
	  -ffunction-sections -fdata-sections -Wl,--gc-sections \
	  -Iplatform/modules/util/include -Iplatform/modules/base/include \
	  -Iplatform/modules/json/include -Iplatform/modules/platform/include \
	  platform/modules/platform/tests/cpu_affinity_android_acceptance.c \
	  platform/modules/util/src/cpu_topology.c \
	  platform/modules/platform/src/logical_cpu.c \
	  platform/modules/base/src/log_level.c \
	  -o $(ZCL_ANDROID_ACCEPTANCE_DIR)/cpu_affinity_android_acceptance

android-acceptance-device: android-acceptance
	@test -n '$(ANDROID_SERIAL)' || { echo 'android-acceptance-device: set ANDROID_SERIAL to one adb device serial' >&2; exit 1; }
	@set -eu; for name in $(ZCL_ANDROID_ACCEPTANCE_TESTS); do \
	  $(ADB) -s '$(ANDROID_SERIAL)' push "$(ZCL_ANDROID_ACCEPTANCE_DIR)/$$name" "/data/local/tmp/$$name"; \
	  $(ADB) -s '$(ANDROID_SERIAL)' shell chmod 755 "/data/local/tmp/$$name"; \
	  $(ADB) -s '$(ANDROID_SERIAL)' shell timeout 30 "/data/local/tmp/$$name"; \
	done

# A unique shell-owned directory contains all device-side fixture data.
# On failure retain it and its logs; delete it only after a complete pass.
android-snapshot-recovery-device:
	@test -n '$(ANDROID_SERIAL)' || { echo 'android-snapshot-recovery-device: set ANDROID_SERIAL' >&2; exit 1; }
	@set -eu; \
	  case '$(BIN_DIR)' in /*) ;; *) echo 'set BIN_DIR to the absolute runner directory' >&2; exit 1;; esac; \
	  case '$(BUILD_DIR)' in /*) ;; *) echo 'set BUILD_DIR to an absolute receipt directory' >&2; exit 1;; esac; \
	  test '$(origin ADB)' = 'command line' || { echo 'set ADB explicitly' >&2; exit 1; }; \
	  printf '%s\n' '$(EXPECTED_RUNNER_SHA256)' | grep -Eq '^[0-9a-f]{64}$$' || { echo 'set EXPECTED_RUNNER_SHA256 to the qualified artifact hash' >&2; exit 1; }; \
	  test -x '$(BIN_DIR)/android_snapshot_recovery' || { echo 'build android-snapshot-recovery-build first' >&2; exit 1; }; \
	  mkdir -p '$(BUILD_DIR)'; out=$$(mktemp -d '$(BUILD_DIR)/android-snapshot-recovery.XXXXXX'); \
	  readelf -h -l '$(BIN_DIR)/android_snapshot_recovery' > "$$out/elf.txt"; \
	  grep -Eq 'Machine:[[:space:]]+AArch64' "$$out/elf.txt"; \
	  grep -F '/system/bin/linker64' "$$out/elf.txt" >/dev/null; \
	  readelf -dW '$(BIN_DIR)/android_snapshot_recovery' > "$$out/dynamic.txt"; \
	  sed -n 's/.*Shared library: \[\([^]]*\)\].*/\1/p' "$$out/dynamic.txt" > "$$out/needed.txt"; \
	  test -s "$$out/needed.txt"; \
	  if grep -Ev '^(libc|libdl|libm|liblog|libandroid|libz)\.so$$' "$$out/needed.txt"; then echo 'unsupported Android runtime dependency' >&2; exit 1; fi; \
	  '$(ADB)' -s '$(ANDROID_SERIAL)' shell -T mktemp -d /data/local/tmp/z23-snapshot-recovery.XXXXXX > "$$out/device-scratch.raw"; \
	  test "$$(wc -l < "$$out/device-scratch.raw")" -eq 1 || { echo 'invalid multiline scratch path' >&2; exit 1; }; \
	  remote=$$(cat "$$out/device-scratch.raw"); \
	  test "$$(wc -c < "$$out/device-scratch.raw")" -eq "$$(($${#remote} + 1))" || { echo 'invalid scratch path bytes' >&2; exit 1; }; \
	  printf '%s\n' "$$remote" | grep -Eq '^/data/local/tmp/z23-snapshot-recovery\.[A-Za-z0-9]{6}$$' || { echo 'invalid scratch path' >&2; exit 1; }; \
	  printf '%s\n' "$$remote" > "$$out/device-scratch.txt"; \
	  '$(ADB)' -s '$(ANDROID_SERIAL)' push '$(BIN_DIR)/android_snapshot_recovery' "$$remote/runner" >/dev/null; \
	  '$(ADB)' -s '$(ANDROID_SERIAL)' shell "chmod 755 '$$remote/runner' && mkdir -m 700 '$$remote/scratch'"; \
	  sha256sum '$(BIN_DIR)/android_snapshot_recovery' > "$$out/host-runner.sha256"; \
	  '$(ADB)' -s '$(ANDROID_SERIAL)' shell -T "sha256sum '$$remote/runner'" > "$$out/device-runner.sha256"; \
	  host_sha=$$(awk '{print $$1}' "$$out/host-runner.sha256"); \
	  device_sha=$$(awk '{print $$1}' "$$out/device-runner.sha256"); \
	  printf '%s\n' "$$host_sha" | grep -Eq '^[0-9a-f]{64}$$'; \
	  test "$$host_sha" = '$(EXPECTED_RUNNER_SHA256)' || { echo 'host runner does not match qualified artifact' >&2; exit 1; }; \
	  test "$$host_sha" = "$$device_sha" || { echo 'device runner hash mismatch' >&2; exit 1; }; \
	  '$(ADB)' -s '$(ANDROID_SERIAL)' shell -T "cd '$$remote' && ./runner --selection-only --exact=test_snapshot_install_recovery" > "$$out/selection.log" 2>&1; \
	  grep -Fx 'SELECTED test_snapshot_install_recovery' "$$out/selection.log" >/dev/null; \
	  grep -Fx 'SELECTION-ONLY groups=1 executed=0 cache_probes=0' "$$out/selection.log" >/dev/null; \
	  rc=0; '$(ADB)' -s '$(ANDROID_SERIAL)' shell -T "cd '$$remote' && ZCL_TEST_TMPFS=0 ZCL_TEST_TMPROOT='$$remote/scratch' ./runner --exact=test_snapshot_install_recovery --jobs=1 --timeout=900 --no-cache --verbose" > "$$out/runner.log" 2>&1 || rc=$$?; \
	  '$(ADB)' -s '$(ANDROID_SERIAL)' pull "$$remote/test-tmp" "$$out/" >/dev/null || rc=1; \
	  test "$$rc" -eq 0 || { echo "fixture failed; retained $$remote" >&2; exit 1; }; \
	  grep -E 'SUITE VERDICT .*groups_ran=1 groups_cached=0 .*groups_failed=0 self_skips=0 env_unobserved=0 load_flaky=0' "$$out/runner.log" >/dev/null; \
	  grep -F 'v2 pool crash: synchronized writer killed... OK' "$$out/runner.log" >/dev/null; \
	  grep -F 'v2 pool crash: fresh process observes atomic tuple... OK' "$$out/runner.log" >/dev/null; \
	  grep -F 'v2 pool guarded crash: committed before marker... OK' "$$out/runner.log" >/dev/null; \
	  grep -F 'v2 pool guarded crash: recovery preserves wallet and state... OK' "$$out/runner.log" >/dev/null; \
	  grep -F 'guarded commit pauses before marker... OK' "$$out/runner.log" >/dev/null; \
	  grep -F 'missing marker recovered with wallet preserved... OK' "$$out/runner.log" >/dev/null; \
	  grep -F 'guarded install returns before kill... OK' "$$out/runner.log" >/dev/null; \
	  grep -F 'completed install and wallet survive fresh restart... OK' "$$out/runner.log" >/dev/null; \
	  '$(ADB)' -s '$(ANDROID_SERIAL)' shell "rm -rf '$$remote'"; \
	  echo "snapshot recovery proof retained in $$out"
else
android-acceptance android-acceptance-device android-snapshot-recovery-device:
	@echo 'Android acceptance requires ZCL_TARGET=android-arm64 and ANDROID_NDK_ROOT' >&2
	@exit 1
endif
