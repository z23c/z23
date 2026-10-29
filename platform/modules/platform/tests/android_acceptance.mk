# Copyright 2026 Rhett Creighton - Apache License 2.0
# Explicit strict-C23 Android acceptance; normal node builds never run ADB.

ZCL_ANDROID_ACCEPTANCE_GOALS := android-acceptance android-acceptance-device
ADB ?= adb
ANDROID_SERIAL ?=
ZCL_ANDROID_ACCEPTANCE_DIR := build/android
ZCL_ANDROID_ACCEPTANCE_TESTS := thread_join_android_acceptance cpu_affinity_android_acceptance
ZCL_ANDROID_ACCEPTANCE_FLAGS := -std=c23 -Wall -Wextra -Werror -pedantic -pthread

.PHONY: android-acceptance android-acceptance-device
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
else
android-acceptance android-acceptance-device:
	@echo 'Android acceptance requires ZCL_TARGET=android-arm64 and ANDROID_NDK_ROOT' >&2
	@exit 1
endif
