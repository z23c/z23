# Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
.DEFAULT_GOAL := apk
SDK_ROOT ?= $(ANDROID_SDK_ROOT)
ANDROID_NDK_ROOT ?= $(ANDROID_NDK_HOME)
ANDROID_API ?= 35
BUILD_TOOLS_VERSION ?= 35.0.0
JAVA_HOME ?= /usr/lib/jvm/default
ADB ?= $(SDK_ROOT)/platform-tools/adb
ANDROID_SERIAL ?=
BUILD_DIR ?= ../../build/android-app
NODE_BIN ?= ../../build/bin/z23
APP_ID := org.z23.nativeapp
TOOLS := $(SDK_ROOT)/build-tools/$(BUILD_TOOLS_VERSION)
ANDROID_JAR := $(SDK_ROOT)/platforms/android-$(ANDROID_API)/android.jar
KEYSTORE ?= $(BUILD_DIR)/development.keystore
APK := $(BUILD_DIR)/z23.apk
QUIRC_DIR := $(abspath $(BUILD_DIR)/quirc)
QUIRC_SOURCES := $(QUIRC_DIR)/quirc.c $(QUIRC_DIR)/decode.c $(QUIRC_DIR)/identify.c $(QUIRC_DIR)/version_db.c
HOST_CC ?= cc
HOST_WARNINGS := -std=c23 -O2 -Wall -Wextra -Werror -pedantic
export JAVA_HOME
export PATH := $(JAVA_HOME)/bin:$(PATH)

.PHONY: apk native install launch check-config check-node prepare-quirc test
prepare-quirc:
	@mkdir -p '$(QUIRC_DIR)'
	cp ../../vendor/quirc/*.[ch] '$(QUIRC_DIR)/'
	patch -s -d '$(QUIRC_DIR)' -p1 < ../../vendor/quirc/patches/strict-c23.patch

test: prepare-quirc
	$(HOST_CC) $(HOST_WARNINGS) -I. -I../../vendor/qrcodegen -I'$(QUIRC_DIR)' \
	  tests/fleet_test.c fleet.c ../../vendor/qrcodegen/qrcodegen.c $(QUIRC_SOURCES) \
	  -lm -o '$(BUILD_DIR)/fleet-test'
	'$(BUILD_DIR)/fleet-test'
	$(HOST_CC) $(HOST_WARNINGS) -pthread -I. -I../../platform/modules/json/include \
	  -I../../platform/modules/base/include tests/operations_test.c operations.c \
	  ../../platform/modules/json/src/json.c ../../platform/modules/base/src/cleanse.c \
	  ../../platform/modules/base/src/safe_alloc.c -Wl,--wrap=clock_gettime \
	  -o '$(BUILD_DIR)/operations-test'
	'$(BUILD_DIR)/operations-test'
	$(HOST_CC) $(HOST_WARNINGS) -I. -I../../platform/modules/json/include \
	  -I../../platform/modules/base/include -I../../contexts/commons/packages/zutf8/include \
	  tests/conversation_test.c conversation.c ../../contexts/commons/packages/zutf8/src/zutf8.c \
	  ../../platform/modules/json/src/json.c ../../platform/modules/base/src/cleanse.c \
	  ../../platform/modules/base/src/safe_alloc.c -o '$(BUILD_DIR)/conversation-test'
	'$(BUILD_DIR)/conversation-test'
	$(HOST_CC) $(HOST_WARNINGS) -pthread -I. -I../../platform/modules/json/include \
	  -I../../platform/modules/base/include tests/bridge_client_test.c bridge_client.c \
	  ../../platform/modules/json/src/json.c ../../platform/modules/base/src/cleanse.c \
	  ../../platform/modules/base/src/safe_alloc.c -o '$(BUILD_DIR)/bridge-client-test'
	@set -e; scratch=$$(mktemp -d '$(BUILD_DIR)/bridge-test.XXXXXX'); \
	  trap 'rmdir "$$scratch"' 0; '$(BUILD_DIR)/bridge-client-test' "$$scratch"

check-node:
	@test -x '$(NODE_BIN)' || { echo 'Build the Android node first' >&2; exit 1; }
	@headers="$$(LC_ALL=C readelf -lW '$(NODE_BIN)')" && printf '%s\n' "$$headers" | grep -F '/system/bin/linker64' >/dev/null || { echo 'NODE_BIN must be an Android ARM64 executable' >&2; exit 1; }
	@../../tools/scripts/check_c23_node_binary.sh '$(NODE_BIN)'

check-config:
	@test -f '$(ANDROID_NDK_ROOT)/build/cmake/android.toolchain.cmake' || { echo 'Set ANDROID_NDK_ROOT to the installed NDK' >&2; exit 1; }
	@test -r '$(ANDROID_JAR)' && test -x '$(TOOLS)/aapt' && test -x '$(TOOLS)/zipalign' && test -x '$(TOOLS)/apksigner' || { echo 'Set SDK_ROOT and BUILD_TOOLS_VERSION to an installed Android SDK' >&2; exit 1; }
	@test -x '$(JAVA_HOME)/bin/keytool' && test -x '$(JAVA_HOME)/bin/jar' || { echo 'Set JAVA_HOME to an installed JDK' >&2; exit 1; }
	@test '$(ANDROID_API)' = 35 || { echo 'The current application manifest requires API 35' >&2; exit 1; }

native: check-config prepare-quirc
	cmake -S . -B '$(BUILD_DIR)/native' \
	  -DCMAKE_TOOLCHAIN_FILE='$(ANDROID_NDK_ROOT)/build/cmake/android.toolchain.cmake' \
	  -DANDROID_ABI=arm64-v8a -DANDROID_PLATFORM=android-$(ANDROID_API) \
	  -DZ23_ANDROID_API=$(ANDROID_API) -DZ23_QUIRC_DIR='$(QUIRC_DIR)' -DCMAKE_BUILD_TYPE=Release
	cmake --build '$(BUILD_DIR)/native' --parallel 4

$(KEYSTORE):
	@mkdir -p '$(dir $(KEYSTORE))'
	'$(JAVA_HOME)/bin/keytool' -genkeypair -keystore '$@' -storepass android \
	  -alias z23-development -keypass android -dname 'CN=Z23 Development' \
	  -keyalg RSA -keysize 3072 -validity 3650 -noprompt

apk: check-node native $(KEYSTORE)
	@test -x '$(NODE_BIN)' || { echo 'Build the Android node with make ZCL_TARGET=android-arm64 z23 first' >&2; exit 1; }
	@mkdir -p '$(BUILD_DIR)/package/lib/arm64-v8a'
	cp '$(BUILD_DIR)/native/libz23android.so' '$(BUILD_DIR)/package/lib/arm64-v8a/'
	cp '$(NODE_BIN)' '$(BUILD_DIR)/package/lib/arm64-v8a/libz23node.so'
	'$(TOOLS)/aapt' package -f -M AndroidManifest.xml -S res \
	  -I '$(ANDROID_JAR)' -F '$(BUILD_DIR)/resources.apk'
	cp '$(BUILD_DIR)/resources.apk' '$(BUILD_DIR)/unsigned.apk'
	'$(JAVA_HOME)/bin/jar' uf '$(BUILD_DIR)/unsigned.apk' -C '$(BUILD_DIR)/package' lib
	'$(TOOLS)/zipalign' -f -P 16 4 '$(BUILD_DIR)/unsigned.apk' '$(BUILD_DIR)/aligned.apk'
	'$(TOOLS)/apksigner' sign --ks '$(KEYSTORE)' --ks-key-alias z23-development \
	  --ks-pass pass:android --key-pass pass:android --out '$(APK)' '$(BUILD_DIR)/aligned.apk'
	'$(TOOLS)/apksigner' verify --verbose '$(APK)'

install: apk
	@test -n '$(ANDROID_SERIAL)' || { echo 'Set ANDROID_SERIAL to one adb device serial' >&2; exit 1; }
	'$(ADB)' -s '$(ANDROID_SERIAL)' install -r '$(APK)'

launch:
	@test -n '$(ANDROID_SERIAL)' || { echo 'Set ANDROID_SERIAL to one adb device serial' >&2; exit 1; }
	'$(ADB)' -s '$(ANDROID_SERIAL)' shell am start -n '$(APP_ID)/android.app.NativeActivity'
