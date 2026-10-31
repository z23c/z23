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
APP_MANIFEST ?= AndroidManifest.xml
QUIRC_DIR := $(abspath $(BUILD_DIR)/quirc)
QUIRC_SOURCES := $(QUIRC_DIR)/quirc.c $(QUIRC_DIR)/decode.c $(QUIRC_DIR)/identify.c $(QUIRC_DIR)/version_db.c
QUIRC_FLAGS := -DQUIRC_MAX_REGIONS=65534
HOST_CC ?= cc
HOST_WARNINGS := -std=c23 -O2 -Wall -Wextra -Werror -pedantic
export JAVA_HOME
export PATH := $(JAVA_HOME)/bin:$(PATH)

.PHONY: dexgen test-dexgen test-watch apk native install launch check-config check-node prepare-quirc test bridge test-bridge
prepare-quirc:
	@mkdir -p '$(QUIRC_DIR)'
	cp ../../vendor/quirc/*.[ch] '$(QUIRC_DIR)/'
	patch -s -d '$(QUIRC_DIR)' -p1 < ../../vendor/quirc/patches/strict-c23.patch

bridge:
	@mkdir -p '$(BUILD_DIR)'
	$(HOST_CC) $(HOST_WARNINGS) -I../../platform/modules/json/include \
	  -I../../platform/modules/base/include -I../../contexts/commons/packages/zutf8/include \
	  bridge/main.c bridge/relay.c ../../contexts/commons/packages/zutf8/src/zutf8.c \
	  ../../platform/modules/json/src/json.c ../../platform/modules/base/src/cleanse.c \
	  ../../platform/modules/base/src/safe_alloc.c -o '$(BUILD_DIR)/z23-bridge'

test-bridge: bridge
	@mkdir -p '$(BUILD_DIR)/bridge-fixture'
	$(HOST_CC) $(HOST_WARNINGS) bridge/mock_codex.c -o '$(BUILD_DIR)/bridge-fixture/codex'
	@unset BRIDGE_MOCK_UNKNOWN_ENABLED; printf '%s\n' '{"prompt":"test"}' | \
	  PATH='$(abspath $(BUILD_DIR))/bridge-fixture' '$(BUILD_DIR)/z23-bridge' > '$(BUILD_DIR)/bridge-ok.json'
	grep -Fx '{"ok":true,"answer":"mock answer"}' '$(BUILD_DIR)/bridge-ok.json'
	@if printf '%s\n' '{"prompt":"test"}' | \
	  PATH='$(abspath $(BUILD_DIR))/bridge-fixture' BRIDGE_MOCK_UNKNOWN_ENABLED=1 \
	  '$(BUILD_DIR)/z23-bridge' > '$(BUILD_DIR)/bridge-refused.json'; then exit 1; fi
	grep -Fx '{"ok":false,"error":"Could not safely configure local Codex."}' '$(BUILD_DIR)/bridge-refused.json'
	$(HOST_CC) $(HOST_WARNINGS) -I. -Ibridge -I../../platform/modules/json/include \
	  -I../../platform/modules/base/include -I../../contexts/commons/packages/zutf8/include \
	  tests/relay_test.c bridge/relay.c ../../contexts/commons/packages/zutf8/src/zutf8.c \
	  ../../platform/modules/json/src/json.c ../../platform/modules/base/src/cleanse.c \
	  ../../platform/modules/base/src/safe_alloc.c -o '$(BUILD_DIR)/relay-test'
	@set -e; scratch=$$(mktemp -d '$(BUILD_DIR)/relay-test.XXXXXX'); \
	  trap 'rmdir "$$scratch"' 0; '$(BUILD_DIR)/relay-test' "$$scratch"

SPEECH_JSON := ../../platform/modules/json/src/json.c ../../platform/modules/base/src/cleanse.c ../../platform/modules/base/src/safe_alloc.c
SPEECH_INCLUDES := -I. -Ibridge -I../../platform/modules/json/include -I../../platform/modules/base/include -I../../contexts/commons/packages/zutf8/include -I../../platform/modules/encoding/include -I../../platform/modules/sha3/include
HOST_SOURCES := bridge/assistant.c bridge/http.c bridge/fleet_probe.c bridge/host_ops.c bridge/host.c bridge/relay.c hosts.c pairing.c voice.c \
  ../../platform/modules/sha3/src/sha3.c \
  ../../platform/modules/encoding/src/utilstrencodings.c ../../contexts/commons/packages/zutf8/src/zutf8.c
.PHONY: speech-bridge speech-probe test-voice test-host preview-apk
speech-bridge:
	@mkdir -p '$(BUILD_DIR)'
	$(HOST_CC) $(HOST_WARNINGS) -pthread $(SPEECH_INCLUDES) bridge/speech_main.c $(HOST_SOURCES) \
	  $(SPEECH_JSON) -o '$(BUILD_DIR)/z23-speech-bridge'

speech-probe:
	@mkdir -p '$(BUILD_DIR)'
	$(HOST_CC) $(HOST_WARNINGS) $(SPEECH_INCLUDES) tests/speech_roundtrip.c speech_client.c bridge_client.c voice.c \
	  $(SPEECH_JSON) -o '$(BUILD_DIR)/speech-roundtrip'

DEXDUMP ?= $(TOOLS)/dexdump
dexgen:
	@mkdir -p '$(BUILD_DIR)'
	$(HOST_CC) $(HOST_WARNINGS) dexgen.c -o '$(BUILD_DIR)/dexgen'

test-watch:
	@mkdir -p '$(BUILD_DIR)'
	$(HOST_CC) $(HOST_WARNINGS) -pthread -I. tests/node_watch_test.c node_watch.c -o '$(BUILD_DIR)/node-watch-test'
	'$(BUILD_DIR)/node-watch-test'

test-dexgen:
	@mkdir -p '$(BUILD_DIR)'
	$(HOST_CC) $(HOST_WARNINGS) -I. tests/dexgen_test.c -o '$(BUILD_DIR)/dexgen-test'
	@set -e; scratch=$$(mktemp -d '$(BUILD_DIR)/dexgen-test.XXXXXX'); \
	  trap 'rm -rf "$$scratch"' 0; '$(BUILD_DIR)/dexgen-test' "$$scratch" $$(test -x '$(DEXDUMP)' && echo '$(DEXDUMP)')

preview-apk:
	@mkdir -p '$(BUILD_DIR)/preview'
	sed -e 's/package="org.z23.nativeapp"/package="org.z23.voicepreview"/' -e 's/android:label="Z23"/android:label="Z23 Voice Preview"/' \
	  -e 's/android:debuggable="false"/android:debuggable="true"/' AndroidManifest.xml > '$(BUILD_DIR)/preview/AndroidManifest.xml'
	$(MAKE) apk APP_MANIFEST='$(BUILD_DIR)/preview/AndroidManifest.xml' APK='$(BUILD_DIR)/z23-preview.apk'

test-voice:
	@mkdir -p '$(BUILD_DIR)'
	$(HOST_CC) $(HOST_WARNINGS) -I. tests/voice_test.c voice.c -o '$(BUILD_DIR)/voice-test'
	'$(BUILD_DIR)/voice-test'
	$(HOST_CC) $(HOST_WARNINGS) $(SPEECH_INCLUDES) tests/speech_client_test.c speech_client.c voice.c \
	  $(SPEECH_JSON) -o '$(BUILD_DIR)/speech-client-test'
	@set -e; scratch=$$(mktemp -d '$(BUILD_DIR)/speech-client.XXXXXX'); \
	  trap 'rmdir "$$scratch"' 0; '$(BUILD_DIR)/speech-client-test' "$$scratch"

test: prepare-quirc test-bridge test-voice test-host test-dexgen test-watch test-scan test-qr-window test-payment
	$(HOST_CC) $(HOST_WARNINGS) -I. -I../../vendor/qrcodegen -I'$(QUIRC_DIR)' $(QUIRC_FLAGS) \
	  tests/fleet_test.c fleet.c ../../vendor/qrcodegen/qrcodegen.c $(QUIRC_SOURCES) \
	  -lm -o '$(BUILD_DIR)/fleet-test'
	'$(BUILD_DIR)/fleet-test'
	$(HOST_CC) $(HOST_WARNINGS) -pthread -I. -I../../platform/modules/json/include \
	  -I../../platform/modules/base/include tests/operations_test.c operations.c rpc.c nodelog.c \
	  ../../platform/modules/json/src/json.c ../../platform/modules/base/src/cleanse.c \
	  ../../platform/modules/base/src/safe_alloc.c -Wl,--wrap=clock_gettime \
	  -o '$(BUILD_DIR)/operations-test'
	'$(BUILD_DIR)/operations-test'
	$(HOST_CC) $(HOST_WARNINGS) -pthread -I. -I../../platform/modules/json/include \
	  -I../../platform/modules/base/include tests/direct_test.c operations.c rpc.c nodelog.c \
	  ../../platform/modules/json/src/json.c ../../platform/modules/base/src/cleanse.c \
	  ../../platform/modules/base/src/safe_alloc.c -o '$(BUILD_DIR)/direct-test'
	'$(BUILD_DIR)/direct-test'
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

QR_WINDOW_SOURCES := bridge/qr_window.c ../../vendor/qrcodegen/qrcodegen.c
.PHONY: qr-window test-qr-window test-scan
qr-window:
	@mkdir -p '$(BUILD_DIR)'
	$(HOST_CC) $(HOST_WARNINGS) -I../../vendor/qrcodegen $(QR_WINDOW_SOURCES) -lX11 -o '$(BUILD_DIR)/z23-qr-window'

test-qr-window: prepare-quirc
	@mkdir -p '$(BUILD_DIR)'
	$(HOST_CC) $(HOST_WARNINGS) -DZAPP_QR_NO_X11 -I../../vendor/qrcodegen $(QR_WINDOW_SOURCES) -o '$(BUILD_DIR)/z23-qr-dump'
	$(HOST_CC) $(HOST_WARNINGS) -I. -I'$(QUIRC_DIR)' tests/qr_window_test.c $(QUIRC_FLAGS) $(QUIRC_SOURCES) -lm -o '$(BUILD_DIR)/qr-window-test'
	@set -e; scratch=$$(mktemp -d '$(BUILD_DIR)/qr-window-test.XXXXXX'); \
	  trap 'rm -rf "$$scratch"' 0; '$(BUILD_DIR)/qr-window-test' '$(BUILD_DIR)/z23-qr-dump' "$$scratch"

test-scan:
	@mkdir -p '$(BUILD_DIR)'
	$(HOST_CC) $(HOST_WARNINGS) $(SPEECH_INCLUDES) -I../../vendor/qrcodegen tests/scan_test.c scan.c fleet.c speech_client.c bridge_client.c voice.c ../../vendor/qrcodegen/qrcodegen.c $(SPEECH_JSON) -o '$(BUILD_DIR)/scan-test'
	'$(BUILD_DIR)/scan-test'

test-payment:
	@mkdir -p '$(BUILD_DIR)'
	$(HOST_CC) $(HOST_WARNINGS) -I. -I../../contexts/commons/packages/zutf8/include \
	  tests/payment_code_test.c payment_code.c ../../contexts/commons/packages/zutf8/src/zutf8.c \
	  -o '$(BUILD_DIR)/payment-code-test'
	'$(BUILD_DIR)/payment-code-test'

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

apk: check-node native dexgen $(KEYSTORE)
	@test -x '$(NODE_BIN)' || { echo 'Build the Android node with make ZCL_TARGET=android-arm64 z23 first' >&2; exit 1; }
	@mkdir -p '$(BUILD_DIR)/package/lib/arm64-v8a'
	cp '$(BUILD_DIR)/native/libz23android.so' '$(BUILD_DIR)/package/lib/arm64-v8a/'
	cp '$(NODE_BIN)' '$(BUILD_DIR)/package/lib/arm64-v8a/libz23node.so'
	'$(TOOLS)/aapt' package -f -M '$(APP_MANIFEST)' -S res \
	  -I '$(ANDROID_JAR)' -F '$(BUILD_DIR)/resources.apk'
	'$(BUILD_DIR)/dexgen' '$(BUILD_DIR)/package/classes.dex'
	cp '$(BUILD_DIR)/resources.apk' '$(BUILD_DIR)/unsigned.apk'
	'$(JAVA_HOME)/bin/jar' uf '$(BUILD_DIR)/unsigned.apk' -C '$(BUILD_DIR)/package' classes.dex -C '$(BUILD_DIR)/package' lib
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

HOST_TEST_BASE := $(SPEECH_JSON) ../../platform/modules/sha3/src/sha3.c
test-host:
	@mkdir -p '$(BUILD_DIR)'
	$(HOST_CC) $(HOST_WARNINGS) $(SPEECH_INCLUDES) tests/hosts_test.c hosts.c pairing.c $(HOST_TEST_BASE) -o '$(BUILD_DIR)/hosts-test'
	'$(BUILD_DIR)/hosts-test'
	$(HOST_CC) $(HOST_WARNINGS) -pthread -I. tests/nodelog_test.c nodelog.c -o '$(BUILD_DIR)/nodelog-test'
	@set -e; scratch=$$(mktemp -d '$(BUILD_DIR)/nodelog-test.XXXXXX'); \
	  trap 'rm -rf "$$scratch"' 0; '$(BUILD_DIR)/nodelog-test' "$$scratch"
	$(HOST_CC) $(HOST_WARNINGS) $(SPEECH_INCLUDES) tests/fleet_probe_test.c bridge/fleet_probe.c \
	  ../../contexts/commons/packages/zutf8/src/zutf8.c $(SPEECH_JSON) -o '$(BUILD_DIR)/fleet-probe-test'
	'$(BUILD_DIR)/fleet-probe-test'
	$(HOST_CC) $(HOST_WARNINGS) $(SPEECH_INCLUDES) tests/host_ops_test.c bridge/host_ops.c $(SPEECH_JSON) -o '$(BUILD_DIR)/host-ops-test'
	'$(BUILD_DIR)/host-ops-test'
	$(HOST_CC) $(HOST_WARNINGS) -pthread $(SPEECH_INCLUDES) tests/http_test.c bridge/http.c $(SPEECH_JSON) -o '$(BUILD_DIR)/http-test'
	'$(BUILD_DIR)/http-test'
	$(HOST_CC) $(HOST_WARNINGS) -pthread $(SPEECH_INCLUDES) tests/assistant_test.c bridge/http.c bridge/fleet_probe.c voice.c \
	  ../../platform/modules/encoding/src/utilstrencodings.c ../../contexts/commons/packages/zutf8/src/zutf8.c \
	  $(SPEECH_JSON) -o '$(BUILD_DIR)/assistant-test'
	'$(BUILD_DIR)/assistant-test'
	$(HOST_CC) $(HOST_WARNINGS) $(SPEECH_INCLUDES) tests/thermal_test.c thermal.c -o '$(BUILD_DIR)/thermal-test'
	'$(BUILD_DIR)/thermal-test'
	$(HOST_CC) $(HOST_WARNINGS) -D__ANDROID__ -pthread -Itests/ndk_fake -I. tests/thermal_start_test.c thermal.c -o '$(BUILD_DIR)/thermal-start-test'
	'$(BUILD_DIR)/thermal-start-test'
	$(HOST_CC) $(HOST_WARNINGS) $(SPEECH_INCLUDES) tests/layout_test.c layout.c $(SPEECH_JSON) -o '$(BUILD_DIR)/layout-test'
	'$(BUILD_DIR)/layout-test'
	$(HOST_CC) $(HOST_WARNINGS) $(SPEECH_INCLUDES) tests/home_test.c home.c layout.c hosts.c pairing.c $(HOST_TEST_BASE) -o '$(BUILD_DIR)/home-test'
	'$(BUILD_DIR)/home-test'
