# Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
.DEFAULT_GOAL := apk
SDK_ROOT ?= $(ANDROID_SDK_ROOT)
ANDROID_NDK_ROOT ?= $(ANDROID_NDK_HOME)
ANDROID_API ?= 35
DEVKEY_PROBE ?= OFF
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
export EXPECTED_SIGNER_SHA256
APK := $(BUILD_DIR)/z23.apk
APP_MANIFEST ?= AndroidManifest.xml
QUIRC_DIR := $(abspath $(BUILD_DIR)/quirc)
QUIRC_SOURCES := $(QUIRC_DIR)/quirc.c $(QUIRC_DIR)/decode.c $(QUIRC_DIR)/identify.c $(QUIRC_DIR)/version_db.c
QUIRC_FLAGS := -DQUIRC_MAX_REGIONS=65534
PARAMS_DIR ?= ../../vendor/params
PARAMS_SUMS := params.sha256
# 1 packs the Sapling proving parameters into the package (make apk). A preview build leaves them out
# unless PREVIEW_PARAMS=1, because a preview runs no node and the files add 51.6 MB.
PACK_PARAMS ?= 1
PREVIEW_PARAMS ?= 0
HOST_CC ?= cc
HOST_WARNINGS := -std=c23 -O2 -Wall -Wextra -Werror -pedantic
export JAVA_HOME
export PATH := $(JAVA_HOME)/bin:$(PATH)

.PHONY: check-probe dexgen test-dexgen test-watch apk native install launch check-config check-node check-params prepare-quirc test bridge test-bridge
prepare-quirc:
	@mkdir -p '$(QUIRC_DIR)'
	cp ../../vendor/quirc/*.[ch] '$(QUIRC_DIR)/'
	patch -s -d '$(QUIRC_DIR)' -p1 < ../../vendor/quirc/patches/strict-c23.patch

bridge:
	@mkdir -p '$(BUILD_DIR)'
	$(HOST_CC) $(HOST_WARNINGS) -I../../platform/modules/json/include \
	  -I../../platform/modules/base/include -I../../contexts/commons/packages/zutf8/include \
	  -I. -I../../platform/modules/sha3/include -pthread bridge/main.c bridge/relay.c bridge_auth.c ../../platform/modules/sha3/src/sha3.c ../../contexts/commons/packages/zutf8/src/zutf8.c \
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
	  -I../../platform/modules/sha3/include -pthread tests/relay_test.c bridge/relay.c bridge_auth.c ../../platform/modules/sha3/src/sha3.c ../../contexts/commons/packages/zutf8/src/zutf8.c \
	  ../../platform/modules/json/src/json.c ../../platform/modules/base/src/cleanse.c \
	  ../../platform/modules/base/src/safe_alloc.c -o '$(BUILD_DIR)/relay-test'
	@set -e; scratch=$$(mktemp -d '$(BUILD_DIR)/relay-test.XXXXXX'); \
	  trap 'rmdir "$$scratch"' 0; '$(BUILD_DIR)/relay-test' "$$scratch"

SPEECH_JSON := ../../platform/modules/json/src/json.c ../../platform/modules/base/src/cleanse.c ../../platform/modules/base/src/safe_alloc.c
SPEECH_INCLUDES := -I. -Ibridge -I../../platform/modules/json/include -I../../platform/modules/base/include -I../../contexts/commons/packages/zutf8/include -I../../platform/modules/encoding/include -I../../platform/modules/sha3/include
HOST_SOURCES := bridge_auth.c bridge/assistant.c bridge/http.c bridge/fleet_probe.c private.c bridge/host_ops.c bridge/host.c bridge/relay.c hosts.c pairing.c voice.c \
  ../../platform/modules/sha3/src/sha3.c \
  ../../platform/modules/encoding/src/utilstrencodings.c ../../contexts/commons/packages/zutf8/src/zutf8.c
.PHONY: speech-bridge speech-probe test-voice test-host preview-apk
speech-bridge:
	@mkdir -p '$(BUILD_DIR)'
	$(HOST_CC) $(HOST_WARNINGS) -pthread $(SPEECH_INCLUDES) bridge/speech_main.c $(HOST_SOURCES) \
	  $(SPEECH_JSON) -o '$(BUILD_DIR)/z23-speech-bridge'

speech-probe:
	@mkdir -p '$(BUILD_DIR)'
	$(HOST_CC) $(HOST_WARNINGS) $(SPEECH_INCLUDES) tests/speech_roundtrip.c speech_client.c bridge_client.c bridge_auth.c ../../platform/modules/sha3/src/sha3.c voice.c \
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
	$(MAKE) apk PACK_PARAMS='$(PREVIEW_PARAMS)' APP_MANIFEST='$(BUILD_DIR)/preview/AndroidManifest.xml' APK='$(BUILD_DIR)/z23-preview.apk'

test-voice:
	@mkdir -p '$(BUILD_DIR)'
	$(HOST_CC) $(HOST_WARNINGS) -I. tests/voice_test.c voice.c -o '$(BUILD_DIR)/voice-test'
	'$(BUILD_DIR)/voice-test'
	$(HOST_CC) $(HOST_WARNINGS) $(SPEECH_INCLUDES) tests/speech_client_test.c speech_client.c voice.c \
	  $(SPEECH_JSON) -o '$(BUILD_DIR)/speech-client-test'
	@set -e; scratch=$$(mktemp -d '$(BUILD_DIR)/speech-client.XXXXXX'); \
	  trap 'rmdir "$$scratch"' 0; '$(BUILD_DIR)/speech-client-test' "$$scratch"

test: prepare-quirc test-bridge test-voice test-host test-devkey test-dexgen test-watch test-scan test-qr-window test-payment test-wallet test-wallet-send test-qr-fuzz test-setup test-camera-access
	$(HOST_CC) $(HOST_WARNINGS) -I. -I../../vendor/qrcodegen -I'$(QUIRC_DIR)' $(QUIRC_FLAGS) \
	  tests/fleet_test.c fleet.c ../../vendor/qrcodegen/qrcodegen.c $(QUIRC_SOURCES) \
	  -lm -o '$(BUILD_DIR)/fleet-test'
	'$(BUILD_DIR)/fleet-test'
	$(HOST_CC) $(HOST_WARNINGS) -pthread -I. -I../../platform/modules/json/include \
	  -I../../platform/modules/base/include -I../../platform/modules/sha3/include tests/operations_test.c operations.c setup_state.c private.c params.c rpc.c nodelog.c \
	  ../../platform/modules/sha3/src/sha3.c ../../platform/modules/json/src/json.c ../../platform/modules/base/src/cleanse.c \
	  ../../platform/modules/base/src/safe_alloc.c -Wl,--wrap=clock_gettime \
	  -o '$(BUILD_DIR)/operations-test'
	'$(BUILD_DIR)/operations-test'
	$(HOST_CC) $(HOST_WARNINGS) -pthread -I. -I../../platform/modules/json/include \
	  -I../../platform/modules/base/include -I../../platform/modules/sha3/include tests/direct_test.c operations.c setup_state.c private.c params.c rpc.c nodelog.c \
	  ../../platform/modules/sha3/src/sha3.c ../../platform/modules/json/src/json.c ../../platform/modules/base/src/cleanse.c \
	  ../../platform/modules/base/src/safe_alloc.c -o '$(BUILD_DIR)/direct-test'
	'$(BUILD_DIR)/direct-test'
	$(HOST_CC) $(HOST_WARNINGS) -I. -I../../platform/modules/json/include \
	  -I../../platform/modules/base/include -I../../contexts/commons/packages/zutf8/include \
	  tests/conversation_test.c conversation.c ../../contexts/commons/packages/zutf8/src/zutf8.c \
	  ../../platform/modules/json/src/json.c ../../platform/modules/base/src/cleanse.c \
	  ../../platform/modules/base/src/safe_alloc.c -o '$(BUILD_DIR)/conversation-test'
	'$(BUILD_DIR)/conversation-test'
	$(HOST_CC) $(HOST_WARNINGS) -pthread -I. -I../../platform/modules/json/include \
	  -I../../platform/modules/base/include -I../../platform/modules/sha3/include tests/bridge_client_test.c bridge_client.c bridge_auth.c ../../platform/modules/sha3/src/sha3.c \
	  ../../platform/modules/json/src/json.c ../../platform/modules/base/src/cleanse.c \
	  ../../platform/modules/base/src/safe_alloc.c -o '$(BUILD_DIR)/bridge-client-test'
	@set -e; scratch=$$(mktemp -d '$(BUILD_DIR)/bridge-test.XXXXXX'); \
	  trap 'rmdir "$$scratch"' 0; '$(BUILD_DIR)/bridge-client-test' "$$scratch"
	$(HOST_CC) $(HOST_WARNINGS) -I. -I../../platform/modules/json/include \
	  -I../../platform/modules/base/include -I../../contexts/commons/packages/zutf8/include -Itests tests/wallet_view_test.c wallet_view.c payment_code.c ../../contexts/commons/packages/zutf8/src/zutf8.c \
	  ../../platform/modules/json/src/json.c ../../platform/modules/base/src/cleanse.c \
	  ../../platform/modules/base/src/safe_alloc.c -o '$(BUILD_DIR)/wallet-view-test'
	'$(BUILD_DIR)/wallet-view-test'

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

# Host fuzz of the QR path (quirc, then scan.c and payment_code.c) under ASan and UBSan, no NDK.
QR_FUZZ_ITERATIONS ?= 2000
QR_FUZZ_SAN ?= -fsanitize=address,undefined -fno-sanitize-recover=all
QR_FUZZ_SOURCES := scan.c payment_code.c fleet.c speech_client.c bridge_client.c bridge_auth.c ../../platform/modules/sha3/src/sha3.c voice.c \
  ../../contexts/commons/packages/zutf8/src/zutf8.c ../../vendor/qrcodegen/qrcodegen.c
.PHONY: test-qr-fuzz
test-qr-fuzz: prepare-quirc
	@mkdir -p '$(BUILD_DIR)'
	clang -std=c23 -O1 -g $(QR_FUZZ_SAN) -Wall -Wextra -Werror -pedantic \
	  -DQUIRC_MAX_REGIONS=65534 $(SPEECH_INCLUDES) -I../../vendor/qrcodegen -I'$(QUIRC_DIR)' \
	  tests/qr_fuzz_test.c $(QR_FUZZ_SOURCES) $(QUIRC_SOURCES) $(SPEECH_JSON) -lm -o '$(BUILD_DIR)/qr-fuzz-test'
	QR_FUZZ_ITERATIONS='$(QR_FUZZ_ITERATIONS)' '$(BUILD_DIR)/qr-fuzz-test'

test-scan:
	@mkdir -p '$(BUILD_DIR)'
	$(HOST_CC) $(HOST_WARNINGS) $(SPEECH_INCLUDES) -I../../vendor/qrcodegen tests/scan_test.c scan.c payment_code.c fleet.c speech_client.c bridge_client.c bridge_auth.c ../../platform/modules/sha3/src/sha3.c voice.c ../../contexts/commons/packages/zutf8/src/zutf8.c ../../vendor/qrcodegen/qrcodegen.c $(SPEECH_JSON) -o '$(BUILD_DIR)/scan-test'
	'$(BUILD_DIR)/scan-test'
.PHONY: test-camera-access
test-camera-access:
	@mkdir -p '$(BUILD_DIR)'
	$(HOST_CC) $(HOST_WARNINGS) -I. tests/camera_access_test.c camera_access.c -o '$(BUILD_DIR)/camera-access-test'
	'$(BUILD_DIR)/camera-access-test'
	@grep -q 'zapp_camera_wait_goes_on(i, atomic_load(&camera_paused)' android_main.c || { echo 'the camera wait must end on the dialog result or when no dialog appears' >&2; exit 1; }
	@grep -q 'zapp_camera_screen(ZAPP_CAMERA_GRANTED).hint' shell.c || { echo 'the scan screen must say what to point the camera at' >&2; exit 1; }

.PHONY: test-payment test-wallet
test-payment:
	@mkdir -p '$(BUILD_DIR)'
	$(HOST_CC) $(HOST_WARNINGS) -I. -I../../contexts/commons/packages/zutf8/include \
	  tests/payment_code_test.c payment_code.c ../../contexts/commons/packages/zutf8/src/zutf8.c \
	  -o '$(BUILD_DIR)/payment-code-test'
	'$(BUILD_DIR)/payment-code-test'

# wallet_ui.c and shell.c draw with the Android API and are not built on the host; the NDK build compiles them.
# What the host proves is the behaviour in wallet_screens.c, the command layer, and that no file that makes Home,
# the assistant or the controller can reach wallet data.
WALLET_FREE := home.c layout.c hosts.c pairing.c controller.c conversation.c bridge_client.c native_ui.c surface.c \
  launcher.c fleet.c voice.c speech_client.c scan.c audio.c nodelog.c rpc.c
test-wallet:
	@mkdir -p '$(BUILD_DIR)'
	$(HOST_CC) $(HOST_WARNINGS) -pthread $(SPEECH_INCLUDES) tests/wallet_screens_test.c wallet_screens.c payment_code.c wallet_view.c \
	  ../../contexts/commons/packages/zutf8/src/zutf8.c $(SPEECH_JSON) -o '$(BUILD_DIR)/wallet-screens-test'
	TMPDIR="$$(cd '$(BUILD_DIR)' && pwd)" '$(BUILD_DIR)/wallet-screens-test'
	$(HOST_CC) $(HOST_WARNINGS) -pthread $(SPEECH_INCLUDES) tests/wallet_run_test.c operations.c setup_state.c private.c params.c rpc.c nodelog.c \
	  ../../platform/modules/sha3/src/sha3.c $(SPEECH_JSON) -Wl,--wrap=posix_spawn -o '$(BUILD_DIR)/wallet-run-test'
	@set -e; scratch=$$(mktemp -d '$(BUILD_DIR)/wallet-run.XXXXXX'); \
	  trap 'rm -rf "$$scratch"' 0; ZAPP_TEST_DIR="$$(cd "$$scratch" && pwd)" '$(BUILD_DIR)/wallet-run-test'
	$(HOST_CC) $(HOST_WARNINGS) $(SPEECH_INCLUDES) tests/json_wipe_test.c $(SPEECH_JSON) -Wl,--wrap=realloc -Wl,--wrap=free \
	  -o '$(BUILD_DIR)/json-wipe-test'
	'$(BUILD_DIR)/json-wipe-test'
	@if grep -nwE 'printf|fprintf|puts|perror|__android_log_print|__android_log_write' wallet_screens.c wallet_ui.c; then \
	  echo 'wallet screens must not write to a log or console' >&2; exit 1; fi
	@if grep -nE '#include "(wallet_screens|wallet_view|wallet_ui|payment_code)\.h"' $(WALLET_FREE); then \
	  echo 'only the wallet files, the command layer and the shell may include the wallet headers' >&2; exit 1; fi
	@if test "$$(grep -c wallet_screens_close shell.c)" != 1; then \
	  echo 'the shell may close the wallet screens only when it is destroyed; every other exit pauses them' >&2; exit 1; fi
	@if grep -nE 'setTextIsSelectable", true|ClipboardManager|setPrimaryClip' wallet_screens.c wallet_view.c wallet_ui.c wallet_send_*.c; then \
	  echo 'wallet text must not be selectable or copied; the one exception is Copy address on Receive, which copies the bare receive address only, through secure_window.c' >&2; exit 1; fi
	@if grep -n zapp_clipboard_copy_sensitive wallet_screens.c wallet_view.c wallet_ui.c wallet_send_*.c | grep -v 'wallet_ui.c:[0-9]*:static bool bound_copy_address'; then \
	  echo 'zapp_clipboard_copy_sensitive may be called only from bound_copy_address in wallet_ui.c' >&2; exit 1; fi
	@grep -q 'zapp_wallet_ui_create(env, shell.activity, content, footer)' shell.c && grep -q 'wallet_item_pinned(&ui.screen.items\[item\]) ? ui.footer : ui.container' wallet_ui.c || { echo 'the wallet Back must be pinned under the scrolling content' >&2; exit 1; }

check-node:
	@test -x '$(NODE_BIN)' || { echo 'Build the Android node first' >&2; exit 1; }
	@headers="$$(LC_ALL=C readelf -lW '$(NODE_BIN)')" && printf '%s\n' "$$headers" | grep -F '/system/bin/linker64' >/dev/null || { echo 'NODE_BIN must be an Android ARM64 executable' >&2; exit 1; }
	@../../tools/scripts/check_c23_node_binary.sh '$(NODE_BIN)'

check-probe:
	@test "$(DEVKEY_PROBE)" = OFF || grep -q 'package="org.z23.voicepreview"' '$(APP_MANIFEST)' || { echo "DEVKEY_PROBE=$(DEVKEY_PROBE) refused: the device key probe is built only into the org.z23.voicepreview manifest (make preview-apk), never into org.z23.nativeapp" >&2; exit 1; }

check-config:
	@$(MAKE) --no-print-directory check-probe
	@test -f '$(ANDROID_NDK_ROOT)/build/cmake/android.toolchain.cmake' || { echo 'Set ANDROID_NDK_ROOT to the installed NDK' >&2; exit 1; }
	@test -r '$(ANDROID_JAR)' && test -x '$(TOOLS)/aapt' && test -x '$(TOOLS)/zipalign' && test -x '$(TOOLS)/apksigner' || { echo 'Set SDK_ROOT and BUILD_TOOLS_VERSION to an installed Android SDK' >&2; exit 1; }
	@test -x '$(JAVA_HOME)/bin/keytool' && test -x '$(JAVA_HOME)/bin/jar' || { echo 'Set JAVA_HOME to an installed JDK' >&2; exit 1; }
	@test '$(ANDROID_API)' = 35 || { echo 'The current application manifest requires API 35' >&2; exit 1; }
	@min=$$(sed -n 's/.*minSdkVersion="\([0-9][0-9]*\)".*/\1/p' '$(APP_MANIFEST)'); test -n "$$min" && test "$$min" -ge 30 || { echo 'The device key needs per-use authentication with a device credential: the manifest minSdkVersion must be 30 or higher' >&2; exit 1; }

# The Sapling proving parameters are build inputs kept out of git, like vendor/cross.
check-params:
	@test -d '$(PARAMS_DIR)' || { echo 'Proving parameters not found: put the files listed in $(PARAMS_SUMS) in $(PARAMS_DIR) or set PARAMS_DIR.' >&2; exit 1; }
	@out=$$(cd '$(PARAMS_DIR)' && sha256sum -c '$(abspath $(PARAMS_SUMS))' 2>&1) || { printf '%s\n' "$$out" >&2; echo 'Proving parameters in $(PARAMS_DIR) are missing or do not match $(PARAMS_SUMS); refusing to build.' >&2; exit 1; }

native: check-config prepare-quirc
	cmake -S . -B '$(BUILD_DIR)/native' \
	  -DCMAKE_TOOLCHAIN_FILE='$(ANDROID_NDK_ROOT)/build/cmake/android.toolchain.cmake' \
	  -DANDROID_ABI=arm64-v8a -DANDROID_PLATFORM=android-$(ANDROID_API) \
	  -DZ23_ANDROID_API=$(ANDROID_API) -DZ23_QUIRC_DIR='$(QUIRC_DIR)' -DZ23_DEVKEY_PROBE=$(DEVKEY_PROBE) -DCMAKE_BUILD_TYPE=Release
	cmake --build '$(BUILD_DIR)/native' --parallel 4

.PHONY: check-signer-input check-signer-output
check-signer-input:
	@if test -n "$$EXPECTED_SIGNER_SHA256"; then \
	  case "$$EXPECTED_SIGNER_SHA256" in *[!0-9a-fA-F]*) echo "EXPECTED_SIGNER_SHA256 must be 64 hex digits" >&2; exit 1;; esac; \
	  test "$${#EXPECTED_SIGNER_SHA256}" -eq 64 || { echo "EXPECTED_SIGNER_SHA256 must be 64 hex digits" >&2; exit 1; }; \
	  test -r '$(KEYSTORE)' || { echo "Expected signer requires an existing readable keystore" >&2; exit 1; }; \
	fi

$(KEYSTORE): | check-signer-input
	@mkdir -p '$(dir $(KEYSTORE))'
	'$(JAVA_HOME)/bin/keytool' -genkeypair -keystore '$@' -storepass android \
	  -alias z23-development -keypass android -dname 'CN=Z23 Development' \
	  -keyalg RSA -keysize 3072 -validity 3650 -noprompt

apk: check-signer-input check-probe check-node $(if $(filter 1,$(PACK_PARAMS)),check-params) native dexgen $(KEYSTORE)
	@test -x '$(NODE_BIN)' || { echo 'Build the Android node with make ZCL_TARGET=android-arm64 z23 first' >&2; exit 1; }
	@mkdir -p '$(BUILD_DIR)/package/lib/arm64-v8a'
	cp '$(BUILD_DIR)/native/libz23android.so' '$(BUILD_DIR)/package/lib/arm64-v8a/'
	cp '$(NODE_BIN)' '$(BUILD_DIR)/package/lib/arm64-v8a/libz23node.so'
	rm -rf '$(BUILD_DIR)/assets'
	$(if $(filter 1,$(PACK_PARAMS)),mkdir -p '$(BUILD_DIR)/assets/params' && cp $(addprefix '$(PARAMS_DIR)'/,$(shell awk '{print $$2}' $(PARAMS_SUMS))) '$(BUILD_DIR)/assets/params/')
	'$(TOOLS)/aapt' package -f -M '$(APP_MANIFEST)' -S res $(if $(filter 1,$(PACK_PARAMS)),-A '$(BUILD_DIR)/assets' -0 params) \
	  -I '$(ANDROID_JAR)' -F '$(BUILD_DIR)/resources.apk'
	'$(BUILD_DIR)/dexgen' '$(BUILD_DIR)/package/classes.dex'
	cp '$(BUILD_DIR)/resources.apk' '$(BUILD_DIR)/unsigned.apk'
	'$(JAVA_HOME)/bin/jar' uf '$(BUILD_DIR)/unsigned.apk' -C '$(BUILD_DIR)/package' classes.dex -C '$(BUILD_DIR)/package' lib
	'$(TOOLS)/zipalign' -f -P 16 4 '$(BUILD_DIR)/unsigned.apk' '$(BUILD_DIR)/aligned.apk'
	'$(TOOLS)/apksigner' sign --ks '$(KEYSTORE)' --ks-key-alias z23-development \
	  --ks-pass pass:android --key-pass pass:android --out '$(APK)' '$(BUILD_DIR)/aligned.apk'
	'$(TOOLS)/apksigner' verify --verbose '$(APK)'
	@$(MAKE) --no-print-directory check-signer-output

check-signer-output: check-signer-input
	@if test -n "$$EXPECTED_SIGNER_SHA256"; then \
	  certs=$$('$(TOOLS)/apksigner' verify --print-certs '$(APK)') || { echo "APK signature verification failed" >&2; exit 1; }; \
	  actual=$$(printf '%s\n' "$$certs" | sed -n 's/^Signer #1 certificate SHA-256 digest: //p'); \
	  expected=$$(printf '%s' "$$EXPECTED_SIGNER_SHA256" | tr 'A-F' 'a-f'); \
	  test "$$actual" = "$$expected" || { echo "APK signer does not match EXPECTED_SIGNER_SHA256" >&2; exit 1; }; \
	fi

install: apk
	@test -n '$(ANDROID_SERIAL)' || { echo 'Set ANDROID_SERIAL to one adb device serial' >&2; exit 1; }
	'$(ADB)' -s '$(ANDROID_SERIAL)' install -r '$(APK)'

launch:
	@test -n '$(ANDROID_SERIAL)' || { echo 'Set ANDROID_SERIAL to one adb device serial' >&2; exit 1; }
	'$(ADB)' -s '$(ANDROID_SERIAL)' shell am start -n '$(APP_ID)/android.app.NativeActivity'

HOST_TEST_BASE := $(SPEECH_JSON) ../../platform/modules/sha3/src/sha3.c
test-host:
	@mkdir -p '$(BUILD_DIR)'
	$(HOST_CC) $(HOST_WARNINGS) tests/surface_test.c -o '$(BUILD_DIR)/surface-test'
	'$(BUILD_DIR)/surface-test'
	@grep -q 'bind->node->lines > 0 ? VIEW_INVISIBLE : VIEW_GONE' surface.c || { echo 'an empty text whose layout node names its lines must keep its place' >&2; exit 1; }
	$(HOST_CC) $(HOST_WARNINGS) -I. -I../../contexts/commons/packages/zsha256/include tests/params_test.c params.c params_install.c params_job.c \
	  -I../../platform/modules/json/include -I../../platform/modules/base/include ../../platform/modules/json/src/json.c \
	  ../../platform/modules/base/src/safe_alloc.c ../../platform/modules/base/src/cleanse.c \
	  ../../contexts/commons/packages/zsha256/src/zsha256.c -Wl,--wrap=fsync -Wl,--wrap=write -Wl,--wrap=pread -Wl,--wrap=close -Wl,--wrap=calloc -Wl,--wrap=free -Wl,--wrap=pthread_create -pthread -o '$(BUILD_DIR)/params-test'
	@set -e; scratch=$$(mktemp -d '$(BUILD_DIR)/params-test.XXXXXX'); \
	  trap 'rm -rf "$$scratch"' 0; '$(BUILD_DIR)/params-test' "$$scratch"
	$(HOST_CC) $(HOST_WARNINGS) $(SPEECH_INCLUDES) tests/hosts_test.c hosts.c pairing.c private.c $(HOST_TEST_BASE) -o '$(BUILD_DIR)/hosts-test'
	'$(BUILD_DIR)/hosts-test'
	$(HOST_CC) $(HOST_WARNINGS) $(SPEECH_INCLUDES) tests/private_test.c private.c $(HOST_TEST_BASE) -o '$(BUILD_DIR)/private-test'
	@set -e; scratch=$$(mktemp -d '$(BUILD_DIR)/private-test.XXXXXX'); \
	  trap 'rm -rf "$$scratch"' 0; '$(BUILD_DIR)/private-test' "$$scratch"
	$(HOST_CC) $(HOST_WARNINGS) -pthread -I. tests/nodelog_test.c nodelog.c -o '$(BUILD_DIR)/nodelog-test'
	@set -e; scratch=$$(mktemp -d '$(BUILD_DIR)/nodelog-test.XXXXXX'); \
	  trap 'rm -rf "$$scratch"' 0; '$(BUILD_DIR)/nodelog-test' "$$scratch"
	$(HOST_CC) $(HOST_WARNINGS) $(SPEECH_INCLUDES) tests/fleet_probe_test.c bridge/fleet_probe.c private.c \
	  ../../contexts/commons/packages/zutf8/src/zutf8.c $(SPEECH_JSON) -o '$(BUILD_DIR)/fleet-probe-test'
	'$(BUILD_DIR)/fleet-probe-test'
	$(HOST_CC) $(HOST_WARNINGS) $(SPEECH_INCLUDES) tests/host_ops_test.c bridge/host_ops.c $(SPEECH_JSON) -o '$(BUILD_DIR)/host-ops-test'
	'$(BUILD_DIR)/host-ops-test'
	$(HOST_CC) $(HOST_WARNINGS) -pthread $(SPEECH_INCLUDES) tests/http_test.c bridge/http.c $(SPEECH_JSON) -o '$(BUILD_DIR)/http-test'
	'$(BUILD_DIR)/http-test'
	$(HOST_CC) $(HOST_WARNINGS) -pthread $(SPEECH_INCLUDES) tests/assistant_test.c bridge/http.c bridge/fleet_probe.c private.c voice.c \
	  ../../platform/modules/encoding/src/utilstrencodings.c ../../contexts/commons/packages/zutf8/src/zutf8.c \
	  $(SPEECH_JSON) -o '$(BUILD_DIR)/assistant-test'
	'$(BUILD_DIR)/assistant-test'
	$(HOST_CC) $(HOST_WARNINGS) $(SPEECH_INCLUDES) tests/thermal_test.c thermal.c -o '$(BUILD_DIR)/thermal-test'
	'$(BUILD_DIR)/thermal-test'
	$(HOST_CC) $(HOST_WARNINGS) -D__ANDROID__ -pthread -Itests/ndk_fake -I. tests/thermal_start_test.c thermal.c -o '$(BUILD_DIR)/thermal-start-test'
	'$(BUILD_DIR)/thermal-start-test'
	$(HOST_CC) $(HOST_WARNINGS) $(SPEECH_INCLUDES) tests/layout_test.c layout.c $(SPEECH_JSON) -o '$(BUILD_DIR)/layout-test'
	@set -e; scratch=$$(mktemp -d '$(BUILD_DIR)/layout-test.XXXXXX'); \
	  trap 'rm -rf "$$scratch"' 0; '$(BUILD_DIR)/layout-test' "$$scratch"
	$(HOST_CC) $(HOST_WARNINGS) $(SPEECH_INCLUDES) -pthread -I../../vendor/qrcodegen tests/home_test.c home.c layout.c hosts.c private.c pairing.c scan.c payment_code.c wallet_screens.c wallet_view.c fleet.c speech_client.c bridge_client.c bridge_auth.c voice.c ../../contexts/commons/packages/zutf8/src/zutf8.c ../../vendor/qrcodegen/qrcodegen.c $(HOST_TEST_BASE) -o '$(BUILD_DIR)/home-test'
	'$(BUILD_DIR)/home-test'
	$(HOST_CC) $(HOST_WARNINGS) -I. tests/node_notice_test.c node_notice.c -o '$(BUILD_DIR)/node-notice-test'
	'$(BUILD_DIR)/node-notice-test'
	$(HOST_CC) $(HOST_WARNINGS) -I. tests/node_restart_test.c node_restart.c -o '$(BUILD_DIR)/node-restart-test'
	'$(BUILD_DIR)/node-restart-test'
	$(HOST_CC) $(HOST_WARNINGS) -I. tests/action_text_test.c action_text.c -o '$(BUILD_DIR)/action-text-test'
	'$(BUILD_DIR)/action-text-test'
	$(HOST_CC) $(HOST_WARNINGS) -I. tests/view_hit_test.c view_hit.c -o '$(BUILD_DIR)/view-hit-test'
	'$(BUILD_DIR)/view-hit-test'
	@! sed -n '/^static void \*worker(/,/^}/p' controller.c | grep -n 'observe_node' || { echo 'the action worker must not read the node status: a stuck read would hold every tap' >&2; exit 1; }

.PHONY: test-devkey
test-devkey:
	@mkdir -p '$(BUILD_DIR)'
	$(HOST_CC) $(HOST_WARNINGS) -pthread -I. -I../../platform/modules/base/include tests/device_key_test.c device_key.c \
	  ../../platform/modules/base/src/cleanse.c -o '$(BUILD_DIR)/device-key-test'
	@set -e; scratch=$$(mktemp -d '$(BUILD_DIR)/device-key-test.XXXXXX'); \
	  trap 'rm -rf "$$scratch"' 0; '$(BUILD_DIR)/device-key-test' "$$scratch"
	@grep -q 'android:name="android.permission.USE_BIOMETRIC"' AndroidManifest.xml || { echo "AndroidManifest.xml lacks USE_BIOMETRIC: BiometricPrompt.authenticate would throw SecurityException and every wallet key use would fail" >&2; exit 1; }
	@grep -q 'android:allowAudioPlaybackCapture="false"' AndroidManifest.xml || { echo "AndroidManifest.xml must set android:allowAudioPlaybackCapture=false: otherwise another app can record what the Assistant says aloud" >&2; exit 1; }
	@if $(MAKE) --no-print-directory check-probe DEVKEY_PROBE=ON 2>/dev/null; then echo "production manifest accepted DEVKEY_PROBE=ON" >&2; exit 1; fi
	@sed -n '/^static jobject key_spec/,/^}/p' device_key_jni.c | grep -q 'setUserAuthenticationParameters", BUILDER_SIG("II"), AUTH_EVERY_USE, AUTH_TYPES' || { echo "the wallet key must ask for the screen lock at every use" >&2; exit 1; }
	@spec="$$(sed -n '/^static jobject balance_spec/,/^}/p' device_key_jni.c)"; \
	  printf '%s\n' "$$spec" | grep -q 'setUserAuthenticationRequired", BUILDER_SIG("Z"), JNI_FALSE' && \
	  printf '%s\n' "$$spec" | grep -q 'setUnlockedDeviceRequired", BUILDER_SIG("Z"), JNI_TRUE' && \
	  printf '%s\n' "$$spec" | grep -q 'NewStringUTF(env, BALANCE_ALIAS)' || { echo "the balance key must ask for no screen lock and be refused while the phone is locked" >&2; exit 1; }
	@grep -q '^#define BALANCE_ALIAS "z23.wallet.balance-key.v1"$$' device_key_jni.c && grep -q '^#define ALIAS "z23.wallet.device-key.v2"$$' device_key_jni.c || { echo "the balance key must keep an alias apart from the wallet key" >&2; exit 1; }
	$(HOST_CC) $(HOST_WARNINGS) -I. tests/secure_window_test.c secure_window.c -o '$(BUILD_DIR)/secure-window-test'
	@set -e; scratch=$$(mktemp -d '$(BUILD_DIR)/secure-window-test.XXXXXX'); \
	  trap 'rm -rf "$$scratch"' 0; '$(BUILD_DIR)/secure-window-test' "$$scratch"

# First-run wallet setup: the words, the state files, the node adapter and the wizard model over a fake device and node.
# None of these files may log or write the words and the passphrase that pass through them.
.PHONY: test-setup
test-setup:
	@mkdir -p '$(BUILD_DIR)'
	$(HOST_CC) $(HOST_WARNINGS) -pthread -I. -I../../platform/modules/sha3/include -I../../platform/modules/json/include -I../../platform/modules/base/include \
	  -I../../contexts/commons/packages/zsha256/include tests/setup_test.c setup_words.c setup_wordlist.c setup_state.c setup_node.c wallet_setup.c device_key.c ../../platform/modules/sha3/src/sha3.c ../../contexts/commons/packages/zsha256/src/zsha256.c $(SPEECH_JSON) -Wl,--wrap=free -o '$(BUILD_DIR)/setup-test'
	@set -e; scratch=$$(mktemp -d '$(BUILD_DIR)/setup-test.XXXXXX'); \
	  trap 'rm -rf "$$scratch"' 0; '$(BUILD_DIR)/setup-test' "$$(cd "$$scratch" && pwd)"
	@sed -n '/^static const char \*const bip39_english\[2048\] = {$$/,/^};$$/p' ../../contexts/wallet/domain/src/mnemonic.c | sed '1d;$$d' > '$(BUILD_DIR)/wordlist.expect'; \
	  sed -n '/^const char \*const zapp_wordlist/,/^};$$/p' setup_wordlist.c | sed '1d;$$d' > '$(BUILD_DIR)/wordlist.ours'; \
	  [ "$$(wc -l < '$(BUILD_DIR)/wordlist.expect')" -eq 2048 ] && [ "$$(wc -l < '$(BUILD_DIR)/wordlist.ours')" -eq 2048 ] && cmp -s '$(BUILD_DIR)/wordlist.ours' '$(BUILD_DIR)/wordlist.expect' || { echo "setup_wordlist.c is not the 2048 words of mnemonic.c" >&2; exit 1; }
	@if grep -nE '(^|[^a-z_])(printf|fprintf|puts|fputs|perror|syslog)\(|nodelog|__android_log' setup_words.c setup_state.c setup_node.c wallet_setup.c wallet_setup_ui.c; then \
	  echo 'wallet setup must not log' >&2; exit 1; fi
	@if grep -nE '(^|[^a-z_])(fopen|fwrite|fputs|open|write|creat|rename)\(' setup_words.c setup_node.c wallet_setup.c wallet_setup_ui.c; then \
	  echo 'the recovery words and the passphrase must not be written by the setup modules' >&2; exit 1; fi
	@grep -q 'if (!v.protected)' wallet_setup_ui.c || { echo 'the setup screens must draw nothing while the window is unprotected (the model also withholds the words; see protection_tests)' >&2; exit 1; }
	@grep -q 'env_progress, env_protect' wallet_setup_ui.c || { echo 'the setup screens must give the model the window protection' >&2; exit 1; }
	@sed -n '/^static bool input_view/,/^}/p' wallet_setup_ui.c | grep -q 'setCursorVisible", false' || { echo 'the word fields must hide the cursor so no insertion handle offers Paste' >&2; exit 1; }
	@! grep -q 'nothing can have been sent' wallet_setup_ui.c || { echo 'the setup screens must not claim a wallet is empty' >&2; exit 1; }
	@sed -n '/^static void draw_failed_buttons/,/^}/p' wallet_setup_ui.c | grep -q 'WSU_ASIDE_STUCK) return;' || { echo 'a wallet that could not be put back must be offered no button' >&2; exit 1; }
	@sed -n '/^static void draw_failed_buttons/,/^}/p' wallet_setup_ui.c | grep -q 'WSU_NO_BIRTHDAY) (void)button_view(env, B_START_OVER_ASK' || { echo 'a wallet with no start height must be offered Start over' >&2; exit 1; }
	@sed -n '/^static void draw_failed_buttons/,/^}/p' wallet_setup_ui.c | grep -q 'else if (wsu_failure_retries(failure))' || { echo 'a phone that cannot protect a wallet key in hardware must be offered no Try again' >&2; exit 1; }
	@sed -n '/^static bool by_button/,/^}/p' shell.c | grep -q 'TARGET_SETUP' || { echo 'a setup tap must be matched by button identity at release' >&2; exit 1; }
	@grep -q 'v->refusal != WSU_NO_FAILURE' wallet_setup_ui.c || { echo 'a refused Start over must say why on the screen it returns to' >&2; exit 1; }
	@grep -q 'ZAPP_FIELD_PRIVATE' wallet_setup_ui.c || { echo 'the word fields must be checked against ZAPP_FIELD_PRIVATE' >&2; exit 1; }
	@sed -n '/^static void draw_words/,/^}/p' wallet_setup_ui.c | grep -q 'WSU_SCREEN_LOCK_NOTICE' || { echo 'the words screen must carry the screen lock notice' >&2; exit 1; }
	@grep -q 'zj_text(env, ui.words_input, v->form)' wallet_setup_ui.c || { echo 'the restore form must show the words kept from its last try' >&2; exit 1; }
	@sed -n '/^void zapp_setup_ui_clear/,/^}/p' wallet_setup_ui.c | grep -q 'wsu_forget_form(&ui.model)' || { echo 'leaving or hiding setup must cleanse the kept restore words' >&2; exit 1; }
	@grep -q 'v->may_start_over' wallet_setup_ui.c || { echo 'Start over must be offered only for a create' >&2; exit 1; }
	@grep -q 'wsu_view_can_recheck(v)' wallet_setup_ui.c || { echo 'the interrupted screen must offer Check again by the model' >&2; exit 1; }
	@grep -q 'wsu_words_intro(v, line' wallet_setup_ui.c || { echo 'the words screen must write its intro by the model, which omits an unrecorded start height' >&2; exit 1; }
	@grep -q 'ZAPP_SETUP_READY ? SCREEN_WALLET : SCREEN_SETUP' shell.c || { echo 'the Wallet tile must open setup until setup is finished' >&2; exit 1; }
	@grep -q 'if (wallet_screen(next) || next == SCREEN_ASSISTANT) shell.gate.protect = true' shell.c && grep -q 'static bool wallet_screen(enum screen s) { return s == SCREEN_WALLET || s == SCREEN_SEND || s == SCREEN_SETUP; }' shell.c || { echo 'the shell must drop obscured touches on the wallet, send, setup and assistant screens' >&2; exit 1; }
	@grep -q 'setTextIsSelectable", false' wallet_setup_ui.c || { echo 'the recovery words must not be selectable' >&2; exit 1; }
	@grep -q 'next = screen_for(next);' shell.c || { echo 'the shell must send the wallet and payment screens through setup until it is confirmed' >&2; exit 1; }
	@test "$$(grep -c 'go(env, SCREEN_SEND)' shell.c)" = 2 && grep -q 'take_reshow()) go(env, SCREEN_SEND);' shell.c || { echo 'Send must be entered through open_send, except to show a kept flow' >&2; exit 1; }
	@grep -q 'case CMD_CAMERA_PASTE: open_send(env, NULL, "", false);' shell.c || { echo 'Paste instead must open the Send flow' >&2; exit 1; }
	@grep -q 'memory_cleanse(buffer, sizeof(buffer))' operations.c || { echo 'the command reader must wipe its read buffer' >&2; exit 1; }
	@grep -q 'zapp_setup_state(r->files) != ZAPP_SETUP_READY' operations.c || { echo 'the receive command must be refused until setup is confirmed' >&2; exit 1; }

WALLET_SEND_INCLUDES := -I. -I../../platform/modules/json/include -I../../platform/modules/base/include \
  -I../../contexts/commons/packages/zutf8/include \
  -I../../contexts/wallet/controllers/include -I../../platform/modules/util/include -I../../platform/modules/sha3/include
WALLET_SEND_SOURCES := wallet_send.c payment_code.c ../../contexts/commons/packages/zutf8/src/zutf8.c
SEND_KEY_SOURCES := send_key.c ../../platform/modules/sha3/src/sha3.c
# The send flow: the state machine with its random event sequences, then the screen over fake node, device
# key and host. No wallet field may reach a log, so the two modules call no logging function.
test-wallet-send:
	@mkdir -p '$(BUILD_DIR)'
	$(HOST_CC) $(HOST_WARNINGS) $(WALLET_SEND_INCLUDES) tests/wallet_send_test.c $(WALLET_SEND_SOURCES) \
	  -o '$(BUILD_DIR)/wallet-send-test'
	'$(BUILD_DIR)/wallet-send-test'
	$(HOST_CC) $(HOST_WARNINGS) -pthread $(WALLET_SEND_INCLUDES) tests/wallet_send_screen_test.c wallet_send_screen.c wallet_send_keeper.c wallet_screens.c \
	  secure_window.c wallet_view.c $(SEND_KEY_SOURCES) $(WALLET_SEND_SOURCES) $(SPEECH_JSON) -o '$(BUILD_DIR)/wallet-send-screen-test'
	'$(BUILD_DIR)/wallet-send-screen-test'
	$(HOST_CC) $(HOST_WARNINGS) $(WALLET_SEND_INCLUDES) tests/send_key_test.c $(SEND_KEY_SOURCES) payment_code.c \
	  ../../contexts/commons/packages/zutf8/src/zutf8.c $(SPEECH_JSON) -o '$(BUILD_DIR)/send-key-test'
	@set -e; scratch=$$(mktemp -d '$(BUILD_DIR)/send-key-test.XXXXXX'); \
	  trap 'rm -rf "$$scratch"' 0; '$(BUILD_DIR)/send-key-test' "$$(cd "$$scratch" && pwd)"
	$(HOST_CC) $(HOST_WARNINGS) -pthread $(WALLET_SEND_INCLUDES) tests/wallet_send_node_test.c wallet_send_node.c wallet_send_screen.c wallet_screens.c \
	  secure_window.c wallet_view.c $(WALLET_SEND_SOURCES) $(SPEECH_JSON) -o '$(BUILD_DIR)/wallet-send-node-test'
	'$(BUILD_DIR)/wallet-send-node-test'
	$(HOST_CC) $(HOST_WARNINGS) -pthread $(WALLET_SEND_INCLUDES) tests/wallet_sweep_test.c wallet_sweep.c wallet_send_node.c wallet_send_screen.c wallet_screens.c \
	  secure_window.c wallet_view.c $(WALLET_SEND_SOURCES) $(SPEECH_JSON) -o '$(BUILD_DIR)/wallet-sweep-test'
	'$(BUILD_DIR)/wallet-sweep-test'
	$(HOST_CC) $(HOST_WARNINGS) -pthread $(WALLET_SEND_INCLUDES) tests/wallet_send_device_test.c wallet_send_device.c device_key.c wallet_send_screen.c wallet_screens.c \
	  secure_window.c wallet_view.c $(WALLET_SEND_SOURCES) $(SPEECH_JSON) -o '$(BUILD_DIR)/wallet-send-device-test'
	@set -e; scratch=$$(mktemp -d '$(BUILD_DIR)/wallet-send-device.XXXXXX'); \
	  trap 'rm -rf "$$scratch"' 0; '$(BUILD_DIR)/wallet-send-device-test' "$$(cd "$$scratch" && pwd)"
	$(HOST_CC) $(HOST_WARNINGS) -pthread $(WALLET_SEND_INCLUDES) tests/wallet_reveal_test.c wallet_reveal.c wallet_send_screen.c wallet_screens.c \
	  secure_window.c wallet_view.c $(WALLET_SEND_SOURCES) $(SPEECH_JSON) -o '$(BUILD_DIR)/wallet-reveal-test'
	'$(BUILD_DIR)/wallet-reveal-test'
	$(HOST_CC) $(HOST_WARNINGS) -pthread $(SPEECH_INCLUDES) -I../../vendor/qrcodegen tests/pay_stash_test.c pay_stash.c scan.c payment_code.c fleet.c speech_client.c bridge_client.c bridge_auth.c ../../platform/modules/sha3/src/sha3.c voice.c \
	  ../../contexts/commons/packages/zutf8/src/zutf8.c ../../vendor/qrcodegen/qrcodegen.c $(SPEECH_JSON) -o '$(BUILD_DIR)/pay-stash-test'
	'$(BUILD_DIR)/pay-stash-test'
	$(HOST_CC) $(HOST_WARNINGS) -I. tests/payment_notice_test.c payment_notice.c -o '$(BUILD_DIR)/payment-notice-test'
	'$(BUILD_DIR)/payment-notice-test'
	@if grep -nE '(^|[^a-z_])(printf|fprintf|puts|fputs|perror|syslog)\(|nodelog|__android_log' wallet_send.c wallet_send_screen.c wallet_send_node.c wallet_sweep.c wallet_send_device.c wallet_send_keeper.c wallet_send_ui.c wallet_reveal.c pay_stash.c send_key.c; then \
	  echo 'wallet_send must not log' >&2; exit 1; fi
	@if grep -n 'zapp_pay_stash_take' $(WALLET_FREE); then \
	  echo 'only the shell may take the payment out of the stash' >&2; exit 1; fi
	@for flag in uiMode screenLayout smallestScreenSize density keyboard navigation; do \
	  grep -q "android:configChanges=\"[^\"]*\b$$flag\b" AndroidManifest.xml || { echo "AndroidManifest.xml must handle the $$flag change itself: a recreated activity would orphan a payment in flight" >&2; exit 1; }; done
	@test "$$(grep -c zapp_pay_stash_clear shell.c)" -ge 3 && grep -q zapp_pay_stash_clear android_main.c || { echo 'the payment stash must be cleared on Back while decoding, when a dismissed scan finishes, and on destroy' >&2; exit 1; }
	@grep -q zapp_send_key_derive wallet_send_ui.c || { echo 'the send screen must derive the payment key from the request' >&2; exit 1; }
	@grep -q "v->can_pay_again) (void)button_view(env, B_PAY_AGAIN" wallet_send_ui.c || { echo 'the send screen must draw Pay again when the view offers it' >&2; exit 1; }
	@sed -n '/^static void draw_flow/,/^}/p' wallet_send_ui.c | grep -q 'if (v->state == WS_PARSED || v->state == WS_REVIEW) {' || { echo 'the send screen must offer Change amount on the review' >&2; exit 1; }
	@grep -q "make_screen, wait_for_lock, bind_screen}" wallet_send_ui.c || { echo 'the send screen must bind an adopted flow to the new window' >&2; exit 1; }
	@grep -q 'wallet_view_trim_address(text);' wallet_send_ui.c || { echo 'the address field must be trimmed before it is parsed' >&2; exit 1; }
	@grep -q zapp_send_ui_take_reshow shell.c || { echo 'the shell must show a payment kept from the replaced activity' >&2; exit 1; }
	@grep -q 'if (start->paste) (void)button_view(env, B_PASTE, "Paste address"' wallet_send_ui.c || { echo 'Paste address must be drawn only while the clipboard holds an address' >&2; exit 1; }
	@! grep -q 'Enter address' wallet_send_ui.c || { echo 'the Send page must show the address field without a tap on Enter address' >&2; exit 1; }
	@grep -q 'ask_keyboard(env, flow ? v.focus : start.focus);' wallet_send_ui.c || { echo 'a Send page with a field must ask for its keyboard when it opens' >&2; exit 1; }
	@grep -q 'wallet_screens_spendable(&spendable)) zapp_send_ui_known_balance(spendable);' shell.c || { echo 'Send opened from Funds must start from the balance Funds shows' >&2; exit 1; }
	@grep -q 'ui.drawn_flow && ui.keeper.screen) wss_keep_balance(ui.keeper.screen, true);' wallet_send_ui.c || { echo 'the Send page with no payment open must keep its balance reading while it is shown' >&2; exit 1; }
	@grep -q 'wss_clip_check(&ui.clip, state, stamp, clip_text, ui.activity, ZAPP_SCAN_NETWORK);' wallet_send_ui.c || { echo 'the Send page must read each clip once, through wss_clip_check' >&2; exit 1; }
