# Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
# Shared playable Skycombat recipe for repository and self-contained copies.
# Defaults apply only when the enclosing build has not supplied its policy.
SKYCOMBAT_RECIPE := $(lastword $(MAKEFILE_LIST))
SKYCOMBAT_MAKE_INPUTS := $(patsubst ./%,%,$(or $(SKYCOMBAT_ENTRY_MAKEFILE),Makefile) $(SKYCOMBAT_RECIPE))
# An empty goal list means the default build, not a query. A mixed invocation
# must still load header dependencies for every build target it requests.
override SKYCOMBAT_QUERY_ONLY := $(if $(strip $(MAKECMDGOALS)),$(if $(filter-out print-game-closure print-app-closure,$(MAKECMDGOALS)),,1),)
ZCL_HOST_OS ?= $(shell uname -s)
ZCL_REPRO_ROOT ?= /zclassic23
ZCL_CC_DRIVER ?= $(notdir $(lastword $(CC)))
ZCL_CC_IS_CLANG ?= $(if $(findstring clang,$(ZCL_CC_DRIVER)),1,)
BUILD_DIR ?= build
BIN_DIR ?= $(BUILD_DIR)/bin
SKYCOMBAT_IMAGE ?= $(BIN_DIR)/z23-skycombat

ifeq ($(ZCL_HOST_OS),Darwin)
ifeq ($(origin CC),default)
CC := clang
endif
ifeq ($(origin SDKROOT),undefined)
SDKROOT := $(shell /usr/bin/xcrun --sdk macosx --show-sdk-path 2>/dev/null)
endif
ifeq ($(strip $(SDKROOT)),)
$(error Darwin SDK unavailable: set SDKROOT to an installed macOS SDK or configure xcrun)
endif
ifneq ($(shell test -r '$(subst ','"'"',$(SDKROOT))/usr/include/assert.h' && printf yes),yes)
$(error Darwin SDK unavailable: SDKROOT must name an installed macOS SDK with usr/include/assert.h)
endif
export SDKROOT
REPRO_CFLAGS ?= -ffile-prefix-map=$(CURDIR)=$(ZCL_REPRO_ROOT)
ZCL_MACOS_DEPLOYMENT_TARGET ?= 14.0
export MACOSX_DEPLOYMENT_TARGET := $(ZCL_MACOS_DEPLOYMENT_TARGET)
ZCL_PLATFORM_CPPFLAGS ?= -mmacosx-version-min=$(ZCL_MACOS_DEPLOYMENT_TARGET) \
	-DZCL_MACOS_DEPLOYMENT_TARGET=\"$(ZCL_MACOS_DEPLOYMENT_TARGET)\" \
	-D_DARWIN_C_SOURCE -Dst_atim=st_atimespec -Dst_mtim=st_mtimespec \
	-Dst_ctim=st_ctimespec -fblocks
else
REPRO_CFLAGS ?= -ffile-prefix-map=$(CURDIR)=$(ZCL_REPRO_ROOT) -gno-record-gcc-switches
ifneq ($(filter MINGW% MSYS% CYGWIN%,$(ZCL_HOST_OS)),)
ZCL_PLATFORM_CPPFLAGS ?= -D_WIN32_WINNT=0x0A00 \
	-DWIN32_LEAN_AND_MEAN -D__USE_MINGW_ANSI_STDIO=1 -DSECP256K1_STATIC
else
ZCL_PLATFORM_CPPFLAGS ?=
endif
endif

# The root build supplies its selected dialect. A standalone copy asks its
# actual compiler without creating an object, including during closure query.
ifeq ($(origin ZCL_C_STD),undefined)
SKYCOMBAT_PROBE_ENV := $(if $(filter Darwin,$(ZCL_HOST_OS)),SDKROOT='$(subst ','"'"',$(SDKROOT))',)
ZCL_C_STD := $(shell printf 'int main(void){return 0;}' | $(SKYCOMBAT_PROBE_ENV) $(CC) -std=c23 -fsyntax-only -x c - >/dev/null 2>&1 && printf c23 || printf c2x)
endif

ifneq ($(strip $(filter Darwin,$(ZCL_HOST_OS)) $(ZCL_CC_IS_CLANG)),)
ZCL_WARN_EXTRA_GATES ?= -Wundef -Wstrict-prototypes -Wdouble-promotion \
	-Wshift-overflow -Walloca -Wvla
ZCL_WARN_STRINGOP_OVERFLOW ?=
else
ZCL_WARN_EXTRA_GATES ?= -Wundef -Wstrict-prototypes -Wdouble-promotion \
	-Wduplicated-cond -Wduplicated-branches -Wshift-overflow=2 \
	-Wattribute-alias=2 -Walloca -Wvla -Wtrampolines \
	-Wflex-array-member-not-at-end
# suppression-ok: preserve the maintained root Makefile's GCC warning policy in standalone copies; this extraction adds no suppressed diagnostic class
ZCL_WARN_STRINGOP_OVERFLOW ?= -Wno-stringop-overflow
endif

SKYCOMBAT_DIR ?= apps/skycombat
Z23RAYLIB_DIR := vendor/raylib
SKYCOMBAT_OBJ_DIR := $(BUILD_DIR)/skycombat
Z23RAYLIB_OBJ_DIR := $(BUILD_DIR)/raylib
Z23RAYLIB_LIB := $(BUILD_DIR)/lib/libz23raylib.a

# The header closure RGFW and rlgl reach for on each host. `make game` and
# `make game-check` probe these and refuse by name rather than letting the
# compiler produce a wall of errors about a missing -dev package.
ifeq ($(ZCL_HOST_OS),Darwin)
SKYCOMBAT_PLATFORM_HEADERS :=
SKYCOMBAT_HOST_LIBS := -framework Cocoa -framework IOKit -framework OpenGL \
	-framework CoreVideo -framework CoreFoundation -lm
else ifneq ($(filter MINGW% MSYS% CYGWIN%,$(ZCL_HOST_OS)),)
SKYCOMBAT_PLATFORM_HEADERS :=
SKYCOMBAT_HOST_LIBS := -lgdi32 -lopengl32 -lwinmm -lshell32 -lm
else
SKYCOMBAT_PLATFORM_HEADERS := X11/Xlib.h X11/extensions/Xrandr.h \
	X11/extensions/XInput2.h X11/Xcursor/Xcursor.h GL/glx.h
SKYCOMBAT_HOST_LIBS := -lX11 -lXrandr -lXi -lXcursor -lGL -lm -lpthread -ldl
endif

# Every SUPPORT_* knob raylib's config.h guards with #ifndef, set from here so
# the vendored config.h is never edited. Off: all audio, every model file
# format (cgltf/tinyobj/vox/m3d), every image file format (stb_image/qoi/pep),
# font file loading, image export, screen capture, mesh generation and the
# deflate codec. On: the five renderer modules, the default font, the camera
# and gesture systems and GenImage* -- exactly what the game calls.
Z23RAYLIB_CPPFLAGS := -DPLATFORM_DESKTOP_RGFW -DGRAPHICS_API_OPENGL_33 \
	-DSUPPORT_MODULE_RSHAPES=1 -DSUPPORT_MODULE_RTEXT=1 \
	-DSUPPORT_MODULE_RTEXTURES=1 -DSUPPORT_MODULE_RMODELS=1 \
	-DSUPPORT_MODULE_RAUDIO=0 \
	-DSUPPORT_FILEFORMAT_PNG=0 -DSUPPORT_FILEFORMAT_BMP=0 \
	-DSUPPORT_FILEFORMAT_TGA=0 -DSUPPORT_FILEFORMAT_JPG=0 \
	-DSUPPORT_FILEFORMAT_GIF=0 -DSUPPORT_FILEFORMAT_QOI=0 \
	-DSUPPORT_FILEFORMAT_PEP=0 -DSUPPORT_FILEFORMAT_PSD=0 \
	-DSUPPORT_FILEFORMAT_DDS=0 -DSUPPORT_FILEFORMAT_HDR=0 \
	-DSUPPORT_FILEFORMAT_PIC=0 -DSUPPORT_FILEFORMAT_PNM=0 \
	-DSUPPORT_FILEFORMAT_KTX=0 -DSUPPORT_FILEFORMAT_ASTC=0 \
	-DSUPPORT_FILEFORMAT_PKM=0 -DSUPPORT_FILEFORMAT_PVR=0 \
	-DSUPPORT_FILEFORMAT_TTF=0 -DSUPPORT_FILEFORMAT_FNT=0 \
	-DSUPPORT_FILEFORMAT_BDF=0 \
	-DSUPPORT_FILEFORMAT_OBJ=0 -DSUPPORT_FILEFORMAT_MTL=0 \
	-DSUPPORT_FILEFORMAT_IQM=0 -DSUPPORT_FILEFORMAT_GLTF=0 \
	-DSUPPORT_FILEFORMAT_VOX=0 -DSUPPORT_FILEFORMAT_M3D=0 \
	-DSUPPORT_IMAGE_EXPORT=0 -DSUPPORT_SCREEN_CAPTURE=0 \
	-DSUPPORT_MESH_GENERATION=0 -DSUPPORT_COMPRESSION_API=0 \
	-I$(Z23RAYLIB_DIR)/src
Z23RAYLIB_CFLAGS := -std=$(ZCL_C_STD) -O2 -Wall -Wextra $(REPRO_CFLAGS) $(Z23RAYLIB_CPPFLAGS)

# RAYMATH_USE_SIMD_INTRINSICS is the one raymath.h knob the game's own -Wundef
# would trip over, so it is spelled out rather than left undefined.
SKYCOMBAT_CFLAGS := -std=$(ZCL_C_STD) -O2 -Wall -Wextra -Werror -pedantic $(REPRO_CFLAGS) \
	$(filter-out -Wdouble-promotion,$(ZCL_WARN_EXTRA_GATES)) \
	$(ZCL_WARN_STRINGOP_OVERFLOW) -D_POSIX_C_SOURCE=200809L \
	$(ZCL_PLATFORM_CPPFLAGS) \
	-DRAYMATH_USE_SIMD_INTRINSICS=0 $(Z23RAYLIB_CPPFLAGS) \
	-I$(SKYCOMBAT_DIR)/include -I$(SKYCOMBAT_DIR)/specifications \
	-I$(SKYCOMBAT_DIR)/modules/compile_time_gdb_proof/include \
	-Iplatform/modules/base/include -Iplatform/modules/platform/include \
	-Iplatform/modules/json/include -Iplatform/modules/util/include \
	-Icontexts/commons/packages/zbase64/include \
	-Icontexts/commons/packages/zsha256/include

Z23RAYLIB_SRCS := $(Z23RAYLIB_DIR)/src/rcore.c $(Z23RAYLIB_DIR)/src/rshapes.c \
	$(Z23RAYLIB_DIR)/src/rtext.c $(Z23RAYLIB_DIR)/src/rtextures.c \
	$(Z23RAYLIB_DIR)/src/rmodels.c
Z23RAYLIB_OBJS := $(patsubst $(Z23RAYLIB_DIR)/src/%.c,$(Z23RAYLIB_OBJ_DIR)/%.o,$(Z23RAYLIB_SRCS))

# Explicit directory list, never a recursive wildcard: a file that appears
# under apps/skycombat without being named here does not silently join a build.
SKYCOMBAT_SRCS := \
	$(wildcard $(SKYCOMBAT_DIR)/src/*.c) \
	$(wildcard $(SKYCOMBAT_DIR)/part/expr_*.c) \
	$(wildcard $(SKYCOMBAT_DIR)/src/controllers/*.c) \
	$(wildcard $(SKYCOMBAT_DIR)/src/core/*.c) \
	$(wildcard $(SKYCOMBAT_DIR)/src/models/*.c) \
	$(wildcard $(SKYCOMBAT_DIR)/src/systems/*.c) \
	$(wildcard $(SKYCOMBAT_DIR)/src/utils/*.c) \
	$(wildcard $(SKYCOMBAT_DIR)/src/views/*.c) \
	$(wildcard $(SKYCOMBAT_DIR)/modules/compile_time_gdb_proof/*.c) \
	$(wildcard $(SKYCOMBAT_DIR)/modules/compile_time_gdb_proof/src/*.c)
SKYCOMBAT_OBJS := $(patsubst $(SKYCOMBAT_DIR)/%.c,$(SKYCOMBAT_OBJ_DIR)/%.o,$(SKYCOMBAT_SRCS))

# The one playable program. The imported tree carries several entry points --
# standalone demos and headless spec runners, each with its own main() -- so
# the binary names its own, and the link set is the exact closure of that
# main's undefined symbols over the other objects. game-check still compiles
# every file; only the link is selective.
SKYCOMBAT_GAME_MAIN := $(SKYCOMBAT_DIR)/src/sky_combat_multiplayer_ultimate.c
SKYCOMBAT_GAME_SRCS := $(SKYCOMBAT_GAME_MAIN) \
	$(SKYCOMBAT_DIR)/src/agent_session.c \
	$(SKYCOMBAT_DIR)/src/agent_resident.c \
	$(SKYCOMBAT_DIR)/src/game_runtime.c \
	$(wildcard $(SKYCOMBAT_DIR)/part/expr_*.c) \
	$(SKYCOMBAT_DIR)/src/controllers/input_controller_fast.c \
	$(SKYCOMBAT_DIR)/src/controllers/input_mvc_fast.c \
	$(SKYCOMBAT_DIR)/src/models/aircraft.c \
	$(SKYCOMBAT_DIR)/src/models/aircraft_manager.c \
	$(SKYCOMBAT_DIR)/src/models/aircraft_responsive.c \
	$(SKYCOMBAT_DIR)/src/models/cyberpunk_world.c \
	$(SKYCOMBAT_DIR)/src/models/input_model_fast.c \
	$(SKYCOMBAT_DIR)/src/models/match_rules.c \
	$(SKYCOMBAT_DIR)/src/models/powerups.c \
	$(SKYCOMBAT_DIR)/src/models/weapons.c \
	$(SKYCOMBAT_DIR)/src/views/camera_controller.c \
	$(SKYCOMBAT_DIR)/src/views/combat_effects.c
SKYCOMBAT_GAME_OBJS := $(patsubst $(SKYCOMBAT_DIR)/%.c,$(SKYCOMBAT_OBJ_DIR)/%.o,$(SKYCOMBAT_GAME_SRCS))

# Gameplay and its mixed entrypoint use separately rounded operations on every
# host. Dedicated views, cosmetic world generation and raylib retain their
# existing policy. Keep raymath local so an external renderer implementation
# cannot supply simulation arithmetic compiled with a different policy.
SKYCOMBAT_SIM_SRCS := $(filter-out $(SKYCOMBAT_DIR)/src/views/% \
	$(SKYCOMBAT_DIR)/src/models/cyberpunk_world.c,$(SKYCOMBAT_GAME_SRCS))
SKYCOMBAT_SIM_OBJS := $(patsubst $(SKYCOMBAT_DIR)/%.c,$(SKYCOMBAT_OBJ_DIR)/%.o,$(SKYCOMBAT_SIM_SRCS))
SKYCOMBAT_SIM_FP_FLAGS := -ffp-contract=off -DRAYMATH_STATIC_INLINE

# These objects require raylib's portable headers, not a window-system SDK.
# The real game still probes its platform before compiling raylib and views.
$(SKYCOMBAT_SIM_OBJS): $(SKYCOMBAT_OBJ_DIR)/%.o: $(SKYCOMBAT_DIR)/%.c $(SKYCOMBAT_MAKE_INPUTS)
	@mkdir -p $(dir $@)
	$(CC) $(SKYCOMBAT_CFLAGS) $(SKYCOMBAT_SIM_FP_FLAGS) -MD -MP -MF $(@:.o=.d) -c $< -o $@

# The probe is a FILE target, not just a phony one. Only raylib's SDK-using
# objects take it as an order-only prerequisite; game/support objects consume
# portable declarations and remain available to headless tests. Under `make -j`
# the stamp prevents SDK-using objects from starting before a named refusal.
# FORCE keeps the probe honest on every run without dirtying a single object.
SKYCOMBAT_PLATFORM_STAMP := $(SKYCOMBAT_OBJ_DIR)/.platform-ok

$(SKYCOMBAT_PLATFORM_STAMP): FORCE
	@mkdir -p $(dir $@)
	@missing=""; \
	for h in $(SKYCOMBAT_PLATFORM_HEADERS); do \
	  [ -e "/usr/include/$$h" ] || [ -e "/usr/local/include/$$h" ] || missing="$$missing $$h"; \
	done; \
	if [ -n "$$missing" ]; then \
	  echo "game_platform_headers_missing:$$missing"; \
	  exit 2; \
	fi
	@touch $@

$(Z23RAYLIB_OBJ_DIR)/%.o: $(Z23RAYLIB_DIR)/src/%.c $(SKYCOMBAT_MAKE_INPUTS) | $(SKYCOMBAT_PLATFORM_STAMP)
	@mkdir -p $(dir $@)
	$(CC) $(Z23RAYLIB_CFLAGS) -MD -MP -MF $(@:.o=.d) -c $< -o $@

# These application TUs consume portable raylib declarations, not SDK headers.
# Only raylib's platform TUs (above) need the native SDK admission probe.
$(SKYCOMBAT_OBJ_DIR)/%.o: $(SKYCOMBAT_DIR)/%.c $(SKYCOMBAT_MAKE_INPUTS)
	@mkdir -p $(dir $@)
	$(CC) $(SKYCOMBAT_CFLAGS) -MD -MP -MF $(@:.o=.d) -c $< -o $@

$(Z23RAYLIB_LIB): $(Z23RAYLIB_OBJS) $(SKYCOMBAT_MAKE_INPUTS)
	@mkdir -p $(dir $@)
	@rm -f $@
	$(AR) rcs $@ $(Z23RAYLIB_OBJS)

.PHONY: game-platform-probe game game-check
# One typed refusal, never a wall of "No such file" from the preprocessor.
game-platform-probe: $(SKYCOMBAT_PLATFORM_STAMP)

$(SKYCOMBAT_OBJ_DIR)/src/sky_combat_multiplayer_ultimate.o: $(SKYCOMBAT_DIR)/part/expr_use.h $(SKYCOMBAT_DIR)/part/expr_format.h
$(patsubst $(SKYCOMBAT_DIR)/%.c,$(SKYCOMBAT_OBJ_DIR)/%.o,$(wildcard $(SKYCOMBAT_DIR)/part/*.c)): $(SKYCOMBAT_DIR)/part/expr_format.h

# Standalone canonical reader/hash support: no core/engine or node link.
SKYCOMBAT_SUPPORT_SRCS := platform/modules/platform/src/positioned_file.c \
	platform/modules/base/src/safe_alloc.c platform/modules/base/src/cleanse.c \
	platform/modules/json/src/json.c platform/modules/util/src/png_writer.c \
	contexts/commons/packages/zbase64/src/zbase64.c \
	contexts/commons/packages/zsha256/src/zsha256.c
SKYCOMBAT_SUPPORT_OBJS := $(addprefix $(SKYCOMBAT_OBJ_DIR)/support/,$(SKYCOMBAT_SUPPORT_SRCS:.c=.o))
$(SKYCOMBAT_OBJ_DIR)/support/%.o: %.c $(SKYCOMBAT_MAKE_INPUTS)
	@mkdir -p $(@D)
	$(CC) $(SKYCOMBAT_CFLAGS) -MD -MP -MF $(@:.o=.d) -c $< -o $@

# Compilation inputs, not a standalone build recipe or a host SDK. Header
# directories are a conservative export set; translation units retain their
# existing ordered lists above. Included vendor .c files are inputs, not extra
# link objects. The default game has no external image/model/font asset files.
SKYCOMBAT_HEADER_DIRS := $(SKYCOMBAT_DIR)/include/sky_combat \
	$(addprefix $(SKYCOMBAT_DIR)/include/sky_combat/,controllers models utils views)
SKYCOMBAT_GAME_HEADERS := $(wildcard $(addsuffix /*.h,$(SKYCOMBAT_HEADER_DIRS))) \
	$(SKYCOMBAT_DIR)/part/expr_format.h $(SKYCOMBAT_DIR)/part/expr_use.h
SKYCOMBAT_SUPPORT_HEADERS := platform/modules/base/include/base/safe_alloc.h \
	platform/modules/base/include/base/cleanse.h platform/modules/base/include/base/hex.h \
	platform/modules/base/include/base/serialize_le.h platform/modules/base/include/base/result.h \
	platform/modules/base/include/base/format_attribute.h platform/modules/json/include/json/json.h \
	platform/modules/platform/include/platform/positioned_file.h \
	platform/modules/platform/include/platform/windows_path.h \
	platform/modules/platform/src/windows_path_internal.h \
	platform/modules/platform/include/platform/resident_launch.h \
	platform/modules/platform/include/platform/os_sandbox.h \
	platform/modules/util/include/util/png_writer.h platform/modules/util/include/util/safe_alloc.h \
	platform/modules/util/include/util/result.h \
	contexts/commons/packages/zbase64/include/zbase64/zbase64.h \
	contexts/commons/packages/zsha256/include/zsha256/zsha256.h
Z23RAYLIB_INCLUDE_INPUTS := $(addprefix $(Z23RAYLIB_DIR)/src/,config.h raylib.h \
	raymath.h rcamera.h rgestures.h rlgl.h platforms/rcore_desktop_rgfw.c \
	external/RGFW/RGFW.h external/RGFW/deps/minigamepad.h external/glad.h \
	external/rprand.h external/stb_image_resize2.h external/stb_perlin.h \
	external/fix_win32_compatibility.h external/win32_clipboard.h)
SKYCOMBAT_GAME_CLOSURE = $(sort $(patsubst ./%,%,$(SKYCOMBAT_GAME_SRCS) $(SKYCOMBAT_SUPPORT_SRCS) \
	$(Z23RAYLIB_SRCS) $(SKYCOMBAT_GAME_HEADERS) $(SKYCOMBAT_SUPPORT_HEADERS) \
	$(Z23RAYLIB_INCLUDE_INPUTS) $(SKYCOMBAT_MAKE_INPUTS)))
.PHONY: print-game-closure
print-game-closure:
	@set -eu; for input in $(SKYCOMBAT_GAME_CLOSURE); do \
	  test -f "$$input" || { printf 'game input missing or not regular: %s\n' "$$input" >&2; exit 2; }; \
	done; printf '%s\n' $(SKYCOMBAT_GAME_CLOSURE)

# Rebuild on real transitive include changes, and retain the compiler's input
# evidence for closure qualification. Pure queries never read warm depfiles.
ifeq ($(strip $(ZCL_INVENTORY_LINT_ONLY) $(SKYCOMBAT_QUERY_ONLY)),)
-include $(SKYCOMBAT_GAME_OBJS:.o=.d) $(SKYCOMBAT_SUPPORT_OBJS:.o=.d) $(Z23RAYLIB_OBJS:.o=.d)
endif

game: $(SKYCOMBAT_IMAGE)
	@echo "game: built $(SKYCOMBAT_IMAGE) (not run: it opens a window)"

$(SKYCOMBAT_IMAGE): $(SKYCOMBAT_SUPPORT_OBJS) $(SKYCOMBAT_GAME_OBJS) $(Z23RAYLIB_LIB) $(SKYCOMBAT_MAKE_INPUTS)
	@mkdir -p $(dir $@)
	$(CC) $(SKYCOMBAT_CFLAGS) $(SKYCOMBAT_SUPPORT_OBJS) $(SKYCOMBAT_GAME_OBJS) $(Z23RAYLIB_LIB) \
		$(SKYCOMBAT_HOST_LIBS) -o $@
