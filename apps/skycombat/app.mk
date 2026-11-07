# Sky Combat make fragment for a seeded copy (app seed / app build).
#
# `z23 app seed skycombat` publishes this file as the copy's Makefile, next
# to the game and the checkout files zcode-seed.def maps (the trimmed raylib
# and the standalone support sources), so a copy builds with nothing outside
# itself. It implements the app.build contract
# (tools/command/app_build_make.h):
#   print-app-closure  every input the build reads, one copy path per line;
#   app                $(APP_OUT)/app, compiled out of tree with -MMD so each
#                      object leaves a depfile under $(APP_OUT).
# The flags are the repository Makefile's game section (`make game`) as GCC
# on Linux expands them: SKYCOMBAT_CFLAGS with REPRO_CFLAGS, the same
# simulation floating-point policy, raylib's flags (warnings reported, never
# fatal, vendor bytes untouched) and the X11/GL link. No $(shell): the
# closure query runs with nothing writable.

APP_OUT ?= build/app-out

CC ?= cc
REPRO_CFLAGS := -ffile-prefix-map=$(CURDIR)=/zclassic23 \
	-ffile-prefix-map=$(APP_OUT)=/out -gno-record-gcc-switches

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
	-Ivendor/raylib/src
Z23RAYLIB_CFLAGS := -std=c23 -O2 -Wall -Wextra $(REPRO_CFLAGS) \
	$(Z23RAYLIB_CPPFLAGS)

SKYCOMBAT_CFLAGS := -std=c23 -O2 -Wall -Wextra -Werror -pedantic \
	$(REPRO_CFLAGS) -Wundef -Wstrict-prototypes -Wduplicated-cond \
	-Wduplicated-branches -Wshift-overflow=2 -Wattribute-alias=2 -Walloca \
	-Wvla -Wtrampolines -Wflex-array-member-not-at-end \
	-Wno-stringop-overflow -D_POSIX_C_SOURCE=200809L \
	-DRAYMATH_USE_SIMD_INTRINSICS=0 $(Z23RAYLIB_CPPFLAGS) \
	-Iinclude -Ispecifications -Imodules/compile_time_gdb_proof/include \
	-Iplatform/modules/base/include -Iplatform/modules/platform/include \
	-Iplatform/modules/json/include -Iplatform/modules/util/include \
	-Icontexts/commons/packages/zbase64/include \
	-Icontexts/commons/packages/zsha256/include
SKYCOMBAT_SIM_FP_FLAGS := -ffp-contract=off -DRAYMATH_STATIC_INLINE
SKYCOMBAT_HOST_LIBS := -lX11 -lXrandr -lXi -lXcursor -lGL -lm -lpthread -ldl

Z23RAYLIB_SRCS := vendor/raylib/src/rcore.c vendor/raylib/src/rshapes.c \
	vendor/raylib/src/rtext.c vendor/raylib/src/rtextures.c \
	vendor/raylib/src/rmodels.c

SKYCOMBAT_GAME_SRCS := src/sky_combat_multiplayer_ultimate.c \
	src/agent_session.c src/agent_resident.c src/game_runtime.c \
	$(wildcard part/expr_*.c) \
	src/controllers/input_controller_fast.c \
	src/controllers/input_mvc_fast.c \
	src/models/aircraft.c src/models/aircraft_manager.c \
	src/models/aircraft_responsive.c src/models/cyberpunk_world.c \
	src/models/input_model_fast.c src/models/match_rules.c \
	src/models/powerups.c src/models/weapons.c \
	src/views/camera_controller.c src/views/combat_effects.c

# Gameplay uses separately rounded operations; views, cosmetic world
# generation and raylib keep their own policy (as in the repo Makefile).
SKYCOMBAT_SIM_SRCS := $(filter-out src/views/% src/models/cyberpunk_world.c,\
	$(SKYCOMBAT_GAME_SRCS))
SKYCOMBAT_PLAIN_SRCS := $(filter-out $(SKYCOMBAT_SIM_SRCS),\
	$(SKYCOMBAT_GAME_SRCS))

SKYCOMBAT_SUPPORT_SRCS := platform/modules/platform/src/positioned_file.c \
	platform/modules/base/src/safe_alloc.c platform/modules/base/src/cleanse.c \
	platform/modules/json/src/json.c platform/modules/util/src/png_writer.c \
	contexts/commons/packages/zbase64/src/zbase64.c \
	contexts/commons/packages/zsha256/src/zsha256.c

SKYCOMBAT_GAME_HEADERS := $(wildcard include/sky_combat/*.h \
	include/sky_combat/controllers/*.h include/sky_combat/models/*.h \
	include/sky_combat/utils/*.h include/sky_combat/views/*.h) \
	part/expr_format.h part/expr_use.h
SKYCOMBAT_SUPPORT_HEADERS := platform/modules/base/include/base/safe_alloc.h \
	platform/modules/base/include/base/cleanse.h \
	platform/modules/base/include/base/hex.h \
	platform/modules/base/include/base/serialize_le.h \
	platform/modules/base/include/base/result.h \
	platform/modules/base/include/base/format_attribute.h \
	platform/modules/json/include/json/json.h \
	platform/modules/platform/include/platform/positioned_file.h \
	platform/modules/platform/include/platform/windows_path.h \
	platform/modules/platform/src/windows_path_internal.h \
	platform/modules/platform/include/platform/resident_launch.h \
	platform/modules/platform/include/platform/os_sandbox.h \
	platform/modules/util/include/util/png_writer.h \
	platform/modules/util/include/util/safe_alloc.h \
	platform/modules/util/include/util/result.h \
	contexts/commons/packages/zbase64/include/zbase64/zbase64.h \
	contexts/commons/packages/zsha256/include/zsha256/zsha256.h
Z23RAYLIB_INCLUDE_INPUTS := $(addprefix vendor/raylib/src/,config.h raylib.h \
	raymath.h rcamera.h rgestures.h rlgl.h platforms/rcore_desktop_rgfw.c \
	external/RGFW/RGFW.h external/RGFW/deps/minigamepad.h external/glad.h \
	external/rprand.h external/stb_image_resize2.h external/stb_perlin.h \
	external/fix_win32_compatibility.h external/win32_clipboard.h)

APP_CLOSURE := $(sort Makefile $(SKYCOMBAT_GAME_SRCS) \
	$(SKYCOMBAT_SUPPORT_SRCS) $(Z23RAYLIB_SRCS) $(SKYCOMBAT_GAME_HEADERS) \
	$(SKYCOMBAT_SUPPORT_HEADERS) $(Z23RAYLIB_INCLUDE_INPUTS))

SIM_OBJS := $(patsubst %.c,$(APP_OUT)/%.o,$(SKYCOMBAT_SIM_SRCS))
PLAIN_OBJS := $(patsubst %.c,$(APP_OUT)/%.o,$(SKYCOMBAT_PLAIN_SRCS))
SUPPORT_OBJS := $(patsubst %.c,$(APP_OUT)/%.o,$(SKYCOMBAT_SUPPORT_SRCS))
RAYLIB_OBJS := $(patsubst %.c,$(APP_OUT)/%.o,$(Z23RAYLIB_SRCS))

.PHONY: app print-app-closure

print-app-closure:
	@printf '%s\n' $(APP_CLOSURE)

app: $(APP_OUT)/app

$(APP_OUT)/app: $(SUPPORT_OBJS) $(SIM_OBJS) $(PLAIN_OBJS) $(RAYLIB_OBJS)
	$(CC) $(SKYCOMBAT_CFLAGS) $(SUPPORT_OBJS) $(SIM_OBJS) $(PLAIN_OBJS) \
		$(RAYLIB_OBJS) $(SKYCOMBAT_HOST_LIBS) -o $@

$(SIM_OBJS): $(APP_OUT)/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(SKYCOMBAT_CFLAGS) $(SKYCOMBAT_SIM_FP_FLAGS) -MMD -MP -c $< -o $@

$(PLAIN_OBJS) $(SUPPORT_OBJS): $(APP_OUT)/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(SKYCOMBAT_CFLAGS) -MMD -MP -c $< -o $@

$(RAYLIB_OBJS): $(APP_OUT)/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(Z23RAYLIB_CFLAGS) -MMD -MP -c $< -o $@
