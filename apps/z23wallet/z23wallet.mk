# Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
# z23-wallet: the lightweight Z23 wallet window. OPT-IN: no target here is
# reachable from all, z23, build-only, test or any lint gate.
#   make z23-wallet          links build/bin/z23-wallet (.exe on Windows hosts)
#   make z23-wallet-check    compiles every wallet and gui unit, links nothing
#   make z23-wallet-windows  mingw cross-build (ZCL_TARGET=windows-x86_64)
# The program links neither core/ nor engine/: platform modules only.
Z23WALLET_DIR := apps/z23wallet
Z23WALLET_APP_SRCS := $(sort $(wildcard $(Z23WALLET_DIR)/src/*.c))
Z23WALLET_SRCS := $(Z23WALLET_APP_SRCS) $(GUI_SRCS) $(GUI_DEP_SRCS)
# main.c owns main(); the test binary supplies its own.
Z23WALLET_TEST_SRCS := $(filter-out $(Z23WALLET_DIR)/src/main.c,$(Z23WALLET_APP_SRCS))
Z23WALLET_TEST_INCLUDES = -I$(Z23WALLET_DIR)/src
Z23WALLET_OBJ_DIR := $(BUILD_DIR)/z23wallet$(if $(ZCL_HOST_WINDOWS),-win,)
Z23WALLET_OBJS := $(patsubst %.c,$(Z23WALLET_OBJ_DIR)/%.o,$(Z23WALLET_SRCS))
Z23WALLET_BIN := $(BIN_DIR)/z23-wallet$(ZCL_HOST_EXEEXT)
Z23WALLET_INC := -I$(Z23WALLET_DIR)/src -Iplatform/modules/gui/include -Iplatform/modules/gui/src \
	-Iplatform/modules/base/include -Iplatform/modules/json/include \
	-Iplatform/modules/util/include -Iplatform/modules/sha3/include \
	-Iplatform/modules/platform/include
Z23WALLET_CFLAGS = -std=$(ZCL_C_STD) -O2 -Wall -Wextra -Werror -pedantic -Wundef \
	-Wstrict-prototypes -Wdouble-promotion -Wshift-overflow -Walloca -Wvla -ffp-contract=off \
	-ffile-prefix-map=$(CURDIR)=/zclassic23 -gno-record-gcc-switches $(Z23WALLET_INC)
ifneq ($(ZCL_HOST_WINDOWS),)
Z23WALLET_CFLAGS += -D_WIN32_WINNT=0x0A00 -DWIN32_LEAN_AND_MEAN -DUNICODE -D_UNICODE -D__USE_MINGW_ANSI_STDIO=1
Z23WALLET_LIBS = -s -mwindows -static -luser32 -lgdi32 -lshell32 -lws2_32 -lpthread
else
Z23WALLET_CFLAGS += -D_POSIX_C_SOURCE=200809L
Z23WALLET_LIBS = -lm -lpthread -ldl
endif

$(Z23WALLET_OBJ_DIR)/%.o: %.c $(wildcard $(Z23WALLET_DIR)/src/*.h $(GUI_DIR)/include/gui/*.h $(GUI_DIR)/src/*.h) $(Z23WALLET_DIR)/z23wallet.mk
	@mkdir -p $(dir $@)
	$(CC) $(Z23WALLET_CFLAGS) -c $< -o $@

$(Z23WALLET_BIN): $(Z23WALLET_OBJS)
	@mkdir -p $(dir $@)
	$(CC) $(Z23WALLET_OBJS) $(Z23WALLET_LIBS) -o $@

.PHONY: z23-wallet z23-wallet-check z23-wallet-windows
z23-wallet: $(Z23WALLET_BIN)

# A floor, not decoration: an empty object list is how a check would pass
# while compiling nothing.
z23-wallet-check: $(Z23WALLET_OBJS)
	@test $(words $(Z23WALLET_APP_SRCS)) -ge 12 || { echo "z23-wallet-check: only $(words $(Z23WALLET_APP_SRCS)) wallet sources found" >&2; exit 2; }
	@echo "z23-wallet-check: compiled $(words $(Z23WALLET_SRCS)) translation units, no link"

z23-wallet-windows:
	@$(MAKE) ZCL_TARGET=windows-x86_64 z23-wallet
