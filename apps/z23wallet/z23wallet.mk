# Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
# z23-wallet: the lightweight Z23 wallet window. OPT-IN: no target here is
# reachable from all, z23, build-only, test or any lint gate.
#   make z23-wallet              links build/bin/z23-wallet (.exe on Windows hosts),
#                                release profile, debug info split to z23-wallet.debug
#   make z23-wallet Z23WALLET_PROFILE=dev   uniform -O2, no LTO, no split (quick rebuilds)
#   make z23-wallet-check        compiles every wallet and gui unit, links nothing
#   make z23-wallet-windows      mingw cross-build (ZCL_TARGET=windows-x86_64)
#   make check-z23-wallet-size   builds the wallet and fails past its size budget
# The program links neither core/ nor engine/: platform modules only.
Z23WALLET_DIR := apps/z23wallet
Z23WALLET_APP_SRCS := $(sort $(wildcard $(Z23WALLET_DIR)/src/*.c))
Z23WALLET_SRCS := $(Z23WALLET_APP_SRCS) $(GUI_SRCS) $(GUI_DEP_SRCS)
# main.c owns main(); the test binary supplies its own.
Z23WALLET_TEST_SRCS := $(filter-out $(Z23WALLET_DIR)/src/main.c,$(Z23WALLET_APP_SRCS))
Z23WALLET_TEST_INCLUDES = -I$(Z23WALLET_DIR)/src
Z23WALLET_PROFILE ?= release
Z23WALLET_OBJ_DIR := $(BUILD_DIR)/z23wallet$(if $(ZCL_HOST_WINDOWS),-win,)-$(Z23WALLET_PROFILE)
Z23WALLET_OBJS := $(patsubst %.c,$(Z23WALLET_OBJ_DIR)/%.o,$(Z23WALLET_SRCS))
Z23WALLET_BIN := $(BIN_DIR)/z23-wallet$(ZCL_HOST_EXEEXT)
Z23WALLET_DEBUG := $(BIN_DIR)/z23-wallet.debug
Z23WALLET_INC := -I$(Z23WALLET_DIR)/src -Iplatform/modules/gui/include -Iplatform/modules/gui/src \
	-Iplatform/modules/base/include -Iplatform/modules/json/include \
	-Iplatform/modules/util/include -Iplatform/modules/sha3/include \
	-Iplatform/modules/platform/include

# ---- release profile --------------------------------------------------------
# Measured on the integrated wallet (every page), Windows 10, MSYS2 UCRT64 gcc
# 16.2 / binutils 2.47, headless scripted pass through every page against the
# fixture node; each lever alone on top of the old `-O2 -s` link (544,256 bytes).
# Frame = median paint of a full page, interleaved runs. All 46 goldens stayed
# bit-identical under every lever (see README "Release profile").
#   lever                                         exe bytes   delta     frame
#   old -O2 -s (baseline)                           544,256        0   1.31 ms
#   -Os everywhere                                  458,240  -86,016   1.52 ms (slower)
#   -O3 everywhere                                  620,544  +76,288   0.79 ms
#   -Os, -O3 for draw.c draw_text.c ui_paint.c      (in the final row below)
#   UCRT printf/strtod (no __USE_MINGW_ANSI_STDIO)  479,232  -65,024   same
#   -flto                                           523,776  -20,480   same
#   -ffunction-sections + --gc-sections             538,624   -5,632   same
#   -fno-ident                                      541,696   -2,560   same
#   -fstack-protector-strong                        555,008  +10,752   same
#   -D_FORTIFY_SOURCE=3                             535,552   -8,704   same
#   manifest + version resource                      +2,048
#   split debug info (.gnu_debuglink)                  +531
#   final release profile (this block)              404,499 -139,757   0.83 ms
# Later integration preview (more pages): 586,752 -> 434,707. Milestone 1 alone:
# 366,592 -> 264,211.
# Rejected, with the reason: -fdata-sections (mingw moves .bss into .data: the
# exe grows to 1.68 MB); -fno-asynchronous-unwind-tables (+2 KB on Windows x64,
# where SEH unwind data is mandatory; on Linux it would drop 28,672 bytes of
# .eh_frame, kept for glibc backtraces: a follow-up); lld --icf=all (+1 KB);
# -fwhole-program (no change over LTO); -fmerge-all-constants (non-conforming,
# 1 KB); executable packers such as UPX (they defeat page sharing, trip
# antivirus heuristics and hide the code from audit).
Z23WALLET_HOT_SRCS := $(GUI_DIR)/src/draw.c $(GUI_DIR)/src/draw_text.c $(GUI_DIR)/src/ui_paint.c
Z23WALLET_HOT_OBJS := $(patsubst %.c,$(Z23WALLET_OBJ_DIR)/%.o,$(Z23WALLET_HOT_SRCS))
ifeq ($(Z23WALLET_PROFILE),release)
Z23WALLET_OPT := -Os
$(Z23WALLET_HOT_OBJS): Z23WALLET_OPT := -O3
Z23WALLET_PROFILE_CFLAGS := -g -flto=auto -ffunction-sections -fno-ident -fstack-protector-strong \
	-U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=3
Z23WALLET_PROFILE_LDFLAGS := -Os -g -flto=auto -fstack-protector-strong -Wl,--gc-sections
ifneq ($(ZCL_HOST_WINDOWS),)
# The GNU ld defaults since 2.36, stated so a toolchain change cannot drop them:
# ASLR with high entropy (relocations kept) and DEP. Control Flow Guard needs
# -mguard=cf, which gcc does not offer for mingw-w64; -fcf-protection only adds
# endbr64 bytes Windows never checks, so it stays off here.
Z23WALLET_PROFILE_LDFLAGS += -Wl,--dynamicbase -Wl,--high-entropy-va -Wl,--nxcompat
else
Z23WALLET_PROFILE_CFLAGS += -fPIE -fstack-clash-protection -fcf-protection=full
Z23WALLET_PROFILE_LDFLAGS += -pie -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack
endif
else ifeq ($(Z23WALLET_PROFILE),dev)
Z23WALLET_OPT := -O2
Z23WALLET_PROFILE_CFLAGS :=
Z23WALLET_PROFILE_LDFLAGS := -s
else
$(error Z23WALLET_PROFILE must be release or dev, not '$(Z23WALLET_PROFILE)')
endif

Z23WALLET_CFLAGS = -std=$(ZCL_C_STD) $(Z23WALLET_OPT) -Wall -Wextra -Werror -pedantic -Wundef \
	-Wstrict-prototypes -Wdouble-promotion -Wshift-overflow -Walloca -Wvla -ffp-contract=off \
	-ffile-prefix-map=$(CURDIR)=/zclassic23 -gno-record-gcc-switches $(Z23WALLET_PROFILE_CFLAGS) $(Z23WALLET_INC)
ifneq ($(ZCL_HOST_WINDOWS),)
# On a UCRT toolchain the system CRT already has C99 printf/scanf/strtod, so the
# static mingw copies (64 KB) are not linked; msvcrt toolchains still need them.
Z23WALLET_UCRT = $(shell $(CC) -dM -E -include stdio.h -x c /dev/null 2>/dev/null | grep -c '^.define _UCRT$$\|^.define _UCRT ')
Z23WALLET_CFLAGS += -D_WIN32_WINNT=0x0A00 -DWIN32_LEAN_AND_MEAN -DUNICODE -D_UNICODE \
	$(if $(filter-out 0,$(Z23WALLET_UCRT)),,-D__USE_MINGW_ANSI_STDIO=1)
Z23WALLET_LIBS = -mwindows -static -luser32 -lgdi32 -lshell32 -lws2_32 -lpthread
Z23WALLET_WINDRES := $(if $(ZCL_CROSS_TRIPLE),$(ZCL_CROSS_TRIPLE)-windres,windres)
Z23WALLET_RES := $(Z23WALLET_OBJ_DIR)/z23wallet_res.o
else
Z23WALLET_CFLAGS += -D_POSIX_C_SOURCE=200809L
Z23WALLET_LIBS = -lm -lpthread -ldl
Z23WALLET_RES :=
endif

$(Z23WALLET_OBJ_DIR)/%.o: %.c $(wildcard $(Z23WALLET_DIR)/src/*.h $(GUI_DIR)/include/gui/*.h $(GUI_DIR)/src/*.h) $(Z23WALLET_DIR)/z23wallet.mk
	@mkdir -p $(dir $@)
	$(CC) $(Z23WALLET_CFLAGS) -c $< -o $@

# Manifest (asInvoker, per-monitor DPI v2, Windows 10 compatibility) and version.
$(Z23WALLET_OBJ_DIR)/z23wallet_res.o: $(Z23WALLET_DIR)/z23wallet.rc $(Z23WALLET_DIR)/z23wallet.manifest
	@mkdir -p $(dir $@)
	$(Z23WALLET_WINDRES) -O coff -I$(Z23WALLET_DIR) -i $< -o $@

# Both profiles link the same path. A build whose profile did not link it last
# removes it first (decided when make reads this file, because timestamps can
# tie), so a profile switch always relinks; the link records its profile.
Z23WALLET_PROFILE_STAMP := $(BUILD_DIR)/z23wallet-linked.$(Z23WALLET_PROFILE)
ifneq ($(filter z23-wallet check-z23-wallet-size $(Z23WALLET_BIN),$(MAKECMDGOALS)),)
ifeq ($(wildcard $(Z23WALLET_PROFILE_STAMP)),)
$(shell rm -f $(Z23WALLET_BIN) $(BUILD_DIR)/z23wallet-linked.*)
endif
endif

# The release link keeps its debug information beside the binary
# (z23-wallet.debug, found by debuggers through .gnu_debuglink) and ships the
# stripped image: crashes stay diagnosable, the release carries no symbols.
$(Z23WALLET_BIN): $(Z23WALLET_OBJS) $(Z23WALLET_RES)
	@mkdir -p $(dir $@)
ifeq ($(Z23WALLET_PROFILE),release)
	$(CC) $(Z23WALLET_PROFILE_LDFLAGS) $(Z23WALLET_OBJS) $(Z23WALLET_RES) $(Z23WALLET_LIBS) -o $@.full
	$(ZCL_OBJCOPY) --only-keep-debug $@.full $(Z23WALLET_DEBUG)
	$(ZCL_OBJCOPY) --strip-all --add-gnu-debuglink=$(Z23WALLET_DEBUG) $@.full $@
	@rm -f $@.full
else
	$(CC) $(Z23WALLET_PROFILE_LDFLAGS) $(Z23WALLET_OBJS) $(Z23WALLET_RES) $(Z23WALLET_LIBS) -o $@
endif
	@touch $(Z23WALLET_PROFILE_STAMP)

.PHONY: z23-wallet z23-wallet-check z23-wallet-windows check-z23-wallet-size
z23-wallet: $(Z23WALLET_BIN)

# A floor, not decoration: an empty object list is how a check would pass
# while compiling nothing.
z23-wallet-check: $(Z23WALLET_OBJS)
	@test $(words $(Z23WALLET_APP_SRCS)) -ge 12 || { echo "z23-wallet-check: only $(words $(Z23WALLET_APP_SRCS)) wallet sources found" >&2; exit 2; }
	@echo "z23-wallet-check: compiled $(words $(Z23WALLET_SRCS)) translation units, no link"

z23-wallet-windows:
	@$(MAKE) ZCL_TARGET=windows-x86_64 z23-wallet

# ---- size budget ------------------------------------------------------------
# apps/z23wallet/size/budget.tsv records, per reference toolchain, the release
# binary's byte budget and the section sizes it was set from. Over budget fails
# with the bytes over and the sections that grew; another toolchain is reported
# only. The checker is a host program (it reads PE and ELF itself).
Z23WALLET_SIZE_CHECK := $(BUILD_DIR)/z23wallet-tools/z23-wallet-size-check$(if $(ZCL_CROSS_TRIPLE),,$(ZCL_HOST_EXEEXT))
Z23WALLET_TOOLCHAIN = $(shell $(CC) -dumpmachine)$(if $(filter-out 0,$(Z23WALLET_UCRT)),-ucrt,)-$(if $(filter-out 0,$(shell $(CC) -dM -E -x c /dev/null 2>/dev/null | grep -c __clang__)),clang,gcc)$(firstword $(subst ., ,$(shell $(CC) -dumpversion)))

$(Z23WALLET_SIZE_CHECK): $(Z23WALLET_DIR)/size/size_check.c $(Z23WALLET_DIR)/z23wallet.mk
	@mkdir -p $(dir $@)
	$(or $(if $(ZCL_CROSS_TRIPLE),$(HOST_CC),$(CC)),cc) -std=$(ZCL_C_STD) -O2 -Wall -Wextra -Werror -pedantic \
	    -Wundef -Wstrict-prototypes -Wshift-overflow -Wvla -o $@ $<

check-z23-wallet-size: $(Z23WALLET_BIN) $(Z23WALLET_SIZE_CHECK)
	@test "$(Z23WALLET_PROFILE)" = release || { echo "check-z23-wallet-size: the budget is for the release profile, not Z23WALLET_PROFILE=$(Z23WALLET_PROFILE)" >&2; exit 2; }
	@TMPDIR=$(dir $(Z23WALLET_SIZE_CHECK)) $(Z23WALLET_SIZE_CHECK) --selftest >/dev/null 2>&1 || { TMPDIR=$(dir $(Z23WALLET_SIZE_CHECK)) $(Z23WALLET_SIZE_CHECK) --selftest; exit 1; }
	@$(Z23WALLET_SIZE_CHECK) $(Z23WALLET_BIN) $(Z23WALLET_DIR)/size/budget.tsv $(Z23WALLET_TOOLCHAIN)
