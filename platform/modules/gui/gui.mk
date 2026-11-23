# Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
# Source lists of platform/modules/gui for the opt-in z23-wallet program and for
# the gui test group. The node never links this module (Makefile filters
# platform/modules/gui/src out of LIB_SRCS): a CPU/GL window layer is not node
# code, and the node must not carry its fonts or user32/gdi32 references.
GUI_DIR := platform/modules/gui
GUI_ALL_SRCS := $(sort $(wildcard $(GUI_DIR)/src/*.c))
# The Win32 backend exists only where Win32 does; elsewhere only headless links.
GUI_SRCS := $(if $(ZCL_HOST_WINDOWS),$(GUI_ALL_SRCS),$(filter-out $(GUI_DIR)/src/window_win32.c $(GUI_DIR)/src/window_win32_gl.c,$(GUI_ALL_SRCS)))
# Platform modules the gui and the wallet program need: allocation, cleansing,
# JSON, the PNG encoder and SHA3. No node, core or engine source.
GUI_DEP_SRCS := platform/modules/base/src/safe_alloc.c platform/modules/base/src/cleanse.c \
	platform/modules/json/src/json.c platform/modules/util/src/png_writer.c \
	platform/modules/sha3/src/sha3.c
GUI_TEST_SRCS := $(GUI_SRCS)
