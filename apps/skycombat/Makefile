# Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
# Package entrypoint. The assembled copy carries the exact vendor/platform
# inputs named by skycombat.mk; nothing is fetched from a host checkout.
.DEFAULT_GOAL := app
SKYCOMBAT_ENTRY_MAKEFILE := $(lastword $(MAKEFILE_LIST))
SKYCOMBAT_DIR := .

# Queries need no writable directory. A build must receive its output root
# explicitly from app.build (or an operator), never write beside source.
override SKYCOMBAT_QUERY_ONLY := $(if $(strip $(MAKECMDGOALS)),$(if $(filter-out print-game-closure print-app-closure,$(MAKECMDGOALS)),,1),)
ifeq ($(SKYCOMBAT_QUERY_ONLY),)
ifeq ($(strip $(APP_OUT)),)
$(error APP_OUT is required for every non-query target)
endif
endif
# These are derived output locations, not independent caller overrides.
override BUILD_DIR := $(APP_OUT)
override BIN_DIR := $(APP_OUT)
override SKYCOMBAT_IMAGE := $(APP_OUT)/app
override SKYCOMBAT_OBJ_DIR := $(APP_OUT)/skycombat
override Z23RAYLIB_OBJ_DIR := $(APP_OUT)/raylib
override Z23RAYLIB_LIB := $(APP_OUT)/lib/libz23raylib.a
override SKYCOMBAT_PLATFORM_STAMP := $(APP_OUT)/skycombat/.platform-ok
override ZCL_INVENTORY_LINT_ONLY :=
include $(dir $(SKYCOMBAT_ENTRY_MAKEFILE))skycombat.mk

.PHONY: app print-app-closure FORCE
app: $(SKYCOMBAT_IMAGE)
print-app-closure: print-game-closure
FORCE:
