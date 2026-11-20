# Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
# Package entrypoint for the tasks app: a thin wrapper whose whole payload is
# the commons ztasks package, carried into the seeded tree at the canonical
# package layout (include/, src/, the declared app/ program) by
# zcode-seed.def. Nothing is fetched from a host checkout.
.DEFAULT_GOAL := app
ZTASKS_SRCS := app/main.c src/ztasks.c
ZTASKS_HEADERS := include/ztasks/ztasks.h
# The tree's package entrypoint, an input of every compile and the link.
TASKS_MAKE_INPUTS := Makefile

# Queries need no writable directory. A build must receive its output root
# explicitly from app.build (or an operator), never write beside source.
override TASKS_QUERY_ONLY := $(if $(strip $(MAKECMDGOALS)),$(if $(filter-out print-app-closure,$(MAKECMDGOALS)),,1),)
ifeq ($(TASKS_QUERY_ONLY),)
ifeq ($(strip $(APP_OUT)),)
$(error APP_OUT is required for every non-query target)
endif
endif

# The root build supplies its selected dialect. A standalone copy asks its
# actual compiler without creating an object, including during closure query.
ifeq ($(origin ZCL_C_STD),undefined)
ZCL_C_STD := $(shell printf 'int main(void){return 0;}' | $(CC) -std=c23 -fsyntax-only -x c - >/dev/null 2>&1 && printf c23 || printf c2x)
endif

ZCL_CC_DRIVER ?= $(notdir $(lastword $(CC)))
ZCL_CC_IS_CLANG ?= $(if $(findstring clang,$(ZCL_CC_DRIVER)),1,)
# suppression-ok: ta_title_valid bounds every accepted title to 95 characters
# before task_apply copies it into a 96-byte field, so the copy cannot
# truncate; GCC cannot see that bound through the shared package source, and
# this extraction adds no other suppressed diagnostic class.
ifeq ($(ZCL_CC_IS_CLANG),)
ZTASKS_NOWARN := -Wno-format-truncation
endif
ZTASKS_CFLAGS := -std=$(ZCL_C_STD) -O2 -Wall -Wextra -Werror -pedantic \
	-D_POSIX_C_SOURCE=200809L $(ZTASKS_NOWARN) -Iinclude
ZTASKS_OBJ_DIR := $(APP_OUT)/ztasks
ZTASKS_OBJS := $(addprefix $(ZTASKS_OBJ_DIR)/,$(ZTASKS_SRCS:.c=.o))
ZTASKS_IMAGE := $(APP_OUT)/app

# Compilation inputs: the wrapper reads exactly the seeded package files and
# its own entrypoint. Named explicitly, never a wildcard, so a file that
# appears in the tree without being declared here does not silently join.
TASKS_CLOSURE := $(sort $(ZTASKS_SRCS) $(ZTASKS_HEADERS) $(TASKS_MAKE_INPUTS))

.PHONY: app print-app-closure
app: $(ZTASKS_IMAGE)
print-app-closure:
	@set -eu; for input in $(TASKS_CLOSURE); do \
	  test -f "$$input" || { printf 'app input missing or not regular: %s\n' "$$input" >&2; exit 2; }; \
	done; printf '%s\n' $(TASKS_CLOSURE)

$(ZTASKS_IMAGE): $(ZTASKS_OBJS) $(TASKS_MAKE_INPUTS)
	@mkdir -p $(dir $@)
	$(CC) $(ZTASKS_CFLAGS) $(ZTASKS_OBJS) -o $@

$(ZTASKS_OBJ_DIR)/%.o: %.c $(TASKS_MAKE_INPUTS) $(ZTASKS_HEADERS)
	@mkdir -p $(dir $@)
	$(CC) $(ZTASKS_CFLAGS) -MD -MP -MF $@.d -c $< -o $@

# Rebuild on real transitive include changes. Pure queries never read warm
# depfiles.
ifeq ($(strip $(TASKS_QUERY_ONLY)),)
-include $(ZTASKS_OBJS:.o=.o.d)
endif
