# docs/examples/Makefile — standalone build for the z23 teaching examples.
#
# Invoke as `make -C examples <target>` (or `cd examples && make <target>`).
# This file is intentionally separate from the root ../Makefile — it never
# edits it, only reads a handful of variables out of it (see printvar.mk)
# and calls its `test_parallel_fast` target to get (or reuse) a built object
# tree.
#
# WHAT EACH EXAMPLE LINKS AGAINST
# --------------------------------
# Every example is one small .c file exercising the REAL node libraries
# (engine/modules/sim, lib/consensus, contexts/wallet/modules/wallet, contexts/naming/modules/znam, contexts/market/modules/zslp, core/modules/script, ...) —
# not a mock. Rather than re-deriving the root Makefile's ~40 -I flags,
# CFLAGS, and link recipe by hand here (a guaranteed drift hazard), this
# Makefile reads them straight out of ../Makefile via printvar.mk
# (`make -C .. -f printvar.mk print-VARNAME`). It then makes sure
# ../build/test-obj/**.o is built via the root `test_parallel_fast` target —
# the SAME non-LTO object tree the node's fast edit/test inner loop
# (`make t-fast`) already produces and reuses — and links each example's own
# object file against that whole object set (minus tests/harness/src/test_parallel.o,
# which owns its own main() and would collide with the example's main()).
#
# Because the root build's objects are compiled with -DZCL_TESTING (see
# TEST_FAST_CFLAGS in ../Makefile), every example is compiled the same way,
# whether or not it happens to touch any #ifdef ZCL_TESTING declaration.
#
# Targets:
#   make -C examples             — build every example binary into bin/,
#                                   then print a friendly one-screen index
#   make -C examples run         — build, then run every binary in order;
#                                   stop at the first nonzero exit, naming
#                                   the failing example
#   make -C examples run-<name>  — build (if needed) and run just one
#                                   example, e.g. run-04_zslp_token
#   make -C examples clean       — remove bin/ and obj/ (does not touch the
#                                   root build)

ROOT := ..

# GETVAR(name) — fetch a variable's fully-expanded value straight out of the
# root Makefile via printvar.mk, so these flags can never drift from what
# `make -C .. test_parallel_fast` itself actually used to build the objects
# we are about to link against.
GETVAR = $(shell $(MAKE) -s -C $(ROOT) -f $(CURDIR)/printvar.mk print-$(1))

CC       := cc
BIN_DIR  := bin
OBJ_DIR  := obj

# _shim.c provides the one process-global symbol (g_shutdown_requested)
# every example needs but doesn't define — see _shim.c for why. It is not
# itself an example (no main()), so it is excluded from SRCS/NAMES/BINS and
# instead linked into every example binary below.
SRCS  := $(filter-out _shim.c,$(wildcard *.c))
NAMES := $(basename $(SRCS))
BINS  := $(addprefix $(BIN_DIR)/,$(NAMES))
SHIM_OBJ := $(OBJ_DIR)/_shim.o

# Pulled verbatim from the root build (evaluated once, at parse time) so
# these never hand-drift from the real node/test compile+link flags.
EX_CFLAGS   := $(call GETVAR,TEST_FAST_CFLAGS)
EX_LDFLAGS  := $(call GETVAR,TEST_FAST_LDFLAGS)
EX_TOR_LIBS := $(call GETVAR,TOR_LIBS)
EX_LIBS     := $(call GETVAR,LIBS)
EX_GTK_LIBS := $(call GETVAR,GTK_LIBS)
EX_WK_LIBS  := $(call GETVAR,WEBKIT_LIBS)

# The full non-LTO test object tree (lib/, app/, config/, domain/,
# engine/application/, platform/adapters/, tools/command/, tests/harness/src/*.o, tests/harness/spec/*.o,
# tools/sim/sim_peer.o) minus tests/harness/src/test_parallel.o's own main().
# Paths are relative to $(ROOT) — kept that way (not re-prefixed) because the
# compile/link recipes below `cd $(ROOT)` first, exactly where these paths,
# and the -I/-L flags baked into EX_CFLAGS/EX_LIBS/EX_TOR_LIBS above, are
# meant to resolve from.
LIB_OBJS := $(filter-out %/tests/harness/src/test_parallel.o %tests/harness/src/test_parallel.o,\
              $(call GETVAR,TEST_PARALLEL_FAST_OBJS))

.PHONY: all run clean objects

# Bare `make -C examples` builds every binary, then prints a friendly
# one-screen map of what's here and how to run it — free to print (the
# build already happened) and the fastest way to learn this directory's
# entry points without opening README.md first.
all: $(BINS)
	@echo
	@echo "Built $(words $(BINS)) z23 teaching examples into $(BIN_DIR)/."
	@echo
	@echo "  make -C examples run               run all $(words $(BINS)), in order, stop at the first failure"
	@echo "  make -C examples run-<name>        run just one example, e.g. run-04_zslp_token"
	@echo "  make -C examples clean             remove bin/ and obj/"
	@echo
	@echo "Examples (see docs/examples/README.md / docs/cookbook/<name>.md for the full walkthrough):"
	@for n in $(NAMES); do printf "  %-24s ./%s/%s\n" "$$n" "$(BIN_DIR)" "$$n"; done
	@echo

# Make sure the root's non-LTO test object tree exists and is up to date.
# This is the exact target the node's fast edit/test loop (`make t-fast`)
# already keeps warm, so a prior `make t-fast` / `make test_parallel_fast`
# in the root leaves nothing to rebuild here.
objects:
	$(MAKE) -s -C $(ROOT) test_parallel_fast

# Order-only on `objects`: an example's .o must not be treated as
# perpetually stale just because `objects` (phony) always "runs" — only its
# own .c should decide that.
$(OBJ_DIR)/%.o: %.c | objects
	@mkdir -p $(OBJ_DIR)
	cd $(ROOT) && $(CC) $(EX_CFLAGS) -c -o $(abspath $@) $(abspath $<)

$(BIN_DIR)/%: $(OBJ_DIR)/%.o $(SHIM_OBJ)
	@mkdir -p $(BIN_DIR)
	cd $(ROOT) && $(CC) $(EX_LDFLAGS) -o $(abspath $@) $(abspath $<) $(abspath $(SHIM_OBJ)) \
	    $(LIB_OBJS) $(EX_TOR_LIBS) $(EX_LIBS) $(EX_GTK_LIBS) $(EX_WK_LIBS)

# One command, zero parameters: build+run all 11 in order, stop at the
# FIRST failure and name it plainly (rather than relying on make's own
# "recipe for target ... failed" noise) so a broken example is unambiguous.
run: all
	@set -e; \
	for b in $(BINS); do \
	  echo "=== running $$b ==="; \
	  if ! ./$$b; then \
	    echo; \
	    echo ">>> FAILED: $$b (see output above) <<<" >&2; \
	    exit 1; \
	  fi; \
	  echo; \
	done
	@echo "All $(words $(BINS)) examples ran successfully."

# `make -C examples run-<name>` — build (if needed) and run exactly one
# example, e.g. `make -C examples run-04_zslp_token`.
run-%: $(BIN_DIR)/%
	@./$<

clean:
	rm -rf $(BIN_DIR) $(OBJ_DIR)
