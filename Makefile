# ZClassic C23 Full Node
# Copyright 2026 Rhett Creighton - Apache License 2.0

# Reproduction is an execution phase, never an acquisition phase.  Force the
# vendor builder into its checksum-verified offline mode and disable host
# compiler caches before Make selects CC or evaluates the early vendor-input
# restart barrier below.  Doing this in the recipe is too late: GNU Make may
# compile a parse-time helper or remake VENDOR_BOOTSTRAP_MK before the requested
# target recipe starts.  `override` is deliberate; a permissive caller
# environment may not silently weaken a hermetic release gate.
ZCL_NETWORK_DENIED_BUILD_GOALS := ci-reproducible repro-verify
ifneq ($(strip $(filter $(ZCL_NETWORK_DENIED_BUILD_GOALS),$(MAKECMDGOALS))),)
override ZCL_VENDOR_OFFLINE := 1
override ZCL_USE_CCACHE := 0
export ZCL_VENDOR_OFFLINE
export ZCL_USE_CCACHE
endif

CC = cc
CXX ?= c++
ZCL_USE_CCACHE ?= 1
# The compile cache ships in-tree (tools/zcc.c). Prefer it over any installed
# sccache/ccache so every developer gets the same fast rebuilds with nothing
# to install, and fall back to a host cache only if the in-tree one cannot be
# built here. This is a parse-time $(shell) because $(CC) is fixed before the
# first recipe runs; see tools/dev/zcc_bootstrap.sh for why and what it costs.
ZCL_CCACHE_BIN := $(shell if [ "$(ZCL_USE_CCACHE)" != "0" ]; then \
                              $(CURDIR)/tools/dev/zcc_bootstrap.sh 2>/dev/null \
                              || command -v sccache 2>/dev/null \
                              || command -v ccache 2>/dev/null; fi)
ifneq ($(ZCL_CCACHE_BIN),)
ifeq ($(filter zcc sccache ccache,$(notdir $(firstword $(CC)))),)
CC := $(ZCL_CCACHE_BIN) $(CC)
endif
endif

# Standalone cleanup must never bootstrap vendor archives, generated views, or
# a compiler merely to delete artifacts. Mixed goals remain ordinary builds.
ZCL_STANDALONE_CLEAN := $(if $(filter clean coverage-clean,$(MAKECMDGOALS)),$(if $(word 2,$(MAKECMDGOALS)),,1),)
ZCL_ZERO_SHA256 = 0000000000000000000000000000000000000000000000000000000000000000

# The observable hot-swap loop (hotswap-try / hotswap-apply) delegates the
# module rebuild to tools/dev/hotswap-module-fast.sh, which works from cached
# compile metadata and falls back to a nested authoritative `make
# hotswap-module-so` whenever that cache is stale. Its parse therefore never
# needs the whole-tree source identity, the compiler/toolchain epochs, or the
# object depfile graphs — skipping them takes the observable loop from ~13 s
# to ~2 s. The set is exact: any other goal (including hotswap-module-so
# itself, which stamps artifacts with the real identity) forces the full
# authoritative parse. The standalone presentation package has the same
# property: its explicit, tiny dependency graph neither consumes nor stamps a
# whole-node source identity, so visual relaunches share this lean parse path.
ZCL_HOTSWAP_LOOP_GOALS := hotswap-try hotswap-apply \
	presentation-lib presentation-demo presentation-relaunch \
	presentation-desktop-install presentation-portability
ZCL_HOTSWAP_LOOP_ONLY := $(if $(strip $(MAKECMDGOALS)),$(if $(strip $(filter-out $(ZCL_HOTSWAP_LOOP_GOALS),$(MAKECMDGOALS))),,1),)

# hotswap-module-so compiles exactly one TU via a direct $(CC) shell command in
# its recipe body, never through make's %.o pattern rules, so it needs none of
# the four object depfile graphs either — unlike hotswap-try/hotswap-apply it
# DOES stamp its artifact names with the real captured source identity (see
# BUILD_SOURCE_RECORD below), so it deliberately stays out of
# ZCL_HOTSWAP_LOOP_GOALS above (that set fakes a zero identity). This wider
# set only gates the depfile-graph import skip.
ZCL_HOTSWAP_DEPFILE_LEAN_GOALS := $(ZCL_HOTSWAP_LOOP_GOALS) hotswap-module-so
ZCL_HOTSWAP_DEPFILE_LEAN_ONLY := $(if $(strip $(MAKECMDGOALS)),$(if $(strip $(filter-out $(ZCL_HOTSWAP_DEPFILE_LEAN_GOALS),$(MAKECMDGOALS))),,1),)

# worktree-prime's whole point is to supply vendor/lib/*.a by copy instead of
# the vendor-bootstrap rule's from-pinned-source rebuild (measured ~57s for a
# from-empty vendor/lib on this host; `cp -a` is sub-second) — so on a fresh
# worktree (vendor/lib empty) it must run BEFORE the -include below can see
# missing archives and force that rebuild as a parse-time side effect. Same
# exemption shape as ZCL_HOTSWAP_LOOP_ONLY above.
ZCL_WORKTREE_PRIME_ONLY := $(if $(strip $(MAKECMDGOALS)),$(if $(strip $(filter-out worktree-prime,$(MAKECMDGOALS))),,1),)

# These front doors establish their own checksum-pinned sysroot and vendor
# archives before entering a nested authoritative Make. On a from-empty clone,
# do not let this outer parse first bootstrap host-ABI archives that the
# portable builder would immediately replace.
ZCL_PORTABLE_FRONTDOOR_GOALS := portable c23-portable-toolchain \
	c23-portable-release c23-portable-install c23-commons-installed-acceptance \
	native-agent-ui-alpha
ZCL_PORTABLE_FRONTDOOR_ONLY := $(if $(strip $(MAKECMDGOALS)),$(if $(strip \
	$(filter-out $(ZCL_PORTABLE_FRONTDOOR_GOALS),$(MAKECMDGOALS))),,1),)

# Linked vendor archives are part of the exact source identity. On a fresh
# clone they do not exist until the vendor builder runs, so Make must cross a
# parse/restart boundary before BUILD_SOURCE_RECORD is captured. Otherwise the
# first parse would omit the archives, create them later, and correctly refuse
# its own post-link identity check. The same boundary protects entry points
# whose `vendor-ready` prerequisite may repair stale archives. Because GNU Make
# keeps its pid (and therefore its ZCL_SOURCE_IDENTITY_SESSION) across the
# restart, the boundary recipe must also drop this session's cached capture:
# the pre-boundary parse may already have memoized a record that cannot see
# the inputs this boundary establishes.
NODE_VENDOR_ARCHIVES = libsecp256k1.a libcrypto.a libssl.a libevent.a \
	libevent_openssl.a libevent_pthreads.a libsqlite3.a libz.a libtor_stub.a
# A focused `make z23` (or legacy `make zclassic23`) needs no C++ toolchain.
# Test/dev builds retain LevelDB strictly as a differential oracle.
ZCL_NODE_ONLY_BUILD := $(if $(strip $(MAKECMDGOALS)),$(if $(strip $(filter-out z23 zclassic23,$(MAKECMDGOALS))),,1),)
VENDOR_ARCHIVES = $(NODE_VENDOR_ARCHIVES) \
	$(if $(ZCL_NODE_ONLY_BUILD),,libleveldb.a)
VENDOR_LIBS = $(addprefix vendor/lib/,$(VENDOR_ARCHIVES))
NODE_VENDOR_LIBS = $(addprefix vendor/lib/,$(NODE_VENDOR_ARCHIVES))
VENDOR_BOOTSTRAP_MK := build/identity/vendor-inputs-ready.mk
VENDOR_MISSING_INPUTS := $(filter-out $(wildcard $(VENDOR_LIBS)),$(VENDOR_LIBS))
VENDOR_REPAIR_GOALS := vendor-ready deploy install
VENDOR_REPAIR_REQUESTED := $(filter $(VENDOR_REPAIR_GOALS),$(MAKECMDGOALS))
ifneq ($(ZCL_STANDALONE_CLEAN),1)
ifneq ($(ZCL_WORKTREE_PRIME_ONLY),1)
ifneq ($(ZCL_PORTABLE_FRONTDOOR_ONLY),1)
ifneq ($(strip $(VENDOR_MISSING_INPUTS) $(VENDOR_REPAIR_REQUESTED)),)
ifeq ($(strip $(MAKE_RESTARTS)),)
-include $(VENDOR_BOOTSTRAP_MK)
endif
endif
endif
endif
endif

# Generated view headers are compiler inputs and therefore part of the exact
# source identity. Make must establish them before BUILD_SOURCE_RECORD is
# captured: after a template edit, building a stale header later in the same
# parse would correctly trip post-link verification. Remaking this included
# marker forces a parse restart whenever either generated header is missing or
# stale, so the authoritative capture always observes the bytes actually used.
VIEW_GEN_HEADERS_EARLY := app/views/include/views/wallet_templates_gen.h \
	app/views/include/views/site_css.h
VIEW_BOOTSTRAP_MK := build/identity/view-inputs-ready.mk
ifneq ($(ZCL_STANDALONE_CLEAN),1)
ifeq ($(strip $(MAKE_RESTARTS)),)
-include $(VIEW_BOOTSTRAP_MK)
endif
endif

# <short-hash>[-dirty] — the -dirty suffix means the binary contains
# uncommitted tracked changes, so the hash alone does NOT identify the code
# (a binary built minutes before its fix was committed reports the parent
# commit; that ambiguity cost a live-deploy verification detour 2026-06-12).
# `git update-index -q --refresh` first: a fresh `git clone` leaves stale stat
# info in the index, so `git diff-index` reports spurious "-dirty" on a pristine
# tree until the index is refreshed. Refreshing compares content and clears the
# false positive, while a genuinely modified tree still reports -dirty. The
# hot-swap loop never bakes a commit id into an artifact, so it skips the git
# probes (and their index refresh) entirely.
ifeq ($(ZCL_HOTSWAP_LOOP_ONLY),1)
BUILD_COMMIT := hotswap-loop
else
BUILD_COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)$(shell git update-index -q --refresh >/dev/null 2>&1; git diff-index --quiet HEAD -- 2>/dev/null || echo -dirty)
endif
# A parent Make/watcher may freeze its already-captured record on the recursive
# command line.  GNU Make gives command-line variables precedence, but an
# unconditional `:= $(shell ...)` still executes the discarded shell RHS and
# used to reread the complete source inventory in every nested Make.  Accept
# only command-line provenance here: an ambient environment variable cannot
# suppress capture.  Artifact sessions still verify-record before compilation
# and again before aggregate/candidate publication.
#
# BUILD_EPOCH_CLEAN_ONLY / BUILD_INVOCATION_* are pulled forward from their
# original home down near the epoch-lease definitions so a session token
# exists before the FIRST source-identity.sh call below. capture-record/
# verify-record are each a full git-ls-files+find+sha256 walk of every build
# input (~1.2s measured on this tree), and one plain `make build-only` or
# `make t-fast` invocation calls one of them 4-5 times over (this parse-time
# capture, the mutation/identity stamps further down, and every
# build-epoch-session.sh acquire/verify) even with zero source changes.
# ZCL_SOURCE_IDENTITY_SESSION lets every one of those calls within THIS live
# Make process -- keyed by its own pid + kernel start-time, so a reused pid
# from an already-dead Make never matches -- reuse the ONE walk any of them
# already paid for instead of repeating it. A new `make` invocation always
# derives a new token, so cross-invocation supersession detection (a real
# source edit between two separate builds) is untouched; see the session
# cache in tools/dev/source-identity.sh.
BUILD_EPOCH_CLEAN_ONLY := $(if $(ZCL_STANDALONE_CLEAN)$(ZCL_HOTSWAP_LOOP_ONLY),1,)
BUILD_INVOCATION_PID := $(if $(BUILD_EPOCH_CLEAN_ONLY),0,$(strip $(shell printf '%s' $$PPID)))
BUILD_INVOCATION_START := $(if $(BUILD_EPOCH_CLEAN_ONLY),0,$(strip $(shell awk '{print $$22}' /proc/$(BUILD_INVOCATION_PID)/stat 2>/dev/null)))
BUILD_INVOCATION_ID := $(if $(BUILD_EPOCH_CLEAN_ONLY),clean,$(strip $(shell printf '%s\0%s' '$(BUILD_INVOCATION_PID)' '$(BUILD_INVOCATION_START)' | sha256sum | awk '{print $$1}')))
ZCL_SOURCE_IDENTITY_SESSION := $(BUILD_INVOCATION_PID):$(BUILD_INVOCATION_START)

# Deriving one compile epoch fingerprints the compiler, sysroot, flags, and
# build-system inputs.  Doing that for every profile on every parse made a
# warm one-group test pay for build-only, dev, strict, coverage, and sanitizer
# profiles it could never consume.  Exact known goals select only the profile
# they execute; mixed/default/unknown goals retain the conservative all-profile
# fallback so a newly-added goal cannot silently lose freshness authority.
ZCL_EPOCH_ALL_PROFILES := build-only dev dev-asan dev-tsan test-fast \
	test-strict test-asan test-tsan coverage
ZCL_EPOCH_PROFILES := $(ZCL_EPOCH_ALL_PROFILES)
ifeq ($(BUILD_EPOCH_CLEAN_ONLY),1)
ZCL_EPOCH_PROFILES :=
else ifeq ($(ZCL_WORKTREE_PRIME_ONLY),1)
ZCL_EPOCH_PROFILES :=
else ifeq ($(words $(MAKECMDGOALS)),1)
ZCL_EPOCH_SINGLE_GOAL := $(firstword $(MAKECMDGOALS))
ifneq ($(filter build-only,$(ZCL_EPOCH_SINGLE_GOAL)),)
ZCL_EPOCH_PROFILES := build-only
else ifneq ($(filter fast-compile dev-build-only,$(ZCL_EPOCH_SINGLE_GOAL)),)
ZCL_EPOCH_PROFILES := dev
else ifneq ($(filter dev-bin z23-dev zclassic23-dev,$(ZCL_EPOCH_SINGLE_GOAL)),)
ZCL_EPOCH_PROFILES := dev test-fast
else ifneq ($(filter dev-package-verifier,$(ZCL_EPOCH_SINGLE_GOAL)),)
ZCL_EPOCH_PROFILES := dev
else ifneq ($(filter t-fast t-fast-exact test_parallel_fast test-parallel-fast-active test-parallel-fast-active-locked t-fast-locked t-fast-exact-locked,$(ZCL_EPOCH_SINGLE_GOAL)),)
ZCL_EPOCH_PROFILES := test-fast
else ifneq ($(filter t test test_parallel test-parallel test-parallel-active test-parallel-active-locked test-parallel-locked t-locked test-locked secure-release-regressions secure-release-regressions-locked,$(ZCL_EPOCH_SINGLE_GOAL)),)
ZCL_EPOCH_PROFILES := test-strict
else ifneq ($(filter t-asan test-asan asan-ci zcode-package-asan,$(ZCL_EPOCH_SINGLE_GOAL)),)
ZCL_EPOCH_PROFILES := test-asan
else ifneq ($(filter dev-asan z23-dev-asan zclassic23-dev-asan,$(ZCL_EPOCH_SINGLE_GOAL)),)
ZCL_EPOCH_PROFILES := dev-asan
else ifneq ($(filter t-tsan test-tsan tsan-ci,$(ZCL_EPOCH_SINGLE_GOAL)),)
ZCL_EPOCH_PROFILES := test-tsan
else ifneq ($(filter dev-tsan z23-dev-tsan zclassic23-dev-tsan,$(ZCL_EPOCH_SINGLE_GOAL)),)
ZCL_EPOCH_PROFILES := dev-tsan
else ifneq ($(filter coverage coverage-locked,$(ZCL_EPOCH_SINGLE_GOAL)),)
ZCL_EPOCH_PROFILES := coverage
else ifneq ($(filter lint lint-fast watcher-safety-gates dev-failure-execution-id ff t-changed fast-changed-compile fast-rebuild rebuild-fast dev-rebuild hot-rebuild super-rebuild fast-ci agent-fast-ci dev-ci agent-plan agent-loop agent-dev-loop pre-push-ci t-list templates site-css explorer-css,$(ZCL_EPOCH_SINGLE_GOAL)),)
ZCL_EPOCH_PROFILES :=
endif
endif

ifneq ($(origin BUILD_SOURCE_RECORD),command line)
ifeq ($(ZCL_STANDALONE_CLEAN),1)
BUILD_SOURCE_RECORD := $(ZCL_ZERO_SHA256) 1 $(ZCL_ZERO_SHA256)
else ifeq ($(ZCL_HOTSWAP_LOOP_ONLY),1)
# The hot-swap loop recipe re-derives any identity it needs through the
# authoritative nested make; the zero record is never stamped into an artifact.
BUILD_SOURCE_RECORD := $(ZCL_ZERO_SHA256) 1 $(ZCL_ZERO_SHA256)
else
BUILD_SOURCE_RECORD := $(shell ZCL_SOURCE_IDENTITY_SESSION='$(ZCL_SOURCE_IDENTITY_SESSION)' tools/dev/source-identity.sh capture-record 2>/dev/null || echo unknown 0 unknown)
endif
endif
BUILD_SOURCE_ID := $(word 1,$(BUILD_SOURCE_RECORD))
BUILD_CLEAN := $(word 2,$(BUILD_SOURCE_RECORD))
BUILD_MUTATION := $(word 3,$(BUILD_SOURCE_RECORD))
# Keep standalone cleanup usable on a host whose compiler/toolchain has already
# been removed. Every target that can create an artifact remains fail-closed.
# The hot-swap loop goals join this epoch/identity-free parse: their recipes
# touch no compile epoch, lease, or identity stamp.
ifeq ($(BUILD_EPOCH_CLEAN_ONLY),1)
BUILD_SOURCE_RECORD_VALID := yes
else
BUILD_SOURCE_RECORD_VALID := $(shell printf '%s\n' '$(BUILD_SOURCE_ID) $(BUILD_CLEAN) $(BUILD_MUTATION)' | awk 'BEGIN { ok=0 } $$1 ~ /^[0-9a-f]{64}$$/ && $$2 == "1" && $$3 ~ /^[0-9a-f]{64}$$/ && NF == 3 { ok=1 } END { if (ok) print "yes" }')
ifneq ($(BUILD_SOURCE_RECORD_VALID),yes)
$(error exact source capture failed; refusing to select a compile epoch)
endif
endif
BUILD_DIR = build
BIN_DIR = $(BUILD_DIR)/bin
OBJ_ROOT = $(BUILD_DIR)/obj
DEV_OBJ_ROOT = $(BUILD_DIR)/dev-obj
OBJ_DIR = $(OBJ_ROOT)/epochs/$(BUILD_ONLY_COMPILE_EPOCH)
DEV_OBJ_DIR = $(DEV_OBJ_ROOT)/epochs/$(DEV_COMPILE_EPOCH)

# Non-executing make modes: -n (dry run), -q (question), -t (touch). GNU Make
# puts the concatenated SHORT flags of the current invocation in the first
# word of MAKEFLAGS, and that word never begins with '-' when it exists (long
# options arrive as their own '--word' entries), so filtering '-%' out of word
# 1 leaves exactly the short-flag letters or nothing.
#
# WHY THIS EXISTS. $(file >...) is a make FUNCTION, so it runs when the recipe
# line is EXPANDED — and make expands every recipe line under -n in order to
# print it. A response-file recipe written the obvious way therefore writes
# its file during a dry run, which both violates -n's promise to change
# nothing and hard-fails when the epoch directory does not exist yet, because
# the mkdir that would have created it lives in a recipe -n only printed. On a
# cold checkout that made `make -n <any test goal>` die with
# "open: .../link-inputs.rsp: No such file or directory", exit 2 — observed on
# the hosted runner via test_test_group_selector's Make admission probe, which
# passes on a warm tree and fails on a cold one. Guard every $(file >...) with
# this so a non-executing mode expands to nothing.
ZCL_MAKE_SHORT_FLAGS := $(filter-out -%,$(word 1,$(MAKEFLAGS)))
ZCL_MAKE_NO_EXEC := \
    $(strip $(foreach f,n q t,$(findstring $(f),$(ZCL_MAKE_SHORT_FLAGS))))

# Only ZCL_BUILD_SOURCE_ID is baked into the sovereign binary. Git commit ids
# remain external GitHub trace/publish metadata: embedding them would make the
# exact executable digest (and therefore producer receipts) change with a
# history-only commit. The identity-keyed stamp refreshes clientversion.c only
# when authoritative source bytes change. Concurrent builds of different source
# epochs use different targets, and same-epoch writers publish identical stamp
# contents by atomic rename.
BUILD_MUTATION_STAMP := $(BUILD_DIR)/identity/mutation.$(BUILD_MUTATION).stamp
$(BUILD_MUTATION_STAMP): tools/dev/source-identity.sh
	@set -eu; \
	mkdir -p "$(dir $@)"; \
	ZCL_SOURCE_IDENTITY_SESSION='$(ZCL_SOURCE_IDENTITY_SESSION)' tools/dev/source-identity.sh verify-record "$(BUILD_SOURCE_ID)" "$(BUILD_CLEAN)" "$(BUILD_MUTATION)" >/dev/null; \
	tmp="$$(mktemp "$(dir $@).stamp.XXXXXX")"; \
	trap 'rm -f "$$tmp"' EXIT HUP INT TERM; \
	printf '%s\n' 'mutation=$(BUILD_MUTATION)' > "$$tmp"; \
	mv -f -- "$$tmp" "$@"; \
	trap - EXIT HUP INT TERM

BUILD_PROVER_BACKEND := native-c23
BUILD_IDENTITY_STAMP := $(BUILD_DIR)/identity/$(BUILD_SOURCE_ID).$(BUILD_CLEAN).$(BUILD_MUTATION).prover-$(BUILD_PROVER_BACKEND).stamp
$(BUILD_IDENTITY_STAMP): $(BUILD_MUTATION_STAMP) tools/dev/source-identity.sh
	@set -eu; \
	mkdir -p "$(dir $@)"; \
	ZCL_SOURCE_IDENTITY_SESSION='$(ZCL_SOURCE_IDENTITY_SESSION)' tools/dev/source-identity.sh verify-record "$(BUILD_SOURCE_ID)" "$(BUILD_CLEAN)" "$(BUILD_MUTATION)" >/dev/null; \
	tmp="$$(mktemp "$(dir $@).stamp.XXXXXX")"; \
	trap 'rm -f "$$tmp"' EXIT HUP INT TERM; \
	printf '%s\n' \
	  'source=$(BUILD_SOURCE_ID)' \
	  'clean=$(BUILD_CLEAN)' \
	  'mutation=$(BUILD_MUTATION)' \
	  'prover_backend=$(BUILD_PROVER_BACKEND)' > "$$tmp"; \
	mv -f -- "$$tmp" "$@"; \
	trap - EXIT HUP INT TERM

# Preferred binary names are z23/z23-dev (product rename from ZClassic23).
# The ZCLASSIC23_* variable names stay (build-internal), and the old
# build/bin/zclassic23* names remain as temporary symlink aliases so existing
# bots and scripts get an obvious migration path.
ZCLASSIC23_BIN = $(BIN_DIR)/z23
ZCLASSIC23_DEV_BIN = $(BIN_DIR)/z23-dev
ZCLASSIC23_BIN_ALIAS = $(BIN_DIR)/zclassic23
ZCLASSIC23_DEV_BIN_ALIAS = $(BIN_DIR)/zclassic23-dev
DEV_RESTART_PLAN = $(BUILD_DIR)/dev-loop/restart.env
TEST_ZCL_BIN = $(BIN_DIR)/test_zcl
TEST_PARALLEL_BIN = $(BIN_DIR)/test_parallel
ZCLASSIC_CLI_BIN = $(BIN_DIR)/zclassic-cli
ZCL_RPC_BIN = $(BIN_DIR)/zcl-rpc
# Stable output names do not encode the compiler/sysroot that produced them.
# The portable release therefore opts its whole-program products into a fresh
# atomic link; otherwise a newer host-built file could pass Make's timestamp
# check and reach the release audit/install boundary.
C23_PORTABLE_RELINK := $(if $(filter 1,$(ZCL_C23_PORTABLE_RELEASE)),FORCE,)
ZCL_AGENT_BIN ?= $(ZCLASSIC23_DEV_BIN)
ZCL_AGENT_DEV_BIN ?= $(HOME)/.local/bin/zclassic23-dev
ZCL_AGENT_DEV_DATADIR ?= $(HOME)/.zclassic-c23-dev
ZCL_AGENT_DEV_RPCPORT ?= 18252
ZCL_NODECTL_BIN = $(BIN_DIR)/zcl-nodectl
WAL_CHECKPOINT_BIN = $(BIN_DIR)/wal_checkpoint
SOAK_RUNNER_BIN = $(BIN_DIR)/soak_runner
CRASH_RECOVERY_TEST_BIN = $(BIN_DIR)/crash_recovery_test
P2_INVARIANT_CHECK_BIN = $(BIN_DIR)/p2_invariant_check
ZCLASSIC23_CHAOS_BIN = $(BIN_DIR)/zclassic23-chaos
CHAOS_SEEDS ?= 64
CHAOS_SWEEP_SCENARIO ?= tools/sim/scenarios/seeded_peer_churn.scenario

# The make-vendor merge introduced the `vendor:` target ahead of `all:`, which
# made `vendor` the implicit first target (and thus the default goal). A bare
# `make` would then only build the vendored libs, never the binary. Pin the
# default goal back to `all` so `git clone && make vendor && make` (and a plain
# `make`) builds the node as expected; the auto-vendor prerequisite machinery
# still pulls missing archives in transparently.
.DEFAULT_GOAL := all

# App layer (MVC)
APP_DIRS = models controllers views services supervisors conditions jobs
APP_INCLUDES = $(foreach d,$(APP_DIRS),-Iapp/$(d)/include)
# Lint-gate tests intentionally plant short-lived fixture files inside the
# production scan tree so the lint scopes stay honest. Those files must remain
# visible to lint, but concurrent builds must never compile them.
zcl_ephemeral_sources = $(foreach s,$(1),$(if $(findstring /_,$(s)),$(s)))
zcl_filter_ephemeral_sources = $(filter-out $(call zcl_ephemeral_sources,$(1)),$(1))
APP_SRCS = $(call zcl_filter_ephemeral_sources,\
	$(foreach d,$(APP_DIRS),$(wildcard app/$(d)/src/*.c)))

# Config layer
CONFIG_INCLUDES = -Iconfig/include
CONFIG_SRCS = $(call zcl_filter_ephemeral_sources,\
	$(wildcard config/src/*.c))

# Library layer
# DERIVED, never restated. config/lib_module_order.def is the one declaration
# of which lib/ modules exist; this reads its set. Sorted rather than kept in
# the file's rank order because rank governs the LINK graph, not the compile
# order, and a canonical sort makes the source list stable no matter how the
# ranks are later rearranged. `sort` also dedupes, so a doubled row there
# cannot double a wildcard here.
LIB_MODULE_ORDER_DEF = config/lib_module_order.def
LIB_MODULES := $(sort $(shell sed -n 's/^[[:space:]]*LIB_MODULE("\([A-Za-z0-9_]*\)").*/\1/p' \
	$(LIB_MODULE_ORDER_DEF) 2>/dev/null))
ifeq ($(strip $(LIB_MODULES)),)
$(error could not derive LIB_MODULES from $(LIB_MODULE_ORDER_DEF) — every lib/ \
source glob and -I flag comes from that file, so an empty parse would silently \
build nothing rather than fail. Check the file exists and its LIB_MODULE rows \
are intact)
endif
LIB_INCLUDES = $(foreach m,$(LIB_MODULES),-Ilib/$(m)/include)
LIB_SRCS = $(call zcl_filter_ephemeral_sources,\
	$(foreach m,$(LIB_MODULES),$(wildcard lib/$(m)/src/*.c)))

# Ports layer (Clean Architecture / Hexagonal interface headers).
# Headers only — adapters that implement these interfaces live elsewhere.
# See ports/include/ports/README.md for the convention.
PORTS_INCLUDES = -Iports/include

# Domain layer (pure, framework-free, no I/O).
# Bounded contexts under domain/<context>/ each expose include/domain/<context>/.
DOMAIN_CONTEXTS = wallet encoding
DOMAIN_INCLUDES = $(foreach c,$(DOMAIN_CONTEXTS),-Idomain/$(c)/include)
DOMAIN_SRCS = $(call zcl_filter_ephemeral_sources,\
	$(foreach c,$(DOMAIN_CONTEXTS),$(wildcard domain/$(c)/src/*.c)))

# Sealed consensus core (Wave 1.1 split). Bounded contexts under core/<context>/
# hold the consensus predicates + static parameter tables. Include TOKENS are
# preserved across the physical move (core/consensus keeps the "domain/consensus/"
# token via -Icore/consensus/include; core/params keeps the "consensus/" token
# via -Icore/params/include; core/math keeps the "core/" token via
# -Icore/math/include over core/math/include/core/*.h — absorbing the pure
# lib/core primitives resolves the core/ namespace collision, the reduced
# lib/core keeps only the dirty leaves amount/random/utiltime; core/chainparams
# keeps the "chain/" token via -Icore/chainparams/include over
# core/chainparams/include/chain/*.h — the pure params/verify subset
# chainparams/chainparamsbase/equihash/pow/subsidy/checkpoints, with the
# orchestration remainder chain/mmb/mmr/sha3_windows/utxo_* staying in lib/chain;
# the two "chain/" -I paths serve disjoint headers), so no consumer #include
# changes. core/ is a source/gate/seal unit that stays IN the whole-program LTO
# link — NOT a separate archive (a libzclcore.a would sever hot-path inlining).
# Sealed by core/MANIFEST.sha3; boundary-gated by check-core-include-boundary.
CORE_CONTEXTS = consensus params math chainparams
CORE_INCLUDES = $(foreach c,$(CORE_CONTEXTS),-Icore/$(c)/include)
CORE_SRCS = $(call zcl_filter_ephemeral_sources,\
	$(foreach c,$(CORE_CONTEXTS),$(wildcard core/$(c)/src/*.c)))

# Application layer (use cases / service objects).
# May depend on domain/, ports/, primitives, util — never on adapters or I/O.
APPLICATION_CONTEXTS = consensus
APPLICATION_INCLUDES = $(foreach c,$(APPLICATION_CONTEXTS),-Iapplication/$(c)/include)
APPLICATION_SRCS = $(call zcl_filter_ephemeral_sources,\
	$(foreach c,$(APPLICATION_CONTEXTS),$(wildcard application/$(c)/src/*.c)))

# Adapters layer (port implementations).
# Outbound adapters implement the port interfaces. Inbound surfaces currently
# live in app/controllers and tools/command until a real adapter shape
# is introduced.
ADAPTERS_INCLUDES = -Iadapters/outbound/persistence/include
ADAPTERS_SRCS = $(call zcl_filter_ephemeral_sources,\
	$(wildcard adapters/outbound/persistence/src/*.c))

# tools/ header root (the "command/" prefix for the native command adapter,
# plus any other tools headers).
TOOLS_INCLUDES = -Itools

# Native development control plane.  These C adapters are the AI-facing
# save -> classify -> prove -> publish loop; tools/dev/*.sh remain temporary
# compatibility/self-test fixtures, not the primary interface.
DEVLOOP_INCLUDES = -Itools/dev
# tools/dev/*.c splits into two groups. The read-only helpers (registry-driven
# menu/help/search, App-manifest describe/plan/simulate, source-change
# classification) are release-safe and back the registry dev handlers, so they
# stay in ALL_SRCS. The mutating executors (the checkout-local dispatcher, the
# hot-swap/reload cycle, the persistent inotify watcher, and the subprocess
# runner) are DEV_ONLY_SRCS: linked only into the DEV binary, never the release
# binary. `check-release-no-dev-symbols` proves their entry points are absent.
DEVLOOP_ALL_SRCS = $(call zcl_filter_ephemeral_sources,\
	$(wildcard tools/dev/*.c))
DEV_ONLY_SRCS = tools/dev/devloop_cli.c tools/dev/devloop_cycle.c \
	tools/dev/devloop_watch.c tools/dev/devloop_process.c \
	tools/dev/devloop_hotswap_build.c tools/dev/devloop_restart_build.c \
	tools/dev/devloop_baseline.c tools/dev/dev_failure_store.c \
	tools/dev/dev_source_identity.c
DEVLOOP_SRCS = $(filter-out $(DEV_ONLY_SRCS),$(DEVLOOP_ALL_SRCS))

# The stable public Core -> App ABI is lib/framework/include/zclassic23/app.h,
# reached through LIB_INCLUDES. It deliberately exposes no consensus, storage,
# wallet-key, socket, or boot internals; the header itself states the rule.

# Native command adapter (registry-backed CLI). Release-visible: core/ops/
# discover leaves ship in the release binary, so this is part of ALL_SRCS
# rather than the dev-only lane. Header path -Itools is provided by TOOLS_INCLUDES.
COMMAND_SRCS = $(call zcl_filter_ephemeral_sources,\
	$(wildcard tools/command/*.c))
# Declarative command rows are C include inputs, but the whole-program release
# rules below do not emit depfiles.  Keep them as explicit prerequisites so a
# command-contract-only edit cannot leave build/bin/zclassic23 stale.
COMMAND_CATALOG_DEFS = $(wildcard config/commands/*.def) \
	$(wildcard config/commands/*/*.def)

NODE_ENTRY_SRCS = src/main.c src/main_cli_modes.c
ALL_SRCS = $(APP_SRCS) $(CONFIG_SRCS) $(LIB_SRCS) $(CORE_SRCS) $(DOMAIN_SRCS) $(APPLICATION_SRCS) $(ADAPTERS_SRCS) $(DEVLOOP_SRCS) $(COMMAND_SRCS)
ALL_OBJS = $(patsubst %.c,$(OBJ_DIR)/%.o,$(ALL_SRCS))

# The DEV binary keeps everything: the release source set plus the dev-only
# executors excluded from ALL_SRCS above.
DEV_SRCS = $(NODE_ENTRY_SRCS) $(ALL_SRCS) $(DEV_ONLY_SRCS)
DEV_OBJS = $(patsubst %.c,$(DEV_OBJ_DIR)/%.o,$(DEV_SRCS))
DEV_OBJ_COMPLETE = $(DEV_OBJ_DIR)/.complete
DEV_PACKAGE_VERIFY_OBJ = $(DEV_OBJ_DIR)/tools/package_verify.o
DEV_PACKAGE_VERIFY_NODE_OBJS = $(patsubst %.c,$(DEV_OBJ_DIR)/%.o,\
	$(ALL_SRCS) $(DEV_ONLY_SRCS))
DEV_PACKAGE_VERIFY_LINK_RSP = $(DEV_OBJ_DIR)/package-verify-link-inputs.rsp
DEV_PACKAGE_VERIFY_BIN = $(BIN_DIR)/zclassic23-package-verify-dev
DEV_PACKAGE_VERIFY_ENSURE_STAMP = $(BUILD_DIR)/dev-package-verifier.ensure

# pkg-config probes feed only compile/link flag expansion. The hot-swap loop
# compiles nothing inside this parse (the fast path replays cached flags), so
# it skips the probes.
ifeq ($(ZCL_HOTSWAP_LOOP_ONLY),1)
GTK_CFLAGS :=
GTK_LIBS   :=
GTK_DEF    :=
WEBKIT_CFLAGS :=
WEBKIT_LIBS   :=
WEBKIT_DEF    :=
else
GTK_CFLAGS := $(shell pkg-config --cflags gtk+-3.0 2>/dev/null)
GTK_LIBS   := $(shell pkg-config --libs gtk+-3.0 2>/dev/null)
GTK_DEF    := $(if $(GTK_CFLAGS),-DHAVE_GTK,)
WEBKIT_CFLAGS := $(shell pkg-config --cflags webkit2gtk-4.1 2>/dev/null)
WEBKIT_LIBS   := $(shell pkg-config --libs webkit2gtk-4.1 2>/dev/null)
WEBKIT_DEF    := $(if $(WEBKIT_CFLAGS),-DHAVE_WEBKIT,)
endif

# Binary-hardening flags, applied explicitly so the guarantees do not depend on
# distro/toolchain defaults (a judge running `checksec` sees them every build):
#   -fstack-protector-strong  stack canaries
#   -D_FORTIFY_SOURCE=2       compile-time + runtime libc bounds checks (needs -O)
#   -fcf-protection=full      Intel CET (endbr64 IBT + shadow stack); NOPs on
#                             pre-CET CPUs, so it is safe to always enable
#   -fPIE / -pie              position-independent executable (ASLR)
#   -Wl,-z,relro -Wl,-z,now   full RELRO (GOT mapped read-only after binding)
#   -Wl,-z,noexecstack        non-executable stack (NX)
HARDEN_CFLAGS = -fstack-protector-strong -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2 -fcf-protection=full -fPIE
HARDEN_LDFLAGS = -pie -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack -fcf-protection=full
BUILD_IDENTITY_CPPFLAGS = -DZCL_BUILD_SOURCE_ID=\"$(BUILD_SOURCE_ID)\" -DZCL_BUILD_CLEAN=$(BUILD_CLEAN)
# The ABA mutation token contains host-local inode/time metadata and therefore
# MUST NOT enter the reproducible sovereign/release binary. Dev/test artifacts
# may carry it as a fast admission receipt: their publication path already
# verify-records this exact source+mutation pair before the atomic alias move.
DEV_SOURCE_RECEIPT_CPPFLAGS = -DZCL_BUILD_SOURCE_MUTATION=\"$(BUILD_MUTATION)\"
# -g: full debug info so addr2line resolves file:line through the split
# sidecar (see the zclassic23 link rule below). -g1 was tried first and is
# NOT sufficient: under the whole-program LTO link its line tables degrade
# to <artificial> file attribution. Code generation is identical; only the
# .debug sidecar grows — the shipped binary is stripped either way.
# -g: full debug info so crash-log addresses resolve to file:line through
# the split sidecar (see the zclassic23 link rule below). -g1 was tried
# first and is NOT sufficient: under the whole-program LTO link its line
# tables degrade to <artificial> file attribution. Note binutils addr2line
# only resolves ~3% of addresses on this LTO binary (GCC's .debug_aranges
# for the LTO partitions do not cover most of .text), which is why
# tools/scripts/symbolize_crash.sh uses gdb as its resolution engine.
# Code generation is identical; only the .debug sidecar grows — the
# shipped binary is stripped either way.
# ── Reproducible-build flags (two-builder byte identity) ──────────────────
# Behavior-identical determinism flags — no optimization or codegen change.
# The shipped node binary is stripped (`strip -s`), so its .text/.rodata/.data
# are already byte-identical across two builders in different absolute
# directories; the ONLY divergences the two-builder gate (`make repro-verify`,
# docs/SECURITY_AND_INTEGRITY.md) found were the absolute build directory baked
# into DWARF:
#   * DW_AT_comp_dir = the compile-time CWD (an absolute path) — differs per
#     builder, perturbing the split .debug sidecar and therefore the
#     .gnu_debuglink CRC32 (4 bytes) in the shipped binary, and the pre-strip
#     link content and therefore the content-derived .note.gnu.build-id sha1
#     (20 bytes).
#   * DW_AT_producer records the exact gcc switch line when GCC defaults to
#     -grecord-gcc-switches; that line contains the absolute -ffile-prefix-map
#     argument below, so it is re-canonicalized with -gno-record-gcc-switches
#     (the shipped binary is stripped, so this only trims debug metadata).
# -ffile-prefix-map remaps the absolute build root ($(CURDIR)) to a fixed
# virtual root in comp_dir and any absolute path GCC would emit. __FILE__ /
# LOG_* strings are already RELATIVE (compiled with relative source paths), so
# -fmacro-prefix-map (folded into -ffile-prefix-map) does not touch them —
# log/error text is unchanged. Source file:line crash symbolization
# (tools/scripts/symbolize_crash.sh via the .debug sidecar) is unaffected:
# DW_AT_name entries stay relative and the line program is unchanged; only the
# (already-unresolvable-post-deploy) comp_dir source-root hint moves.
ZCL_REPRO_ROOT ?= /zclassic23
REPRO_CFLAGS = -ffile-prefix-map=$(CURDIR)=$(ZCL_REPRO_ROOT) -gno-record-gcc-switches

# ── The two blanket warning suppressions, each defined exactly ONCE ───────
# Both arrived in the first commit as unexplained copy-forward defaults and
# had since been copy-pasted into seven separate compile rules, so there was
# no single place to reason about either one. Each now has one definition,
# one written reason, and a lint gate (check-no-warning-suppression) that
# rejects any new unmarked instance. A rule that needs one references the
# variable; a rule that does not, does not.
#
# -Wunused-result is ALSO the diagnostic GCC and Clang use to report
# [[nodiscard]], so this flag silently voids the repository's result-type
# discipline: a result type could be annotated and every dropped return would
# still compile clean. Deleting it is not a Makefile change — it is a source
# change at every site that drops a write/read/link/fgets/system result.
#
# The SHIPPED tree is now clean: every ALL_SRCS TU was rebuilt at -O3 with the
# suppression defeated and reported zero, with a deliberately-planted ignored
# write() confirming the scan was armed. What remains is lib/test/ alone.
# Deleting the flag means fixing those, and only then does [[nodiscard]] on
# struct zcl_result start doing anything — both ride this one diagnostic.
#
# Note GCC does NOT accept a `(void)` cast as consuming a warn_unused_result
# return, so most of those sites need a real check, not a cast. The check runs
# during gimplification, so `cc -fsyntax-only` reports NONE of them even at
# -O3 — only an optimised codegen pass finds them.
# Re-derive the current site list (never trust a count typed here):
#   sed -i 's/^ZCL_WARN_UNUSED_RESULT = .*/ZCL_WARN_UNUSED_RESULT = -Wno-error=unused-result/' Makefile
#   make build-only && make -j$(nproc) 2>&1 | grep -- '-Wunused-result]'
# suppression-ok: removing it breaks the build until the source sites above are fixed; tracked, not defaulted
ZCL_WARN_UNUSED_RESULT = -Wno-unused-result
#
# -Wstringop-overflow hides a memory-safety diagnostic class. Deleting it is
# likewise a source change, not a flag change: the sites live in
# lib/script/include/script/script.h, lib/script/include/script/op_return_push.h,
# app/controllers/src/nodelog_controller.c and one test, plus the glibc
# fortify header they induce. Note the per-TU compile is clean — these only
# appear in the whole-program LTO build, so `make build-only` alone will
# report zero and mislead you. Re-derive with the same substitution as above,
# using -Wno-error=stringop-overflow, and a FULL `make -j$(nproc)`.
# suppression-ok: separate decision from the unused-result deletion; blockers are source sites, measured, not assumed
ZCL_WARN_STRINGOP_OVERFLOW = -Wno-stringop-overflow

# ── Warning gates BEYOND -Wall -Wextra -pedantic ────────────────────────────
#
# Every flag below was measured at ZERO warnings over BOTH -Werror-bearing
# compile configurations in this tree — the 1298 node TUs at these CFLAGS, and
# all 2116 TUs again at TEST_REL_CFLAGS (-DZCL_TESTING), which also keeps
# -Werror. Adopting a flag that is already clean costs nothing today and turns
# a whole defect class into a build failure from here on.
#
# Every flag here is one GCC reports as OFF under -Wall -Wextra -pedantic
# (`cc -Wall -Wextra -pedantic -Q --help=warning`). Flags that merely restate
# what -Wall/-Wextra already enable were deliberately left out rather than
# listed for appearance: -Wpointer-arith, -Wenum-conversion, -Wenum-int-mismatch,
# -Wcast-function-type, -Wformat-security, -Wcalloc-transposed-args,
# -Wpacked-not-aligned, -Wmultistatement-macros, -Wshift-negative-value and
# -Wbidi-chars=any are ALL already on. -Wold-style-definition is a no-op in
# C23, where `f()` already means `f(void)`.
#
# Two entries raise a level rather than add a flag: -Wall gives
# -Wshift-overflow=1, and the default is -Wattribute-alias=1.
#
# MEASURE MIDDLE-END WARNINGS WITH -c, NOT -fsyntax-only. -Wimplicit-fallthrough,
# -Wunused-result, -Wnull-dereference, -Warray-bounds, -Wuse-after-free and the
# -Wstringop-* family are emitted during gimplification, which -fsyntax-only
# never reaches: a syntax-only screen reports ZERO for all of them and is not
# evidence. Every flag in the list below was re-measured with a real `-c`
# codegen pass over all 3414 TUs, not just the fast screen.
#
# -Wimplicit-fallthrough=5 was TRIED AND REJECTED, and it is the reason for the
# paragraph above: the fast screen said 0, the codegen pass said 911 warnings
# at 439 sites. Level 3 (what -Wextra gives) accepts a `/* fallthrough */`
# COMMENT; level 5 accepts only the attribute. Raising it would mean annotating
# 439 sites — and two of them are inside glibc's own
# bits/string_fortified.h, which this tree cannot edit at all, so level 5 is
# not reachable regardless of effort. Left at 3.
#
# -Walloc-zero was TRIED AND REJECTED for a subtler reason worth keeping:
# MEASURE EVERY CANDIDATE IN THE NON-LTO CONFIGURATION TOO. It reports ZERO
# across all 3414 TUs at these CFLAGS, because -flto=auto defers the inlining
# that would expose a constant 0 — but TEST_REL_CFLAGS (Makefile:995) filters
# -flto=auto OUT and keeps -Werror, and there the same flag reports 393
# warnings, i.e. it would compile the node fine and then break
# `make test-parallel`. All 393 are the same one line (the zcl_malloc wrapper
# in lib/base/include/base/safe_alloc.h:49) re-reported once per inlined
# caller, so they are one inlining artifact, not 393 defects. A flag whose
# output depends on optimizer visibility is a poor permanent -Werror gate.
#
# -Wvla + -Walloca together close stack-exhaustion-by-runtime-length. The six
# production VLAs (domain/encoding/src/{base58,bech32}.c) were already bounded
# by a constant, so they became fixed arrays plus an explicit bounds check;
# a VLA turns a weakened length check into stack exhaustion, a fixed array
# turns it into a failed call.
#
# To re-derive (never trust a count typed here) — drop a flag from this list,
# then compile every TU in $(ALL_SRCS) and $(TEST_SRCS) with `-fsyntax-only`
# at these flags minus -Werror, once plain and once with -DZCL_TESTING.
# Confirm the rig is armed before believing a zero: a deliberately bogus
# -Wnot-a-real-flag must report one error per TU.
ZCL_WARN_EXTRA_GATES = \
	-Wundef -Wstrict-prototypes -Wdouble-promotion \
	-Wduplicated-cond -Wduplicated-branches \
	-Wshift-overflow=2 -Wattribute-alias=2 \
	-Walloca -Wvla -Wtrampolines \
	-Wflex-array-member-not-at-end

CFLAGS = -std=c23 -g -O3 $(if $(ZCL_NATIVE),-march=native,-march=x86-64-v3) -flto=auto -Wall -Wextra -Werror -pedantic \
	$(REPRO_CFLAGS) \
	$(HARDEN_CFLAGS) \
	$(ZCL_WARN_EXTRA_GATES) \
	$(ZCL_WARN_STRINGOP_OVERFLOW) $(ZCL_WARN_UNUSED_RESULT) \
	$(APP_INCLUDES) $(CONFIG_INCLUDES) $(LIB_INCLUDES) $(CORE_INCLUDES) $(PORTS_INCLUDES) $(DOMAIN_INCLUDES) $(APPLICATION_INCLUDES) $(ADAPTERS_INCLUDES) $(TOOLS_INCLUDES) $(DEVLOOP_INCLUDES) \
	-Ilib/test/include \
	-D_POSIX_C_SOURCE=200809L -DZCL_AR_ENFORCE $(BUILD_IDENTITY_CPPFLAGS) -Ivendor/include -Ivendor/x11/include $(GTK_DEF) $(GTK_CFLAGS) \
	$(WEBKIT_DEF) $(WEBKIT_CFLAGS)
LDFLAGS = -pthread -flto=auto -rdynamic $(HARDEN_LDFLAGS)
CACHED_CFLAGS = $(filter-out -DZCL_BUILD_SOURCE_ID=% -DZCL_BUILD_CLEAN=%,$(CFLAGS))
BUILD_ONLY_CFLAGS = $(CACHED_CFLAGS) -Wno-deprecated-declarations
ZCL_DEV_OPT ?= -Og
ZCL_DEV_HOT_OPT ?= -O2
ZCL_DEV_LINKER ?= $(shell tools/dev/dev-linker-select.sh)
DEV_CFLAGS = $(filter-out -O3 -flto=auto -Werror,$(CACHED_CFLAGS)) $(ZCL_DEV_OPT) -g3 -DZCL_DEV_BUILD \
	-Wno-deprecated-declarations -Wno-format-truncation -Wno-maybe-uninitialized
DEV_HOT_CFLAGS = $(filter-out $(ZCL_DEV_OPT),$(DEV_CFLAGS)) $(ZCL_DEV_HOT_OPT)
DEV_LDFLAGS = $(filter-out -flto=auto,$(LDFLAGS)) $(ZCL_DEV_LINKER)

# Explicit save-to-release profiles.  Live modules, incremental restarts, and
# static integration are non-LTO by contract; only RELEASE retains the
# production whole-program optimizer.  check-dev-loop-profiles inspects the
# expanded values and the recipes that consume them.
DEV_LIVE_CFLAGS := $(DEV_CFLAGS)
DEV_RESTART_CFLAGS := $(DEV_CFLAGS)
DEV_RESTART_LDFLAGS := $(DEV_LDFLAGS)
RELEASE_CFLAGS := $(CFLAGS)
RELEASE_LDFLAGS := $(LDFLAGS)

# Sanitizer flags shared by the two opt-in ASan/UBSan profiles (t-asan,
# dev-asan). -fsanitize must appear at both compile and link time. These
# flags are referenced ONLY by the ASan profiles below — they are never
# appended to CFLAGS/CACHED_CFLAGS/LDFLAGS, so they cannot leak into the
# release/dev/test default builds (each profile's epoch key also binds its
# exact flag set, making any leak a fresh, separate object tree).
# -fno-sanitize=alignment mirrors the fuzz harnesses' established UBSan
# profile (FUZZ_CFLAGS below): the serialization/crypto paths perform
# deliberate unaligned loads that the fuzz lane already found too noisy to
# keep the UBSan signal usable. An alignment-specific audit is a follow-up.
override ASAN_COMMON_SAN_FLAGS := -fsanitize=address,undefined -fno-omit-frame-pointer \
	-fno-sanitize=alignment
# The shared Montgomery inline assembly needs one additional general-purpose
# register when the compiler reserves a frame pointer.  Keep this exception
# closed over the two translation units that instantiate it; ASan+UBSan remain
# enabled because these flags are appended to the full sanitizer profile.
# check-no-adx-overclaim validates the exact allowlist, both object rules, and
# the compile-epoch bindings below (including a mutation self-test).
override ASAN_ADX_FRAME_POINTER_EXCEPTION_SRCS := \
	lib/sapling/src/bn254_accel.c \
	lib/sapling/src/fr_avx512.c
override ASAN_ADX_FRAME_POINTER_EXCEPTION_FLAGS := -fomit-frame-pointer
# dev-asan: the dev node profile (-Og, -g3, -DZCL_DEV_BUILD, non-LTO, dev
# linker) plus ASan+UBSan. Uniform optimization for every TU — no DEV_HOT
# split — because sanitizer signal fidelity matters more here than
# optimizer-sensitivity coverage.
DEV_ASAN_CFLAGS = $(filter-out -O3 -flto=auto -Werror,$(CACHED_CFLAGS)) $(ZCL_DEV_OPT) -g3 -DZCL_DEV_BUILD \
	$(ASAN_COMMON_SAN_FLAGS) \
	-Wno-deprecated-declarations -Wno-format-truncation -Wno-maybe-uninitialized
DEV_ASAN_LDFLAGS = $(filter-out -flto=auto,$(LDFLAGS)) $(ZCL_DEV_LINKER) $(ASAN_COMMON_SAN_FLAGS)

# Sanitizer flags shared by the two opt-in TSan profiles (t-tsan, dev-tsan).
# Same containment posture as ASAN_COMMON_SAN_FLAGS: referenced ONLY by the
# TSan profiles below, never appended to CFLAGS/CACHED_CFLAGS/LDFLAGS, so the
# thread instrumentation cannot leak into the release/dev/test default builds.
# -fsanitize=thread is mutually exclusive with address/undefined (gcc rejects
# the combination), so this is a sibling flag set, not an extension of the
# ASan one. -fno-omit-frame-pointer keeps race stacks attributable.
TSAN_COMMON_SAN_FLAGS = -fsanitize=thread -fno-omit-frame-pointer
# dev-tsan: the dev node profile (-Og, -g3, -DZCL_DEV_BUILD, non-LTO, dev
# linker) plus TSan. LTO stays off — mirrors every instrumented profile here,
# and is a deliberate correctness call for TSan: race reports need precise
# per-TU PCs and stacks, whole-program LTO inlining degrades exactly that
# attribution, and -fsanitize=thread under -flto=auto is a far less-traveled
# gcc path than the strict harness's own established non-LTO posture.
DEV_TSAN_CFLAGS = $(filter-out -O3 -flto=auto -Werror,$(CACHED_CFLAGS)) $(ZCL_DEV_OPT) -g3 -DZCL_DEV_BUILD \
	$(TSAN_COMMON_SAN_FLAGS) \
	-Wno-deprecated-declarations -Wno-format-truncation -Wno-maybe-uninitialized
DEV_TSAN_LDFLAGS = $(filter-out -flto=auto,$(LDFLAGS)) $(ZCL_DEV_LINKER) $(TSAN_COMMON_SAN_FLAGS)

# Use vendor/tor/libtor.a when Tor is built from source.
# Tor: use full Tor if built, otherwise fall back to stub.
TOR_FULL = $(wildcard vendor/tor/libtor.a \
	vendor/tor/src/ext/ed25519/donna/libed25519_donna.a \
	vendor/tor/src/ext/ed25519/ref10/libed25519_ref10.a \
	vendor/tor/src/ext/keccak-tiny/libkeccak-tiny.a)
TOR_LIBS = $(if $(TOR_FULL),$(TOR_FULL),-Lvendor/lib -ltor_stub)
# All dependencies bundled in vendor/lib as static archives.
# Zero system library requirements beyond libc.
# OpenSSL 3.0 (Apache 2.0), libevent and zlib are vendored and statically
# linked. Wallet proving and consensus verification remain C23 in every build.
# LevelDB is a C++ archive behind a C API. Link with cc for release LTO
# consistency, but add the C++ driver's stdlib search directory so hosts whose
# cc/c++ packages are split still find libstdc++.
ifeq ($(BUILD_EPOCH_CLEAN_ONLY),1)
CXX_STDLIB_FILE :=
else
CXX_STDLIB_FILE := $(shell $(CXX) -print-file-name=libstdc++.a 2>/dev/null)
endif
CXX_STDLIB_DIR := $(if $(filter /%,$(CXX_STDLIB_FILE)),$(dir $(CXX_STDLIB_FILE)),)
CXX_STDLIB_LDFLAGS := $(if $(CXX_STDLIB_DIR),-L$(CXX_STDLIB_DIR),)
LIBS = -Lvendor/lib -lsecp256k1 -lleveldb \
	$(CXX_STDLIB_LDFLAGS) -lstdc++ -lsqlite3 \
	-levent -levent_openssl -levent_pthreads \
	-lssl -lcrypto -lz -ldl -lpthread -lm

# The shipped node is a C23 artifact. It never links the optional GTK/WebKit
# presentation stack, the C++ LevelDB oracle, or libstdc++. Legacy LevelDB
# bootstrap reads use the in-tree C23
# reader; every other third-party input is an exact pinned static archive.
NODE_C23_CFLAGS = $(CFLAGS) -DZCL_C23_NODE -UHAVE_GTK -UHAVE_WEBKIT
NODE_C23_TOR_LIBS = $(if $(TOR_FULL),$(TOR_FULL),vendor/lib/libtor_stub.a)
NODE_C23_LIBS = vendor/lib/libsecp256k1.a vendor/lib/libsqlite3.a \
	vendor/lib/libevent.a vendor/lib/libevent_openssl.a \
	vendor/lib/libevent_pthreads.a vendor/lib/libssl.a \
	vendor/lib/libcrypto.a vendor/lib/libz.a -ldl -lpthread -lm

# ── Host-local compile epochs ─────────────────────────────────────────────
# Source bytes remain the portable authority, but they no longer select the
# object namespace. The epoch key binds ONLY inputs that change object bytes
# without changing a tracked TU: compiler/tool/search-root fingerprint,
# profile name, effective compile flags, effective link inputs, and
# BUILD_SYSTEM_ID (the root Makefile — which holds every flag variable and
# per-object/per-pattern override — plus the four epoch driver scripts,
# hashed by `build-epoch-key.sh build-system-id`). A source edit therefore
# recompiles exactly the TUs that make's timestamp+depfile graph marks stale
# inside the STABLE epoch; a flags/Makefile/toolchain edit re-keys every
# epoch and forces a full rebuild. Source freshness of the shipped identity
# is unchanged: BUILD_IDENTITY_STAMP (above) rebuilds clientversion.o and
# relinks every binary on any source-identity move, and every publish path
# re-verifies the exact source record after compiling.
BUILD_EPOCH_KEY_TOOL = tools/dev/build-epoch-key.sh
BUILD_EPOCH_OBJECT_TOOL = tools/dev/compile-epoch-object.sh
BUILD_EPOCH_PUBLISH_TOOL = tools/dev/publish-build-alias.sh
BUILD_EPOCH_SESSION_TOOL = tools/dev/build-epoch-session.sh
BUILD_EPOCH_KEEP ?= 3

# Checkout-wide counterpart to the per-profile epoch-GC lock above: the
# per-profile lock only keeps two writers of the SAME object root from
# colliding, not the dev-watch loop's `make ff` (dev profile) from running
# at the same instant as a foreground `make test-parallel`/`make test`
# (test-rel profile) — both drive test_make_lint_gates/
# test_consensus_state_snapshot_install through fixed fixture paths, so two
# concurrent test_parallel processes racing those paths is a real
# false-failure source. ZCL_DEV_WATCH_LANE=1 (set only by
# tools/dev/watch-dev-lane.sh) selects the non-blocking, defer-on-contention
# side; every other caller blocks. See tools/dev/checkout-lock.sh.
CHECKOUT_LOCK_TOOL = tools/dev/checkout-lock.sh
CHECKOUT_LOCK = $(BUILD_DIR)/.checkout.lock
CHECKOUT_LOCK_MODE = $(if $(filter 1,$(ZCL_DEV_WATCH_LANE)),watcher,foreground)
CHECKOUT_LOCKED_TEST_GOALS := test-parallel-active-locked \
	test-parallel-fast-active-locked test-parallel-locked t-locked \
	t-fast-locked t-fast-exact-locked test-locked \
	secure-release-regressions-locked
ifneq ($(filter $(CHECKOUT_LOCKED_TEST_GOALS),$(MAKECMDGOALS)),)
ifneq ($(ZCL_CHECKOUT_LOCK_HELD),1)
$(error internal locked test goal requires the checkout lock; invoke its public target)
endif
endif
BUILD_EPOCH_OBJECT_FORCE = $(if $(ZCL_COMPDB_FORCE),FORCE,)
ifeq ($(strip $(ZCL_EPOCH_PROFILES)),)
BUILD_COMPILER_ID := $(ZCL_ZERO_SHA256)
BUILD_SYSTEM_ID := $(ZCL_ZERO_SHA256)
else
BUILD_COMPILER_ID := $(strip $(shell $(BUILD_EPOCH_KEY_TOOL) compiler-id "$(CC)" "$(CXX)" 2>/dev/null))
BUILD_COMPILER_ID_VALID := $(shell printf '%s\n' '$(BUILD_COMPILER_ID)' | awk '$$0 ~ /^[0-9a-f]{64}$$/ { print "yes" }')
ifneq ($(BUILD_COMPILER_ID_VALID),yes)
$(error compiler/toolchain fingerprint failed; refusing to select a compile epoch)
endif
# Fingerprint of every build-system input that changes compile/link semantics
# without changing a tracked TU (this Makefile's flag variables and per-object
# overrides, plus the epoch driver scripts). This is what keeps a Makefile
# CFLAGS edit — which touches no source file — busting every epoch now that
# the source identity no longer does.
BUILD_SYSTEM_ID := $(strip $(shell $(BUILD_EPOCH_KEY_TOOL) build-system-id 2>/dev/null))
BUILD_SYSTEM_ID_VALID := $(shell printf '%s\n' '$(BUILD_SYSTEM_ID)' | awk '$$0 ~ /^[0-9a-f]{64}$$/ { print "yes" }')
ifneq ($(BUILD_SYSTEM_ID_VALID),yes)
$(error build-system fingerprint failed; refusing to select a compile epoch)
endif
endif

# $(1) profile name, $(2) NAME of the profile's *_EPOCH_COMPILE_FLAGS variable,
# $(3) NAME of its *_EPOCH_LINK_FLAGS variable. Source identity is deliberately
# NOT an input: see the epoch-section comment above.
define zcl_compile_epoch
$(strip $(shell $(BUILD_EPOCH_KEY_TOOL) key "$(BUILD_COMPILER_ID)" "$(1)" "$(strip $($(2)))" "$(strip $($(3)))" "$(BUILD_SYSTEM_ID)" 2>/dev/null))
endef

BUILD_ONLY_EPOCH_COMPILE_FLAGS := $(strip $(BUILD_ONLY_CFLAGS) deps=-MD,-MP)
BUILD_ONLY_EPOCH_LINK_FLAGS := no-link
DEV_EPOCH_COMPILE_FLAGS := $(strip normal=$(DEV_CFLAGS) hot=$(DEV_HOT_CFLAGS) deps=-MD,-MP)
DEV_EPOCH_LINK_FLAGS := $(strip $(DEV_LDFLAGS) $(TOR_LIBS) $(LIBS) $(GTK_LIBS) $(WEBKIT_LIBS) cxx=$(CXX))

ifneq ($(filter build-only,$(ZCL_EPOCH_PROFILES)),)
BUILD_ONLY_COMPILE_EPOCH := $(call zcl_compile_epoch,build-only-v2,BUILD_ONLY_EPOCH_COMPILE_FLAGS,BUILD_ONLY_EPOCH_LINK_FLAGS)
BUILD_ONLY_COMPILE_EPOCH_VALID := $(shell printf '%s\n' '$(BUILD_ONLY_COMPILE_EPOCH)' | awk '$$0 ~ /^[0-9a-f]{64}$$/ { print "yes" }')
ifneq ($(BUILD_ONLY_COMPILE_EPOCH_VALID),yes)
$(error build-only compile-epoch derivation failed)
endif
else
BUILD_ONLY_COMPILE_EPOCH := $(ZCL_ZERO_SHA256)
endif
ifneq ($(filter dev,$(ZCL_EPOCH_PROFILES)),)
DEV_COMPILE_EPOCH := $(call zcl_compile_epoch,dev-v2,DEV_EPOCH_COMPILE_FLAGS,DEV_EPOCH_LINK_FLAGS)
DEV_COMPILE_EPOCH_VALID := $(shell printf '%s\n' '$(DEV_COMPILE_EPOCH)' | awk '$$0 ~ /^[0-9a-f]{64}$$/ { print "yes" }')
ifneq ($(DEV_COMPILE_EPOCH_VALID),yes)
$(error dev compile-epoch derivation failed)
endif
else
DEV_COMPILE_EPOCH := $(ZCL_ZERO_SHA256)
endif

DEV_CANDIDATE_BIN = $(BIN_DIR)/dev/epochs/$(DEV_COMPILE_EPOCH)/zclassic23-dev
DEV_ACTIVE_BIN = $(DEV_CANDIDATE_BIN)

# dev-asan: epoch-keyed ASan/UBSan dev node (build/bin/zclassic23-dev-asan).
# Own object root (build/dev-asan-obj) and own candidate dir, mirroring the
# coverage profile's self-contained derivation; the shared *_EPOCHS_VALID
# asserts above stay untouched.
DEV_ASAN_EPOCH_COMPILE_FLAGS := $(strip $(DEV_ASAN_CFLAGS) \
	adx-exception=$(ASAN_ADX_FRAME_POINTER_EXCEPTION_SRCS):$(ASAN_ADX_FRAME_POINTER_EXCEPTION_FLAGS) \
	deps=-MD,-MP)
DEV_ASAN_EPOCH_LINK_FLAGS := $(strip $(DEV_ASAN_LDFLAGS) $(TOR_LIBS) $(LIBS) $(GTK_LIBS) $(WEBKIT_LIBS) cxx=$(CXX))
ifneq ($(filter dev-asan,$(ZCL_EPOCH_PROFILES)),)
DEV_ASAN_COMPILE_EPOCH := $(call zcl_compile_epoch,dev-asan-v2,DEV_ASAN_EPOCH_COMPILE_FLAGS,DEV_ASAN_EPOCH_LINK_FLAGS)
DEV_ASAN_COMPILE_EPOCH_VALID := $(shell printf '%s\n' '$(DEV_ASAN_COMPILE_EPOCH)' | awk '$$0 ~ /^[0-9a-f]{64}$$/ { print "yes" }')
ifneq ($(DEV_ASAN_COMPILE_EPOCH_VALID),yes)
$(error dev-asan compile-epoch derivation failed)
endif
else
DEV_ASAN_COMPILE_EPOCH := $(ZCL_ZERO_SHA256)
endif
DEV_ASAN_OBJ_ROOT = $(BUILD_DIR)/dev-asan-obj
DEV_ASAN_OBJ_DIR = $(DEV_ASAN_OBJ_ROOT)/epochs/$(DEV_ASAN_COMPILE_EPOCH)
DEV_ASAN_OBJS = $(patsubst %.c,$(DEV_ASAN_OBJ_DIR)/%.o,$(DEV_SRCS))
DEV_ASAN_LINK_RSP = $(DEV_ASAN_OBJ_DIR)/link-inputs.rsp
DEV_ASAN_CANDIDATE_BIN = $(BIN_DIR)/dev-asan/epochs/$(DEV_ASAN_COMPILE_EPOCH)/zclassic23-dev-asan
DEV_ASAN_BIN = $(BIN_DIR)/z23-dev-asan
DEV_ASAN_BIN_ALIAS = $(BIN_DIR)/zclassic23-dev-asan
DEV_ASAN_PROFILE = dev-asan-v2
DEV_ASAN_SESSION = $(DEV_ASAN_OBJ_DIR)/.build-session
DEV_ASAN_LEASE = $(DEV_ASAN_OBJ_DIR)/.leases/$(BUILD_INVOCATION_ID)

# dev-tsan: epoch-keyed TSan dev node (build/bin/zclassic23-dev-tsan).
# Own object root (build/dev-tsan-obj) and own candidate dir, mirroring the
# dev-asan derivation; the shared *_EPOCHS_VALID asserts above stay untouched.
DEV_TSAN_EPOCH_COMPILE_FLAGS := $(strip $(DEV_TSAN_CFLAGS) deps=-MD,-MP)
DEV_TSAN_EPOCH_LINK_FLAGS := $(strip $(DEV_TSAN_LDFLAGS) $(TOR_LIBS) $(LIBS) $(GTK_LIBS) $(WEBKIT_LIBS) cxx=$(CXX))
ifneq ($(filter dev-tsan,$(ZCL_EPOCH_PROFILES)),)
DEV_TSAN_COMPILE_EPOCH := $(call zcl_compile_epoch,dev-tsan-v2,DEV_TSAN_EPOCH_COMPILE_FLAGS,DEV_TSAN_EPOCH_LINK_FLAGS)
DEV_TSAN_COMPILE_EPOCH_VALID := $(shell printf '%s\n' '$(DEV_TSAN_COMPILE_EPOCH)' | awk '$$0 ~ /^[0-9a-f]{64}$$/ { print "yes" }')
ifneq ($(DEV_TSAN_COMPILE_EPOCH_VALID),yes)
$(error dev-tsan compile-epoch derivation failed)
endif
else
DEV_TSAN_COMPILE_EPOCH := $(ZCL_ZERO_SHA256)
endif
DEV_TSAN_OBJ_ROOT = $(BUILD_DIR)/dev-tsan-obj
DEV_TSAN_OBJ_DIR = $(DEV_TSAN_OBJ_ROOT)/epochs/$(DEV_TSAN_COMPILE_EPOCH)
DEV_TSAN_OBJS = $(patsubst %.c,$(DEV_TSAN_OBJ_DIR)/%.o,$(DEV_SRCS))
DEV_TSAN_LINK_RSP = $(DEV_TSAN_OBJ_DIR)/link-inputs.rsp
DEV_TSAN_CANDIDATE_BIN = $(BIN_DIR)/dev-tsan/epochs/$(DEV_TSAN_COMPILE_EPOCH)/zclassic23-dev-tsan
DEV_TSAN_BIN = $(BIN_DIR)/z23-dev-tsan
DEV_TSAN_BIN_ALIAS = $(BIN_DIR)/zclassic23-dev-tsan
DEV_TSAN_PROFILE = dev-tsan-v2
DEV_TSAN_SESSION = $(DEV_TSAN_OBJ_DIR)/.build-session
DEV_TSAN_LEASE = $(DEV_TSAN_OBJ_DIR)/.leases/$(BUILD_INVOCATION_ID)
# BUILD_INVOCATION_PID/START/ID moved up next to BUILD_EPOCH_CLEAN_ONLY (near
# BUILD_SOURCE_RECORD above) so ZCL_SOURCE_IDENTITY_SESSION exists before the
# first source-identity.sh call in this parse.

BUILD_ONLY_PROFILE = build-only-v2
DEV_PROFILE = dev-v2
BUILD_ONLY_SESSION = $(OBJ_DIR)/.build-session
DEV_SESSION = $(DEV_OBJ_DIR)/.build-session
BUILD_ONLY_LEASE = $(OBJ_DIR)/.leases/$(BUILD_INVOCATION_ID)
DEV_LEASE = $(DEV_OBJ_DIR)/.leases/$(BUILD_INVOCATION_ID)

$(BUILD_ONLY_LEASE): FORCE
	@$(BUILD_EPOCH_SESSION_TOOL) acquire "$(BUILD_ONLY_SESSION)" "$@" \
	  "$(OBJ_ROOT)" - "$(BUILD_EPOCH_KEEP)" "$(BUILD_SOURCE_ID)" \
	  "$(BUILD_CLEAN)" "$(BUILD_MUTATION)" "$(BUILD_COMPILER_ID)" \
	  "$(BUILD_ONLY_COMPILE_EPOCH)" "$(BUILD_ONLY_PROFILE)" \
	  "$(BUILD_ONLY_EPOCH_COMPILE_FLAGS)" "$(BUILD_ONLY_EPOCH_LINK_FLAGS)" \
	  "$(CC)" "$(CXX)" "$$PPID"

$(DEV_LEASE): FORCE
	@$(BUILD_EPOCH_SESSION_TOOL) acquire "$(DEV_SESSION)" "$@" \
	  "$(DEV_OBJ_ROOT)" "$(BIN_DIR)/dev" "$(BUILD_EPOCH_KEEP)" \
	  "$(BUILD_SOURCE_ID)" "$(BUILD_CLEAN)" "$(BUILD_MUTATION)" \
	  "$(BUILD_COMPILER_ID)" "$(DEV_COMPILE_EPOCH)" "$(DEV_PROFILE)" \
	  "$(DEV_EPOCH_COMPILE_FLAGS)" "$(DEV_EPOCH_LINK_FLAGS)" \
	  "$(CC)" "$(CXX)" "$$PPID"

$(DEV_ASAN_LEASE): FORCE
	@$(BUILD_EPOCH_SESSION_TOOL) acquire "$(DEV_ASAN_SESSION)" "$@" \
	  "$(DEV_ASAN_OBJ_ROOT)" "$(BIN_DIR)/dev-asan" "$(BUILD_EPOCH_KEEP)" \
	  "$(BUILD_SOURCE_ID)" "$(BUILD_CLEAN)" "$(BUILD_MUTATION)" \
	  "$(BUILD_COMPILER_ID)" "$(DEV_ASAN_COMPILE_EPOCH)" "$(DEV_ASAN_PROFILE)" \
	  "$(DEV_ASAN_EPOCH_COMPILE_FLAGS)" "$(DEV_ASAN_EPOCH_LINK_FLAGS)" \
	  "$(CC)" "$(CXX)" "$$PPID"

$(DEV_TSAN_LEASE): FORCE
	@$(BUILD_EPOCH_SESSION_TOOL) acquire "$(DEV_TSAN_SESSION)" "$@" \
	  "$(DEV_TSAN_OBJ_ROOT)" "$(BIN_DIR)/dev-tsan" "$(BUILD_EPOCH_KEEP)" \
	  "$(BUILD_SOURCE_ID)" "$(BUILD_CLEAN)" "$(BUILD_MUTATION)" \
	  "$(BUILD_COMPILER_ID)" "$(DEV_TSAN_COMPILE_EPOCH)" "$(DEV_TSAN_PROFILE)" \
	  "$(DEV_TSAN_EPOCH_COMPILE_FLAGS)" "$(DEV_TSAN_EPOCH_LINK_FLAGS)" \
	  "$(CC)" "$(CXX)" "$$PPID"

# Make normally imports four large immutable depfile graphs even when one
# profile (or no compiler at all) is requested.  Narrow only an exact,
# explicitly-known single goal.  Empty/default, mixed, and unknown goals keep
# the conservative source-wide fallback so a new target cannot accidentally
# lose header invalidation merely because this table was not updated.
ZCL_DEPFILE_ALL_PROFILES := build-only dev test-fast test-strict coverage fuzz
ZCL_DEPFILE_PROFILES := $(ZCL_DEPFILE_ALL_PROFILES)
ifeq ($(ZCL_HOTSWAP_DEPFILE_LEAN_ONLY),1)
# The hot-swap loop recipes (plus hotswap-module-so's own single-TU shell
# compile) build no objects through make's %.o pattern rules; the fast path
# tracks its own single-TU depfile. Skip every depfile graph — an unmatched
# single goal below would otherwise fall through to importing all four.
ZCL_DEPFILE_PROFILES :=
else ifeq ($(words $(MAKECMDGOALS)),1)
ZCL_DEPFILE_SINGLE_GOAL := $(firstword $(MAKECMDGOALS))
ifneq ($(filter build-only,$(ZCL_DEPFILE_SINGLE_GOAL)),)
ZCL_DEPFILE_PROFILES := build-only
else ifneq ($(filter fast-compile dev-build-only,$(ZCL_DEPFILE_SINGLE_GOAL)),)
ZCL_DEPFILE_PROFILES := dev
else ifneq ($(filter dev-bin z23-dev zclassic23-dev,$(ZCL_DEPFILE_SINGLE_GOAL)),)
ZCL_DEPFILE_PROFILES := dev test-fast
else ifneq ($(filter t-fast t-fast-exact test_parallel_fast test-parallel-fast-active test-parallel-fast-active-locked t-fast-locked t-fast-exact-locked,$(ZCL_DEPFILE_SINGLE_GOAL)),)
ZCL_DEPFILE_PROFILES := test-fast
else ifneq ($(filter t test test_parallel test-parallel test-parallel-active test-parallel-active-locked test-parallel-locked t-locked test-locked secure-release-regressions secure-release-regressions-locked,$(ZCL_DEPFILE_SINGLE_GOAL)),)
ZCL_DEPFILE_PROFILES := test-strict
else ifneq ($(filter t-asan test-asan asan-ci,$(ZCL_DEPFILE_SINGLE_GOAL)),)
ZCL_DEPFILE_PROFILES := test-asan
else ifneq ($(filter dev-asan z23-dev-asan zclassic23-dev-asan,$(ZCL_DEPFILE_SINGLE_GOAL)),)
ZCL_DEPFILE_PROFILES := dev-asan
else ifneq ($(filter t-tsan test-tsan tsan-ci,$(ZCL_DEPFILE_SINGLE_GOAL)),)
ZCL_DEPFILE_PROFILES := test-tsan
else ifneq ($(filter dev-tsan z23-dev-tsan zclassic23-dev-tsan,$(ZCL_DEPFILE_SINGLE_GOAL)),)
ZCL_DEPFILE_PROFILES := dev-tsan
else ifneq ($(filter coverage coverage-locked,$(ZCL_DEPFILE_SINGLE_GOAL)),)
ZCL_DEPFILE_PROFILES := coverage
else ifneq ($(filter fuzz fuzz-ci fuzz-ci-leaks fuzz-replay fuzz_block fuzz_script fuzz_p2p fuzz_http fuzz_compactblock fuzz_snapshot fuzz_tx_bundle fuzz_rom_manifest fuzz_overlay fuzz_ecdsa,$(ZCL_DEPFILE_SINGLE_GOAL)),)
ZCL_DEPFILE_PROFILES := fuzz
else ifneq ($(filter lint lint-fast watcher-safety-gates dev-failure-execution-id ff t-changed fast-changed-compile fast-rebuild rebuild-fast dev-rebuild hot-rebuild super-rebuild fast-ci agent-fast-ci dev-ci agent-plan agent-loop agent-dev-loop pre-push-ci,$(ZCL_DEPFILE_SINGLE_GOAL)),)
ZCL_DEPFILE_PROFILES :=
endif
endif

# Header dependencies use -MD (including system headers) and live inside their
# exact epoch. There is no mutable "current object directory" symlink.
ifneq ($(filter build-only,$(ZCL_DEPFILE_PROFILES)),)
-include $(ALL_OBJS:.o=.d)
endif
ifneq ($(filter dev,$(ZCL_DEPFILE_PROFILES)),)
-include $(DEV_OBJS:.o=.d)
endif
ifneq ($(filter dev-asan,$(ZCL_DEPFILE_PROFILES)),)
-include $(DEV_ASAN_OBJS:.o=.d)
endif
ifneq ($(filter dev-tsan,$(ZCL_DEPFILE_PROFILES)),)
-include $(DEV_TSAN_OBJS:.o=.d)
endif

# Vendored static archives the final link needs.  Only libsecp256k1.a is
# committed to git; `make vendor` builds the rest from source (pinned URL +
# SHA256), so `git clone && make zclassic23` links in one shot.  See
# docs/BUILD.md and tools/scripts/build_vendor.sh.
.PHONY: vendor vendor-force vendor-provenance vendor-ready tor-full check-vendor-provenance
# Build every missing OR provenance-stale vendor/lib/*.a from its pinned,
# SHA256-verified source. `make vendor-force` rebuilds all of them.
vendor:
	tools/scripts/build_vendor.sh
vendor-force:
	VENDOR_FORCE=1 tools/scripts/build_vendor.sh
vendor-provenance:
	@tools/scripts/build_vendor.sh --check-provenance
# Link/release/deploy front door: repair stale archives, then independently
# audit installed bytes before any binary can consume them.
vendor-ready:
	@tools/scripts/build_vendor.sh
	@tools/dep_audit.sh

# Explicit opt-in for the real embedded onion service. This initializes the
# pinned submodule, disables optional host-library integrations that the
# self-contained outer link does not consume, and produces every static archive
# TOR_FULL needs. The default vendor path remains the offline-friendly stub.
tor-full:
	@tools/scripts/build_tor_full.sh

# Included only on the first parse when inputs are missing or a requested
# front door can repair them. Remaking an included makefile forces GNU Make to
# restart parsing; the second parse captures the final linked archive bytes.
# The session-cache drop runs FIRST: the pre-restart parse already memoized a
# capture keyed by this Make process's identity-session token, and without the
# drop the post-restart parse would cache-hit that cold record instead of
# re-deriving the identity from the archives vendor-ready just established.
$(VENDOR_BOOTSTRAP_MK): vendor-ready
	@set -eu; \
	mkdir -p "$(dir $@)"; \
	ZCL_SOURCE_IDENTITY_SESSION='$(ZCL_SOURCE_IDENTITY_SESSION)' tools/dev/source-identity.sh session-cache-drop; \
	tmp="$$(mktemp "$(dir $@).vendor-ready.XXXXXX")"; \
	trap 'rm -f "$$tmp"' EXIT HUP INT TERM; \
	printf '%s\n' '# generated: vendor inputs established before source identity capture' > "$$tmp"; \
	mv -f -- "$$tmp" "$@"; \
	trap - EXIT HUP INT TERM
check-vendor-provenance:
	@tools/scripts/test_vendor_provenance.sh
	@tools/scripts/build_vendor_offline_selftest.sh
	@tools/scripts/repro_network_policy_selftest.sh
	@sha256sum --check vendor/rgfw/SHA256SUMS
	@sha256sum --check vendor/qrcodegen/SHA256SUMS
	@sha256sum --check vendor/typography/SHA256SUMS
	@sha256sum --check vendor/x11/SHA256SUMS

# Reusable native presentation package. This deliberately has a tiny source
# closure: twelve project TUs plus pinned RGFW headers, with no node/app objects.
PRESENTATION_BUILD_DIR := build/presentation
PRESENTATION_PACKAGE_CFLAGS := -std=c23 -O2 -Wall -Wextra -Werror -pedantic \
	-Ilib/presentation/include -Ilib/base/include -Ivendor/x11/include
PRESENTATION_PACKAGE_SRCS := \
	lib/presentation/src/presentation.c \
	lib/presentation/src/presentation_canvas_model.c \
	lib/presentation/src/presentation_canvas_select.c \
	lib/presentation/src/presentation_focus.c \
	lib/presentation/src/presentation_form.c \
	lib/presentation/src/presentation_form_model.c \
	lib/presentation/src/presentation_input.c \
	lib/presentation/src/canvas.c \
	lib/presentation/src/model.c \
	lib/presentation/src/model_text.c \
	lib/presentation/src/model_render.c \
	lib/presentation/src/zclassic_brand.c
PRESENTATION_PACKAGE_OBJS := \
	$(PRESENTATION_BUILD_DIR)/presentation.o \
	$(PRESENTATION_BUILD_DIR)/presentation_canvas_model.o \
	$(PRESENTATION_BUILD_DIR)/presentation_canvas_select.o \
	$(PRESENTATION_BUILD_DIR)/presentation_focus.o \
	$(PRESENTATION_BUILD_DIR)/presentation_form.o \
	$(PRESENTATION_BUILD_DIR)/presentation_form_model.o \
	$(PRESENTATION_BUILD_DIR)/presentation_input.o \
	$(PRESENTATION_BUILD_DIR)/canvas.o \
	$(PRESENTATION_BUILD_DIR)/model.o \
	$(PRESENTATION_BUILD_DIR)/model_text.o \
	$(PRESENTATION_BUILD_DIR)/model_render.o \
	$(PRESENTATION_BUILD_DIR)/zclassic_brand.o
PRESENTATION_PACKAGE_ARCHIVE := build/lib/libzclpresentation.a
PRESENTATION_DEMO_BIN := $(PRESENTATION_BUILD_DIR)/bitmap-demo
PRESENTATION_PROVENANCE_STAMP := \
	$(PRESENTATION_BUILD_DIR)/.vendor-provenance.ok
PRESENTATION_VENDOR_INPUTS := \
	vendor/rgfw/RGFW.h vendor/rgfw/XDL.h vendor/rgfw/LICENSE \
	vendor/rgfw/SOURCE vendor/rgfw/SHA256SUMS \
	vendor/qrcodegen/qrcodegen.c vendor/qrcodegen/qrcodegen.h \
	vendor/qrcodegen/LICENSE vendor/qrcodegen/SOURCE \
	vendor/qrcodegen/SHA256SUMS \
	vendor/typography/stb_truetype.h \
	vendor/typography/noto_sans_ascii.inc \
	vendor/typography/LICENSE.stb vendor/typography/LICENSE.noto \
	vendor/typography/SOURCE vendor/typography/SHA256SUMS \
	vendor/x11/LICENSE vendor/x11/SOURCE vendor/x11/SHA256SUMS \
	$(wildcard vendor/x11/include/X11/*.h) \
	$(wildcard vendor/x11/include/X11/extensions/*.h) \
	tools/scripts/test_vendor_provenance.sh
PRESENTATION_HOST_OS := $(shell uname -s 2>/dev/null)
ifeq ($(PRESENTATION_HOST_OS),Darwin)
PRESENTATION_HOST_LIBS := -framework Cocoa -framework CoreGraphics \
	-framework QuartzCore -framework CoreVideo
else ifneq ($(filter MINGW% MSYS% CYGWIN%,$(PRESENTATION_HOST_OS)),)
PRESENTATION_HOST_LIBS := -luser32 -lgdi32 -lshell32 -lole32
else
PRESENTATION_HOST_LIBS := -ldl -lm
endif

.PHONY: presentation-lib presentation-demo presentation-relaunch \
	presentation-desktop-install \
	presentation-portability
presentation-lib: $(PRESENTATION_PACKAGE_ARCHIVE)

$(PRESENTATION_PROVENANCE_STAMP): $(PRESENTATION_VENDOR_INPUTS)
	@mkdir -p $(PRESENTATION_BUILD_DIR)
	@tools/scripts/test_vendor_provenance.sh
	@sha256sum --check vendor/rgfw/SHA256SUMS
	@sha256sum --check vendor/qrcodegen/SHA256SUMS
	@sha256sum --check vendor/typography/SHA256SUMS
	@sha256sum --check vendor/x11/SHA256SUMS
	@touch $@

$(PRESENTATION_BUILD_DIR)/presentation.o: \
	lib/presentation/src/presentation.c \
	lib/presentation/src/presentation_canvas_internal.h \
	lib/presentation/src/presentation_focus_internal.h \
	lib/presentation/src/presentation_form_internal.h \
	lib/presentation/include/presentation/presentation.h \
	lib/presentation/include/presentation/model_render.h \
	vendor/rgfw/RGFW.h vendor/rgfw/XDL.h \
	$(PRESENTATION_PROVENANCE_STAMP)
	@mkdir -p $(PRESENTATION_BUILD_DIR)
	$(CC) $(PRESENTATION_PACKAGE_CFLAGS) -c \
	lib/presentation/src/presentation.c \
		-o $(PRESENTATION_BUILD_DIR)/presentation.o

$(PRESENTATION_BUILD_DIR)/presentation_canvas_select.o: \
	lib/presentation/src/presentation_canvas_select.c \
	lib/presentation/src/presentation_canvas_internal.h \
	lib/presentation/include/presentation/presentation.h \
	lib/presentation/include/presentation/canvas.h \
	lib/presentation/include/presentation/model_render.h
	@mkdir -p $(PRESENTATION_BUILD_DIR)
	$(CC) $(PRESENTATION_PACKAGE_CFLAGS) -c \
		lib/presentation/src/presentation_canvas_select.c \
		-o $(PRESENTATION_BUILD_DIR)/presentation_canvas_select.o

$(PRESENTATION_BUILD_DIR)/presentation_canvas_model.o: \
	lib/presentation/src/presentation_canvas_model.c \
	lib/presentation/src/presentation_canvas_internal.h \
	lib/presentation/include/presentation/presentation.h \
	lib/presentation/include/presentation/model.h
	@mkdir -p $(PRESENTATION_BUILD_DIR)
	$(CC) $(PRESENTATION_PACKAGE_CFLAGS) -c \
		lib/presentation/src/presentation_canvas_model.c \
		-o $(PRESENTATION_BUILD_DIR)/presentation_canvas_model.o

$(PRESENTATION_BUILD_DIR)/presentation_focus.o: \
	lib/presentation/src/presentation_focus.c \
	lib/presentation/src/presentation_focus_internal.h \
	lib/presentation/include/presentation/presentation.h \
	lib/presentation/include/presentation/model_render.h
	@mkdir -p $(PRESENTATION_BUILD_DIR)
	$(CC) $(PRESENTATION_PACKAGE_CFLAGS) -c \
		lib/presentation/src/presentation_focus.c \
		-o $(PRESENTATION_BUILD_DIR)/presentation_focus.o

$(PRESENTATION_BUILD_DIR)/presentation_form.o: \
	lib/presentation/src/presentation_form.c \
	lib/presentation/src/presentation_form_internal.h \
	lib/presentation/include/presentation/presentation.h \
	lib/presentation/include/presentation/canvas.h \
	lib/presentation/include/presentation/model_render.h
	@mkdir -p $(PRESENTATION_BUILD_DIR)
	$(CC) $(PRESENTATION_PACKAGE_CFLAGS) -c \
		lib/presentation/src/presentation_form.c \
		-o $(PRESENTATION_BUILD_DIR)/presentation_form.o

$(PRESENTATION_BUILD_DIR)/presentation_form_model.o: \
	lib/presentation/src/presentation_form_model.c \
	lib/presentation/include/presentation/presentation.h \
	lib/presentation/include/presentation/model.h
	@mkdir -p $(PRESENTATION_BUILD_DIR)
	$(CC) $(PRESENTATION_PACKAGE_CFLAGS) -c \
		lib/presentation/src/presentation_form_model.c \
		-o $(PRESENTATION_BUILD_DIR)/presentation_form_model.o

$(PRESENTATION_BUILD_DIR)/presentation_input.o: \
	lib/presentation/src/presentation_input.c \
	lib/presentation/include/presentation/presentation.h \
	lib/presentation/include/presentation/model_render.h
	@mkdir -p $(PRESENTATION_BUILD_DIR)
	$(CC) $(PRESENTATION_PACKAGE_CFLAGS) -c \
		lib/presentation/src/presentation_input.c \
		-o $(PRESENTATION_BUILD_DIR)/presentation_input.o

$(PRESENTATION_BUILD_DIR)/zclassic_brand.o: \
	lib/presentation/src/zclassic_brand.c \
	lib/presentation/src/zclassic_icon_mask.inc \
	lib/presentation/include/presentation/zclassic_brand.h
	@mkdir -p $(PRESENTATION_BUILD_DIR)
	$(CC) $(PRESENTATION_PACKAGE_CFLAGS) -c \
		lib/presentation/src/zclassic_brand.c \
		-o $(PRESENTATION_BUILD_DIR)/zclassic_brand.o

$(PRESENTATION_BUILD_DIR)/canvas.o: \
	lib/presentation/src/canvas.c \
	lib/presentation/include/presentation/canvas.h \
	vendor/typography/stb_truetype.h \
	vendor/typography/noto_sans_ascii.inc \
	$(PRESENTATION_PROVENANCE_STAMP)
	@mkdir -p $(PRESENTATION_BUILD_DIR)
	$(CC) $(PRESENTATION_PACKAGE_CFLAGS) -c \
		lib/presentation/src/canvas.c \
		-o $(PRESENTATION_BUILD_DIR)/canvas.o

$(PRESENTATION_BUILD_DIR)/model.o: \
	lib/presentation/src/model.c \
	lib/presentation/include/presentation/model.h \
	lib/base/include/base/serialize_le.h
	@mkdir -p $(PRESENTATION_BUILD_DIR)
	$(CC) $(PRESENTATION_PACKAGE_CFLAGS) -c \
		lib/presentation/src/model.c \
		-o $(PRESENTATION_BUILD_DIR)/model.o

$(PRESENTATION_BUILD_DIR)/model_render.o: \
	lib/presentation/src/model_render.c \
	lib/presentation/src/presentation_canvas_internal.h \
	lib/presentation/include/presentation/model_render.h \
	lib/presentation/include/presentation/model.h \
	lib/presentation/include/presentation/canvas.h
	@mkdir -p $(PRESENTATION_BUILD_DIR)
	$(CC) $(PRESENTATION_PACKAGE_CFLAGS) -c \
		lib/presentation/src/model_render.c \
		-o $(PRESENTATION_BUILD_DIR)/model_render.o

$(PRESENTATION_BUILD_DIR)/model_text.o: \
	lib/presentation/src/model_text.c \
	lib/presentation/include/presentation/model_text.h \
	lib/presentation/include/presentation/model.h
	@mkdir -p $(PRESENTATION_BUILD_DIR)
	$(CC) $(PRESENTATION_PACKAGE_CFLAGS) -c \
		lib/presentation/src/model_text.c \
		-o $(PRESENTATION_BUILD_DIR)/model_text.o

$(PRESENTATION_PACKAGE_ARCHIVE): $(PRESENTATION_PACKAGE_OBJS) \
	$(PRESENTATION_PROVENANCE_STAMP)
	@mkdir -p build/lib
	$(AR) rcs $@ $(PRESENTATION_PACKAGE_OBJS)

presentation-demo: $(PRESENTATION_DEMO_BIN)

$(PRESENTATION_DEMO_BIN): lib/presentation/examples/bitmap_demo.c \
	$(PRESENTATION_PACKAGE_ARCHIVE)
	@mkdir -p $(PRESENTATION_BUILD_DIR)
	$(CC) $(PRESENTATION_PACKAGE_CFLAGS) \
		lib/presentation/examples/bitmap_demo.c \
		$(PRESENTATION_PACKAGE_ARCHIVE) $(PRESENTATION_HOST_LIBS) \
		-o $@

# Host-side visual iteration: rebuild only stale package objects, replace the
# previous demo process, and return immediately. Release LTO is not in this
# path; strict release/full-suite proof remains an end-of-cycle gate.
presentation-relaunch: presentation-demo
	@pkill -x bitmap-demo 2>/dev/null || true
	@nohup $(PRESENTATION_DEMO_BIN) \
		>$(PRESENTATION_BUILD_DIR)/bitmap-demo.log 2>&1 </dev/null &
	@printf '%s\n' 'presentation-relaunch: window launched'

# Explicit per-user Linux packaging. The presentation library itself retains
# no filesystem authority; installation is a developer/operator action.
presentation-desktop-install:
	@install -d "$(HOME)/.local/share/applications" \
		"$(HOME)/.local/share/icons/hicolor/scalable/apps"
	@install -m 0644 packaging/linux/org.zclassic.ZClassic23.desktop \
		"$(HOME)/.local/share/applications/org.zclassic.ZClassic23.desktop"
	@install -m 0644 packaging/linux/org.zclassic.ZClassic23.svg \
		"$(HOME)/.local/share/icons/hicolor/scalable/apps/org.zclassic.ZClassic23.svg"
	@if command -v update-desktop-database >/dev/null 2>&1; then \
		update-desktop-database "$(HOME)/.local/share/applications"; \
	fi
	@if command -v kbuildsycoca6 >/dev/null 2>&1; then \
		kbuildsycoca6 >/dev/null; \
	elif command -v kbuildsycoca5 >/dev/null 2>&1; then \
		kbuildsycoca5 >/dev/null; \
	fi
	@printf '%s\n' 'presentation-desktop-install: ZClassic23 identity installed'

# Current maintainer host carries MinGW, so this is a real Windows compile+link
# proof, not a preprocessor simulation. macOS is linked by the hosted matrix.
presentation-portability: presentation-demo
	@if command -v x86_64-w64-mingw32-gcc >/dev/null 2>&1; then \
		mkdir -p $(PRESENTATION_BUILD_DIR)/windows; \
		x86_64-w64-mingw32-gcc -std=c2x -O2 -Wall -Wextra -Werror \
			-pedantic -Ilib/presentation/include -Ilib/base/include \
			lib/presentation/src/presentation.c \
			lib/presentation/src/presentation_canvas_model.c \
			lib/presentation/src/presentation_canvas_select.c \
			lib/presentation/src/presentation_focus.c \
			lib/presentation/src/presentation_form.c \
			lib/presentation/src/presentation_form_model.c \
			lib/presentation/src/presentation_input.c \
			lib/presentation/src/canvas.c \
			lib/presentation/src/model.c \
			lib/presentation/src/model_text.c \
			lib/presentation/src/model_render.c \
			lib/presentation/src/zclassic_brand.c \
			lib/presentation/examples/bitmap_demo.c \
			-luser32 -lgdi32 -lshell32 -lole32 \
			-o $(PRESENTATION_BUILD_DIR)/windows/bitmap-demo.exe; \
		printf '%s\n' 'presentation-portability: Windows cross-link OK'; \
	else \
		printf '%s\n' 'presentation-portability: MinGW unavailable (Windows cross-link skipped)'; \
	fi

.PHONY: worktree-prime
# Formalizes the "cp -a vendor/lib before a fresh worktree can link" tribal
# knowledge (docs/work/README.md, the zclassic23-dev skill's Parallel-worktree
# section): copies already-built vendor/lib/*.a from a sibling checkout
# instead of paying `make vendor`'s from-pinned-source rebuild in every new
# worktree. Source defaults to this worktree's primary checkout (derived from
# `git rev-parse --git-common-dir`, which every `git worktree add` lane shares
# with its origin checkout); override with SRC=<path-to-a-primed-checkout>
# for wt2/wt3-style siblings that are not the primary checkout.
worktree-prime:
	@set -eu; \
	src="$(SRC)"; \
	if [ -z "$$src" ]; then \
	  gcd="$$(git rev-parse --path-format=absolute --git-common-dir 2>/dev/null)"; \
	  case "$$gcd" in \
	    */.git) src="$${gcd%/.git}" ;; \
	    *) src="" ;; \
	  esac; \
	fi; \
	if [ -z "$$src" ]; then \
	  echo "worktree-prime: could not derive a primary checkout; pass SRC=<path>" >&2; \
	  exit 1; \
	fi; \
	if [ ! -d "$$src/vendor/lib" ] || [ -z "$$(ls -A "$$src/vendor/lib" 2>/dev/null)" ]; then \
	  echo "worktree-prime: $$src/vendor/lib is missing or empty (run 'make vendor' there, or pass SRC=<a primed checkout>)" >&2; \
	  exit 1; \
	fi; \
	if [ "$$(cd "$$src" && pwd -P)" = "$$(pwd -P)" ]; then \
	  echo "worktree-prime: this checkout ($$src) IS the source — nothing to do"; \
	  exit 0; \
	fi; \
	mkdir -p vendor/lib; \
	cp -a "$$src/vendor/lib/." vendor/lib/; \
	n=$$(ls vendor/lib | wc -l); \
	echo "worktree-prime: copied $$n vendor archive(s) from $$src/vendor/lib"

# Auto-vendor: if any required archive is absent, build it.  The per-archive
# rule lets `make zclassic23` pull in `make vendor` transparently on a fresh
# clone without re-running the whole script when the libs are already there.
# libsecp256k1.a is tracked, so it has no recipe (git provides it).
$(filter-out vendor/lib/libsecp256k1.a,$(VENDOR_LIBS)):
	tools/scripts/build_vendor.sh $(notdir $@)

.PHONY: all test test-e2e test-shielded-payment test-store-e2e clean deploy deploy-dev remote-node-plan remote-node-plan-json remote-node-update remote-node-update-json lane-health lane-recover check-agent-cli check-restart-follow \
        background-fuzz background-coverage background-tests install-quality-linger quality-linger-status pre-push-ci \
        install-replay-canary replay-canary-linger-status \
        coverage coverage-clean ci audit release \
        bench bench-crypto-verify bench-regress \
	lint check-build-epoch-integrity check-checkout-lock check-malloc check-raw-sqlite check-vcs-no-git check-vcs-no-sha1 check-raw-malloc check-json-value-init check-stable-publish-contained check-no-retired-agent-protocol \
        check-coins-lookup-nullcheck check-observability-pairing \
        check-silent-errors-services check-silent-errors-controllers \
        check-silent-errors-jobs check-silent-errors-conditions check-silent-errors-bool \
        check-log-macro-return-type \
        check-wallet-raw-prepare-log check-blob-read-bounds \
        check-before-save-hooks check-pthread-create check-model-validation \
        check-long-functions check-rpc-registrar check-lag-slo-observable \
        check-file-size-ceiling check-framework-filename-suffix \
        check-stopwatch-skip-detector \
        check-proof-server-pin \
        check-promotion-receipt-chain \
        check-verification-coverage \
        check-ship-remote-transaction \
        check-z23-release-install \
        check-identity-parser-single \
        check-status-reason-single \
        check-operator-needed-sink check-systemd-memory-budget check-doc-accuracy check-doc-counts check-doc-claims check-no-stale-pinned-facts check-markdown-links check-doc-inline-paths \
        check-api-reference-generated check-describe-budget \
        check-no-new-repair-rung \
        fuzz-ci-leaks \
        soak-smoke soak-7day soak-ci test-crash-bootstrap \
        test-reindex-smoke test-reindex-killmid \
        test-two-node-peer-tip test-science-acceptance test-market-acceptance \
        test-market-moderation-acceptance \
        chaos chaos-clean \
        replay-canary-anchor replay-canary-genesis \
        soak-evidence-report soak-evidence-selftest \
        install-slo-probe slo-probe-status slo-probe-selftest \
        install-tip-agreement tip-agreement-status tip-agreement-selftest

CLI_SRCS = lib/rpc/src/client.c lib/json/src/json.c lib/encoding/src/utilstrencodings.c lib/base/src/log_level.c
all: test_zcl zclassic23 zclassic-cli zcl-rpc zclassic23-package-verify \
	zclassic23-zcode-adapter-runner

TEST_SRCS = $(call zcl_filter_ephemeral_sources,\
	$(wildcard lib/test/src/*.c))
TEST_DEV_EXECUTOR_SRCS = tools/dev/devloop_cycle.c tools/dev/dev_failure_store.c \
	tools/dev/dev_source_identity.c tools/dev/devloop_process.c \
	tools/dev/devloop_hotswap_build.c tools/dev/devloop_restart_build.c
SPEC_SRCS = $(wildcard lib/test/spec/*.c)
CHAOS_SIM_SRCS = tools/sim/sim_peer.c

# test.c and test_parallel.c each own their own main() — never both in
# one binary. test_parallel_zcl uses the latter + the same test/spec
# helpers as sequential test_zcl.
TEST_SRCS_NO_MAIN = $(filter-out lib/test/src/test.c lib/test/src/test_parallel.c, $(TEST_SRCS)) $(TEST_DEV_EXECUTOR_SRCS)
TEST_FAST_OBJ_ROOT = $(BUILD_DIR)/test-obj
TEST_PARALLEL_FAST_BIN = $(BIN_DIR)/test_parallel_fast
TEST_PARALLEL_FAST_SRCS = $(TEST_SRCS_NO_MAIN) lib/test/src/test_parallel.c $(SPEC_SRCS) $(CHAOS_SIM_SRCS) $(ALL_SRCS)
TEST_FAST_CFLAGS = $(filter-out -O3 -flto=auto -Werror,$(CACHED_CFLAGS)) -O1 -g -DZCL_TESTING \
	-Wno-deprecated-declarations -Wno-format-truncation -Wno-maybe-uninitialized
TEST_FAST_LDFLAGS = $(filter-out -flto=auto,$(LDFLAGS)) $(ZCL_DEV_LINKER)
TEST_FAST_EPOCH_COMPILE_FLAGS := $(strip $(TEST_FAST_CFLAGS) deps=-MD,-MP)
TEST_FAST_EPOCH_LINK_FLAGS := $(strip $(TEST_FAST_LDFLAGS) $(TOR_LIBS) $(LIBS) $(GTK_LIBS) $(WEBKIT_LIBS) cxx=$(CXX))
ifneq ($(filter test-fast,$(ZCL_EPOCH_PROFILES)),)
TEST_FAST_COMPILE_EPOCH := $(call zcl_compile_epoch,test-fast-v2,TEST_FAST_EPOCH_COMPILE_FLAGS,TEST_FAST_EPOCH_LINK_FLAGS)
TEST_FAST_COMPILE_EPOCH_VALID := $(shell printf '%s\n' '$(TEST_FAST_COMPILE_EPOCH)' | awk '$$0 ~ /^[0-9a-f]{64}$$/ { print "yes" }')
ifneq ($(TEST_FAST_COMPILE_EPOCH_VALID),yes)
$(error test-fast compile-epoch derivation failed)
endif
else
TEST_FAST_COMPILE_EPOCH := $(ZCL_ZERO_SHA256)
endif
TEST_FAST_OBJ_DIR = $(TEST_FAST_OBJ_ROOT)/epochs/$(TEST_FAST_COMPILE_EPOCH)
TEST_PARALLEL_FAST_OBJS = $(patsubst %.c,$(TEST_FAST_OBJ_DIR)/%.o,$(TEST_PARALLEL_FAST_SRCS))
TEST_PARALLEL_FAST_LINK_RSP = $(TEST_FAST_OBJ_DIR)/link-inputs.rsp
TEST_PARALLEL_FAST_CANDIDATE = $(BIN_DIR)/test-fast/epochs/$(TEST_FAST_COMPILE_EPOCH)/test_parallel_fast
TEST_PARALLEL_FAST_ACTIVE = $(TEST_PARALLEL_FAST_CANDIDATE)

ifneq ($(filter test-fast,$(ZCL_DEPFILE_PROFILES)),)
-include $(TEST_PARALLEL_FAST_OBJS:.o=.d)
endif

# ── Cached STRICT test_parallel (per-TU, depfile-tracked) ────────────────────
# `test_parallel` (what `make t`/`make test` run) was one whole-program `cc`
# over ~1,300 .c files, so ccache could never cache it and EVERY full-suite gate
# paid a full recompile (~90s here) even for a one-line edit — and, worse, the
# monolith rule listed only .c files as prerequisites, so a header-only edit did
# not rebuild at all (false green). Both are fixed by compiling into a dedicated
# per-TU object tree with -MD -MP depfiles and linking the cached objects.
#
# Flags are IDENTICAL to the old whole-program test_parallel rule with ONE
# deliberate delta: `-flto=auto` is dropped. LTO is a *link-time* whole-program
# optimization — caching per-TU GIMPLE objects would still force the expensive
# whole-program optimize+codegen at every link, defeating the cache. Dropping it
# makes each TU independently compiled AND code-generated. A source mutation
# selects a fresh immutable object epoch; ccache/sccache recovers unchanged TU
# work before one plain link. This cannot change
# test semantics: -O3, -Werror, -pedantic, the hardening flags and -DZCL_TESTING
# are all preserved byte-for-byte; LTO only alters cross-TU inlining, never
# observable behavior. The whole-program LTO build remains as `test_parallel_wpo`
# (below) for the rare case of chasing an optimizer/LTO-dependent divergence.
TEST_REL_OBJ_ROOT = $(BUILD_DIR)/test-rel-obj
# Second (documented) delta: the -O3 + _FORTIFY_SOURCE heuristic-warning family
# (-Wformat-truncation/-Wformat-overflow, -Warray-bounds, -Wstringop-truncation,
# -Wstringop-overread, -Wrestrict, -Wnonnull, -Wmaybe-uninitialized) is off. These
# fire ONLY once real per-TU codegen runs at -O3; every other build in the tree
# defers codegen and never emits them
# — the release binary and `make build-only` both compile with -flto=auto (LTO
# defers codegen to link, which does not re-emit these), and test_parallel_fast
# runs at -O1 (below the level that enables -Warray-bounds). So NO build in the
# repo enforces this family today; excluding it here keeps the ENFORCED warning
# set a superset-or-equal of the retired whole-program test_parallel's — every
# warning the old monolith would have failed on, this pipeline still fails on.
# Each is a conservative worst-case estimate on intentionally-bounded snprintf /
# memcpy / guarded locals (verified: the flagged sites are all safe), not a real
# defect. -Werror and -pedantic remain in force for every other warning.
TEST_REL_CFLAGS = $(filter-out -flto=auto,$(CACHED_CFLAGS)) -DZCL_TESTING \
	-Wno-deprecated-declarations -Wno-format-truncation -Wno-format-overflow \
	-Wno-array-bounds -Wno-stringop-truncation -Wno-stringop-overread \
	-Wno-restrict -Wno-nonnull -Wno-maybe-uninitialized
TEST_REL_LDFLAGS = $(filter-out -flto=auto,$(LDFLAGS))
INTEGRATION_CFLAGS := $(TEST_REL_CFLAGS)
INTEGRATION_LDFLAGS := $(TEST_REL_LDFLAGS)
TEST_REL_EPOCH_COMPILE_FLAGS := $(strip $(TEST_REL_CFLAGS) deps=-MD,-MP)
TEST_REL_EPOCH_LINK_FLAGS := $(strip $(TEST_REL_LDFLAGS) $(TOR_LIBS) $(LIBS) $(GTK_LIBS) $(WEBKIT_LIBS) cxx=$(CXX))
ifneq ($(filter test-strict,$(ZCL_EPOCH_PROFILES)),)
TEST_REL_COMPILE_EPOCH := $(call zcl_compile_epoch,test-strict-v2,TEST_REL_EPOCH_COMPILE_FLAGS,TEST_REL_EPOCH_LINK_FLAGS)
TEST_REL_COMPILE_EPOCH_VALID := $(shell printf '%s\n' '$(TEST_REL_COMPILE_EPOCH)' | awk '$$0 ~ /^[0-9a-f]{64}$$/ { print "yes" }')
ifneq ($(TEST_REL_COMPILE_EPOCH_VALID),yes)
$(error test-strict compile-epoch derivation failed)
endif
else
TEST_REL_COMPILE_EPOCH := $(ZCL_ZERO_SHA256)
endif
TEST_REL_OBJ_DIR = $(TEST_REL_OBJ_ROOT)/epochs/$(TEST_REL_COMPILE_EPOCH)
TEST_PARALLEL_REL_SRCS = $(TEST_SRCS_NO_MAIN) lib/test/src/test_parallel.c $(SPEC_SRCS) $(CHAOS_SIM_SRCS) $(ALL_SRCS)
TEST_PARALLEL_REL_OBJS = $(patsubst %.c,$(TEST_REL_OBJ_DIR)/%.o,$(TEST_PARALLEL_REL_SRCS))
TEST_PARALLEL_REL_LINK_RSP = $(TEST_REL_OBJ_DIR)/link-inputs.rsp
TEST_PARALLEL_REL_CANDIDATE = $(BIN_DIR)/test-strict/epochs/$(TEST_REL_COMPILE_EPOCH)/test_parallel
TEST_PARALLEL_REL_ACTIVE = $(TEST_PARALLEL_REL_CANDIDATE)
TEST_FAST_PROFILE = test-fast-v2
TEST_REL_PROFILE = test-strict-v2
TEST_FAST_SESSION = $(TEST_FAST_OBJ_DIR)/.build-session
TEST_REL_SESSION = $(TEST_REL_OBJ_DIR)/.build-session
TEST_FAST_LEASE = $(TEST_FAST_OBJ_DIR)/.leases/$(BUILD_INVOCATION_ID)
TEST_REL_LEASE = $(TEST_REL_OBJ_DIR)/.leases/$(BUILD_INVOCATION_ID)

$(TEST_FAST_LEASE): FORCE
	@$(BUILD_EPOCH_SESSION_TOOL) acquire "$(TEST_FAST_SESSION)" "$@" \
	  "$(TEST_FAST_OBJ_ROOT)" "$(BIN_DIR)/test-fast" "$(BUILD_EPOCH_KEEP)" \
	  "$(BUILD_SOURCE_ID)" "$(BUILD_CLEAN)" "$(BUILD_MUTATION)" \
	  "$(BUILD_COMPILER_ID)" "$(TEST_FAST_COMPILE_EPOCH)" "$(TEST_FAST_PROFILE)" \
	  "$(TEST_FAST_EPOCH_COMPILE_FLAGS)" "$(TEST_FAST_EPOCH_LINK_FLAGS)" \
	  "$(CC)" "$(CXX)" "$$PPID"

$(TEST_REL_LEASE): FORCE
	@$(BUILD_EPOCH_SESSION_TOOL) acquire "$(TEST_REL_SESSION)" "$@" \
	  "$(TEST_REL_OBJ_ROOT)" "$(BIN_DIR)/test-strict" "$(BUILD_EPOCH_KEEP)" \
	  "$(BUILD_SOURCE_ID)" "$(BUILD_CLEAN)" "$(BUILD_MUTATION)" \
	  "$(BUILD_COMPILER_ID)" "$(TEST_REL_COMPILE_EPOCH)" "$(TEST_REL_PROFILE)" \
	  "$(TEST_REL_EPOCH_COMPILE_FLAGS)" "$(TEST_REL_EPOCH_LINK_FLAGS)" \
	  "$(CC)" "$(CXX)" "$$PPID"

ifneq ($(filter test-strict,$(ZCL_DEPFILE_PROFILES)),)
-include $(TEST_PARALLEL_REL_OBJS:.o=.d)
endif

# ── ASan/UBSan test harness (opt-in; mirrors the test-fast profile) ────────
# `make t-asan ONLY=<group>` runs one test group under AddressSanitizer +
# UndefinedBehaviorSanitizer, extending the fuzz-only sanitizer coverage to
# the whole suite. Own epoch-keyed object tree (build/test-asan-obj) and own
# candidate dir so the sanitizer flags can never leak into the
# strict/fast/release builds — the epoch key binds the exact flag set and
# nothing else references this tree. Flags mirror TEST_FAST plus
# ASAN_COMMON_SAN_FLAGS; the sanitizer flag combination itself follows the
# fuzz harnesses' established profile (FUZZ_CFLAGS).
TEST_ASAN_OBJ_ROOT = $(BUILD_DIR)/test-asan-obj
TEST_ASAN_BIN = $(BIN_DIR)/test-asan
TEST_ASAN_SRCS = $(TEST_PARALLEL_FAST_SRCS)
TEST_ASAN_CFLAGS = $(filter-out -O3 -flto=auto -Werror,$(CACHED_CFLAGS)) -O1 -g -DZCL_TESTING \
	$(ASAN_COMMON_SAN_FLAGS) \
	-Wno-deprecated-declarations -Wno-format-truncation -Wno-maybe-uninitialized
TEST_ASAN_LDFLAGS = $(filter-out -flto=auto,$(LDFLAGS)) $(ASAN_COMMON_SAN_FLAGS)
TEST_ASAN_EPOCH_COMPILE_FLAGS := $(strip $(TEST_ASAN_CFLAGS) \
	adx-exception=$(ASAN_ADX_FRAME_POINTER_EXCEPTION_SRCS):$(ASAN_ADX_FRAME_POINTER_EXCEPTION_FLAGS) \
	deps=-MD,-MP)
TEST_ASAN_EPOCH_LINK_FLAGS := $(strip $(TEST_ASAN_LDFLAGS) $(TOR_LIBS) $(LIBS) $(GTK_LIBS) $(WEBKIT_LIBS) cxx=$(CXX))
ifneq ($(filter test-asan,$(ZCL_EPOCH_PROFILES)),)
TEST_ASAN_COMPILE_EPOCH := $(call zcl_compile_epoch,test-asan-v2,TEST_ASAN_EPOCH_COMPILE_FLAGS,TEST_ASAN_EPOCH_LINK_FLAGS)
TEST_ASAN_COMPILE_EPOCH_VALID := $(shell printf '%s\n' '$(TEST_ASAN_COMPILE_EPOCH)' | awk '$$0 ~ /^[0-9a-f]{64}$$/ { print "yes" }')
ifneq ($(TEST_ASAN_COMPILE_EPOCH_VALID),yes)
$(error test-asan compile-epoch derivation failed)
endif
else
TEST_ASAN_COMPILE_EPOCH := $(ZCL_ZERO_SHA256)
endif
TEST_ASAN_OBJ_DIR = $(TEST_ASAN_OBJ_ROOT)/epochs/$(TEST_ASAN_COMPILE_EPOCH)
TEST_ASAN_OBJS = $(patsubst %.c,$(TEST_ASAN_OBJ_DIR)/%.o,$(TEST_ASAN_SRCS))
TEST_ASAN_LINK_RSP = $(TEST_ASAN_OBJ_DIR)/link-inputs.rsp
# The alias file (build/bin/test-asan) and the candidate DIRECTORY must have
# different names (same convention as test_parallel_fast vs test-fast/):
# publish-build-alias renames a file onto the alias, and mv onto an existing
# directory would move the binary INTO the directory instead.
TEST_ASAN_CANDIDATE = $(BIN_DIR)/test-asan-epochs/epochs/$(TEST_ASAN_COMPILE_EPOCH)/test-asan
TEST_ASAN_ACTIVE = $(TEST_ASAN_CANDIDATE)
TEST_ASAN_PROFILE = test-asan-v2
TEST_ASAN_SESSION = $(TEST_ASAN_OBJ_DIR)/.build-session
TEST_ASAN_LEASE = $(TEST_ASAN_OBJ_DIR)/.leases/$(BUILD_INVOCATION_ID)

$(TEST_ASAN_LEASE): FORCE
	@$(BUILD_EPOCH_SESSION_TOOL) acquire "$(TEST_ASAN_SESSION)" "$@" \
	  "$(TEST_ASAN_OBJ_ROOT)" "$(BIN_DIR)/test-asan-epochs" "$(BUILD_EPOCH_KEEP)" \
	  "$(BUILD_SOURCE_ID)" "$(BUILD_CLEAN)" "$(BUILD_MUTATION)" \
	  "$(BUILD_COMPILER_ID)" "$(TEST_ASAN_COMPILE_EPOCH)" "$(TEST_ASAN_PROFILE)" \
	  "$(TEST_ASAN_EPOCH_COMPILE_FLAGS)" "$(TEST_ASAN_EPOCH_LINK_FLAGS)" \
	  "$(CC)" "$(CXX)" "$$PPID"

ifneq ($(filter test-asan,$(ZCL_DEPFILE_PROFILES)),)
-include $(TEST_ASAN_OBJS:.o=.d)
endif

# ── TSan test harness (opt-in; mirrors the test-asan profile) ─────────────
# `make t-tsan ONLY=<group>` runs one test group under ThreadSanitizer. Own
# epoch-keyed object tree (build/test-tsan-obj) and own candidate dir so the
# sanitizer flags can never leak into the strict/fast/release/asan builds —
# the epoch key binds the exact flag set and nothing else references this
# tree. Flags mirror TEST_ASAN with TSAN_COMMON_SAN_FLAGS in place of the
# ASan set (thread is mutually exclusive with address/undefined). Non-LTO,
# same rationale as the dev-tsan note above: TSan report fidelity depends on
# per-TU PC/stack attribution that whole-program LTO inlining degrades.
TEST_TSAN_OBJ_ROOT = $(BUILD_DIR)/test-tsan-obj
TEST_TSAN_BIN = $(BIN_DIR)/test-tsan
TEST_TSAN_SRCS = $(TEST_PARALLEL_FAST_SRCS)
TEST_TSAN_CFLAGS = $(filter-out -O3 -flto=auto -Werror,$(CACHED_CFLAGS)) -O1 -g -DZCL_TESTING \
	$(TSAN_COMMON_SAN_FLAGS) \
	-Wno-deprecated-declarations -Wno-format-truncation -Wno-maybe-uninitialized
TEST_TSAN_LDFLAGS = $(filter-out -flto=auto,$(LDFLAGS)) $(TSAN_COMMON_SAN_FLAGS)
TEST_TSAN_EPOCH_COMPILE_FLAGS := $(strip $(TEST_TSAN_CFLAGS) deps=-MD,-MP)
TEST_TSAN_EPOCH_LINK_FLAGS := $(strip $(TEST_TSAN_LDFLAGS) $(TOR_LIBS) $(LIBS) $(GTK_LIBS) $(WEBKIT_LIBS) cxx=$(CXX))
ifneq ($(filter test-tsan,$(ZCL_EPOCH_PROFILES)),)
TEST_TSAN_COMPILE_EPOCH := $(call zcl_compile_epoch,test-tsan-v2,TEST_TSAN_EPOCH_COMPILE_FLAGS,TEST_TSAN_EPOCH_LINK_FLAGS)
TEST_TSAN_COMPILE_EPOCH_VALID := $(shell printf '%s\n' '$(TEST_TSAN_COMPILE_EPOCH)' | awk '$$0 ~ /^[0-9a-f]{64}$$/ { print "yes" }')
ifneq ($(TEST_TSAN_COMPILE_EPOCH_VALID),yes)
$(error test-tsan compile-epoch derivation failed)
endif
else
TEST_TSAN_COMPILE_EPOCH := $(ZCL_ZERO_SHA256)
endif
TEST_TSAN_OBJ_DIR = $(TEST_TSAN_OBJ_ROOT)/epochs/$(TEST_TSAN_COMPILE_EPOCH)
TEST_TSAN_OBJS = $(patsubst %.c,$(TEST_TSAN_OBJ_DIR)/%.o,$(TEST_TSAN_SRCS))
TEST_TSAN_LINK_RSP = $(TEST_TSAN_OBJ_DIR)/link-inputs.rsp
# Alias file (build/bin/test-tsan) vs candidate DIRECTORY name: same
# convention as test-asan vs test-asan-epochs/ — publish-build-alias renames
# a file onto the alias, and mv onto an existing directory would move the
# binary INTO the directory instead.
TEST_TSAN_CANDIDATE = $(BIN_DIR)/test-tsan-epochs/epochs/$(TEST_TSAN_COMPILE_EPOCH)/test-tsan
TEST_TSAN_ACTIVE = $(TEST_TSAN_CANDIDATE)
TEST_TSAN_PROFILE = test-tsan-v2
TEST_TSAN_SESSION = $(TEST_TSAN_OBJ_DIR)/.build-session
TEST_TSAN_LEASE = $(TEST_TSAN_OBJ_DIR)/.leases/$(BUILD_INVOCATION_ID)

$(TEST_TSAN_LEASE): FORCE
	@$(BUILD_EPOCH_SESSION_TOOL) acquire "$(TEST_TSAN_SESSION)" "$@" \
	  "$(TEST_TSAN_OBJ_ROOT)" "$(BIN_DIR)/test-tsan-epochs" "$(BUILD_EPOCH_KEEP)" \
	  "$(BUILD_SOURCE_ID)" "$(BUILD_CLEAN)" "$(BUILD_MUTATION)" \
	  "$(BUILD_COMPILER_ID)" "$(TEST_TSAN_COMPILE_EPOCH)" "$(TEST_TSAN_PROFILE)" \
	  "$(TEST_TSAN_EPOCH_COMPILE_FLAGS)" "$(TEST_TSAN_EPOCH_LINK_FLAGS)" \
	  "$(CC)" "$(CXX)" "$$PPID"

ifneq ($(filter test-tsan,$(ZCL_DEPFILE_PROFILES)),)
-include $(TEST_TSAN_OBJS:.o=.d)
endif

# Generate templates from .chtml and .ccss files
TMPL_GEN = app/views/include/views/wallet_templates_gen.h
TMPL_SRC = $(wildcard app/views/templates/*.chtml) $(wildcard app/views/css/*.ccss)
TMPL_TOOL = $(BIN_DIR)/gen_templates
SITE_CSS_GEN = app/views/include/views/site_css.h
SITE_CSS_SRC = app/views/src/site.css
VIEW_GEN_HEADERS = $(VIEW_GEN_HEADERS_EARLY)

$(TMPL_TOOL): tools/gen_templates.c lib/base/src/safe_alloc.c
	@mkdir -p $(dir $@)
	$(CC) -std=c23 -O2 -Wall -Wextra -Ilib/base/include -Ilib/util/include -o $@ $^

$(BIN_DIR)/inspect_html: tools/inspect_html.c lib/base/src/safe_alloc.c
	@mkdir -p $(dir $@)
	$(CC) -std=c23 -O2 -Wall -Wextra \
	    -Ilib/base/include -Ilib/util/include -o $@ $^

# These two run on EVERY make invocation (they are prerequisites of the
# -include'd view bootstrap, so they are re-checked before any goal), which
# meant every target in this repo — `make t-list` included — opened with two
# lines of command echo on STDOUT. That is fine for a human and fatal for a
# target whose stdout is meant to be a machine-readable list. The echo is
# suppressed; nothing is lost, because gen_templates itself reports what it
# did (file counts, byte counts, "unchanged") on stderr either way.
$(TMPL_GEN): $(TMPL_SRC) tools/gen_templates.c | $(TMPL_TOOL)
	@$(TMPL_TOOL) app/views/templates $@ app/views/css

$(SITE_CSS_GEN): $(SITE_CSS_SRC) tools/gen_templates.c | $(TMPL_TOOL)
	@$(TMPL_TOOL) --single-css $< $@ site_css SITE_CSS_H

# Included near the top of this file. Updating it after its generated-header
# prerequisites makes GNU Make restart before any ordinary target recipe runs.
# Same session-cache contract as VENDOR_BOOTSTRAP_MK above: a regenerated
# header is invisible to a capture the pre-restart parse already memoized, so
# drop that record and let the post-restart parse re-derive it.
$(VIEW_BOOTSTRAP_MK): $(VIEW_GEN_HEADERS)
	@set -eu; \
	mkdir -p "$(dir $@)"; \
	ZCL_SOURCE_IDENTITY_SESSION='$(ZCL_SOURCE_IDENTITY_SESSION)' tools/dev/source-identity.sh session-cache-drop; \
	tmp="$$(mktemp "$(dir $@).views-ready.XXXXXX")"; \
	trap 'rm -f "$$tmp"' EXIT HUP INT TERM; \
	printf '%s\n' '# generated: view inputs established before source identity capture' > "$$tmp"; \
	mv -f -- "$$tmp" "$@"; \
	trap - EXIT HUP INT TERM

.PHONY: templates
templates: $(VIEW_GEN_HEADERS)

# Prove a no-op regeneration changes neither tracked bytes nor filesystem
# metadata. The source mutation token includes inode/mtime/ctime specifically
# to catch edit/revert ABA, so this fast check guards the exact contract the
# build-twice reproducibility gate relies on.
.PHONY: templates-no-touch-selftest
templates-no-touch-selftest: $(VIEW_GEN_HEADERS)
	@set -eu; \
	before="$$(tools/dev/source-identity.sh capture-record)"; \
	$(TMPL_TOOL) app/views/templates $(TMPL_GEN) app/views/css >/dev/null; \
	$(TMPL_TOOL) --single-css $(SITE_CSS_SRC) $(SITE_CSS_GEN) site_css SITE_CSS_H >/dev/null; \
	after="$$(tools/dev/source-identity.sh capture-record)"; \
	[ "$$before" = "$$after" ] || { \
	    echo "templates-no-touch-selftest: source metadata changed on no-op regeneration" >&2; \
	    exit 1; \
	}; \
	echo "templates-no-touch-selftest: PASS"

.PHONY: site-css explorer-css
site-css: $(SITE_CSS_GEN)
explorer-css: site-css

.PHONY: tools/gen_templates tools/inspect_html
tools/gen_templates: $(TMPL_TOOL)
tools/inspect_html: $(BIN_DIR)/inspect_html

# Build a tool/test binary that links against the full node library stack
# (Tor, OpenSSL, libevent, GTK, WebKit). Used by 8 binaries to keep the
# recipe in one place — a new tool becomes one $(eval $(call ...)) line and
# cannot drift on flags.
#   $(1) = target name (e.g., wallet_dump)
#   $(2) = entry source(s) — single file or whitespace-separated list
#   $(3) = extra link libs (e.g., -lm); empty by default
#   $(4) = extra CFLAGS (e.g., -DZCL_TESTING); empty by default
define BUILD_NODE_TOOL
.PHONY: $(1)
$(1): $$(BIN_DIR)/$(1)
$$(BIN_DIR)/$(1): $$(VIEW_GEN_HEADERS) $$(BUILD_IDENTITY_STAMP) \
		$(2) $$(ALL_SRCS) $$(COMMAND_CATALOG_DEFS) | $$(VENDOR_LIBS)
	@mkdir -p $$(dir $$@)
	@set -eu; \
	tmp="$$$$(mktemp "$$@.link.XXXXXX")"; \
	trap 'rm -f "$$$$tmp"' EXIT HUP INT TERM; \
	$$(CC) $$(CFLAGS) $(4) -Wno-deprecated-declarations $$(LDFLAGS) -o "$$$$tmp" $$(filter-out $$(VIEW_GEN_HEADERS) $$(BUILD_IDENTITY_STAMP) $$(COMMAND_CATALOG_DEFS),$$^) $$(TOR_LIBS) $$(LIBS) $$(GTK_LIBS) $$(WEBKIT_LIBS) $(3); \
	tools/dev/source-identity.sh verify-record "$$(BUILD_SOURCE_ID)" "$$(BUILD_CLEAN)" "$$(BUILD_MUTATION)" >/dev/null; \
	mv -f -- "$$$$tmp" "$$@"; \
	trap - EXIT HUP INT TERM
endef

$(eval $(call BUILD_NODE_TOOL,test_zcl,$(TEST_SRCS_NO_MAIN) lib/test/src/test.c $(SPEC_SRCS) $(CHAOS_SIM_SRCS),,-DZCL_TESTING $(DEV_SOURCE_RECEIPT_CPPFLAGS)))
# Whole-program LTO test_parallel, kept for debugging any per-TU-vs-LTO
# divergence. `make t`/`make test` no longer build this — they use the cached
# per-TU $(TEST_PARALLEL_BIN) rule below — but `make test_parallel_wpo` still
# produces the original monolithic binary at build/bin/test_parallel_wpo.
$(eval $(call BUILD_NODE_TOOL,test_parallel_wpo,$(TEST_SRCS_NO_MAIN) lib/test/src/test_parallel.c $(SPEC_SRCS) $(CHAOS_SIM_SRCS),,-DZCL_TESTING $(DEV_SOURCE_RECEIPT_CPPFLAGS)))

# test_parallel is built as an immutable epoch candidate. The familiar
# build/bin alias is a locked atomic copy and is FORCE-driven so A -> B -> A
# cannot be skipped by stable-path mtimes. Internal commands execute the exact
# candidate, never the concurrently replaceable alias.
.PHONY: FORCE test_parallel test_parallel_fast test-parallel-active \
	test-parallel-active-locked test-parallel-fast-active \
	test-parallel-fast-active-locked test-asan test-tsan
FORCE:

test_parallel: $(TEST_PARALLEL_BIN)

$(TEST_PARALLEL_BIN): $(TEST_PARALLEL_REL_CANDIDATE) FORCE
	@$(BUILD_EPOCH_PUBLISH_TOOL) "$(TEST_PARALLEL_REL_CANDIDATE)" "$@" "$(TEST_REL_SESSION)" \
	  "$(BUILD_SOURCE_ID)" "$(BUILD_CLEAN)" "$(BUILD_MUTATION)" \
	  "$(TEST_REL_COMPILE_EPOCH)" "$(BUILD_COMPILER_ID)" "$(TEST_REL_PROFILE)" \
	  "$(TEST_REL_EPOCH_COMPILE_FLAGS)" "$(TEST_REL_EPOCH_LINK_FLAGS)" "$(CC)" "$(CXX)"

$(TEST_PARALLEL_REL_CANDIDATE): $(VIEW_GEN_HEADERS) $(BUILD_IDENTITY_STAMP) $(TEST_PARALLEL_REL_OBJS) $(TEST_PARALLEL_REL_LINK_RSP) | $(VENDOR_LIBS)
	@mkdir -p $(dir $@)
	@set -eu; \
	tmp="$$(mktemp "$@.link.XXXXXX")"; \
	trap 'rm -f "$$tmp"' EXIT HUP INT TERM; \
	$(CC) $(TEST_REL_CFLAGS) $(TEST_REL_LDFLAGS) -o "$$tmp" "@$(TEST_PARALLEL_REL_LINK_RSP)" $(TOR_LIBS) $(LIBS) $(GTK_LIBS) $(WEBKIT_LIBS); \
	$(BUILD_EPOCH_SESSION_TOOL) verify "$(TEST_REL_SESSION)" "$(TEST_REL_LEASE)" \
	  "$(TEST_REL_OBJ_ROOT)" "$(BIN_DIR)/test-strict" "$(BUILD_EPOCH_KEEP)" \
	  "$(BUILD_SOURCE_ID)" "$(BUILD_CLEAN)" "$(BUILD_MUTATION)" "$(BUILD_COMPILER_ID)" \
	  "$(TEST_REL_COMPILE_EPOCH)" "$(TEST_REL_PROFILE)" "$(TEST_REL_EPOCH_COMPILE_FLAGS)" \
	  "$(TEST_REL_EPOCH_LINK_FLAGS)" "$(CC)" "$(CXX)" "$$PPID" >/dev/null; \
	mv -f -- "$$tmp" "$@"; \
	trap - EXIT HUP INT TERM

test_parallel_fast: $(TEST_PARALLEL_FAST_BIN)

$(TEST_PARALLEL_FAST_BIN): $(TEST_PARALLEL_FAST_CANDIDATE) FORCE
	@$(BUILD_EPOCH_PUBLISH_TOOL) "$(TEST_PARALLEL_FAST_CANDIDATE)" "$@" "$(TEST_FAST_SESSION)" \
	  "$(BUILD_SOURCE_ID)" "$(BUILD_CLEAN)" "$(BUILD_MUTATION)" \
	  "$(TEST_FAST_COMPILE_EPOCH)" "$(BUILD_COMPILER_ID)" "$(TEST_FAST_PROFILE)" \
	  "$(TEST_FAST_EPOCH_COMPILE_FLAGS)" "$(TEST_FAST_EPOCH_LINK_FLAGS)" "$(CC)" "$(CXX)"

$(TEST_PARALLEL_FAST_CANDIDATE): $(VIEW_GEN_HEADERS) $(BUILD_IDENTITY_STAMP) $(TEST_PARALLEL_FAST_OBJS) $(TEST_PARALLEL_FAST_LINK_RSP) | $(VENDOR_LIBS)
	@mkdir -p $(dir $@)
	@set -eu; \
	tmp="$$(mktemp "$@.link.XXXXXX")"; \
	trap 'rm -f "$$tmp"' EXIT HUP INT TERM; \
	$(CC) $(TEST_FAST_CFLAGS) $(TEST_FAST_LDFLAGS) -o "$$tmp" "@$(TEST_PARALLEL_FAST_LINK_RSP)" $(TOR_LIBS) $(LIBS) $(GTK_LIBS) $(WEBKIT_LIBS); \
	$(BUILD_EPOCH_SESSION_TOOL) verify "$(TEST_FAST_SESSION)" "$(TEST_FAST_LEASE)" \
	  "$(TEST_FAST_OBJ_ROOT)" "$(BIN_DIR)/test-fast" "$(BUILD_EPOCH_KEEP)" \
	  "$(BUILD_SOURCE_ID)" "$(BUILD_CLEAN)" "$(BUILD_MUTATION)" "$(BUILD_COMPILER_ID)" \
	  "$(TEST_FAST_COMPILE_EPOCH)" "$(TEST_FAST_PROFILE)" "$(TEST_FAST_EPOCH_COMPILE_FLAGS)" \
	  "$(TEST_FAST_EPOCH_LINK_FLAGS)" "$(CC)" "$(CXX)" "$$PPID" >/dev/null; \
	mv -f -- "$$tmp" "$@"; \
	trap - EXIT HUP INT TERM

# Expanding the complete object list inside a recipe makes the recipe itself
# one oversized `/bin/sh -c` argument on Linux.  GNU Make writes the exact,
# epoch-scoped prerequisite order directly; the compiler consumes it through a
# response file, keeping the shell command bounded without rediscovering or
# reordering objects from the filesystem.
$(TEST_PARALLEL_REL_LINK_RSP): $(TEST_PARALLEL_REL_OBJS)
	@$(if $(ZCL_MAKE_NO_EXEC),,$(file >$@,$(TEST_PARALLEL_REL_OBJS))) test -s "$@"

$(TEST_PARALLEL_FAST_LINK_RSP): $(TEST_PARALLEL_FAST_OBJS)
	@$(if $(ZCL_MAKE_NO_EXEC),,$(file >$@,$(TEST_PARALLEL_FAST_OBJS))) test -s "$@"

TEST_RESTART_BASE_RELOC = $(TEST_FAST_OBJ_DIR)/restart-base.o
$(TEST_RESTART_BASE_RELOC): $(TEST_PARALLEL_FAST_LINK_RSP) \
		$(TEST_PARALLEL_FAST_OBJS)
	@set -eu; \
	tmp="$$(mktemp "$@.XXXXXX")"; \
	trap 'rm -f "$$tmp"' EXIT HUP INT TERM; \
	$(CC) $(ZCL_DEV_LINKER) -r -nostdlib -o "$$tmp" \
	  "@$(TEST_PARALLEL_FAST_LINK_RSP)"; \
	chmod 0444 "$$tmp"; \
	mv -f -- "$$tmp" "$@"; \
	trap - EXIT HUP INT TERM

test-asan: $(TEST_ASAN_BIN)

$(TEST_ASAN_BIN): $(TEST_ASAN_CANDIDATE) FORCE
	@$(BUILD_EPOCH_PUBLISH_TOOL) "$(TEST_ASAN_CANDIDATE)" "$@" "$(TEST_ASAN_SESSION)" \
	  "$(BUILD_SOURCE_ID)" "$(BUILD_CLEAN)" "$(BUILD_MUTATION)" \
	  "$(TEST_ASAN_COMPILE_EPOCH)" "$(BUILD_COMPILER_ID)" "$(TEST_ASAN_PROFILE)" \
	  "$(TEST_ASAN_EPOCH_COMPILE_FLAGS)" "$(TEST_ASAN_EPOCH_LINK_FLAGS)" "$(CC)" "$(CXX)"

$(TEST_ASAN_CANDIDATE): $(VIEW_GEN_HEADERS) $(BUILD_IDENTITY_STAMP) $(TEST_ASAN_OBJS) $(TEST_ASAN_LINK_RSP) | $(VENDOR_LIBS)
	@mkdir -p $(dir $@)
	@set -eu; \
	tmp="$$(mktemp "$@.link.XXXXXX")"; \
	trap 'rm -f "$$tmp"' EXIT HUP INT TERM; \
	$(CC) $(TEST_ASAN_CFLAGS) $(TEST_ASAN_LDFLAGS) -o "$$tmp" "@$(TEST_ASAN_LINK_RSP)" $(TOR_LIBS) $(LIBS) $(GTK_LIBS) $(WEBKIT_LIBS); \
	$(BUILD_EPOCH_SESSION_TOOL) verify "$(TEST_ASAN_SESSION)" "$(TEST_ASAN_LEASE)" \
	  "$(TEST_ASAN_OBJ_ROOT)" "$(BIN_DIR)/test-asan-epochs" "$(BUILD_EPOCH_KEEP)" \
	  "$(BUILD_SOURCE_ID)" "$(BUILD_CLEAN)" "$(BUILD_MUTATION)" "$(BUILD_COMPILER_ID)" \
	  "$(TEST_ASAN_COMPILE_EPOCH)" "$(TEST_ASAN_PROFILE)" "$(TEST_ASAN_EPOCH_COMPILE_FLAGS)" \
	  "$(TEST_ASAN_EPOCH_LINK_FLAGS)" "$(CC)" "$(CXX)" "$$PPID" >/dev/null; \
	mv -f -- "$$tmp" "$@"; \
	trap - EXIT HUP INT TERM

$(TEST_ASAN_LINK_RSP): $(TEST_ASAN_OBJS)
	@$(if $(ZCL_MAKE_NO_EXEC),,$(file >$@,$(TEST_ASAN_OBJS))) test -s "$@"

test-tsan: $(TEST_TSAN_BIN)

$(TEST_TSAN_BIN): $(TEST_TSAN_CANDIDATE) FORCE
	@$(BUILD_EPOCH_PUBLISH_TOOL) "$(TEST_TSAN_CANDIDATE)" "$@" "$(TEST_TSAN_SESSION)" \
	  "$(BUILD_SOURCE_ID)" "$(BUILD_CLEAN)" "$(BUILD_MUTATION)" \
	  "$(TEST_TSAN_COMPILE_EPOCH)" "$(BUILD_COMPILER_ID)" "$(TEST_TSAN_PROFILE)" \
	  "$(TEST_TSAN_EPOCH_COMPILE_FLAGS)" "$(TEST_TSAN_EPOCH_LINK_FLAGS)" "$(CC)" "$(CXX)"

$(TEST_TSAN_CANDIDATE): $(VIEW_GEN_HEADERS) $(BUILD_IDENTITY_STAMP) $(TEST_TSAN_OBJS) $(TEST_TSAN_LINK_RSP) | $(VENDOR_LIBS)
	@mkdir -p $(dir $@)
	@set -eu; \
	tmp="$$(mktemp "$@.link.XXXXXX")"; \
	trap 'rm -f "$$tmp"' EXIT HUP INT TERM; \
	$(CC) $(TEST_TSAN_CFLAGS) $(TEST_TSAN_LDFLAGS) -o "$$tmp" "@$(TEST_TSAN_LINK_RSP)" $(TOR_LIBS) $(LIBS) $(GTK_LIBS) $(WEBKIT_LIBS); \
	$(BUILD_EPOCH_SESSION_TOOL) verify "$(TEST_TSAN_SESSION)" "$(TEST_TSAN_LEASE)" \
	  "$(TEST_TSAN_OBJ_ROOT)" "$(BIN_DIR)/test-tsan-epochs" "$(BUILD_EPOCH_KEEP)" \
	  "$(BUILD_SOURCE_ID)" "$(BUILD_CLEAN)" "$(BUILD_MUTATION)" "$(BUILD_COMPILER_ID)" \
	  "$(TEST_TSAN_COMPILE_EPOCH)" "$(TEST_TSAN_PROFILE)" "$(TEST_TSAN_EPOCH_COMPILE_FLAGS)" \
	  "$(TEST_TSAN_EPOCH_LINK_FLAGS)" "$(CC)" "$(CXX)" "$$PPID" >/dev/null; \
	mv -f -- "$$tmp" "$@"; \
	trap - EXIT HUP INT TERM

$(TEST_TSAN_LINK_RSP): $(TEST_TSAN_OBJS)
	@$(if $(ZCL_MAKE_NO_EXEC),,$(file >$@,$(TEST_TSAN_OBJS))) test -s "$@"

# Both active runners execute groups that spawn the fixed external package
# verifier. Build that exact in-tree helper here, not only on the public
# test-parallel wrapper: fast-ci/pre-push invokes the active fast runner
# directly, and a clean checkout must not depend on a leftover binary.
test-parallel-active:
	@mkdir -p "$(BUILD_DIR)"
	@$(CHECKOUT_LOCK_TOOL) foreground "$(CHECKOUT_LOCK)" -- \
	  $(MAKE) --no-print-directory test-parallel-active-locked

test-parallel-active-locked: $(TEST_PARALLEL_REL_CANDIDATE) dev-package-verifier-ensure
	ulimit -s unlimited && $(TEST_PARALLEL_REL_ACTIVE)

test-parallel-fast-active:
	@mkdir -p "$(BUILD_DIR)"
	@$(CHECKOUT_LOCK_TOOL) foreground "$(CHECKOUT_LOCK)" -- \
	  $(MAKE) --no-print-directory test-parallel-fast-active-locked

test-parallel-fast-active-locked: $(TEST_PARALLEL_FAST_CANDIDATE) dev-package-verifier-ensure
	ulimit -s unlimited && $(TEST_PARALLEL_FAST_ACTIVE)

.PHONY: test-parallel
# Checkout-locked (see CHECKOUT_LOCK above): the make_lint_gates exclusive lane
# plants a fixture into the live worktree (app/services/src/ and the repo root)
# and unlinks it, so two concurrent test_parallel processes racing this run
# inside ONE checkout is a real false-failure source, not just a build-object
# collision. It is per-checkout on purpose and that is sufficient: every path
# involved is worktree-relative, so two different worktrees cannot collide.
# Always foreground (the watcher never calls this target — it runs test_parallel
# through `make ff`, which is itself checkout-locked).
#
# The fixed development package verifier is a hard prerequisite because the
# ZCODE groups exec it.  Test/integration profiles deliberately use the
# non-LTO DEV_RESTART companion; the separately named release verifier remains
# part of `all` and release proof, never the focused-feedback critical path.
#
# TEST_PARALLEL_ARGS is empty by default, so the canonical gate is byte-for-byte
# the historical cold run; pass e.g. TEST_PARALLEL_ARGS=--cold-audit (verify the
# content cache) or --no-cache (force cold with ZCL_TEST_CACHE set).
test-parallel:
	@mkdir -p "$(BUILD_DIR)"
	@$(CHECKOUT_LOCK_TOOL) foreground "$(CHECKOUT_LOCK)" -- \
	  $(MAKE) --no-print-directory test-parallel-locked \
	    TEST_PARALLEL_ARGS='$(TEST_PARALLEL_ARGS)'

.PHONY: test-parallel-locked
test-parallel-locked: $(TEST_PARALLEL_REL_CANDIDATE) dev-package-verifier-ensure
	ulimit -s unlimited && $(TEST_PARALLEL_REL_ACTIVE) $(TEST_PARALLEL_ARGS)

# ── Fast inner loop ──────────────────────────────────────────────────────
# The edit -> check -> test loop runs dozens of times per session. Use these,
# NOT `make` + `build/bin/test_zcl` (8-15 min) and NOT a bare `build/bin/test_parallel`.
#
# THE REBUILD TRAP: plain `make` does NOT rebuild test_parallel (it is not in
# the default `all`), so running build/bin/test_parallel directly after editing a test
# can false-green an old binary or report "matched no groups" for a new test.
# `make t ONLY=<group>` always rebuilds the harness first, closing that trap.
.PHONY: t t-fast t-fast-exact t-asan asan-ci t-tsan tsan-ci t-changed ff verify-change watcher-safety-gates syntax-check build-only fast-compile fast-changed-compile dev-build-only dev-bin dev-asan z23-dev-asan zclassic23-dev-asan dev-tsan z23-dev-tsan zclassic23-dev-tsan z23-dev zclassic23-dev fast-rebuild rebuild-fast dev-rebuild hot-rebuild super-rebuild lint-fast fast-ci agent-fast-ci dev-ci agent-plan agent-loop agent-dev-loop dev-watch dev-watch-once dev-watch-selftest dev-activation-selftest dev-loop-selftest native-dev-loop-wait-selftest native-dev-failure-selftest agent-index compdb dev-loop-bench dev-loop-bench-selftest hotswap-sim immutable-history-canaries historical-canaries agent-dev-status agent-dev-recover dev-recovery-selftest agent-clear-stale-dev-reindex agent-doctor doctor-build stage-dev-bin agent-stage-dev deploy-dev-fast agent-deploy-fast

# ── ONLY= is validated BEFORE anything compiles ──────────────────────────
# Every focused target below carried its ONLY= check in the RECIPE. Make builds
# prerequisites before it runs a recipe, so that check could not fire until the
# whole test binary had already been linked. Two failures followed from it:
#
#   make t-fast ONLY=<substring>    (the placeholder typed literally, straight
#                                    out of CLAUDE.md) paid a full test-binary
#                                    compile and then died in the shell with
#                                    `Syntax error: end of file unexpected`,
#                                    because `<substring>` was pasted unquoted
#                                    into the recipe's sh -c and read as a
#                                    redirection.
#   make t-fast ONLY=typoed_name    paid the same compile to learn the name
#                                    matched nothing.
#
# The validation therefore runs at Makefile PARSE time — before make considers
# a single prerequisite — and resolves ONLY= against the registered group list
# using the runner's own substring rule (tools/dev/test-group-list.sh, which
# reads the X-macro registry directly and needs no build).
#
# That resolution is also what makes the recipes' unquoted `--only=$(ONLY)`
# safe, and the reason is worth stating rather than assuming: a value only gets
# past the guard if it is a literal substring of a registered group name, and
# every registered name is [A-Za-z_0-9] only. So by the time a recipe runs,
# ONLY cannot contain a redirection, a quote, a space, or any other shell
# metacharacter. `<substring>` never reaches sh at all.
T_LIST_TOOL := tools/dev/test-group-list.sh
ONLY_REQUIRED_GOALS := t t-fast t-tsan
ONLY_SELECTOR_GOALS := $(ONLY_REQUIRED_GOALS) t-asan
ONLY_ACTIVE_GOALS := $(filter $(ONLY_SELECTOR_GOALS),$(MAKECMDGOALS))
ifneq ($(ONLY_ACTIVE_GOALS),)
  ONLY_GOAL := $(firstword $(ONLY_ACTIVE_GOALS))
  ifeq ($(strip $(ONLY)),)
    ifneq ($(filter $(ONLY_REQUIRED_GOALS),$(ONLY_ACTIVE_GOALS)),)
      $(error make $(ONLY_GOAL): ONLY= is required and must name a test group. \
        usage: make $(ONLY_GOAL) ONLY=<group-substr>   e.g. make $(ONLY_GOAL) ONLY=boot_phase. \
        List every registered group with: make t-list)
    endif
  else
    # A single quote in ONLY= would break the quoting below; reject it rather
    # than let it reach a shell.
    ifneq ($(findstring ',$(ONLY)),)
      $(error make $(ONLY_GOAL): ONLY= must not contain a single quote)
    endif
    ONLY_MATCHED := $(shell $(T_LIST_TOOL) --match '$(ONLY)' 2>/dev/null)
    ifeq ($(strip $(ONLY_MATCHED)),)
      ONLY_NEAR := $(shell $(T_LIST_TOOL) --suggest '$(ONLY)' 2>/dev/null | tr '\n' ' ')
      ifeq ($(strip $(ONLY_NEAR)),)
        ONLY_NEAR := (none — see `make t-list`)
      endif
      $(error make $(ONLY_GOAL): ONLY='$(ONLY)' matches NO registered test group — \
        refusing before the test binary is built. \
        Closest candidates: $(ONLY_NEAR))
    endif
    $(info $(ONLY_GOAL): ONLY='$(ONLY)' selects $(words $(ONLY_MATCHED)) group(s): $(ONLY_MATCHED))
  endif
endif

# Proof automation never dispatches a substring selector. Canonicalize every
# requested ID before any prerequisite is considered, then hand the complete
# full-ID set to the runner's exact selector.
EXACT_ONLY_ACTIVE_GOALS := $(filter t-fast-exact,$(MAKECMDGOALS))
ifneq ($(EXACT_ONLY_ACTIVE_GOALS),)
  ifeq ($(strip $(ONLY)),)
    $(error make t-fast-exact: ONLY= is required and must name one or more exact test groups)
  endif
  ifneq ($(findstring ',$(ONLY)),)
    $(error make t-fast-exact: ONLY= must not contain a single quote)
  endif
  override EXACT_ONLY_MATCHED := $(shell $(T_LIST_TOOL) --resolve-exact-set '$(ONLY)' 2>/dev/null)
  ifeq ($(strip $(EXACT_ONLY_MATCHED)),)
    $(error make t-fast-exact: ONLY='$(ONLY)' is not a valid exact registered group set)
  endif
  $(info t-fast-exact: ONLY='$(ONLY)' resolves to exact set $(EXACT_ONLY_MATCHED))
endif

# Print every REGISTERED test group, one per line. No build, no test binary —
# it parses the X-macro registry in lib/test/src/test_parallel.c. This is THE
# documented way to enumerate groups; the old `git grep -hoE 'X\(...\)'`
# incantation drops the test_/spec_ prefixes and mislabels 28 spec groups.
.PHONY: t-list
t-list:
	@$(T_LIST_TOOL)

# One memorable custody regression command for contributors. Keep the list
# exact: a substring silently selecting a sibling group is not rollout proof.
CUSTODY_FOCUSED_TESTS := test_agent_session,test_agent_spend_policy,test_vault_session,test_vault_dispatch,test_transaction_intent,test_metaverse_agent_broker
.PHONY: custody-check custody-bind custody-bind-selftest custody-status custody-status-selftest \
	dev-wallet-credential-setup dev-wallet-credential-status \
	transaction-micro-lab-wallets-setup transaction-micro-lab-wallets-status \
	transaction-micro-lab-wallets-selftest
custody-check:
	@$(MAKE) --no-print-directory t-fast-exact ONLY='$(CUSTODY_FOCUSED_TESTS)'
	@echo "custody-check: PASS — no live wallet or funds were touched"

# Owner-only, value-free provisioning for private money bindings. ARGS may set
# --wallet-scope=dev|prod|portfolio; portfolio is the default. A scoped setup
# never probes or requires the other wallet. Endpoint-bearing state stays
# outside Git under mode 0600. No funds are moved.
custody-bind:
	@tools/dev/custody-bind.sh setup $(ARGS)

custody-bind-selftest:
	@tools/dev/custody-bind.sh selftest

# Read-only live rollout doctor. With no ARGS it reads custody-bind's private
# default; ARGS may name a different owner-created private broker directory.
custody-status:
	@tools/dev/custody-status.sh $(ARGS)

custody-status-selftest:
	@ZCL_CUSTODY_STATUS_SELFTEST=1 tools/dev/custody-status.sh

dev-wallet-credential-setup:
	@tools/dev/dev-wallet-credential.sh setup

dev-wallet-credential-status:
	@tools/dev/dev-wallet-credential.sh status

# Value-free preparation for the live micro lab. The setup creates two fresh
# isolated receive wallets, derives transparent + Sapling recipients, stores
# only private mode-0600 address manifests, stops both nodes, and prints no
# address/key/path. It never funds, reserves, signs, or broadcasts.
transaction-micro-lab-wallets-setup:
	@tools/dev/transaction-micro-lab-wallets.sh setup $(ARGS)

transaction-micro-lab-wallets-status:
	@tools/dev/transaction-micro-lab-wallets.sh status $(ARGS)

transaction-micro-lab-wallets-selftest:
	@tools/dev/transaction-micro-lab-wallets.sh selftest

# Transaction-lab evidence is deliberately split from live mainnet spending.
# These exact groups exercise production transaction builders, signatures,
# Sapling proofs, consensus verification, script interpretation, and isolated
# settlement projections without contacting a live wallet.
# Derived from the notebook catalog so adding a case cannot silently omit its
# proof from `make transaction-lab-proof`. The check also requires an exact
# posture row in tools/dev/transaction_live_catalog.def, preventing a new type
# from silently escaping the live runbook. Stable sort deduplicates groups
# shared by several semantic transaction types.
TRANSACTION_LAB_PROOF_TESTS := $(shell { \
	awk -F'|' 'substr($$0, 1, 1) != sprintf("%c", 35) && NF { print $$5 }' tools/dev/transaction_lab_catalog.def; \
	awk -F'"' '/^TX_TYPE_SUPPLEMENTAL/ { print $$4 }' app/controllers/include/controllers/transaction_type_supplemental_tests.def; \
	} | sort -u | paste -sd, -)
.PHONY: transaction-lab-status transaction-lab-check transaction-lab-proof \
	transaction-micro-lab-status transaction-micro-lab-check
transaction-lab-status:
	@tools/dev/transaction-lab.sh status

transaction-lab-check: transaction-micro-lab-check
	@tools/dev/transaction-lab.sh check
	@tools/dev/transaction-lab.sh selftest

transaction-lab-proof:
	@ZCL_PARAMS_TESTS=1 ZCL_STRESS_TESTS=1 \
	 $(MAKE) --no-print-directory t-fast-exact ONLY='$(TRANSACTION_LAB_PROOF_TESTS)'
	@tools/dev/transaction-lab.sh status

# Redacted evidence notebook for the bounded 100 x 1,000-zatoshi campaign.
# These targets never plan, sign, authorize, broadcast, or touch a datadir.
transaction-micro-lab-status:
	@tools/dev/transaction-micro-lab.sh status

transaction-micro-lab-check:
	@tools/dev/transaction-micro-lab.sh check
	@tools/dev/transaction-micro-lab.sh selftest

# ── Agent-harness reporting targets ──────────────────────────────────────
# Three read-only targets the orchestrator was doing by hand. None builds,
# none writes anything, none touches a datadir.
.PHONY: test-registry-report agent-baseline worktree-gc

# Which registered groups did a run actually EXECUTE, and why not the rest.
# Reads the runner's own .cache/test-timing/last-run.json as the evidence for
# EXECUTED; override with ZCL_TEST_TIMING_JSON=<path> to reconcile against a
# run recorded in another checkout. Exits non-zero on an UNACCOUNTED-FOR group.
test-registry-report:
	@tools/dev/test-registry-report.sh

# The lane pin, as key=value. Deterministic, no timestamp — two runs on the
# same tree are byte-identical, which is the whole point.
#   make agent-baseline BASELINE_FILES="core/MANIFEST.sha3 Makefile"
# The lint gate count is passed from $(words $(LINT_GATES)) — the umbrella's
# own definition — rather than re-counted from a doc that can go stale.
agent-baseline:
	@ZCL_BASELINE_LINT_GATES='$(words $(LINT_GATES))' \
	 BASELINE_FILES='$(BASELINE_FILES)' tools/dev/agent-baseline.sh

# Classify every git worktree and remove only the provably dead ones.
# DRY RUN by default; --apply is required before anything is deleted. This is a
# convenience wrapper — the collector is tools/scripts/worktree_gc.sh, which is
# also what the zclassic23-worktree-gc systemd unit runs, and there is exactly
# one of it on purpose. Two collectors with different safety flags is how the
# wrong one gets run.
#   make worktree-gc                          dry run: classify, report bytes
#   make worktree-gc APPLY=1                  remove the SAFE bucket
worktree-gc:
	@tools/scripts/worktree_gc.sh $(if $(APPLY),--apply)

# ── Gate receipts: a lane's claims, checkable without re-running them ─────
# "make lint passed" costs the orchestrator a full re-run to verify, and has
# been wrong twice here (a test green only because it read the live node's
# datadir; a lint gate CLEAN because printf|grep -q inverted under pipefail).
# Wrap the gate instead: the receipt is a byproduct of running it, holding the
# command, HEAD, dirty state, exit status, wall/child-CPU time, and a SHA3 of
# the captured output, which is stored alongside. See the forgery model in
# tools/agent/gate-receipt.sh — this is EVIDENCE, not proof.
.PHONY: gate-receipt check-claims agent-velocity agent-sha3

AGENT_SHA3_SRCS := tools/agent/agent_sha3.c lib/sha3/src/sha3.c lib/crypto/src/keccak_x4.c lib/crypto/src/simd_dispatch.c
agent-sha3: $(BIN_DIR)/agent_sha3
$(BIN_DIR)/agent_sha3: $(AGENT_SHA3_SRCS)
	@mkdir -p $(dir $@)
	$(CC) -std=c23 -O2 -Wall -Wextra -Werror \
	    -Ilib/sha3/include -Ilib/crypto/include -Ilib/support/include -Ilib/base/include \
	    -o $@ $(AGENT_SHA3_SRCS)

# Independent package gates compile only the authoritative package trees and
# their declared direct dependencies.  They never open a node datadir.
ZCODE_PACKAGE_BASE_TEST_BIN := $(BIN_DIR)/zcode-package-base-test
ZCODE_PACKAGE_SHA3_TEST_BIN := $(BIN_DIR)/zcode-package-sha3-test
ZCODE_PACKAGE_CODEC_TEST_BIN := $(BIN_DIR)/zcode-package-codec-test
ZCODE_PACKAGE_BASE_ASAN_BIN := $(BIN_DIR)/zcode-package-base-test-asan
ZCODE_PACKAGE_SHA3_ASAN_BIN := $(BIN_DIR)/zcode-package-sha3-test-asan
ZCODE_PACKAGE_CODEC_ASAN_BIN := $(BIN_DIR)/zcode-package-codec-test-asan
ZCODE_PACKAGE_REGISTRY_CHECK_BIN := $(BIN_DIR)/zcode-package-registry-check
.PHONY: zcode-package-base-test zcode-package-sha3-test zcode-package-codec-test zcode-package-foundation-test zcode-package-asan zclassic23-package-sign
zcode-package-base-test: $(ZCODE_PACKAGE_BASE_TEST_BIN)
	@$(ZCODE_PACKAGE_BASE_TEST_BIN)
$(ZCODE_PACKAGE_BASE_TEST_BIN): lib/base/tests/test_base.c \
		lib/base/tests/cleanse_probe.c lib/base/src/cleanse.c \
		lib/base/src/log_level.c lib/base/src/result.c \
		lib/base/src/safe_alloc.c
	@mkdir -p $(dir $@)
	$(CC) -std=c23 -O3 -flto -Wall -Wextra -Werror -pedantic \
	    -D_POSIX_C_SOURCE=200809L -Ilib/base/include -o $@ $^

zcode-package-sha3-test: $(ZCODE_PACKAGE_SHA3_TEST_BIN)
	@$(ZCODE_PACKAGE_SHA3_TEST_BIN)
$(ZCODE_PACKAGE_SHA3_TEST_BIN): lib/sha3/tests/test_sha3.c \
		lib/sha3/src/sha3.c
	@mkdir -p $(dir $@)
	$(CC) -std=c23 -O2 -Wall -Wextra -Werror -pedantic \
	    -Ilib/sha3/include -Ilib/base/include -o $@ $^

zcode-package-codec-test: $(ZCODE_PACKAGE_CODEC_TEST_BIN)
	@$(ZCODE_PACKAGE_CODEC_TEST_BIN)
$(ZCODE_PACKAGE_CODEC_TEST_BIN): lib/codec/tests/test_codec.c \
		lib/codec/src/cursor.c
	@mkdir -p $(dir $@)
	$(CC) -std=c23 -O2 -Wall -Wextra -Werror -pedantic \
	    -Ilib/codec/include -Ilib/base/include -o $@ $^

zcode-package-foundation-test: zcode-package-base-test zcode-package-sha3-test zcode-package-codec-test

# Permanent memory/undefined-behavior gate for the self-hosted package
# foundation and its complete signed evidence lifecycle.  The first three
# binaries compile ONLY each authoritative package tree plus its declared
# direct dependencies; the monolith groups then prove the same sources through
# prepare/seal, registry, accepted-lane publication, work/proof/PROVEN and
# score paths.  No sanitizer class is suppressed.  Keep this opt-in: like the
# DHT sanitizer lane it is deliberately too expensive for every pre-push.
ZCODE_PACKAGE_ASAN_FLAGS := -fsanitize=address,undefined -fno-omit-frame-pointer -O2 -g
ZCODE_PACKAGE_ASAN_GROUPS := test_base_foundation test_codec_cursor \
	test_sha3_256_x4 test_sha3_512_x4 test_zcode_score_receipt \
	test_zcode_shadow_policy \
	test_zcode_package_registry test_zcode_store test_zcode_publish \
	test_zcode_package_dev test_zcode_recipe test_zcode_verify \
	test_zcode_dev_objects

$(ZCODE_PACKAGE_BASE_ASAN_BIN): lib/base/tests/test_base.c \
		lib/base/tests/cleanse_probe.c lib/base/src/cleanse.c
	@mkdir -p $(dir $@)
	$(CC) -std=c23 $(ZCODE_PACKAGE_ASAN_FLAGS) -Wall -Wextra -Werror -pedantic \
	    -Ilib/base/include -o $@ $^

$(ZCODE_PACKAGE_SHA3_ASAN_BIN): lib/sha3/tests/test_sha3.c \
		lib/sha3/src/sha3.c
	@mkdir -p $(dir $@)
	$(CC) -std=c23 $(ZCODE_PACKAGE_ASAN_FLAGS) -Wall -Wextra -Werror -pedantic \
	    -Ilib/sha3/include -Ilib/base/include -o $@ $^

$(ZCODE_PACKAGE_CODEC_ASAN_BIN): lib/codec/tests/test_codec.c \
		lib/codec/src/cursor.c
	@mkdir -p $(dir $@)
	$(CC) -std=c23 $(ZCODE_PACKAGE_ASAN_FLAGS) -Wall -Wextra -Werror -pedantic \
	    -Ilib/codec/include -Ilib/base/include -o $@ $^

zcode-package-asan: $(ZCODE_PACKAGE_BASE_ASAN_BIN) \
		$(ZCODE_PACKAGE_SHA3_ASAN_BIN) $(ZCODE_PACKAGE_CODEC_ASAN_BIN) \
		$(BIN_DIR)/zclassic23-package-verify
	@$(CHECKOUT_LOCK_TOOL) foreground "$(CHECKOUT_LOCK)" -- \
	  sh -c 'set -e; ulimit -s 1048576; \
	  export UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1; \
	  for t in $(ZCODE_PACKAGE_BASE_ASAN_BIN) $(ZCODE_PACKAGE_SHA3_ASAN_BIN) $(ZCODE_PACKAGE_CODEC_ASAN_BIN); do \
	    echo "zcode-package-asan: --- $$t ---"; "$$t"; \
	  done'
	@$(MAKE) --no-print-directory asan-ci \
	  ASAN_CI_GROUPS='$(ZCODE_PACKAGE_ASAN_GROUPS)'
	@echo "zcode-package-asan: OK (isolated base/sha3/codec + signed package lifecycle)"

.PHONY: check-zcode-package-registry print-zcode-monolith-lib-sources
check-zcode-package-registry: $(ZCODE_PACKAGE_REGISTRY_CHECK_BIN)
	@tools/lint/check_zcode_package_registry.sh
print-zcode-monolith-lib-sources:
	@printf '%s\n' $(LIB_SRCS)
$(ZCODE_PACKAGE_REGISTRY_CHECK_BIN): tools/zcode_package_registry_check.c \
        config/zcode_package_registry.def \
		config/zcode_c23_commons_app.def \
		lib/vcs/src/package_prepare.c lib/vcs/src/package_manifest.c \
		lib/vcs/src/package_recipe.c lib/vcs/src/package_deps.c \
		lib/vcs/src/package_capsule.c lib/vcs/src/package_release.c \
		lib/json/src/json.c lib/codec/src/cursor.c lib/sha3/src/sha3.c \
		lib/base/src/safe_alloc.c lib/base/src/log_level.c \
		lib/platform/src/clock.c
	@mkdir -p $(dir $@)
	$(CC) -std=c23 -D_GNU_SOURCE -O0 -Wall -Wextra -Werror -pedantic \
	    -Ilib/vcs/include -Ilib/json/include -Ilib/codec/include -Ilib/sha3/include \
	    -Ilib/crypto/include -Ilib/base/include -Ilib/util/include \
	    -Ilib/platform/include -Ivendor/include -o $@ $(filter %.c,$^) \
	    -Lvendor/lib -l:libsecp256k1.a -lpthread -lm

zclassic23-package-sign: $(BIN_DIR)/zclassic23-package-sign
$(BIN_DIR)/zclassic23-package-sign: FORCE tools/zcode_dev_signer.c lib/base/src/cleanse.c
	@mkdir -p $(dir $@)
	$(CC) -std=c23 -O2 -Wall -Wextra -Werror -pedantic \
	    -Ilib/base/include -Ivendor/include -o $@ $(filter-out FORCE,$^) \
	    -Lvendor/lib -l:libsecp256k1.a -lpthread -lm

# Run a gate and leave a receipt. The wrapper is transparent — same output,
# same exit status — so this is a drop-in for the bare command:
#   make gate-receipt GATE=lint CMD='make lint'
#   make gate-receipt GATE=t-fast CMD='make t-fast ONLY=boot_phase'
# Or call it directly, which avoids a second Makefile parse:
#   tools/agent/gate-receipt.sh --gate lint -- make lint
gate-receipt:
	@if [ -z "$(GATE)" ] || [ -z "$(CMD)" ]; then \
	    echo "usage: make gate-receipt GATE=<slug> CMD='<command>'"; \
	    echo "  e.g. make gate-receipt GATE=lint CMD='make lint'"; \
	    exit 2; \
	fi
	@RECEIPTS='$(RECEIPTS)'; \
	 tools/agent/gate-receipt.sh --gate '$(GATE)' \
	    $${RECEIPTS:+--dir "$$RECEIPTS"} -- $(CMD)

# Verify a lane's gate claims from its receipts. Non-zero if a claimed gate
# has no receipt, if a receipt does not describe the current HEAD, or if the
# stored output no longer backs the verdict.
#   make check-claims CLAIMS="lint t-fast"
check-claims:
	@RECEIPTS='$(RECEIPTS)'; \
	 tools/agent/check-claims.sh $${RECEIPTS:+--dir "$$RECEIPTS"} \
	    $(if $(CLAIMS),--require '$(CLAIMS)') $(if $(STRICT),--strict)

# What a lane cost and produced, computed rather than remembered. Everything
# that is not mechanically derivable is printed as a NOT-DERIVABLE line naming
# what the orchestrator must supply — never silently omitted.
#   make agent-velocity BASE=b82b40e77
agent-velocity:
	@RECEIPTS='$(RECEIPTS)'; \
	 tools/agent/agent-velocity.sh $(if $(BASE),--base '$(BASE)') \
	    $(if $(HEAD),--head '$(HEAD)') $(if $(AGAINST),--against '$(AGAINST)') \
	    $${RECEIPTS:+--receipts "$$RECEIPTS"}

# Run ONE test group, always rebuilding the harness first:
#   make t ONLY=service_state_driver
# Checkout-locked around BOTH prerequisite construction and execution. Locking
# only this target's final recipe allowed a concurrent public invocation to
# rewrite build depfiles while codeindex was sealing its physical input graph.
.PHONY: t-locked t-fast-locked t-fast-exact-locked
t:
	@mkdir -p "$(BUILD_DIR)"
	@$(CHECKOUT_LOCK_TOOL) foreground "$(CHECKOUT_LOCK)" -- \
	  $(MAKE) --no-print-directory t-locked ONLY='$(ONLY)'

t-locked: $(TEST_PARALLEL_REL_CANDIDATE) dev-package-verifier-ensure
	ulimit -s unlimited && $(TEST_PARALLEL_REL_ACTIVE) --only=$(ONLY)

# Hot-path variant for edit loops. It resolves the complete source inventory in
# a cached, stable (toolchain+flags-keyed) per-file epoch and links a non-LTO harness; use strict `make t`
# before push/release or when chasing optimizer-dependent behavior.
# Checkout-locked around prerequisite construction and execution.
t-fast:
	@mkdir -p "$(BUILD_DIR)"
	@$(CHECKOUT_LOCK_TOOL) foreground "$(CHECKOUT_LOCK)" -- \
	  $(MAKE) --no-print-directory t-fast-locked ONLY='$(ONLY)'

t-fast-locked: $(TEST_PARALLEL_FAST_CANDIDATE) dev-package-verifier-ensure
	ulimit -s unlimited && $(TEST_PARALLEL_FAST_ACTIVE) --only=$(ONLY)

# Proof-facing sibling of t-fast. The human convenience target above keeps its
# documented substring behavior; impact plans and durable receipts use this
# exact-ID path so a stale mapping cannot pass by selecting a sibling group.
t-fast-exact:
	@mkdir -p "$(BUILD_DIR)"
	@$(CHECKOUT_LOCK_TOOL) foreground "$(CHECKOUT_LOCK)" -- \
	  $(MAKE) --no-print-directory t-fast-exact-locked \
	    EXACT_ONLY_MATCHED='$(EXACT_ONLY_MATCHED)'

t-fast-exact-locked: $(TEST_PARALLEL_FAST_CANDIDATE) dev-package-verifier-ensure
	ulimit -s unlimited && \
	  $(TEST_PARALLEL_FAST_ACTIVE) --exact=$(EXACT_ONLY_MATCHED)

# Closed historical-failure corpus required by build_release_confirmation.v2.
# This focused physical gate is uncached and exact; release qualification also
# requires the candidate-bound all-groups test action and its canonical proof
# set, so this convenience target is evidence preparation, never qualification.
SECURE_RELEASE_REGRESSION_GROUPS := test_sqlite,test_boot_stale_locks,test_build_fabric,test_coins,test_accept_to_mempool,test_zcode_dht_service,test_zcode_swarm,test_utxo_mirror_sync,test_addrman_shutdown_race,test_dev_activation,test_wallet_flush_rollback,test_reorg_safety

.PHONY: secure-release-regressions secure-release-regressions-locked
secure-release-regressions:
	@mkdir -p "$(BUILD_DIR)"
	@$(CHECKOUT_LOCK_TOOL) foreground "$(CHECKOUT_LOCK)" -- \
	  $(MAKE) --no-print-directory secure-release-regressions-locked

secure-release-regressions-locked: $(TEST_PARALLEL_REL_CANDIDATE) dev-package-verifier-ensure
	@tools/dev/secure-release-regressions-selftest.sh \
	  '$(SECURE_RELEASE_REGRESSION_GROUPS)'
	ulimit -s unlimited && $(TEST_PARALLEL_REL_ACTIVE) \
	  --exact=$(SECURE_RELEASE_REGRESSION_GROUPS) --no-cache

# ── the front door ───────────────────────────────────────────────────────
# `make commons-demo` is the one command that shows the whole product: a
# person asks for behavior, their node reuses C23 from a peer, creates only
# what is missing, shows the result, a second node reproduces the exact
# bytes, tampering is refused by name, the person accepts, and the accepted
# application runs. Then the publisher process is killed and a third node
# still discovers, fetches, reproduces and runs those exact bytes from the
# remaining seeder. Three fresh isolated datadirs; nothing outside this
# machine is contacted after the build. Exit 0 means every one of those held.
#
# It is deliberately not part of `make ci`: it spawns three real regtest
# daemons, mines a regtest chain and runs confined package builds.
.PHONY: commons-demo commons-journey-acceptance
commons-demo: zclassic23 zcl-rpc zclassic23-package-sign zclassic23-package-verify tools/arena-product-journey-c23
	@bash tools/dev/commons_journey_acceptance.sh

# The same proof under its acceptance name, for scripts and release notes.
commons-journey-acceptance: commons-demo

# The SAME journey with nodes B and C on their own physical hosts. The
# publisher's machine itself is gone; host C still discovers, fetches,
# reproduces and runs the exact accepted bytes from B. Requires:
#   CJ_HOST_B=user@hostB  CJ_HOST_C=user@hostC   (BatchMode ssh, cc present)
#   CJ_PEER_ADDR_A=<this host's LAN address>     (B and C dial it)
#   optional: CJ_PEER_ADDR_B / CJ_PEER_ADDR_C    (default: ssh host parts)
# Fails closed without them. Deliberately not part of `make ci` and not the
# front door: `make commons-demo` stays the fast same-host proof.
.PHONY: commons-multihost-acceptance
commons-multihost-acceptance: zclassic23 zcl-rpc zclassic23-package-sign zclassic23-package-verify tools/arena-product-journey-c23
	@ZCL_COMMONS_MULTIHOST=1 bash tools/dev/commons_journey_acceptance.sh

.PHONY: zcode-development-acceptance zcode-adapter-readiness-acceptance zcode-c23-commons-alpha zcode-dht-harness-selftest zcode-async-proof-acceptance zcode-async-proof-scaling public-node-coin-generation-matrix sovereign-source-roundtrip native-agent-ui-alpha native-agent-ui-physical-acceptance arena-product-journey
zcode-development-acceptance:
	@$(MAKE) --no-print-directory t-fast-exact ONLY=test_zcode_package_dev

# No-model proof that the native CLI can independently check every prerequisite
# for the fixed, confined Codex adapter across the frozen twelve-task corpus.
zcode-adapter-readiness-acceptance: $(BIN_DIR)/z23 \
		$(BIN_DIR)/zclassic23-zcode-adapter-runner
	@tools/dev/zcode_adapter_benchmark.sh preflight

# One product proof for the C23 Commons Alpha. The two exact groups remain the
# owners of their generic, data-driven scenarios: package_registry proves all
# ten declarative builds, independent reproduction, the standalone stranger
# application and two monolith dogfood consumers; swarm_net proves the signed
# four-node P2P lifecycle, publisher disappearance and cold/repeat/edit/revert
# accounting. The structural gates bind the same graph to exact-once monolith
# source ownership and keep ZVCS independent of Git/Git SHA-1 while stable
# publication remains separately contained. Do not split this into per-package
# runners: config/zcode_package_registry.def is the package parameter set.
zcode-c23-commons-alpha:
	@$(MAKE) --no-print-directory check-zcode-package-registry
	@$(MAKE) --no-print-directory t-fast-exact \
	  ONLY='test_zcode_package_registry,test_zcode_swarm_net'
	@$(MAKE) --no-print-directory check-vcs-no-git check-vcs-no-sha1 \
	  check-stable-publish-contained
	@printf '%s\n' '{"schema":"zcl.c23_commons_alpha_acceptance.v1","verdict":"PASS","package_count":10,"dependency_levels":3,"package_graph_validation":true,"standalone_build":true,"four_node_lifecycle":true,"independent_reproduction":true,"incremental_transfer":true,"sample_application":true,"internal_dogfood_consumers":2,"vcs_git_free":true,"vcs_sha1_free":true,"stable_publish_contained":true}'

# Runs the real DHT fixture's central lifecycle boundary without booting full
# nodes: concurrent owners, a forced middle failure, signal cleanup, immediate
# port reuse, and an uncontaminated rerun are all fail-closed assertions.
zcode-dht-harness-selftest: tools/arena-product-journey-c23
	@DHT_LIFECYCLE_MODE=selftest bash tools/dev/zcode_dht_acceptance.sh

# Zero-wait development protocol acceptance. The exact groups jointly prove
# three interchangeable signed work nodes, dead-peer retry/stale-result
# refusal, the append-only requester ledger, and the user-facing local path.
zcode-async-proof-acceptance: zclassic23 zcl-rpc tools/arena-product-journey-c23
	@$(MAKE) --no-print-directory zcode-dht-harness-selftest
	@$(MAKE) --no-print-directory t-fast-exact \
	  ONLY='test_build_fabric,test_zcode_dev_objects,test_zcode_package_dev'
	@$(MAKE) --no-print-directory check-vcs-no-git
	@DHT_PACKAGEHOST=1 DHT_BUILDWORKERS=1 \
	  DHT_AFTER_SPARSE_HOOK="$(CURDIR)/tools/dev/zcode_async_proof_acceptance_hook.sh" \
	  bash tools/dev/zcode_dht_acceptance.sh

# One installed-product story for the exact zdogace pursuit-sign correction.
# The wrapper builds an ordinary portable product, changes cwd outside this
# checkout, then composes the existing authenticated seven-node/DHT owner with
# the accepted-work, publication, package, and Arena authorities.  It is
# deliberately opt-in: real isolated daemons and confined build workers run.
arena-product-journey:
	@bash tools/dev/arena_product_journey.sh

# One browser-free product proof for the AI-controlled native C23 UI. The two
# exact semantic owners prove model sensitivity, provenance labels, bounded
# actions and publication plan/commit separation. The physical phase measures
# cold/warm/replacement latency on real native windows and returns a real user
# action through the display-only host. Full Stranger Beta remains an explicit
# prerequisite, so smooth presentation can never hide a broken installed
# obtain/verify/reproduce/use journey.

# The physical-only target deliberately consumes an already audited node. Use
# native-agent-ui-alpha as the public front door: it establishes the portable
# compiler/sysroot first, avoiding any accidental host-ABI or optional-Tor
# relink between the product build and the window proof.
native-agent-ui-physical-acceptance: native-ui-driver
	@test -x "$(ZCLASSIC23_BIN)" || { \
	  echo 'native-agent-ui: missing audited node; run make native-agent-ui-alpha' >&2; \
	  exit 1; \
	}
	@tools/scripts/check_c23_node_binary.sh "$(ZCLASSIC23_BIN)" >/dev/null
	@bash tools/dev/native_agent_ui_alpha_acceptance.sh

native-agent-ui-alpha:
	@$(MAKE) --no-print-directory c23-portable-release
	@$(MAKE) --no-print-directory native-ui-driver
	@$(MAKE) --no-print-directory native-agent-ui-physical-acceptance
	@$(MAKE) --no-print-directory t-fast-exact \
	  ONLY='test_qr,test_syncdiag_rpc,test_zcode_publish'
	@$(MAKE) --no-print-directory zcode-c23-commons-alpha
	@$(MAKE) --no-print-directory native-ui-driver
	@C23_BETA_NATIVE_UI_JOURNEY=1 \
	  C23_BETA_NATIVE_UI_DRIVER="$(CURDIR)/$(NATIVE_UI_DRIVER_BIN)" \
	  bash tools/dev/c23_commons_beta_acceptance.sh
	@printf '%s\n' '{"schema":"zcl.c23_commons_beta_acceptance.v1","verdict":"PASS","alpha_regression_floor":true,"installed_stranger_journey":true,"corrupt_provider_bytes_rejected":true,"alternate_provider_exact_root_repair":true,"interrupted_download_resumes_same_graph":true,"verified_objects_retransmitted_after_restart":0}'
	@printf '%s\n' '{"schema":"zcl.native_agent_ui_alpha.v1","verdict":"PASS","renderer_neutral_model":true,"resident_same_binary_host":true,"bounded_keyboard_pagination":true,"visible_action_focus":true,"tab_enter_actions":true,"bounded_sessions_under_load":true,"no_detached_capacity_escape":true,"no_stale_screens":true,"no_lost_decisions":true,"no_orphan_processes_after_restart":true,"blockchain_and_package_work_concurrent":true,"progress_host_restart_resume":true,"configured_agent_typed_views":true,"typed_qr":true,"typed_status":true,"typed_code_diff":true,"typed_development_consequence":true,"typed_reproduction_progress":true,"exact_publication_confirmation":true,"exact_publication_progress":true,"installed_package_change_journey":true,"agent_visual_requests":9,"human_actions":1,"visual_authority":"none","authored_ux":"c23","browser_required":false,"headless_refusal_named":true,"stranger_beta_green":true}'

# Measurement-only scaling campaign over the same three interchangeable full
# nodes.  It creates no lifecycle/cache authority beyond canonical immutable
# task/action/receipt rows and emits an artifact-backed timing CSV/report.
zcode-async-proof-scaling: zclassic23 zcl-rpc
	@DHT_PACKAGEHOST=1 DHT_BUILDWORKERS=1 DHT_KEEP=1 \
	  DHT_AFTER_SPARSE_HOOK="$(CURDIR)/tools/dev/zcode_async_proof_scaling_hook.sh" \
	  bash tools/dev/zcode_dht_acceptance.sh

# Permanent physical adversarial campaign for the repaired mempool/coins/
# finalization ownership boundary.  It composes the existing authenticated
# full-node harness and its confined proof workers; no parallel lifecycle,
# transport, CAS, or acceptance framework is introduced.
public-node-coin-generation-matrix: zclassic23 zcl-rpc
	@DHT_PACKAGEHOST=1 DHT_BUILDWORKERS=1 DHT_KEEP=1 \
	  DHT_AFTER_SPARSE_HOOK="$(CURDIR)/tools/dev/public_node_coin_generation_matrix_hook.sh" \
	  bash tools/dev/zcode_dht_acceptance.sh

# Hermetic P2P source-publication proof. The exact group emits one canonical
# zcl.sovereign_source_roundtrip.v1 receipt only after workspace/release/
# Passport/accepted-work verification, two-provider fetch, Git-free rebuild,
# failover, corrupt-chunk recovery and successor ancestry all pass.
sovereign-source-roundtrip:
	@$(MAKE) --no-print-directory t-fast-exact ONLY=test_zcode_swarm_net

# ASan/UBSan variant of `t-fast`: one group per invocation under the
# instrumented harness (build/bin/test-asan, own build/test-asan-obj tree).
# Triage posture: ASan aborts the failing child (halt_on_error=1 default) so
# a memory error surfaces as a red group with the full report in its
# replayed log; UBSan stays in gcc's default recover-and-continue mode so
# one run collects every finding — export UBSAN_OPTIONS=halt_on_error=1 to
# make reports fatal instead. Findings are the point of this target; fix
# forward, don't suppress.
# The stack limit is a large FINITE 1 GiB, not unlimited: ASan + PIE with an
# unlimited stack intermittently aborts at startup with "Shadow memory range
# interleaves with an existing memory mapping" (google/sanitizers#856 —
# measured ~11/15 failures here at unlimited, 0/15 at 1 GiB). 1 GiB keeps
# the deep-recursion headroom the suite needs.
# Checkout-locked — see the `test-parallel` target above for why.
# Opt-in sanitizer smoke: a small set of fast, params-free groups under
# test-asan. Deliberately NOT wired into `make ci` — instrumented runs are
# several times slower than the plain fast harness and push times must stay
# stable. Run locally before pushing memory-risky changes, or in a dedicated
# CI lane. Override the set with ASAN_CI_GROUPS="...".
# Gate posture: UBSAN_OPTIONS=halt_on_error=1 turns every UBSan report into
# a red group (gcc's default is recover-and-continue, which would let a
# finding print yet stay green); ASan already halts by default. Every group
# in the default set is verified clean under this posture — a red asan-ci
# run is a real finding to fix, never an expected failure.
ASAN_CI_GROUPS ?= test_bloom test_json test_parse_num test_zcl_result test_supervisor test_encoding test_zcode_site \
	test_bn254_accel test_fr_mont_parity test_fr_accel test_mont_adx_honest
T_ASAN_GROUPS = $(if $(strip $(ONLY)),$(ONLY),$(ASAN_CI_GROUPS))

# With ONLY=, run the requested substring exactly as before.  With no selector,
# run the params-free smoke set plus the positive/negative ADX differential
# oracles.  This is the public, flagless sanitizer front door.
t-asan: $(TEST_ASAN_CANDIDATE) dev-package-verifier-ensure
	@mkdir -p "$(BUILD_DIR)"
	@$(CHECKOUT_LOCK_TOOL) foreground "$(CHECKOUT_LOCK)" -- \
	  sh -c 'set -e; ulimit -s 1048576; \
	  export UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1; \
	  for g in $(T_ASAN_GROUPS); do \
	    echo "t-asan: --- $$g ---"; \
	    $(TEST_ASAN_ACTIVE) --only=$$g; \
	  done'

asan-ci: $(TEST_ASAN_CANDIDATE) dev-package-verifier-ensure
	@mkdir -p "$(BUILD_DIR)"
	@$(CHECKOUT_LOCK_TOOL) foreground "$(CHECKOUT_LOCK)" -- \
	  sh -c 'set -e; ulimit -s 1048576; \
	  export UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1; \
	  for g in $(ASAN_CI_GROUPS); do \
	    echo "asan-ci: --- $$g ---"; \
	    $(TEST_ASAN_ACTIVE) --only=$$g; \
	  done; \
	  echo "asan-ci: OK ($(ASAN_CI_GROUPS))"'

# S6 DHT memory/UB gate.  Unlike the broad historical sanitizer profile this
# focused lane has no sanitizer exclusions: codec, routing, service, lookup,
# scale-model and lock-lifecycle code all run with the complete ASan+UBSan
# instrumentation set.  The monolithic harness uses the same two-TU ADX
# frame-pointer exception as every other ASan target; the epoch key records it.
.PHONY: zcode-dht-asan
zcode-dht-asan:
	@$(MAKE) asan-ci \
	  ASAN_CI_GROUPS='test_zcode_dht test_zcode_dht_msgs test_zcode_dht_service test_zcode_dht_lookup test_zcode_dht_model'

# TSan variant of `t-asan`: one group per invocation under the
# thread-instrumented harness (build/bin/test-tsan, own build/test-tsan-obj
# tree). Triage posture: TSan's default report-and-continue mode collects
# every race in one run, then exits the failing child with exitcode=66 so a
# group WITH reports surfaces red — findings are the point of this target.
# Suppressions come from tools/tsan.supp (documented-benign entries only —
# never seed it to hide an untriaged report; see docs/BUILD.md
# "ThreadSanitizer profiles" for the current known-good triage state). Same
# finite 1 GiB stack as t-asan.
# setarch -R (disable ASLR) is REQUIRED: TSan reserves fixed shadow address
# ranges and the default-ASLR PIE/mmap placement intermittently collides at
# startup ("FATAL: ThreadSanitizer: unexpected memory mapping" — reproduced
# on the first t-tsan run here). These are opt-in triage binaries, never
# release artifacts, so no-ASLR is an acceptable trade.
# Checkout-locked — see the `test-parallel` target above for why.
TSAN_SUPP_FILE = $(CURDIR)/tools/tsan.supp
t-tsan: $(TEST_TSAN_CANDIDATE) dev-package-verifier-ensure
	@mkdir -p "$(BUILD_DIR)"
	@$(CHECKOUT_LOCK_TOOL) foreground "$(CHECKOUT_LOCK)" -- \
	  sh -c 'ulimit -s 1048576 && \
	  TSAN_OPTIONS="suppressions=$(TSAN_SUPP_FILE):print_stacktrace=1" \
	  exec setarch -R $(TEST_TSAN_ACTIVE) --only=$(ONLY)'

# Opt-in sanitizer smoke: a small set of fast, thread-spawning groups under
# test-tsan. Deliberately NOT wired into `make ci` — instrumented runs are
# several times slower than the plain fast harness and push times must stay
# stable. Green as of the first TSan sweep's one finding (R1, atomic
# publication of thread_liveness_child.id) getting fixed in code — see
# docs/BUILD.md "ThreadSanitizer profiles" for the known-good writeup. Run it
# locally before touching threaded code. Override the set with
# TSAN_CI_GROUPS="...". Gate posture: halt_on_error=1 turns the first race
# report into a red group (mirrors asan-ci's UBSan posture) — a red tsan-ci
# is a real NEW finding, not expected noise. setarch -R: see the t-tsan note
# above.
TSAN_CI_GROUPS ?= test_supervisor test_workpool test_mailbox test_parallel_range_fold test_validate_parallel_determinism test_net_bootstrap test_cpu_topology
tsan-ci: $(TEST_TSAN_CANDIDATE) dev-package-verifier-ensure
	@mkdir -p "$(BUILD_DIR)"
	@$(CHECKOUT_LOCK_TOOL) foreground "$(CHECKOUT_LOCK)" -- \
	  sh -c 'set -e; ulimit -s 1048576; \
	  export TSAN_OPTIONS="halt_on_error=1:print_stacktrace=1:suppressions=$(TSAN_SUPP_FILE)"; \
	  for g in $(TSAN_CI_GROUPS); do \
	    echo "tsan-ci: --- $$g ---"; \
	    setarch -R $(TEST_TSAN_ACTIVE) --only=$$g; \
	  done; \
	  echo "tsan-ci: OK ($(TSAN_CI_GROUPS))"'

# The leanest changed-aware spelling: no ONLY= to remember. Impact mappings
# classify the current working-tree hints, but never reduce proof scope; this
# runs the exact source-wide fast candidate. Use `make t-fast ONLY=<g>` for a
# manual focused run and `make pre-push-ci` as the pre-push gate.
t-changed:
	@ZCL_FAST_BUILD_SOURCE_RECORD="$(BUILD_SOURCE_RECORD)" \
	  tools/agent_fast_ci.sh test-changed

# Exact compile-check of the whole node (no link). Every source is resolved in
# the current immutable epoch; ccache/sccache recovers unchanged TU work. The
# -Wno-deprecated-declarations matches the real node/test build (zclassic23,
# test_parallel) so these targets don't false-fail on pre-existing deprecations.
build-only: $(VIEW_GEN_HEADERS) $(ALL_OBJS)
	@$(BUILD_EPOCH_SESSION_TOOL) verify "$(BUILD_ONLY_SESSION)" "$(BUILD_ONLY_LEASE)" \
	  "$(OBJ_ROOT)" - "$(BUILD_EPOCH_KEEP)" "$(BUILD_SOURCE_ID)" \
	  "$(BUILD_CLEAN)" "$(BUILD_MUTATION)" "$(BUILD_COMPILER_ID)" \
	  "$(BUILD_ONLY_COMPILE_EPOCH)" "$(BUILD_ONLY_PROFILE)" \
	  "$(BUILD_ONLY_EPOCH_COMPILE_FLAGS)" "$(BUILD_ONLY_EPOCH_LINK_FLAGS)" \
	  "$(CC)" "$(CXX)" "$$PPID" >/dev/null
	@echo "build-only: all node objects compiled epoch=$(BUILD_ONLY_COMPILE_EPOCH)"

# Fastest no-link compile-check for local edit loops. This resolves the complete
# current source inventory in the same non-LTO epoch as zclassic23-dev; compiler
# caches recover unchanged TU work and no final executable link is paid.
fast-compile dev-build-only: $(DEV_OBJ_COMPLETE)
	@echo "fast-compile: all dev node objects compiled (non-LTO, no link)"

$(DEV_OBJ_COMPLETE): $(VIEW_GEN_HEADERS) $(DEV_OBJS)
	@set -eu; \
	mkdir -p "$(dir $@)"; \
	$(BUILD_EPOCH_SESSION_TOOL) verify "$(DEV_SESSION)" "$(DEV_LEASE)" \
	  "$(DEV_OBJ_ROOT)" "$(BIN_DIR)/dev" "$(BUILD_EPOCH_KEEP)" \
	  "$(BUILD_SOURCE_ID)" "$(BUILD_CLEAN)" "$(BUILD_MUTATION)" "$(BUILD_COMPILER_ID)" \
	  "$(DEV_COMPILE_EPOCH)" "$(DEV_PROFILE)" "$(DEV_EPOCH_COMPILE_FLAGS)" \
	  "$(DEV_EPOCH_LINK_FLAGS)" "$(CC)" "$(CXX)" "$$PPID" >/dev/null; \
	tmp="$$(mktemp "$(dir $@).complete.XXXXXX")"; \
	trap 'rm -f "$$tmp"' EXIT HUP INT TERM; \
	printf '%s\n' 'epoch=$(DEV_COMPILE_EPOCH)' > "$$tmp"; \
	mv -f -- "$$tmp" "$@"; \
	trap - EXIT HUP INT TERM

# Compatibility name for the common edit-loop compile gate. Changed paths are
# classification hints only: the proof always resolves every current dev source
# in the stable (toolchain+flags-keyed) epoch via `fast-compile`.
fast-changed-compile:
	@ZCL_FAST_BUILD_SOURCE_RECORD="$(BUILD_SOURCE_RECORD)" \
	  ZCL_FAST_CC="$${ZCL_FAST_CC:-$(CC)}" \
	  tools/agent_fast_ci.sh compile-changed

# Fail-fast edit-loop ladder: compile -> source-wide-tests -> lint-fast, cost-ordered
# and short-circuiting, with a dense FIRST-ERROR[<rung>] line on the first break.
# No live probe, no full/LTO build. `make ff` after an edit; strict gate before
# push is still `make lint && make build-only && relevant tests` / `make pre-push-ci`.
# Checkout-locked (see CHECKOUT_LOCK above): the watcher's own `make ff` defers
# instead of racing a foreground build/test run in the same checkout.
# One exact goal keeps both mandatory watcher gates under one conservative
# contract without turning their old mixed-goal invocation into a reason to
# import unrelated compiler depfiles.
watcher-safety-gates: check-core-seal check-consensus-parity check-dev-loop-profiles

.PHONY: check-dev-loop-profiles dev-loop-profile-flags dev-loop-history-bench dev-loop-history-bench-selftest dev-loop-history-replay dev-loop-history-replay-selftest reflex-reactor-bench reflex-coverage-audit reflex-coverage-audit-selftest reflex-hotfork-transport-acceptance reflex-hotfork-source-bundle-acceptance reflex-hotfork-test-catalog-acceptance reflex-hotfork-shop-want-view-acceptance reflex-hotfork-zcode-package-view-acceptance reflex-hotfork-shop-status-acceptance reflex-hotfork-shop-reputation-acceptance reflex-hotfork-zcode-work-acceptance reflex-hotfork-watch-core-acceptance reflex-hotfork-cycle-core-acceptance reflex-hotfork-corpus-core-acceptance reflex-hotfork-plan-core-acceptance reflex-hotfork-shop-want-core-acceptance reflex-hotfork-command-input-core-acceptance reflex-hotfork-native-dev-core-acceptance reflex-hotfork-curve25519-acceptance reflex-hotfork-package-policy-acceptance
dev-loop-profile-flags:
	@printf 'DEV_LIVE\t%s\t%s\n' '$(DEV_LIVE_CFLAGS)' '$(HOTSWAP_MODULE_LDFLAGS)'
	@printf 'DEV_RESTART\t%s\t%s\n' '$(DEV_RESTART_CFLAGS)' '$(DEV_RESTART_LDFLAGS)'
	@printf 'INTEGRATION\t%s\t%s\n' '$(INTEGRATION_CFLAGS)' '$(INTEGRATION_LDFLAGS)'
	@printf 'RELEASE\t%s\t%s\n' '$(RELEASE_CFLAGS)' '$(RELEASE_LDFLAGS)'

check-dev-loop-profiles:
	@tools/dev/dev-loop-profile-selftest.sh

dev-loop-history-bench:
	@tools/dev/dev-loop-history-bench.sh run

dev-loop-history-bench-selftest:
	@tools/dev/dev-loop-history-bench.sh --self-test

.PHONY: dev-loop-active-bench dev-loop-active-bench-selftest \
	dev-linker-shootout dev-linker-shootout-selftest
dev-loop-active-bench:
	@tools/dev/dev-loop-active-bench.sh run

dev-loop-active-bench-selftest:
	@tools/dev/dev-loop-active-bench.sh --self-test

reflex-reactor-bench: dev-bin
	@tools/dev/reflex-reactor-bench.sh

reflex-coverage-audit: dev-bin
	@ZCL_DEV_HISTORY_BASE_REF=HEAD \
	 ZCL_DEV_HISTORY_OUTPUT=build/dev-loop/substrate-history-benchmark.json \
	 tools/dev/dev-loop-history-bench.sh run
	@ZCL_REFLEX_HISTORY=build/dev-loop/substrate-history-benchmark.json \
	 tools/dev/reflex-coverage-audit.sh run

reflex-coverage-audit-selftest:
	@tools/dev/reflex-coverage-audit.sh --self-test

reflex-hotfork-transport-acceptance: dev-bin
	@tools/dev/reflex-hotfork-transport-acceptance.sh

reflex-hotfork-source-bundle-acceptance: dev-bin
	@tools/dev/reflex-hotfork-source-bundle-acceptance.sh

reflex-hotfork-test-catalog-acceptance: dev-bin
	@tools/dev/reflex-hotfork-test-catalog-acceptance.sh

reflex-hotfork-shop-want-view-acceptance: dev-bin
	@tools/dev/reflex-hotfork-shop-want-view-acceptance.sh

reflex-hotfork-zcode-package-view-acceptance: dev-bin
	@tools/dev/reflex-hotfork-zcode-package-view-acceptance.sh

reflex-hotfork-shop-status-acceptance: dev-bin
	@tools/dev/reflex-hotfork-shop-status-acceptance.sh

reflex-hotfork-shop-reputation-acceptance: dev-bin
	@tools/dev/reflex-hotfork-shop-reputation-acceptance.sh

reflex-hotfork-zcode-work-acceptance: dev-bin
	@tools/dev/reflex-hotfork-zcode-work-acceptance.sh

reflex-hotfork-watch-core-acceptance: dev-bin
	@tools/dev/reflex-hotfork-watch-core-acceptance.sh

reflex-hotfork-cycle-core-acceptance: dev-bin
	@ZCL_REFLEX_OWNER_KIND=cycle tools/dev/reflex-hotfork-watch-core-acceptance.sh

reflex-hotfork-corpus-core-acceptance: dev-bin
	@ZCL_REFLEX_OWNER_KIND=corpus tools/dev/reflex-hotfork-watch-core-acceptance.sh

reflex-hotfork-plan-core-acceptance: dev-bin
	@ZCL_REFLEX_OWNER_KIND=plan tools/dev/reflex-hotfork-watch-core-acceptance.sh

reflex-hotfork-shop-want-core-acceptance: dev-bin
	@ZCL_REFLEX_OWNER_KIND=shop-want tools/dev/reflex-hotfork-watch-core-acceptance.sh

reflex-hotfork-command-input-core-acceptance: dev-bin
	@ZCL_REFLEX_OWNER_KIND=command-input tools/dev/reflex-hotfork-watch-core-acceptance.sh

reflex-hotfork-native-dev-core-acceptance: dev-bin
	@ZCL_REFLEX_OWNER_KIND=native-dev tools/dev/reflex-hotfork-watch-core-acceptance.sh

reflex-hotfork-curve25519-acceptance: dev-bin
	@ZCL_REFLEX_OWNER_KIND=curve25519 tools/dev/reflex-hotfork-watch-core-acceptance.sh

reflex-hotfork-package-policy-acceptance: dev-bin
	@ZCL_REFLEX_OWNER_KIND=package-policy tools/dev/reflex-hotfork-watch-core-acceptance.sh

dev-linker-shootout:
	@tools/dev/dev-linker-shootout.sh run

dev-linker-shootout-selftest:
	@tools/dev/dev-linker-shootout.sh --self-test

dev-loop-history-replay:
	@tools/dev/dev-loop-history-replay.sh run

dev-loop-history-replay-selftest:
	@tools/dev/dev-loop-history-replay.sh --self-test

# Cheap pre-execution identity for deterministic negative-receipt lookup.  The
# dev compile epoch already binds the exact source+ABA record, compiler and
# linker/search-root fingerprints, profile, flags, and link inputs.  Native
# devloop hashes this value into its SHA3 execution identity before deciding
# whether an unchanged compiler failure may be coalesced.  Callers must supply
# the exact BUILD_SOURCE_RECORD on the Make command line; ambient values are
# ignored by the source-record guard above.
.PHONY: dev-failure-execution-id
dev-failure-execution-id:
	@printf '%s\n' '$(DEV_COMPILE_EPOCH)'

ff:
	@mkdir -p "$(BUILD_DIR)"
	@$(CHECKOUT_LOCK_TOOL) $(CHECKOUT_LOCK_MODE) "$(CHECKOUT_LOCK)" -- \
	  env ZCL_FAST_BUILD_SOURCE_RECORD="$(BUILD_SOURCE_RECORD)" \
	  ZCL_FAST_CC="$${ZCL_FAST_CC:-$(CC)}" tools/agent_fast_ci.sh ff

# Changed-scope edit proof: fresh compilation-database recipes for directly
# changed C translation units (source-wide fallback for headers/build graph),
# mapped focused groups only, then lint-fast. Full output is retained below
# build/verify-change while stdout stays a compact verdict/failure capsule.
verify-change:
	@mkdir -p "$(BUILD_DIR)"
	@$(CHECKOUT_LOCK_TOOL) $(CHECKOUT_LOCK_MODE) "$(CHECKOUT_LOCK)" -- \
	  env ZCL_FAST_BUILD_SOURCE_RECORD="$(BUILD_SOURCE_RECORD)" \
	  ZCL_FAST_CC="$${ZCL_FAST_CC:-$(CC)}" tools/agent_fast_ci.sh verify-change

# Fast local node executable for AI/operator development. `fast-rebuild` first
# runs the changed-file dev compile gate, then links the non-LTO dev binary.
# This deliberately does not replace `z23`, `make deploy`, or release
# artifacts.
HOTSWAP_ACTION_PLAN = $(BUILD_DIR)/hotswap/fast/flags.env
dev-bin z23-dev zclassic23-dev: $(ZCLASSIC23_DEV_BIN) $(ZCLASSIC23_DEV_BIN_ALIAS) \
	$(DEV_RESTART_PLAN) \
	$(HOTSWAP_ACTION_PLAN) dev-package-verifier \
	zclassic23-zcode-adapter-runner

# Temporary migration alias: build/bin/zclassic23-dev keeps resolving to
# z23-dev while bots/scripts migrate.
$(ZCLASSIC23_DEV_BIN_ALIAS): $(ZCLASSIC23_DEV_BIN)
	@ln -sfn z23-dev "$@"
# Checkout-locked (see CHECKOUT_LOCK above) — the watcher invokes this same
# target via run_rebuild_command, so it defers instead of racing a foreground
# rebuild in the same checkout.
fast-rebuild rebuild-fast dev-rebuild hot-rebuild super-rebuild:
	@mkdir -p "$(BUILD_DIR)"
	@$(CHECKOUT_LOCK_TOOL) $(CHECKOUT_LOCK_MODE) "$(CHECKOUT_LOCK)" -- \
	  env ZCL_FAST_BUILD_SOURCE_RECORD="$(BUILD_SOURCE_RECORD)" \
	  ZCL_FAST_CC="$${ZCL_FAST_CC:-$(CC)}" tools/agent_fast_ci.sh rebuild-dev

$(ZCLASSIC23_DEV_BIN): $(DEV_CANDIDATE_BIN) FORCE
	@$(BUILD_EPOCH_PUBLISH_TOOL) "$(DEV_CANDIDATE_BIN)" "$@" "$(DEV_SESSION)" \
	  "$(BUILD_SOURCE_ID)" "$(BUILD_CLEAN)" "$(BUILD_MUTATION)" \
	  "$(DEV_COMPILE_EPOCH)" "$(BUILD_COMPILER_ID)" "$(DEV_PROFILE)" \
	  "$(DEV_EPOCH_COMPILE_FLAGS)" "$(DEV_EPOCH_LINK_FLAGS)" "$(CC)" "$(CXX)"
	@echo "dev-bin: $@ <= $(DEV_CANDIDATE_BIN) (non-LTO, unstripped; not for release/deploy)"

$(DEV_CANDIDATE_BIN): $(VIEW_GEN_HEADERS) $(BUILD_IDENTITY_STAMP) $(DEV_OBJ_COMPLETE) | $(VENDOR_LIBS)
	@mkdir -p $(dir $@)
	@set -eu; \
	tmp="$$(mktemp "$@.link.XXXXXX")"; \
	trap 'rm -f "$$tmp"' EXIT HUP INT TERM; \
	$(CC) $(DEV_RESTART_CFLAGS) $(DEV_RESTART_LDFLAGS) -o "$$tmp" "@$(DEV_LINK_RSP)" $(TOR_LIBS) $(LIBS) $(GTK_LIBS) $(WEBKIT_LIBS); \
	$(BUILD_EPOCH_SESSION_TOOL) verify "$(DEV_SESSION)" "$(DEV_LEASE)" \
	  "$(DEV_OBJ_ROOT)" "$(BIN_DIR)/dev" "$(BUILD_EPOCH_KEEP)" \
	  "$(BUILD_SOURCE_ID)" "$(BUILD_CLEAN)" "$(BUILD_MUTATION)" "$(BUILD_COMPILER_ID)" \
	  "$(DEV_COMPILE_EPOCH)" "$(DEV_PROFILE)" "$(DEV_EPOCH_COMPILE_FLAGS)" \
	  "$(DEV_EPOCH_LINK_FLAGS)" "$(CC)" "$(CXX)" "$$PPID" >/dev/null; \
	mv -f -- "$$tmp" "$@"; \
	trap - EXIT HUP INT TERM

DEV_LINK_RSP = $(DEV_OBJ_DIR)/link-inputs.rsp
DEV_RESTART_BASE_RELOC = $(DEV_OBJ_DIR)/restart-base.o
$(DEV_LINK_RSP): $(DEV_OBJS)
	@$(if $(ZCL_MAKE_NO_EXEC),,$(file >$@,$(DEV_OBJS))) test -s "$@"

$(DEV_RESTART_BASE_RELOC): $(DEV_LINK_RSP) $(DEV_OBJS)
	@set -eu; \
	tmp="$$(mktemp "$@.XXXXXX")"; \
	trap 'rm -f "$$tmp"' EXIT HUP INT TERM; \
	$(CC) $(ZCL_DEV_LINKER) -r -nostdlib -o "$$tmp" "@$(DEV_LINK_RSP)"; \
	chmod 0444 "$$tmp"; \
	mv -f -- "$$tmp" "$@"; \
	trap - EXIT HUP INT TERM

# Focused tests intentionally select only their own compile epoch at parse
# time.  The common path compares one identity-bound readiness line; only a
# missing/stale helper enters a nested dev-profile build.  This gives a clean
# checkout its prerequisite without paying a recursive Make on every test.
.PHONY: dev-package-verifier dev-package-verifier-ensure
dev-package-verifier: $(DEV_PACKAGE_VERIFY_BIN)
	@mkdir -p '$(dir $(DEV_PACKAGE_VERIFY_ENSURE_STAMP))'
	@set -eu; \
	tmp="$$(mktemp '$(DEV_PACKAGE_VERIFY_ENSURE_STAMP).XXXXXX')"; \
	trap 'rm -f "$$tmp"' EXIT HUP INT TERM; \
	printf '%s %s %s\n' '$(BUILD_SOURCE_ID)' '$(BUILD_CLEAN)' \
	  '$(BUILD_MUTATION)' > "$$tmp"; \
	mv -f -- "$$tmp" '$(DEV_PACKAGE_VERIFY_ENSURE_STAMP)'; \
	trap - EXIT HUP INT TERM

ifeq ($(ZCL_STANDALONE_CLEAN),1)
dev-package-verifier-ensure:
	@:
else
dev-package-verifier-ensure:
	@set -eu; \
	want='$(BUILD_SOURCE_ID) $(BUILD_CLEAN) $(BUILD_MUTATION)'; \
	have=''; \
	if test -r '$(DEV_PACKAGE_VERIFY_ENSURE_STAMP)'; then \
	  IFS= read -r have < '$(DEV_PACKAGE_VERIFY_ENSURE_STAMP)' || :; \
	fi; \
	if ! test -x '$(DEV_PACKAGE_VERIFY_BIN)' || test "$$have" != "$$want"; then \
	  $(MAKE) --no-print-directory dev-package-verifier; \
	fi
endif

# The confined ZBuild worker is a runtime prerequisite of several focused
# ZCODE groups.  A fresh dev worktree must not need the release-only,
# whole-program-LTO verifier before those groups can produce feedback.  Reuse
# the already compiled DEV_RESTART object graph, add only the verifier main,
# and link this fixed dev-only companion once during environment bootstrap.
# Save cycles never rebuild it unless one of its exact inputs changed.
$(DEV_PACKAGE_VERIFY_BIN): $(DEV_PACKAGE_VERIFY_LINK_RSP) \
		$(DEV_OBJ_COMPLETE) | $(VENDOR_LIBS)
	@mkdir -p $(dir $@)
	@set -eu; \
	tmp="$$(mktemp "$@.link.XXXXXX")"; \
	trap 'rm -f "$$tmp"' EXIT HUP INT TERM; \
	$(CC) $(DEV_RESTART_CFLAGS) $(DEV_RESTART_LDFLAGS) -o "$$tmp" \
	  "@$(DEV_PACKAGE_VERIFY_LINK_RSP)" \
	  $(TOR_LIBS) $(LIBS) $(GTK_LIBS) $(WEBKIT_LIBS); \
	$(BUILD_EPOCH_SESSION_TOOL) verify "$(DEV_SESSION)" "$(DEV_LEASE)" \
	  "$(DEV_OBJ_ROOT)" "$(BIN_DIR)/dev" "$(BUILD_EPOCH_KEEP)" \
	  "$(BUILD_SOURCE_ID)" "$(BUILD_CLEAN)" "$(BUILD_MUTATION)" \
	  "$(BUILD_COMPILER_ID)" "$(DEV_COMPILE_EPOCH)" "$(DEV_PROFILE)" \
	  "$(DEV_EPOCH_COMPILE_FLAGS)" "$(DEV_EPOCH_LINK_FLAGS)" \
	  "$(CC)" "$(CXX)" "$$PPID" >/dev/null; \
	mv -f -- "$$tmp" "$@"; \
	trap - EXIT HUP INT TERM

$(DEV_PACKAGE_VERIFY_LINK_RSP): $(DEV_PACKAGE_VERIFY_OBJ) \
		$(DEV_PACKAGE_VERIFY_NODE_OBJS)
	@$(if $(ZCL_MAKE_NO_EXEC),,$(file >$@,$(DEV_PACKAGE_VERIFY_OBJ) $(DEV_PACKAGE_VERIFY_NODE_OBJS))) test -s "$@"

$(DEV_RESTART_PLAN): $(DEV_OBJ_COMPLETE) $(DEV_LINK_RSP) \
		$(DEV_RESTART_BASE_RELOC) $(TEST_PARALLEL_FAST_LINK_RSP) \
		$(TEST_RESTART_BASE_RELOC) Makefile FORCE
	@set -eu; \
	mkdir -p "$(dir $@)"; \
	tmp="$$(mktemp "$(dir $@).restart.XXXXXX")"; \
	trap 'rm -f "$$tmp"' EXIT HUP INT TERM; \
	{ \
	  printf 'CC=%s\n' '$(CC)'; \
	  printf 'COMPILER_ID=%s\n' '$(BUILD_COMPILER_ID)'; \
	  printf 'BASE_GENERATION=%s\n' '$(BUILD_MUTATION)'; \
	  printf 'DEV_CFLAGS=%s\n' '$(DEV_RESTART_CFLAGS)'; \
	  printf 'DEV_LDFLAGS=%s\n' '$(DEV_RESTART_LDFLAGS)'; \
	  printf 'DEV_LIBS=%s\n' '$(TOR_LIBS) $(LIBS) $(GTK_LIBS) $(WEBKIT_LIBS)'; \
	  printf 'DEV_OBJ_DIR=%s\n' '$(DEV_OBJ_DIR)'; \
	  printf 'DEV_LINK_RSP=%s\n' '$(DEV_LINK_RSP)'; \
	  printf 'DEV_BASE_RELOC=%s\n' '$(DEV_RESTART_BASE_RELOC)'; \
	  printf 'TEST_CFLAGS=%s\n' '$(TEST_FAST_CFLAGS)'; \
	  printf 'TEST_LDFLAGS=%s\n' '$(TEST_FAST_LDFLAGS)'; \
	  printf 'TEST_LIBS=%s\n' '$(TOR_LIBS) $(LIBS) $(GTK_LIBS) $(WEBKIT_LIBS)'; \
	  printf 'TEST_OBJ_DIR=%s\n' '$(TEST_FAST_OBJ_DIR)'; \
	  printf 'TEST_LINK_RSP=%s\n' '$(TEST_PARALLEL_FAST_LINK_RSP)'; \
	  printf 'TEST_BASE_RELOC=%s\n' '$(TEST_RESTART_BASE_RELOC)'; \
	} >"$$tmp"; \
	mv -f -- "$$tmp" "$@"; \
	trap - EXIT HUP INT TERM

$(DEV_CANDIDATE_BIN): $(DEV_LINK_RSP)

# dev-asan: ASan/UBSan dev node for local memory/UB debugging. Same source
# set as z23-dev, own epoch-keyed object tree (build/dev-asan-obj);
# -Og, non-LTO, no hot-path split (sanitizer fidelity over optimizer
# coverage). Never a release/deploy artifact. Boot it on a scratch datadir
# with ASAN_OPTIONS=detect_leaks=0 until leak triage is done (follow-up).
dev-asan z23-dev-asan zclassic23-dev-asan: $(DEV_ASAN_BIN) $(DEV_ASAN_BIN_ALIAS)

# Temporary migration alias: build/bin/zclassic23-dev-asan -> z23-dev-asan.
$(DEV_ASAN_BIN_ALIAS): $(DEV_ASAN_BIN)
	@ln -sfn z23-dev-asan "$@"

$(DEV_ASAN_BIN): $(DEV_ASAN_CANDIDATE_BIN) FORCE
	@$(BUILD_EPOCH_PUBLISH_TOOL) "$(DEV_ASAN_CANDIDATE_BIN)" "$@" "$(DEV_ASAN_SESSION)" \
	  "$(BUILD_SOURCE_ID)" "$(BUILD_CLEAN)" "$(BUILD_MUTATION)" \
	  "$(DEV_ASAN_COMPILE_EPOCH)" "$(BUILD_COMPILER_ID)" "$(DEV_ASAN_PROFILE)" \
	  "$(DEV_ASAN_EPOCH_COMPILE_FLAGS)" "$(DEV_ASAN_EPOCH_LINK_FLAGS)" "$(CC)" "$(CXX)"
	@echo "dev-asan: $@ <= $(DEV_ASAN_CANDIDATE_BIN) (ASan+UBSan, -Og, non-LTO; not for release/deploy)"

$(DEV_ASAN_CANDIDATE_BIN): $(VIEW_GEN_HEADERS) $(BUILD_IDENTITY_STAMP) $(DEV_ASAN_OBJS) $(DEV_ASAN_LINK_RSP) | $(VENDOR_LIBS)
	@mkdir -p $(dir $@)
	@set -eu; \
	tmp="$$(mktemp "$@.link.XXXXXX")"; \
	trap 'rm -f "$$tmp"' EXIT HUP INT TERM; \
	$(CC) $(DEV_ASAN_CFLAGS) $(DEV_ASAN_LDFLAGS) -o "$$tmp" "@$(DEV_ASAN_LINK_RSP)" $(TOR_LIBS) $(LIBS) $(GTK_LIBS) $(WEBKIT_LIBS); \
	$(BUILD_EPOCH_SESSION_TOOL) verify "$(DEV_ASAN_SESSION)" "$(DEV_ASAN_LEASE)" \
	  "$(DEV_ASAN_OBJ_ROOT)" "$(BIN_DIR)/dev-asan" "$(BUILD_EPOCH_KEEP)" \
	  "$(BUILD_SOURCE_ID)" "$(BUILD_CLEAN)" "$(BUILD_MUTATION)" "$(BUILD_COMPILER_ID)" \
	  "$(DEV_ASAN_COMPILE_EPOCH)" "$(DEV_ASAN_PROFILE)" "$(DEV_ASAN_EPOCH_COMPILE_FLAGS)" \
	  "$(DEV_ASAN_EPOCH_LINK_FLAGS)" "$(CC)" "$(CXX)" "$$PPID" >/dev/null; \
	mv -f -- "$$tmp" "$@"; \
	trap - EXIT HUP INT TERM

$(DEV_ASAN_LINK_RSP): $(DEV_ASAN_OBJS)
	@$(if $(ZCL_MAKE_NO_EXEC),,$(file >$@,$(DEV_ASAN_OBJS))) test -s "$@"

# dev-tsan: TSan dev node for local data-race debugging. Same source set as
# z23-dev, own epoch-keyed object tree (build/dev-tsan-obj); -Og,
# non-LTO, no hot-path split (sanitizer fidelity over optimizer coverage).
# Never a release/deploy artifact. Boot it on a scratch datadir; race
# reports go to stderr — triage before suppressing anything (see
# docs/BUILD.md "ThreadSanitizer profiles").
dev-tsan z23-dev-tsan zclassic23-dev-tsan: $(DEV_TSAN_BIN) $(DEV_TSAN_BIN_ALIAS)

# Temporary migration alias: build/bin/zclassic23-dev-tsan -> z23-dev-tsan.
$(DEV_TSAN_BIN_ALIAS): $(DEV_TSAN_BIN)
	@ln -sfn z23-dev-tsan "$@"

$(DEV_TSAN_BIN): $(DEV_TSAN_CANDIDATE_BIN) FORCE
	@$(BUILD_EPOCH_PUBLISH_TOOL) "$(DEV_TSAN_CANDIDATE_BIN)" "$@" "$(DEV_TSAN_SESSION)" \
	  "$(BUILD_SOURCE_ID)" "$(BUILD_CLEAN)" "$(BUILD_MUTATION)" \
	  "$(DEV_TSAN_COMPILE_EPOCH)" "$(BUILD_COMPILER_ID)" "$(DEV_TSAN_PROFILE)" \
	  "$(DEV_TSAN_EPOCH_COMPILE_FLAGS)" "$(DEV_TSAN_EPOCH_LINK_FLAGS)" "$(CC)" "$(CXX)"
	@echo "dev-tsan: $@ <= $(DEV_TSAN_CANDIDATE_BIN) (TSan, -Og, non-LTO; not for release/deploy)"

$(DEV_TSAN_CANDIDATE_BIN): $(VIEW_GEN_HEADERS) $(BUILD_IDENTITY_STAMP) $(DEV_TSAN_OBJS) $(DEV_TSAN_LINK_RSP) | $(VENDOR_LIBS)
	@mkdir -p $(dir $@)
	@set -eu; \
	tmp="$$(mktemp "$@.link.XXXXXX")"; \
	trap 'rm -f "$$tmp"' EXIT HUP INT TERM; \
	$(CC) $(DEV_TSAN_CFLAGS) $(DEV_TSAN_LDFLAGS) -o "$$tmp" "@$(DEV_TSAN_LINK_RSP)" $(TOR_LIBS) $(LIBS) $(GTK_LIBS) $(WEBKIT_LIBS); \
	$(BUILD_EPOCH_SESSION_TOOL) verify "$(DEV_TSAN_SESSION)" "$(DEV_TSAN_LEASE)" \
	  "$(DEV_TSAN_OBJ_ROOT)" "$(BIN_DIR)/dev-tsan" "$(BUILD_EPOCH_KEEP)" \
	  "$(BUILD_SOURCE_ID)" "$(BUILD_CLEAN)" "$(BUILD_MUTATION)" "$(BUILD_COMPILER_ID)" \
	  "$(DEV_TSAN_COMPILE_EPOCH)" "$(DEV_TSAN_PROFILE)" "$(DEV_TSAN_EPOCH_COMPILE_FLAGS)" \
	  "$(DEV_TSAN_EPOCH_LINK_FLAGS)" "$(CC)" "$(CXX)" "$$PPID" >/dev/null; \
	mv -f -- "$$tmp" "$@"; \
	trap - EXIT HUP INT TERM

$(DEV_TSAN_LINK_RSP): $(DEV_TSAN_OBJS)
	@$(if $(ZCL_MAKE_NO_EXEC),,$(file >$@,$(DEV_TSAN_OBJS))) test -s "$@"

# ── Tier-1 in-process hot-swap (DEV-ONLY) ──────────────────────────────
# Compile named app-layer native-handler TUs into a "generation" .so and
# dlopen it into a running dev node via the `dev change apply` native command
# (dev_hotswap_native RPC) — the edited handler goes live with no restart.
# Uses ONLY the stock toolchain:
# a plain `$(CC) -shared` link and libc dlopen (-ldl, already in LIBS). The
# RELEASE binary never links any of this (every dlopen sits behind
# ZCL_DEV_BUILD). See docs/work/HOTSWAP.md.
HOTSWAP_OBJ_DIR = $(BUILD_DIR)/hotswap-obj
HOTSWAP_SO_DIR  = $(BUILD_DIR)/hotswap

.PHONY: hotswap-so hotswap
# make hotswap-so FILES="app/controllers/src/status_native_handlers.c ..."
# Compile one manifest-admitted stateless provider into a read-only,
# input-addressed candidate. The digest covers the compiler identity, exact
# C23/dev flags, source identity, and fully preprocessed source (therefore every
# included/generated header).  It is embedded in zcl_hotswap_manifest_v2 and
# the .so path is the LAST line printed.  Multiple providers remain
# reload_required until they share one generated aggregate manifest/entrypoint.
hotswap-so: $(VIEW_GEN_HEADERS) $(BUILD_IDENTITY_STAMP)
	@if [ -z "$(FILES)" ]; then \
	  echo "usage: make hotswap-so FILES=\"app/controllers/src/status_native_handlers.c\"" >&2; \
	  exit 2; fi
	@set -eu; \
	count=0; selected=""; probe=""; \
	eligible="$$(sed -n 's/^[[:space:]]*HOTSWAP_ELIGIBLE("\([^"]*\)").*/\1/p' config/hotswap_eligible.def)"; \
	for f in $(FILES); do \
	  count=$$((count + 1)); selected="$$f"; \
	  [ -f "$$f" ] || { echo "hotswap-so: source does not exist: $$f" >&2; exit 2; }; \
	  printf '%s\n' "$$eligible" | grep -Fqx "$$f" || { \
	    echo "hotswap-so: reload_required: $$f is not admitted by config/hotswap_eligible.def" >&2; exit 2; }; \
	done; \
	[ "$$count" -eq 1 ] || { \
	  echo "hotswap-so: reload_required: v2 pilot admits one atomic provider per generation (got $$count)" >&2; exit 2; }; \
	probe="$$(sed -n 's/^[[:space:]]*HOTSWAP_ELIGIBLE("\([^"]*\)")[[:space:]]*HOTSWAP_PROBE("\([^"]*\)").*/\1\t\2/p' config/hotswap_eligible.def | awk -F '\t' -v selected="$$selected" '$$1 == selected { print $$2 }')"; \
	case "$$probe" in ''|*[!A-Za-z0-9_.]*) echo "hotswap-so: missing/unsafe canonical probe for $$selected" >&2; exit 2;; esac; \
	mkdir -p "$(HOTSWAP_OBJ_DIR)" "$(HOTSWAP_SO_DIR)"; \
	inputs="$$(mktemp "$(HOTSWAP_SO_DIR)/.inputs.XXXXXX")"; \
	tmp_o="$$(mktemp "$(HOTSWAP_OBJ_DIR)/.generation.XXXXXX.o")"; \
	tmp_so="$$(mktemp "$(HOTSWAP_SO_DIR)/.generation.XXXXXX.so")"; \
	tmp_json="$$(mktemp "$(HOTSWAP_SO_DIR)/.generation.XXXXXX.json")"; \
	trap 'rm -f "$$inputs" "$$tmp_o" "$$tmp_so" "$$tmp_json"' EXIT HUP INT TERM; \
	publish_exact() { \
	  src="$$1"; dst="$$2"; \
	  if ln -- "$$src" "$$dst" 2>/dev/null; then rm -f "$$src"; return 0; fi; \
	  [ -f "$$dst" ] && [ ! -L "$$dst" ] && cmp -s "$$src" "$$dst" || return 1; \
	  rm -f "$$src"; \
	}; \
	{ \
	  printf '%s\n' 'schema=zcl.hotswap_inputs.v2'; \
	  printf 'compiler='; $(CC) --version 2>/dev/null | head -1; \
	  printf '%s\n' 'flags=$(DEV_CFLAGS) -fPIC -DZCL_HOTSWAP_GEN -DZCL_HOTSWAP_BUILD_IDENTITY=<build> -DZCL_HOTSWAP_SOURCE_ID=<source> -DZCL_HOTSWAP_INPUT_DIGEST=<sha256> -DZCL_HOTSWAP_PROBE_TOOLS=<probe> -DZCL_HOTSWAP_PROBE_LEAF=<probe>'; \
	  printf 'source=%s\n' "$$selected"; \
	  printf 'probe=%s\n' "$$probe"; \
	  $(CC) $(DEV_CFLAGS) -fPIC -DZCL_HOTSWAP_GEN \
	    -DZCL_HOTSWAP_BUILD_IDENTITY=\"$(BUILD_SOURCE_ID)\" \
	    -DZCL_HOTSWAP_SOURCE_ID=\"$$selected\" \
	    -DZCL_HOTSWAP_PROBE_TOOLS=\"$$probe\" \
	    -DZCL_HOTSWAP_PROBE_LEAF=\"$$probe\" -E -P "$$selected"; \
	} > "$$inputs"; \
	digest="$$(sha256sum "$$inputs" | awk '{print $$1}')"; \
	case "$$digest" in *[!0-9a-f]*|'') echo "hotswap-so: invalid input digest" >&2; exit 1;; esac; \
	o="$(HOTSWAP_OBJ_DIR)/gen-$$digest.o"; \
	so="$(HOTSWAP_SO_DIR)/gen-$$digest.so"; \
	$(CC) $(DEV_CFLAGS) -fPIC -DZCL_HOTSWAP_GEN \
	  -DZCL_HOTSWAP_BUILD_IDENTITY=\"$(BUILD_SOURCE_ID)\" \
	  -DZCL_HOTSWAP_SOURCE_ID=\"$$selected\" \
	  -DZCL_HOTSWAP_INPUT_DIGEST=\"$$digest\" \
	  -DZCL_HOTSWAP_PROBE_TOOLS=\"$$probe\" \
	  -DZCL_HOTSWAP_PROBE_LEAF=\"$$probe\" \
	  -c -o "$$tmp_o" "$$selected" >&2; \
	$(CC) -shared -Wl,--build-id=none -Wl,-z,relro -Wl,-z,now \
	  -Wl,-z,noexecstack -Wl,-Bsymbolic -o "$$tmp_so" "$$tmp_o" >&2; \
	artifact_digest="$$(sha256sum "$$tmp_so" | awk '{print $$1}')"; \
	tools/dev/source-identity.sh verify-record "$(BUILD_SOURCE_ID)" "$(BUILD_CLEAN)" "$(BUILD_MUTATION)" >/dev/null; \
	publish_exact "$$tmp_o" "$$o" || { \
	  echo "hotswap-so: REFUSING mismatched existing object $$o" >&2; exit 3; }; \
	publish_exact "$$tmp_so" "$$so" || { \
	  echo "hotswap-so: REFUSING mismatched existing candidate $$so" >&2; exit 3; }; \
	chmod a-w "$$o" "$$so"; \
	json="$(HOTSWAP_SO_DIR)/gen-$$digest.json"; \
	printf '{"schema":"zcl.hotswap_build.v2","input_digest":"%s","artifact_sha256":"%s","source":"%s","artifact":"%s","publishable":false}\n' \
	  "$$digest" "$$artifact_digest" "$$selected" "$$so" > "$$tmp_json"; \
	publish_exact "$$tmp_json" "$$json" || { \
	  echo "hotswap-so: REFUSING mismatched existing manifest $$json" >&2; exit 3; }; \
	echo "hotswap-so: linked read-only, unpublishable candidate $$so" >&2; \
	echo "$$so"

# make hotswap FILES="..." [PROBE=core.status]
# Build the generation .so, then hand it to the native hot-swap path. NOTE: a
# The dev-only `dev_hotswap` RPC executes inside the already-running isolated
# dev node, so the committed router generation persists until its next process
# restart.  This target never starts/stops any service and can never target the
# canonical or soak lane.
hotswap: $(VIEW_GEN_HEADERS)
	@echo "hotswap: REFUSING — runtime publication and resident probing are contained; use make hotswap-so plus build/test verification" >&2
	@exit 3

.PHONY: hotswap-module-so
# make hotswap-module-so FILE=app/controllers/src/status_native_handlers.c
# make hotswap-module-so HANDLER=core.status      (compat: leaf -> owning file)
# Compile ONE swappable TU (a row in config/hotswap_swappable.def) into a
# content-addressed, MULTI-LEAF module .so that exports `zcl_hotswap_module`
# carrying every leaf that file owns. This is the REAL (activatable) ABI's build
# path — deliberately NOT the whole-program LTO node compile: ONE non-LTO
# `-fPIC -shared` translation unit, seconds not a relink. Unresolved kernel
# symbols (node_rpc_call, json_*, zcl_native_bridge_run, ...) bind against the
# -rdynamic dev node at dlopen. Prints the .so path as the LAST line. The .so is
# loaded ONLY by hotswap_activate (dev-only, gated). See docs/work/HOTSWAP.md
# "Real module ABI".
#
# -DZCL_HOTSWAP_MODULE_SOURCE_TU stamps the module with the repo-relative TU it
# was built from, so a module cannot mislabel which allowlist row it belongs to;
# hotswap_module_admit() refuses any source_tu absent from the allowlist.
#
# HOTSWAP_MODULE_LDFLAGS is the single source of truth for the module link,
# shared by this recipe and the fast path's cached flags.env. -Wl,-Bsymbolic
# is LOAD-BEARING: without it a dlopen'd handler's internal calls interpose
# back onto the resident (old) code and the swap silently does nothing.
HOTSWAP_MODULE_LDFLAGS = -shared -Wl,--build-id=none -Wl,-z,relro -Wl,-z,now \
	-Wl,-z,noexecstack -Wl,-Bsymbolic

# Intentionally NOT ordered on $(BUILD_IDENTITY_STAMP): that stamp exists to
# gate $(BUILD_IDENTITY_CPPFLAGS) into clientversion.o for whole-program
# binaries, and DEV_CFLAGS (used below) never carries those flags (see
# CACHED_CFLAGS's explicit filter-out). Chaining through the stamp's own
# recipe here bought nothing but a second, fully redundant, source-identity
# capture+verify pass on top of the verify-record already performed inline
# below (which is the one that actually matters: it re-checks identity AFTER
# the compile, catching an edit-during-build TOCTOU right before publish).
# BUILD_SOURCE_ID/CLEAN/MUTATION themselves are ordinary parse-time variables
# and remain available regardless.
$(HOTSWAP_ACTION_PLAN): Makefile config/hotswap_swappable.def \
		config/hotswap_islands.def config/hotswap_services.def \
		config/hotswap_shadow_owners.def config/hotfork_capsules.def
	@set -eu; \
	mkdir -p "$(dir $@)"; \
	tmp="$$(mktemp "$(dir $@).flags.XXXXXX")"; \
	trap 'rm -f "$$tmp"' EXIT HUP INT TERM; \
	{ \
	  printf '%s\n' '# zcl.hotswap_fast_flags.v1 — frozen resident action plan'; \
	  printf 'CC=%s\n' '$(CC)'; \
	  printf 'COMPILER_ID=%s\n' '$(BUILD_COMPILER_ID)'; \
	  printf 'DEV_CFLAGS=%s\n' '$(DEV_LIVE_CFLAGS)'; \
	  printf 'HOTSWAP_MODULE_LDFLAGS=%s\n' '$(HOTSWAP_MODULE_LDFLAGS)'; \
	} > "$$tmp"; \
	mv -f -- "$$tmp" "$@"; \
	trap - EXIT HUP INT TERM

hotswap-module-so: $(VIEW_GEN_HEADERS) $(HOTSWAP_ACTION_PLAN)
	@if [ -z "$(HANDLER)$(FILE)" ]; then \
	  echo "usage: make hotswap-module-so FILE=app/controllers/src/status_native_handlers.c" >&2; \
	  echo "   or: make hotswap-module-so HANDLER=core.status" >&2; exit 2; fi
	@set -eu; \
	rows="$$(tr '\n' ' ' < config/hotswap_swappable.def \
	  | grep -oE 'HOTSWAP_SWAPPABLE\("[^"]*"[[:space:]]*,[[:space:]]*"[^"]*"\)')"; \
	[ -n "$$rows" ] || { echo "hotswap-module-so: config/hotswap_swappable.def parsed to zero rows" >&2; exit 2; }; \
	if [ -n "$(FILE)" ]; then \
	  src="$(FILE)"; \
	  printf '%s\n' "$$rows" | grep -Fq "HOTSWAP_SWAPPABLE(\"$$src\"" || { \
	    echo "hotswap-module-so: '$$src' is not a row in config/hotswap_swappable.def (the swappable shape-leaf allowlist)" >&2; exit 2; }; \
	else \
	  src="$$(printf '%s\n' "$$rows" | awk -v leaf='$(HANDLER)' -F '"' '{ n = split($$4, L, " "); for (i = 1; i <= n; i++) if (L[i] == leaf) { print $$2; exit } }')"; \
	  [ -n "$$src" ] || { echo "hotswap-module-so: leaf '$(HANDLER)' is not on config/hotswap_swappable.def (the swappable shape-leaf allowlist)" >&2; exit 2; }; \
	fi; \
	[ -f "$$src" ] || { echo "hotswap-module-so: source does not exist: $$src" >&2; exit 2; }; \
	mkdir -p "$(HOTSWAP_OBJ_DIR)" "$(HOTSWAP_SO_DIR)" "$(HOTSWAP_SO_DIR)/fast"; \
	safe="$$(printf '%s' "$$src" | tr -c 'A-Za-z0-9_.-' '_')"; \
	compile_src="$$src"; \
	island_rows="$$(tr '\n' ' ' < config/hotswap_islands.def \
	  | grep -oE 'HOTSWAP_ISLAND\("[^"]*"[[:space:]]*,[[:space:]]*"[^"]*"\)' || true)"; \
	members="$$(printf '%s\n' "$$island_rows" | awk -v owner="$$src" -F '"' '$$2 == owner { print $$4; exit }')"; \
	if [ -n "$$members" ]; then \
	  unity="$(HOTSWAP_SO_DIR)/fast/$$safe.island.c"; \
	  tmp_unity="$$(mktemp "$(HOTSWAP_SO_DIR)/fast/.island.XXXXXX.c")"; \
	  for member in $$members; do \
	    [ -f "$$member" ] || { echo "hotswap-module-so: missing island member $$member" >&2; exit 2; }; \
	    printf '#include "%s/%s"\n' '$(CURDIR)' "$$member" >> "$$tmp_unity"; \
	  done; \
	  printf '#include "%s/%s"\n' '$(CURDIR)' "$$src" >> "$$tmp_unity"; \
	  if [ -f "$$unity" ] && cmp -s "$$tmp_unity" "$$unity"; then rm -f "$$tmp_unity"; \
	  else mv -f "$$tmp_unity" "$$unity"; fi; \
	  compile_src="$$unity"; \
	fi; \
	o="$(HOTSWAP_OBJ_DIR)/mod-$$safe-$(BUILD_SOURCE_ID).o"; \
	so="$(HOTSWAP_SO_DIR)/$$safe-$(BUILD_SOURCE_ID).so"; \
	tmp_o="$$(mktemp "$(HOTSWAP_OBJ_DIR)/.module.XXXXXX.o")"; \
	tmp_d="$$(mktemp "$(HOTSWAP_SO_DIR)/fast/.module.XXXXXX.d")"; \
	tmp_so="$$(mktemp "$(HOTSWAP_SO_DIR)/.module.XXXXXX.so")"; \
	trap 'rm -f "$$tmp_o" "$$tmp_d" "$$tmp_so"' EXIT HUP INT TERM; \
	publish_exact() { \
	  pe_src="$$1"; pe_dst="$$2"; \
	  if ln -- "$$pe_src" "$$pe_dst" 2>/dev/null; then rm -f "$$pe_src"; return 0; fi; \
	  [ -f "$$pe_dst" ] && [ ! -L "$$pe_dst" ] && cmp -s "$$pe_src" "$$pe_dst" || return 1; \
	  rm -f "$$pe_src"; \
	}; \
	$(CC) $(DEV_LIVE_CFLAGS) -fPIC -DZCL_HOTSWAP_MODULE_GEN \
	  -DZCL_HOTSWAP_MODULE_SOURCE_TU=\"$$src\" \
	  -MD -MF "$$tmp_d" -c -o "$$tmp_o" "$$compile_src" >&2; \
	$(CC) $(HOTSWAP_MODULE_LDFLAGS) -o "$$tmp_so" "$$tmp_o" >&2; \
	tools/dev/source-identity.sh verify-record "$(BUILD_SOURCE_ID)" "$(BUILD_CLEAN)" "$(BUILD_MUTATION)" >/dev/null; \
	publish_exact "$$tmp_o" "$$o" || { \
	  echo "hotswap-module-so: REFUSING mismatched existing object $$o" >&2; exit 3; }; \
	publish_exact "$$tmp_so" "$$so" || { \
	  echo "hotswap-module-so: REFUSING mismatched existing candidate $$so" >&2; exit 3; }; \
	chmod a-w "$$o" "$$so"; \
	cache_o="$(HOTSWAP_SO_DIR)/fast/$$safe.o"; \
	cache_d="$(HOTSWAP_SO_DIR)/fast/$$safe.d"; \
	cache_cmd="$(HOTSWAP_SO_DIR)/fast/$$safe.cmd"; \
	cache_ptr="$(HOTSWAP_SO_DIR)/fast/$$safe.so-path"; \
	rm -f "$$cache_o"; \
	cp -- "$$o" "$$cache_o"; \
	chmod u+w "$$cache_o"; \
	mv -f -- "$$tmp_d" "$$cache_d"; \
	printf '%s\n' '$(CC) $(DEV_CFLAGS)' > "$$cache_cmd"; \
	printf '%s\n' "$$so" > "$$cache_ptr"; \
	trap - EXIT HUP INT TERM; \
	echo "hotswap-module-so: linked multi-leaf module candidate $$so ($$src)" >&2; \
	echo "$$so"

.PHONY: hotswap-apply
# make hotswap-apply HANDLER=core.status
# make hotswap-apply FILE=app/controllers/src/status_native_handlers.c
# One shot from edit to live: build the MULTI-LEAF module .so for the owning TU
# (hotswap-module-so, seconds) and hand it to the RUNNING dev node's resident
# dev_hotswap_native RPC via `dev hotswap apply`, which re-points EVERY leaf that
# file owns in ONE all-or-nothing registry batch with no restart. Gated inside
# the node by hotswap_activation_authorized() (-hotswap-activate +
# ZCL_HOTSWAP_ACTIVATE=1 + the exact dev datadir); only config/
# hotswap_swappable.def READY read-only leaves can ever activate, the declared
# probe leaf must pass probe-before-publish, and the canonical datadir is
# hard-refused. Prints the zcl.hotswap_activate.v2 report. See
# docs/work/HOTSWAP.md "Real module ABI".
hotswap-apply:
	@if [ -z "$(HANDLER)$(FILE)" ]; then \
	  echo "usage: make hotswap-apply HANDLER=core.status | FILE=<tu.c>" >&2; exit 2; fi
	@so="$$(tools/dev/hotswap-module-fast.sh $(if $(FILE),FILE=$(FILE),HANDLER=$(HANDLER)) | tail -1)"; \
	case "$$so" in /*) ;; *) so="$(CURDIR)/$$so" ;; esac; \
	[ -n "$$so" ] && [ -f "$$so" ] || { \
	  echo "hotswap-apply: module build did not yield a .so (see stderr)" >&2; exit 3; }; \
	[ -x build/bin/zclassic23-dev ] || { \
	  echo "hotswap-apply: build/bin/zclassic23-dev missing — run make fast-rebuild first" >&2; exit 2; }; \
	echo "hotswap-apply: activating $$so" >&2; \
	build/bin/zclassic23-dev -datadir=$(HOME)/.zclassic-c23-dev -rpcport=18252 \
	  dev hotswap apply --input="{\"so_path\":\"$$so\"}"

.PHONY: hotswap-try
# make hotswap-try HANDLER=core.status ARGS="core status"
# make hotswap-try FILE=app/controllers/src/status_native_handlers.c ARGS="core status"
# The OBSERVABLE dev loop: build the MULTI-LEAF module .so for the owning TU,
# then run ARGS in a one-shot CLI with ZCL_HOTSWAP_PRELOAD — every leaf that
# file owns is installed in ONE batch and the freshly compiled bodies execute in
# the CLI process (probe-class authority; the overrides die with the process)
# while fetching live data from the dev lane. No resident restart; the full
# edit->see loop is seconds. Only config/hotswap_swappable.def READY read-only
# leaves can be built into a module. The module rebuild goes through
# tools/dev/hotswap-module-fast.sh (cached compile metadata, no second make
# parse on the happy path) and falls back to the authoritative
# `hotswap-module-so` whenever the cache is stale.
hotswap-try:
	@if [ -z "$(HANDLER)$(FILE)" ]; then \
	  echo "usage: make hotswap-try HANDLER=core.status ARGS=\"core status\"" >&2; exit 2; fi
	@if [ -z "$(ARGS)" ]; then \
	  echo "hotswap-try: ARGS is required, e.g. ARGS=\"core status\"" >&2; exit 2; fi
	@so="$$(tools/dev/hotswap-module-fast.sh $(if $(FILE),FILE=$(FILE),HANDLER=$(HANDLER)) | tail -1)"; \
	case "$$so" in /*) ;; *) so="$(CURDIR)/$$so" ;; esac; \
	[ -n "$$so" ] && [ -f "$$so" ] || { \
	  echo "hotswap-try: module build did not yield a .so (see stderr)" >&2; exit 3; }; \
	[ -x build/bin/zclassic23-dev ] || { \
	  echo "hotswap-try: build/bin/zclassic23-dev missing — run make fast-rebuild first" >&2; exit 2; }; \
	ZCL_HOTSWAP_PRELOAD="$$so" build/bin/zclassic23-dev \
	  -datadir=$(HOME)/.zclassic-c23-dev -rpcport=18252 $(ARGS)

# Full no-link syntax check across every TU in one shot (no incremental state).
syntax-check: $(VIEW_GEN_HEADERS)
	@$(CC) $(CFLAGS) -Wno-deprecated-declarations -fsyntax-only $(ALL_SRCS) $(NODE_ENTRY_SRCS) && echo "syntax-check: OK"

# The highest-signal lint gates for the inner loop — a measured ~15-gate set
# (per-gate timings live in .cache/lint-timing/last-run.json after any driver
# run) covering the most common push-breaking classes: stray sources, raw
# sqlite/malloc, the AR lifecycle laws, thread-registry discipline, framework
# shape, supervisor adoption, vendor drift. All but two gates measure <1 s;
# the stray-source guard (~5 s) dominates, so the set stays ~6-8 s wall under
# the parallel driver. Same ZCL_LINT_SERIAL=1 fallback as lint.
# Run full `make lint` at sub-wave boundaries / before commit.
LINT_FAST_GATES := \
    check-no-stray-untracked-source \
    check-no-stray-root-files \
    check-no-live-lab-history \
    check-raw-sqlite \
    check-malloc \
    check-raw-malloc \
    check-json-value-init \
    check-no-raw-sqlite-in-controllers \
    check-model-validation \
    check-model-ar-lifecycle \
    check-one-write-path \
    check-before-save-hooks \
    check-pthread-create \
    check-log-macro-return-type \
    check-wallet-raw-prepare-log \
    check-zcc-cache \
    check-equihash-params \
    check-framework-shape \
    check-supervisor-registration \
    check-vendor-provenance

ifeq ($(ZCL_LINT_SERIAL),1)
lint-fast: $(LINT_FAST_GATES)
	@echo "lint-fast: OK (serial)"
else
lint-fast:
	@tools/lint/run_lint.sh --jobs "$(ZCL_LINT_JOBS)" --bin-dir "$(BIN_DIR)" $(LINT_FAST_GATES)
	@echo "lint-fast: OK"
endif

# Cache-aware agent/operator loop:
#   make fast-ci
#   ZCL_FAST_CC='ccache cc' make fast-ci
#   ZCL_FAST_TESTS=make_lint_gates,api make fast-ci
#   ZCL_FAST_CACHE=0 make fast-ci      # force rerun even on identical input
#   ZCL_FAST_CACHE_RESET=1 make fast-ci
#   ZCL_FAST_LIVE=0 make fast-ci   # skip live linger-service probe
#   ZCL_FAST_CHANGED_FILES_FILE=/tmp/files make fast-ci
#   ZCL_FAST_CHANGED_FILES='app/controllers/src/agent_controller.c' make fast-ci
#   ZCL_FAST_CHANGED_FILES_ONLY=1  # trust only the explicit changed-file list
#   ZCL_FAST_COMPILE=dev make fast-ci  # force full dev-object fast-compile
#   make pre-push-ci               # skips live probe; code gate only
fast-ci agent-fast-ci dev-ci:
	@mkdir -p "$(BUILD_DIR)"
	@$(CHECKOUT_LOCK_TOOL) $(CHECKOUT_LOCK_MODE) "$(CHECKOUT_LOCK)" -- \
	  env ZCL_FAST_BUILD_SOURCE_RECORD="$(BUILD_SOURCE_RECORD)" \
	  tools/agent_fast_ci.sh

agent-plan:
	@ZCL_FAST_BUILD_SOURCE_RECORD="$(BUILD_SOURCE_RECORD)" \
	  tools/agent_fast_ci.sh plan-json

immutable-history-canaries historical-canaries:
	@echo "==> immutable history canaries: real ZClassic mainnet facts"
	@$(MAKE) --no-print-directory t-fast ONLY=domain_consensus_tx_structural
	@$(MAKE) --no-print-directory t-fast ONLY=consensus_parity
	@echo "immutable-history-canaries: PASS (fast historic KATs; full replay gates: make replay-canary-anchor / make replay-canary-genesis)"

# One-command AI/operator development loop. Runtime activation selectors remain
# accepted only to return the hard containment refusal while the transactional
# epoch/proof/rollback protocol is unfinished:
#   make agent-loop
#   ZCL_AGENT_LOOP_BIN=1 make agent-loop
#   ZCL_AGENT_LOOP_DEPLOY=stage make agent-loop
#   ZCL_AGENT_LOOP_DEPLOY=dev make agent-loop
agent-loop agent-dev-loop:
	@ZCL_FAST_BUILD_SOURCE_RECORD="$(BUILD_SOURCE_RECORD)" \
	  tools/agent_fast_ci.sh
	@case "$${ZCL_AGENT_LOOP_DEPLOY:-}" in \
	  "") \
	    if [ "$${ZCL_AGENT_LOOP_BIN:-0}" = "1" ]; then \
	      $(MAKE) dev-bin; \
	    fi ;; \
	  stage) \
	    $(MAKE) agent-stage-dev ;; \
	  dev) \
	    $(MAKE) agent-deploy-fast ;; \
	  *) \
	    echo "agent-loop: unsupported ZCL_AGENT_LOOP_DEPLOY=$${ZCL_AGENT_LOOP_DEPLOY} (use stage, dev, or unset)"; \
	    exit 2 ;; \
	esac

# JavaScript-like save loop for C: debounce relevant source changes, classify
# them, and run the smallest mapped verification path. The default is
# verify-only and never updates a running process. Runtime publication modes
# are rejected before compilation or activation. Canonical and soak are never
# targets.
dev-watch:
	@ZCL_DEV_WATCH_MODE="$${MODE:-$${ZCL_DEV_WATCH_MODE:-verify}}" tools/dev/watch-dev-lane.sh

dev-watch-once:
	@ZCL_DEV_WATCH_ONCE=1 ZCL_DEV_WATCH_MODE="$${MODE:-$${ZCL_DEV_WATCH_MODE:-verify}}" tools/dev/watch-dev-lane.sh

dev-watch-selftest:
	@tools/dev/watch-dev-lane.sh --self-test

dev-activation-selftest:
	@tools/dev/deploy-dev-lane.sh --self-test

agent-index:
	@bash tools/dev/generate-compdb.sh

# Friendly alias for agent-index: regenerate root compile_commands.json for
# clangd/LSP (see root .clangd and the zclassic23-dev skill's LSP section).
compdb: agent-index

dev-loop-bench:
	@bash tools/dev/dev-loop-bench.sh

dev-loop-bench-selftest:
	@bash tools/dev/dev-loop-bench.sh --self-test

# Fast deterministic network/generation proof. The focused group models
# multiple peers plus an in-flight old-generation call; sim-fast remains the
# broader seeded P2P suite.
hotswap-sim: $(TEST_PARALLEL_FAST_CANDIDATE)
	@ulimit -s unlimited && $(TEST_PARALLEL_FAST_ACTIVE) --only=hotswap_simnet

native-dev-loop-wait-selftest: dev-bin
	@tools/dev/native-dev-loop-wait-selftest.sh

native-dev-failure-selftest: dev-bin
	@tools/dev/native-dev-failure-selftest.sh

dev-loop-selftest: check-dev-loop-profiles dev-loop-history-replay-selftest dev-watch-selftest dev-activation-selftest dev-loop-bench-selftest native-dev-loop-wait-selftest native-dev-failure-selftest hotswap-sim
	@echo "dev-loop-selftest: PASS"

remote-node-plan:
	@if [ -n "$${ZCL_REMOTE_HOST:-}" ]; then \
	    tools/scripts/remote_node_update.sh "$$ZCL_REMOTE_HOST"; \
	else \
	    tools/scripts/remote_node_update.sh $${ZCL_REMOTE_HOSTS:-}; \
	fi

remote-node-plan-json:
	@ZCL_REMOTE_JSON=1 $(MAKE) --no-print-directory remote-node-plan

remote-node-update remote-node-update-json:
	@echo "$@: REFUSING — remote apply/install/restart is contained; use make remote-node-plan" >&2
	@exit 3

# ── Live-truth diagnosis + safe reproduction ─────────────────────────────
# diagnose-gap: one-shot three-orthogonal-views dump + root-cause verdict over
#   the RUNNING node (live or a repro copy). LIVE TRUTH BEFORE DESIGN.
#     make diagnose-gap SLUG=mystall
#     ZCL_RPCPORT=18299 ZCL_DATADIR=<copy> make diagnose-gap SLUG=onacopy
# repro-on-copy: snapshot the live datadir to a throwaway COPY and run the node
#   against it on an isolated port — validate consensus/recovery fixes BEFORE
#   they can touch the live chain; FAILS LOUD on a tip regression. Set
#   CLIMB_PAST=<height> to also require H* to climb strictly past that height.
#   Optional wrapper vars: REPRO_SRC=<dir>, REPRO_FULL=1, REPRO_CONNECT=<peer>,
#   REPRO_DEADLINE=<secs>, REPRO_PORT=<rpcport>, REPRO_P2P_PORT=<p2pport>.
#     make repro-on-copy SLUG=import-reset ARGS='-nobgvalidation'
#     make repro-on-copy SLUG=soak-refold REPRO_SRC=$HOME/.zclassic-c23-soak \
#       REPRO_FULL=1 CLIMB_PAST=3056758 \
#       ARGS='-refold-from-anchor -nobgvalidation -paramsdir=$$HOME/.zcash-params'
.PHONY: diagnose-gap repro-on-copy
diagnose-gap:
	@tools/diagnose_gap.sh $(SLUG)

repro-on-copy:
	@tools/repro_on_copy.sh "$(SLUG)" \
	    $(if $(REPRO_SRC),"--src=$(REPRO_SRC)",) \
	    $(if $(REPRO_FULL),"--full",) \
	    $(if $(REPRO_CONNECT),"--connect=$(REPRO_CONNECT)",) \
	    $(if $(REPRO_DEADLINE),"--deadline=$(REPRO_DEADLINE)",) \
	    $(if $(REPRO_PORT),"--port=$(REPRO_PORT)",) \
	    $(if $(REPRO_P2P_PORT),"--p2p-port=$(REPRO_P2P_PORT)",) \
	    $(if $(CLIMB_PAST),"--expect-climb-past=$(CLIMB_PAST)",) \
	    $(if $(ARGS),-- $(ARGS),)

$(eval $(call BUILD_NODE_TOOL,spec_zcl,lib/test/spec_main.c $(SPEC_SRCS) lib/test/src/test_helpers.c))
$(eval $(call BUILD_NODE_TOOL,wallet_dump,tools/wallet_dump.c))
$(eval $(call BUILD_NODE_TOOL,snapshot_from_coinskv,tools/snapshot_from_coinskv.c))
$(eval $(call BUILD_NODE_TOOL,mint_v2_snapshot,tools/mint_v2_snapshot.c))

# ── Bootstrap starter-pack: produce + COPY-PROVE a local candidate bundle ─
# Turns the one-command bundle producer (mint_v2_snapshot) into a body-digest-
# verified, checksummed, manifested local candidate. Stable publication is deliberately
# disabled until commit-bound quality/release evidence exists; copy proof alone
# grants no network-publication authority.
#
#   make bootstrap            Mint a bundle from a COPY of a synced datadir, then
#                             boot a FRESH /tmp datadir from that bundle with
#                             -nolegacyimport and ASSERT H* CLIMBS past the seed
#                             (not merely "booted"). Writes a .copyprove-ok
#                             marker on success. mint_v2_snapshot authors the
#                             rich SHA256SUMS + manifest.json during the mint.
#   make bootstrap-manifest   (Re)generate ONLY SHA256SUMS over an existing
#                             bundle dir (the rich manifest.json is authored by
#                             mint_v2_snapshot; this target does not rewrite it).
#   make bootstrap-publish    Fail-closed containment target. It publishes
#                             nothing until the stable evidence factory lands.
#
# Env (override on the command line, e.g. `make bootstrap ZCL_BOOTSTRAP_SRC=...`):
#   ZCL_BOOTSTRAP_SRC       Source datadir to mint from. MUST be a SYNCED datadir
#                           that is NOT being written by a running node. The
#                           recipe REFUSES a source owned by a live pid, so the
#                           default (the full-history datadir) is rejected while
#                           zclassic23.service runs on it — point this at a
#                           stopped / non-live synced datadir instead.
#   ZCL_BOOTSTRAP_WORK      Throwaway FULL copy of the source; minting runs HERE,
#                           never on the source (a torn live copy is unsafe).
#   ZCL_BOOTSTRAP_OUT       Bundle output dir: block_index.bin, utxo-seed-<h>.
#                           snapshot, SHA256SUMS, manifest.json.
#   ZCL_BOOTSTRAP_PROVE     Fresh /tmp datadir the copy-prove boots from.
#   ZCL_BOOTSTRAP_PEER      Local peer the copy-prove fetches above-seed bodies
#                           from so H* can climb (default the live node p2p port).
#   ZCL_BOOTSTRAP_DEADLINE  Seconds to wait for the H* climb past the seed.
ZCL_BOOTSTRAP_SRC      ?= $(HOME)/.zclassic-c23-fullhist
ZCL_BOOTSTRAP_WORK     ?= $(HOME)/.zclassic-c23-bootstrap-work
ZCL_BOOTSTRAP_OUT      ?= $(BUILD_DIR)/bootstrap
ZCL_BOOTSTRAP_PROVE    ?= /tmp/zcl-bootstrap-prove
ZCL_BOOTSTRAP_PEER     ?= 127.0.0.1:8033
ZCL_BOOTSTRAP_DEADLINE ?= 900

.PHONY: bootstrap bootstrap-manifest bootstrap-publish

bootstrap: $(ZCLASSIC23_BIN) $(BIN_DIR)/mint_v2_snapshot $(ZCL_RPC_BIN)
	@set -eu; \
	SRC='$(ZCL_BOOTSTRAP_SRC)'; WORK='$(ZCL_BOOTSTRAP_WORK)'; \
	OUT='$(ZCL_BOOTSTRAP_OUT)'; PROVE='$(ZCL_BOOTSTRAP_PROVE)'; \
	PEER='$(ZCL_BOOTSTRAP_PEER)'; DEADLINE='$(ZCL_BOOTSTRAP_DEADLINE)'; \
	NODE='$(ZCLASSIC23_BIN)'; MINT='$(BIN_DIR)/mint_v2_snapshot'; RPC='$(ZCL_RPC_BIN)'; \
	[ -d "$$SRC" ] || { echo "bootstrap: source datadir not found: $$SRC" >&2; exit 1; }; \
	case "$$SRC" in "$$WORK"|"$$PROVE") echo "bootstrap: SRC must differ from WORK/PROVE" >&2; exit 1;; esac; \
	: 'SAFETY: never mint from a datadir a running node owns (torn SQLite copy).'; \
	if [ -f "$$SRC/zclassic23.pid" ] && kill -0 "$$(cat "$$SRC/zclassic23.pid" 2>/dev/null)" 2>/dev/null; then \
	  echo "bootstrap: REFUSING — $$SRC is owned by a live node (pid $$(cat "$$SRC/zclassic23.pid"))." >&2; \
	  echo "           Stop the service or set ZCL_BOOTSTRAP_SRC to a stopped/non-live synced datadir." >&2; \
	  exit 1; \
	fi; \
	echo "[bootstrap] full-copy $$SRC -> $$WORK (minting runs on the copy, never on SRC)"; \
	rm -rf "$$WORK"; mkdir -p "$$WORK"; cp -a "$$SRC"/. "$$WORK"/; \
	rm -f "$$WORK/zclassic23.pid" "$$WORK/.lock" "$$WORK/.cookie" 2>/dev/null || true; \
	echo "[bootstrap] minting bundle into $$OUT (mint_v2_snapshot is read-only over the copy)"; \
	rm -rf "$$OUT"; mkdir -p "$$OUT"; \
	"$$MINT" "$$WORK" 0 "$$OUT/.snapshot.tmp" "$$OUT"; \
	rm -f "$$OUT/.snapshot.tmp"; \
	SNAP="$$(ls "$$OUT"/utxo-seed-*.snapshot 2>/dev/null | head -1)"; \
	[ -n "$$SNAP" ] || { echo "bootstrap: mint produced no utxo-seed-*.snapshot in $$OUT" >&2; exit 1; }; \
	[ -f "$$OUT/block_index.bin" ] || { echo "bootstrap: mint produced no block_index.bin in $$OUT" >&2; exit 1; }; \
	SEED_H="$$(basename "$$SNAP" | sed -n 's/^utxo-seed-\([0-9][0-9]*\)\.snapshot$$/\1/p')"; \
	[ -n "$$SEED_H" ] || { echo "bootstrap: cannot parse seed height from $$SNAP" >&2; exit 1; }; \
	echo "[bootstrap] bundle minted: seed_height=$$SEED_H"; \
	: 'COPY-PROVE: fresh /tmp datadir, zero-flag autodetect, assert H* CLIMBS past seed.'; \
	echo "[bootstrap] copy-prove: booting fresh $$PROVE from the bundle (-nolegacyimport, no -load-snapshot flag)"; \
	rm -rf "$$PROVE"; mkdir -p "$$PROVE"; \
	cp "$$OUT/block_index.bin" "$$PROVE/"; cp "$$SNAP" "$$PROVE/"; \
	ISO_HOME="$$PROVE/.home"; mkdir -p "$$ISO_HOME"; \
	HOME="$$ISO_HOME" "$$NODE" -datadir="$$PROVE" -nolegacyimport -nobgvalidation \
	  -rpcport=18299 -port=18933 -fsport=18934 -httpsport=18935 -addnode="$$PEER" \
	  > "$$PROVE/prove.log" 2>&1 & NODE_PID=$$!; \
	trap 'kill -TERM '"$$NODE_PID"' 2>/dev/null || true' EXIT INT TERM; \
	tipof() { \
	  resp="$$(HOME="$$ISO_HOME" ZCL_DATADIR="$$PROVE" ZCL_RPCPORT=18299 "$$RPC" getblockcount 2>/dev/null || true)"; \
	  case "$$resp" in \
	    *'"result"'*) printf '%s\n' "$$resp" | sed -n 's/.*"result"[[:space:]]*:[[:space:]]*\(-\{0,1\}[0-9][0-9]*\).*/\1/p' | head -1 ;; \
	    *) printf '%s\n' "$$resp" | sed -n 's/^[[:space:]]*\(-\{0,1\}[0-9][0-9]*\)[[:space:]]*$$/\1/p' | head -1 ;; \
	  esac; \
	}; \
	deadline=$$(( $$(date +%s) + DEADLINE )); first=-1; cur=-1; climbed=0; \
	while [ "$$(date +%s)" -lt "$$deadline" ]; do \
	  if ! kill -0 "$$NODE_PID" 2>/dev/null; then echo "[bootstrap] node exited early (see $$PROVE/prove.log)"; break; fi; \
	  t="$$(tipof)"; t="$${t:--1}"; \
	  if [ "$$t" -ge 0 ] 2>/dev/null; then \
	    if [ "$$first" -lt 0 ]; then first="$$t"; echo "[bootstrap] first served H*=$$t (seed=$$SEED_H)"; fi; \
	    cur="$$t"; \
	    if [ "$$t" -gt "$$SEED_H" ]; then climbed=1; echo "[bootstrap] H* CLIMBED to $$t (> seed $$SEED_H)"; break; fi; \
	  fi; \
	  sleep 5; \
	done; \
	kill -TERM "$$NODE_PID" 2>/dev/null || true; wait "$$NODE_PID" 2>/dev/null || true; trap - EXIT INT TERM; \
	if [ "$$climbed" != "1" ]; then \
	  echo "[bootstrap] COPY-PROVE FAILED: H* did not climb past seed $$SEED_H (first=$$first last=$$cur) within $${DEADLINE}s" >&2; \
	  echo "            Bundle is NOT proven; refusing to mark publishable. log: $$PROVE/prove.log" >&2; \
	  exit 1; \
	fi; \
	printf 'seed_height=%s\ngit_head=%s\nproved_utc=%s\nfirst_hstar=%s\nclimbed_to=%s\n' \
	  "$$SEED_H" "$$(git rev-parse HEAD 2>/dev/null || echo unknown)" \
	  "$$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$$first" "$$cur" > "$$OUT/.copyprove-ok"; \
	echo "[bootstrap] COPY-PROVE PASSED — assisted bundle in $$OUT passed byte-integrity and climb checks (seed=$$SEED_H, H* $$first -> $$cur)"
	@: 'mint_v2_snapshot already wrote the authoritative SHA256SUMS + rich (schema_version 2) manifest.json'
	@: 'during the mint step above — do NOT regenerate them here (the shell bootstrap-manifest writes a leaner'
	@: 'schema that would DROP anchor_block_hash / snapshot_sha3 / utxo_count / total_supply / build_commit).'

# Standalone: regenerate ONLY SHA256SUMS over an existing bundle dir (e.g. after a
# manual file swap). The rich manifest.json is authored by mint_v2_snapshot during
# `make bootstrap`; this target deliberately does NOT rewrite it, to avoid
# downgrading its schema.
bootstrap-manifest:
	@set -eu; \
	OUT='$(ZCL_BOOTSTRAP_OUT)'; \
	[ -d "$$OUT" ] || { echo "bootstrap-manifest: no bundle dir: $$OUT" >&2; exit 1; }; \
	SNAP="$$(ls "$$OUT"/utxo-seed-*.snapshot 2>/dev/null | head -1)"; \
	[ -n "$$SNAP" ] || { echo "bootstrap-manifest: no utxo-seed-*.snapshot in $$OUT" >&2; exit 1; }; \
	[ -f "$$OUT/block_index.bin" ] || { echo "bootstrap-manifest: no block_index.bin in $$OUT" >&2; exit 1; }; \
	SNAP_BASE="$$(basename "$$SNAP")"; \
	SEED_H="$$(printf '%s' "$$SNAP_BASE" | sed -n 's/^utxo-seed-\([0-9][0-9]*\)\.snapshot$$/\1/p')"; \
	[ -n "$$SEED_H" ] || { echo "bootstrap-manifest: cannot parse seed height from $$SNAP_BASE" >&2; exit 1; }; \
	( cd "$$OUT" && sha256sum block_index.bin "$$SNAP_BASE" > SHA256SUMS ); \
	echo "[bootstrap-manifest] regenerated $$OUT/SHA256SUMS (seed_height=$$SEED_H)"; \
	echo "[bootstrap-manifest] manifest.json is authored by mint_v2_snapshot (make bootstrap); not rewritten here"; \
	echo "[bootstrap-manifest] verify with: ( cd $$OUT && sha256sum -c SHA256SUMS )"

bootstrap-publish:
	@echo "bootstrap-publish: REFUSING — stable starter-pack publication is contained" >&2
	@echo "  Copy proof alone is not publication authority. Canonical sync/security," >&2
	@echo "  exact-candidate fuzz, coverage, reproducibility, soak, signed manifest," >&2
	@echo "  and immutable release-evidence gates are not all implemented and green." >&2
	@echo "  Local bundle production remains available via 'make bootstrap'." >&2
	@exit 2

$(BIN_DIR)/session: $(TMPL_GEN) $(BUILD_IDENTITY_STAMP) tools/session.c \
		$(ALL_SRCS) $(COMMAND_CATALOG_DEFS)
	@mkdir -p $(dir $@)
	@set -eu; \
	tmp="$$(mktemp "$@.link.XXXXXX")"; \
	trap 'rm -f "$$tmp"' EXIT HUP INT TERM; \
	$(CC) $(CFLAGS) -Wno-deprecated-declarations $(LDFLAGS) -o "$$tmp" $(filter-out $(TMPL_GEN) $(BUILD_IDENTITY_STAMP) $(COMMAND_CATALOG_DEFS),$^) $(TOR_LIBS) $(LIBS) $(GTK_LIBS) $(WEBKIT_LIBS) -lm; \
	tools/dev/source-identity.sh verify-record "$(BUILD_SOURCE_ID)" "$(BUILD_CLEAN)" "$(BUILD_MUTATION)" >/dev/null; \
	mv -f -- "$$tmp" "$@"; \
	trap - EXIT HUP INT TERM

session: $(BIN_DIR)/session
	$(BIN_DIR)/session

$(BIN_DIR)/bot: $(TMPL_GEN) $(BUILD_IDENTITY_STAMP) tools/bot.c \
		$(ALL_SRCS) $(COMMAND_CATALOG_DEFS)
	@mkdir -p $(dir $@)
	@set -eu; \
	tmp="$$(mktemp "$@.link.XXXXXX")"; \
	trap 'rm -f "$$tmp"' EXIT HUP INT TERM; \
	$(CC) $(CFLAGS) -Wno-deprecated-declarations $(LDFLAGS) -o "$$tmp" $(filter-out $(TMPL_GEN) $(BUILD_IDENTITY_STAMP) $(COMMAND_CATALOG_DEFS),$^) $(TOR_LIBS) $(LIBS) $(GTK_LIBS) $(WEBKIT_LIBS) -lm; \
	tools/dev/source-identity.sh verify-record "$(BUILD_SOURCE_ID)" "$(BUILD_CLEAN)" "$(BUILD_MUTATION)" >/dev/null; \
	mv -f -- "$$tmp" "$@"; \
	trap - EXIT HUP INT TERM

bot: $(BIN_DIR)/bot
	$(BIN_DIR)/bot

mock_rpc: $(BIN_DIR)/mock_rpc
$(BIN_DIR)/mock_rpc: tools/mock_rpc.c
	@mkdir -p $(dir $@)
	$(CC) -std=c23 -O2 -Wall -Wextra -Werror -pthread -o $@ $<

$(eval $(call BUILD_NODE_TOOL,wallet_sim,tools/wallet_sim.c))
$(eval $(call BUILD_NODE_TOOL,wallet_check,tools/wallet_check.c,-lm))
$(eval $(call BUILD_NODE_TOOL,rebuild_recent,tools/rebuild_recent.c,-lm,-fopenmp))
# The EXTERNAL ZCODE package verifier (slice 6): the ONLY program that ever
# compiles/executes package code, sandboxed per child (seccomp + rlimits +
# Landlock). The node binary never does. Its fixed offline boundary also makes
# the Tor stub the only honest link input; a host's optional full-Tor build must
# not affect verifier bytes. See tools/package_verify.c.
.PHONY: zclassic23-package-verify
zclassic23-package-verify: $(BIN_DIR)/zclassic23-package-verify
$(BIN_DIR)/zclassic23-package-verify: $(VIEW_GEN_HEADERS) \
		$(BUILD_IDENTITY_STAMP) tools/package_verify.c $(ALL_SRCS) \
		$(COMMAND_CATALOG_DEFS) $(C23_PORTABLE_RELINK) | $(NODE_VENDOR_LIBS)
	@mkdir -p $(dir $@)
	@set -eu; \
	tmp="$$(mktemp "$@.link.XXXXXX")"; \
	trap 'rm -f "$$tmp"' EXIT HUP INT TERM; \
	$(CC) $(NODE_C23_CFLAGS) -Wno-deprecated-declarations $(LDFLAGS) \
		-o "$$tmp" \
		$(filter-out $(VIEW_GEN_HEADERS) $(BUILD_IDENTITY_STAMP) \
			$(COMMAND_CATALOG_DEFS) $(C23_PORTABLE_RELINK),$^) \
		vendor/lib/libtor_stub.a $(NODE_C23_LIBS); \
	tools/dev/source-identity.sh verify-record "$(BUILD_SOURCE_ID)" \
		"$(BUILD_CLEAN)" "$(BUILD_MUTATION)" >/dev/null; \
	mv -f -- "$$tmp" "$@"; \
	trap - EXIT HUP INT TERM
# Opt-in C23 development adapter. This small front process enters Landlock and
# scrubs credentials before it invokes the fixed Codex CLI; the node handler
# never executes a caller-supplied command.
ZCODE_ADAPTER_RUNNER_SRCS = tools/zcode_adapter_runner.c \
	lib/platform/src/os_sandbox_linux.c lib/base/src/cleanse.c \
	lib/base/src/log_level.c lib/base/src/result.c lib/sha3/src/sha3.c
.PHONY: zclassic23-zcode-adapter-runner
zclassic23-zcode-adapter-runner: $(BIN_DIR)/zclassic23-zcode-adapter-runner
$(BIN_DIR)/zclassic23-zcode-adapter-runner: $(BUILD_IDENTITY_STAMP) \
		$(ZCODE_ADAPTER_RUNNER_SRCS)
	@mkdir -p $(dir $@)
	@set -eu; \
	tmp="$$(mktemp "$@.link.XXXXXX")"; \
	trap 'rm -f "$$tmp"' EXIT HUP INT TERM; \
	$(CC) $(DEV_RESTART_CFLAGS) -Wno-deprecated-declarations \
		$(BUILD_IDENTITY_CPPFLAGS) \
		$(DEV_RESTART_LDFLAGS) -o "$$tmp" \
		$(ZCODE_ADAPTER_RUNNER_SRCS); \
	tools/dev/source-identity.sh verify-record "$(BUILD_SOURCE_ID)" "$(BUILD_CLEAN)" "$(BUILD_MUTATION)" >/dev/null; \
	mv -f -- "$$tmp" "$@"; \
	trap - EXIT HUP INT TERM

# Measurement-only Codex app-server client. It exposes no command or external
# tool surface and drives exactly one candidate-rooted thread over JSON-RPC.
ZCODE_APP_SERVER_BENCHMARK_SRCS = tools/zcode_app_server_benchmark.c \
	lib/json/src/json.c lib/base/src/safe_alloc.c lib/platform/src/clock.c
.PHONY: zcode-app-server-benchmark
zcode-app-server-benchmark: $(BIN_DIR)/zclassic23-zcode-app-server-benchmark
$(BIN_DIR)/zclassic23-zcode-app-server-benchmark: $(BUILD_IDENTITY_STAMP) \
		$(ZCODE_APP_SERVER_BENCHMARK_SRCS)
	@mkdir -p $(dir $@)
	@set -eu; \
	tmp="$$(mktemp "$@.link.XXXXXX")"; \
	trap 'rm -f "$$tmp"' EXIT HUP INT TERM; \
	$(CC) $(DEV_RESTART_CFLAGS) $(DEV_RESTART_LDFLAGS) -o "$$tmp" \
		$(ZCODE_APP_SERVER_BENCHMARK_SRCS); \
	tools/dev/source-identity.sh verify-record "$(BUILD_SOURCE_ID)" \
		"$(BUILD_CLEAN)" "$(BUILD_MUTATION)" >/dev/null; \
	mv -f -- "$$tmp" "$@"; \
	trap - EXIT HUP INT TERM

# C23-only parser and deterministic content oracle for the isolated two-node
# market acceptance.  The shell harness retains process-group orchestration;
# all JSON interpretation and content hashing stays in this bounded binary.
MARKET_ACCEPTANCE_HELPER_SRCS = tools/market_acceptance_helper.c \
	lib/json/src/json.c lib/base/src/safe_alloc.c lib/sha3/src/sha3.c
.PHONY: market-acceptance-helper test-market-acceptance-helper
market-acceptance-helper: $(BIN_DIR)/zclassic23-market-acceptance-helper
$(BIN_DIR)/zclassic23-market-acceptance-helper: \
		$(MARKET_ACCEPTANCE_HELPER_SRCS)
	@mkdir -p $(dir $@)
	@set -eu; \
	tmp="$$(mktemp "$@.link.XXXXXX")"; \
	trap 'rm -f "$$tmp"' EXIT HUP INT TERM; \
	$(CC) $(DEV_RESTART_CFLAGS) $(DEV_RESTART_LDFLAGS) -o "$$tmp" \
		$(MARKET_ACCEPTANCE_HELPER_SRCS); \
	mv -f -- "$$tmp" "$@"; \
	trap - EXIT HUP INT TERM

test-market-acceptance-helper: market-acceptance-helper
	@$(BIN_DIR)/zclassic23-market-acceptance-helper --selftest

.PHONY: sim dump check-wallet
sim: wallet_sim
	$(BIN_DIR)/wallet_sim
dump: wallet_dump
	$(BIN_DIR)/wallet_dump

check-wallet: wallet_check
	$(BIN_DIR)/wallet_check

.PHONY: spec
spec: spec_zcl
	ulimit -s unlimited && $(BIN_DIR)/spec_zcl

.PHONY: z23 zclassic23 portable c23-portable-toolchain c23-portable-release \
	c23-portable-install
z23: $(ZCLASSIC23_BIN) $(ZCLASSIC23_BIN_ALIAS)

# Temporary migration alias: `make zclassic23` and build/bin/zclassic23 keep
# working while bots/scripts move to z23.
zclassic23: z23

$(ZCLASSIC23_BIN_ALIAS): $(ZCLASSIC23_BIN)
	@ln -sfn z23 "$@"

# Release portability is an explicit, reproducible build input rather than an
# accidental property of the maintainer's workstation. This path downloads a
# checksum-pinned Debian 11 glibc 2.31 sysroot, then uses the ordinary host C23
# compiler for every linked archive and the node. No container, sudo, Zig, or
# alternate language toolchain is involved. The portable baseline deliberately
# selects the default Tor stub so an optional host-built full-Tor archive cannot
# leak a newer host ABI into the artifact.
c23-portable-toolchain:
	@tools/scripts/c23_portable_sysroot.sh verify

c23-portable-release:
	@tools/scripts/build_c23_portable_release.sh

# Short, memorable release front door. Keep the explicit name above for
# scripts and old documentation; operators should only need `make portable`.
portable: c23-portable-release

# Split-debug: CFLAGS carries -g, but the shipped binary stays stripped —
# the debug payload moves to $@.debug next to the binary and .gnu_debuglink
# points at it, so addr2line/gdb resolve file:line (symbolize_crash.sh)
# without growing the deployed artifact. The sidecar is staged in a temp
# dir under its final basename because --add-gnu-debuglink reads the file
# (stored name + CRC32) at link time.
$(ZCLASSIC23_BIN): $(VIEW_GEN_HEADERS) $(BUILD_IDENTITY_STAMP) \
		$(NODE_ENTRY_SRCS) $(ALL_SRCS) $(COMMAND_CATALOG_DEFS) \
		$(C23_PORTABLE_RELINK) | $(NODE_VENDOR_LIBS)
	@mkdir -p $(dir $@)
	@set -eu; \
	tmp="$$(mktemp "$@.link.XXXXXX")"; \
	dbg="$@.debug"; \
	dbgdir="$$(mktemp -d "$@.dbgdir.XXXXXX")"; \
	trap 'rm -rf "$$tmp" "$$dbgdir"' EXIT HUP INT TERM; \
	$(CC) $(NODE_C23_CFLAGS) -Wno-deprecated-declarations $(LDFLAGS) -o "$$tmp" $(filter-out $(VIEW_GEN_HEADERS) $(BUILD_IDENTITY_STAMP) $(COMMAND_CATALOG_DEFS) $(C23_PORTABLE_RELINK),$^) $(NODE_C23_TOR_LIBS) $(NODE_C23_LIBS); \
	objcopy --only-keep-debug "$$tmp" "$$dbgdir/$$(basename "$$dbg")"; \
	strip -s "$$tmp"; \
	objcopy --add-gnu-debuglink="$$dbgdir/$$(basename "$$dbg")" "$$tmp"; \
	tools/scripts/check_c23_node_binary.sh "$$tmp"; \
	tools/dev/source-identity.sh verify-record "$(BUILD_SOURCE_ID)" "$(BUILD_CLEAN)" "$(BUILD_MUTATION)" >/dev/null; \
	mv -f -- "$$tmp" "$@"; \
	mv -f -- "$$dbgdir/$$(basename "$$dbg")" "$$dbg"; \
	rmdir "$$dbgdir"; \
	trap - EXIT HUP INT TERM

.PHONY: zclassic-cli
zclassic-cli: $(ZCLASSIC_CLI_BIN)
$(ZCLASSIC_CLI_BIN): $(BUILD_IDENTITY_STAMP) src/cli.c $(CLI_SRCS) lib/base/src/safe_alloc.c
	@mkdir -p $(dir $@)
	@set -eu; \
	tmp="$$(mktemp "$@.link.XXXXXX")"; \
	trap 'rm -f "$$tmp"' EXIT HUP INT TERM; \
	$(CC) $(CFLAGS) $(LDFLAGS) -o "$$tmp" $(filter-out $(BUILD_IDENTITY_STAMP),$^) -lm; \
	strip -s "$$tmp"; \
	tools/dev/source-identity.sh verify-record "$(BUILD_SOURCE_ID)" "$(BUILD_CLEAN)" "$(BUILD_MUTATION)" >/dev/null; \
	mv -f -- "$$tmp" "$@"; \
	trap - EXIT HUP INT TERM

# In-tree WAL checkpoint tool used by `deploy`.  Replaces a dependency on
# the sqlite3(1) CLI that isn't installed by default on stock Ubuntu/Debian
# (only libsqlite3-0) — was P12.4 in AGENT.md.  Calls
# sqlite3_wal_checkpoint_v2(TRUNCATE) on the open DB and exits non-zero on
# failure so `make deploy` halts loudly instead of silently skipping the
# checkpoint.
.PHONY: tools/wal_checkpoint
tools/wal_checkpoint: $(WAL_CHECKPOINT_BIN)
$(WAL_CHECKPOINT_BIN): tools/wal_checkpoint.c
	@mkdir -p $(dir $@)
	$(CC) -std=c23 -O2 -Wall -Wextra -Werror -Ivendor/include -o $@ $< \
	    -Lvendor/lib -l:libsqlite3.a -lpthread -ldl -lm

$(eval $(call BUILD_NODE_TOOL,wallet-wireframes,tools/wallet_wireframes.c))
$(eval $(call BUILD_NODE_TOOL,speedrun,tools/speedrun.c))

.PHONY: zcl-rpc
zcl-rpc: $(ZCL_RPC_BIN)
$(ZCL_RPC_BIN): FORCE tools/zcl-rpc.c
	@mkdir -p $(dir $@)
	$(CC) -std=c23 -O2 -Wall -o $@ $(filter-out FORCE,$^)

# zcl-portfwd: tiny self-contained userspace TCP forwarder that maps public
# 443/80 -> the node's unprivileged high ports (8443/8080). It is the ONE file
# that gets cap_net_bind_service (via tools/scripts/zcl-portfwd-setup.sh), so
# the node binary stays uncapped across redeploys. No node deps. See
# docs/BLOCK_EXPLORER_HOSTING.md.
.PHONY: zcl-portfwd
zcl-portfwd: $(BIN_DIR)/zcl-portfwd
$(BIN_DIR)/zcl-portfwd: tools/zcl_portfwd.c
	@mkdir -p $(dir $@)
	$(CC) -std=c23 -O2 -Wall -Wextra -o $@ $<

# gen_sha3_windows: one-shot tool that queries a fully-synced reference
# node and overwrites lib/chain/{include/chain,src}/sha3_windows.{h,c}
# with SHA3-256 commitments over 1000-block windows. Standalone build:
# only the libs it directly uses, no DB, no Tor.
.PHONY: tools/gen_sha3_windows
tools/gen_sha3_windows: $(BIN_DIR)/gen_sha3_windows
$(BIN_DIR)/gen_sha3_windows: tools/gen_sha3_windows.c \
		lib/chain/src/sha3_windows.c \
		lib/sha3/src/sha3.c lib/crypto/src/keccak_x4.c lib/crypto/src/simd_dispatch.c lib/encoding/src/utilstrencodings.c \
		lib/json/src/json.c lib/platform/src/clock.c \
		lib/base/src/safe_alloc.c lib/base/src/cleanse.c
	@mkdir -p $(dir $@)
	$(CC) -std=c23 -O3 -march=native -Wall -Wextra -Werror -pedantic \
	    $(ZCL_WARN_STRINGOP_OVERFLOW) \
	    -Ilib/chain/include -Ilib/sha3/include -Ilib/crypto/include -Ilib/encoding/include \
	    -Ilib/json/include -Ilib/platform/include -Ilib/base/include -Ilib/util/include \
	    -Ilib/support/include \
	    -D_POSIX_C_SOURCE=200809L \
	    -o $@ $^ -pthread

# corpus-census: offline driver for the C23 corpus odometer (slice 1b).
# Reads corpus/scopes.def, enumerates scopes via git ls-files, binds every
# census evidence bit to a real recomputable artifact, and emits the signed
# checkpoint/shard/evidence/report set under corpus/. Standalone build: the
# pure census core plus the vcs evidence objects it drives — no DB, no Tor.
.PHONY: tools/corpus-census
tools/corpus-census: $(BIN_DIR)/corpus-census
$(BIN_DIR)/corpus-census: tools/corpus_census.c \
		lib/vcs/src/zcode_c23_corpus_census.c \
		lib/vcs/src/zcode_c23_corpus_objects.c \
		lib/vcs/src/zcode_c23_corpus_shard.c \
		lib/vcs/src/zcode_c23_corpus_checkpoint.c \
		lib/vcs/src/zcode_family_admission_object.c \
		lib/vcs/src/zcode_family_moderation.c \
		lib/vcs/src/signed_evidence.c \
		lib/vcs/src/package_score.c lib/vcs/src/package_release.c \
		lib/vcs/src/package_manifest.c lib/vcs/src/package_recipe.c \
		lib/vcs/src/package_build.c lib/vcs/src/package_reproduce.c \
		lib/vcs/src/vcs_object.c \
		lib/crypto/src/ed25519.c lib/crypto/src/sha512.c \
		lib/sha3/src/sha3.c \
		lib/base/src/cleanse.c lib/base/src/log_level.c \
		lib/base/src/safe_alloc.c \
		lib/codec/src/cursor.c lib/json/src/json.c \
		lib/platform/src/rng.c lib/platform/src/clock.c
	@mkdir -p $(dir $@)
	# --gc-sections: ed25519's batch-verify path (never called here) pulls
	# zcl_random_secret_bytes -> sealed-tree random.c; the collector drops it.
	$(CC) -std=c23 -O2 -Wall -Wextra -Werror -pedantic \
	    $(ZCL_WARN_STRINGOP_OVERFLOW) \
	    -D_POSIX_C_SOURCE=200809L \
	    -ffunction-sections -fdata-sections -Wl,--gc-sections \
	    -Ilib/vcs/include -Ilib/base/include -Ilib/util/include \
	    -Ilib/crypto/include -Ilib/sha3/include -Ilib/codec/include \
	    -Ilib/json/include -Ilib/platform/include -Ilib/support/include \
	    -Ilib/core/include -Ivendor/include \
	    -o $@ $^ -Lvendor/lib -l:libsecp256k1.a -lpthread -lm

# Run the corpus census. The default is a SMOKE run into build/corpus-census/
# (unsigned, cutoff 1, quality unattested) so it can never overwrite the
# committed signed artifacts under corpus/. Advancing the canonical sequence
# is an explicit operator act (the predecessor root and previous report are
# discovered from CORPUS_OUT automatically):
#   make corpus-census CORPUS_OUT=corpus CORPUS_SEQUENCE=N \
#       CORPUS_CUTOFF_HEIGHT=... CORPUS_CUTOFF_MTP=... \
#       CORPUS_QUALITY_ATTESTED=1 CORPUS_INSTALL=<datadir>
#   (CORPUS_PREDECESSOR_ROOT / CORPUS_PREVIOUS_REPORT override discovery)
.PHONY: corpus-census
corpus-census: $(BIN_DIR)/corpus-census
	$(BIN_DIR)/corpus-census --repo . --def corpus/scopes.def \
	    --out $${CORPUS_OUT:-build/corpus-census} \
	    --cutoff-height $${CORPUS_CUTOFF_HEIGHT:-1} \
	    --cutoff-mtp $${CORPUS_CUTOFF_MTP:-1700000000} \
	    --quality-attested $${CORPUS_QUALITY_ATTESTED:-0} \
	    $${CORPUS_SEQUENCE:+--sequence $${CORPUS_SEQUENCE}} \
	    $${CORPUS_PREDECESSOR_ROOT:+--predecessor-root $${CORPUS_PREDECESSOR_ROOT}} \
	    $${CORPUS_INSTALL:+--install $${CORPUS_INSTALL}} \
	    $${CORPUS_PREVIOUS_REPORT:+--previous-report $${CORPUS_PREVIOUS_REPORT}}

# package-factory: the one reusable package pipeline (slice 2). Gates a
# fixed-layout package dir, prepares + seals + publishes a signed release
# into two independent local stores, files a second distinct confined-build
# receipt (quick + standard flag profiles on one host, disclosed), verifies
# reproduction, and prints a JSON report. It drives the zclassic23 CLI and
# the package-sign/package-verify helpers as subprocesses; the only linked
# vcs code is the pure evidence-object layer (no DB, no Tor). `pin-dep`
# splices a published dependency root into zcode-package.json when the
# dependency still carries the all-zero placeholder. `selftest` runs the
# full journey on the tiny-lines fixture and then drives corpus-census over
# the published store to prove the census package-scope intake end to end.
.PHONY: tools/package-factory
tools/package-factory: $(BIN_DIR)/package-factory
$(BIN_DIR)/package-factory: tools/package_factory.c \
		lib/vcs/src/package_prepare.c lib/vcs/src/package_manifest.c \
		lib/vcs/src/package_recipe.c lib/vcs/src/package_deps.c \
		lib/vcs/src/package_capsule.c lib/vcs/src/package_release.c \
		lib/vcs/src/package_build.c lib/vcs/src/package_reproduce.c \
		lib/vcs/src/zcode_c23_corpus_objects.c \
		lib/vcs/src/zcode_family_admission_object.c \
		lib/vcs/src/zcode_family_moderation.c \
		lib/vcs/src/signed_evidence.c \
		lib/crypto/src/ed25519.c lib/crypto/src/sha512.c \
		lib/sha3/src/sha3.c \
		lib/base/src/cleanse.c lib/base/src/log_level.c \
		lib/base/src/safe_alloc.c \
		lib/codec/src/cursor.c lib/json/src/json.c \
		lib/platform/src/rng.c lib/platform/src/clock.c
	@mkdir -p $(dir $@)
	$(CC) -std=c23 -O2 -Wall -Wextra -Werror -pedantic \
	    $(ZCL_WARN_STRINGOP_OVERFLOW) \
	    -D_POSIX_C_SOURCE=200809L \
	    -ffunction-sections -fdata-sections -Wl,--gc-sections \
	    -Ilib/vcs/include -Ilib/base/include -Ilib/util/include \
	    -Ilib/crypto/include -Ilib/sha3/include -Ilib/codec/include \
	    -Ilib/json/include -Ilib/platform/include -Ilib/support/include \
	    -Ilib/core/include -Ivendor/include \
	    -o $@ $^ -Lvendor/lib -l:libsecp256k1.a -lpthread -lm

# arena_runner: deterministic 2-team zdogfight match driver (dev tool; NOT a
# native command — config/commands/*.def untouched). Spawns one confined
# pilot process per team (os_sandbox session child profile, zero fs grants),
# drives the fixed obs/ctl pipe protocol, and emits replay/final-state roots
# for cross-node byte-identical replay verification. Standalone target like
# the factory's; not wired into any default build path.
.PHONY: tools/arena-runner tools/arena-product-journey-c23
tools/arena-runner: $(BIN_DIR)/arena_runner
tools/arena-product-journey-c23: $(BIN_DIR)/arena_product_journey_c23
$(BIN_DIR)/arena_product_journey_c23: tools/arena_product_journey_c23.c \
		lib/json/src/json.c lib/base/src/safe_alloc.c \
		lib/base/src/log_level.c
	@mkdir -p $(dir $@)
	$(CC) -std=c23 -O2 -Wall -Wextra -Werror -pedantic \
	    $(ZCL_WARN_STRINGOP_OVERFLOW) -D_POSIX_C_SOURCE=200809L \
	    -Ilib/json/include -Ilib/base/include -o $@ $^ -lpthread -lm
$(BIN_DIR)/arena_runner: tools/arena_runner.c \
		packages/zdogfight/src/zdogfight.c packages/zdogfight/src/zdogfix.c \
		packages/zprng/src/zprng.c \
		lib/platform/src/os_sandbox_linux.c lib/platform/src/clock.c \
		lib/base/src/result.c lib/base/src/log_level.c \
		lib/base/src/safe_alloc.c \
		lib/sha3/src/sha3.c
	@mkdir -p $(dir $@)
	$(CC) -std=c23 -O2 -Wall -Wextra -Werror -pedantic \
	    $(ZCL_WARN_STRINGOP_OVERFLOW) \
	    -D_POSIX_C_SOURCE=200809L \
	    -ffunction-sections -fdata-sections -Wl,--gc-sections \
	    -Ipackages/zdogfight/include -Ipackages/zprng/include \
	    -Ilib/platform/include -Ilib/base/include -Ilib/util/include \
	    -Ilib/sha3/include -Ilib/support/include -Ivendor/include \
	    -o $@ $^ -lm

# arena_present: bridge one zdogfight replay stream into the bounded
# renderer-neutral presentation model ABI (M6). Re-simulates the replay and
# REFUSES anything whose trailing state does not re-derive exactly; the kill
# narrative comes from deterministic alive->dead transitions, never a side
# log. Standalone dev tool; not wired into any default build path.
.PHONY: tools/arena-present
tools/arena-present: $(BIN_DIR)/arena_present
$(BIN_DIR)/arena_present: tools/arena_present.c \
		packages/zdogfight/src/zdogfight.c packages/zdogfight/src/zdogfix.c \
		packages/zprng/src/zprng.c \
		lib/presentation/src/model.c \
		lib/base/src/safe_alloc.c \
		lib/sha3/src/sha3.c
	@mkdir -p $(dir $@)
	$(CC) -std=c23 -O2 -Wall -Wextra -Werror -pedantic \
	    $(ZCL_WARN_STRINGOP_OVERFLOW) \
	    -D_POSIX_C_SOURCE=200809L \
	    -ffunction-sections -fdata-sections -Wl,--gc-sections \
	    -Ipackages/zdogfight/include -Ipackages/zprng/include \
	    -Ilib/presentation/include -Ilib/base/include -Ilib/util/include \
	    -Ilib/sha3/include -Ilib/support/include -Ivendor/include \
	    -o $@ $^ -lm

# arena-selftest: build and run the born-red package test suites for the
# zdogfight arena core, both starter pilots, and the integer 3D view
# (cross-instance determinism, match rules, wire round-trips, replay
# refusal, deterministic PPM). The packages ship these tests in their
# zcode-package.json manifests; this is the local runner. Standalone
# target; not wired into any default build path.
.PHONY: tools/arena-selftest
tools/arena-selftest: $(BIN_DIR)/test_zdogfight $(BIN_DIR)/test_zdogace \
		$(BIN_DIR)/test_zdogdrone $(BIN_DIR)/test_zdogview
	$(BIN_DIR)/test_zdogfight
	$(BIN_DIR)/test_zdogace
	$(BIN_DIR)/test_zdogdrone
	$(BIN_DIR)/test_zdogview

$(BIN_DIR)/test_zdogfight: packages/zdogfight/tests/test_zdogfight.c \
		packages/zdogfight/src/zdogfight.c packages/zdogfight/src/zdogfix.c \
		packages/zprng/src/zprng.c
	@mkdir -p $(dir $@)
	$(CC) -std=c23 -O2 -Wall -Wextra -Werror -pedantic \
	    $(ZCL_WARN_STRINGOP_OVERFLOW) \
	    -D_POSIX_C_SOURCE=200809L \
	    -Ipackages/zdogfight/include -Ipackages/zprng/include \
	    -o $@ $^ -lm

$(BIN_DIR)/test_zdogace: packages/zdogace/tests/test_zdogace.c \
		packages/zdogace/src/zdogace.c \
		packages/zdogfight/src/zdogfight.c packages/zdogfight/src/zdogfix.c \
		packages/zprng/src/zprng.c
	@mkdir -p $(dir $@)
	$(CC) -std=c23 -O2 -Wall -Wextra -Werror -pedantic \
	    $(ZCL_WARN_STRINGOP_OVERFLOW) \
	    -D_POSIX_C_SOURCE=200809L \
	    -Ipackages/zdogace/include -Ipackages/zdogfight/include \
	    -Ipackages/zprng/include \
	    -o $@ $^ -lm

$(BIN_DIR)/test_zdogdrone: packages/zdogdrone/tests/test_zdogdrone.c \
		packages/zdogdrone/src/zdogdrone.c \
		packages/zprng/src/zprng.c
	@mkdir -p $(dir $@)
	$(CC) -std=c23 -O2 -Wall -Wextra -Werror -pedantic \
	    $(ZCL_WARN_STRINGOP_OVERFLOW) \
	    -D_POSIX_C_SOURCE=200809L \
	    -Ipackages/zdogdrone/include -Ipackages/zdogfight/include \
	    -Ipackages/zprng/include \
	    -o $@ $^ -lm

$(BIN_DIR)/test_zdogview: packages/zdogview/tests/test_zdogview.c \
		packages/zdogview/src/zdogview.c \
		packages/zdogfight/src/zdogfight.c packages/zdogfight/src/zdogfix.c \
		packages/zprng/src/zprng.c
	@mkdir -p $(dir $@)
	$(CC) -std=c23 -O2 -Wall -Wextra -Werror -pedantic \
	    $(ZCL_WARN_STRINGOP_OVERFLOW) \
	    -D_POSIX_C_SOURCE=200809L \
	    -Ipackages/zdogview/include -Ipackages/zdogfight/include \
	    -Ipackages/zprng/include \
	    -o $@ $^ -lm

.PHONY: tools/zdogview
tools/zdogview: $(BIN_DIR)/zdogview
$(BIN_DIR)/zdogview: packages/zdogview/app/main.c \
		packages/zdogview/src/zdogview.c \
		packages/zdogfight/src/zdogfight.c packages/zdogfight/src/zdogfix.c \
		packages/zprng/src/zprng.c
	@mkdir -p $(dir $@)
	$(CC) -std=c23 -O2 -Wall -Wextra -Werror -pedantic \
	    $(ZCL_WARN_STRINGOP_OVERFLOW) \
	    -D_POSIX_C_SOURCE=200809L \
	    -Ipackages/zdogview/include -Ipackages/zdogfight/include \
	    -Ipackages/zprng/include \
	    -o $@ $^ -lm

# ── ZCODE Arena: the public demo ──────────────────────────────────────────
# `make arena-demo` is the one command a brand-new reader runs after cloning.
# It needs no blockchain sync, no Tor, no wallet, no browser, no live node
# and no network: it compiles the arena core, two pilot programs and the
# runner, plays one deterministic match, re-simulates the recorded replay,
# checks the result against the pinned reference roots, and proves that a
# single altered control byte is refused by name.
#
# The pilots are linked -static on purpose: each one runs as a CONFINED
# child (Landlock domain granting read+execute on the pilot image alone,
# plus the session seccomp W^X deny-list), and W^X denies the PROT_EXEC
# mapping a dynamic loader needs. -O1 matches tools/dev/arena_acceptance.sh,
# whose two-node proof produced the pinned roots; the simulation is
# integer-only so the optimisation level cannot move them, and `make
# arena-demo-opt-parity` asserts exactly that instead of assuming it.
ARENA_PILOT_CFLAGS = -std=c23 -O1 -static -Wall -Wextra -Werror -pedantic \
    $(ZCL_WARN_STRINGOP_OVERFLOW) -D_POSIX_C_SOURCE=200809L

$(BIN_DIR)/pilot_zdogace: packages/zdogace/app/main.c \
		packages/zdogace/src/zdogace.c \
		packages/zdogfight/src/zdogfight.c packages/zdogfight/src/zdogfix.c \
		packages/zprng/src/zprng.c
	@mkdir -p $(dir $@)
	$(CC) $(ARENA_PILOT_CFLAGS) \
	    -Ipackages/zdogace/include -Ipackages/zdogfight/include \
	    -Ipackages/zprng/include \
	    -o $@ $^ -lm

$(BIN_DIR)/pilot_zdogdrone: packages/zdogdrone/app/main.c \
		packages/zdogdrone/src/zdogdrone.c \
		packages/zdogfight/src/zdogfight.c packages/zdogfight/src/zdogfix.c \
		packages/zprng/src/zprng.c
	@mkdir -p $(dir $@)
	$(CC) $(ARENA_PILOT_CFLAGS) \
	    -Ipackages/zdogdrone/include -Ipackages/zdogfight/include \
	    -Ipackages/zprng/include \
	    -o $@ $^ -lm

# arena_svg: deterministic headless replay renderer (see the file header).
# Re-simulates a replay and refuses to draw anything it cannot re-derive.
.PHONY: tools/arena-svg
tools/arena-svg: $(BIN_DIR)/arena_svg
$(BIN_DIR)/arena_svg: tools/arena_svg.c \
		packages/zdogfight/src/zdogfight.c packages/zdogfight/src/zdogfix.c \
		packages/zprng/src/zprng.c \
		lib/base/src/safe_alloc.c \
		lib/sha3/src/sha3.c
	@mkdir -p $(dir $@)
	$(CC) -std=c23 -O2 -Wall -Wextra -Werror -pedantic \
	    $(ZCL_WARN_STRINGOP_OVERFLOW) \
	    -D_POSIX_C_SOURCE=200809L \
	    -ffunction-sections -fdata-sections -Wl,--gc-sections \
	    -Ipackages/zdogfight/include -Ipackages/zprng/include \
	    -Ilib/base/include -Ilib/util/include \
	    -Ilib/sha3/include -Ilib/support/include -Ivendor/include \
	    -o $@ $^ -lm

# arena_view: interactive raylib 3D replay viewer (see the file header).
# Re-simulates a replay, refuses anything it cannot re-derive, then opens
# a window: chase/cockpit/orbit/overview cameras over a seed-deterministic
# city. Optional tool — requires raylib; not wired into any default path.
.PHONY: tools/arena-view
tools/arena-view: $(BIN_DIR)/arena_view
RAYLIB_CFLAGS := $(shell pkg-config --cflags raylib 2>/dev/null)
RAYLIB_LIBS := $(shell pkg-config --libs raylib 2>/dev/null)
$(BIN_DIR)/arena_view: tools/arena_view.c \
		packages/zdogview/src/zdogview.c \
		packages/zdogfight/src/zdogfight.c packages/zdogfight/src/zdogfix.c \
		packages/zprng/src/zprng.c \
		lib/base/src/safe_alloc.c \
		lib/sha3/src/sha3.c
	@mkdir -p $(dir $@)
	@if ! pkg-config --exists raylib; then \
	    echo "arena_view: raylib not found via pkg-config."; \
	    echo "  install it first (e.g. apt install libraylib-dev)"; \
	    exit 1; fi
	$(CC) -std=c23 -O2 -Wall -Wextra -Werror -pedantic \
	    $(ZCL_WARN_STRINGOP_OVERFLOW) \
	    -D_POSIX_C_SOURCE=200809L $(RAYLIB_CFLAGS) \
	    -ffunction-sections -fdata-sections -Wl,--gc-sections \
	    -Ipackages/zdogview/include -Ipackages/zdogfight/include \
	    -Ipackages/zprng/include \
	    -Ilib/base/include -Ilib/util/include \
	    -Ilib/sha3/include -Ilib/support/include -Ivendor/include \
	    -o $@ $^ $(RAYLIB_LIBS) -lm

ARENA_DEMO_BINS = $(BIN_DIR)/arena_runner $(BIN_DIR)/arena_svg \
	$(BIN_DIR)/pilot_zdogace $(BIN_DIR)/pilot_zdogdrone

.PHONY: arena-demo
arena-demo: $(ARENA_DEMO_BINS)
	@tools/dev/arena_demo.sh

# Regenerate the committed artwork from a freshly played, freshly verified
# match. The renderer is byte-deterministic, so `arena-svg-check` is a real
# staleness gate: edit the arena, a pilot, or the renderer without
# regenerating and it fails.
.PHONY: arena-svg arena-svg-check
arena-svg: $(ARENA_DEMO_BINS)
	@ARENA_SVG_WRITE=1 tools/dev/arena_demo.sh
arena-svg-check: $(ARENA_DEMO_BINS)
	@ARENA_SVG_CHECK=1 tools/dev/arena_demo.sh

# arena-view: play the demo match (or view REPLAY=<file>) in the 3D viewer.
# Passes --show so the window is visible. arena-view-check is the headless
# gate: argv refusals plus --check-only against the pinned demo roots.
.PHONY: arena-view arena-view-check
arena-view: $(BIN_DIR)/arena_view $(BIN_DIR)/arena_runner \
		$(BIN_DIR)/pilot_zdogace $(BIN_DIR)/pilot_zdogdrone
	@ZCL_BIN_DIR=$(BIN_DIR) REPLAY="$(REPLAY)" tools/dev/arena_view.sh
arena-view-check: $(BIN_DIR)/arena_view $(BIN_DIR)/zdogview \
		$(BIN_DIR)/arena_runner \
		$(BIN_DIR)/pilot_zdogace $(BIN_DIR)/pilot_zdogdrone
	@ZCL_BIN_DIR=$(BIN_DIR) CHECK=1 tools/dev/arena_view.sh

# Determinism is a property of the simulation, not of the compiler flags:
# play the pinned match with -O0 and -O2 pilots and require the same roots.
.PHONY: arena-demo-opt-parity
arena-demo-opt-parity: $(ARENA_DEMO_BINS)
	@ARENA_OPT_PARITY=1 tools/dev/arena_demo.sh

# ── README terminal figures ───────────────────────────────────────────────
# The README shows what the command surface actually prints. A hand-made
# screenshot is a pinned fact with no live source, so the figures are
# GENERATED from the built binary (ZCL_HUMAN=1 + fixed COLUMNS, ANSI -> SVG:
# no screen, no browser, no image library). `readme-svg-check` is the
# staleness gate — change the registry or the human renderer without
# regenerating and it names the stale figure.
.PHONY: readme-svg readme-svg-check
readme-svg: $(ZCLASSIC23_BIN)
	@tools/dev/readme_svg.sh
readme-svg-check: $(ZCLASSIC23_BIN)
	@READMESVG_CHECK=1 tools/dev/readme_svg.sh


# The in-tree compile cache (tools/zcc.c). Wired into $(CC) at parse time by
# tools/dev/zcc_bootstrap.sh, so these targets are for inspecting and
# maintaining it, never for enabling it. `ZCL_USE_CCACHE=0 make ...` opts out
# for one invocation; the hermetic goals (ci-reproducible, repro-verify)
# already force that and never serve a reproducibility claim from a cache.
ZCC_BIN := $(BIN_DIR)/zcc
ZCC_TRIM_MB ?= 4096
CC_AUDIT_LOG := $(BUILD_DIR)/cc-cache-audit.log

.PHONY: cc-cache cc-cache-stats cc-cache-clear cc-cache-trim cc-cache-audit
cc-cache:
	@tools/dev/zcc_bootstrap.sh >/dev/null
cc-cache-stats: cc-cache
	@$(ZCC_BIN) --zcc-stats
cc-cache-clear: cc-cache
	@$(ZCC_BIN) --zcc-clear
cc-cache-trim: cc-cache
	@$(ZCC_BIN) --zcc-trim $(ZCC_TRIM_MB)

# Prove the cache rather than assert it: every served artifact is recompiled
# for real and byte-compared against what the cache would have handed back.
# Slower than a cold build by design — this is the gate to run after touching
# tools/zcc.c, and the reason the fast path is believable rather than claimed.
cc-cache-audit: cc-cache
	@echo "cc-cache-audit: rebuilding with ZCC_AUDIT=1 (every hit is verified)"
	@ZCC_AUDIT=1 $(MAKE) --no-print-directory build-only >$(CC_AUDIT_LOG) 2>&1 || \
		{ echo "cc-cache-audit: FAIL - the audited build itself failed" >&2; \
		  tail -40 $(CC_AUDIT_LOG) >&2; exit 1; }
	@printf 'cc-cache-audit: %s verified, %s divergent\n' \
		"$$(grep -c 'AUDIT MATCH' $(CC_AUDIT_LOG) || true)" \
		"$$(grep -c 'AUDIT DIVERGENCE' $(CC_AUDIT_LOG) || true)"
	@if grep -q 'AUDIT DIVERGENCE' $(CC_AUDIT_LOG); then \
		grep 'AUDIT DIVERGENCE' $(CC_AUDIT_LOG) >&2; \
		echo "cc-cache-audit: FAIL - a cached artifact did not match a fresh build" >&2; \
		exit 1; \
	fi
	@echo "cc-cache-audit: PASS - every served artifact matched a fresh build"

# End-to-end proof of the factory plus the census package-scope intake on
# the tiny-lines fixture, entirely under test-tmp/.
.PHONY: package-factory-selftest
package-factory-selftest: $(BIN_DIR)/package-factory $(BIN_DIR)/corpus-census \
		zclassic23 zclassic23-package-sign zclassic23-package-verify
	$(BIN_DIR)/package-factory selftest --repo . --bin-dir $(BIN_DIR)

# gen_utxo_root_ladder: one-shot tool that reads a COPY of a zclassic23
# node.db (never the live datadir) and overwrites
# lib/chain/{include/chain,src}/utxo_root_ladder.{h,c} with the golden-height
# UTXO root ladder — cross-checked SHA3 UTXO-set commitments at fixed stride
# heights plus the zclassicd-verified checkpoint rung (re-stated as a local
# constant in the tool — see the comment above g_checkpoint_anchor — so this
# standalone tool avoids pulling in the full chain.h/block_index header
# graph just for chain/checkpoints.h). Standalone build: lib/chain/src/mmb.c
# (pure, no DB) for the dense layer + libsqlite3.a for the node.db reads.
# No node libs, no Tor, no RPC.
.PHONY: tools/gen_utxo_root_ladder
tools/gen_utxo_root_ladder: $(BIN_DIR)/gen_utxo_root_ladder
$(BIN_DIR)/gen_utxo_root_ladder: tools/gen_utxo_root_ladder.c \
		lib/chain/src/mmb.c lib/sha3/src/sha3.c lib/crypto/src/keccak_x4.c lib/crypto/src/simd_dispatch.c lib/base/src/cleanse.c \
		lib/base/src/log_level.c
	@mkdir -p $(dir $@)
	$(CC) -std=c23 -O2 -Wall -Wextra -Werror -pedantic \
	    $(ZCL_WARN_STRINGOP_OVERFLOW) \
	    -Ilib/chain/include -Ilib/sha3/include -Ilib/crypto/include -Ilib/support/include \
	    -Ilib/base/include -Ilib/util/include -Ivendor/include \
	    -D_POSIX_C_SOURCE=200809L \
	    -o $@ $^ -Lvendor/lib -l:libsqlite3.a -lpthread -lm

# rom_two_builder_compare: the ROM two-builder gate. Independently re-derives
# the coins/anchors/nullifiers section digests from the raw rows of two
# consensus-state bundles (bit-exact codec preimages) and asserts each bundle
# is self-consistent and the two are byte-identical in chain content. Run
# after every independent from-genesis producer fold BEFORE baking ROM
# commitments. Standalone build: vendored sqlite + lib/crypto sha3 only;
# opens both bundles read-only, never touches a datadir.
.PHONY: tools/rom_two_builder_compare
tools/rom_two_builder_compare: $(BIN_DIR)/rom_two_builder_compare
$(BIN_DIR)/rom_two_builder_compare: tools/rom_two_builder_compare.c \
		lib/sha3/src/sha3.c lib/crypto/src/keccak_x4.c lib/crypto/src/simd_dispatch.c lib/base/src/cleanse.c
	@mkdir -p $(dir $@)
	$(CC) -std=c23 -O2 -Wall -Wextra -Werror -pedantic \
	    $(ZCL_WARN_STRINGOP_OVERFLOW) \
	    -Ilib/sha3/include -Ilib/crypto/include -Ilib/support/include -Ilib/base/include \
	    -Ivendor/include \
	    -D_POSIX_C_SOURCE=200809L \
	    -o $@ $^ -Lvendor/lib -l:libsqlite3.a -lpthread -lm

# checkpoint_rung_export: the ladder RUNG generator. Reads a consensus-state
# bundle and emits the complete-state rung at its height as BOTH a binary
# artifact (parseable by the node's checkpoint_ladder verifier) and a C
# designated-initializer fragment for the sealed keystone table (owner unseal
# ritual only). Reuses the CANONICAL node rung module
# (lib/storage/src/checkpoint_rung.c) so tool + node artifacts are byte-
# identical; that TU is deliberately free of the chain/ include tree so it
# links standalone here alongside vendored sqlite + lib/crypto sha3 + log_level.
.PHONY: tools/checkpoint_rung_export
tools/checkpoint_rung_export: $(BIN_DIR)/checkpoint_rung_export
$(BIN_DIR)/checkpoint_rung_export: tools/checkpoint_rung_export.c \
		lib/storage/src/checkpoint_rung.c lib/base/src/log_level.c \
		lib/sha3/src/sha3.c lib/crypto/src/keccak_x4.c lib/crypto/src/simd_dispatch.c lib/base/src/cleanse.c
	@mkdir -p $(dir $@)
	$(CC) -std=c23 -O2 -Wall -Wextra -Werror -pedantic \
	    $(ZCL_WARN_STRINGOP_OVERFLOW) \
	    -Ilib/storage/include -Ilib/sha3/include -Ilib/crypto/include -Ilib/base/include -Ilib/util/include \
	    -Ilib/support/include -Ivendor/include \
	    -D_POSIX_C_SOURCE=200809L \
	    -o $@ $^ -Lvendor/lib -l:libsqlite3.a -lpthread -lm

# rom_bundle_sha3: standalone whole-file SHA3-256 digest tool used by
# tools/scripts/rom-bundle-replicate.sh to verify a ROM bundle replication
# copy byte-for-byte against its source. No node libs, no sqlite, no Tor —
# links only lib/sha3/src/sha3.c, the same primitive rom_seed.c and every
# other consensus-facing digest in the node uses.
.PHONY: tools/rom_bundle_sha3
tools/rom_bundle_sha3: $(BIN_DIR)/rom_bundle_sha3
$(BIN_DIR)/rom_bundle_sha3: tools/rom_bundle_sha3.c \
		lib/sha3/src/sha3.c lib/crypto/src/keccak_x4.c lib/crypto/src/simd_dispatch.c lib/base/src/cleanse.c
	@mkdir -p $(dir $@)
	$(CC) -std=c23 -O2 -Wall -Wextra -Werror -pedantic \
	    $(ZCL_WARN_STRINGOP_OVERFLOW) \
	    -Ilib/sha3/include -Ilib/crypto/include -Ilib/support/include -Ilib/base/include \
	    -D_POSIX_C_SOURCE=200809L \
	    -o $@ $^ -lm

# rom-bundle-replicate: copy a verified consensus-state bundle + its replay
# receipt + a producing-binary hash record to a second directory, verified
# byte-identical by SHA3 (tools/scripts/rom-bundle-replicate.sh). Point a
# node's -rombundlereplicadir at DEST to serve it (config/rom_bundle_admission.h).
#   make rom-bundle-replicate BUNDLE=path/to/consensus-state-bundle-H.sqlite \
#       RECEIPT=path/to/consensus_state_replay_receipt.v1 DEST=/some/second/dir
.PHONY: rom-bundle-replicate
rom-bundle-replicate: $(BIN_DIR)/rom_bundle_sha3
	@if [ -z "$(BUNDLE)" ] || [ -z "$(RECEIPT)" ] || [ -z "$(DEST)" ]; then \
	    echo "usage: make rom-bundle-replicate BUNDLE=... RECEIPT=... DEST=... [BINARY=...]"; \
	    exit 2; fi
	tools/scripts/rom-bundle-replicate.sh --bundle="$(BUNDLE)" \
	    --receipt="$(RECEIPT)" --dest="$(DEST)" \
	    $(if $(BINARY),--binary="$(BINARY)",)

# bundle-bootstrap: BYTE DELIVERY ONLY — stage a release-shipped
# consensus-state bundle into <datadir>/bundles/ so a fresh node's zero-flag
# cold-boot autodetect (boot_autodetect_consensus_bundle,
# config/src/boot_auto_install_bundle.c) finds it with no further operator
# action at boot time (deploy/zclassic23-bundle-bootstrap.sh; see
# docs/ROM_DELIVERY.md "Local bundle bootstrap"). Idempotent: a no-op if
# <datadir>/bundles/ already holds a *.sqlite or the datadir already has an
# installed-bundle marker. Never a trust decision — that stays entirely at
# INSTALL time (RECEIPT/CHECKPOINT_ROM/CHECKPOINT_CONTENT authority).
#   make bundle-bootstrap SOURCE=path/to/consensus-state-bundle-H.sqlite \
#       [DATADIR=/path/to/datadir]
.PHONY: bundle-bootstrap
bundle-bootstrap: $(BIN_DIR)/rom_bundle_sha3
	@if [ -z "$(SOURCE)" ]; then \
	    echo "usage: make bundle-bootstrap SOURCE=... [DATADIR=...]"; \
	    exit 2; fi
	deploy/zclassic23-bundle-bootstrap.sh --source="$(SOURCE)" \
	    --sha3-tool="$(BIN_DIR)/rom_bundle_sha3" \
	    $(if $(DATADIR),--datadir="$(DATADIR)",)

# gen_utxo_snapshot: build-time tool that walks a legacy zclassicd
# chainstate LevelDB and emits a canonical UTXO sidecar file ready
# for runtime mmap+SHA3-verify+bulk-INSERT (Stage J of fast-sync
# plan). Implemented as a `--gen-utxo-snapshot` mode of zclassic23
# itself (avoids duplicating the dep tree); invoke via:
#   zclassic23 --gen-utxo-snapshot <legacy_datadir> <out_path>

.PHONY: zcl-nodectl
zcl-nodectl: $(ZCL_NODECTL_BIN)
$(ZCL_NODECTL_BIN): tools/zcl-nodectl.c lib/util/include/util/rpc_paths.h \
		lib/platform/src/clock.c lib/base/src/log_level.c
	@mkdir -p $(dir $@)
	$(CC) -std=c23 -O2 -Wall -Wextra -Werror \
	    -Ilib/base/include -Ilib/util/include -Ilib/platform/include \
	    -D_POSIX_C_SOURCE=200809L -o $@ \
	    tools/zcl-nodectl.c lib/platform/src/clock.c lib/base/src/log_level.c

.PHONY: export_snapshot
export_snapshot: $(BIN_DIR)/export_snapshot
$(BIN_DIR)/export_snapshot: tools/export_snapshot.c \
		lib/platform/src/clock.c lib/base/src/log_level.c
	@mkdir -p $(dir $@)
	$(CC) -std=c23 -O2 -Wall -Wextra -Werror -Ivendor/include \
	    -Ilib/platform/include -Ilib/base/include -Ilib/util/include \
	    -D_POSIX_C_SOURCE=200809L \
	    -o $@ $^ -Lvendor/lib -l:libsqlite3.a -lpthread -lm

# verify_anchor_completeness: cross-checks a zclassicd chainstate LevelDB copy
# against a zclassic23 progress.kv — did the shielded-history importer
# (shielded_history_import_service.c) capture every anchor/nullifier its
# source chainstate held? Reads the raw LevelDB keyspace directly (leveldb/c.h),
# independent of chainstate_legacy_reader.c, as an orthogonal ground truth.
.PHONY: verify_anchor_completeness
verify_anchor_completeness: $(BIN_DIR)/verify_anchor_completeness
$(BIN_DIR)/verify_anchor_completeness: tools/verify_anchor_completeness.c
	@mkdir -p $(dir $@)
	$(CC) -std=c23 -O2 -Wall -Wextra -Werror -Ivendor/include -o $@ $< -Lvendor/lib -l:libleveldb.a -l:libsqlite3.a -lstdc++ -lpthread -lm -ldl

# ldb_verify_c23: differential proof that the C23 read-only LevelDB reader
# (lib/storage/src/ldb_reader_*.c) returns byte-identical data to the
# vendored C++ libleveldb.a. Links BOTH implementations and walks the whole
# ordered keyspace of two COPIES of the same directory — the C++ open
# mutates its target, so each side needs its own. This is the only rule in
# the tree that deliberately links libleveldb.a as a cross-check oracle.
#   build/bin/ldb_verify_c23 <dir-for-cxx> <dir-for-c23> [max-records]
.PHONY: ldb_verify_c23
ldb_verify_c23: $(BIN_DIR)/ldb_verify_c23
$(BIN_DIR)/ldb_verify_c23: tools/ldb_verify_c23.c \
		lib/storage/src/ldb_reader_format.c \
		lib/storage/src/ldb_reader_table.c \
		lib/storage/src/ldb_reader_version.c \
		lib/storage/src/ldb_reader_db.c \
		lib/storage/src/ldb_reader_api.c \
		lib/util/src/crc32c.c lib/base/src/safe_alloc.c
	@mkdir -p $(dir $@)
	$(CC) -std=c23 -O2 -Wall -Wextra -Werror -pedantic \
	    -D_POSIX_C_SOURCE=200809L \
	    -Ivendor/include -Ilib/base/include -Ilib/util/include \
	    -Ilib/storage/include \
	    -o $@ $^ -Lvendor/lib -l:libleveldb.a -lstdc++ -lpthread -lm -ldl

.PHONY: zcl-blog
zcl-blog: $(BIN_DIR)/zcl-blog
$(BIN_DIR)/zcl-blog: tools/zcl-blog
	@mkdir -p $(dir $@)
	$(CC) -std=c23 -O2 -x c $$(pkg-config --cflags webkit2gtk-4.1) -o $@ $< $$(pkg-config --libs webkit2gtk-4.1)

# Default `make test` = the fast fork-based parallel suite (~1min, 282 groups).
# The slow single-process binary is still available as `make test-full`.
# Doctrine: never run test_zcl in the inner loop — use `make t ONLY=<group>`.
# Checkout-locked around prerequisite construction and execution — see the
# `t` target above for the depfile-integrity failure this boundary prevents.
test:
	@mkdir -p "$(BUILD_DIR)"
	@$(CHECKOUT_LOCK_TOOL) foreground "$(CHECKOUT_LOCK)" -- \
	  $(MAKE) --no-print-directory test-locked \
	    TEST_PARALLEL_ARGS='$(TEST_PARALLEL_ARGS)'

.PHONY: test-locked
test-locked: $(TEST_PARALLEL_REL_CANDIDATE) dev-package-verifier-ensure
	ulimit -s unlimited && $(TEST_PARALLEL_REL_ACTIVE) $(TEST_PARALLEL_ARGS)

test-full: test_zcl
	ulimit -s unlimited && $(TEST_ZCL_BIN)

# zclassic23-chaos links the FULL node source tree ($(ALL_SRCS), same
# whole-program LTO shape as wire_sweep/test_parallel below) rather than a
# hand-picked file list. `mode simnet` scenarios drive lib/sim/simnet_cluster
# (real connect_block/disconnect_block/fork-choice), so the binary needs the
# real consensus/coins/script/validation stack, not just sim_peer's counters.
$(eval $(call BUILD_NODE_TOOL,zclassic23-chaos,tools/sim/chaos.c $(CHAOS_SIM_SRCS)))

chaos: zclassic23-chaos
	@set -eu; \
	for s in tools/sim/scenarios/*.scenario; do \
	    echo "==> $$s"; \
	    $(ZCLASSIC23_CHAOS_BIN) --scenario="$$s"; \
	done; \
	echo "==> All chaos scenarios PASSED"

.PHONY: sim-fast
sim-fast: $(TEST_PARALLEL_REL_CANDIDATE) zclassic23-chaos
	@set -eu; \
	echo "==> chaos harness unit slice"; \
	ulimit -s unlimited && $(TEST_PARALLEL_REL_ACTIVE) --only=chaos_harness; \
	echo "==> checked-in chaos scenarios"; \
	$(MAKE) --no-print-directory chaos; \
	echo "==> bounded chaos seed sweep ($(CHAOS_SEEDS) seeds via $(CHAOS_SWEEP_SCENARIO))"; \
	i=1; \
	while [ "$$i" -le "$(CHAOS_SEEDS)" ]; do \
	    seed=$$(printf '0x%016x' "$$i"); \
	    out="$$( $(ZCLASSIC23_CHAOS_BIN) --scenario="$(CHAOS_SWEEP_SCENARIO)" --seed="$$seed" 2>&1 )" || { \
	        printf '%s\n' "$$out"; \
	        exit 1; \
	    }; \
	    i=$$((i + 1)); \
	done; \
	echo "==> sim-fast PASSED ($(CHAOS_SEEDS) seeded replays)"

chaos-clean:
	rm -f $(ZCLASSIC23_CHAOS_BIN)
	rm -rf build/chaos-output/ chaos-output/

# ── simnet_trace_query: linear-scan filter over a simnet state trace ─────
# (lib/sim/include/sim/simnet_trace.h; docs/CHAOS_HARNESS.md "Recording a
# full-state trace"). Standalone build: only lib/json (the trace's own
# format) plus the safe_alloc/log_level it transitively needs — no DB, no
# node libs, no Tor, no simulator/consensus code, same discipline as
# tools/postmortem_to_scenario.c.
.PHONY: tools/sim/simnet_trace_query
tools/sim/simnet_trace_query: $(BIN_DIR)/simnet_trace_query
$(BIN_DIR)/simnet_trace_query: tools/sim/simnet_trace_query.c \
		lib/json/src/json.c \
		lib/base/src/safe_alloc.c lib/base/src/log_level.c
	@mkdir -p $(dir $@)
	$(CC) -std=c23 -O2 -Wall -Wextra -Werror -pedantic \
	    -Ilib/json/include -Ilib/base/include -Ilib/util/include \
	    -D_POSIX_C_SOURCE=200809L \
	    -o $@ $^ -lpthread -lm

# ── wire_sweep: nightly seed-fuzzing runner for the simnet_wire harness ───
# (Step F, docs/work/wire-next-wave-specs.md §3). Standalone binary, same
# BUILD_NODE_TOOL shape as every other tools/*.c entry point — NOT part of
# the test_zcl/test_parallel/zclassic23 link units, so a nightly sweep of
# thousands of seeds never gates the normal build or `make ci`/`make test`.
$(eval $(call BUILD_NODE_TOOL,wire_sweep,tools/sim/wire_sweep.c))

WIRE_SWEEP_START ?= 1
WIRE_SWEEP_SEEDS ?= 2000
WIRE_SWEEP_ARTIFACT_DIR ?= build/wire-sweep-output
# `SEEDS=N` is the documented short-hand (`make wire-sweep SEEDS=200`);
# WIRE_SWEEP_SEEDS is the nightly default when SEEDS is not given.
WIRE_SWEEP_COUNT = $(if $(SEEDS),$(SEEDS),$(WIRE_SWEEP_SEEDS))

.PHONY: wire-sweep wire-sweep-clean
wire-sweep: wire_sweep
	@mkdir -p $(WIRE_SWEEP_ARTIFACT_DIR)
	$(BIN_DIR)/wire_sweep --start=$(WIRE_SWEEP_START) \
	    --count=$(WIRE_SWEEP_COUNT) \
	    --artifact-dir=$(WIRE_SWEEP_ARTIFACT_DIR)

wire-sweep-clean:
	rm -f $(BIN_DIR)/wire_sweep
	rm -rf build/wire-sweep-output/

# ── simperf: algorithmic-cost detector for the block-connect/UTXO path ────
# Runs one deterministic simnet workload (mint N blocks of M transparent
# spends, folded by the REAL connect_block) at 1x/2x/4x size and gates on how
# much per-transaction CPU cost GROWS across that span — a dimensionless
# ratio, so the same threshold holds on a fast, slow, or loaded box. It is a
# CI-cheap PROXY for complexity regressions ONLY: no disk, no network, no real
# PoW, so it neither is nor replaces the wall-clock coldstart-to-tip stopwatch.
# Full contract: docs/SIMNET_PERF.md. Same standalone BUILD_NODE_TOOL shape as
# wire_sweep above.
$(eval $(call BUILD_NODE_TOOL,simperf,tools/sim/simperf.c))

SIMPERF_ARGS ?=

.PHONY: sim-perf sim-perf-teeth sim-perf-clean
sim-perf: simperf
	$(BIN_DIR)/simperf $(SIMPERF_ARGS)

# The parent-failing prover for the detector itself: the SAME workload with a
# real, correctness-preserving O(1)->O(n) regression armed in the UTXO map
# (coins/coins_fault.h) must FAIL the budget that the clean run passes. A perf
# gate never shown to fail is not a gate. `make t ONLY=simnet_perf` runs the
# same both-directions proof in-process on every suite run.
sim-perf-teeth: simperf
	@echo "══ sim-perf-teeth: clean run must PASS ══"
	@$(BIN_DIR)/simperf $(SIMPERF_ARGS)
	@echo "══ sim-perf-teeth: regression-armed run must FAIL ══"
	@if $(BIN_DIR)/simperf --inject=coins-hash-collapse $(SIMPERF_ARGS); then \
	    echo "sim-perf-teeth: FAILED — the injected O(n^2) UTXO regression did"; \
	    echo "  NOT trip the budget. The detector has no teeth; do not trust a"; \
	    echo "  passing sim-perf run until this is fixed."; \
	    exit 1; \
	else \
	    echo "sim-perf-teeth: PASSED — budget passes clean, fails armed"; \
	fi

sim-perf-clean:
	rm -f $(BIN_DIR)/simperf

# ── simnet-repro / simnet-replay: one-command seed/capsule reproduction ──
# Both targets reuse wire_sweep as-is (its own --start/--count seed
# selection, its own capsule-writing convention) — no new harness, no new
# binary. `wire_sweep_run_one(seed)` (tools/sim/wire_sweep.c) is a pure
# function of the scalar seed, so a single seed fully determines the
# archetype/sub-case/event stream ("bugs become 64-bit seeds",
# docs/work/sim-phase2-plan.md); replaying a capsule only needs the seed
# it was saved under, which is already encoded in the capsule's filename
# (see tools/scripts/simnet_replay_capsule.sh).
SIMNET_REPRO_ARTIFACT_DIR ?= build/simnet-repro-output

.PHONY: simnet-repro
simnet-repro: wire_sweep
	@if [ -z "$(SEED)" ]; then \
	    echo "usage: make simnet-repro SEED=0x<hex>  (e.g. SEED=0x2a)"; \
	    exit 2; \
	fi
	@mkdir -p $(SIMNET_REPRO_ARTIFACT_DIR)
	$(BIN_DIR)/wire_sweep --start=$(SEED) --count=1 --verbose \
	    --artifact-dir=$(SIMNET_REPRO_ARTIFACT_DIR)

.PHONY: simnet-replay
simnet-replay: wire_sweep
	@if [ -z "$(CAP)" ]; then \
	    echo "usage: make simnet-replay CAP=<capsule-dir-or-.tape-file>"; \
	    exit 2; \
	fi
	@bash tools/scripts/simnet_replay_capsule.sh "$(CAP)" \
	    $(BIN_DIR)/wire_sweep $(SIMNET_REPRO_ARTIFACT_DIR)

# ── simnet-nightly / simnet-fuzz-sweep: Wave-2 lane B2 (nightly automation) ──
# No new harness, no new binary — this composes the EXISTING chaos/wire-sweep/
# sim-fast machinery so the checked-in .scenario corpus (tools/sim/scenarios/,
# currently 13 files) plus a bounded simnet_wire seed sweep stop being caught
# "only by developer discipline" (`make ci` does not run `make chaos` today —
# see the ci-gate decision recorded beside the `ci:` target below). Both
# targets are fixed/seeded and MUST terminate; wire_sweep_run_one(seed) is a
# pure function of the scalar seed (docs/work/sim-phase2-plan.md), so every
# run here is exactly reproducible via `make simnet-repro SEED=0x<hex>`.
#
# simnet-nightly: the bounded default the nightly timer runs every night —
# whole scenario corpus (make chaos) + the wire_sweep nightly-default seed
# count (make wire-sweep, WIRE_SWEEP_SEEDS=2000) + the sim-fast unit-test +
# 64-seed churn slice. sim-fast re-runs `make chaos` internally too — that's
# deliberate, harmless duplication (both runs are deterministic and each is
# sub-2s once built): it means a scenario-corpus regression is reported at
# the very first step, with the clearest per-scenario PASS/FAIL line, before
# the slower composite steps even start.
#
# Byzantine cluster sweep (step 4): lane B1's `simnet_nodes N honest=P` DSL
# verb has landed (tools/sim/chaos.c handle_simnet_nodes /
# simnet_cluster_byzantine_mint_on) and the detective scenario corpus
# (tools/sim/scenarios/detective_*.scenario) already exercises it. `make
# chaos` in step 1 already runs every *.scenario file including these three
# via its glob, so this step is deliberately-duplicate — same doctrine as
# sim-fast re-running `make chaos` internally (see the comment block above):
# a byzantine-cluster regression gets its OWN named PASS/FAIL line instead of
# being buried inside the generic "full corpus" step, and the perf/mixed
# smoke (ZCL_SIMNET_PERF=1) is opt-in-cheap (sub-second, N=100 nodes) and
# otherwise SKIPped by test_parallel itself — see fz_perf_smoke /
# fz_byz_perf_smoke in lib/test/src/test_simnet_fuzz.c.
DETECTIVE_SCENARIOS = \
    tools/sim/scenarios/detective_100_80.scenario \
    tools/sim/scenarios/detective_66_honest_partition.scenario \
    tools/sim/scenarios/detective_51_honest_edge.scenario

# ZCL_UTXO_LADDER_HEAVY dense-MMB recompute (step 5): re-folds mmb_root()
# from a REAL mmb_leaves.bin copy (millions of leaves) to prove the compiled
# dense anchor (g_utxo_root_ladder_dense_mmb_root) still reproduces
# bit-for-bit — see test_utxo_root_ladder.c's HEAVY section. The fixture is
# ~100 MB and only exists on a box that has actually synced/self-folded to
# the dense anchor height, so this step SKIPs (not FAILs) when it is absent
# — a fresh checkout or a CI runner has no such fixture and that is not a
# regression signal.
UTXO_LADDER_LEAF_STORE ?= $(HOME)/.zclassic-c23/mmb_leaves.bin

.PHONY: simnet-nightly
simnet-nightly: $(TEST_PARALLEL_REL_CANDIDATE)
	@echo "══ simnet-nightly: step 1/6 — full .scenario corpus (make chaos) ══"
	@if $(MAKE) --no-print-directory chaos; then \
	    step1=PASS; \
	else \
	    step1=FAIL; \
	fi; \
	echo "══ simnet-nightly: step 2/6 — bounded wire_sweep seed range (make wire-sweep) ══"; \
	if $(MAKE) --no-print-directory wire-sweep; then \
	    step2=PASS; \
	else \
	    step2=FAIL; \
	fi; \
	echo "══ simnet-nightly: step 3/6 — sim-fast (chaos_harness unit slice + churn sweep) ══"; \
	if $(MAKE) --no-print-directory sim-fast; then \
	    step3=PASS; \
	else \
	    step3=FAIL; \
	fi; \
	echo "══ simnet-nightly: step 4/6 — byzantine detective cluster sweep ══"; \
	if $(MAKE) --no-print-directory zclassic23-chaos >/dev/null; then \
	    step4=PASS; \
	    for s in $(DETECTIVE_SCENARIOS); do \
	        echo "  ==> $$s"; \
	        if ! $(ZCLASSIC23_CHAOS_BIN) --scenario="$$s"; then step4=FAIL; fi; \
	    done; \
	    echo "  ==> ZCL_SIMNET_PERF=1 mixed smoke (simnet_fuzz + simnet_byzantine_cluster)"; \
	    if ! ZCL_SIMNET_PERF=1 $(TEST_PARALLEL_REL_ACTIVE) --only=simnet_fuzz; then step4=FAIL; fi; \
	    if ! ZCL_SIMNET_PERF=1 $(TEST_PARALLEL_REL_ACTIVE) --only=simnet_byzantine_cluster; then step4=FAIL; fi; \
	else \
	    step4=FAIL; \
	fi; \
	echo "══ simnet-nightly: step 5/6 — ZCL_UTXO_LADDER_HEAVY dense-MMB recompute ══"; \
	if [ -f "$(UTXO_LADDER_LEAF_STORE)" ]; then \
	    if ZCL_UTXO_LADDER_HEAVY=1 ZCL_UTXO_LADDER_LEAF_STORE="$(UTXO_LADDER_LEAF_STORE)" \
	        $(TEST_PARALLEL_REL_ACTIVE) --only=utxo_root_ladder; then \
	        step5=PASS; \
	    else \
	        step5=FAIL; \
	    fi; \
	else \
	    step5="SKIP (no fixture at $(UTXO_LADDER_LEAF_STORE))"; \
	fi; \
	echo "══ simnet-nightly: step 6/6 — golden-table tip-coverage-lag check ══"; \
	if bash tools/scripts/check_golden_freshness.sh; then \
	    step6=PASS; \
	else \
	    step6=FAIL; \
	fi; \
	echo ""; \
	echo "══ simnet-nightly SUMMARY ══"; \
	echo "  1. chaos (full corpus) ................. $$step1"; \
	echo "  2. wire-sweep ($(WIRE_SWEEP_SEEDS) seeds) .......... $$step2"; \
	echo "  3. sim-fast ............................. $$step3"; \
	echo "  4. byzantine detective cluster sweep .... $$step4"; \
	echo "  5. utxo-ladder dense-MMB heavy recompute . $$step5"; \
	echo "  6. golden-table tip-coverage-lag check ... $$step6"; \
	if [ "$$step1" = PASS ] && [ "$$step2" = PASS ] && [ "$$step3" = PASS ] && \
	   [ "$$step4" = PASS ] && [ "$$step5" != FAIL ] && [ "$$step6" = PASS ]; then \
	    echo "==> simnet-nightly PASSED"; \
	else \
	    echo "==> simnet-nightly FAILED"; \
	    exit 1; \
	fi

# simnet-fuzz-sweep: the LONGER seed sweep for the nightly timer (bigger
# --count than the default `make wire-sweep`, same wire_sweep binary/CLI —
# no new harness). Kept as its own target/artifact-dir so it composes
# independently of simnet-nightly's bounded default (a slow night can run
# both back-to-back via the driver script without artifact collisions).
WIRE_SWEEP_NIGHTLY_SEEDS ?= 20000
WIRE_SWEEP_NIGHTLY_ARTIFACT_DIR ?= build/wire-sweep-nightly-output

.PHONY: simnet-fuzz-sweep
simnet-fuzz-sweep: wire_sweep
	@mkdir -p $(WIRE_SWEEP_NIGHTLY_ARTIFACT_DIR)
	@echo "══ simnet-fuzz-sweep: $(WIRE_SWEEP_NIGHTLY_SEEDS) wire_sweep seeds ══"
	$(BIN_DIR)/wire_sweep --start=$(WIRE_SWEEP_START) \
	    --count=$(WIRE_SWEEP_NIGHTLY_SEEDS) \
	    --artifact-dir=$(WIRE_SWEEP_NIGHTLY_ARTIFACT_DIR)
	@echo "==> simnet-fuzz-sweep PASSED ($(WIRE_SWEEP_NIGHTLY_SEEDS) seeds)"

# Gate: the simnet_wire harness must be pure in-memory — no real sockets.
# See tools/scripts/check_wire_harness_security_gate.sh.
.PHONY: check-wire-harness-security-gate
check-wire-harness-security-gate:
	@echo "══ LINT: simnet_wire harness has zero real-network calls ══"
	@bash tools/scripts/check_wire_harness_security_gate.sh

# Offline P2 self-heal invariant checker: coins_applied_height == utxo_apply
# cursor, read read-only from a progress.kv (works while the node is down —
# the kill-9 window). Self-contained against the vendored sqlite3 header.
.PHONY: p2_invariant_check
p2_invariant_check: $(P2_INVARIANT_CHECK_BIN)
$(P2_INVARIANT_CHECK_BIN): tools/p2_invariant_check.c vendor/include/sqlite3.h vendor/lib/libsqlite3.a
	@mkdir -p $(dir $@)
	$(CC) -std=c23 -O2 -Wall -Wextra -Werror -pedantic \
	    -D_POSIX_C_SOURCE=200809L -Ivendor/include \
	    -o $@ tools/p2_invariant_check.c \
	    -Lvendor/lib -l:libsqlite3.a -lpthread -ldl -lm

# Read-only SQL query CLI over any sqlite db (progress.kv, node.db, fixture
# datadirs). Python is banned and the host has no sqlite3 CLI; this is the
# shell-side diagnostic primitive (the native `sql` command covers node.db).
SQLQ_BIN = $(BIN_DIR)/sqlq
.PHONY: sqlq
sqlq: $(SQLQ_BIN)
$(SQLQ_BIN): tools/sqlq.c vendor/include/sqlite3.h vendor/lib/libsqlite3.a
	@mkdir -p $(dir $@)
	$(CC) -std=c23 -O2 -Wall -Wextra -Werror -pedantic \
	    -D_POSIX_C_SOURCE=200809L -Ivendor/include \
	    -o $@ tools/sqlq.c \
	    -Lvendor/lib -l:libsqlite3.a -lpthread -ldl -lm

# Nested JSON path query for operator scripts. Python is banned; grep/sed
# covers flat RPC fields, and this C23 walker covers nested envelopes.
JSONQ_BIN = $(BIN_DIR)/jsonq
.PHONY: jsonq
jsonq: $(JSONQ_BIN)
$(JSONQ_BIN): tools/jsonq.c \
    packages/zjsonp/src/zjsonp.c packages/zutf8/src/zutf8.c \
    packages/zjsonp/include/zjsonp/zjsonp.h \
    packages/zutf8/include/zutf8/zutf8.h
	@mkdir -p $(dir $@)
	$(CC) -std=c23 -O2 -Wall -Wextra -Werror -pedantic \
	    -D_POSIX_C_SOURCE=200809L \
	    -Ipackages/zjsonp/include -Ipackages/zutf8/include \
	    -o $@ tools/jsonq.c packages/zjsonp/src/zjsonp.c \
	    packages/zutf8/src/zutf8.c

# Physical native-agent UI acceptance driver. It links only the workstation's
# X11 client ABI and sends one bounded event to an exact titled window; it owns
# no node/package authority and is never shipped. Link the stable runtime
# SONAME directly so a physical runner needs the X11 runtime, not a distro's
# optional development-package linker alias.
NATIVE_UI_DRIVER_BIN = $(BIN_DIR)/native_ui_driver
.PHONY: native-ui-driver
native-ui-driver: $(NATIVE_UI_DRIVER_BIN)
$(NATIVE_UI_DRIVER_BIN): tools/native_ui_driver.c
	@mkdir -p $(dir $@)
	$(CC) -std=c23 -O2 -Wall -Wextra -Werror -pedantic \
	    -D_POSIX_C_SOURCE=200809L -Ivendor/x11/include \
	    -o $@ $< -Wl,-l:libX11.so.6

# Crash recovery harness: fork zclassic23, SIGKILL at random points,
# restart, and assert data-integrity invariants. Needs a pre-seeded
# datadir (skips trivially if none exists — see tool header). Build
# depends on the node binary and the CLI RPC helper.
.PHONY: crash_recovery_test
crash_recovery_test: $(CRASH_RECOVERY_TEST_BIN)
$(CRASH_RECOVERY_TEST_BIN): tools/crash_recovery_test.c lib/platform/src/clock.c
	@mkdir -p $(dir $@)
	$(CC) -std=c23 -O2 -Wall -Wextra -Werror -pthread \
	    -Ilib/platform/include -Ilib/base/include -Ilib/util/include -Ivendor/include -o $@ \
	    tools/crash_recovery_test.c lib/platform/src/clock.c \
	    -Lvendor/lib -l:libsqlite3.a -lpthread -ldl -lm

.PHONY: test-crash
# CI entry point for the crash recovery harness.
#
# The harness skips (exit 0) when its datadir does NOT exist, and keeps
# CI green on clean hosts. Don't pre-create the dir — an empty dir
# makes the harness try to start the node on a blank chainstate, which
# then reports "RPC never came up" as a harness error (false negative).
#
# When a fully seeded datadir is available (a CI worker with a pinned
# snapshot), point ZCL_CRASH_DATADIR at it and this target runs the
# full 10-iteration kill/restart cycle against real data. Otherwise
# the target runs through to the SKIP path.
test-crash: crash_recovery_test zclassic23 zcl-rpc
	@set -eu; \
	 dd="$${ZCL_CRASH_DATADIR:-/tmp/zcl-crashtest-ci.absent}"; \
	 if [ -n "$${ZCL_CRASH_DATADIR:-}" ] && [ ! -d "$$dd" ]; then \
	     echo "test-crash: ZCL_CRASH_DATADIR=$$dd does not exist — harness will SKIP"; \
	 fi; \
	 ZCL_CRASH_DATADIR="$$dd" $(CRASH_RECOVERY_TEST_BIN) --iterations=10

# ── Opt-in, node-spawning harnesses (NOT in `make ci`) ─────────────
#
# test-crash-bootstrap and soak-ci both SPAWN a real (isolated regtest)
# node. They are DELIBERATELY excluded from the default `ci:` recipe to
# keep CI hermetic and fast — `make ci` must never start a node. Run
# them explicitly (operator/agent) on a clean host, or in a dedicated
# slow-CI stage. Both source tools/scripts/isolated_node_env.sh, which
# is the single audited chokepoint enforcing /tmp datadir + 39xxx ports
# + refuse-on-live preflight + process-group kill + cleanup trap.
#
# C7 full-binary kill-9: the bootstrap path self-seeds a fresh isolated
# /tmp regtest datadir (mine N blocks), then runs kill/restart cycles
# asserting height-monotone + zero-UTXO-above-tip recovery. The `iso_*`
# helpers mint the datadir/ports and own the cleanup trap; the C harness
# does its own spawn/kill loop against them.
.PHONY: test-crash-bootstrap
# The recipe runs under bash (NOT the default /bin/sh=dash) because
# isolated_node_env.sh relies on `set -o pipefail`. The whole body is one
# bash invocation so the sourced trap stays armed for the harness run.
test-crash-bootstrap: crash_recovery_test zclassic23 zcl-rpc
	@bash -c 'set -euo pipefail; \
	 export ISO_KIND=crash ISO_PORT_BASE=39030; \
	 . tools/scripts/isolated_node_env.sh; \
	 iso_init; \
	 echo "test-crash-bootstrap: kill-9 cycles on $$ISO_DD (rpc=$$ISO_RPCPORT)"; \
	 $(CRASH_RECOVERY_TEST_BIN) \
	     --bootstrap-regtest \
	     --datadir="$$ISO_DD" \
	     --rpc-port="$$ISO_RPCPORT" \
	     --p2p-port="$$ISO_PORT" \
	     --fs-port="$$ISO_FSPORT" \
	     --https-port="$$ISO_HTTPSPORT" \
	     --connect=127.0.0.1:"$$ISO_CONNECT_SINK" \
	     --seed-blocks=30 \
	     --iterations=2 --min-delay-ms=200 --max-delay-ms=800 \
	     --verbose; \
	 echo "test-crash-bootstrap: PASS (recovery invariants held under SIGKILL)"'

# Item-3 reindex epilogue acceptance (a): seed an isolated /tmp regtest node,
# clean-restart with -reindex-chainstate, and assert the FOUR teeth (tip parity,
# gettxoutsetinfo.txouts parity, getutxocommitment parity, SERVING + no coin
# tear in node.log). A torn/no-op epilogue changes txouts/commitment and fails.
# Opt-in (NOT in hermetic `make ci`): it SPAWNS a real regtest node. All
# isolation is delegated to tools/scripts/isolated_node_env.sh.
.PHONY: test-reindex-smoke
test-reindex-smoke: zclassic23 zcl-rpc
	@ISO_KIND=reindex ISO_PORT_BASE=$${ISO_PORT_BASE:-39050} \
	    SEED_BLOCKS=50 KILL_MID=0 \
	    bash tools/scripts/reindex_smoke.sh

# Item-3 reindex epilogue acceptance (c): kill -9 mid-reindex then reboot
# converges. Spawn with -reindex-chainstate, SIGKILL after a randomized
# 200-2000ms during replay, reboot normally (crash-only re-replay), and assert
# eventual SERVING at tip with the same four teeth within <=3 reboot cycles.
# Proves the epilogue is crash-only safe (runs only after errors==0, clears the
# sentinel only after the H* self-check). Opt-in (NOT in hermetic `make ci`).
.PHONY: test-reindex-killmid
test-reindex-killmid: zclassic23 zcl-rpc
	@ISO_KIND=reindex ISO_PORT_BASE=$${ISO_PORT_BASE:-39054} \
	    SEED_BLOCKS=50 KILL_MID=1 \
	    bash tools/scripts/reindex_smoke.sh

# C7 PEER-tip kill-9 (the FULL #7 claim): two isolated regtest nodes on
# disjoint 39xxx quads, B connect-only to A. A mines; assert B syncs to A
# over NATIVE P2P, then kill-9 B mid-life, mine more on A, restart B, and
# assert B re-catches up to A's PEER-tip. This is the complement to
# test-crash-bootstrap (which only proves SINGLE-node boot recovery).
# DELIBERATELY opt-in (NOT in `make ci`) — it spawns two real nodes. The
# harness owns its own /tmp datadirs + 39xxx port refuse/LISTEN preflight
# + process-group SIGKILL + EXIT/INT/TERM cleanup trap (same discipline
# as tools/scripts/isolated_node_env.sh, generalized to two nodes).
.PHONY: test-two-node-peer-tip
# Runs under bash for `set -o pipefail` parity with the other spawn
# harnesses; the script itself sets -euo pipefail.
test-two-node-peer-tip: zclassic23 zcl-rpc
	@bash tools/scripts/two_node_peer_tip.sh

# ZCODE science-slice v1 acceptance proof: two disjoint isolated regtest
# nodes (39xxx quads, loopback only, B connect-only to A). Preregister a
# study, run a confined c23.benchmark.v1 execute, reproduce it via the v1
# mirror, publish findings/review/vote, rank locally, restart both nodes,
# and rebuild the science projection byte-identically from CAS hashes
# (including after a direct SQL wipe of the six projection tables).
# Proves the generic S7 path: the publisher files a signed one-day POINTER
# plus a two-hour PROVIDER over the existing authenticated DHT, and the fresh
# node starts with only the semantic science root.  It resolves, fetches via
# the existing package verifier, re-derives the science root, admits, restarts,
# and rebuilds the six projection tables byte-identically from CAS hashes.
# DELIBERATELY opt-in (NOT in `make ci`) — it spawns two real nodes and
# depends on the host Landlock/seccomp sandbox for the confined executor.
.PHONY: test-zcode-dht-acceptance test-science-acceptance \
	c23-commons-installed-acceptance \
	sovereign-source-network-acceptance \
	test-market-acceptance test-market-onion-acceptance \
	test-market-moderation-acceptance \
	zcode-reproduction-acceptance
test-zcode-dht-acceptance: zclassic23 zcl-rpc tools/arena-product-journey-c23
	@bash tools/dev/zcode_dht_acceptance.sh

test-science-acceptance: test-zcode-dht-acceptance
	@bash tools/dev/science_acceptance.sh

# Aggregate C23 Commons Beta.  The Alpha proof is an explicit prerequisite,
# so the installed stranger journey can never green while its generic graph,
# transport, or adversarial regression floor is red.  The installed phase
# then puts the ordinary node plus package signer/verifier in a throwaway
# prefix and composes the canonical DHT/Noise physical-node owner with an
# outside-tree package graph.  Opt-in: seven real daemons; no production
# datadir, wallet key, or live port.
c23-commons-installed-acceptance: zcode-c23-commons-alpha
	@bash tools/dev/c23_commons_beta_acceptance.sh
	@printf '%s\n' '{"schema":"zcl.c23_commons_beta_acceptance.v1","verdict":"PASS","alpha_regression_floor":true,"installed_stranger_journey":true,"corrupt_provider_bytes_rejected":true,"alternate_provider_exact_root_repair":true,"interrupted_download_resumes_same_graph":true,"verified_objects_retransmitted_after_restart":0}'

# Four-role, real-process sovereign source acceptance. It composes the proven
# seven-identity DHT/Noise harness rather than inventing test-only networking;
# the source hook assigns publisher, two independent hosts and a no-Git fresh
# consumer after sparse authentication. Opt-in: real daemons and full builds.
sovereign-source-network-acceptance: zclassic23 zcl-rpc zclassic23-package-sign
	@bash tools/dev/sovereign_source_network_acceptance.sh

# B3 file-market trade acceptance: two isolated regtest daemons (395xx
# quads + 20030/20031, loopback only). The seller (-externalip + file
# service) plans then commits a signed paid offer; it gossips to the buyer,
# which plans/commits a real Sapling payment, is refused delivery before
# confirmation (authorize-before-read), then retrieves the file after one
# mined block into an atomically published, byte-identical destination.
# Closes with idempotent offer/plan/commit replays and the seller-side
# CONFIRMED payment-claim row. DELIBERATELY opt-in (NOT in `make ci`) —
# it spawns two real nodes and needs ~/.zcash-params for the prover.
test-market-acceptance: zclassic23 zcl-rpc market-acceptance-helper
	@bash tools/dev/market_acceptance.sh

# B5 onion-delivery acceptance: two isolated regtest daemons (396xx quads +
# 20040/20041 + 39998, loopback P2P only), BOTH booted with -tor and NEITHER
# with -externalip. The seller commits a v2 onion-endpoint signed offer; the
# buyer pays with a real Sapling transaction, is refused delivery before
# confirmation through the onion route, is refused BY NAME
# (ONION_DELIVERY_UNAVAILABLE) when restarted without -tor, then retrieves
# the fixture as 60 KiB slices over real Tor circuits — witnessed by the
# /market/chunk lines in BOTH tor.log files and a byte-identical
# republication of the offer root. DELIBERATELY opt-in (NOT in `make ci` or
# any aggregate) — it needs public Tor network reachability (Tor bootstrap
# to the real network twice, ~10-60 s per node) and ~/.zcash-params for the
# prover, and it FAILS with a named reason when the host cannot bootstrap.
test-market-onion-acceptance: zclassic23 zcl-rpc
	@bash tools/dev/market_onion_acceptance.sh

# Moderation acceptance: two isolated regtest daemons (397xx quads +
# 20050/20051 + 39997, loopback P2P only, no Tor — moderation is
# transport-independent). The seller commits one signed paid offer; it
# gossips to the buyer, and the two nodes then apply DIFFERENT
# moderation profiles to the SAME offer_id: the boot-default
# general-audience.v1 hides the unreviewed offer with an honest
# hidden_count, the explicit {"profile":"open"} opt-in and an open-view
# node default (plan/commit) show it annotated, reviewed_ok/sensitive
# review marks drive per-node visibility, and A and B legitimately
# disagree while file_offers keeps exactly one gossip-stored row on
# both (hidden != rejected). Closes with the protocol-validity
# separation proof: the signed wire columns are byte-identical on both
# nodes and untouched by every moderation action. DELIBERATELY opt-in
# (NOT in `make ci`) — it spawns two real nodes; no payment is planned
# or paid (visibility acceptance, not a trade), so ~/.zcash-params is
# not needed beyond what regtestshielded mining already loads.
test-market-moderation-acceptance: zclassic23 zcl-rpc
	@bash tools/dev/market_moderation_acceptance.sh

# ── metaverse-tour / metaverse-verify (docs/METAVERSE_MVP.md, MM1 + MM7) ──
#
# metaverse-tour is criterion MM1: ONE hermetic script driving an isolated
# regtest node (own /tmp datadir + 39xxx ports, same discipline as
# tools/scripts/isolated_node_env.sh) through the five-step tour — publish a
# package, space plan/commit/show, scout plan/run/show, commons status,
# property list. Exit 0 only when every step's typed output confirms.
.PHONY: metaverse-tour
metaverse-tour: zclassic23 zcl-rpc
	@bash tools/dev/metaverse_tour.sh

# metaverse-verify is criterion MM7: the ONE-COMMAND local aggregate of the
# metaverse MVP proofs, modeled on mvp-verify — runs ALL members and reports
# each (a FAIL does not stop the run), then exits non-zero if any failed.
# The multi-daemon members stay OUT of hermetic `make ci` by the same rule
# as mvp-verify (they spawn real /tmp regtest nodes).
.PHONY: metaverse-verify
metaverse-verify: zclassic23 zcl-rpc zclassic23-package-verify
	@bash -c 'set -uo pipefail; \
	 echo "══════════════════════════════════════════════════════════════"; \
	 echo "  metaverse-verify: LOCAL metaverse MVP proofs (MM1-MM7)"; \
	 echo "  Daemon-spawning members stay OUT of hermetic make ci."; \
	 echo "══════════════════════════════════════════════════════════════"; \
	 declare -A NAME=( \
	   [1]="MM1 metaverse tour, isolated regtest node (metaverse-tour)" \
	   [2]="MM2 package lifecycle groups (publish/fetch/verify)" \
	   [3]="MM3 property catalog decision table (metaverse_catalog)" \
	   [4]="MM4 ZC23 simulation unit groups (patronage/continuity/commons)" \
	   [5]="MM5 metaverse site render gate (metaverse_site)" \
	   [6]="MM7a seven-daemon DHT acceptance (test-zcode-dht-acceptance)" \
	   [7]="MM7b two-daemon science acceptance (test-science-acceptance)" ); \
	 declare -A TGT=( [1]=metaverse-tour \
	   [2]="t-fast-exact ONLY=zcode_publish,zcode_fetch,zcode_verify" \
	   [3]="t-fast ONLY=metaverse_catalog" \
	   [4]="t-fast-exact ONLY=zcode_patronage,zcode_continuity,zcode_commons_projection" \
	   [5]="t-fast ONLY=metaverse_site" \
	   [6]=test-zcode-dht-acceptance [7]=test-science-acceptance ); \
	 declare -A ST; fails=0; \
	 for i in 1 2 3 4 5 6 7; do \
	   echo ""; echo "── metaverse-verify [$$i/7]: $${NAME[$$i]} ──"; \
	   if $(MAKE) $${TGT[$$i]}; then ST[$$i]="PASS"; else ST[$$i]="FAIL"; fails=$$((fails+1)); fi; \
	 done; \
	 echo ""; echo "══ metaverse-verify SUMMARY ══"; \
	 for i in 1 2 3 4 5 6 7; do printf "  [%s] %-62s %s\n" "$$i" "$${NAME[$$i]}" "$${ST[$$i]}"; done; \
	 [ "$$fails" = 0 ] || { echo "metaverse-verify: $$fails member(s) FAILED"; exit 1; }; \
	 echo "metaverse-verify: ALL MEMBERS PASS"'
# O5 Living Commons protocol acceptance.  Keep these exact registered groups
# together: the Score/Commons group owns the three disjoint scratch processes
# and policy admission, shadow_policy owns expiry/replay/approval bounds,
# swarm owns cancellation races, swarm_net owns real zpkgswm frames plus
# corruption, restart/resume and provider failover, dht_service owns signed
# root-only discovery/churn/restart, and science_store owns corrupt-CAS refusal
# and byte-identical projection rebuild.  This is deliberately same-host
# protocol proof; it cannot award the real independent-reproduction unit.
ZCODE_REPRODUCTION_ACCEPTANCE_TESTS := test_zcode_score_receipt,test_zcode_shadow_policy,test_zcode_swarm,test_zcode_swarm_net,test_zcode_dht_service,test_zcode_science_store
zcode-reproduction-acceptance:
	@$(MAKE) --no-print-directory t-fast-exact \
	  ONLY='$(ZCODE_REPRODUCTION_ACCEPTANCE_TESTS)'
	@echo "zcode-reproduction-acceptance: PASS distinct_signer_simulation=true approved_fixture_policy=true actual_off_host_credit=false"

# ── STICKINESS fault-injection matrix (sticky-node-plan §4 metric) ──
#
# sticky-matrix: for each fault class, inject on a THROWAWAY /tmp datadir
# copy, plain-restart the binary, gate on H* CLIMB to tip with the G-SOV
# sub-gate green (recovered AND sovereign). Emits a JSON verdict sentinel
# with AAR (auto-recovery %) + MTTUR. Default gate: AAR over ATTEMPTABLE
# rows == 100% AND verdict is PASS|BLOCKED (BLOCKED = a row that cannot be
# made hermetic yet — flagged, never a vacuous green). FRESH-sentinel guard
# (anti-false-green, same discipline as replay-canary-anchor): the verdict
# file must exist, be strictly newer than a marker dropped at run start, and
# say verdict PASS|BLOCKED. DELIBERATELY out of hermetic `make ci` — it
# SPAWNS a real isolated node (isolated_node_env.sh owns all isolation).
.PHONY: sticky-matrix
sticky-matrix: zclassic23 zcl-rpc
	@bash -c 'set -uo pipefail; \
	 vd="$${ZCL_STICKY_VERDICT_DIR:-$$HOME/.local/state/zclassic23-sticky}"; \
	 mkdir -p "$$vd"; \
	 marker="$$vd/.guard_started_matrix"; rm -f "$$marker"; : > "$$marker"; \
	 export ISO_KIND=sticky ISO_PORT_BASE=$${ISO_PORT_BASE:-39060}; \
	 set +e; bash tools/scripts/sticky_matrix.sh; rc=$$?; set -e; \
	 f="$$vd/sticky_matrix.json"; \
	 if [ ! -f "$$f" ] || [ ! "$$f" -nt "$$marker" ]; then \
	     echo "sticky-matrix: FAIL (no FRESH verdict sentinel at $$f; harness rc=$$rc)"; \
	     [ -f "$$f" ] && cat "$$f"; rm -f "$$marker"; exit 1; \
	 fi; \
	 rm -f "$$marker"; \
	 if grep -Eq "\"verdict\":\"(PASS|BLOCKED)\"" "$$f"; then \
	     echo "sticky-matrix: PASS (fresh verdict; AAR over attemptable rows == 100%)"; cat "$$f"; \
	 else \
	     echo "sticky-matrix: FAIL (verdict not PASS|BLOCKED)"; cat "$$f"; exit 1; \
	 fi'

# sticky-matrix-v1: the v1 STICKINESS BAR — AAR_strict == 100% (every row
# passes, zero blocked, zero human/flag/legacy-datadir). Sets
# ZCL_STICKY_REQUIRE_ALL=1 so a BLOCKED row is a HARD FAIL. This is the gate
# that flips MVP stickiness once the regtest-durability + sibling-adopt
# dependencies (rows 7/12) and the disk/clock mount/inject helpers (11/13)
# land. Until then it is EXPECTED to fail loud — that is the honest signal.
.PHONY: sticky-matrix-v1
sticky-matrix-v1: zclassic23 zcl-rpc
	@ZCL_STICKY_REQUIRE_ALL=1 ISO_PORT_BASE=$${ISO_PORT_BASE:-39064} \
	    $(MAKE) sticky-matrix

# C6 bounded compressed-soak PROXY: self-spawn an isolated /tmp regtest
# node, drive 180 s of generate-load, and assert the soak runner exits
# SOAK_OK (verdict=OK sentinel grepped so a no-op runner fails loud —
# false-green guard, same discipline as the mvp_gate macro). This is a
# hermetic CI green/red SIGNAL, NOT the real 168 h operational soak.
.PHONY: soak-ci
# Runs under bash for `set -o pipefail` (see test-crash-bootstrap note).
# `set +e` around the runner so a non-zero verdict is reported (not
# swallowed by errexit) before the false-green sentinel check.
soak-ci: soak_runner zclassic23 zcl-rpc
	@bash -c 'set -uo pipefail; \
	 export ISO_KIND=soak ISO_PORT_BASE=39040; \
	 . tools/scripts/isolated_node_env.sh; \
	 iso_init; \
	 log="$$ISO_DD/soak-ci.log"; \
	 echo "soak-ci: 180s compressed soak on $$ISO_DD (rpc=$$ISO_RPCPORT)"; \
	 set +e; \
	 out=$$($(SOAK_RUNNER_BIN) \
	     --ci-proxy \
	     --node-datadir="$$ISO_DD" \
	     --rpcport="$$ISO_RPCPORT" \
	     --p2p-port="$$ISO_PORT" \
	     --fs-port="$$ISO_FSPORT" \
	     --https-port="$$ISO_HTTPSPORT" \
	     --connect=127.0.0.1:"$$ISO_CONNECT_SINK" \
	     --interval-sec=5 \
	     --load=generate:5 \
	     --rpc=$(ZCL_RPC_BIN) \
	     --log="$$log" 2>&1); rc=$$?; set -e; \
	 echo "$$out"; \
	 if [ "$$rc" != "0" ]; then \
	     echo "soak-ci: FAILED (runner exit $$rc != SOAK_OK); log tail:"; \
	     tail -20 "$$log" 2>/dev/null || true; \
	     exit 1; \
	 fi; \
	 if ! echo "$$out" | grep -q "verdict=OK"; then \
	     echo "soak-ci: FALSE-GREEN GUARD — runner exited 0 but never printed verdict=OK (no-op?)"; \
	     exit 1; \
	 fi; \
	 echo "soak-ci: PASS (SOAK_OK — tip advanced under load, RSS plateaued)"'

# ── Standing replay canary (opt-in, spawns an isolated mainnet node) ──
#
# replay-canary-anchor / -genesis drive tools/scripts/replay_canary.sh,
# which replays the REAL chain through the HEAD reducer in an ISOLATED
# /tmp scratch datadir on 3905x ports and asserts zero consensus rejects,
# the anchor checkpoint passed without an integrity FATAL, and coarse UTXO
# stats == co-located zclassicd gettxoutsetinfo (RPC 8232, read-only). They
# are DELIBERATELY excluded from `make ci` — like soak-ci/test-crash-bootstrap
# they SPAWN a real node (and read tens of GB on /tmp). `make ci` runs only
# the hermetic verdict-logic gate (test_replay_canary_verdict, inside
# test_zcl). The AUTHORITATIVE verdict is the sentinel FILE; the false-green
# guard below requires a FRESH PASS — the sentinel must exist, say PASS, AND
# be strictly newer than a marker dropped right before this run started. The
# harness ALSO removes any prior sentinel at run start (reset_verdict), so a
# no-op harness (crashed, killed, OOM, timed out, produced no sentinel) fails
# loud and a STALE PASS left by a previous successful run can never be read
# as this run's proof — never exit-0-as-proof, never stale-file-as-proof.
.PHONY: replay-canary-anchor
replay-canary-anchor: zclassic23 zcl-rpc
	@bash -c 'set -uo pipefail; \
	 vd="$${ZCL_CANARY_VERDICT_DIR:-$$HOME/.local/state/zclassic23-canary}"; \
	 mkdir -p "$$vd"; \
	 marker="$$vd/.guard_started_anchor"; rm -f "$$marker"; : > "$$marker"; \
	 set +e; bash tools/scripts/replay_canary.sh --from=anchor; rc=$$?; set -e; \
	 f="$$vd/replay_canary_anchor.json"; \
	 if [ ! -f "$$f" ] || [ ! "$$f" -nt "$$marker" ] || ! grep -q "\"verdict\":\"PASS\"" "$$f"; then \
	     echo "replay-canary-anchor: FAIL (no FRESH PASS sentinel at $$f; harness rc=$$rc)"; \
	     [ -f "$$f" ] && cat "$$f"; \
	     rm -f "$$marker"; exit 1; \
	 fi; \
	 rm -f "$$marker"; \
	 echo "replay-canary-anchor: PASS (fresh sentinel verdict=PASS)"'

.PHONY: replay-canary-genesis
replay-canary-genesis: zclassic23 zcl-rpc
	@bash -c 'set -uo pipefail; \
	 vd="$${ZCL_CANARY_VERDICT_DIR:-$$HOME/.local/state/zclassic23-canary}"; \
	 mkdir -p "$$vd"; \
	 marker="$$vd/.guard_started_genesis"; rm -f "$$marker"; : > "$$marker"; \
	 set +e; bash tools/scripts/replay_canary.sh --from=genesis; rc=$$?; set -e; \
	 f="$$vd/replay_canary_genesis.json"; \
	 if [ ! -f "$$f" ] || [ ! "$$f" -nt "$$marker" ] || ! grep -q "\"verdict\":\"PASS\"" "$$f"; then \
	     echo "replay-canary-genesis: FAIL (no FRESH PASS sentinel at $$f; harness rc=$$rc)"; \
	     [ -f "$$f" ] && cat "$$f"; \
	     rm -f "$$marker"; exit 1; \
	 fi; \
	 rm -f "$$marker"; \
	 echo "replay-canary-genesis: PASS (fresh sentinel verdict=PASS)"'

# ── D2 coinbase-maturity REPLAY GATE ──
# Full-history safety doctrine: docs/CONSENSUS_PARITY_DOCTRINE.md.
#
# Replays the real chain genesis->tip on a COPY datadir with the
# coinbase-maturity tightening ON (-enforce-coinbase-maturity) under the
# env gate ZCL_REPLAY_COUNT_ONLY=1, which makes the fold COUNT-AND-CONTINUE:
# every premature-coinbase-spend the tightening would NEWLY reject is
# logged+counted and the fold continues to tip WITHOUT authoring the
# offending block's coins. The gate then greps the structured summary:
#   total_newly_rejected == 0  => safe to flip the default (no real block
#                                  depends on the looser rule)
#   total_newly_rejected >= 1  => MUST NOT ship (the h=478544 class)
# AND blocks_replayed == tip+1 (contiguous from genesis) — a sparse / non
# -genesis walk reports a FALSE 0 and is a GATE FAILURE, not a pass.
#
# SAFETY: REFUSES to run against the live datadirs (~/.zclassic-c23 and
# ~/.zclassic). DATADIR=<copy> is mandatory and must be a copy:
#   cp -a ~/.zclassic-c23 ~/.zclassic-c23-replay-d2
#   make replay-gate-d2 DATADIR=$HOME/.zclassic-c23-replay-d2
# The fold authors coins_kv on the COPY (~cold-sync-apply cost, tens of
# minutes); zclassicd and the live node are untouched.
.PHONY: replay-gate-d2
replay-gate-d2: zclassic23
	@bash -c 'set -uo pipefail; \
	 dd="$${DATADIR:-}"; \
	 if [ -z "$$dd" ]; then \
	     echo "replay-gate-d2: DATADIR=<copy> is required (a COPY of the datadir, never the live one)"; \
	     echo "  cp -a $$HOME/.zclassic-c23 $$HOME/.zclassic-c23-replay-d2"; \
	     echo "  make replay-gate-d2 DATADIR=$$HOME/.zclassic-c23-replay-d2"; \
	     exit 2; \
	 fi; \
	 ddabs="$$(readlink -f "$$dd" 2>/dev/null || echo "$$dd")"; \
	 live1="$$(readlink -f "$$HOME/.zclassic-c23" 2>/dev/null || echo "$$HOME/.zclassic-c23")"; \
	 live2="$$(readlink -f "$$HOME/.zclassic" 2>/dev/null || echo "$$HOME/.zclassic")"; \
	 if [ "$$ddabs" = "$$live1" ] || [ "$$ddabs" = "$$live2" ]; then \
	     echo "replay-gate-d2: REFUSING — DATADIR ($$ddabs) is a LIVE datadir. The fold WRITES coins_kv; run it on a COPY only."; \
	     exit 2; \
	 fi; \
	 if [ ! -d "$$ddabs" ]; then \
	     echo "replay-gate-d2: DATADIR $$ddabs does not exist"; exit 2; \
	 fi; \
	 logf="$$ddabs/replay-gate-d2.run.log"; rm -f "$$logf"; \
	 rm -f "$$ddabs/zclassic23.pid"; \
	 echo "replay-gate-d2: replaying $$ddabs genesis->tip (count-and-continue); log -> $$logf"; \
	 set +e; \
	 ZCL_REPLAY_COUNT_ONLY=1 build/bin/zclassic23 -datadir="$$ddabs" \
	     -refold-staged -enforce-coinbase-maturity -nobgvalidation \
	     > "$$logf" 2>&1; \
	 rc=$$?; set -e; \
	 line="$$(grep -F "\"event\":\"replay_gate.d2.summary\"" "$$logf" | tail -1)"; \
	 if [ -z "$$line" ]; then \
	     echo "replay-gate-d2: FALSE-GREEN GUARD — no replay_gate.d2.summary line in $$logf (binary rc=$$rc). Did the fold reach tip?"; \
	     tail -20 "$$logf" 2>/dev/null || true; \
	     exit 1; \
	 fi; \
	 echo "replay-gate-d2: summary => $$line"; \
	 total="$$(echo "$$line" | grep -oE "\"total_newly_rejected\":[0-9]+" | grep -oE "[0-9]+")"; \
	 pass="$$(echo "$$line" | grep -oE "\"gate_pass\":(true|false)" | grep -oE "(true|false)")"; \
	 contig="$$(echo "$$line" | grep -oE "\"contiguous\":(true|false)" | grep -oE "(true|false)")"; \
	 reached="$$(echo "$$line" | grep -oE "\"reached_target\":(true|false)" | grep -oE "(true|false)")"; \
	 if [ "$$contig" != "true" ]; then \
	     echo "replay-gate-d2: FAIL — blocks_replayed != tip+1 (sparse/non-genesis walk = FALSE 0, NOT a pass)"; \
	     exit 1; \
	 fi; \
	 if [ "$$reached" != "true" ]; then \
	     echo "replay-gate-d2: FAIL — reached_target=false (the apply walk stalled BELOW the header tip; a contiguous-but-truncated walk is NOT a pass)"; \
	     exit 1; \
	 fi; \
	 if [ "$$total" != "0" ] || [ "$$pass" != "true" ]; then \
	     echo "replay-gate-d2: FAIL — total_newly_rejected=$$total (>=1 => the chain depends on the looser rule; the h=478544 class; MUST NOT flip the default)"; \
	     exit 1; \
	 fi; \
	 echo "replay-gate-d2: PASS — 0 newly-rejected over a contiguous genesis->FULL-header-tip walk; safe to flip the default"'

# ── MVP-C6 live-soak evidence (opt-in; reads the LIVE soak node) ─────
#
# soak-evidence-report judges the hourly evidence JSONL accumulated by
# the zclassic23-soak-evidence timer (deploy/examples/) against the
# 168 h MVP #6 window and prints VERDICT=MET|NOT_MET|INSUFFICIENT from
# PARSED DATA only. DELIBERATELY excluded from the default `ci:` recipe:
# the collector reads the LIVE soak node + zclassicd (read-only RPC) and
# `make ci` must stay hermetic — it must never depend on (or start) a
# node. The hermetic logic check is soak-evidence-selftest (fixture
# JSONL in a mktemp dir; no nodes, no live state). The false-green
# guard below requires the judge to actually PRINT a verdict line — a
# crashed/no-op judge fails loud, never exit-0-as-proof.
.PHONY: soak-evidence-report
soak-evidence-report:
	@bash -c 'set -uo pipefail; \
	 set +e; out=$$(bash tools/scripts/soak_evidence.sh judge $${ZCL_SOAK_JUDGE_ARGS:-}); rc=$$?; set -e; \
	 echo "$$out"; \
	 if ! echo "$$out" | grep -q "soak-evidence: VERDICT="; then \
	     echo "soak-evidence-report: FALSE-GREEN GUARD — judge printed no VERDICT line (rc=$$rc)"; \
	     exit 1; \
	 fi; \
	 exit "$$rc"'

.PHONY: soak-evidence-selftest
soak-evidence-selftest:
	@bash -c 'set -uo pipefail; \
	 set +e; out=$$(bash tools/scripts/soak_evidence.sh --selftest 2>&1); rc=$$?; set -e; \
	 echo "$$out"; \
	 if [ "$$rc" != "0" ] || ! echo "$$out" | grep -q "^selftest: PASS"; then \
	     echo "soak-evidence-selftest: FAIL (rc=$$rc; no selftest: PASS line)"; \
	     exit 1; \
	 fi; \
	 echo "soak-evidence-selftest: PASS"'

# ── stopwatch gates (opt-in; wall-clock evidence ledgers) ────────────
#
# c3-stopwatch-report / netdisrupt-stopwatch-report judge the LAST line of
# the ledgers appended by tools/scripts/c3_stopwatch_run_and_record.sh /
# tools/scripts/netdisrupt_stopwatch_run_and_record.sh (deploy/examples/
# zcl-c3-stopwatch.timer / zcl-netdisrupt-stopwatch.timer run those every
# 6h) via tools/scripts/stopwatch_evidence_judge.sh — a point-in-time
# judge (PASS/FAIL/STALE), not a windowed accrual judge like
# soak-evidence-report. Same false-green guard discipline: the judge MUST
# print a VERDICT= line or the recipe fails loud regardless of its own
# exit code. DELIBERATELY excluded from `make ci` — these read a LEDGER
# file under $HOME/.local/state, not hermetic fixtures.
.PHONY: c3-stopwatch-report
c3-stopwatch-report:
	@bash -c 'set -uo pipefail; \
	 hist="$${ZCL_C3_STOPWATCH_HISTORY:-$$HOME/.local/state/zclassic23-c3-stopwatch/history.jsonl}"; \
	 set +e; out=$$(bash tools/scripts/stopwatch_evidence_judge.sh "$$hist" $${ZCL_STOPWATCH_JUDGE_ARGS:-}); rc=$$?; set -e; \
	 echo "$$out"; \
	 if ! echo "$$out" | grep -q "stopwatch-judge: VERDICT="; then \
	     echo "c3-stopwatch-report: FALSE-GREEN GUARD — judge printed no VERDICT line (rc=$$rc)"; \
	     exit 1; \
	 fi; \
	 exit "$$rc"'

# stopwatch-judge-selftest: hermetic regression guard for the stopwatch judge's
# fixture-integrity gates — canned tmp ledgers, no live nodes/ledgers touched.
# Proves a below-checkpoint tip is refused (THIN_FIXTURE), a fixture lagging a
# fresh oracle sample is refused (LAGGING_FIXTURE), a missing SLO ledger is
# tolerated, and legacy/netdisrupt lines without final_network_tip still judge
# exactly as before. Same false-green discipline as the sibling *-selftest
# targets (rc==0 AND a "selftest: PASS" line).
.PHONY: stopwatch-judge-selftest
stopwatch-judge-selftest:
	@bash -c 'set -uo pipefail; \
	 set +e; out=$$(bash tools/scripts/stopwatch_evidence_judge.sh --selftest 2>&1); rc=$$?; set -e; \
	 echo "$$out"; \
	 if [ "$$rc" != "0" ] || ! echo "$$out" | grep -q "^selftest: PASS"; then \
	     echo "stopwatch-judge-selftest: FAIL stopwatch_evidence_judge.sh (rc=$$rc; no selftest: PASS line)"; \
	     exit 1; \
	 fi; \
	 echo "stopwatch-judge-selftest: PASS"'

# stopwatch-symmetry-selftest: hermetic mutation test of the artifact-symmetry
# comparison (tools/scripts/stopwatch_artifact_symmetry_check.sh --selftest).
# No node, no network, no nc listener, no datadir — it drives the comparison
# against synthetic artifact pairs and requires that BREAKING each thing the
# comparison claims to check turns it red, and that an untouched pair stays
# green. That control-plus-mutation shape is the point: a comparison that
# always failed, and one that always passed, would both look fine under a
# single-direction check.
#
# stopwatch-symmetry-prove is the full end-to-end version — it drives the real
# C3 harness twice against a mock node (forced pass, forced non-pass) and
# compares the two artifact sets. It is separate because it needs an nc
# listener on a fixed loopback port, which makes it unsuitable for an
# unattended aggregate; run it by hand after touching the harness's capture or
# artifact code.
.PHONY: stopwatch-symmetry-selftest
stopwatch-symmetry-selftest:
	@bash -c 'set -uo pipefail; \
	 set +e; out=$$(bash tools/scripts/stopwatch_artifact_symmetry_check.sh --selftest 2>&1); rc=$$?; set -e; \
	 echo "$$out"; \
	 if [ "$$rc" != "0" ] || ! echo "$$out" | grep -q "^selftest: PASS"; then \
	     echo "stopwatch-symmetry-selftest: FAIL stopwatch_artifact_symmetry_check.sh (rc=$$rc; no selftest: PASS line)"; \
	     exit 1; \
	 fi; \
	 echo "stopwatch-symmetry-selftest: PASS"'

.PHONY: stopwatch-symmetry-prove
stopwatch-symmetry-prove:
	@bash -c 'set -uo pipefail; \
	 set +e; out=$$(bash tools/scripts/stopwatch_artifact_symmetry_check.sh 2>&1); rc=$$?; set -e; \
	 echo "$$out"; \
	 if [ "$$rc" = "2" ]; then \
	     echo "stopwatch-symmetry-prove: SKIP (no nc to stand up the named loopback fixture peer)"; \
	     exit 0; \
	 fi; \
	 if [ "$$rc" != "0" ] || ! echo "$$out" | grep -q "^symmetry: PASS"; then \
	     echo "stopwatch-symmetry-prove: FAIL (rc=$$rc; the pass and non-pass runs did NOT record the same evidence set)"; \
	     exit 1; \
	 fi; \
	 echo "stopwatch-symmetry-prove: PASS"'

.PHONY: arch-score
# Mechanical completion score for the ARCHITECTURE NORTH STAR
# (docs/ARCHITECTURE_NORTH_STAR.md). Run as you work — the score rises only when
# a real invariant is satisfied or an outcome gate passes. Lowest-weight-last =
# "chase these next". This is the LLM's on-track compass toward instant-on.
arch-score:
	@bash tools/scripts/arch_score.sh

.PHONY: metaverse-score
# Mechanical completion score for the METAVERSE MVP (docs/METAVERSE_MVP.md,
# criteria MM1-MM8). Same rules as arch-score: the score rises only on a
# mechanical proof; never edit the scorer to win; ZC23 stays simulation-only.
metaverse-score:
	@bash tools/scripts/metaverse_score.sh

# ── netdisrupt-stopwatch (PROOF B, SELF-CONTAINED two-node RUNNER) ────
#
# The runnable, no-fixture-needed companion to
# mvp-netdisrupt-recovery-stopwatch above. That target drills an
# already-running live client + a caller-supplied upstream pid; THIS one
# spawns its OWN isolated two-node regtest fixture (a throwaway miner +
# follower under /tmp on non-live 39xxx ports), proves the follower reaches
# the miner's tip, YANKS the network (SIGSTOP the miner — a clean partition),
# holds --cut-secs of silence, restores it (SIGCONT), mines a fresh gap, and
# times how long the follower takes to auto-resume and re-catch the miner's
# tip WITHOUT a restart — the plan's proof pillar
# (docs/work/stopwatch-gates.md, PROOF B). It records the RESUME LATENCY as
# the headline metric.
#
# It ALWAYS appends one line to the shared PROOF B ledger
# (~/.local/state/zclassic23-netdisrupt-stopwatch/history.jsonl) so
# `make netdisrupt-stopwatch-report` (the judge) has a fresh last line to
# gate on, THEN surfaces the drill verdict the coldstart-recipe way: SKIP
# (a precondition absent — binary/ports/initial-sync) maps to a clean exit 0;
# SEAM (3) / STALLED-NAMED (4) / FAIL (1) propagate as a failing recipe.
# Tunables are the ZCL_ND2_* env vars (see
# tools/scripts/netdisrupt_two_node_drill.sh). SPAWNS real nodes, so it is
# DELIBERATELY out of `make ci` — opt-in, same as test-two-node-peer-tip.
.PHONY: netdisrupt-stopwatch
netdisrupt-stopwatch: zclassic23 zcl-rpc
	@bash -c 'set -uo pipefail; \
	 echo "══ PROOF B STOPWATCH (self-contained): spawn miner+follower -> yank (SIGSTOP) -> restore (SIGCONT)+gap -> time follower auto-resume+climb ══"; \
	 bash tools/scripts/netdisrupt_two_node_run_and_record.sh; rc=$$?; \
	 exit $$rc'

.PHONY: netdisrupt-stopwatch-report
netdisrupt-stopwatch-report:
	@bash -c 'set -uo pipefail; \
	 hist="$${ZCL_NETDISRUPT_STOPWATCH_HISTORY:-$$HOME/.local/state/zclassic23-netdisrupt-stopwatch/history.jsonl}"; \
	 set +e; out=$$(bash tools/scripts/stopwatch_evidence_judge.sh "$$hist" $${ZCL_STOPWATCH_JUDGE_ARGS:-}); rc=$$?; set -e; \
	 echo "$$out"; \
	 if ! echo "$$out" | grep -q "stopwatch-judge: VERDICT="; then \
	     echo "netdisrupt-stopwatch-report: FALSE-GREEN GUARD — judge printed no VERDICT line (rc=$$rc)"; \
	     exit 1; \
	 fi; \
	 exit "$$rc"'

# Always-fresh end-to-end test.
#
# Some in-suite tests fork the real `build/bin/zclassic23` binary and assert
# runtime behavior.  If the binary is older than its source files those tests
# can SKIP or false-green, so `make test-e2e` forces a rebuild of zclassic23
# (and test_zcl) before running, ensuring the suite always runs against the
# current source.
test-e2e: zclassic23 test_zcl
	ulimit -s unlimited && $(TEST_ZCL_BIN)

# P11.4 shielded-payment gate.
#
# Runs the real transparent->shielded wallet path inside test_zcl with
# Sapling proving params loaded from ~/.zcash-params. The target skips on
# hosts that do not have the proving/verifying params installed so CI can
# call it unconditionally without creating false negatives on clean workers.
test-shielded-payment: test_zcl
	@set -eu; \
	params_dir="$$HOME/.zcash-params"; \
	for f in sapling-spend.params sapling-output.params sprout-groth16.params sprout-verifying.key; do \
		if [ ! -r "$$params_dir/$$f" ]; then \
			echo "test-shielded-payment: SKIP ($$params_dir/$$f missing)"; \
			exit 0; \
		fi; \
	done; \
	ZCL_STRESS_TESTS=1 ZCL_TEST_ONLY=shielded_payment $(TEST_ZCL_BIN)

# P11.5 store end-to-end gate.
#
# Runs the store order -> payment reconciliation -> token access path inside
# test_zcl. This is deterministic and self-contained, but remains opt-in so
# the default suite does not pay extra setup/runtime cost.
test-store-e2e: test_zcl
	ZCL_STRESS_TESTS=1 ZCL_TEST_ONLY=store_e2e $(TEST_ZCL_BIN)

# P11.5b store OPERATOR proof (MVP criterion #5 rung A, full binary).
#
# The hermetic store_e2e gates above run the store flow inside test_zcl; this
# target boots a real build/bin/zclassic23 node on regtest in a throwaway
# /tmp datadir (isolated 391xx ports, dead -connect sink — never the live
# node, the oracle, or their datadirs) and drives the whole MVP #5 claim
# through the native typed CLI an operator uses: app.store.list-product with
# a binary blob carrying embedded NUL bytes -> catalog -> order (the real
# CSRF + PoW order route) -> pay (real shielded z_sendmany t->z with the
# ZCL23ORDER:<id> memo, broadcast to the node's own mempool) -> mined
# confirmations -> purchases until ready_to_collect -> collect -> cmp the
# delivered bytes against the original. Prints VERDICT=PASS/SKIP/FAIL with
# the failing stage named. Params-guarded like test-shielded-payment; the
# script additionally SKIPs if regtest mining is unavailable. Opt-in; NOT in
# `make ci`.
test-store-operator-proof: zclassic23 zcl-rpc
	@set -eu; \
	params_dir="$$HOME/.zcash-params"; \
	for f in sapling-spend.params sapling-output.params sprout-groth16.params sprout-verifying.key; do \
		if [ ! -r "$$params_dir/$$f" ]; then \
			echo "test-store-operator-proof: SKIP ($$params_dir/$$f missing)"; \
			exit 0; \
		fi; \
	done; \
	tools/scripts/store_sell_operator_proof.sh

# ── MVP acceptance gates: hermetic vs fixture-bound ───────────
#
# The MVP acceptance tests (docs/MVP.md #2..#7) all self-skip unless
# ZCL_STRESS_TESTS=1. We split them by what a clean CI container can
# actually provide, so `make ci` only blocks on tests that truly run:
#
#   ci-mvp-gates  HERMETIC — no network, no params, no oracle. Runs in
#                 `make ci`. Each gate is invoked FOCUSED via
#                 ZCL_TEST_ONLY so we do NOT accidentally trip the
#                 non-hermetic onion gate by blanket-setting the env
#                 var on the whole suite.
#                   #3 cold_start             (in-process sync FSM, ~6-10s)
#                   #5 store_e2e              (local SQLite + store ctrl, sub-s)
#                   #7 kill9                  (fork+SIGKILL+SQLite, ~4-8s)
#                      chain_advance_atomicity (fork child procs, supports #7)
#
#   ci-stress     NON-HERMETIC — needs external resources a clean
#                 container lacks. NOT in `make ci`. Run where the
#                 resource exists (params staged / Tor egress allowed):
#                   #2 onion_bootstrap        (real Tor + dir-authority net)
#                   #4 shielded_payment       (~/.zcash-params, params-guarded)
#
# Each focused run is its own process, so a failure in one gate names
# exactly which MVP criterion regressed.
#
# Focused MVP gate (DRY): run ONE ZCL_TEST_ONLY selector hermetically and
# PROVE it actually ran that focused subset. test.c returns early only on a
# selector match, so an unknown/renamed selector silently falls through to the
# FULL suite — which under ZCL_STRESS_TESTS=1 runs the non-hermetic onion test
# and would hang CI while looking green. The sentinel grep converts that silent
# fall-through into a loud failure. Redirect (not pipe) so the test's real exit
# status survives on dash. $(1)=label $(2)=selector $(3)=unique sentinel.
define mvp_gate
@echo "══ $(1) ══"; l=$$(mktemp); if ! ZCL_STRESS_TESTS=1 ZCL_TEST_ONLY=$(2) $(TEST_ZCL_BIN) >"$$l" 2>&1; then cat "$$l"; rm -f "$$l"; echo "MVP GATE FAILED: $(1) (ZCL_TEST_ONLY=$(2) exited non-zero)"; exit 1; fi; cat "$$l"; if ! grep -qF "$(3)" "$$l"; then rm -f "$$l"; echo "MVP GATE FALSE-GREEN GUARD: $(1) — sentinel \"$(3)\" not printed; the ZCL_TEST_ONLY=$(2) selector likely no longer exists in lib/test/src/test.c so the full suite ran. Restore the selector or re-point this gate."; exit 1; fi; rm -f "$$l"
endef

.PHONY: ci-mvp-gates ci-stress
ci-mvp-gates: test_zcl
	$(call mvp_gate,MVP gate 3: cold-start sync FSM (hermetic),cold_start,=== Cold-start subset complete:)
	$(call mvp_gate,MVP gate 5: store end-to-end (hermetic),store_e2e,=== store e2e subset complete:)
	$(call mvp_gate,MVP gate 5b: store SHIELDED real ivk-decrypt + memo-bound (hermetic),store_e2e_shielded,=== store e2e shielded subset complete:)
	$(call mvp_gate,MVP gate 7: kill -9 recovery (hermetic),kill9,=== kill9 subset complete:)
	$(call mvp_gate,MVP support: chain-advance atomicity (hermetic),chain_advance_atomicity,=== chain_advance_atomicity subset complete:)
	$(call mvp_gate,MVP "it works": mined block -> reducer front door -> tip+1 (hermetic),reducer_ingest,=== reducer-ingest subset complete:)
	$(call mvp_gate,MVP gate 2 (slice): onion bootstrap <60s budget + v3 address (hermetic),onion_slice,=== onion_bootstrap_slice subset complete:)
	$(call mvp_gate,MVP gate 4 (slice): note encrypted to wallet ivk -> wallet decrypts -> z-balance (hermetic),shielded_receive,=== shielded_receive subset complete:)
	$(call mvp_gate,MVP gate 4b: DURABLE receive — decrypt -> node.db -> reopen -> z-balance (hermetic),shielded_receive_persist,=== shielded_receive_persist subset complete:)
	$(call mvp_gate,MVP forward-progress: N sequential blocks + heavier-fork reorg (hermetic),reducer_forward,=== reducer-forward subset complete:)
	$(call mvp_gate,MVP gate 8 (slice): consensus-parity mismatch-detection machinery (hermetic fixture),parity_slice,=== parity_slice subset complete:)
	$(call mvp_gate,MVP recovery: destroy the datadir -> restore from backup -> rescan -> SPEND (hermetic),destruction_drill,=== destruction_drill subset complete:)
	@echo "══ MVP hermetic gates: ALL PASSED ══"

# mvp-it-works: the single "you know your app works" proof — boots a fresh
# in-process regtest reducer, mines one real Equihash (48,5) block, drives it
# through reducer_ingest_block (the same front door live intake uses), and
# asserts the authoritative tip advances by exactly 1 with the block's coinbase
# live in the UTXO set and the commitment moved. Runs isolated (fresh process)
# because it drives reducer process-globals; teeth-verified (fails if the
# reducer cannot finalize forward — the live-wedge failure mode).
.PHONY: mvp-it-works
mvp-it-works: test_zcl
	$(call mvp_gate,MVP "it works": one mined block through the reducer -> tip+1,reducer_ingest,=== reducer-ingest subset complete:)
	@echo "══ MVP it-works gate: PASSED ══"

# mvp-onion-slice (C2 hermetic half): proves the bootstrap readiness/<60s budget
# LOGIC + the v3 .onion address format check in-process. The real <60s gate
# stays in ci-stress (selector "onion"). Runs isolated (onion_service singleton).
.PHONY: mvp-onion-slice
mvp-onion-slice: test_zcl
	$(call mvp_gate,MVP gate 2 (slice): onion bootstrap <60s budget + v3 address,onion_slice,=== onion_bootstrap_slice subset complete:)
	@echo "══ MVP onion-slice gate: PASSED ══"

# mvp-shielded-receive (C4 hermetic half): encrypts a note to the wallet's ivk,
# drives wallet_try_sapling_decrypt, asserts z-balance reflects it (and a note
# to a foreign ivk is NOT credited). Params-free — decryption needs no proving key.
.PHONY: mvp-shielded-receive
mvp-shielded-receive: test_zcl
	$(call mvp_gate,MVP C4 (receive): note encrypted to wallet ivk -> wallet decrypts -> z-balance,shielded_receive,=== shielded_receive subset complete:)

.PHONY: mvp-shielded-receive-persist
mvp-shielded-receive-persist: test_zcl
	$(call mvp_gate,MVP C4b (durable receive): decrypt -> node.db -> reopen -> z-balance,shielded_receive_persist,=== shielded_receive_persist subset complete:)
	@echo "══ MVP shielded-receive gate: PASSED ══"

# mvp-forward-progress: the live-wedge repro gate — boots a fresh in-process
# regtest reducer, mines + ingests N=32 sequential blocks through the front
# door asserting MONOTONIC tip advance (no stall/oscillation), then a heavier
# near-tip fork and asserts a clean reorg with a consistent UTXO commitment.
# On a stall it captures the height + all 8 stage cursors. Runs isolated.
.PHONY: mvp-forward-progress
mvp-forward-progress: test_zcl
	$(call mvp_gate,MVP forward-progress: N sequential blocks + heavier-fork reorg through the reducer,reducer_forward,=== reducer-forward subset complete:)
	@echo "══ MVP forward-progress gate: PASSED ══"

# mvp-parity-slice (C8 hermetic slice): regression-protects the UTXO parity
# service's mismatch-detection machinery via the in-process fixture reference —
# a CONSISTENT set reports 0 mismatches, a REAL injected outpoint is DETECTED
# (the negative control). The FULL C8 claim (live zclassicd oracle parity over
# the soak window) still needs the oracle. Runs isolated (parity-service globals).
.PHONY: mvp-parity-slice
mvp-parity-slice: test_zcl
	$(call mvp_gate,MVP C8 (slice): consensus-parity mismatch-detection machinery,parity_slice,=== parity_slice subset complete:)
	@echo "══ MVP parity-slice gate: PASSED ══"

# ci-stress: the fixture/network-bound MVP gates. Run on a worker that
# has the resource (Tor egress for #2, ~/.zcash-params for #4). Reuses
# the params-probe in test-shielded-payment so a host missing the params
# SKIPs cleanly instead of failing — do NOT call this from `make ci`.
ci-stress: test_zcl
	@echo "══ MVP gate #2: onion bootstrap (needs Tor network) ══"
	ZCL_STRESS_TESTS=1 ZCL_TEST_ONLY=onion $(TEST_ZCL_BIN)
	@echo "══ MVP gate #4: shielded payment (needs ~/.zcash-params) ══"
	$(MAKE) test-shielded-payment

# ── MVP gate #1: hermetic single-binary install ───────────────
#
# ci-install: the C1 ("single-binary install on clean Ubuntu/Debian")
# proxy gate. It BUILDS, INSTALLs the node + zcl-rpc to a THROWAWAY /tmp
# prefix (the file-copy a real `make install` performs, to a disposable
# DESTDIR), then SPAWNS one fully isolated regtest node FROM that prefix
# via the single audited isolation chokepoint
# tools/scripts/isolated_node_env.sh (unique /tmp datadir + 39xxx
# non-live ports + -connect=39999 dead sink + process-group cleanup),
# polls RPC readiness with a bounded timeout, asserts the installed
# binary answers + bound ONLY non-live ports, and cleans everything up.
#
# DELIBERATELY opt-in (NOT in `make ci`) — like ci-stress / soak-ci it
# spawns a real process. It NEVER runs systemctl and NEVER touches a
# live port or the live datadir. Runs under bash because the sourced
# isolation harness relies on `set -o pipefail`.
.PHONY: ci-install
ci-install: zclassic23 zcl-rpc zclassic23-package-verify zclassic23-package-sign
	@bash tools/scripts/ci_install_gate.sh

# ── ci-install-linger (C1 FULL operator claim, no docker) ─
#
# The clean-OS half of C1 is proven WITHOUT docker (docker is never used in this
# project): the portability floor is enforced statically by `make ci-symbol-floor`
# (in `make ci`), and the FULL operator claim — a real `make install` +
# `systemctl --user start` bringing the installed binary up to serve RPC — is
# exercised here via a fully ISOLATED linger unit `zclassic23-citest` (distinct
# name / /tmp datadir / 3906x non-live ports / dead-sink connect / -nolegacyimport;
# torn down on exit; NEVER touches the live `zclassic23` unit). SKIPs cleanly
# (exit 2 -> 0) where there is no systemd --user session. A mvp-verify member;
# out of hermetic `make ci` (spawns a real service).
.PHONY: ci-install-linger
ci-install-linger: zclassic23 zcl-rpc
	@bash -c 'bash tools/scripts/ci_install_linger_gate.sh; rc=$$?; \
	 if [ "$$rc" -eq 2 ]; then echo "ci-install-linger: SKIP (no systemd --user session)"; exit 0; fi; exit $$rc'

# ── mvp-onion-local (C2 real <60s bootstrap, Tor-egress-gated) ─
#
# The FULL C2 claim (a fresh node bootstraps its v3 onion in <60s over the
# real Tor network) needs Tor network EGRESS, which a hermetic CI container
# lacks — so it CANNOT live in `make ci` and stays out of ci-mvp-gates (the
# hermetic onion half is mvp-onion-slice). This target runs the real timed
# bootstrap test (ZCL_TEST_ONLY=onion) but FIRST refuses the two fixture
# absences that make the real claim un-runnable: it SKIPs cleanly (exit 0)
# when the binary links the offline Tor stub (vendor/tor not built — the stub
# tor_run_main returns -1 immediately, which would otherwise false-FAIL after
# the 90s ceiling; `make tor-full` opts into the real embedded Tor), and SKIPs
# cleanly (exit 0) when Tor network egress is unavailable, so it never
# false-FAILs on a sandboxed host — same SKIP-not-FAIL discipline as
# test-shielded-payment. Locally-verified, network-gated; NOT a hermetic-✅
# gate.
.PHONY: mvp-onion-local
mvp-onion-local: test_zcl
	@bash -c 'set -uo pipefail; \
	 echo "══ MVP C2 (real): onion bootstrap <60s over Tor (egress-gated) ══"; \
	 if [ -z "$(TOR_FULL)" ]; then \
	     echo "mvp-onion-local: SKIP (binary links the offline Tor stub — vendor/tor not built; run make tor-full to enable the real embedded onion claim)"; \
	     exit 0; \
	 fi; \
	 reachable=0; \
	 for hp in moria1.torproject.org:9101 tor26.torproject.org:443 dizum.com:443; do \
	     h=$${hp%%:*}; p=$${hp##*:}; \
	     if timeout 5 bash -c "exec 3<>/dev/tcp/$$h/$$p" 2>/dev/null; then reachable=1; break; fi; \
	 done; \
	 if [ "$$reachable" != "1" ]; then \
	     echo "mvp-onion-local: SKIP (no Tor network egress detected — run on a host where Tor egress is allowed)"; \
	     exit 0; \
	 fi; \
	 echo "mvp-onion-local: Tor egress present — running the real timed onion bootstrap"; \
	 ZCL_STRESS_TESTS=1 ZCL_TEST_ONLY=onion $(TEST_ZCL_BIN)'

# ── mvp-coldstart-local (C3 real snapshot-first cold boot, fixture-gated) ─
#
# The FULL C3 claim (a fresh node cold-syncs to tip in <10min) needs a second
# serving node + real wall-clock and cannot be hermetic. The nearest REAL proof
# is the snapshot authority boot: cold_start_test.sh starts a fresh /tmp datadir
# from the local operator bundle (block_index.bin + utxo-seed-*.snapshot) and
# asserts >1M UTXOs are body-digest verified + seeded in <90s. It falls back to
# consensus_snapshot.db only for checkpoint-height fixtures. This wraps the
# underlying script directly for mvp-verify with the same SKIP-not-FAIL
# discipline as mvp-onion-local: cold_start_test.sh exits 2 when the fixture or
# binaries are absent, which we map to a clean SKIP (exit 0). Do not wrap this
# through `make ci-coldstart` here: GNU make returns 2 for a failed recipe,
# which would misclassify a real cold-start failure as "missing fixture".
# Locally-verified; NOT a hermetic-✅.
.PHONY: mvp-coldstart-local
mvp-coldstart-local: zclassic23 zcl-rpc
	@bash -c 'set -uo pipefail; \
	 echo "══ MVP C3 (real): snapshot-first cold boot >1M UTXOs <90s (fixture-gated) ══"; \
	 bash tools/scripts/cold_start_test.sh; rc=$$?; \
	 if [ "$$rc" -eq 2 ]; then \
	     echo "mvp-coldstart-local: SKIP (no operator bundle / consensus_snapshot.db / binaries — run on a host with the fixture)"; \
	     exit 0; \
	 fi; \
	 exit $$rc'

# ── mvp-coldstart-to-tip-local (C3 full fresh bundle -> at-tip proof) ─
#
# This is the LONG empirical C3 proof: a fresh /tmp datadir loads the secure
# operator bundle (block_index.bin + utxo-seed-*.snapshot), dials a serving
# zclassic23 peer, and must reach that peer's captured tip within the 10-minute
# MVP budget. It SKIPs only when the local bundle or serving peer is absent.
# Exit 3 is an honest C3 seam, not a fixture skip.
.PHONY: mvp-coldstart-to-tip-local
mvp-coldstart-to-tip-local: zclassic23 zcl-rpc
	@bash -c 'set -uo pipefail; \
	 echo "══ MVP C3 FULL (real): fresh operator bundle -> zclassic23 peer tip <10min ══"; \
	 bash tools/scripts/cold_start_to_tip_probe.sh; rc=$$?; \
	 if [ "$$rc" -eq 2 ]; then \
	     echo "mvp-coldstart-to-tip-local: SKIP (per the c3-probe SKIP line above — no usable bundle/snapshot fixture, serving peer, or binary for this build)"; \
	     exit 0; \
	 fi; \
	 exit $$rc'

# ── mvp-coldstart-to-tip-stopwatch (C3 the GENUINE wipe -> tip stopwatch) ─
#
# mvp-coldstart-to-tip-local above is an ASSISTED proof: it pre-seeds a local
# operator bundle (block_index.bin + utxo-seed-*.snapshot) into the fresh
# datadir before boot. This target is the harness FORWARD_PLAN.md §1 item 3
# calls the remaining C3 gap: a genuinely WIPED/empty datadir, no bundle, no
# snapshot flag, no import flag — just the target binary's own boot pipeline
# (today's compiled-in checkpoint-ROM authority fold; transparently the
# checkpoint/weld path once that lands, no harness change needed) dialing a
# real serving zclassic23 peer over P2P and folding forward. It gates on the
# actual MVP claim — H* (dumpstate reducer_frontier's "hstar", the reducer's
# provable authoritative tip) reaching "network_tip" (the best height any
# handshake-complete peer advertised) — never on "the FSM says at_tip", which
# is all the ~7s in-process stub (lib/test/src/test_cold_start_sync.c,
# already in ci-mvp-gates) proves. Prints a real WALL_CLOCK_SECONDS=<n> line
# on PASS — the published wipe-to-tip stopwatch number FORWARD_PLAN.md says
# does not exist yet.
#
# Binary-path argument: ZCL_BIN=/path/to/zclassic23 make
# mvp-coldstart-to-tip-stopwatch points the stopwatch at any built binary
# (e.g. an orchestrator's freshly-integrated candidate) without editing this
# file or the script. ZCL_PEER=HOST:PORT names the serving peer, and it is
# REQUIRED: there is deliberately no default. It used to default to
# 127.0.0.1:8033 — the canonical node's own P2P port — so a bare
# `make mvp-coldstart-to-tip-stopwatch` on an operator host quietly synced a
# full chain off the live node nobody had asked it to touch. With no peer
# stated the run SKIPs and says so. Point it at a stopwatch fixture peer
# (the zcl-stopwatch-peer unit listens on 127.0.0.1:39070), or name the
# canonical node explicitly if that is genuinely what you mean.
# Isolated /tmp datadir + non-live ports (39170-39173); dials the peer as a
# read-only P2P client only — never touches its datadir or systemd. SKIPs
# (exit 2 -> 0) when the binary is absent, no peer is stated, or the stated
# peer is unreachable; exit 3 (SEAM, real forward progress but budget expired)
# and exit 4 (STALLED-NAMED, a named blocker explains a stall) are both honest
# non-SKIP verdicts and propagate as a failing recipe, same discipline as
# mvp-coldstart-to-tip-local's exit 3.
#
# The recipe runs the harness's own hermetic --selftest first (no binary, no
# network, no datadir): it re-asserts the verdict-classification table AND the
# no-implicit-peer guardrail above, so the proof lane cannot quietly regain a
# default peer between runs.
#
# ZCL_FILE_PEER=HOST:PORT names the bundle/file-service peer and forwards to
# the harness's --file-peer (env ZCL_CS_FILE_PEER). It is OPTIONAL and has no
# default, on purpose — same no-implicit-peer discipline as ZCL_PEER. It is
# exposed here because this target previously had no way to state one, while
# the evidence collector tools/scripts/c3_stopwatch_run_and_record.sh DOES
# default ZCL_CS_FILE_PEER=127.0.0.1:39072. That asymmetry meant the
# documented `make mvp-coldstart-to-tip-stopwatch ZCL_PEER=…` command and the
# recorded C3 ledger were measuring two different lanes: with no
# -fileservice peer the node has no state source, reports the named blocker
# bootstrap.no_state_source (NO_STATE_SOURCE_FETCH_SKIPPED, "connect-only
# with no -fileservice peer"), and does a from-genesis IBD instead of the
# bundle-then-fold path the ledger's numbers came from. Measured here
# 2026-07-30: without it, H* pinned at 0 for the whole 600 s budget.
.PHONY: mvp-coldstart-to-tip-stopwatch
mvp-coldstart-to-tip-stopwatch: zclassic23
	@bash -c 'set -uo pipefail; \
	 echo "══ MVP C3 STOPWATCH (real): wiped datadir -> checkpoint/fold -> peer tip, real wall-clock ══"; \
	 if ! bash tools/scripts/cold_start_to_tip_stopwatch.sh --selftest >/dev/null 2>&1; then \
	     echo "mvp-coldstart-to-tip-stopwatch: FAIL harness --selftest (run it directly to see which check broke)"; \
	     exit 1; \
	 fi; \
	 if ! bash tools/scripts/stopwatch_artifact_symmetry_check.sh --selftest >/dev/null 2>&1; then \
	     echo "mvp-coldstart-to-tip-stopwatch: FAIL artifact-symmetry --selftest (run tools/scripts/stopwatch_artifact_symmetry_check.sh --selftest to see which mutation stopped going red)"; \
	     exit 1; \
	 fi; \
	 bash tools/scripts/cold_start_to_tip_stopwatch.sh \
	     $(if $(ZCL_BIN),--bin=$(ZCL_BIN),) $(if $(ZCL_PEER),--peer=$(ZCL_PEER),) \
	     $(if $(ZCL_FILE_PEER),--file-peer=$(ZCL_FILE_PEER),); rc=$$?; \
	 if [ "$$rc" -eq 2 ]; then \
	     echo "mvp-coldstart-to-tip-stopwatch: SKIP (binary absent / no serving peer stated or reachable — set ZCL_PEER=HOST:PORT and run on a host with a synced zclassic23 peer)"; \
	     exit 0; \
	 fi; \
	 exit $$rc'

# ── mvp-coldstart-to-tip-triple (the stopwatch, N TIMES, HASH-CONFIRMED) ────
#
# mvp-coldstart-to-tip-stopwatch above times ONE genuinely-wiped run and gates
# on H* reaching network_tip. Two things that leaves open, and this target
# closes exactly those two without re-measuring anything:
#
#   1. network_tip is a HEIGHT the peer advertised. "H* == network_tip" says the
#      client counted to the same number as the peer, not that both mean the
#      same chain by it. This target reads the peer's own `core chain tip`
#      (height AND hash) at both ends of every run and polls the CLIENT's tip
#      while it runs, so the verdict can state hash agreement at equal height —
#      or say plainly that it could not read one side. The client's scratch
#      datadir is deleted on the way out, so the client hash must be sampled
#      DURING the run; there is no way to recover it afterwards.
#
#   2. One run is an anecdote. The 600s bar is a claim about the general case,
#      so the smallest honest form of it is N wiped runs back to back with the
#      peer's tip recorded around each.
#
# ZCL_PEER=HOST:PORT is REQUIRED, same discipline and same reason as the
# single-run target: with nothing stated the run SKIPs and names the variable.
# ZCL_RUNS (default 3), ZCL_BIN, ZCL_FILE_PEER (see the single-run target above
# for why it exists and what its absence measures instead), and
# ZCL_BUDGET_SECS pass through. Read-only
# toward the peer (its own RPC port; never its datadir or its systemd unit) and
# fully isolated on the client side, because the client side IS the single-run
# harness. Exit 1 means at least one run missed the bar or could not be
# hash-confirmed; the printed table names which run and why.
ZCL_RUNS ?= 3
.PHONY: mvp-coldstart-to-tip-triple
mvp-coldstart-to-tip-triple: zclassic23
	@bash -c 'set -uo pipefail; \
	 echo "══ MVP C3 STOPWATCH x$(ZCL_RUNS) (real): wiped -> peer tip, hash-confirmed, per run ══"; \
	 if ! bash tools/scripts/c3_stopwatch_triple_run.sh --selftest >/dev/null 2>&1; then \
	     echo "mvp-coldstart-to-tip-triple: FAIL driver --selftest (run tools/scripts/c3_stopwatch_triple_run.sh --selftest to see which check broke)"; \
	     exit 1; \
	 fi; \
	 bash tools/scripts/c3_stopwatch_triple_run.sh --runs=$(ZCL_RUNS) \
	     $(if $(ZCL_BIN),--bin=$(ZCL_BIN),) $(if $(ZCL_PEER),--peer=$(ZCL_PEER),) \
	     $(if $(ZCL_FILE_PEER),--file-peer=$(ZCL_FILE_PEER),) \
	     $(if $(ZCL_BUDGET_SECS),--budget=$(ZCL_BUDGET_SECS),); rc=$$?; \
	 if [ "$$rc" -eq 2 ]; then \
	     echo "mvp-coldstart-to-tip-triple: SKIP (binary absent / no serving peer stated or reachable — set ZCL_PEER=HOST:PORT and run on a host with a synced zclassic23 peer)"; \
	     exit 0; \
	 fi; \
	 exit $$rc'

# ── mvp-coldstart-to-tip-remote (the SAME C3 stopwatch, REMOTE peer) ────────
#
# Identical harness to mvp-coldstart-to-tip-stopwatch above, with the peer
# PINNED to a remote serving zclassic23 node instead of the loopback default
# (127.0.0.1:8033). This is not a convenience alias. Every other sync proof in
# this repo dials a peer on the SAME machine, and loopback is structurally
# privileged on both sides of the wire:
#   - client side: lib/net/src/net.c is_trusted_peer() exempts 127.0.0.0/8 and
#     -whitelist peers from peer_misbehaving(), so a loopback run can never
#     exercise the score-to-ban path a real remote client rides;
#   - server side: the per-IP inbound sybil cap ("too many inbound connections
#     from same IP", max 3) is only ever contended when several clients share
#     one source IP — which is exactly the remote case, and never the
#     one-node-per-loopback case.
# Pinning the invocation keeps the remote run repeatable instead of folklore.
#
# ZCL_REMOTE_PEER=HOST:PORT is REQUIRED (no default): fleet endpoints are
# operator-local and are not committed to the public source. ZCL_BIN /
# ZCL_BUDGET_SECS / ZCL_SAMPLE_SECS pass through. Same isolation as the
# sibling target (fresh /tmp datadir, isolated $$HOME, ports 39170-39173,
# -listen=0, -nolegacyimport, no bundle/snapshot/import flags) and the same
# read-only posture: it dials the remote as a P2P CLIENT only and never
# writes to the peer's datadir or its systemd. Same SKIP discipline: exit 2
# -> 0 when the binary is absent or the remote peer is unreachable. Exits 3
# (SEAM), 4 (STALLED-NAMED), 5 (FRONTIER-BUSY-TIMEOUT) and 6
# (READBACK-FAILED) are honest verdicts and propagate as a failing recipe —
# a remote peer that refuses the handshake is NOT laundered into a SKIP, it
# is labelled peer_precheck=accept_close in the artifact and the run reports
# what the node actually earned.
.PHONY: mvp-coldstart-to-tip-remote
mvp-coldstart-to-tip-remote: zclassic23
	@if [ -z "$(ZCL_REMOTE_PEER)" ]; then \
	 echo "mvp-coldstart-to-tip-remote: set ZCL_REMOTE_PEER=<host:port> locally; fleet endpoints are operator-local and not committed"; \
	 exit 1; \
	fi
	@bash -c 'set -uo pipefail; \
	 echo "══ MVP C3 STOPWATCH (REMOTE peer $(ZCL_REMOTE_PEER)): wiped datadir -> fold -> peer tip, real wall-clock ══"; \
	 bash tools/scripts/cold_start_to_tip_stopwatch.sh \
	     --peer=$(ZCL_REMOTE_PEER) \
	     $(if $(ZCL_BIN),--bin=$(ZCL_BIN),) \
	     $(if $(ZCL_BUDGET_SECS),--budget=$(ZCL_BUDGET_SECS),) \
	     $(if $(ZCL_SAMPLE_SECS),--sample=$(ZCL_SAMPLE_SECS),); rc=$$?; \
	 if [ "$$rc" -eq 2 ]; then \
	     echo "mvp-coldstart-to-tip-remote: SKIP (binary absent / remote peer $(ZCL_REMOTE_PEER) unreachable)"; \
	     exit 0; \
	 fi; \
	 exit $$rc'

# ── mvp-netdisrupt-recovery-stopwatch (PROOF B: network-disruption recovery) ─
#
# The sibling wall-clock gate to mvp-coldstart-to-tip-stopwatch above, but
# for RECOVERY instead of first sync: an already-at-tip client node survives
# an upstream peer outage (SIGSTOP the peer, sleep, SIGCONT it) and the
# harness times how long the client's H* takes to re-catch network_tip.
# Gates on the same real claim — `dumpstate reducer_frontier`'s "hstar"
# reaching "network_tip" — never "the FSM says at_tip".
#
# This target does NOT spawn either node: point it at an already-running,
# already-synced client (ZCL_ND_CLIENT_RPCPORT/ZCL_ND_CLIENT_DATADIR) and a
# controllable upstream peer process (ZCL_ND_UPSTREAM_PID_FILE or a bare
# ZCL_ND_UPSTREAM_PID). SKIPs (exit 2 -> 0) when any fixture is absent or the
# client is not already at tip before the cut starts — same SKIP-mapping
# discipline as mvp-coldstart-to-tip-stopwatch above. Exit 3 (SEAM) and exit
# 4 (STALLED-NAMED) are both honest non-SKIP verdicts and propagate as a
# failing recipe.
.PHONY: mvp-netdisrupt-recovery-stopwatch
mvp-netdisrupt-recovery-stopwatch: zclassic23
	@bash -c 'set -uo pipefail; \
	 echo "══ PROOF B STOPWATCH (real): upstream SIGSTOP -> SIGCONT -> client H* re-catches network_tip, real wall-clock ══"; \
	 ZCL_ND_UPSTREAM_PID="$(ZCL_ND_UPSTREAM_PID)" \
	 bash tools/scripts/network_disruption_recovery_stopwatch.sh \
	     $(if $(ZCL_ND_NODE_BIN),--bin=$(ZCL_ND_NODE_BIN),) \
	     $(if $(ZCL_ND_UPSTREAM_PID_FILE),--upstream-pid-file=$(ZCL_ND_UPSTREAM_PID_FILE),) \
	     $(if $(ZCL_ND_CLIENT_RPCPORT),--client-rpc=$(ZCL_ND_CLIENT_RPCPORT),) \
	     $(if $(ZCL_ND_CLIENT_DATADIR),--client-datadir=$(ZCL_ND_CLIENT_DATADIR),) \
	     $(if $(ZCL_ND_CUT_SECS),--cut-secs=$(ZCL_ND_CUT_SECS),) \
	     $(if $(ZCL_ND_BUDGET_SECS),--budget=$(ZCL_ND_BUDGET_SECS),); rc=$$?; \
	 if [ "$$rc" -eq 2 ]; then \
	     echo "mvp-netdisrupt-recovery-stopwatch: SKIP (fixture absent — client not at tip / client RPC unreachable / upstream pid not a live process / binary absent — run against a live already-at-tip client + a controllable upstream peer)"; \
	     exit 0; \
	 fi; \
	 exit $$rc'

# ── mvp-verify: ONE-COMMAND local verification of the real MVP claims ──
#
# The operator's local counterpart to the hermetic `make ci` gate. It runs the
# full-scope MVP proofs that CANNOT join hermetic `make ci` because each spawns
# a real isolated /tmp regtest node (C1/C7) or needs Tor network egress (C2).
# They are DELIBERATELY out of `make ci` — see the per-target notes and the
# ci-install no-node invariant. It runs ALL members and reports each (a FAIL
# does not stop the run), then exits non-zero if any member failed — an HONEST
# local diagnostic, not a rubber stamp.
#
# Live status (2026-06-17): the full-binary C7 harnesses now PASS end-to-end.
# generate-RPC forward progress is FIXED (f83101b81 — a fresh on-demand node
# self-seeds the genesis anchor) so test-two-node-peer-tip passes; AND the
# single-node restart-durability keystone landed (341020c05 — a kill-9'd fresh
# node restores its durable finalized tip via a forward-only genesis-root seed
# instead of stranding at h=-1), so test-crash-bootstrap now PASSES with
# height_regress: 0. Both still spawn real nodes, so they stay OUT of the
# hermetic `make ci` target (◐, not ✅). See MVP.md #7.
#
# Membership (all already exist; mvp-verify only composes them):
#   ci-install             C1 — install both binaries to a throwaway /tmp
#                               prefix + spawn one isolated regtest node
#   ci-install-linger      C1 — FULL claim: real make install + systemctl
#                               --user start of an isolated linger unit (no docker)
#   test-crash-bootstrap   C7 — single-node full-binary kill-9 boot recovery
#   test-two-node-peer-tip C7 — two-node native-P2P peer-tip kill-9 recovery
#   mvp-coldstart-to-tip-local
#                            C3 — FULL real bundle cold boot + zclassic23
#                               peer delta sync to tip (<10min, fixture/peer
#                               gated, SKIPs cleanly when absent)
#   mvp-shielded-receive   C4 — params-free receive half (note→ivk→z-balance)
#   test-shielded-payment  C4 — FULL Groth16 t→z send + wallet decrypt
#                               (params-gated, SKIPs cleanly without params)
#   mvp-onion-local        C2 — real <60s onion bootstrap (Tor-egress-gated,
#                               SKIPs cleanly when egress is unavailable)
#
# DOC-HONESTY (revised 2026-06-17): under the local-only-CI / never-docker MVP
# rule (docs/MVP.md), a criterion is ✅ when its FULL operator claim RUN-PASSES
# (not SKIPs, not a slice) via the relevant member here — `make mvp-verify` IS
# the local operator proof. A member that SKIPs for a missing local dependency
# (params / Tor egress / fixture) keeps its criterion ◐ until it run-passes.
.PHONY: mvp-verify
mvp-verify: zclassic23 zcl-rpc test_zcl
	@bash -c 'set -uo pipefail; \
	 echo "══════════════════════════════════════════════════════════════"; \
	 echo "  mvp-verify: LOCAL full-scope MVP proofs (NOT hermetic ✅)"; \
	 echo "  These spawn real /tmp regtest nodes / need Tor egress — they"; \
	 echo "  stay OUT of hermetic make ci. Locally-verified only."; \
	 echo "  Runs ALL members + reports each; a FAIL does not stop the run."; \
	 echo "══════════════════════════════════════════════════════════════"; \
	 declare -A NAME=( \
	   [1]="C1 install mechanism (ci-install)" \
	   [2]="C1 FULL: make install + systemctl --user start (ci-install-linger)" \
	   [3]="C7 single-node kill-9 boot recovery (test-crash-bootstrap)" \
	   [4]="C7 two-node peer-tip kill-9 recovery (test-two-node-peer-tip)" \
	   [5]="C4 shielded receive, params-free (mvp-shielded-receive)" \
	   [6]="C4 full shielded send+receive, params-gated (test-shielded-payment)" \
	   [7]="C3 FULL cold boot to peer tip, fixture/peer-gated (mvp-coldstart-to-tip-local)" \
	   [8]="C2 real onion bootstrap, Tor-egress-gated (mvp-onion-local)" ); \
	 declare -A TGT=( [1]=ci-install [2]=ci-install-linger \
	   [3]=test-crash-bootstrap [4]=test-two-node-peer-tip \
	   [5]=mvp-shielded-receive [6]=test-shielded-payment \
	   [7]=mvp-coldstart-to-tip-local [8]=mvp-onion-local ); \
	 declare -A ST; fails=0; \
	 for i in 1 2 3 4 5 6 7 8; do \
	   echo ""; echo "── mvp-verify [$$i/8]: $${NAME[$$i]} ──"; \
	   if $(MAKE) $${TGT[$$i]}; then ST[$$i]="PASS"; else ST[$$i]="FAIL"; fails=$$((fails+1)); fi; \
	 done; \
	 echo ""; echo "══ mvp-verify SUMMARY (local operator proof — ✅ = run-passes) ══"; \
	 for i in 1 2 3 4 5 6 7 8; do printf "  [%s] %-68s %s\n" "$$i" "$${NAME[$$i]}" "$${ST[$$i]}"; done; \
	 echo ""; \
	 if [ "$$fails" -eq 0 ]; then \
	   echo "  ALL LOCAL FULL-SCOPE PROOFS PASSED (or SKIPped cleanly)."; \
	 else \
	   echo "  $$fails member(s) FAILED. The C7 full-binary harnesses now PASS"; \
	   echo "  (test-crash-bootstrap height_regress:0 via keystone 341020c05;"; \
	   echo "  test-two-node-peer-tip via f83101b81), so a FAIL here usually means"; \
	   echo "  a missing local dependency (params/Tor egress/snapshot fixture) —"; \
	   echo "  check the per-member SKIP line above. See MVP.md #7."; \
	 fi; \
	 exit $$fails'

# ── mvp: the HONEST MVP 8/8 scoreboard ────────────────────────
#
# AGENTS.md P1 priority — CI-enforce the MVP criteria. `make mvp` is the
# single per-criterion reporter: for each of the 8 docs/MVP.md acceptance
# criteria it runs the ONE mechanically-runnable check that proves it (a
# hermetic test_zcl slice, the symbol-floor gate, the soak-evidence judge,
# or a live-node probe) and prints a verdict line PASS / FAIL / BLOCKED(reason).
#
# THE CONTRACT (cannot false-green): PASS is earned ONLY when the criterion's
# check actually RAN and PASSED at the full operator-claim level. The three
# SYNCED-NODE-dependent criteria — C3 (cold-start to tip), C6 (168h soak),
# C8 (parity over the soak window) — CANNOT pass while the live node is
# stopped/wedged below tip, so they report BLOCKED(needs synced node) — never
# silently skipped-as-pass, never green. A criterion whose full claim needs
# Tor egress / ~/.zcash-params / a live oracle reports BLOCKED(reason) when
# that resource is absent. A hermetic slice that regresses prints FAIL.
#
# It needs test_zcl (the slice gates) + the node/RPC binaries (symbol-floor +
# the live probe). It is a STATUS REPORTER, not a build gate: it exits 0 even
# with BLOCKED criteria (the honest state of a stopped node), so it can be a
# VISIBLE report inside `make ci` without breaking the build. Real
# hermetic-slice FAILs are printed loudly in the summary.
.PHONY: mvp
mvp: test_zcl zclassic23 zcl-rpc
	@TEST_ZCL_BIN=$(TEST_ZCL_BIN) ZCL_RPC_BIN=$(ZCL_RPC_BIN) bash tools/scripts/mvp_scoreboard.sh

# ── libFuzzer harnesses ───────────────────────────────────────
#
# Fuzz targets use clang + libFuzzer + ASan + UBSan. They compile
# the same ALL_SRCS as the main build (minus src/main.c), so the same
# code paths the node exercises are the code paths the fuzzer
# exercises. -O1 + -g because aggressive optimisation confuses
# sanitizer reports.
#
# `make fuzz` builds every listed binary. `make fuzz-ci` runs each
# for 60 seconds as a smoke test; CI uses this to detect already-
# latent crashes without chasing exhaustive coverage. Fuzz CI must
# never false-green without the toolchain: install clang/libFuzzer or
# opt out explicitly with `make ci SKIP_FUZZ=1`.
#
# -artifact_prefix is not optional. Without it libFuzzer writes a repro unit
# to CWD, which for these rules is the repository root: a run that found
# anything dropped a bare `timeout-<sha1>` file into the tree, where
# check-no-stray-root-files then failed on it and nothing routed the finding
# anywhere. Both loops point it at the per-target /tmp work dir they already
# create and delete.
FUZZ_CC ?= clang
FUZZ_CFLAGS = -std=c23 -O1 -g -Wall -Wextra \
	-Wno-deprecated-declarations \
	$(APP_INCLUDES) $(CONFIG_INCLUDES) $(LIB_INCLUDES) $(CORE_INCLUDES) \
	$(PORTS_INCLUDES) $(DOMAIN_INCLUDES) $(APPLICATION_INCLUDES) \
	$(ADAPTERS_INCLUDES) $(TOOLS_INCLUDES) $(DEVLOOP_INCLUDES) \
	-Ilib/test/include -Ivendor/x11/include \
	-D_POSIX_C_SOURCE=200809L -D_DEFAULT_SOURCE \
	-DZCL_FUZZ_QUIET_LOG_MACROS -Ivendor/include \
	-fsanitize=fuzzer,address,undefined \
	-fno-sanitize=alignment
FUZZ_LIBS = $(TOR_LIBS) $(LIBS)

FUZZ_TARGETS = $(BIN_DIR)/fuzz_block $(BIN_DIR)/fuzz_script $(BIN_DIR)/fuzz_p2p $(BIN_DIR)/fuzz_http $(BIN_DIR)/fuzz_compactblock $(BIN_DIR)/fuzz_snapshot $(BIN_DIR)/fuzz_tx_bundle $(BIN_DIR)/fuzz_rom_manifest $(BIN_DIR)/fuzz_overlay $(BIN_DIR)/fuzz_ecdsa $(BIN_DIR)/fuzz_zcode_commons $(BIN_DIR)/fuzz_zcode_dht $(BIN_DIR)/fuzz_zcode_science
# Keep the line above literal and keep one `$(BIN_DIR)/fuzz_<kind>:` rule per
# harness below: check_fuzz_artifact_replay.sh derives the corpus<->binary map
# from those rule lines, and background_quality_lane.sh derives its kind list
# from this variable's text. Both are deliberate "a new harness is covered the
# day its rule lands" scrapes; a `$(patsubst ...)` spelling blinds them.
FUZZ_TARGET_NAMES = $(notdir $(FUZZ_TARGETS))
FUZZ_CI_TIME ?= 60
FUZZ_CI_WALL_TIME ?= 120

# Per-TU object tree with -MD -MP depfiles — the same header-invalidation
# mechanism every other profile in this Makefile uses (see the -include block
# under ZCL_DEPFILE_PROFILES near the top).
#
# Before this, each harness was ONE whole-program clang whose prerequisites
# were `tools/fuzz/<name>.c $(TMPL_GEN) $(ALL_SRCS)` — sources only, no
# headers. A header-only fix therefore changed no listed prerequisite and
# `make fuzz` was a no-op, so every fuzz gate kept running the binary from
# before the fix. That is not hypothetical: on 2026-07-29 `make fuzz-replay`
# reported 14 live script hangs against a build/bin/fuzz_script dated July 10
# — nineteen days and one header-only fix (b8e6b35dc, script.h) stale. A
# hand-written header list would rot the same way; the depfiles record the
# real include closure the compiler actually opened.
#
# The harnesses share ONE object tree, so this also retires the per-target
# redundant compile of $(ALL_SRCS) the old rules paid on every edit.
FUZZ_OBJ_DIR = $(BUILD_DIR)/fuzz-obj
FUZZ_HARNESS_SRCS = $(patsubst %,tools/fuzz/%.c,$(FUZZ_TARGET_NAMES))
FUZZ_OBJS = $(patsubst %.c,$(FUZZ_OBJ_DIR)/%.o,$(ALL_SRCS))
FUZZ_HARNESS_OBJS = $(patsubst %.c,$(FUZZ_OBJ_DIR)/%.o,$(FUZZ_HARNESS_SRCS))
ifneq ($(filter fuzz,$(ZCL_DEPFILE_PROFILES)),)
-include $(FUZZ_OBJS:.o=.d) $(FUZZ_HARNESS_OBJS:.o=.d)
endif
# How much fuzzing each 60-second slot actually buys, and the floor under it.
#
# FUZZ_CI_PRINT_FUNCS turns off libFuzzer's NEW_FUNC log lines. Those lines are
# symbolized, and symbolizing against an 82 MB -g whole-program binary means
# spawning llvm-symbolizer and blocking in poll() for hundreds of milliseconds
# per line. Measured 2026-07-29 on this tree, same 60 s slot, nothing else
# changed: fuzz_block 25 -> 697,333 executions, fuzz_p2p 11 -> 595,993,
# fuzz_script 83 -> 359,075. Coverage collection, corpus growth and crash
# reporting are all unaffected — a crash still prints a symbolized file:line
# stack trace. Set FUZZ_CI_PRINT_FUNCS=2 for one run if you want the lines.
#
# FUZZ_CI_MIN_EXEC_PER_SEC is the under-covered floor the runner enforces after
# the loop, and the reason the runner prints a rate table at all: a green run
# that names its own weak harnesses is worth more than a green run that does
# not. Measured on this tree 2026-07-29, all then-current harnesses landed between
# 5,202/s (fuzz_script, the slowest) and 40,826/s (fuzz_overlay). The floor is
# set at a fifth of the slowest — low enough that a loaded box cannot flake it,
# three to four orders of magnitude above the collapse it exists to catch (the
# five harnesses this fixed were running at 0.1 to 1.5 executions per second).
# It is a collapse detector, not a regression detector: the printed rate is
# what a reader uses to spot a harness that merely got slower. Raising the
# floor is fine; lowering it to make a slow harness pass is the one move that
# is not — the number has to rise because the harness got faster.
FUZZ_CI_PRINT_FUNCS ?= 0
FUZZ_CI_MIN_EXEC_PER_SEC ?= 1000

.PHONY: check-fuzz-toolchain check-fuzz-ci-tools fuzz fuzz-ci
check-fuzz-toolchain:
	@if ! command -v $(FUZZ_CC) >/dev/null 2>&1; then \
		echo "fuzz-ci: ERROR: $(FUZZ_CC) not found (install clang/libFuzzer or run make ci SKIP_FUZZ=1)"; \
		exit 2; \
	fi

check-fuzz-ci-tools: check-fuzz-toolchain
	@if ! command -v timeout >/dev/null 2>&1; then \
		echo "fuzz-ci: ERROR: timeout not found (install coreutils or run make ci SKIP_FUZZ=1)"; \
		exit 2; \
	fi

fuzz: check-fuzz-toolchain $(FUZZ_TARGETS)

.PHONY: fuzz_block fuzz_script fuzz_p2p fuzz_http fuzz_compactblock fuzz_snapshot fuzz_tx_bundle fuzz_rom_manifest fuzz_overlay fuzz_ecdsa fuzz_zcode_commons fuzz_zcode_dht fuzz_zcode_science
fuzz_ecdsa: $(BIN_DIR)/fuzz_ecdsa
fuzz_zcode_commons: $(BIN_DIR)/fuzz_zcode_commons
fuzz_zcode_dht: $(BIN_DIR)/fuzz_zcode_dht
fuzz_zcode_science: $(BIN_DIR)/fuzz_zcode_science
fuzz_block: $(BIN_DIR)/fuzz_block
fuzz_script: $(BIN_DIR)/fuzz_script
fuzz_p2p: $(BIN_DIR)/fuzz_p2p
fuzz_http: $(BIN_DIR)/fuzz_http
fuzz_compactblock: $(BIN_DIR)/fuzz_compactblock
fuzz_snapshot: $(BIN_DIR)/fuzz_snapshot
fuzz_tx_bundle: $(BIN_DIR)/fuzz_tx_bundle
fuzz_rom_manifest: $(BIN_DIR)/fuzz_rom_manifest
fuzz_overlay: $(BIN_DIR)/fuzz_overlay

# One object per TU, shared by every harness. -MD -MP writes the
# per-object depfile imported above; that is what makes a header edit
# invalidate exactly the objects that read it.
$(FUZZ_OBJ_DIR)/%.o: %.c $(TMPL_GEN) $(VIEW_GEN_HEADERS) | check-fuzz-toolchain
	@mkdir -p $(dir $@)
	@$(FUZZ_CC) $(FUZZ_CFLAGS) -MD -MP -c -o $@ $<

# Shared link step. $< is the harness object; $(FUZZ_OBJS) is the node tree.
define FUZZ_LINK
	@mkdir -p $(dir $@)
	@echo "$(FUZZ_CC) ... -o $@"
	@$(FUZZ_CC) $(FUZZ_CFLAGS) -o $@ $< $(FUZZ_OBJS) $(FUZZ_LIBS)
endef

$(BIN_DIR)/fuzz_block: $(FUZZ_OBJ_DIR)/tools/fuzz/fuzz_block.o $(FUZZ_OBJS) | check-fuzz-toolchain
	$(FUZZ_LINK)

$(BIN_DIR)/fuzz_script: $(FUZZ_OBJ_DIR)/tools/fuzz/fuzz_script.o $(FUZZ_OBJS) | check-fuzz-toolchain
	$(FUZZ_LINK)

$(BIN_DIR)/fuzz_p2p: $(FUZZ_OBJ_DIR)/tools/fuzz/fuzz_p2p.o $(FUZZ_OBJS) | check-fuzz-toolchain
	$(FUZZ_LINK)

$(BIN_DIR)/fuzz_http: $(FUZZ_OBJ_DIR)/tools/fuzz/fuzz_http.o $(FUZZ_OBJS) | check-fuzz-toolchain
	$(FUZZ_LINK)

$(BIN_DIR)/fuzz_compactblock: $(FUZZ_OBJ_DIR)/tools/fuzz/fuzz_compactblock.o $(FUZZ_OBJS) | check-fuzz-toolchain
	$(FUZZ_LINK)

$(BIN_DIR)/fuzz_snapshot: $(FUZZ_OBJ_DIR)/tools/fuzz/fuzz_snapshot.o $(FUZZ_OBJS) | check-fuzz-toolchain
	$(FUZZ_LINK)

$(BIN_DIR)/fuzz_tx_bundle: $(FUZZ_OBJ_DIR)/tools/fuzz/fuzz_tx_bundle.o $(FUZZ_OBJS) | check-fuzz-toolchain
	$(FUZZ_LINK)

$(BIN_DIR)/fuzz_rom_manifest: $(FUZZ_OBJ_DIR)/tools/fuzz/fuzz_rom_manifest.o $(FUZZ_OBJS) | check-fuzz-toolchain
	$(FUZZ_LINK)

$(BIN_DIR)/fuzz_overlay: $(FUZZ_OBJ_DIR)/tools/fuzz/fuzz_overlay.o $(FUZZ_OBJS) | check-fuzz-toolchain
	$(FUZZ_LINK)

$(BIN_DIR)/fuzz_ecdsa: $(FUZZ_OBJ_DIR)/tools/fuzz/fuzz_ecdsa.o $(FUZZ_OBJS) | check-fuzz-toolchain
	$(FUZZ_LINK)

$(BIN_DIR)/fuzz_zcode_commons: $(FUZZ_OBJ_DIR)/tools/fuzz/fuzz_zcode_commons.o $(FUZZ_OBJS) | check-fuzz-toolchain
	$(FUZZ_LINK)

$(BIN_DIR)/fuzz_zcode_dht: $(FUZZ_OBJ_DIR)/tools/fuzz/fuzz_zcode_dht.o $(FUZZ_OBJS) | check-fuzz-toolchain
	$(FUZZ_LINK)

$(BIN_DIR)/fuzz_zcode_science: $(FUZZ_OBJ_DIR)/tools/fuzz/fuzz_zcode_science.o $(FUZZ_OBJS) | check-fuzz-toolchain
	$(FUZZ_LINK)

fuzz-ci: check-fuzz-ci-tools $(FUZZ_TARGETS)
	@./tools/fuzz/run_fuzz_ci.sh $(FUZZ_CI_TIME) $(FUZZ_CI_WALL_TIME) \
		$(FUZZ_CI_MIN_EXEC_PER_SEC) $(FUZZ_CI_PRINT_FUNCS) 0 $(FUZZ_TARGETS)

# Replay every SAVED finding and fail on any that still reproduces.
#
# fuzz-ci above already executes the checked-in corpus (libFuzzer runs the seed
# dir before it mutates), and it has been red since 2026-07-14 over a five-byte
# script that hangs the node forever. Nobody saw it, because fuzz-ci is
# reachable only from `make ci` — which no hook, timer or workflow runs — and
# because a libFuzzer corpus run stops at the first bad unit and tells you
# nothing about the other 72. This target is the verdict route that was missing:
# it replays each artifact-prefixed seed individually against a written verdict
# in lib/test/fuzz_seeds/ARTIFACT_VERDICTS.txt and names every disagreement.
#
# Why it is not part of `make lint`: measured on the dev reference host, the
# replay itself is 18.3 s for 22 artifacts at -P6, and it needs the large
# sanitizer-instrumented binaries built first. That build was 5 min 45 s at -j6
# — one whole-program clang per binary over ~1300 TUs, nine times over, with no
# per-TU object cache — until the shared $(FUZZ_OBJ_DIR) tree above; it is now
# 34 s cold and 21 s after a header edit (607 of 1295 objects recompile).
# `make lint` still runs the cheap half instead (check-fuzz-artifact-ledger,
# 21 ms: every artifact has a live binary and a recorded verdict, no orphans).
#
# --selftest first, always: it plants an untriaged artifact and asserts the gate
# still trips AND still names the file, so a "0 violations" line below can never
# be a gate that has quietly stopped being able to fail.
.PHONY: fuzz-replay
fuzz-replay: check-fuzz-ci-tools $(FUZZ_TARGETS)
	@echo "══ FUZZ-REPLAY: every saved finding, replayed against its verdict ══"
	@./tools/lint/check_fuzz_artifact_replay.sh --selftest
	@./tools/lint/check_fuzz_artifact_replay.sh

# Same binaries with leak detection ON. Separate target so CI stays
# green while known-pre-existing leaks are being triaged; developers
# and Wave 4+ commits that fix leaks opt into this stricter run.
fuzz-ci-leaks: check-fuzz-ci-tools $(FUZZ_TARGETS)
	@./tools/fuzz/run_fuzz_ci.sh $(FUZZ_CI_TIME) $(FUZZ_CI_WALL_TIME) \
		$(FUZZ_CI_MIN_EXEC_PER_SEC) $(FUZZ_CI_PRINT_FUNCS) 1 $(FUZZ_TARGETS)

# ── P11.6 — 7-day soak runner ─────────────────────────────────
#
# Separate binary that polls a running zclassic23 every 60 s
# against the analyzer in lib/test/src/soak_harness.c. Verdict
# failure (crash / tip-stall / RSS-walk / too-short / no-samples)
# causes exit non-zero, so systemd / CI can gate on a 7-day run
# without the operator having to read the log.
#
# `make soak-7day`   runs the full 604800 s gate against the
#                    installed zclassic23 (MVP criterion #6).
# `make soak-smoke`  runs a 5-minute smoke test of the same
#                    binary so the runner itself doesn't rot
#                    between 7-day gates — safe to hook into
#                    CI on a machine that has the node up.
#
# Neither target is wired into the default `ci` pipeline: 7 days
# is obviously out of band, and the smoke target needs a live
# node on the same host, which most CI workers don't provide.
.PHONY: soak_runner
soak_runner: $(SOAK_RUNNER_BIN)
$(SOAK_RUNNER_BIN): tools/soak/main.c lib/test/src/soak_harness.c \
                        lib/platform/src/clock.c \
                        lib/test/include/test/soak_harness.h
	@mkdir -p $(dir $@)
	$(CC) -std=c23 -O2 -Wall -Wextra -Werror -pedantic \
	    -D_POSIX_C_SOURCE=200809L \
	    -Ilib/test/include -Ilib/platform/include -Ilib/base/include -Ilib/util/include -o $@ \
	    tools/soak/main.c lib/test/src/soak_harness.c lib/platform/src/clock.c

soak-7day: soak_runner zcl-rpc
	$(SOAK_RUNNER_BIN) \
	    --duration-sec=604800 \
	    --interval-sec=60 \
	    --service=zclassic23 \
	    --rpc=$(ZCL_RPC_BIN)

soak-smoke: soak_runner zcl-rpc
	$(SOAK_RUNNER_BIN) \
	    --duration-sec=300 \
	    --interval-sec=30 \
	    --service=zclassic23 \
	    --rpc=$(ZCL_RPC_BIN) \
	    --stall-sec=600 \
	    --warmup-sec=60

.PHONY: bench-sync
bench-sync: zclassic23 bench_fresh_sync
	$(BIN_DIR)/bench_fresh_sync

.PHONY: bench_fresh_sync
bench_fresh_sync: $(BIN_DIR)/bench_fresh_sync
$(BIN_DIR)/bench_fresh_sync: tools/bench_fresh_sync.c \
		lib/platform/src/clock.c lib/base/src/log_level.c
	@mkdir -p $(dir $@)
	$(CC) -O2 -Ilib/platform/include -Ilib/base/include -Ilib/util/include \
	    -D_DEFAULT_SOURCE -o $@ $^

# Per-ISA-tier crypto microbenchmark (tools/simd_bench.c). Drives the SAME
# input through EVERY ISA tier of each primitive (generic / SHA-NI / AVX2 /
# AVX-512 / BMI2), asserts every tier is BIT-IDENTICAL to the generic one, and
# only then reports median + p90 ns/op pinned to one core, with the CCD named.
#
# Built at the SHIPPED CFLAGS on purpose (-O3 -march=x86-64-v3, no LTO): the
# whole question it answers is "does the accelerated path beat what the
# compiler already emits for the generic path at the flags we actually ship",
# so building it at anything else would answer a question nobody asked.
# Exits 2 if any tier diverges — a faster path returning different bytes is a
# chain split, not a win.
SIMD_BENCH_SRCS = tools/simd_bench.c \
	lib/crypto/src/sha256.c lib/sha3/src/sha3.c lib/crypto/src/keccak_x4.c lib/crypto/src/simd_dispatch.c \
	lib/crypto/src/sha3_avx512.c lib/crypto/src/sha3_256_x4.c \
	lib/crypto/src/blake2b.c lib/crypto/src/blake2b_avx2.c \
	lib/sapling/src/bn254_accel.c lib/sapling/src/fr_avx512.c \
	lib/base/src/cleanse.c lib/base/src/log_level.c

.PHONY: simd_bench
simd_bench: $(BIN_DIR)/simd_bench
$(BIN_DIR)/simd_bench: $(SIMD_BENCH_SRCS)
	@mkdir -p $(dir $@)
	$(CC) -std=c23 -O3 $(if $(ZCL_NATIVE),-march=native,-march=x86-64-v3) \
	    -Wall -Wextra -Werror -pedantic \
	    -Ilib/sha3/include -Ilib/crypto/include -Ilib/sapling/include -Ilib/base/include \
	    -Ilib/util/include -Ilib/platform/include -Ilib/support/include \
	    -D_POSIX_C_SOURCE=200809L -o $@ $^

# Run it. REPS= and CPU= override the defaults; CPU picks which CCD you land on
# (this host class is asymmetric: one CCD has 3D V-Cache, the other clocks
# higher), so quote the CPU alongside any number you record.
.PHONY: bench-simd
bench-simd: $(BIN_DIR)/simd_bench
	@$(BIN_DIR)/simd_bench $(if $(CPU),--cpu=$(CPU)) $(if $(REPS),--reps=$(REPS))

# Block-body deserialization microbenchmark (tools/serial_bench.c). Drives the
# SAME real chain bytes through the parser once per allocation variant —
# "zero-filled" reproduces the exact pre-change calloc behavior, so BEFORE and
# AFTER are measured in ONE process on ONE input rather than by diffing two
# builds against two moods of the machine. It asserts every variant derives a
# BIT-IDENTICAL digest (block hash + merkle root + every txid + the full
# re-serialized wire bytes) and only then reports median + p90, pinned to one
# core with the CCD named. Exits 2 on any divergence: a parser that is faster
# because it read uninitialized memory into a consensus hash is a chain split,
# not a win.
#
# Built at the SHIPPED CFLAGS (-O3 -march=x86-64-v3, no LTO) on purpose.
#
# CORPUS= points at a file of raw block hex, one per line, e.g. from
#   for h in ...; do zclassic-cli getblock $$(zclassic-cli getblockhash $$h) 0; done
# With no CORPUS it falls back to a synthetic block and labels it as such.
SERIAL_BENCH_SRCS = tools/serial_bench.c \
	lib/primitives/src/transaction.c lib/primitives/src/block.c \
	lib/bloom/src/merkle.c \
	core/math/src/serialize.c core/math/src/uint256.c core/math/src/hash.c \
	lib/crypto/src/sha256.c lib/crypto/src/sha512.c lib/crypto/src/ripemd160.c \
	lib/crypto/src/hmac_sha512.c lib/encoding/src/utilstrencodings.c \
	lib/base/src/cleanse.c lib/base/src/safe_alloc.c lib/base/src/log_level.c

.PHONY: serial_bench
serial_bench: $(BIN_DIR)/serial_bench
$(BIN_DIR)/serial_bench: $(SERIAL_BENCH_SRCS)
	@mkdir -p $(dir $@)
	$(CC) -std=c23 -O3 $(if $(ZCL_NATIVE),-march=native,-march=x86-64-v3) \
	    -Wall -Wextra -Werror -pedantic \
	    -Ilib/primitives/include -Ilib/script/include -Ilib/bloom/include \
	    -Ilib/crypto/include -Ilib/encoding/include -Ilib/base/include \
	    -Ilib/util/include -Ilib/support/include -Ilib/sapling/include \
	    -Ilib/keys/include -Ilib/core/include $(CORE_INCLUDES) \
	    -D_POSIX_C_SOURCE=200809L -o $@ $^

.PHONY: bench-serial
bench-serial: $(BIN_DIR)/serial_bench
	@$(BIN_DIR)/serial_bench $(if $(CORPUS),--corpus=$(CORPUS)) \
	    $(if $(CPU),--cpu=$(CPU)) $(if $(REPS),--reps=$(REPS))

bench: zclassic23
	@ZCL_BENCH_COMMIT="$(BUILD_COMMIT)" $(ZCLASSIC23_BIN) -bench

# Consensus-verify microbenchmark: times the two dominant per-block verify
# primitives (BLS12-381 Groth16 pairing + Equihash 200,9 solution check) and
# APPENDS ns/op rows to docs/bench-history.csv. `bench-regress` then gates
# those rows at ±20% vs the prior recorded run (ns/op is lower-is-better).
# Groth16 row is skipped if ~/.zcash-params is absent (VK not vendored).
.PHONY: bench-crypto-verify
bench-crypto-verify: zclassic23
	@ZCL_BENCH_COMMIT="$(BUILD_COMMIT)" $(ZCLASSIC23_BIN) -bench-crypto-verify

# Crypto-vs-Rust microbenchmark: times EVERY consensus-path C crypto primitive
# (Equihash verify, Groth16/BLS12-381 output verify, BLS12-381 pairing + Fp mul,
# secp256k1 ECDSA verify, ed25519 verify, SHA256, SHA3-256, BLAKE2b) as a
# flake-resistant MEDIAN ns/op, prints machine-readable CRYPTOPERF lines, and
# APPENDS the medians to docs/bench-history.csv.
.PHONY: bench-crypto-vs-rust
bench-crypto-vs-rust: zclassic23
	@ZCL_BENCH_COMMIT="$(BUILD_COMMIT)" $(ZCLASSIC23_BIN) -bench-crypto-vs-rust

# The STANDING crypto-perf gate (docs/CRYPTO_PERF.md): measure C live and
# enforce (a) the RATCHET — no C primitive may regress beyond the flake margin;
# the baseline may only shrink — and (b) the RATIO vs Rust — primitives that
# beat Rust must stay ahead (hard fail on lost lead); primitives behind Rust
# (Groth16 today) print a loud "BEHIND RUST — optimize" line but do NOT fail.
# DELIBERATELY NOT in the default `make lint` aggregate (timing flakes under CI
# load) — run it in a quiet context. Passes on current main = today's numbers.
.PHONY: check-crypto-perf
check-crypto-perf: zclassic23
	@ZCL_BENCH_COMMIT="$(BUILD_COMMIT)" \
	  ZCL_CRYPTO_PERF_BIN=$(ZCLASSIC23_BIN) tools/scripts/check_crypto_perf.sh

# The STANDING Groth16 differential parity gate (docs/CRYPTO_PERF.md
# "Optimizing safely"). Compiles the in-tree consensus verifier
# (lib/sapling/src/bls12_381.c) straight from source and replays a frozen
# corpus of adversarial encodings + crafted proofs, asserting every
# accept/reject verdict still matches lib/test/differential/*.bin. Any flip is
# a consensus break, so this must be run — and pass — before ANY optimization
# of the verifier lands. `record` re-freezes the golden and is ONLY legitimate
# after a deliberate, replay-approved consensus change.
.PHONY: check-groth16-parity
check-groth16-parity:
	@bash lib/test/differential/run_parity_oracle.sh check

# Times the two public-input paths (naive double-and-add vs the precomputed
# fixed-base tables) in ONE process against the same key, at the public-input
# counts the Sapling SPEND (7) and OUTPUT (5) circuits actually use. Verdicts
# are asserted equal every iteration, so a timing run can never report a
# speedup that came from diverging.
.PHONY: bench-groth16-comb
bench-groth16-comb:
	@bash lib/test/differential/run_parity_oracle.sh bench $(or $(ITERS),30)

bench-regress: zclassic23
	@ZCL_BENCH_COMMIT="$(BUILD_COMMIT)" $(ZCLASSIC23_BIN) -bench-regress

# CI guard: fresh datadir, must reach tip-10 in <600s against a local
# peer. Fails the build if sync regresses to the 9-hour stall the
# baked checkpoints + watchdog thread + peer-floor invariant are
# meant to prevent. Skipped automatically if no local peer is up.
# CI guard: fresh datadir + downloaded consensus_snapshot.db only,
# must reach tip > 1M with utxos > 1M in <90s. Asserts Wave 11A
# snapshot-first boot ordering didn't regress — without that fix the
# import path is silently dead. Skipped if no source snapshot is
# available locally (~/.zclassic-c23{,-test}/consensus_snapshot.db).
.PHONY: ci-coldstart
ci-coldstart: zclassic23
	@bash tools/scripts/cold_start_test.sh

.PHONY: ci-sync-smoke
ci-sync-smoke: zclassic23
	@if ! ss -tln 2>/dev/null | grep -q ':8033 '; then \
	    echo "[ci-sync-smoke] no local peer on :8033 — skipping"; \
	    exit 0; \
	fi
	@echo "[ci-sync-smoke] recording C benchmark placeholders..."
	@$(ZCLASSIC23_BIN) -bench-coldstart
	@$(ZCLASSIC23_BIN) -bench-mtbf
	@echo "[ci-sync-smoke] OK"

BUILD_ONLY_OBJECT_CFLAGS = $(BUILD_ONLY_CFLAGS)
$(OBJ_DIR)/lib/util/src/clientversion.o: BUILD_ONLY_OBJECT_CFLAGS += $(BUILD_IDENTITY_CPPFLAGS)
$(OBJ_DIR)/%.o: %.c $(VIEW_GEN_HEADERS) $(BUILD_EPOCH_OBJECT_TOOL) | $(BUILD_ONLY_LEASE)
	@$(BUILD_EPOCH_OBJECT_TOOL) dep "$@" "$<" \
	  "$(BUILD_SOURCE_ID)" "$(BUILD_CLEAN)" "$(BUILD_MUTATION)" \
	  "$(BUILD_ONLY_COMPILE_EPOCH)" "$(BUILD_COMPILER_ID)" "$(BUILD_ONLY_SESSION)" -- \
	  $(CC) $(BUILD_ONLY_OBJECT_CFLAGS)

# The one TU that bakes display + source identity — see the stamp above.
$(OBJ_DIR)/lib/util/src/clientversion.o: $(BUILD_IDENTITY_STAMP)

# Dev-bin keeps most TUs at -Og for quick debug compiles, but leaves the
# consensus/crypto/script/validation hot paths at a configurable optimized
# level. This catches more optimizer-sensitive behavior without paying global
# LTO or making every unrelated edit slow.
DEV_COMPILE_CFLAGS = $(DEV_RESTART_CFLAGS)
$(DEV_OBJ_DIR)/lib/chain/src/%.o: DEV_COMPILE_CFLAGS = $(DEV_HOT_CFLAGS)
$(DEV_OBJ_DIR)/core/chainparams/src/%.o: DEV_COMPILE_CFLAGS = $(DEV_HOT_CFLAGS)
$(DEV_OBJ_DIR)/core/params/src/%.o: DEV_COMPILE_CFLAGS = $(DEV_HOT_CFLAGS)
$(DEV_OBJ_DIR)/lib/crypto/src/%.o: DEV_COMPILE_CFLAGS = $(DEV_HOT_CFLAGS)
$(DEV_OBJ_DIR)/lib/primitives/src/%.o: DEV_COMPILE_CFLAGS = $(DEV_HOT_CFLAGS)
$(DEV_OBJ_DIR)/lib/sapling/src/%.o: DEV_COMPILE_CFLAGS = $(DEV_HOT_CFLAGS)
$(DEV_OBJ_DIR)/lib/script/src/%.o: DEV_COMPILE_CFLAGS = $(DEV_HOT_CFLAGS)
$(DEV_OBJ_DIR)/lib/validation/src/%.o: DEV_COMPILE_CFLAGS = $(DEV_HOT_CFLAGS)

$(DEV_OBJ_DIR)/lib/util/src/clientversion.o: DEV_COMPILE_CFLAGS += $(BUILD_IDENTITY_CPPFLAGS) $(DEV_SOURCE_RECEIPT_CPPFLAGS)
$(DEV_OBJ_DIR)/%.o: %.c $(VIEW_GEN_HEADERS) $(BUILD_EPOCH_OBJECT_TOOL) $(BUILD_EPOCH_OBJECT_FORCE) | $(DEV_LEASE)
	@$(BUILD_EPOCH_OBJECT_TOOL) dep "$@" "$<" \
	  "$(BUILD_SOURCE_ID)" "$(BUILD_CLEAN)" "$(BUILD_MUTATION)" \
	  "$(DEV_COMPILE_EPOCH)" "$(BUILD_COMPILER_ID)" "$(DEV_SESSION)" -- \
	  $(CC) $(DEV_COMPILE_CFLAGS)

# The dev object tree also needs the identity TU refreshed when its stamp changes.
$(DEV_OBJ_DIR)/lib/util/src/clientversion.o: $(BUILD_IDENTITY_STAMP)

# The content-addressed test cache (lib/test/src/testcache.c) folds a
# toolchain+FLAGS fingerprint into every per-group key.
#
# BUILD_COMPILER_ID alone was not enough and shipped a false green:
# build-epoch-key.sh's compiler-id mode fingerprints the CC/CXX argv and the
# tool BYTES, never the flags. TEST_FAST_CFLAGS compiles at -O1 and
# TEST_REL_CFLAGS at -O3, so `make t-fast` and the release gate binary carried
# the SAME toolkey and shared ONE keyspace — a PASS recorded by the -O1 fast
# profile was honored, unexecuted, by the -O3 gate.
#
# The epoch machinery's own digest (zcl_compile_epoch) is deliberately NOT
# reused as the toolkey: it also binds BUILD_SYSTEM_ID (the whole Makefile +
# epoch scripts), so any Makefile touch — even a comment — would bust the
# whole test cache, and it mixes in link flags the per-TU test cache does not
# care about. What is reused is the epoch machinery's already-assembled
# effective-compile-flag strings (*_EPOCH_COMPILE_FLAGS, which also carry the
# depfile flags); this hashes those, and nothing source-dependent.
#
# $(1) profile name, $(2) NAME of the profile's *_EPOCH_COMPILE_FLAGS variable.
# Injected per-object so only testcache.o carries it.
zcl_testcache_toolkey = $(strip $(shell printf '%s\0%s\0%s\0%s\0' \
  'zcl.testcache.toolkey.v1' '$(BUILD_COMPILER_ID)' '$(1)' '$(strip $($(2)))' \
  | sha256sum | cut -d' ' -f1))
TESTCACHE_TOOLKEY_CPPFLAGS = \
  -DZCL_TESTCACHE_TOOLKEY=\"$(call zcl_testcache_toolkey,$(1),$(2))\"

TEST_FAST_OBJECT_CFLAGS = $(TEST_FAST_CFLAGS)
$(TEST_FAST_OBJ_DIR)/lib/util/src/clientversion.o: TEST_FAST_OBJECT_CFLAGS += $(BUILD_IDENTITY_CPPFLAGS) $(DEV_SOURCE_RECEIPT_CPPFLAGS)
$(TEST_FAST_OBJ_DIR)/lib/test/src/testcache.o: TEST_FAST_OBJECT_CFLAGS += \
  $(call TESTCACHE_TOOLKEY_CPPFLAGS,$(TEST_FAST_PROFILE),TEST_FAST_EPOCH_COMPILE_FLAGS)
$(TEST_FAST_OBJ_DIR)/%.o: %.c $(VIEW_GEN_HEADERS) $(BUILD_EPOCH_OBJECT_TOOL) | $(TEST_FAST_LEASE)
	@$(BUILD_EPOCH_OBJECT_TOOL) dep "$@" "$<" \
	  "$(BUILD_SOURCE_ID)" "$(BUILD_CLEAN)" "$(BUILD_MUTATION)" \
	  "$(TEST_FAST_COMPILE_EPOCH)" "$(BUILD_COMPILER_ID)" "$(TEST_FAST_SESSION)" -- \
	  $(CC) $(TEST_FAST_OBJECT_CFLAGS)

# The fast test harness has its own object tree and identity stamp.
$(TEST_FAST_OBJ_DIR)/lib/util/src/clientversion.o: $(BUILD_IDENTITY_STAMP)

# Strict cached test_parallel object tree: same flags as the old whole-program
# test_parallel minus -flto=auto (see the TEST_REL_* comment above). -MD -MP
# records the complete include closure inside the exact epoch — no false green.
TEST_REL_OBJECT_CFLAGS = $(TEST_REL_CFLAGS)
$(TEST_REL_OBJ_DIR)/lib/util/src/clientversion.o: TEST_REL_OBJECT_CFLAGS += $(BUILD_IDENTITY_CPPFLAGS) $(DEV_SOURCE_RECEIPT_CPPFLAGS)
$(TEST_REL_OBJ_DIR)/lib/test/src/testcache.o: TEST_REL_OBJECT_CFLAGS += \
  $(call TESTCACHE_TOOLKEY_CPPFLAGS,$(TEST_REL_PROFILE),TEST_REL_EPOCH_COMPILE_FLAGS)
$(TEST_REL_OBJ_DIR)/%.o: %.c $(VIEW_GEN_HEADERS) $(BUILD_EPOCH_OBJECT_TOOL) | $(TEST_REL_LEASE)
	@$(BUILD_EPOCH_OBJECT_TOOL) dep "$@" "$<" \
	  "$(BUILD_SOURCE_ID)" "$(BUILD_CLEAN)" "$(BUILD_MUTATION)" \
	  "$(TEST_REL_COMPILE_EPOCH)" "$(BUILD_COMPILER_ID)" "$(TEST_REL_SESSION)" -- \
	  $(CC) $(TEST_REL_OBJECT_CFLAGS)

# The strict test tree also needs the identity TU refreshed with its stamp.
$(TEST_REL_OBJ_DIR)/lib/util/src/clientversion.o: $(BUILD_IDENTITY_STAMP)

# ASan/UBSan test harness object tree: TEST_FAST flags plus
# ASAN_COMMON_SAN_FLAGS (see the TEST_ASAN_* block above). -MD -MP records
# the complete include closure inside the exact epoch — no false green.
TEST_ASAN_OBJECT_CFLAGS = $(TEST_ASAN_CFLAGS)
TEST_ASAN_ADX_FRAME_POINTER_EXCEPTION_OBJS := $(addprefix $(TEST_ASAN_OBJ_DIR)/,$(ASAN_ADX_FRAME_POINTER_EXCEPTION_SRCS:.c=.o))
$(TEST_ASAN_ADX_FRAME_POINTER_EXCEPTION_OBJS): TEST_ASAN_OBJECT_CFLAGS += $(ASAN_ADX_FRAME_POINTER_EXCEPTION_FLAGS)
$(TEST_ASAN_OBJ_DIR)/lib/util/src/clientversion.o: TEST_ASAN_OBJECT_CFLAGS += $(BUILD_IDENTITY_CPPFLAGS) $(DEV_SOURCE_RECEIPT_CPPFLAGS)
# The ASan tree needs its OWN testcache keyspace, by design rather than by
# accident: without this the -D is absent and testcache.c falls back to
# __VERSION__, which pins the compiler but not the sanitizer flags.
$(TEST_ASAN_OBJ_DIR)/lib/test/src/testcache.o: TEST_ASAN_OBJECT_CFLAGS += \
  $(call TESTCACHE_TOOLKEY_CPPFLAGS,$(TEST_ASAN_PROFILE),TEST_ASAN_EPOCH_COMPILE_FLAGS)
$(TEST_ASAN_OBJ_DIR)/%.o: %.c $(VIEW_GEN_HEADERS) $(BUILD_EPOCH_OBJECT_TOOL) | $(TEST_ASAN_LEASE)
	@$(BUILD_EPOCH_OBJECT_TOOL) dep "$@" "$<" \
	  "$(BUILD_SOURCE_ID)" "$(BUILD_CLEAN)" "$(BUILD_MUTATION)" \
	  "$(TEST_ASAN_COMPILE_EPOCH)" "$(BUILD_COMPILER_ID)" "$(TEST_ASAN_SESSION)" -- \
	  $(CC) $(TEST_ASAN_OBJECT_CFLAGS)

# The asan test tree also needs the identity TU refreshed with its stamp.
$(TEST_ASAN_OBJ_DIR)/lib/util/src/clientversion.o: $(BUILD_IDENTITY_STAMP)

# ASan/UBSan dev node object tree: uniform DEV_ASAN_CFLAGS for every TU (no
# hot-path split — sanitizer fidelity over optimizer-sensitivity coverage).
DEV_ASAN_OBJECT_CFLAGS = $(DEV_ASAN_CFLAGS)
DEV_ASAN_ADX_FRAME_POINTER_EXCEPTION_OBJS := $(addprefix $(DEV_ASAN_OBJ_DIR)/,$(ASAN_ADX_FRAME_POINTER_EXCEPTION_SRCS:.c=.o))
$(DEV_ASAN_ADX_FRAME_POINTER_EXCEPTION_OBJS): DEV_ASAN_OBJECT_CFLAGS += $(ASAN_ADX_FRAME_POINTER_EXCEPTION_FLAGS)
$(DEV_ASAN_OBJ_DIR)/lib/util/src/clientversion.o: DEV_ASAN_OBJECT_CFLAGS += $(BUILD_IDENTITY_CPPFLAGS) $(DEV_SOURCE_RECEIPT_CPPFLAGS)
$(DEV_ASAN_OBJ_DIR)/%.o: %.c $(VIEW_GEN_HEADERS) $(BUILD_EPOCH_OBJECT_TOOL) | $(DEV_ASAN_LEASE)
	@$(BUILD_EPOCH_OBJECT_TOOL) dep "$@" "$<" \
	  "$(BUILD_SOURCE_ID)" "$(BUILD_CLEAN)" "$(BUILD_MUTATION)" \
	  "$(DEV_ASAN_COMPILE_EPOCH)" "$(BUILD_COMPILER_ID)" "$(DEV_ASAN_SESSION)" -- \
	  $(CC) $(DEV_ASAN_OBJECT_CFLAGS)

# The dev-asan tree also needs the identity TU refreshed with its stamp.
$(DEV_ASAN_OBJ_DIR)/lib/util/src/clientversion.o: $(BUILD_IDENTITY_STAMP)

# TSan test harness object tree: TEST_FAST flags plus TSAN_COMMON_SAN_FLAGS
# (see the TEST_TSAN_* block above). -MD -MP records the complete include
# closure inside the exact epoch — no false green.
TEST_TSAN_OBJECT_CFLAGS = $(TEST_TSAN_CFLAGS)
$(TEST_TSAN_OBJ_DIR)/lib/util/src/clientversion.o: TEST_TSAN_OBJECT_CFLAGS += $(BUILD_IDENTITY_CPPFLAGS) $(DEV_SOURCE_RECEIPT_CPPFLAGS)
$(TEST_TSAN_OBJ_DIR)/%.o: %.c $(VIEW_GEN_HEADERS) $(BUILD_EPOCH_OBJECT_TOOL) | $(TEST_TSAN_LEASE)
	@$(BUILD_EPOCH_OBJECT_TOOL) dep "$@" "$<" \
	  "$(BUILD_SOURCE_ID)" "$(BUILD_CLEAN)" "$(BUILD_MUTATION)" \
	  "$(TEST_TSAN_COMPILE_EPOCH)" "$(BUILD_COMPILER_ID)" "$(TEST_TSAN_SESSION)" -- \
	  $(CC) $(TEST_TSAN_OBJECT_CFLAGS)

# The tsan test tree also needs the identity TU refreshed with its stamp.
$(TEST_TSAN_OBJ_DIR)/lib/util/src/clientversion.o: $(BUILD_IDENTITY_STAMP)

# TSan dev node object tree: uniform DEV_TSAN_CFLAGS for every TU (no
# hot-path split — sanitizer fidelity over optimizer-sensitivity coverage).
DEV_TSAN_OBJECT_CFLAGS = $(DEV_TSAN_CFLAGS)
$(DEV_TSAN_OBJ_DIR)/lib/util/src/clientversion.o: DEV_TSAN_OBJECT_CFLAGS += $(BUILD_IDENTITY_CPPFLAGS) $(DEV_SOURCE_RECEIPT_CPPFLAGS)
$(DEV_TSAN_OBJ_DIR)/%.o: %.c $(VIEW_GEN_HEADERS) $(BUILD_EPOCH_OBJECT_TOOL) | $(DEV_TSAN_LEASE)
	@$(BUILD_EPOCH_OBJECT_TOOL) dep "$@" "$<" \
	  "$(BUILD_SOURCE_ID)" "$(BUILD_CLEAN)" "$(BUILD_MUTATION)" \
	  "$(DEV_TSAN_COMPILE_EPOCH)" "$(BUILD_COMPILER_ID)" "$(DEV_TSAN_SESSION)" -- \
	  $(CC) $(DEV_TSAN_OBJECT_CFLAGS)

# The dev-tsan tree also needs the identity TU refreshed with its stamp.
$(DEV_TSAN_OBJ_DIR)/lib/util/src/clientversion.o: $(BUILD_IDENTITY_STAMP)

# Deploy: lint → WAL checkpoint → install service → restart → RPC verify.
#
# `make deploy` used to print "Deployed." whenever systemd held the unit
# active for >2s — false-positive friendly. The new target fails loudly on
# three distinct paths:
#   1. `lint` — untouched, but now actually FAILs on raw sqlite3_step.
#   2. `wal_checkpoint` — truncate WAL before SIGTERM so SQLite doesn't
#      recover a half-checkpointed journal on boot.
#   3. `tools/deploy_verify.sh` — poll `zclassic-cli getblockcount` until the
#      node answers and diagnostics are ready, with a startup-sized deadline;
#      freshness is exact source SHA-256 plus the running executable SHA-256.
#
# The wal_checkpoint step calls the in-tree tools/wal_checkpoint binary
# (P12.4 — was an inline `sqlite3(1)` CLI invocation before, which failed
# on stock Ubuntu/Debian hosts where the CLI isn't installed).  The tool
# issues `sqlite3_wal_checkpoint_v2(TRUNCATE)` via the library only — no
# DELETE, no unguarded statements, and safe to re-run.
# ── install (MVP criterion #1) ──────────────────────────────────────────────
# Literal install for a fresh operator: copy the two binaries onto PATH and
# install the systemd --user unit pointed at the installed binary, so a clean
# Ubuntu/Debian box can do `make install && systemctl --user start zclassic23`.
#   PREFIX   binary install prefix (default /usr/local; use ~/.local for rootless)
#   DESTDIR  staging root for packaging — when set, the live --user unit + daemon
#            reload are skipped (binaries are only staged under DESTDIR).
PREFIX  ?= /usr/local
DESTDIR ?=
# Stable remains the default promotion bar.  An owner maintaining a node with
# pre-existing named blockers may explicitly choose `challenger`: exact source,
# artifact, process, RPC/P2P, diagnostic, and <=1-tip-gap checks still apply,
# but the deployment does not claim that the stable health bar was met.
DEPLOY_VERIFY_STAGE ?= stable
define INSTALL_C23_PRODUCTS
set -eu; \
install -d "$(DESTDIR)$(PREFIX)/bin"; \
install -m 755 $(ZCLASSIC23_BIN) "$(DESTDIR)$(PREFIX)/bin/z23"; \
ln -sfn z23 "$(DESTDIR)$(PREFIX)/bin/zclassic23"; \
install -m 755 $(ZCL_RPC_BIN) "$(DESTDIR)$(PREFIX)/bin/zcl-rpc"; \
install -m 755 $(BIN_DIR)/zclassic23-package-verify \
	"$(DESTDIR)$(PREFIX)/bin/zclassic23-package-verify"; \
install -m 755 $(BIN_DIR)/zclassic23-package-sign \
	"$(DESTDIR)$(PREFIX)/bin/zclassic23-package-sign"; \
if [ -z "$(DESTDIR)" ]; then \
	install -d "$(HOME)/.config/systemd/user"; \
	sed 's|%h/zclassic23/build/bin/zclassic23|$(PREFIX)/bin/zclassic23|' \
		deploy/zclassic23.service \
		> "$(HOME)/.config/systemd/user/zclassic23.service"; \
	(systemctl --user daemon-reload 2>/dev/null || true); \
	echo "installed systemd --user unit; start: systemctl --user start zclassic23"; \
fi; \
echo "make install: node, RPC, package verifier + offline signer -> $(DESTDIR)$(PREFIX)/bin"
endef

.PHONY: install
install: vendor-ready zclassic23 zcl-rpc zclassic23-package-verify zclassic23-package-sign
	@$(INSTALL_C23_PRODUCTS)

# Same installation surface, but every copied product was freshly built and
# audited by the pinned old-glibc front door above. Keeping the copy recipe
# shared prevents portable installation from becoming a second package path.
c23-portable-install: c23-portable-release
	@$(INSTALL_C23_PRODUCTS)

deploy: vendor-ready lint zclassic-cli tools/wal_checkpoint
	@./tools/deploy_guard.sh canonical-deploy
	@case "$(DEPLOY_VERIFY_STAGE)" in stable|challenger) ;; *) \
	    echo "deploy: DEPLOY_VERIFY_STAGE must be stable or challenger" >&2; exit 2;; esac
	@# Snapshot the executable inode owned by the stable MainPID before the
	@# forced relink below unlinks build/bin/zclassic23.  The running process
	@# remains valid after unlink, but the pathname then names the challenger;
	@# a post-build copy of that pathname is therefore not a rollback image.
	@set -eu; \
	mainpid="$$(systemctl --user show zclassic23 -p MainPID --value 2>/dev/null || true)"; \
	case "$$mainpid" in ''|*[!0-9]*|0) \
	    echo "deploy: canonical service must be running before prior-binary capture" >&2; exit 1;; esac; \
	prior="$(BIN_DIR)/.zclassic23.deploy-prior"; \
	prior_tmp="$$(mktemp "$$prior.tmp.XXXXXX")"; \
	trap 'rm -f "$$prior_tmp"' EXIT HUP INT TERM; \
	install -m 755 "/proc/$$mainpid/exe" "$$prior_tmp"; \
	mv -f -- "$$prior_tmp" "$$prior"; \
	trap - EXIT HUP INT TERM
	@# Option 2 (DEPLOY-WRITE) bridge: stage a verified anchor snapshot into the
	@# datadir so this install carries a reachable snapshot from boot one
	@# (covers the cold-start case the in-fold self-mint cannot). Best-effort:
	@# a missing source does NOT fail deploy; the node SHA3-verifies before trust.
	@# Run every recursive Make before freezing the candidate, and pin it to the
	@# outer parse's source record so it cannot silently authorize a newer epoch.
	$(MAKE) BUILD_SOURCE_RECORD="$(BUILD_SOURCE_RECORD)" seed-anchor-snapshot
	@# Force a fresh production binary. The $(ZCLASSIC23_BIN) rule is a single
	@# whole-program cc over $(ALL_SRCS) with NO depfile tracking, so a
	@# header-only edit leaves every .c mtime unchanged and `make` would skip
	@# the relink and ship a STALE binary — the exact footgun behind a
	@# multi-day stale-binary outage. Removing the binary forces the rebuild;
	@# deploy_verify.sh below confirms the running source id and executable bytes.
	rm -f $(ZCLASSIC23_BIN)
	$(MAKE) BUILD_SOURCE_RECORD="$(BUILD_SOURCE_RECORD)" zclassic23
	@# From here through verification there are no recursive Make parses. Freeze
	@# one candidate, prove its baked source identity against the outer record,
	@# install those exact bytes, and pass that same artifact hash to the verifier.
	@set -eu; \
	command -v timeout >/dev/null 2>&1 || { \
	    echo "deploy: timeout is required for candidate preflight" >&2; exit 1; }; \
	candidate="$$(mktemp "$(dir $(ZCLASSIC23_BIN)).zclassic23.deploy.XXXXXX")"; \
	prior_snapshot="$(BIN_DIR)/.zclassic23.deploy-prior"; \
	dropin_tmp=""; service_tmp=""; rollback_bin=""; rollback_dropin=""; \
	rollback_dropin_present=0; rollback_armed=0; rollback_complete=0; \
	rollback_source_id=""; rollback_artifact_sha256=""; SERVICE_BIN=""; dropin=""; \
	cleanup_deploy() { \
	    deploy_rc=$$?; \
	    trap - EXIT HUP INT TERM; \
	    set +e; \
	    if [ "$$rollback_armed" -eq 1 ] && [ "$$rollback_complete" -eq 0 ]; then \
	        rollback_complete=1; \
	        echo "deploy: candidate verification failed; restoring pinned prior binary/config" >&2; \
	        install -m 755 "$$rollback_bin" "$$SERVICE_BIN"; rollback_install_rc=$$?; \
	        if [ "$$rollback_dropin_present" -eq 1 ]; then \
	            install -m 644 "$$rollback_dropin" "$$dropin"; rollback_dropin_rc=$$?; \
	        else \
	            rm -f "$$dropin"; rollback_dropin_rc=$$?; \
	        fi; \
	        systemctl --user daemon-reload; rollback_reload_rc=$$?; \
	        systemctl --user restart zclassic23; rollback_restart_rc=$$?; \
	        rollback_verify_rc=1; \
	        if [ "$$rollback_install_rc" -eq 0 ] && \
	           [ "$$rollback_dropin_rc" -eq 0 ] && \
	           [ "$$rollback_reload_rc" -eq 0 ] && \
	           [ "$$rollback_restart_rc" -eq 0 ]; then \
	            ZCL_DEPLOY_STAGE=rollback \
	            ZCL_DEPLOY_EXPECT_SOURCE_ID="$$rollback_source_id" \
	            ZCL_DEPLOY_EXPECT_ARTIFACT_SHA256="$$rollback_artifact_sha256" \
	                ./tools/deploy_verify.sh; \
	            rollback_verify_rc=$$?; \
	        fi; \
	        if [ "$$rollback_verify_rc" -eq 0 ]; then \
	            echo "deploy: ROLLED_BACK — prior executable/config restored and verified" >&2; \
	        else \
	            echo "deploy: CRITICAL — rollback verification failed; automation stopped" >&2; \
	        fi; \
	    fi; \
	    rm -f "$$candidate" "$$prior_snapshot" "$$dropin_tmp" "$$service_tmp" \
	          "$$rollback_bin" "$$rollback_dropin"; \
	    exit "$$deploy_rc"; \
	}; \
	trap cleanup_deploy EXIT; \
	trap 'exit 129' HUP; trap 'exit 130' INT; trap 'exit 143' TERM; \
	install -m 755 "$(ZCLASSIC23_BIN)" "$$candidate"; \
	artifact_sha256="$$(sha256sum < "$$candidate" | awk '{print $$1}')"; \
	[ "$${#artifact_sha256}" -eq 64 ] || { \
	    echo "deploy: invalid frozen candidate SHA-256" >&2; exit 1; }; \
	case "$$artifact_sha256" in *[!0-9a-f]*) \
	    echo "deploy: invalid frozen candidate SHA-256" >&2; exit 1;; esac; \
	candidate_agentbuild="$$(timeout 30 "$$candidate" agentbuild 2>&1)" || { \
	    echo "deploy: frozen candidate agentbuild preflight failed" >&2; exit 1; }; \
	printf '%s\n' "$$candidate_agentbuild" | \
	    grep -q '"schema"[[:space:]]*:[[:space:]]*"zcl.agent_build.v2"' || { \
	    echo "deploy: frozen candidate has no agentbuild v1 contract" >&2; exit 1; }; \
	candidate_source_id="$$(printf '%s\n' "$$candidate_agentbuild" | \
	    grep -oE '"source_id_sha256"[[:space:]]*:[[:space:]]*"[^"]*"' | \
	    head -1 | sed -E 's/.*"source_id_sha256"[[:space:]]*:[[:space:]]*"([^"]*)".*/\1/')"; \
	[ "$${#candidate_source_id}" -eq 64 ] || { \
	    echo "deploy: frozen candidate omitted exact source_id_sha256" >&2; exit 1; }; \
	case "$$candidate_source_id" in *[!0-9a-f]*) \
	    echo "deploy: frozen candidate source_id_sha256 is malformed" >&2; exit 1;; esac; \
	[ "$$candidate_source_id" = "$(BUILD_SOURCE_ID)" ] || { \
	    echo "deploy: frozen candidate source id $$candidate_source_id != outer $(BUILD_SOURCE_ID)" >&2; exit 1; }; \
	tools/dev/source-identity.sh verify-record \
	    "$(BUILD_SOURCE_ID)" "$(BUILD_CLEAN)" "$(BUILD_MUTATION)" >/dev/null; \
	if [ -f "$(HOME)/.zclassic-c23/node.db" ]; then \
	    $(WAL_CHECKPOINT_BIN) "$(HOME)/.zclassic-c23/node.db" || { \
	        echo "WAL checkpoint failed" >&2; exit 1; }; \
	fi; \
	install -d "$(HOME)/.config/systemd/user"; \
	service_unit="$(HOME)/.config/systemd/user/zclassic23.service"; \
	if [ ! -f "$$service_unit" ]; then \
	    service_tmp="$$(mktemp "$$service_unit.tmp.XXXXXX")"; \
	    sed 's|%h/zclassic23|$(CURDIR)|g' deploy/zclassic23.service > "$$service_tmp"; \
	    install -m 644 "$$service_tmp" "$$service_unit"; \
	    rm -f "$$service_tmp"; service_tmp=""; \
	    echo "deploy: installed missing canonical service unit from template"; \
	else \
	    echo "deploy: preserving existing canonical service unit"; \
	fi; \
	systemctl --user daemon-reload; \
	service_exec="$$(systemctl --user show zclassic23 -p ExecStart --value 2>/dev/null)"; \
	service_path="$$(printf '%s\n' "$$service_exec" | \
	    sed -n 's/^.*path=\([^ ;]*\).*$$/\1/p')"; \
	service_argv="$$(printf '%s\n' "$$service_exec" | \
	    sed -n 's/^.*argv\[\]=\([^;]*\);.*$$/\1/p')"; \
	service_argv0="$$(printf '%s\n' "$$service_argv" | tr ' ' '\n' | awk 'NF { print; exit }')"; \
	[ -n "$$service_path" ] && [ "$$service_path" = "$$service_argv0" ] || { \
	    echo "deploy: canonical service path and executable argv disagree" >&2; exit 1; }; \
	if [ "$$service_path" = "$(CURDIR)/deploy/zclassic23-launch.sh" ]; then \
	    SERVICE_BIN="$$(printf '%s\n' "$$service_argv" | tr ' ' '\n' | \
	        awk 'NF { n++; if (n == 2) { print; exit } }')"; \
	    [ "$$SERVICE_BIN" = "$(CURDIR)/build/bin/zclassic23" ] || { \
	        echo "deploy: canonical launcher node binary does not resolve to this checkout" >&2; exit 1; }; \
	else \
	    case "$$service_path" in /*) SERVICE_BIN="$$service_path" ;; *) \
	        echo "deploy: direct canonical service binary is not absolute" >&2; exit 1;; esac; \
	fi; \
	mainpid="$$(systemctl --user show zclassic23 -p MainPID --value 2>/dev/null || true)"; \
	case "$$mainpid" in ''|*[!0-9]*|0) \
	    echo "deploy: canonical service must be running before a rollback-safe mutation" >&2; exit 1;; esac; \
	running_exe_raw="$$(readlink "/proc/$$mainpid/exe" 2>/dev/null || true)"; \
	running_exe_path="$${running_exe_raw% (deleted)}"; \
	running_exe="$$(readlink -f "$$running_exe_path" 2>/dev/null || true)"; \
	target_exe="$$(readlink -f "$$SERVICE_BIN" 2>/dev/null || true)"; \
	[ -n "$$running_exe" ] && [ "$$running_exe" = "$$target_exe" ] || { \
	    echo "deploy: canonical MainPID executable does not match service target" >&2; exit 1; }; \
	[ -f "$$prior_snapshot" ] || { \
	    echo "deploy: captured prior executable is missing" >&2; exit 1; }; \
	running_sha256="$$(sha256sum < "/proc/$$mainpid/exe" | awk '{print $$1}')"; \
	prior_sha256="$$(sha256sum < "$$prior_snapshot" | awk '{print $$1}')"; \
	[ "$$running_sha256" = "$$prior_sha256" ] || { \
	    echo "deploy: MainPID changed after prior-binary capture" >&2; exit 1; }; \
	tools/dev/source-identity.sh verify-record \
	    "$(BUILD_SOURCE_ID)" "$(BUILD_CLEAN)" "$(BUILD_MUTATION)" >/dev/null; \
	install -d "$(HOME)/.config/systemd/user/zclassic23.service.d"; \
	dropin="$(HOME)/.config/systemd/user/zclassic23.service.d/90-build-identity.conf"; \
	rollback_bin="$$(mktemp "$$(dirname "$$SERVICE_BIN")/.zclassic23.rollback.XXXXXX")"; \
	install -m 755 "$$prior_snapshot" "$$rollback_bin"; \
	rollback_artifact_sha256="$$(sha256sum < "$$rollback_bin" | awk '{print $$1}')"; \
	rollback_agentbuild="$$(timeout 30 "$$rollback_bin" agentbuild 2>&1)" || { \
	    echo "deploy: prior executable agentbuild preflight failed" >&2; exit 1; }; \
	rollback_source_id="$$(printf '%s\n' "$$rollback_agentbuild" | \
	    grep -oE '"source_id_sha256"[[:space:]]*:[[:space:]]*"[^"]*"' | \
	    head -1 | sed -E 's/.*"source_id_sha256"[[:space:]]*:[[:space:]]*"([^"]*)".*/\1/')"; \
	[ "$${#rollback_source_id}" -eq 64 ] || { \
	    echo "deploy: prior executable omitted exact source_id_sha256" >&2; exit 1; }; \
	case "$$rollback_source_id$$rollback_artifact_sha256" in *[!0-9a-f]*) \
	    echo "deploy: prior rollback identity is malformed" >&2; exit 1;; esac; \
	if [ -f "$$dropin" ]; then \
	    rollback_dropin="$$(mktemp "$$dropin.rollback.XXXXXX")"; \
	    install -m 644 "$$dropin" "$$rollback_dropin"; \
	    rollback_dropin_present=1; \
	fi; \
	rollback_armed=1; \
	dropin_tmp="$$(mktemp "$$dropin.tmp.XXXXXX")"; \
	{ \
	    printf '[Service]\n'; \
	    printf 'Environment="ZCL_AGENT_EXPECT_SOURCE_ID=%s"\n' "$(BUILD_SOURCE_ID)"; \
	    printf 'Environment="ZCL_AGENT_EXPECT_BUILD_COMMIT=%s"\n' "$(BUILD_COMMIT)"; \
	    printf 'Environment="ZCL_AGENT_EXPECT_BUILD_SOURCE=make-deploy"\n'; \
	} > "$$dropin_tmp"; \
	install -m 644 "$$dropin_tmp" "$$dropin"; \
	rm -f "$$dropin_tmp"; dropin_tmp=""; \
	systemctl --user daemon-reload; \
	install -m 755 "$$candidate" "$$SERVICE_BIN"; \
	installed_sha256="$$(sha256sum < "$$SERVICE_BIN" | awk '{print $$1}')"; \
	[ "$$installed_sha256" = "$$artifact_sha256" ] || { \
	    echo "deploy: installed service executable differs from frozen candidate" >&2; exit 1; }; \
	echo "deploy: installed frozen candidate -> $$SERVICE_BIN (service ExecStart)"; \
	install -d "$(HOME)/.local/bin"; \
	if [ "$$SERVICE_BIN" != "$(HOME)/.local/bin/zclassic23" ]; then \
	    ln -sfn "$$SERVICE_BIN" "$(HOME)/.local/bin/zclassic23"; \
	fi; \
	echo "deploy: linked owner command $(HOME)/.local/bin/zclassic23 -> $$SERVICE_BIN"; \
	if [ -e "$(HOME)/bin/zclassic23" ] || [ -L "$(HOME)/bin/zclassic23" ]; then \
	    if [ "$$SERVICE_BIN" != "$(HOME)/bin/zclassic23" ]; then \
	        ln -sfn "$$SERVICE_BIN" "$(HOME)/bin/zclassic23"; \
	    fi; \
	    echo "deploy: refreshed PATH shadow $(HOME)/bin/zclassic23 -> $$SERVICE_BIN"; \
	fi; \
	systemctl --user restart zclassic23; \
	ZCL_DEPLOY_STAGE="$(DEPLOY_VERIFY_STAGE)" \
	ZCL_DEPLOY_EXPECT_SOURCE_ID="$(BUILD_SOURCE_ID)" \
	ZCL_DEPLOY_EXPECT_ARTIFACT_SHA256="$$artifact_sha256" \
	    ./tools/deploy_verify.sh; \
	rollback_armed=0; \
	rm -f "$$candidate"; candidate=""; \
	rm -f "$$rollback_bin" "$$rollback_dropin"; rollback_bin=""; rollback_dropin=""; \
	trap - EXIT HUP INT TERM

# Option 2 (DEPLOY-WRITE) snapshot reachability bridge: stage a verified anchor
# UTXO snapshot into the datadir at <datadir>/utxo-anchor.snapshot (the path the
# torn-import self-heal resolves). Best-effort + idempotent + node-verified on
# boot — see tools/seed_anchor_snapshot.sh. Standalone so an operator can run it
# without a full deploy: `make seed-anchor-snapshot`.
#   ZCL_DATADIR=<dir> ZCL_ANCHOR_SNAPSHOT_SRC=<file> make seed-anchor-snapshot
# Ship one production binary to every node in the fleet. `deploy` above installs
# to THIS host only; `ship` builds one candidate, proves it, and puts those exact
# bytes on each host, verifying every one against the source id its running
# daemon reports and rolling that host back if it does not come back healthy.
# Build-once/ship-many is deliberate: a per-host rebuild both costs a full
# whole-program link per host and produces different bytes per host, which makes
# "is the fleet running the same code" unanswerable by comparison.
#   make ship                   # gate, build, then local + remote
#   make ship SHIP_ARGS=--dry-run
#   make ship SHIP_ARGS=--targets=remote
.PHONY: ship
ship:
	@./tools/ship.sh $(SHIP_ARGS)

.PHONY: seed-anchor-snapshot
seed-anchor-snapshot:
	@./tools/seed_anchor_snapshot.sh

# Deploy the freshly-built binary to the DEV linger lane (isolated datadir
# ~/.zclassic-c23-dev + ports 8053/18252) — where code-in-progress runs live
# instead of rotting unrun in git. NEVER touches the operator-gated live node.
# These are internal activation backends: the native `dev change apply` command
# supplies ZCL_DEV_SOURCE_ID after proving the exact complete dirty epoch.
# Calling them directly without that compare-and-swap capability fails closed.
deploy-dev:
	@echo "deploy-dev: REFUSING — runtime publication is contained pending transactional epoch/proof/rollback receipts" >&2
	@exit 3

deploy-dev-fast agent-deploy-fast:
	@echo "agent-deploy-fast: REFUSING — runtime publication is contained pending transactional epoch/proof/rollback receipts" >&2
	@exit 3

agent-dev-status:
	@tools/dev/agent-dev-status.sh $(ARGS)

# Read-only fresh-datadir recovery plan for the isolated dev lane. Phase-0
# contains public ARGS=--apply; only dev-recovery-selftest reaches the retained
# transaction inside its inherited-FD, fixture-bound harness.
agent-dev-recover:
	@tools/dev/recover-dev-lane.sh $(ARGS)

dev-recovery-selftest:
	@tools/dev/recover-dev-lane-selftest.sh

agent-clear-stale-dev-reindex:
	@tools/dev/agent-clear-stale-reindex.sh $(ARGS)

agent-doctor:
	@tools/dev/agent-doctor.sh $(ARGS)

# Build-host accelerator health: ccache, mold/lld/gold, clang, inotifywait, lcov,
# clangd, nproc — with the concrete per-iteration cost of each missing one.
# Read-only, always exit 0.
doctor-build:
	@tools/dev/doctor-build.sh

stage-dev-bin agent-stage-dev:
	@echo "agent-stage-dev: REFUSING — runtime publication is contained pending transactional epoch/proof/rollback receipts" >&2
	@exit 3

lane-health:
	@./tools/scripts/lane_health.sh

lane-recover:
	@./tools/scripts/lane_recover.sh $(LANE)

background-fuzz:
	@./tools/scripts/background_quality_lane.sh fuzz

background-coverage:
	@./tools/scripts/background_quality_lane.sh coverage

background-tests:
	@./tools/scripts/background_quality_lane.sh tests

.PHONY: install-remote-status-linger remote-status install-self-update-linger self-update-status
install-remote-status-linger:
	@install -d "$(HOME)/.config/systemd/user"
	@install -m 644 deploy/examples/zclassic23-self-update.service "$(HOME)/.config/systemd/user/zclassic23-remote-status.service"
	@install -m 644 deploy/examples/zclassic23-self-update.timer "$(HOME)/.config/systemd/user/zclassic23-remote-status.timer"
	@systemctl --user daemon-reload
	@systemctl --user enable --now zclassic23-remote-status.timer
	@echo "installed read-only remote status timer: zclassic23-remote-status.timer"
	@echo "status: make remote-status"

remote-status:
	@systemctl --user list-timers zclassic23-remote-status.timer --no-pager 2>/dev/null || true
	@systemctl --user status zclassic23-remote-status.service zclassic23-remote-status.timer --no-pager -n 20 2>/dev/null || true

install-self-update-linger:
	@echo "install-self-update-linger: REFUSING — self-update/build publication is contained; use install-remote-status-linger for read-only observation" >&2
	@exit 3

self-update-status: remote-status

.PHONY: install-remote-test-node-linger remote-test-node-status
install-remote-test-node-linger:
	@install -d "$(HOME)/.config/systemd/user" "$(HOME)/.config/zclassic23" "$(HOME)/.zclassic23-test"
	@if [ ! -f "$(HOME)/.config/zclassic23/remote-test.env" ]; then \
		install -m 600 deploy/examples/zclassic23-remote-test.env.example "$(HOME)/.config/zclassic23/remote-test.env"; \
		echo "installed editable env: $(HOME)/.config/zclassic23/remote-test.env"; \
	fi
	@install -m 644 deploy/examples/zclassic23-remote-test-node.service "$(HOME)/.config/systemd/user/zclassic23-test.service"
	@systemctl --user daemon-reload
	@systemctl --user enable zclassic23-test.service
	@echo "installed remote test node service: zclassic23-test.service"
	@echo "edit $(HOME)/.config/zclassic23/remote-test.env, then start/restart when ready"
	@echo "status: make remote-test-node-status"

remote-test-node-status:
	@systemctl --user status zclassic23-test.service --no-pager -n 40 2>/dev/null || true
	@systemctl --user show zclassic23-test.service -p ActiveState -p SubState -p MainPID -p MemoryHigh -p MemoryMax -p CPUWeight -p IOWeight --no-pager 2>/dev/null || true

install-quality-linger:
	@install -d "$(HOME)/.config/systemd/user"
	@install -m 644 deploy/zclassic23-fuzz.service "$(HOME)/.config/systemd/user/zclassic23-fuzz.service"
	@install -m 644 deploy/zclassic23-fuzz.timer "$(HOME)/.config/systemd/user/zclassic23-fuzz.timer"
	@install -m 644 deploy/zclassic23-coverage.service "$(HOME)/.config/systemd/user/zclassic23-coverage.service"
	@install -m 644 deploy/zclassic23-coverage.timer "$(HOME)/.config/systemd/user/zclassic23-coverage.timer"
	@install -m 644 deploy/zclassic23-test-suite.service "$(HOME)/.config/systemd/user/zclassic23-test-suite.service"
	@install -m 644 deploy/zclassic23-test-suite.timer "$(HOME)/.config/systemd/user/zclassic23-test-suite.timer"
	@systemctl --user daemon-reload
	@systemctl --user enable --now zclassic23-fuzz.timer zclassic23-coverage.timer zclassic23-test-suite.timer
	@echo "installed background quality lanes: zclassic23-fuzz.timer zclassic23-coverage.timer zclassic23-test-suite.timer"
	@echo "status: make quality-linger-status"

quality-linger-status:
	@systemctl --user list-timers zclassic23-fuzz.timer zclassic23-coverage.timer zclassic23-test-suite.timer --no-pager 2>/dev/null || true
	@systemctl --user status zclassic23-fuzz.service zclassic23-coverage.service zclassic23-test-suite.service --no-pager -n 12 2>/dev/null || true
	@./tools/scripts/background_quality_lane.sh status

# install-slo-probe: the EXTERNAL uptime prober (lane E3) — a read-only
# client-viewpoint scoreboard for "staying synced" that does not trust node
# self-reports. Probes canonical/soak/dev by RPC every 60s and appends to
# ~/.local/state/zclassic23-slo/uptime-ledger.jsonl (tools/scripts/
# node_slo_probe.sh). Never restarts, stops, or writes to any node.
.PHONY: install-slo-probe install-slo-pager slo-probe-status
install-slo-probe:
	@install -d "$(HOME)/.config/systemd/user"
	@set -eu; tmp="$$(mktemp "$(HOME)/.config/systemd/user/zclassic23-slo-probe.service.tmp.XXXXXX")"; \
		trap 'rm -f "$$tmp"' EXIT HUP INT TERM; \
		sed 's|%h/github/zclassic23|$(CURDIR)|g' deploy/zclassic23-slo-probe.service > "$$tmp"; \
		install -m 644 "$$tmp" "$(HOME)/.config/systemd/user/zclassic23-slo-probe.service"
	@install -m 644 deploy/zclassic23-slo-probe.timer "$(HOME)/.config/systemd/user/zclassic23-slo-probe.timer"
	@systemctl --user daemon-reload
	@systemctl --user enable --now zclassic23-slo-probe.timer
	@echo "installed external SLO prober: zclassic23-slo-probe.timer (every 60s)"
	@echo "ledger: $(HOME)/.local/state/zclassic23-slo/uptime-ledger.jsonl"
	@echo "status: make slo-probe-status"

# install-slo-pager: the pager half of the scoreboard. A SEPARATE 5-min timer
# (self-watchdog: still fires when the probe itself dies) runs
# tools/scripts/slo_page_if_stalled.sh; the unit sitting FAILED is the page
# surface (plus wall(1) + pages.jsonl on first fire / 6h renotify). Pages on:
# canonical no-advance >2h, ledger stale >5m, canonical unreachable >10m.
install-slo-pager:
	@install -d "$(HOME)/.config/systemd/user"
	@install -m 644 deploy/zclassic23-slo-pager.service "$(HOME)/.config/systemd/user/zclassic23-slo-pager.service"
	@install -m 644 deploy/zclassic23-slo-pager.timer "$(HOME)/.config/systemd/user/zclassic23-slo-pager.timer"
	@systemctl --user daemon-reload
	@systemctl --user enable --now zclassic23-slo-pager.timer
	@echo "installed external SLO pager: zclassic23-slo-pager.timer (every 5 min)"
	@echo "pages: $(HOME)/.local/state/zclassic23-slo/pages.jsonl"
	@echo "status: make slo-probe-status"

# install-hold-certifier: the 72h HOLD CERTIFIER — a 15-min timer running
# tools/scripts/slo_hold_judge.sh --record for the canonical instance. Appends
# one JSON verdict line per run to ~/.local/state/zclassic23-slo/
# hold-ledger.jsonl; the first VERDICT=HOLD_PROVEN line is the 72h win-proof.
# Always exits 0 (recorder, not a pager — the pager owns the alarm surface).
.PHONY: install-hold-certifier
install-hold-certifier:
	@install -d "$(HOME)/.config/systemd/user"
	@install -m 644 deploy/zclassic23-hold-certifier.service "$(HOME)/.config/systemd/user/zclassic23-hold-certifier.service"
	@install -m 644 deploy/zclassic23-hold-certifier.timer "$(HOME)/.config/systemd/user/zclassic23-hold-certifier.timer"
	@systemctl --user daemon-reload
	@systemctl --user enable --now zclassic23-hold-certifier.timer
	@echo "installed 72h hold certifier: zclassic23-hold-certifier.timer (every 15 min)"
	@echo "verdicts: $(HOME)/.local/state/zclassic23-slo/hold-ledger.jsonl"

# install-intervention-ledger: independent read-only evidence that the node,
# its unit configuration, and its on-disk/running binaries did or did not
# change. A daily heartbeat distinguishes a quiet node from a dead detector.
.PHONY: install-intervention-ledger intervention-ledger-status
install-intervention-ledger:
	@install -d "$(HOME)/.config/systemd/user"
	@set -eu; tmp="$$(mktemp "$(HOME)/.config/systemd/user/zclassic23-intervention.service.tmp.XXXXXX")"; \
		trap 'rm -f "$$tmp"' EXIT HUP INT TERM; \
		sed 's|%h/github/zclassic23|$(CURDIR)|g' deploy/zclassic23-intervention.service > "$$tmp"; \
		install -m 644 "$$tmp" "$(HOME)/.config/systemd/user/zclassic23-intervention.service"
	@install -m 644 deploy/zclassic23-intervention.timer "$(HOME)/.config/systemd/user/zclassic23-intervention.timer"
	@systemctl --user daemon-reload
	@systemctl --user enable --now zclassic23-intervention.timer
	@echo "installed intervention detector: zclassic23-intervention.timer (every 60s)"
	@echo "ledger: $(HOME)/.local/state/zclassic23-intervention/intervention-ledger.jsonl"

intervention-ledger-status:
	@systemctl --user list-timers zclassic23-intervention.timer --no-pager 2>/dev/null || true
	@systemctl --user status zclassic23-intervention.service zclassic23-intervention.timer --no-pager -n 12 2>/dev/null || true
	@./tools/scripts/intervention_ledger.sh summary 2>/dev/null || true

slo-probe-status:
	@systemctl --user list-timers zclassic23-slo-probe.timer zclassic23-slo-pager.timer --no-pager 2>/dev/null || true
	@systemctl --user status zclassic23-slo-probe.service zclassic23-slo-probe.timer --no-pager -n 12 2>/dev/null || true
	@systemctl --user status zclassic23-slo-pager.service zclassic23-slo-pager.timer --no-pager -n 12 2>/dev/null || true
	@tail -n 6 "$(HOME)/.local/state/zclassic23-slo/uptime-ledger.jsonl" 2>/dev/null || echo "no ledger yet"
	@tail -n 4 "$(HOME)/.local/state/zclassic23-slo/pages.jsonl" 2>/dev/null || echo "no pages (good)"
	@./tools/scripts/slo_ledger_summary.sh --window-hours 24 2>/dev/null || true

# slo-probe-selftest: hermetic regression guard for the prober, the summary
# reader, the 72h hold judge, and the external pager — fixture RPC commands
# / fixture ledgers, no live nodes.
slo-probe-selftest:
	@bash -c 'set -uo pipefail; \
	 set +e; out=$$(bash tools/scripts/node_slo_probe.sh --selftest 2>&1); rc=$$?; set -e; \
	 echo "$$out"; \
	 if [ "$$rc" != "0" ] || ! echo "$$out" | grep -q "^selftest: PASS"; then \
	     echo "slo-probe-selftest: FAIL node_slo_probe.sh (rc=$$rc; no selftest: PASS line)"; \
	     exit 1; \
	 fi; \
	 set +e; out2=$$(bash tools/scripts/slo_ledger_summary.sh --selftest 2>&1); rc2=$$?; set -e; \
	 echo "$$out2"; \
	 if [ "$$rc2" != "0" ] || ! echo "$$out2" | grep -q "^selftest: PASS"; then \
	     echo "slo-probe-selftest: FAIL slo_ledger_summary.sh (rc=$$rc2; no selftest: PASS line)"; \
	     exit 1; \
	 fi; \
	 set +e; out3=$$(bash tools/scripts/slo_hold_judge.sh --selftest 2>&1); rc3=$$?; set -e; \
	 echo "$$out3"; \
	 if [ "$$rc3" != "0" ] || ! echo "$$out3" | grep -q "^selftest: PASS"; then \
	     echo "slo-probe-selftest: FAIL slo_hold_judge.sh (rc=$$rc3; no selftest: PASS line)"; \
	     exit 1; \
	 fi; \
	 set +e; out4=$$(bash tools/scripts/slo_page_if_stalled.sh --selftest 2>&1); rc4=$$?; set -e; \
	 echo "$$out4"; \
	 if [ "$$rc4" != "0" ] || ! echo "$$out4" | grep -q "^selftest: PASS"; then \
	     echo "slo-probe-selftest: FAIL slo_page_if_stalled.sh (rc=$$rc4; no selftest: PASS line)"; \
	     exit 1; \
	 fi; \
	 echo "slo-probe-selftest: PASS"'

# ── off-host tip-hash agreement ───────────────────────────────────────
# The first evidence in this repository that compares a BLOCK HASH against
# genuinely REMOTE peers, rather than a height number against the sibling
# zclassicd on this same box. Recorder: tools/scripts/tip_agreement_probe.sh
# (external process, ledger under ~/.local/state). Judge:
# tools/scripts/tip_agreement_judge.sh (windowed, fails closed).
install-tip-agreement:
	@install -d "$(HOME)/.config/systemd/user"
	@set -eu; tmp="$$(mktemp "$(HOME)/.config/systemd/user/zclassic23-tip-agreement.service.tmp.XXXXXX")"; \
		trap 'rm -f "$$tmp"' EXIT HUP INT TERM; \
		sed 's|%h/github/zclassic23|$(CURDIR)|g' deploy/zclassic23-tip-agreement.service > "$$tmp"; \
		install -m 644 "$$tmp" "$(HOME)/.config/systemd/user/zclassic23-tip-agreement.service"
	@install -m 644 deploy/zclassic23-tip-agreement.timer "$(HOME)/.config/systemd/user/zclassic23-tip-agreement.timer"
	@systemctl --user daemon-reload
	@systemctl --user enable --now zclassic23-tip-agreement.timer
	@echo "installed off-host tip-hash agreement recorder: zclassic23-tip-agreement.timer (every 10 min)"
	@echo "ledger: owner-private state recorded"
	@echo "verdict: make tip-agreement-status"

tip-agreement-status:
	@systemctl --user list-timers zclassic23-tip-agreement.timer --no-pager 2>/dev/null || true
	@./tools/scripts/tip_agreement_judge.sh "$(HOME)/.local/state/zclassic23-parity/agreement-ledger.jsonl" || true

# tip-agreement-selftest: hermetic regression guard for the recorder AND the
# judge. Fixture node readers, no live node, no network. Gates on the PASS
# token, not on an exit code alone.
tip-agreement-selftest:
	@bash -c 'set -uo pipefail; \
	 set +e; out=$$(bash tools/scripts/test_tip_agreement_evidence.sh 2>&1); rc=$$?; set -e; \
	 echo "$$out"; \
	 if [ "$$rc" != "0" ] || ! echo "$$out" | grep -q "^selftest: PASS"; then \
	     echo "tip-agreement-selftest: FAIL (rc=$$rc; no selftest: PASS line)"; \
	     exit 1; \
	 fi; \
	 echo "tip-agreement-selftest: PASS"'

# evidence-selftest: hermetic regression guard for the three evidence
# dimensions that were absent until the ledgers below existed —
#   * intervention_ledger.sh  the manual-intervention record. Without it,
#     "zero operator intervention" is an UNFALSIFIABLE claim: nothing on
#     this host recorded a config edit or a binary swap, and the closest
#     thing (soak_evidence.sh) only INFERS restarts hourly from NRestarts.
#     Its positive cases cover a binary swapped with NO restart and a
#     drop-in edited with NO restart — both invisible to that inference.
#   * zcl_intervene.sh        the human/agent declaration front door, whose
#     ABSENCE around a detected change is what marks it `unattributed`.
#   * public_explorer_smoke.sh  the only EXTERNAL availability evidence;
#     its case=outage-is-recorded is the guard that a FAILED check still
#     writes its ledger line instead of exiting first, which is how the
#     script behaved for its whole prior life.
# All fixture-driven: no live nodes, no systemd units, no network.
.PHONY: evidence-selftest
evidence-selftest:
	@bash -c 'set -uo pipefail; rc_all=0; \
	 for s in tools/scripts/intervention_ledger.sh \
	          tools/scripts/zcl_intervene.sh \
	          tools/scripts/public_explorer_smoke.sh; do \
	   set +e; out=$$(bash "$$s" --selftest 2>&1); rc=$$?; set -e; \
	   echo "$$out"; \
	   if [ "$$rc" != "0" ] || ! echo "$$out" | grep -q "^selftest: PASS"; then \
	     echo "evidence-selftest: FAIL $$s (rc=$$rc; no selftest: PASS line)"; \
	     rc_all=1; \
	   fi; \
	 done; \
	 if [ "$$rc_all" != "0" ]; then exit 1; fi; \
	 echo "evidence-selftest: PASS"'

# ── Warm-standby serving lane + scripted atomic cutover ─────────────────────
# The canonical serving identity (ports 8033/18232, ~/.zclassic-c23) had no
# failover. install-standby installs the always-warm understudy unit; cutover
# promotes a healthy candidate to canonical with a hard preflight + auto-
# rollback. See deploy/zclassic23-standby.service and deploy/zclassic23-cutover.sh.
.PHONY: install-standby cutover cutover-selftest migrate-role-names-selftest

install-standby:
	@install -d "$(HOME)/.config/systemd/user"
	@install -m 644 deploy/zclassic23-standby.service "$(HOME)/.config/systemd/user/zclassic23-standby.service"
	@if [ ! -e "$(HOME)/.config/zclassic23/standby.env" ]; then \
	    install -d "$(HOME)/.config/zclassic23"; \
	    install -m 644 deploy/zclassic23-standby.env.example "$(HOME)/.config/zclassic23/standby.env"; \
	    echo "seeded $(HOME)/.config/zclassic23/standby.env (edit STANDBY_DATADIR/PORT/RPCPORT)"; \
	fi
	@echo "installed zclassic23-standby.service. To arm the understudy:"
	@echo "  systemctl --user daemon-reload && systemctl --user enable --now zclassic23-standby"

# make cutover CANDIDATE_DATADIR=<path> [YES=1] [TIMEOUT=<secs>] [CANDIDATE_RPCPORT=<n>]
# Owner-gated by design: without YES=1 the script prints the height comparison
# and REFUSES. It never edits the canonical unit; it swaps datadirs underneath
# it and auto-rolls-back if the promoted node does not reach the pre-cutover H*.
cutover:
	@[ -n "$(CANDIDATE_DATADIR)" ] || { echo "usage: make cutover CANDIDATE_DATADIR=<path> [YES=1]"; exit 2; }
	@CANDIDATE_DATADIR="$(CANDIDATE_DATADIR)" \
	 $(if $(CANDIDATE_RPCPORT),CANDIDATE_RPCPORT="$(CANDIDATE_RPCPORT)",) \
	 $(if $(TIMEOUT),READY_TIMEOUT="$(TIMEOUT)",) \
	 ./deploy/zclassic23-cutover.sh $(if $(filter 1 yes YES true,$(YES)),--yes,)

# cutover-selftest: hermetic fixture proof of the preflight comparison + the
# auto-rollback logic — mock units (SYSTEMCTL=echo), injected H* readers, two
# throwaway fixture datadirs. No live nodes, no real systemd.
cutover-selftest:
	@bash -c 'set -uo pipefail; \
	 set +e; out=$$(bash deploy/zclassic23-cutover-selftest.sh 2>&1); rc=$$?; set -e; \
	 echo "$$out"; \
	 if [ "$$rc" != "0" ] || ! echo "$$out" | grep -q "^cutover-selftest: PASS"; then \
	     echo "cutover-selftest: FAIL (rc=$$rc; no PASS line)"; \
	     exit 1; \
	 fi'

# migrate-role-names-selftest: hermetic regression proof for
# deploy/migrate-role-names.sh's "%h" specifier handling (see that script's
# NAMING LAW header) — sandboxed $HOME, stubbed systemctl on PATH, no real
# unit or datadir is ever touched. Guards the silent-orphan regression: an
# earlier version extracted "-datadir=%h/..." from the old unit as a raw
# string and used it unexpanded, so the rename check always no-opped while
# the script still enabled/started the new unit against an empty datadir.
migrate-role-names-selftest:
	@bash -c 'set -uo pipefail; \
	 set +e; out=$$(bash deploy/migrate-role-names-selftest.sh 2>&1); rc=$$?; set -e; \
	 echo "$$out"; \
	 if [ "$$rc" != "0" ] || ! echo "$$out" | grep -q "^\[migrate-role-names-selftest\] ALL CHECKS PASSED"; then \
	     echo "migrate-role-names-selftest: FAIL (rc=$$rc; no ALL CHECKS PASSED line)"; \
	     exit 1; \
	 fi'

# install-logrotate: Phase E2 — size-threshold node.log rotation with NO
# external logrotate dependency (repo rule: no external deps). Rotates
# every ~/.zclassic-c23*/node.log + mint-progress.log past 512 MiB,
# copytruncate semantics (see tools/scripts/zcl-logrotate.sh header), 2
# kept gzip generations. Only the TIMER is started (enable --now); the
# .service is never started here — the first real run is whatever the
# timer schedules next (daily ~03:00, see the .timer comments).
.PHONY: install-logrotate logrotate-status logrotate-selftest
install-logrotate:
	@install -d "$(HOME)/.config/systemd/user"
	@install -m 644 deploy/zclassic23-logrotate.service "$(HOME)/.config/systemd/user/zclassic23-logrotate.service"
	@install -m 644 deploy/zclassic23-logrotate.timer "$(HOME)/.config/systemd/user/zclassic23-logrotate.timer"
	@systemctl --user daemon-reload
	@systemctl --user enable --now zclassic23-logrotate.timer
	@echo "installed log rotation: zclassic23-logrotate.timer (daily ~03:00)"
	@echo "status: make logrotate-status"

logrotate-status:
	@systemctl --user list-timers zclassic23-logrotate.timer --no-pager 2>/dev/null || true
	@systemctl --user status zclassic23-logrotate.service zclassic23-logrotate.timer --no-pager -n 12 2>/dev/null || true

# logrotate-selftest: hermetic regression guard — fixture datadir under a
# temp HOME, no live nodes touched.
logrotate-selftest:
	@bash -c 'set -uo pipefail; \
	 set +e; out=$$(bash tools/scripts/zcl-logrotate.sh --selftest 2>&1); rc=$$?; set -e; \
	 echo "$$out"; \
	 if [ "$$rc" != "0" ] || ! echo "$$out" | grep -q "^selftest: PASS"; then \
	     echo "logrotate-selftest: FAIL zcl-logrotate.sh (rc=$$rc; no selftest: PASS line)"; \
	     exit 1; \
	 fi; \
	 echo "logrotate-selftest: PASS"'

# install-bundle-export: scheduled, verified consensus-state-bundle export +
# retention + off-disk copy hook (deploy/zclassic23-bundle-export.sh wraps
# the existing TERMINAL -export-consensus-bundle verb). Only the TIMER is
# started (enable --now); review the target datadir and ZCL_EXPORT_SECONDARY
# in deploy/zclassic23-bundle-export.service BEFORE enabling on a given box —
# see that file's header comment.
.PHONY: install-bundle-export bundle-export-status bundle-export-selftest
install-bundle-export:
	@install -d "$(HOME)/.config/systemd/user"
	@install -m 644 deploy/zclassic23-bundle-export.service "$(HOME)/.config/systemd/user/zclassic23-bundle-export.service"
	@install -m 644 deploy/zclassic23-bundle-export.timer "$(HOME)/.config/systemd/user/zclassic23-bundle-export.timer"
	@systemctl --user daemon-reload
	@systemctl --user enable --now zclassic23-bundle-export.timer
	@echo "installed bundle export: zclassic23-bundle-export.timer (nightly ~04:00)"
	@echo "status: make bundle-export-status"

bundle-export-status:
	@systemctl --user list-timers zclassic23-bundle-export.timer --no-pager 2>/dev/null || true
	@systemctl --user status zclassic23-bundle-export.service zclassic23-bundle-export.timer --no-pager -n 12 2>/dev/null || true

# bundle-export-selftest: hermetic regression guard — REFUSED path against a
# real fresh datadir (fast, no chain data needed), plus retention and
# secondary-copy-hook logic against synthetic fixture files. No live
# datadir touched.
bundle-export-selftest:
	@bash -c 'set -uo pipefail; \
	 set +e; out=$$(bash deploy/zclassic23-bundle-export.sh --selftest 2>&1); rc=$$?; set -e; \
	 echo "$$out"; \
	 if [ "$$rc" != "0" ] || ! echo "$$out" | grep -q "^selftest: PASS"; then \
	     echo "bundle-export-selftest: FAIL zclassic23-bundle-export.sh (rc=$$rc; no selftest: PASS line)"; \
	     exit 1; \
	 fi; \
	 echo "bundle-export-selftest: PASS"'

# install-replay-canary: the standing full-history replay canary (lane
# S2d, wf/s2d-replay-canary-crashloop). nightly = --from=anchor (~45 min,
# 04:30+jitter), weekly = --from=genesis (~6 h, Sun 05:30+jitter) — both
# OFF-PEAK and disjoint from logrotate/fuzz/soak-evidence/simnet-nightly/
# test-suite/coverage (see the .timer comments for the full slot map).
# ExecStart in both .service units runs tools/scripts/replay_canary_guard.sh,
# which SKIPS the run (logged, exit 0, no page) whenever a
# zclassic23-mint-* (or any *mint*) transient unit is actively folding, so
# this evidence lane can never steal CPU/IO from a live sovereign-state
# cure mint. Only the TIMERS are started (enable --now); the heavy
# .service units are never started here — the first real run is whatever
# the timer schedules next.
.PHONY: install-replay-canary replay-canary-linger-status
install-replay-canary:
	@install -d "$(HOME)/.config/systemd/user"
	@install -m 644 deploy/zclassic23-replay-canary-nightly.service "$(HOME)/.config/systemd/user/zclassic23-replay-canary-nightly.service"
	@install -m 644 deploy/zclassic23-replay-canary-nightly.timer "$(HOME)/.config/systemd/user/zclassic23-replay-canary-nightly.timer"
	@install -m 644 deploy/zclassic23-replay-canary-weekly.service "$(HOME)/.config/systemd/user/zclassic23-replay-canary-weekly.service"
	@install -m 644 deploy/zclassic23-replay-canary-weekly.timer "$(HOME)/.config/systemd/user/zclassic23-replay-canary-weekly.timer"
	@install -m 644 "deploy/zclassic23-replay-canary-onfailure@.service" "$(HOME)/.config/systemd/user/zclassic23-replay-canary-onfailure@.service"
	@systemctl --user daemon-reload
	@systemctl --user enable --now zclassic23-replay-canary-nightly.timer zclassic23-replay-canary-weekly.timer
	@echo "installed replay canary timers: zclassic23-replay-canary-nightly.timer zclassic23-replay-canary-weekly.timer"
	@echo "(services NOT started now — they fire on the timer's next OnCalendar)"
	@echo "status: make replay-canary-linger-status"

replay-canary-linger-status:
	@systemctl --user list-timers zclassic23-replay-canary-nightly.timer zclassic23-replay-canary-weekly.timer --no-pager 2>/dev/null || true
	@systemctl --user status zclassic23-replay-canary-nightly.service zclassic23-replay-canary-weekly.service --no-pager -n 12 2>/dev/null || true

release:
	@./tools/release.sh

# Install the tracked git hooks (shared across all worktrees via core.hooksPath).
# pre-push runs the bounded LOCAL CI gate (`make pre-push-ci`): strict
# compile, lint-fast, and mapped focused tests for the files being pushed.
# Unmapped code fails closed. Full-suite/fuzz/coverage proof work runs
# through the linger timers installed by `make install-quality-linger`.
.PHONY: install-hooks
install-hooks:
	@git config core.hooksPath tools/githooks
	@chmod +x tools/githooks/* 2>/dev/null || true
	@echo "Installed git hooks: core.hooksPath=tools/githooks"
	@echo "  pre-push -> runs 'make pre-push-ci' before every push to origin"
	@echo "  pre-commit -> refuses non-main-branch commits in the MAIN checkout"
	@echo "                (lane work goes in a worktree; ZCL_LANE_COMMIT_OK=1 overrides)"
	@echo "  full-suite/fuzz/coverage -> make install-quality-linger"
	@echo "  bypass one push: git push --no-verify   (or ZCL_SKIP_PREPUSH=1)"

.PHONY: check-git-hooks-installed
check-git-hooks-installed:
	@echo "══ LINT: local pre-push hook installed ══"
	@./tools/scripts/check_git_hooks_installed.sh

# One-shot bootstrap for a freshly created `.claude/worktrees/*` lane: copies
# vendor/lib/*.a in from the canonical checkout (idempotent), re-asserts the
# shared core.hooksPath, and sanity-checks the link prerequisites so a
# missing archive fails loud here instead of as an opaque linker error deep
# into `make -j`. See tools/scripts/worktree_init.sh for the full writeup.
#
# NOTE: on a genuinely fresh worktree (vendor/lib not yet populated), `make`
# itself establishes vendor/lib at PARSE time (line ~46, VENDOR_MISSING_INPUTS)
# before this recipe ever runs, via the slow network `vendor-ready` path —
# Make has no way to run a recipe before parsing prerequisites. For the fast,
# network-free copy, run the script directly ONCE before your first `make`:
#     bash tools/scripts/worktree_init.sh
# `make worktree-init` is the idempotent re-verify / repeat-safe entry point
# for every call after vendor/lib already exists (post-prune re-create, or a
# mid-lane repair check).
.PHONY: worktree-init
worktree-init:
	@./tools/scripts/worktree_init.sh

clean:
	rm -rf $(BUILD_DIR)
	rm -f test_zcl test_parallel zclassic23 zclassic-cli zcl-rpc zcl-nodectl \
	    zclassic23-chaos p2_invariant_check crash_recovery_test rebuild_recent \
	    shadow_replay_proof wallet_check spec_zcl session bot wallet_dump \
	    wallet_sim wallet-wireframes mock_rpc export_snapshot bench_fresh_sync \
	    fuzz_block fuzz_script fuzz_p2p fuzz_http fuzz_compactblock \
	    fuzz_snapshot fuzz_tx_bundle fuzz_rom_manifest fuzz_overlay fuzz_ecdsa test_zcl_cov
	rm -f tools/gen_templates tools/inspect_html tools/wal_checkpoint \
	    tools/check_observability_pairing tools/gen_sha3_windows \
	    tools/gen_utxo_root_ladder tools/soak/soak_runner

# ── Coverage (wave 5 #8) ──────────────────────────────────────
#
# Establishes a measurement path.  This is NOT targeted at a specific
# percentage yet — it exists so future commits can track whether they
# move the needle up or down.
#
# Builds a separate `test_zcl_cov` binary with gcov instrumentation
# instead of clobbering the main `test_zcl` (which uses -flto and -O3,
# both of which fight with coverage instrumentation).  Running the
# coverage binary emits .gcda files next to each translation unit;
# we then render them with either lcov+genhtml or gcovr — whichever
# is installed — and leave the tooling path permissive so a developer
# without coverage utilities still gets a useful message.
#
# Normal `make` / `make test` paths are untouched.
#
# NB: `-Werror` gets stripped alongside `-flto -O3` because -O0/-O1 +
# gcov produces a different set of lints (unused-static,
# format-truncation at different inlining thresholds) that fire
# cleanly in the main build but trip -Werror here.  Coverage is an
# observability tool, not a production build — warnings still print,
# they just don't block the binary.
#
# Two things have to be right before the numbers are meaningful:
#
# 1. Optimisation level.  -O0 + gcov drives one of the recursive
#    JSON tests into stack overflow in ~11 minutes wall-clock; -O1
#    keeps the instrumentation accurate (lcov/gcov handle it fine)
#    while cutting runtime roughly in half and eliminating the
#    regression.
#
# 2. Object-file layout.  The main `test_zcl` target compiles all
#    sources in ONE `cc` invocation — that's fast for LTO but ruinous
#    for gcov, because files like `lib/net/src/protocol.c` and
#    `lib/rpc/src/protocol.c` share a basename and collide at .gcda
#    write time ("overwriting an existing profile data with a
#    different checksum").  For the coverage build we therefore
#    compile each source into its own
#    `build/cov/epochs/<compile-epoch>/<same/path>/file.o`
#    FIRST, then link — this way each .gcda lives next to its .o and
#    the directory structure guarantees uniqueness.  Slower than the
#    single-command build, but sound.
COV_BUILD_ROOT = $(BUILD_DIR)/cov
COV_CFLAGS = $(filter-out -flto -flto=% -O3 -march=native -Werror,$(CACHED_CFLAGS)) \
             --coverage -O1 -g -DCOVERAGE_BUILD -DZCL_TESTING
COV_LDFLAGS = $(filter-out -flto -flto=%,$(LDFLAGS)) --coverage
COV_TEST_BIN = $(BIN_DIR)/test_zcl_cov
COV_EPOCH_COMPILE_FLAGS := $(strip $(COV_CFLAGS) -Wno-deprecated-declarations deps=-MD,-MP coverage-staging=v1)
COV_EPOCH_LINK_FLAGS := $(strip $(COV_LDFLAGS) $(TOR_LIBS) $(LIBS) $(GTK_LIBS) $(WEBKIT_LIBS) cxx=$(CXX))
ifneq ($(filter coverage,$(ZCL_EPOCH_PROFILES)),)
COV_COMPILE_EPOCH := $(call zcl_compile_epoch,coverage-v2,COV_EPOCH_COMPILE_FLAGS,COV_EPOCH_LINK_FLAGS)
COV_COMPILE_EPOCH_VALID := $(shell printf '%s\n' '$(COV_COMPILE_EPOCH)' | awk '$$0 ~ /^[0-9a-f]{64}$$/ { print "yes" }')
ifneq ($(COV_COMPILE_EPOCH_VALID),yes)
$(error coverage compile-epoch derivation failed)
endif
else
COV_COMPILE_EPOCH := $(ZCL_ZERO_SHA256)
endif
COV_BUILD_DIR = $(COV_BUILD_ROOT)/epochs/$(COV_COMPILE_EPOCH)
COV_TEST_CANDIDATE = $(BIN_DIR)/coverage/epochs/$(COV_COMPILE_EPOCH)/test_zcl_cov
COV_TEST_ACTIVE = $(COV_TEST_CANDIDATE)
COV_PROFILE = coverage-v2
COV_SESSION = $(COV_BUILD_DIR)/.build-session
COV_LEASE = $(COV_BUILD_DIR)/.leases/$(BUILD_INVOCATION_ID)
COV_INFO = $(BUILD_DIR)/coverage.info
COV_HTML = $(BUILD_DIR)/coverage_html

$(COV_LEASE): FORCE
	@$(BUILD_EPOCH_SESSION_TOOL) acquire "$(COV_SESSION)" "$@" \
	  "$(COV_BUILD_ROOT)" "$(BIN_DIR)/coverage" "$(BUILD_EPOCH_KEEP)" \
	  "$(BUILD_SOURCE_ID)" "$(BUILD_CLEAN)" "$(BUILD_MUTATION)" \
	  "$(BUILD_COMPILER_ID)" "$(COV_COMPILE_EPOCH)" "$(COV_PROFILE)" \
	  "$(COV_EPOCH_COMPILE_FLAGS)" "$(COV_EPOCH_LINK_FLAGS)" \
	  "$(CC)" "$(CXX)" "$$PPID"

COV_TEST_SRCS := $(filter-out lib/test/src/test_parallel.c, $(TEST_SRCS)) $(TEST_DEV_EXECUTOR_SRCS)
COV_OBJS := $(patsubst %.c,$(COV_BUILD_DIR)/%.o,$(COV_TEST_SRCS) $(SPEC_SRCS) $(CHAOS_SIM_SRCS) $(ALL_SRCS))
COV_LINK_RSP = $(COV_BUILD_DIR)/link-inputs.rsp

COV_OBJECT_CFLAGS = $(COV_CFLAGS) -Wno-deprecated-declarations
$(COV_BUILD_DIR)/lib/util/src/clientversion.o: COV_OBJECT_CFLAGS += $(BUILD_IDENTITY_CPPFLAGS) $(DEV_SOURCE_RECEIPT_CPPFLAGS)
$(COV_BUILD_DIR)/%.o: %.c $(VIEW_GEN_HEADERS) $(BUILD_EPOCH_OBJECT_TOOL) | $(COV_LEASE)
	@$(BUILD_EPOCH_OBJECT_TOOL) coverage "$@" "$<" \
	  "$(BUILD_SOURCE_ID)" "$(BUILD_CLEAN)" "$(BUILD_MUTATION)" \
	  "$(COV_COMPILE_EPOCH)" "$(BUILD_COMPILER_ID)" "$(COV_SESSION)" -- \
	  $(CC) $(COV_OBJECT_CFLAGS)

$(COV_BUILD_DIR)/lib/util/src/clientversion.o: $(BUILD_IDENTITY_STAMP)

# The coverage depfile graph now joins the profile table above instead of
# importing on every goal. It never held dependency information for anything
# but a coverage build: unless `make coverage` has run in this checkout the
# import resolves to zero files and costs one failed open per coverage object
# per -I directory (8372 of them here), which measured 0.8-1.6 s of pure
# parse-time waste on EVERY make invocation, including `lint`, `ff` and
# `build-only`. The conservative fallback still selects `coverage` for any
# unrecognized or multi-goal invocation, which is what the nested
# `$(COV_TEST_CANDIDATE)` goal inside `coverage-locked` relies on.
ifneq ($(filter coverage,$(ZCL_DEPFILE_PROFILES)),)
-include $(COV_OBJS:.o=.d)
endif

.PHONY: test_zcl_cov test-zcl-cov-locked
test_zcl_cov:
	@mkdir -p $(BUILD_DIR)
	@flock -x $(BUILD_DIR)/coverage.lock \
	  $(MAKE) --no-print-directory ZCL_COVERAGE_LOCKED=1 test-zcl-cov-locked
test-zcl-cov-locked:
	@test "$(ZCL_COVERAGE_LOCKED)" = 1 || { echo "test-zcl-cov-locked: use make test_zcl_cov" >&2; exit 2; }
	@$(MAKE) --no-print-directory "$(COV_TEST_BIN)"
$(COV_TEST_BIN): $(COV_TEST_CANDIDATE) FORCE
	@$(BUILD_EPOCH_PUBLISH_TOOL) "$(COV_TEST_CANDIDATE)" "$@" "$(COV_SESSION)" \
	  "$(BUILD_SOURCE_ID)" "$(BUILD_CLEAN)" "$(BUILD_MUTATION)" \
	  "$(COV_COMPILE_EPOCH)" "$(BUILD_COMPILER_ID)" "$(COV_PROFILE)" \
	  "$(COV_EPOCH_COMPILE_FLAGS)" "$(COV_EPOCH_LINK_FLAGS)" "$(CC)" "$(CXX)"

$(COV_TEST_CANDIDATE): $(BUILD_IDENTITY_STAMP) $(COV_OBJS)
	@mkdir -p $(dir $@)
	@set -eu; \
	tmp="$$(mktemp "$@.link.XXXXXX")"; \
	trap 'rm -f "$$tmp"' EXIT HUP INT TERM; \
	$(CC) $(COV_CFLAGS) $(COV_LDFLAGS) -o "$$tmp" "@$(COV_LINK_RSP)" $(TOR_LIBS) $(LIBS) $(GTK_LIBS) $(WEBKIT_LIBS); \
	$(BUILD_EPOCH_SESSION_TOOL) verify "$(COV_SESSION)" "$(COV_LEASE)" \
	  "$(COV_BUILD_ROOT)" "$(BIN_DIR)/coverage" "$(BUILD_EPOCH_KEEP)" \
	  "$(BUILD_SOURCE_ID)" "$(BUILD_CLEAN)" "$(BUILD_MUTATION)" "$(BUILD_COMPILER_ID)" \
	  "$(COV_COMPILE_EPOCH)" "$(COV_PROFILE)" "$(COV_EPOCH_COMPILE_FLAGS)" \
	  "$(COV_EPOCH_LINK_FLAGS)" "$(CC)" "$(CXX)" "$$PPID" >/dev/null; \
	mv -f -- "$$tmp" "$@"; \
	trap - EXIT HUP INT TERM

$(COV_LINK_RSP): $(COV_OBJS)
	@$(if $(ZCL_MAKE_NO_EXEC),,$(file >$@,$(COV_OBJS))) test -s "$@"

$(COV_TEST_CANDIDATE): $(COV_LINK_RSP)

.PHONY: coverage-locked
coverage:
	@mkdir -p $(BUILD_DIR)
	@flock -x $(BUILD_DIR)/coverage.lock \
	  $(MAKE) --no-print-directory ZCL_COVERAGE_LOCKED=1 coverage-locked

coverage-locked:
	@test "$(ZCL_COVERAGE_LOCKED)" = 1 || { echo "coverage-locked: use make coverage" >&2; exit 2; }
	@$(MAKE) --no-print-directory ZCL_COVERAGE_LOCKED=1 coverage-clean
	@$(MAKE) --no-print-directory "$(COV_TEST_CANDIDATE)"
	@$(BUILD_EPOCH_SESSION_TOOL) acquire "$(COV_SESSION)" "$(COV_LEASE)" \
	  "$(COV_BUILD_ROOT)" "$(BIN_DIR)/coverage" "$(BUILD_EPOCH_KEEP)" \
	  "$(BUILD_SOURCE_ID)" "$(BUILD_CLEAN)" "$(BUILD_MUTATION)" \
	  "$(BUILD_COMPILER_ID)" "$(COV_COMPILE_EPOCH)" "$(COV_PROFILE)" \
	  "$(COV_EPOCH_COMPILE_FLAGS)" "$(COV_EPOCH_LINK_FLAGS)" \
	  "$(CC)" "$(CXX)" "$$PPID" >/dev/null
	@echo "== Resetting gcov counters =="
	@find $(COV_BUILD_DIR) -name '*.gcda' -delete 2>/dev/null || true
	@echo "== Running test_zcl_cov =="
	@# Match the `test` target — some json/recursion tests need
	@# unlimited stack.  If the binary fails or crashes we still render
	@# partial coverage data first, then propagate the failure below.
	@set +e; ulimit -s unlimited && $(COV_TEST_ACTIVE); rc=$$?; \
		echo $$rc > $(COV_BUILD_DIR)/test_zcl_cov.exit; \
		if [ "$$rc" != "0" ]; then \
			echo "coverage: test_zcl_cov exited $$rc; rendering partial report before failing"; \
		fi; \
		exit 0
	@if command -v lcov >/dev/null 2>&1; then \
		echo "== Rendering coverage via lcov =="; \
		lcov --capture --directory $(COV_BUILD_DIR) --output-file $(COV_INFO) \
		     --rc geninfo_unexecuted_blocks=1 --quiet || true; \
		lcov --remove $(COV_INFO) \
		     '*/lib/test/*' '*/vendor/*' '*/tools/fuzz/*' '/usr/*' \
		     --output-file $(COV_INFO) --quiet || true; \
		lcov --summary $(COV_INFO); \
		if command -v genhtml >/dev/null 2>&1; then \
			genhtml --quiet $(COV_INFO) --output-directory $(COV_HTML); \
			echo "== HTML report: $(COV_HTML)/index.html =="; \
		else \
			echo "(genhtml not installed — summary only)"; \
		fi; \
	elif command -v gcovr >/dev/null 2>&1; then \
		echo "== Rendering coverage via gcovr =="; \
		gcovr --root . --filter 'app/' --filter 'lib/' --filter 'tools/' \
		      --exclude 'lib/test/.*' --exclude 'vendor/.*' \
		      --exclude 'tools/fuzz/.*' --print-summary; \
	elif command -v gcov >/dev/null 2>&1; then \
		echo "== Rendering coverage via plain gcov (install lcov or gcovr for full report) =="; \
		gcov_sum=$$(mktemp); \
		find $(COV_BUILD_DIR) -name '*.gcda' \
		    -not -path '*/lib/test/*' -not -path '*/tools/fuzz/*' \
		    -print0 2>/dev/null \
		    | xargs -0 -r gcov -n 2>/dev/null \
		    > $$gcov_sum || true; \
		awk ' \
		    /^File / { cur=$$2; gsub(/'\''/, "", cur); \
		               sysheader = (index(cur, "/usr/") == 1 || index(cur, "vendor/") > 0 || index(cur, "lib/test/") > 0); \
		               next } \
		    /^Lines executed:/ { \
		        if (sysheader) next; \
		        split($$2, p, ":"); pct = p[2]; gsub(/%.*$$/, "", pct); \
		        total = $$4 + 0; \
		        exec = total * (pct+0) / 100.0; \
		        sum_exec += exec; sum_total += total; n++ \
		    } \
		    END { \
		        if (n > 0 && sum_total > 0) { \
		            printf "coverage: %d translation units, %d / %d lines executed (%.1f%%)\n", \
		                n, sum_exec, sum_total, 100.0 * sum_exec / sum_total; \
		            printf "(install lcov or gcovr for per-file breakdown + HTML report)\n" \
		        } else { \
		            printf "coverage: no .gcda data — did the test binary fail to run?\n" \
		        } \
		    }' $$gcov_sum; \
		rm -f $$gcov_sum *.gcov 2>/dev/null || true; \
	else \
		echo "WARN: install lcov, gcovr, or gcc's gcov to render the report."; \
		echo "Raw .gcda files are left in place for manual inspection."; \
	fi
	@rc=$$(cat $(COV_BUILD_DIR)/test_zcl_cov.exit 2>/dev/null || echo 0); \
	if [ "$$rc" != "0" ]; then \
		echo "coverage: FAIL — test_zcl_cov exited $$rc"; \
		exit "$$rc"; \
	fi

coverage-clean:
	@mkdir -p $(BUILD_DIR)
	@if [ "$(ZCL_COVERAGE_LOCKED)" = 1 ]; then \
		rm -rf $(COV_BUILD_ROOT) $(BIN_DIR)/coverage $(COV_INFO) $(COV_HTML) $(COV_TEST_BIN); \
	else \
		flock -x $(BUILD_DIR)/coverage.lock sh -c \
		  'rm -rf "$$1" "$$2" "$$3" "$$4" "$$5"' sh \
		  "$(COV_BUILD_ROOT)" "$(BIN_DIR)/coverage" "$(COV_INFO)" "$(COV_HTML)" "$(COV_TEST_BIN)"; \
	fi
	@echo "Coverage artifacts removed."

# ── ci ─────────────────────────────────────────────────────────
# Single command for full verification: build, test, fuzz (short),
# and coverage.  Fail-fast — stops at the first broken stage so
# you don't waste minutes on coverage when tests don't pass.
#
# Usage:
#   make ci                 # full pipeline
#   make ci SKIP_FUZZ=1     # skip the fuzz stage (faster)
#   make ci SKIP_COV=1      # skip coverage (faster)
# Mapped focused tests for the files being pushed. Unmapped code fails
# closed (add an impact rule) instead of expanding to the 941-group suite.
# Full-suite/fuzz/coverage remain on make install-quality-linger.
pre-push-ci:
	@mkdir -p "$(BUILD_DIR)"
	@$(CHECKOUT_LOCK_TOOL) $(CHECKOUT_LOCK_MODE) "$(CHECKOUT_LOCK)" -- \
	  env ZCL_FAST_LIVE=0 ZCL_FAST_COMPILE=strict \
	      ZCL_FAST_BUILD_SOURCE_RECORD="$(BUILD_SOURCE_RECORD)" \
	      tools/agent_fast_ci.sh pre-push

check-agent-cli: zclassic23
	@tools/scripts/check_agentdeployguard_cli_exit.sh

check-malloc:
	@echo "══ LINT: bare malloc/calloc/realloc in app/tools code ══"
	@./tools/lint/check_malloc.sh

check-raw-sqlite:
	@echo "══ LINT: raw sqlite3_step in app code ══"
	@tools/scripts/check_raw_sqlite.sh

check-vcs-no-git:
	@echo "══ LINT: lib/vcs is git-free + spawns no processes ══"
	@tools/scripts/check_vcs_no_git.sh

check-vcs-no-sha1:
	@echo "══ LINT: ZVCS/producer-source authority does not inherit Git SHA-1 ══"
	@tools/scripts/check_vcs_no_sha1.sh
	@tools/dev/source-identity-selftest.sh
	@tools/dev/sovereign-source-identity-selftest.sh

# Release purity for the Tier-1 hot-swap loader (HARD). Two invariants:
#   (1) no dlopen/dlsym/dlclose CALL in any .c outside lib/hotswap/ + vendor/;
#   (2) inside lib/hotswap sources, every such call sits within a
#       `#ifdef ZCL_DEV_BUILD` region (a pragmatic toggle scan — see below),
# so a release build links zero dynamic-loading code.
check-hotswap-dev-only:
	@echo "══ LINT: hot-swap dlopen confined to lib/hotswap under ZCL_DEV_BUILD ══"
	@./tools/lint/check_hotswap_dev_only.sh

# Tier-1 hot-swap eligibility manifest (config/hotswap_eligible.def) is kept
# honest by two REAL gates (self-tested in test_make_lint_gates.c): eligible
# TUs must be app-layer surfaces, and must hold no mutable file-scope statics
# (a .so gets its own zero copy). See docs/work/HOTSWAP.md.
check-hotswap-eligible-scope:
	@tools/lint/check_hotswap_eligible_scope.sh

# Scans the UNION of config/hotswap_eligible.def and
# config/hotswap_swappable.def: every TU either manifest can recompile into a
# .so must be free of mutable file-scope statics.
check-hotswap-static-state:
	@tools/lint/check_hotswap_static_state.sh

# Pure calculation service islands may own no ambient state or effects and may
# import only the stable symbols declared beside their frozen ABI/schema/wire/
# KAT fingerprints in config/hotswap_services.def.
check-hotswap-service-islands:
	@tools/lint/check_hotswap_service_islands.sh

# THE HARD LINE for the REAL (activatable) module ABI, both halves: every
# swappable source_tu (config/hotswap_swappable.def) must be owned by a
# controller/view/condition LEAF — never a reducer/consensus/storage/supervisor
# TU — AND every leaf in its leaf list must be declared ZCL_COMMAND_READY_READ
# (READY + read-only) in the config/commands catalog and be claimed by exactly
# one file. Self-tested with seeded-violation fixtures in
# test_make_lint_gates.c. See docs/work/HOTSWAP.md "Real module ABI".
check-hotswap-swappable-shape:
	@tools/lint/check_hotswap_swappable_shape.sh

# Prove the RELEASE binary links none of the dev-only mutation entry points
# (dispatcher, cycle, watcher, subprocess runner) NOR the native dev-lane
# activation engine (tools/dev/dev_activation*.c: stop/start the unit, flip
# the `current` generation symlink, exec `systemctl --user ...`). Structural
# proof always runs; the nm -D artifact proof runs when a fresh release
# binary is present.
check-release-no-dev-symbols:
	@tools/lint/check_release_no_dev_symbols.sh

# Phase-0 release containment.  Remove this gate only in the same reviewed
# change that lands immutable exact-candidate evidence, signed manifests, and
# the stable publisher; a copy-proof marker alone never authorizes upload.
check-stable-publish-contained:
	@echo "══ LINT: stable network publishing contained ══"
	@bash tools/scripts/check_stable_publish_containment.sh --self-test
	@bash tools/scripts/check_stable_publish_containment.sh

check-raw-malloc:
	@echo "══ LINT: raw malloc/calloc/realloc in production code ══"
	@tools/scripts/check_raw_malloc.sh

check-json-value-init:
	@echo "══ LINT: struct json_value initialised before first use ══"
	@tools/scripts/check_json_value_init.sh --self-test
	@tools/scripts/check_json_value_init.sh

check-blob-read-bounds:
	@echo "══ LINT: bounded sqlite blob reads in app models ══"
	@bash tools/lint/check_blob_read_bounds.sh

# Gate — ONE fixed-width byte-order codec. Packing or unpacking a
# 16/32/64-bit integer at a byte address lives only in
# lib/base/include/base/serialize_le.h; a private shift ladder anywhere else
# fails (RATCHET at file granularity; tools/lint/byte_order_codec_baseline.txt
# may only shrink). 23 hand-rolled helpers across 11 files existed when this
# gate was written, despite a canonical set already sitting in
# crypto/common.h that only seven files used.
check-byte-order-codec-single:
	@echo "══ LINT: one byte-order codec ══"
	@./tools/lint/check_byte_order_codec_single.sh --selftest
	@./tools/lint/check_byte_order_codec_single.sh

check-coins-lookup-nullcheck:
	@echo "══ LINT: guarded controller coin lookups ══"
	@tools/scripts/check_coins_lookup_nullcheck.sh

.PHONY: tools/check_observability_pairing
tools/check_observability_pairing: $(BIN_DIR)/check_observability_pairing
$(BIN_DIR)/check_observability_pairing: tools/check_observability_pairing.c
	@mkdir -p $(dir $@)
	$(CC) -std=c23 -O2 -Wall -Wextra -Werror -o $@ $<

check-observability-pairing: tools/check_observability_pairing
	@echo "══ LINT: observable stderr diagnostics ══"
	@$(BIN_DIR)/check_observability_pairing

# ── Sealed consensus core (Wave 1.1 / W0) ───────────────────────────────────
# core/ is the physical sealed consensus tree (predicates + static param
# tables). core_seal is a tiny build-time C tool (no external deps: it links the
# in-tree FIPS-202 SHA3-256 + memory_cleanse) that reads the file list on stdin
# (git ls-files -z) and writes/verifies core/MANIFEST.sha3. See tools/core_seal.c
# and core/UNSEAL.md for the ritual.
.PHONY: core-seal core-seal-check core-unseal check-core-seal check-core-include-boundary check-accel-oracle-pinned check-no-adx-overclaim check-simd-os-support
CORE_MANIFEST := core/MANIFEST.sha3
CORE_UNSEAL_TOKEN := .core-unseal-token
# The sealed set: every tracked file under core/ (consensus predicates +
# parameter tables) PLUS the block-connection ordering layer below. An
# ordering bug in connect_block/chainstate forks the node exactly as hard as
# a bug in a sealed check_block predicate (2026-08-01 review), so those files
# carry the same ritual: editing them requires `make core-unseal REASON=…`.
CORE_SEAL_PATHS := core/ \
    lib/validation/src/connect_block.c \
    lib/validation/src/chainstate.c \
    lib/validation/include/validation/connect_block.h \
    lib/validation/include/validation/chainstate.h
CORE_SEAL_SRCS := tools/core_seal.c lib/sha3/src/sha3.c lib/crypto/src/keccak_x4.c lib/crypto/src/simd_dispatch.c lib/base/src/cleanse.c

.PHONY: tools/core_seal
tools/core_seal: $(BIN_DIR)/core_seal
$(BIN_DIR)/core_seal: $(CORE_SEAL_SRCS)
	@mkdir -p $(dir $@)
	$(CC) -std=c23 -O2 -Wall -Wextra -Werror \
	    -Ilib/sha3/include -Ilib/crypto/include -Ilib/support/include -Ilib/base/include \
	    -o $@ $(CORE_SEAL_SRCS)

# Freeze the seal: recompute and (re)write core/MANIFEST.sha3 over every tracked
# file in CORE_SEAL_PATHS (excluding the manifest itself), and consume any active
# unseal token (the ritual is complete once the seal is re-frozen).
core-seal: tools/core_seal
	@echo "══ core: sealing consensus core → $(CORE_MANIFEST) ══"
	@git ls-files -z $(CORE_SEAL_PATHS) | $(BIN_DIR)/core_seal seal $(CORE_MANIFEST)
	@rm -f $(CORE_UNSEAL_TOKEN)

# Verify the seal: fail LOUD if any sealed path drifts from core/MANIFEST.sha3.
# Honors an active .core-unseal-token (owner-run unseal ritual) for exactly one commit.
core-seal-check: tools/core_seal
	@echo "══ core: verifying consensus-core seal ══"
	@if [ -f "$(CORE_UNSEAL_TOKEN)" ]; then \
	    echo "core-seal-check: unseal token present — seal check LIFTED for this commit"; \
	    echo "  (token: $$(cat $(CORE_UNSEAL_TOKEN) 2>/dev/null | head -1)); re-run 'make core-seal' to refreeze."; \
	    git ls-files -z $(CORE_SEAL_PATHS) | $(BIN_DIR)/core_seal check $(CORE_MANIFEST) || true; \
	else \
	    git ls-files -z $(CORE_SEAL_PATHS) | $(BIN_DIR)/core_seal check $(CORE_MANIFEST); \
	fi

# Owner-run unseal ritual: record the reason + current ROOT hash in the
# append-only core/UNSEAL.md and mint a one-shot .core-unseal-token (gitignored)
# that core-seal-check honors until the next 'make core-seal'. REASON is
# mandatory. No agent source edit can produce this — it is an owner make target.
core-unseal:
	@if [ -z "$(REASON)" ]; then \
	    echo "core-unseal: REASON is required — 'make core-unseal REASON=\"why\"'" >&2; \
	    exit 2; \
	fi
	@ts=$$(date -u +%Y-%m-%dT%H:%M:%SZ); \
	old=$$(grep -E '^ROOT ' $(CORE_MANIFEST) 2>/dev/null | awk '{print $$2}'); \
	old=$${old:-<none>}; \
	printf '\n- %s — REASON: %s\n  old ROOT: %s\n  by: owner unseal ritual (make core-unseal)\n' \
	    "$$ts" "$(REASON)" "$$old" >> core/UNSEAL.md; \
	printf 'unsealed %s\nreason: %s\nold-root: %s\n' "$$ts" "$(REASON)" "$$old" > $(CORE_UNSEAL_TOKEN); \
	echo "core-unseal: token minted ($(CORE_UNSEAL_TOKEN)); seal lifted for one commit."; \
	echo "  Make the core/ edit, then 'make core-seal' + 'make lint && make test_parallel' before commit."

# ── ZVCS unseal ritual (owner-run, separate from core-unseal above) ────────
# ZVCS's own sealed-path pin (lib/vcs/src/vcs_seal.c: pin in .zvcs/index.kv,
# one-shot token via vcs_seal_grant_unseal()) has no operator surface of its
# own — nothing outside lib/test ever called the grant primitive. This
# target is that surface: it mirrors core-unseal's shape (REASON mandatory,
# an append-only record, a one-shot token) but drives the registry-owned
# dev.vcs.seal.grant command (tools/command/native_dev_command.c) instead of
# writing core/UNSEAL.md directly. It authorizes exactly the CURRENT tree's
# sealed content (app/jobs/, core/, lib/consensus/, ... — see
# .zvcs/sealed_paths or the compiled default set) for the next ZVCS
# green-cycle anchor (vcs_snapshot); a further sealed-path change after that
# anchor requires a new grant. No agent source edit can produce this — it is
# an owner make target.
.PHONY: zvcs-unseal
zvcs-unseal: dev-bin
	@if [ -z "$(REASON)" ]; then \
	    echo "zvcs-unseal: REASON is required — 'make zvcs-unseal REASON=\"why\"'" >&2; \
	    exit 2; \
	fi
	@echo "══ zvcs-unseal: authorizing exactly the CURRENT tree's sealed content for ONE anchor ══"
	@reason_json=$$(printf '%s' "$(REASON)" | sed 's/\\/\\\\/g; s/"/\\"/g'); \
	$(ZCLASSIC23_DEV_BIN) dev vcs seal grant \
	    --input="{\"reason\":\"$$reason_json\",\"confirm\":true}"

# HARD lint gate for the seal (frozen at W5 — the whole W0–W4 split has landed).
# core/ drift now FAILS the build unless an owner unseal token is active. A
# deliberate consensus-core change goes through `make core-unseal REASON=…`
# (records the reason in the append-only core/UNSEAL.md + mints the one-shot
# token), lands green on the parity + domain-consensus groups, then re-freezes
# with `make core-seal`.
check-core-seal: tools/core_seal
	@echo "══ LINT: consensus-core seal (HARD) ══"
	@if [ -f "$(CORE_UNSEAL_TOKEN)" ]; then \
	    echo "check-core-seal: unseal token present — seal check lifted for this commit"; \
	    echo "  (owner unseal ritual active; re-run 'make core-seal' to refreeze before commit.)"; \
	    git ls-files -z $(CORE_SEAL_PATHS) | $(BIN_DIR)/core_seal check $(CORE_MANIFEST) || true; \
	else \
	    git ls-files -z $(CORE_SEAL_PATHS) | $(BIN_DIR)/core_seal check $(CORE_MANIFEST); \
	fi

# Sealed-core include boundary: core/ may not depend upward/sideways (esp. not
# on lib/validation). Clone of check_domain_purity.sh over the core/ subdirs.
check-core-include-boundary:
	@echo "══ LINT: sealed consensus-core include boundary ══"
	@./tools/scripts/check_core_include_boundary.sh

# Accelerator-oracle pin: the core/ seal covers the TEXT of the consensus
# predicates, not the ISA-dispatched arithmetic they call (SHA-256, batched
# BLAKE2b for Equihash, BLS12-381/BN254 Montgomery multiply). Those files must
# stay editable for speed, so they are pinned by property instead of by bytes:
# each one carries a differential oracle proving it byte-identical to a
# portable reference. Registry: tools/lint/accel_oracle_registry.txt
check-accel-oracle-pinned:
	@echo "══ LINT: accelerator differential-oracle pin (below the core seal) ══"
	@./tools/lint/check_accel_oracle_pinned.sh

# ADX overclaim: a crypto tier may not advertise ADCX/ADOX carry chains its own
# object code does not contain. The oracle above proves an accelerator computes
# the RIGHT answer; this one proves its operator-visible label describes the
# instructions it actually runs. target("bmi2,adx") only makes the compiler
# WILLING to emit ADCX/ADOX — both intrinsics lower to plain ADC — so the boot
# banner said "MULX+ADCX+ADOX" over an object with zero of either for months.
# The gate compiles each claiming file the way the node ships it and reads the
# disassembly.
check-no-adx-overclaim:
	@echo "══ LINT: no ADCX/ADOX carry-chain overclaim ══"
	@./tools/lint/check_no_adx_overclaim.sh
	@./tools/lint/check_asan_adx_exception.sh --selftest
	@./tools/lint/check_asan_adx_exception.sh

# SIMD OS-support: CPUID reports what the silicon decodes, not whether the OS
# agreed to save the register state. A dispatch predicate that reads only the
# CPUID bit takes a SIGILL on a host booted `noxsave` / `clearcpuid=…` or under
# a hypervisor that masks XCR0 — and blake2b_avx2.c, which is Equihash PoW
# verification, dispatched its AVX2 tier on exactly that. This gate requires
# every target("avx…") file to reach the audited predicate in
# crypto/simd_dispatch.h, read XCR0 with an OSXSAVE guard itself, or delegate
# to a named predicate that does.
check-simd-os-support:
	@echo "══ LINT: SIMD dispatch checks OS state, not just CPUID ══"
	@./tools/lint/check_simd_os_support.sh

check-silent-errors-services:
	@echo "══ LINT: silent error returns in services ══"
	@./tools/lint/check_silent_error_returns.sh app/services/src services service \
	    "use LOG_ERR/LOG_FAIL/LOG_RETURN, prev-line error log, or mark // raw-return-ok:<reason>"

check-silent-errors-controllers:
	@echo "══ LINT: silent error returns in controllers ══"
	@./tools/lint/check_silent_error_returns.sh app/controllers/src controllers controller \
	    "use LOG_ERR/LOG_RETURN, prev-line fprintf, or mark // raw-return-ok:<reason>"

check-silent-errors-jobs:
	@echo "══ LINT: silent error returns in jobs ══"
	@./tools/lint/check_silent_error_returns.sh app/jobs/src jobs job \
	    "use LOG_ERR/LOG_FAIL/LOG_RETURN, prev-line error log, or mark // raw-return-ok:<reason>"

check-silent-errors-conditions:
	@echo "══ LINT: silent error returns in conditions ══"
	@./tools/lint/check_silent_error_returns.sh app/conditions/src conditions condition \
	    "use LOG_ERR/LOG_FAIL/LOG_RETURN, prev-line error log, or mark // raw-return-ok:<reason>"

# Closes the bool/`return false;` blind spot of the four int-convention gates
# above: flags a NEW swallowed call failure (if (!call(...)) return false; with
# no LOG_*). RATCHET (shrink-only) — today's population is baselined.
check-silent-errors-bool:
	@echo "══ LINT: silent call-guard return-false (RATCHET) ══"
	@ZCL_LINT_MODE=FAIL ./tools/lint/check_silent_bool_errors.sh

check-log-macro-return-type:
	@echo "══ LINT: LOG_* macro return type pairing ══"
	@./tools/lint/check_log_macro_return_type.sh

# Closes the raw sqlite3_prepare_v2() + unlogged NULL-check blind spot (the
# wallet_tx.c class the other silent-error gates do not see): a BARE prepare
# followed by `if (!stmt) return ...;` with no LOG_* between them. RATCHET
# (shrink-only) — today's population is baselined.
check-wallet-raw-prepare-log:
	@echo "══ LINT: raw sqlite3_prepare_v2 unlogged NULL-check (RATCHET) ══"
	@ZCL_LINT_MODE=FAIL ./tools/lint/check_wallet_raw_prepare_log.sh

check-before-save-hooks:
	@echo "══ LINT: critical models wire before_save hooks ══"
	@./tools/lint/check_before_save_hooks.sh

# Move 4: every long-running thread goes through thread_registry_spawn{,_ex}.
# Short-burst workers joined within the same function, and pthread_attr-using
# detached-helper wrappers, are explicitly opted out with a `raw-pthread-ok`
# marker on the call line or the line immediately above. The registry's own
# implementation in lib/util/src/thread_registry.c is implicitly skipped.
check-pthread-create:
	@echo "══ LINT: raw pthread_create outside thread_registry ══"
	@./tools/lint/check_pthread_create.sh

# Move 11: every app/models/src/*.c either invokes validates_* macros
# from app/models/include/models/activerecord.h, or carries an
# ar-validate-skip:<tag> marker explaining why the AR validation
# lifecycle does not apply (infrastructure wrapper, registry, etc.).
check-model-validation:
	@echo "══ LINT: model validation coverage ══"
	@./tools/scripts/check_model_validation.sh

check-model-ar-lifecycle:
	@echo "══ LINT: model ActiveRecord lifecycle saves ══"
	@./tools/scripts/check_model_ar_lifecycle.sh

# Keep top-level functions in app/controllers + app/services under 500
# lines. Single state-machines that truly belong as one function can carry
# a `// long-function-ok:<tag>` override marker explaining WHY.
check-long-functions:
	@echo "══ LINT: long function cap (500 lines) ══"
	@./tools/scripts/check_long_functions.sh

# Wave 9a: every register_*_rpc_commands callsite uses rpc_table_must_append.
# rpc_table_append returns false silently on registration failure (duplicate
# name / MAX_RPC_COMMANDS cap / table running) — that silent failure mode
# left the control-group RPCs unreachable for a release cycle. The
# must_append variant aborts at boot with a precise reason.
check-rpc-registrar:
	@echo "══ LINT: rpc_table_must_append in registrars ══"
	@./tools/scripts/check_rpc_registrar.sh

# Lag-SLO observability: the legacy_mirror_sync_service must emit
# EV_LAG_SLO_BREACH and EV_MIRROR_CONCURRENT_CATCHUP, and the
# chain_advance_coordinator must honor mirror_lag_sla_breach_blocks.
# Prevents the "silent lag" regression we shipped this gate to lock down.
check-lag-slo-observable:
	@echo "══ LINT: lag SLO observability ══"
	@./tools/scripts/check_lag_slo_observable.sh

# lib/ layer purity: no lib/ file should #include from app/ unless the
# include is in the grandfathered baseline or has a documented per-line
# override marker. Catches regressions; lets us pay down the existing
# debt incrementally.
check-lib-layering:
	@echo "══ LINT: lib/ layer purity ══"
	@./tools/scripts/check_lib_layering.sh

# lib/ module link order. config/lib_module_order.def declares every lib module
# in link order (rank = line position) and a module may reference only strictly
# lower ranks. Unlike check-lib-layering above, which greps #include lines, this
# gate asks the linker: tools/dev/module-linkgraph.sh joins nm's defined and
# undefined symbols over the compiled objects, so it also sees a module reached
# through a bare `extern` with no include at all.
#
# ARMING. It measures ONE object tree — build/obj, the production compile tree —
# and `make build-only` is the one and only command that populates it, so that
# is the canonical arming path; `make lint-armed` below runs it and then lint
# with this gate made mandatory. A plain `make` does NOT arm it: every binary in
# `all` is a single whole-program `cc` over $(ALL_SRCS) with no -c step and
# leaves zero .o behind. `make test*` populates build/test-rel-obj, which the
# gate deliberately ignores — those objects are -O3 non-LTO with -DZCL_TESTING
# and carry references the shipped binary does not have, so scoring them against
# a build/obj baseline manufactures violations. Unarmed, the gate prints
# NOT MEASURED and exits 0 rather than failing on unmodified code.
#
# Baseline tools/scripts/lib_module_order_baseline.txt grandfathers the 5 back
# edges that are the proven-minimum feedback arc set over the two cycles in the
# graph; it may only shrink.
check-lib-module-order:
	@echo "══ LINT: lib/ module link order ══"
	@./tools/scripts/check_lib_module_order.sh

# Lint with the link-graph gate actually armed and MANDATORY: compile the
# objects it measures, then refuse to accept "NOT MEASURED" as a pass. Plain
# `make lint` stays fast and skips it when build/obj is cold; this is the target
# to run when you want every gate enforced.
.PHONY: lint-armed
lint-armed:
	@$(MAKE) --no-print-directory build-only
	@ZCL_LINT_REQUIRE_LINKGRAPH=1 $(MAKE) --no-print-directory lint

# Inter-shape include direction: the eight app/ shapes include DOWNWARD only
# (controllers -> services -> models -> lib/core). Flags app/models/** files
# including "services/..." or "controllers/...", and app/services/** files
# including "controllers/...". Baseline
# tools/scripts/shape_include_direction_baseline.txt grandfathers pre-existing
# debt; override with `// shape-layer-ok:<tag>`.
check-shape-include-direction:
	@echo "══ LINT: inter-shape include direction ══"
	@./tools/scripts/check_shape_include_direction.sh

# domain/ source purity: the innermost layer may only #include its own
# domain headers, C/system headers, bare domain-local siblings, and the 12
# allowed lib subsystems (bloom chain coins consensus core crypto keys
# primitives script support util validation). Any include from an app/ shape
# (controllers/models/services/views) or an unlisted lib/ subsystem fails the
# build. HARD gate, no baseline (the tree is clean).
check-domain-purity:
	@echo "══ LINT: domain/ source purity ══"
	@./tools/scripts/check_domain_purity.sh

# Supervisor registration: every long-running service in
# app/services/src/*_service.c must register a liveness contract with
# the supervisor (Round 5) OR appear in supervisor_baseline.txt OR
# carry a per-file `// supervisor-ok:<tag>` override marker. Drives
# opt-in adoption of the supervisor primitive over Rounds 6-8.
check-supervisor-registration:
	@echo "══ LINT: supervisor registration ══"
	@./tools/scripts/check_supervisor_registration.sh

# Test-registration drift guard. A test entry point (test_<name>.c defining
# int test_<name>(void)) that is in NEITHER the canonical test group catalog
# NOR dispatched by the serial runner (test.c) is COMPILED
# but never executed — green forever, proving nothing. Caught the lane-3
# refold orphans (2026-06-22). Fails CI on any such orphan.
check-test-registration:
	@echo "══ LINT: test registration ══"
	@./tools/scripts/check_test_registration.sh

# Gate — no NEW runtime abort primitive in network-reachable code (RATCHET,
# shrink-only baseline tools/lint/no_runtime_abort_baseline.txt). assert() is
# LIVE in this build: -DNDEBUG is set only for the vendored LevelDB compile
# (tools/scripts/build_vendor.sh), never in the node's own CFLAGS above. So an
# assert() on a path a peer, an RPC argument, an explorer URL segment or a
# stored blob can reach is a remote process-kill primitive — which is exactly
# what the Base58 codec, BIP32 public child derivation and xpub serialization
# were until they were converted to error returns. _Static_assert is
# compile-time and is NOT counted. An abort that is correct (softening it would
# leak plaintext or forge a key) is annotated in place with
# `// abort-ok:<reason>` instead of being buried in the baseline.
check-no-runtime-abort:
	@echo "══ LINT: no runtime abort primitive ══"
	@./tools/lint/check_no_runtime_abort.sh

# Lint gate #16 — typed blocker primitive adoption (Round 6 C6).
# Ratchets raw `char *_blocker[]` string fields / `lms_set_blocker(`
# legacy setters / `last_blocker_code` mutations to the typed
# `blocker_set()` primitive (lib/util/blocker.h). Baseline file
# enumerates the grandfathered sites; must shrink over Rounds 7-9.
check-typed-blocker:
	@echo "══ LINT: typed blocker adoption ══"
	@./tools/scripts/check_typed_blocker.sh

# Gate #49 — blocker escape-action totality (HARD, no baseline). Every
# non-empty escape_action string literal assigned at a blocker_init/
# blocker_set call site (app/ config/ lib/ src/, excluding lib/test) must
# resolve to a blocker_register_escape() registration somewhere in the tree.
# A misspelled or never-registered name silently dead-ends
# blocker_supervisor_sweep's lookup (lib/util/src/blocker.c ~:492) and is
# invisible to the blocker_stall_meta_detector.c empty-escape backstop too
# (that one only catches an EMPTY string). Empty strings are exempt.
check-blocker-escape-registered:
	@echo "══ LINT: blocker escape-action totality ══"
	@./tools/scripts/check_blocker_escape_registered.sh

# Gate — blocker remedy totality (HARD, no baseline; ratchets by exhaustive
# enumeration instead). Doctrine: docs/work/tenacity-roadmap.md "Hold-class
# doctrine" (`utxo_apply.nullifier_backfill_gap` had ZERO auto-remedy path
# anywhere in the tree and wedged the canonical node for weeks): a typed blocker with an
# empty escape_action and no auto-remedy condition looks exactly like any
# other well-formed typed blocker. This gate makes every blocker id/pattern a
# production call site can raise resolve to a checked-in row in
# app/conditions/include/conditions/blocker_remedy_bindings.def — a real
# condition name (checked to exist) or the honest token OWNER — so a new
# permanent-no-cure blocker cannot be added without declaring that fact.
check-blocker-remedy:
	@echo "══ LINT: blocker remedy totality ══"
	@./tools/scripts/check_blocker_remedy.sh

# Gate — blocker HAND-OFF declaration (RATCHET, shrink-only baseline
# tools/lint/blocker_handoff_baseline.txt). check-blocker-remedy above proves
# every raisable id has SOME row; OWNER satisfies it. That answers "does
# anything auto-heal this?" and stops — it never answers "what am I supposed
# to do?". Measured on the canonical node 2026-07-27,
# address_index.below_snapshot_seed had fired 11,666 times with
# escape_action "" and retry_budget 0. This gate requires every id a
# production site can raise with an EMPTY escape action to carry either an
# automatic remedy (condition healer / ESCAPE(action)) or an explicit
# ZCL_BLOCKER_DECISION row spelling out the decision the operator owns. The
# baseline may only shrink; a stale entry fails too.
check-blocker-handoff-declared:
	@echo "══ LINT: blocker hand-off declaration ══"
	@./tools/lint/check_blocker_handoff_declared.sh

# Every supervised child must declare a progress policy — ARMED (a frozen
# progress marker raises NO_PROGRESS) or EXEMPT with an operator-readable
# reason. The zero-initialised field made "nobody decided" and "deliberately
# off" the same value, which is how chain.op_return_backfill reached
# ticks_run 13083 / blocks_folded 0 / stall_reason "none". Counts shrink only.
check-supervisor-progress-declared:
	@echo "══ LINT: supervisor progress-policy declaration ══"
	@./tools/lint/check_supervisor_progress_declared.sh

# Gate #18 graduated WARN → RATCHET (E10): fails on any new off-shape
# app/ .c file (the allowlist is the baseline and is currently empty).
check-framework-shape:
	@echo "→ Gate #18: framework_shape_check"
	@ZCL_LINT_MODE=RATCHET ./tools/lint/framework_shape_check.sh

# Gate #22 — framework filename suffix (HARD). The recurrence guard for the
# S1 service renames: no app/ file may carry a foreign shape's name suffix
# (e.g. *_controller.c in services/). Override: // suffix-ok:<tag>.
check-framework-filename-suffix:
	@echo "→ Gate #22: framework_filename_suffix"
	@./tools/lint/check_framework_filename_suffix.sh

check-no-raw-clock-outside-platform:
	@echo "→ Gate #19: no_raw_clock_outside_platform"
	@./tools/lint/check_no_raw_clock_outside_platform.sh

# Gate: sysinit boot-boundary ordering (HARD). Pins the deterministic
# (stage, order, name) run order of the declarative boot-stage records in
# config/src/boot.c against a golden file. See check_sysinit_ordering.sh.
check-sysinit-ordering:
	@echo "→ Gate: sysinit_ordering"
	@./tools/lint/check_sysinit_ordering.sh

# Gate: sandbox wiring (HARD). Asserts boot registers the os_sandbox
# steady-state record so -sandbox=steady can never regress to zero
# confinement. See check_sandbox_wired.sh.
check-sandbox-wired:
	@echo "→ Gate: sandbox_wired"
	@./tools/lint/check_sandbox_wired.sh

# Gate: peer-floor single source of truth (HARD). The healthy-outbound floor
# is defined once in net/net.h as ZCL_PEER_FLOOR_HEALTHY; the connman dialer,
# the net.outbound_floor supervisor child, and the peer_floor_violated
# condition must all read it and never reintroduce a retired local literal
# macro. Fails loud on an empty scan (repo law 10). See
# check_peer_floor_single_source.sh.
check-peer-floor-single-source:
	@echo "→ Gate: peer_floor_single_source"
	@./tools/lint/check_peer_floor_single_source.sh

# os-substrate Rung 0: no system()/popen()/execlp() in the resident node
# binary's own code — every shell-out migrated onto lib/util spawn +
# file_tree_ops. HARD (FAIL); tools/ and lib/test/ are out of scope.
check-no-shellouts:
	@echo "→ Gate: no_shellouts (os-substrate Rung 0)"
	@./tools/lint/check_no_shellouts.sh

# The cheap half of the fuzz-artifact replay contract (21 ms, text + git only):
# every saved finding under lib/test/fuzz_seeds/ has a live fuzz binary behind
# it and a written verdict in ARTIFACT_VERDICTS.txt, with no orphan entries and
# no untracked repro sitting uncommitted in the corpus. The replay itself needs
# the nine fuzz binaries (34 s to build cold at -j6), so it lives in `make fuzz-replay`,
# which `make ci` and the fuzz-replay CI job run. A 2026-07-14 hang sat unread
# for two weeks because no build ever read a fuzz verdict; this is the half of
# that route that is cheap enough for the inner loop.
check-fuzz-artifact-ledger:
	@echo "→ Gate: fuzz_artifact_ledger (every saved finding has a verdict)"
	@./tools/lint/check_fuzz_artifact_replay.sh --ledger-only

# Every standalone tool rule in this file must actually build. lint/
# test-parallel/ci build the node, the test runners, the fuzzers and two lint
# helpers — nothing else — so every other $(BIN_DIR)/<tool> rule was reachable
# from no gate and rotted silently. The tool list is DERIVED from this
# Makefile (fail-closed: a new tool is covered the day it lands).
check-standalone-tools-link:
	@echo "→ Gate: standalone_tools_link (every tool rule still builds)"
	@./tools/lint/check_standalone_tools_link.sh

# North Star invariant 1 (single writer per frontier), made mechanical for the
# sealed ROM segment store: only the designated sealer/RPC/healer/writer surface
# may call the store's WRITE API (chain_segment_seal_range /
# chain_segment_manifest_rebuild). See
# tools/lint/check_no_writer_below_sealed_frontier.sh for the rationale.
check-no-writer-below-sealed-frontier:
	@echo "→ Gate: no_writer_below_sealed_frontier (sealed ROM segment store)"
	@./tools/lint/check_no_writer_below_sealed_frontier.sh

# os-substrate Rung 1: no raw /proc/self/* or /proc/uptime reads outside
# lib/platform/ — every such read migrates onto platform/os_proc.h.
# RATCHET: tools/lint/proc_self_shim_baseline.txt grandfathers today's
# sites; shrink-only.
check-proc-self-shim:
	@echo "→ Gate: proc_self_shim (os-substrate Rung 1)"
	@./tools/lint/check_proc_self_shim.sh

# Gate #48: privileged transitions require an independent authority receipt
# (Law 7, OS-A1). Every owner-mutating native command leaf must be
# dispositioned (receipt:/exempt:) in
# tools/lint/privileged_transition_receipt_baseline.txt; a new one FAILS.
.PHONY: check-privileged-transition-receipt
check-privileged-transition-receipt:
	@echo "→ Gate: privileged-transition-receipt (Law 7, OS-A1)"
	@./tools/lint/check_privileged_transition_receipt.sh

# Gate — no ordinal comparison of enum sync_trust_state. The sync-trust states
# (services/sync_trust_policy.h) are ORTHOGONAL provenance facts, not a trust
# ordinal, so any </<=/>/>= against a SYNC_TRUST_* value is a latent
# authorization bug. Authorization must route through the capability mask.
check-no-trust-state-ordering:
	@echo "══ LINT: no ordinal sync_trust_state comparison ══"
	@./tools/scripts/check_no_trust_state_ordering.sh

# The shipped node, development binary, tests and vendor builder have one
# compiled-language path: C23. Historical external vectors may retain source
# attribution, but no Rust source, manifest, toolchain, archive, linker flag or
# FFI route may re-enter the executable tree.
check-c23-only:
	@echo "══ LINT: C23-only build and runtime ══"
	@./tools/lint/check_c23_only.sh --selftest
	@./tools/lint/check_c23_only.sh

# No Python source, shebang, or runtime invocation in the executable tree.
# Historical vector comments may name a Python origin; they must not call it.
check-no-python:
	@echo "══ LINT: no Python runtime ══"
	@./tools/lint/check_no_python.sh --selftest
	@./tools/lint/check_no_python.sh

# The GNU comma-swallowing extension `, ##__VA_ARGS__` is not standard C, and
# it is the single idiom that made this tree unbuildable by a second compiler:
# one use in a header included by ~1100 translation units produced over seven
# thousand diagnostics under `clang -std=c23 -pedantic`. C23 spells it
# `__VA_OPT__(,) __VA_ARGS__` with an identical token stream.
check-no-gnu-va-args:
	@echo "══ LINT: C23 __VA_OPT__, never the GNU comma-swallowing extension ══"
	@./tools/lint/check_no_gnu_va_args.sh

# Second-compiler portability. The node ships as one whole-program GCC build,
# so nothing ever asked a different compiler whether the tree is well-formed
# and GCC-only spellings landed invisibly — including real undefined behaviour
# in lib/net/src/p2p_game.c that only clang rejects. Ratchets realized
# diagnostic sites against a recorded baseline. SKIPs loudly when clang is
# absent, so a contributor without it is never blocked by a tool they lack.
check-clang-portability:
	@echo "══ LINT: second-compiler portability (clang -std=c23 -pedantic) ══"
	@./tools/lint/check_clang_portability.sh --self-test && ./tools/lint/check_clang_portability.sh

# C23 lets a `(void)` cast suppress [[nodiscard]], so annotating
# struct zcl_result fences off NEW silent discards but cannot excavate the
# existing ones. This is the excavator: a shrink-only ratchet over the cast
# discards that remain. Fix one with ZCL_IGNORE_RESULT(expr, "reason").
check-result-discard:
	@echo "══ LINT: zcl_result cast-discard (RATCHET) ══"
	@ZCL_LINT_MODE=FAIL ./tools/lint/check_result_discard.sh

# Gate #20 graduated WARN → RATCHET (E10): fails on any new controller
# file that uses raw sqlite. Baseline of grandfathered files lives in
# tools/lint/no_raw_sqlite_in_controllers_baseline.txt (may only shrink).
check-no-raw-sqlite-in-controllers:
	@echo "→ Gate #20: no_raw_sqlite_in_controllers"
	@ZCL_LINT_MODE=RATCHET ./tools/lint/check_no_raw_sqlite_in_controllers.sh

check-supervisor-domain:
	@echo "→ Gate #21: supervisor_domain"
	@./tools/lint/check_supervisor_domain.sh

# Gate #23: universal thread supervision (RATCHET). Every long-running thread
# spawned via thread_registry_spawn must be on the supervisor liveness tree
# (via util/thread_liveness.h, supervisor_register{,_in_domain}, or a
# // supervised: marker), explicitly exempted (// thread-supervision-ok:), or
# baselined in tools/lint/thread_supervision_baseline.txt (shrink-only).
check-thread-supervision:
	@echo "→ Gate #23: thread_supervision"
	@./tools/lint/check_thread_supervision.sh

# Gate P1 (docs/work/palace-design.md §3) — every indexed .c/.h under the
# codeindex roots has a DERIVABLE one-line purpose (a substantive top-of-file
# comment or an explicit `purpose:` override). RATCHET against the shrink-only
# tools/lint/file_purpose_baseline.txt; graduates to FAIL when it empties.
check-file-purpose:
	@echo "→ Gate P1: check_file_purpose"
	@ZCL_LINT_MODE=RATCHET ./tools/lint/check_file_purpose.sh

# Gate P2 (docs/work/palace-design.md §3) — every navigator group node
# emitted by ci_group_emit_all() has a non-empty ci_group_purpose() (HARD:
# the group population is finite and filled in full, so no ratchet needed).
check-group-purpose:
	@echo "→ Gate P2: check_group_purpose"
	@ZCL_LINT_MODE=FAIL ./tools/lint/check_group_purpose.sh

# Gate P3 (docs/work/palace-design.md §3) — every tracked .c/.h resolves to a
# known navigator group (lib/<mod>, app/<shape>, core, config, tools, domain,
# adapters, ports); a file falling through to the catch-all "root" group is a
# violation. RATCHET against the shrink-only
# tools/lint/orphan_placement_baseline.txt (palace P4.4); graduates to FAIL
# when it empties.
check-no-orphan-placement:
	@echo "→ Gate P3: check_no_orphan_placement"
	@ZCL_LINT_MODE=RATCHET ./tools/lint/check_no_orphan_placement.sh

# Gate E13 — consensus-parity guard (HARD). Bans any non-zclassicd consensus
# mechanism (miner-signaled versionbits / dynamic Equihash override — the
# PR #6 "sidegrade" class) from the consensus path, so zclassic23 stays
# bit-for-bit consensus-compatible with zclassicd. Doctrine:
# docs/CONSENSUS_PARITY_DOCTRINE.md; the golden VALUES are pinned by the
# test_consensus_parity test group.
check-consensus-parity:
	@echo "══ LINT: consensus parity with zclassicd (E13) ══"
	@./tools/scripts/check_consensus_parity.sh

# Gate — command-contract ratchet (lane OS-B1). Every native command leaf in
# config/commands/*.def must supply a non-empty `semantics` argument (the
# OUTPUT-interpretation contract). The compiler enforces presence; this gate
# rejects the empty/blank placeholder and fails loud on a hollow scan.
check-command-contract:
	@echo "══ LINT: command-contract semantics ══"
	@./tools/lint/check_command_contract.sh

# Gate — command-availability truthfulness (HARD). The `availability` a leaf
# declares in config/commands/*.def must match what the catalog actually
# binds: a READY leaf must bind a non-NULL handler (READY with no handler
# advertises a command the engine cannot dispatch), and a PLANNED/COMPAT leaf
# must state a non-empty availability_reason (a typed refusal with no stated
# cause is a silent stall). Parses the macro grammar and aborts LOUD on arity
# drift rather than reading the wrong argument slot.
check-command-availability-truthful:
	@echo "══ LINT: command-availability truthfulness ══"
	@./tools/lint/check_command_availability_truthful.sh

# Gate — declared input_keys vs. the keys the handler actually READS. The
# kernel rejects any input key a leaf does not declare, so a key the C
# consumes but the .def omits is unreachable from the real CLI and the
# command is uncallable (zcode.package.publish.plan required recipe_hex and
# never declared it: pass it -> INVALID_INPUT, omit it -> RECIPE_MISSING).
# Reads the .def AND the C it binds; check-command-contract is a different
# predicate (see that script's header) and neither subsumes the other.
check-command-input-keys:
	@echo "══ LINT: command input_keys vs. handler reads ══"
	@./tools/lint/check_command_input_keys.sh

# Gate — a leaf declared READ may not reach the datadir BOOT CEREMONY.
# `app service access` was READY_READ/AUTH_PUBLIC/IDEMPOTENT and called
# node_db_open(): READWRITE|CREATE, quarantine-rename on a failed
# quick_check, create_schema, node_db_migrate, and DELETE FROM
# snapshot_staging_utxos — against a datadir that DEFAULTS to the operator's
# live node. Five more leaves were wrong the same way, in three different
# files, which is why this gate follows the CALL GRAPH from the declaration
# instead of policing one source file. node_db_open_runtime does not escape
# it: the closure walks on to create_schema.
check-read-leaf-no-boot-ceremony:
	@echo "══ LINT: read leaf must not reach the boot ceremony ══"
	@./tools/lint/check_read_leaf_no_boot_ceremony.sh

# Gate — telemetry-ontology coverage. Every network telemetry field a covered
# dumpstate function emits must carry a machine-readable meaning row (what it
# counts, its health rule, what a bad value implies, what to read next) in
# lib/util/include/util/telemetry_ontology.def. A new field with no meaning
# fails here, named with its file:line.
check-telemetry-ontology:
	@echo "══ LINT: telemetry field ontology ══"
	@./tools/lint/check_telemetry_ontology.sh

# Gate — no NEW repair rung without a write-time-invariant test (RATCHET for
# TENACITY I3). A new repair/reconcile/backfill/heal file in app/ must cite a
# write-time-invariant test (`// repair-rung-ok:<test>`) or be grandfathered in
# tools/scripts/repair_rung_baseline.txt (shrink-only). Fix the WRITER, not
# downstream with another rung.
check-no-new-repair-rung:
	@echo "══ LINT: no new repair rung (TENACITY I3) ══"
	@./tools/scripts/check_no_new_repair_rung.sh

# Sovereign-cure ratchet — no NEW caller of coins_kv_seed_from_node_db (the
# BORROWED zclassicd-chainstate seed the self-verified-tip cure is deleting,
# docs/work/self-verified-tip-plan.md Act 3). Callers are listed in
# tools/lint/borrowed_seed_caller_baseline.txt (shrink-only); a new caller fails.
check-no-new-borrowed-seed:
	@echo "══ LINT: no new borrowed-seed caller (sovereign cure) ══"
	@./tools/lint/check_no_new_borrowed_seed.sh .

# Coin-backfill ratchet — keep the borrowed-seed repair ladder owned by the
# reducer-frontier dispatcher until the sovereign cure deletes it. A new
# production caller, or a second call in the dispatcher, fails.
check-no-new-coin-backfill-caller:
	@echo "══ LINT: no new coin-backfill repair caller (sovereign cure) ══"
	@./tools/lint/check_no_new_coin_backfill_caller.sh .

# Route<->command parity (OS-B3b) — every fixed REST route in
# api_controller_routes.c carries a command_path naming the native command
# leaf (config/commands/*.def) that owns the same data/service, or an
# honest "none:<reason>" listed in the shrink-only
# tools/lint/route_command_parity_baseline.txt. A new unmapped route or a
# command_path that doesn't resolve to a real leaf fails the gate.
check-route-command-parity:
	@echo "══ LINT: REST route <-> native command parity (OS-B3b) ══"
	@./tools/lint/check_route_command_parity.sh .

# Antipoison ratchets (2026-06-18) — keep the docs honest + the node standing
# alone + reorgs safe. Each PASSES on the current tree and only fails on a
# regression. See docs/HANDOFF.md for why these exist.
check-doc-no-false-deleted:
	@echo "══ LINT: doc no-false-deleted ══"
	@./tools/lint/gate_doc_no_false_deleted.sh .

check-zclassicd-reach-allowlist:
	@echo "══ LINT: zclassicd reach allowlist (node stands alone) ══"
	@./tools/lint/gate_zclassicd_reach_allowlist.sh .

check-stage-log-reorg-unsafe:
	@echo "══ LINT: stage-log reorg-unsafe ratchet ══"
	@./tools/scripts/gate_stage_log_reorg_unsafe_ratchet.sh

check-no-csr-lock-on-finalize-drive:
	@echo "══ LINT: no csr->lock on post-finalize drive (LOCK-ORDER LAW / ABBA) ══"
	@./tools/lint/gate_no_csr_lock_on_finalize_drive.sh .

# Gate — OFFLINE-ONLY FENCE for the FAST-MINT crypto pass-through. The
# mint_skip_crypto setter (which makes script_validate/proof_validate skip
# per-block crypto) may be called ONLY from the offline -mint-anchor mint
# driver TUs — never from a P2P/RPC/relay/connect_block path, so a signature
# bypass on a running node is unreachable by construction. See
# jobs/mint_skip_crypto.h.
check-mint-skip-crypto-offline-only:
	@echo "══ LINT: fast-mint crypto pass-through is offline-only ══"
	@./tools/lint/check_mint_skip_crypto_offline_only.sh .

# Gate E1 — file-size ceiling for app/ .c files (RATCHET). Mega-modules
# cannot hide behind <500-LOC functions; baseline at
# tools/scripts/file_size_ceiling_baseline.txt may only shrink.
check-file-size-ceiling:
	@echo "══ LINT: app/ file-size ceiling (E1) ══"
	@./tools/scripts/check_file_size_ceiling.sh

# Rejects dev-history phrasing ("STEP-0 STATUS", "stub bodies"/"stub body",
# "lane <N><letter>", "future slice") from production contract surfaces
# (*.h under any **/include/**, *.def tables) — INCORRECT MODEL CONTEXT once
# the real body has landed. docs/, vendor/, and test paths narrate history on
# purpose and are excluded. See tools/scripts/check_no_dev_history_in_contracts.sh.
check-no-dev-history-in-contracts:
	@./tools/scripts/check_no_dev_history_in_contracts.sh

# Funded transaction receipts and isolated recipient-wallet manifests are
# private local state. Tracked baselines may contain reproducible simnet and
# public consensus fixtures, but never owner experiment history.
check-no-live-lab-history:
	@./tools/scripts/check_no_live_lab_history.sh --selftest
	@./tools/scripts/check_no_live_lab_history.sh

# Gate E9 — EV_OPERATOR_NEEDED emit must reach a registered sink (HARD).
# The silent-halt fix: the loud "human needed" signal can never be emitted
# without a subscriber in lib/event/src/alerts.c.
check-operator-needed-sink:
	@echo "══ LINT: operator-needed sink (E9) ══"
	@./tools/scripts/check_operator_needed_sink.sh

# Gate P1-3 — systemd finite hard memory caps must fit inside the host budget.
# Counts MemoryMax plus finite MemorySwapMax across committed node units and
# fails explicit MemoryMax=infinity. Prevents host OOM from cap drift.
check-systemd-memory-budget:
	@echo "══ LINT: systemd memory budget (P1-3) ══"
	@./tools/scripts/check_systemd_memory_budget.sh

# Gate E14 — a COND_CRITICAL condition whose detect() depends on external/
# network state (peer/connman liveness, the legacy zclassicd RPC oracle)
# must set cooldown_secs > 0 or wire a .progressing callback, so it re-arms
# instead of permanently latching at max_attempts. The 2026-07-13 27h-page
# bug class (sync_violation_lag / tip_wedged_resnapshot shipped without
# cooldown_secs) made this unrepresentable. See tools/scripts/
# check_condition_cooldown.sh for the full rule + self-test.
check-condition-cooldown:
	@echo "══ LINT: condition cooldown re-arm (E14) ══"
	@./tools/scripts/check_condition_cooldown.sh

# Gate E11 — doc accuracy: the gate list in DEFENSIVE_CODING.md must match
# the actual check-* dependencies of the lint: target (count + names).
check-doc-accuracy:
	@echo "══ LINT: doc accuracy (E11) ══"
	@./tools/scripts/check_doc_accuracy.sh

# Local Markdown targets are part of the developer interface. Scan tracked
# Markdown as it exists in the worktree; fail on missing/escaping relative
# files and directories while leaving network URIs, anchors, images, and
# generated placeholders outside this filesystem-only contract.
check-markdown-links:
	@echo "══ LINT: local Markdown targets ══"
	@./tools/lint/check_markdown_links.sh .

# check-markdown-links covers Markdown LINK targets and explicitly excludes
# inline code. Every dead path an agent actually trusts is inline code — a doc
# naming `domain/consensus/src/tx_structural.c:121` reads as verified and sends
# the agent to a directory that moved. This gate resolves every backticked
# source path in tracked Markdown, plus every backticked module directory
# (`lib/consensus`, `app/events`) — a moved module is invisible to a
# file-extension scan. Shrink-only baseline.
check-doc-inline-paths:
	@echo "══ LINT: inline code paths in Markdown ══"
	@./tools/lint/check_doc_inline_paths.sh

# Doc counts vs code: numeric claims (test_groups / port_interfaces /
# persistence_adapters) declared in the <!-- DOC-COUNTS --> block of
# docs/CODEBASE_MAP.md must agree with the code, and known-stale compound
# phrases ("15 ports", "1500+ tests", ...) must not return to the prose.
check-doc-counts:
	@echo "══ LINT: doc counts vs code ══"
	@./tools/scripts/check_doc_counts.sh

# Gate — the stopwatch skip-streak detector's SHELL halves. The C half is
# covered by the test_stopwatch_skip_watch group; the shell half (the shared
# class-table parser both stopwatch scripts source, plus the judge's report
# line and ALARM) had no automatic guard, and a detector whose own proof
# nobody runs is the exact defect it exists to fix.
check-stopwatch-skip-detector:
	@echo "══ LINT: stopwatch skip-streak detector selftests ══"
	@./tools/lint/check_stopwatch_skip_detector.sh

# Gate — the proof-server promotion binding stays self-recording. tools/ship.sh's
# guard used to tell the operator to "re-tag the candidate" and nothing ever did
# it; this runs the pin recorder's hermetic self-test and asserts ship.sh still
# calls `proof_server_pin.sh record` in its promotion path, so the same
# prose-with-no-code defect cannot silently return.
check-proof-server-pin:
	@echo "══ LINT: proof-server promotion pin ══"
	@./tools/lint/check_proof_server_pin.sh

# Gate — promotion evidence survives this machine and cannot be rewritten. The
# pin above is a LOCAL, MUTABLE, UNSIGNED tag; deploy/promotion-receipts.jsonl
# is the authority: tracked (so it replicates on push), hash-chained (so an
# edited/removed/re-ordered record breaks a link) and ssh-signed (so a third
# party verifies authorship offline with no private key). This runs the
# tamper-detection self-test, verifies the in-tree chain, enforces append-only
# against HEAD, and asserts ship.sh still appends a receipt on promotion.
check-promotion-receipt-chain:
	@echo "══ LINT: promotion receipt chain ══"
	@./tools/lint/check_promotion_receipt_chain.sh

# Gate — hosted CI's green must not overstate what it checked. build.yml puts
# five green checks on a commit (gcc, clang, lint, fuzz-replay, a full per-TU
# compile) and the TEST SUITE IS NOT AMONG THEM, so to a reader on GitHub those
# checks look like more verification than happened. .github/verification-coverage.txt
# is the declared coverage and this holds it to the workflow both ways: every
# item claiming to be hosted must name a job key that exists, every job must be
# claimed, a not-hosted item must name who does vouch for it, and the required
# item list lives in the GATE (not the manifest) so the gap cannot be closed by
# deleting a row. It also names the not-hosted items in its own gate log (run
# the script directly to see them — run_lint.sh captures passing gate output and
# may cache-skip the gate; the reader-facing statement is build.yml's own
# comment, which prong 5 forces to point at the manifest).
check-verification-coverage:
	@echo "══ LINT: hosted CI verification coverage ══"
	@./tools/lint/check_verification_coverage.sh

# Gate — execute the exact remote activation transaction embedded in ship.sh.
# Fault injection at daemon-reload and restart must restore both the executable
# and its systemd identity intent; the success case must qualify the /proc
# executable bytes and status command before considering activation complete.
check-ship-remote-transaction:
	@echo "══ LINT: remote ship transaction rollback + process qualification ══"
	@./tools/lint/check_ship_remote_transaction.sh

# Fail-closed Z23 release packager + installer: checksum mismatch never
# installs, and the packager never invokes docker.
check-z23-release-install:
	@echo "══ LINT: z23 release package + fail-closed installer ══"
	@bash packaging/release/build_release.sh --selftest
	@bash tools/scripts/install_z23.sh --selftest

# Gate — stop a tenth copy of the source-identity JSON parser from growing
# back. tools/scripts/source_identity_lib.sh is the one canonical reader
# (anchored on the FIRST "source_id_sha256" occurrence — a greedy copy
# produced a false "identical identities" report on 2026-07-28); this is a
# shrink-only ratchet over the tools/dev/ scripts still carrying their own
# copy, named in tools/lint/identity_parser_baseline.txt.
check-identity-parser-single:
	@echo "══ LINT: source-identity JSON parser stays single ══"
	@./tools/lint/check_identity_parser_single.sh --selftest
	@./tools/lint/check_identity_parser_single.sh

# Anti-rot ratchet: exactly ONE place decides whether a node status reason
# means an operator has to intervene. Two operator surfaces (the public REST
# /api/status endpoint and the agent first-call summary) each carried their own
# inline if/else-if ladder assigning `operator_needed` plus their own copies of
# every rung's status/summary wording, and the two had already drifted — the
# node could give two different answers to "does a human need to act".
# app/controllers/include/controllers/operator_needed_policy.def is now that
# one place. This gate matches the ladder by SHAPE, not by any variable or
# function name (a name-keyed gate is dodged by one rename), over a shrink-only
# baseline at tools/lint/status_reason_baseline.txt.
check-status-reason-single:
	@echo "══ LINT: the operator-needed ladder stays single ══"
	@./tools/lint/check_status_reason_single.sh --selftest
	@./tools/lint/check_status_reason_single.sh

# Anti-rot ratchet: no NEW decision made on the exit status of a
# `printf | grep -q` / `echo | grep -q` pipeline in a script that sets pipefail.
# grep -q exits at the first match, printf then takes SIGPIPE, and pipefail
# reports printf's 141 instead of grep's 0 — so a MATCH becomes
# indistinguishable from a miss and the decision inverts. For a lint gate that
# is a hollow PASS: check_release_no_dev_symbols.sh read the release binary as
# clean in 20/20 runs with a forbidden dev-only symbol planted in it. Fix with
# str_contains/str_lacks (tools/scripts/sh_str.sh) or by extracting the match
# into a variable and testing the string. Shrink-only baseline at
# tools/lint/pipefail_status_pipe_baseline.txt; no allow-comment escape hatch.
check-pipefail-status-pipe:
	@echo "══ LINT: no status-carrying printf|grep -q under pipefail ══"
	@./tools/lint/check_pipefail_status_pipe.sh --selftest
	@./tools/lint/check_pipefail_status_pipe.sh

# Anti-stale forbid gate: no hand-pinned rot-prone facts in the docs. Two
# classes — a "<N> MB … binary" size claim (HARD; the size has a live source,
# tools/scripts/binary_size.sh — de-pin to size-agnostic prose) and a live-state
# HEIGHT PIN outside docs/HANDOFF.md (RATCHET; shrink-only baseline at
# tools/lint/stale_pinned_facts_baseline.txt). Per-line escape hatch: a trailing
# `<!-- stale-ok: <reason> -->` marker. Owner directive 2026-07-17: numeric
# facts with a live source are DERIVED or GATED, never hand-pinned.
check-no-stale-pinned-facts:
	@echo "══ LINT: no stale pinned facts (binary size / live-state height) ══"
	@./tools/lint/check_no_stale_pinned_facts.sh

# No UNCITED victory claim in the one live-state page (HARD). This repo shipped
# 9+ "cured / at tip / fully synced" claims in six weeks, every one later false
# (~103 "wedge FIXED" -> re-wedge cycles). A paragraph in docs/HANDOFF.md that
# carries a victory phrase ("at tip", "cured", "wedge closed", "soak window
# open", ...) must also carry a machine-checkable citation token (VERDICT=PASS,
# gap_vs_oracle, uptime-ledger, a ts= stamp, slo-summary:, WALL_CLOCK_SECONDS)
# or the explicit historical override <!-- victory-ok: <reason> -->. See
# tools/scripts/check_no_uncited_victory.sh (has --selftest).
check-no-uncited-victory:
	@echo "══ LINT: no uncited victory claim (docs/HANDOFF.md) ══"
	@./tools/scripts/check_no_uncited_victory.sh

# Bound doc claims. An author binds ONE prose assertion to ONE machine-checkable
# predicate with an invisible HTML comment next to it:
#   <!-- claim: file-present|file-absent <path> -->
#   <!-- claim: symbol-present|symbol-absent <symbol> <git-pathspec> -->
#   <!-- claim: gate-passes|gate-fails <check-*-gate> -->
# The gate fails when the predicate stops holding and names the file, the line,
# the claim text and the contradicting reality. gate-fails turns the existing
# check-no-* ratchets into freshness oracles for open items: an item that says
# work is outstanding goes red the day the gate that watches it turns green.
# Generalizes the two hardcoded rows in check-doc-no-false-deleted. Covers
# tracked *.md; out-of-repo plans need the explicit
# `tools/lint/check_doc_claims.sh --scan <dir>` invocation.
check-doc-claims:
	@echo "══ LINT: bound doc claims (doc freshness) ══"
	@./tools/lint/check_doc_claims.sh

# The out-of-repo half, made one command instead of a remembered path.
# ~/.claude/plans/*.md is where the motivating failure happened (a plan listed
# a deletion as PENDING that had landed three days earlier, and three agents
# were dispatched to redo it) and no repo gate can reach it: it is outside the
# work tree, invisible to `git grep` and to `make lint`. This target does not
# and must not run in CI — it is what an orchestrator runs before dispatching
# work FROM a plan. It resolves every predicate against this repository.
# PLANS=<dir> overrides the default location.
PLANS ?= $(HOME)/.claude/plans
.PHONY: check-plan-claims
check-plan-claims:
	@echo "══ CHECK: bound claims in out-of-repo plans ($(PLANS)) ══"
	@./tools/lint/check_doc_claims.sh --scan "$(PLANS)"

# A document path baked into an operator-facing C string literal must resolve
# to a file that exists. Three wallet-path boot refusals pointed the operator
# at WALLET_PERSISTENCE_RECOVERY.md, which had never existed — a dead pointer
# at the one moment the reader most needs the instructions.
# check-markdown-links covers .md-to-.md; this covers .md inside C literals.
# See tools/lint/check_error_doc_refs.sh (has --selftest).
check-error-doc-refs:
	@echo "══ LINT: operator-named docs exist (C string literals) ══"
	@./tools/lint/check_error_doc_refs.sh

# docs/API_REFERENCE.md is GENERATED from config/commands/*.def by
# tools/gen_api_reference.c (editorial prose lives in docs/API_REFERENCE.md.in).
# It used to be hand-transcribed, and drifted: the page still claimed 106 leaves
# across 41 branches long after the catalog had more than doubled. This gate
# regenerates into a temp file and fails on any difference, so a `.def` change
# and the reference can never disagree. Fix a failure with
# `make docs-api-reference`, never by editing the generated page.
# Has --selftest (plants a hand edit, proves the gate trips).
check-api-reference-generated:
	@echo "══ LINT: docs/API_REFERENCE.md is generated, not hand-edited ══"
	@./tools/lint/check_api_reference_generated.sh

# Gate — every leaf's `discover describe` document must FIT its byte budget.
# `discover describe` is the only surface that renders a leaf's long-form
# `semantics` text at all, and an over-budget document renders as nothing: the
# leaf keeps dispatching and its written contract is silently unreadable.
# core.wallet.recovery.restore shipped that way with a money-safety warning
# inside the invisible text. Renders EVERY leaf through the REAL renderer.
# Baseline (may only shrink): tools/lint/describe_budget_baseline.txt.
# Fix a failure by trimming `semantics`, NEVER by raising the budget.
# Has --selftest (pads a leaf past the budget, proves the gate trips).
check-describe-budget:
	@echo "══ LINT: every leaf's describe document fits its budget ══"
	@./tools/lint/check_describe_budget.sh --selftest
	@./tools/lint/check_describe_budget.sh

# Regenerate the native command reference from the declarative catalog.
API_REFERENCE_TOOL = $(BIN_DIR)/gen_api_reference

$(API_REFERENCE_TOOL): tools/gen_api_reference.c \
                       lib/kernel/include/kernel/command_registry.h \
                       $(wildcard config/commands/*.def) \
                       $(wildcard config/commands/*/*.def)
	@mkdir -p $(dir $@)
	$(CC) -std=c23 -O2 -Wall -Wextra -Ilib/kernel/include -Ilib/json/include \
	    -o $@ tools/gen_api_reference.c

.PHONY: tools/gen_api_reference docs-api-reference
tools/gen_api_reference: $(API_REFERENCE_TOOL)
docs-api-reference: $(API_REFERENCE_TOOL)
	@$(API_REFERENCE_TOOL) docs/API_REFERENCE.md.in docs/API_REFERENCE.md


# docs/EQUIHASH_PARAMS.md is GENERATED by tools/equihash_params_fact.c, which
# LINKS the real chainparams and upgrade tables and prints what consensus
# would answer at each activation height. Prose across this repository said
# "ZClassic is Equihash 200,9" as a flat present-tense fact; mainnet has been
# height-selected 192,7 since Bubbles, and a reader who believes the flat
# claim sizes a solution buffer wrongly. Fix a failure with
# `make docs-equihash-params`, never by editing the generated page.
EQUIHASH_FACT_TOOL = $(BIN_DIR)/equihash-params-fact
EQUIHASH_FACT_SRCS = tools/equihash_params_fact.c \
    core/chainparams/src/chainparams.c core/chainparams/src/chainparamsbase.c \
    core/params/src/upgrades.c core/consensus/src/upgrades.c \
    core/math/src/uint256.c lib/encoding/src/utilstrencodings.c \
    lib/base/src/log_level.c lib/base/src/result.c

$(EQUIHASH_FACT_TOOL): $(EQUIHASH_FACT_SRCS)
	@mkdir -p $(dir $@)
	$(CC) -std=c23 -O2 -Wall -Wextra -Werror -pedantic \
	    -D_POSIX_C_SOURCE=200809L \
	    -Icore/chainparams/include -Icore/params/include -Icore/math/include \
	    -Icore/consensus/include -Ilib/chain/include -Ilib/base/include \
	    -Ilib/util/include -Ilib/core/include -Ilib/crypto/include \
	    -Ilib/codec/include -Ilib/primitives/include -Ilib/support/include \
	    -Ilib/encoding/include -Ilib/script/include -Ilib/json/include \
	    -Ilib/sapling/include -Ilib/keys/include -Ilib/event/include \
	    -o $@ $(EQUIHASH_FACT_SRCS)

.PHONY: tools/equihash-params-fact docs-equihash-params
tools/equihash-params-fact: $(EQUIHASH_FACT_TOOL)
docs-equihash-params: $(EQUIHASH_FACT_TOOL)
	@$(EQUIHASH_FACT_TOOL) docs/EQUIHASH_PARAMS.md
	@echo "docs-equihash-params: wrote docs/EQUIHASH_PARAMS.md from the consensus tables"

# Gate — the height-selected Equihash fact cannot drift, in either direction.
# Half of it regenerates docs/EQUIHASH_PARAMS.md from the consensus tables and
# diffs; the other half scans prose for a flat "Equihash 200,9" claim about
# what the chain IS, which is what was wrong across nine files.
check-equihash-params:
	@echo "══ LINT: Equihash parameters are height-selected, and said so ══"
	@./tools/lint/check_equihash_params.sh --selftest
	@./tools/lint/check_equihash_params.sh

# Dev-UX: the DERIVED binary size (counterpart to the forbid gate above). Quote
# this instead of hand-pinning a size in prose; a reviewer re-runs it to confirm.
.PHONY: binary-size
binary-size:
	@./tools/scripts/binary_size.sh

# Gate — ONE hex codec. Base-16 encode/decode lives only in
# lib/base/include/base/hex.h; a private copy anywhere else fails
# (RATCHET at file granularity; tools/lint/hex_codec_baseline.txt may only
# shrink). 56 disagreeing copies existed when this gate was written.
check-hex-codec-single:
	@echo "══ LINT: one hex codec ══"
	@./tools/lint/check_hex_codec_single.sh --selftest
	@./tools/lint/check_hex_codec_single.sh

# Gate E2 — new service functions return struct zcl_result, not bare
# bool/int (RATCHET at file granularity; baseline at
# tools/scripts/one_result_type_baseline.txt may only shrink).
check-one-result-type:
	@echo "══ LINT: one result type (E2) ══"
	@./tools/scripts/check_one_result_type.sh

# Gate — service-shape convergence SHRINKING-FLOOR ratchet (Phase 3, sibling
# to E2): counts exported bool-returning function DEFINITIONS per
# app/services/src/*.c file (E2 only requires a file to reference struct
# zcl_result somewhere, so a "mixed" file can be E2-clean forever). Baseline
# at tools/scripts/service_result_convergence_baseline.txt may only shrink;
# see docs/work/service-result-convergence.md for the inventory + lane plan.
check-service-result-convergence:
	@echo "══ LINT: service-result convergence (Phase 3 ratchet) ══"
	@./tools/scripts/check_service_result_convergence.sh

# ── Shape-skeleton generator (Workstream A5, FRAMEWORK.md Law 3) ──────
# Emit a correct, compiling, readable skeleton for one of the four shapes
# into the right shape folder. Plain committed source (no metaprogramming),
# matching the exemplars so it passes the framework lint gates the day it
# lands. The generator never edits a registry — it prints the wiring step.
#
#   make new-condition  NAME=foo_bar   -> app/conditions/src/foo_bar.c
#   make new-model      NAME=foo        -> app/models/src/foo.c
#   make new-job        NAME=foo_stage  -> app/jobs/src/foo_stage.c
#   make new-controller NAME=foo        -> app/controllers/src/foo_controller.c
.PHONY: new-condition new-model new-job new-controller
new-condition:
	@test -n "$(NAME)" || { echo "usage: make new-condition NAME=foo_bar"; exit 1; }
	@./tools/new_shape.sh condition "$(NAME)"
new-model:
	@test -n "$(NAME)" || { echo "usage: make new-model NAME=foo"; exit 1; }
	@./tools/new_shape.sh model "$(NAME)"
new-job:
	@test -n "$(NAME)" || { echo "usage: make new-job NAME=foo_stage"; exit 1; }
	@./tools/new_shape.sh job "$(NAME)"
new-controller:
	@test -n "$(NAME)" || { echo "usage: make new-controller NAME=foo"; exit 1; }
	@./tools/new_shape.sh controller "$(NAME)"

#   make scenario NAME=foo -> tools/sim/scenarios/foo.scenario (chaos DSL
#   skeleton: mode simnet + a small honest cluster + a mint/relay/deliver
#   round + the standard simnet_converged/simnet_tip_monotonic expects; see
#   docs/CHAOS_HARNESS.md. Picked up automatically by `make chaos` — no
#   registry edit needed.
.PHONY: scenario
scenario:
	@test -n "$(NAME)" || { echo "usage: make scenario NAME=foo_bar"; exit 1; }
	@./tools/new_shape.sh scenario "$(NAME)"

# Gate E3 — shape source files include their shape contract header
# (conditions -> framework/condition.h, models -> models/ header,
# supervisors -> supervisor header). HARD: the tree already complies.
check-shape-includes-header:
	@echo "══ LINT: shape includes header (E3) ══"
	@./tools/scripts/check_shape_includes_header.sh

# Gate E4 — projections are pure folds: no app-layer (services/controllers)
# includes and no AR model saves. HARD: the projection set already complies.
check-projections-pure:
	@echo "══ LINT: projections pure (E4) ══"
	@./tools/scripts/check_projections_pure.sh

# Gate E6 — one chain-state write path (RATCHET). Legacy writer surfaces
# would be grandfathered in tools/scripts/one_write_path_baseline.txt (empty
# today — the legacy writers are already deleted); any new write surface
# outside the reducer's single write path fails.
check-one-write-path:
	@echo "══ LINT: one write path (E6) ══"
	@./tools/scripts/check_one_write_path.sh

# Gate E7 — no authoritative RAM state (RATCHET). Direct active_chain
# internals/global active_chain state are forbidden outside the baseline.
check-no-authoritative-ram-state:
	@echo "══ LINT: no authoritative RAM state (E7) ══"
	@./tools/scripts/check_no_authoritative_ram_state.sh

# Gate E5 — Job stages advance OR block (HARD). Every app/jobs/src/*_stage.c
# step must surface JOB_BLOCKED/JOB_IDLE on non-progress AND reference a cursor
# (cursor_out / c->cursor_in / stage_cursor) — no silent forward spin. The 8
# stages already comply, so the gate runs HARD.
check-stage-advances-or-blocks:
	@echo "══ LINT: stage advances-or-blocks (E5) ══"
	@./tools/scripts/check_stage_advances_or_blocks.sh

check-frontier-single-writer:
	@echo "══ LINT: one canonical writer per frontier ══"
	@./tools/scripts/check_frontier_single_writer.sh

check-dumper-never-blocks:
	@echo "══ LINT: no dumpstate view blocks behind the reducer ══"
	@./tools/scripts/check_dumper_never_blocks.sh

# Program H enforcement gates (OBSERVE-style ratchets, baselined at today's
# consumer set). Each lands BEFORE its deletion wave, proving non-growth, and
# shrinks toward a zero-debt invariant as Program H demotes the copy.
check-no-block-index-flat:
	@echo "══ LINT: no new flat/LevelDB/SQLite header-cache consumer (Program H) ══"
	@./tools/scripts/check_no_block_index_flat.sh

check-no-utxo-projection:
	@echo "══ LINT: no new event-sourced UTXO-projection consumer (Program H) ══"
	@./tools/scripts/check_no_utxo_projection.sh

check-no-utxos-mirror-read:
	@echo "══ LINT: no new node.db utxos-mirror reader (Program H) ══"
	@./tools/scripts/check_no_utxos_mirror_read.sh

check-no-silent-ready:
	@echo "══ LINT: no-silent-ready (E8) ══"
	@./tools/scripts/check_no_silent_ready.sh

# Gate E12 — honest witness (Law 7). A Condition's witness must observe the
# symptom MOVE (tip/cursor/block_map/SELECT/progress counter), never just a
# constant, the pure inverse of detect, or an FSM/poison-flag the remedy
# itself set (which lets a no-op remedy self-certify "cleared"). FAIL mode:
# the tree is clean (every witness reads real progress or carries a reviewed
# // honest-witness-ok:<reason> hatch); the baseline at
# tools/lint/honest_witness_baseline.txt is empty and may only shrink.
check-honest-witness:
	@echo "══ LINT: honest witness (E12) ══"
	@ZCL_LINT_MODE=FAIL ./tools/lint/check_honest_witness.sh

# wf/dx-scanner-immunity — every gate invoked as a `check-*` Make target
# (whether standalone `make check-foo` or as a `lint:` prerequisite) runs
# with ZCL_LINT_PRODUCTION_SCAN=1, so tools/lint/scan_exclusions.sh's
# arrays exclude the shared lint-fixture-name glob + build/vendor/worktree
# noise for EVERY production scan. Gate selftests (lib/test/src/
# test_make_lint_gates.c) exec the gate scripts directly — bypassing
# `make` entirely — so this var stays unset there and detection power for
# a freshly-planted selftest fixture is unchanged. See
# tools/lint/scan_exclusions.sh for the full rationale. Pattern-specific
# variables propagate to prerequisites, so this covers both direct
# invocation and the `lint:` umbrella uniformly.
check-%: export ZCL_LINT_PRODUCTION_SCAN := 1

# tools/dev/build-epoch-integrity-cached.sh drives the two real compile-probe
# selftests (tools/dev/build-epoch-selftest.sh and
# tools/dev/make-depfile-scope-selftest.sh) concurrently behind a cache keyed
# on every input those probes read; a cache hit skips the ~15s of real `cc`
# compiles / `make -n` dry runs and reproduces the identical verdict, an
# input change is a cache MISS that reruns both probes for real.
check-build-epoch-integrity:
	@echo "══ LINT: toolchain-keyed compile epochs + atomic publication ══"
	@tools/dev/build-epoch-integrity-cached.sh

check-checkout-lock:
	@echo "══ LINT: checkout-wide watcher/foreground mutual exclusion ══"
	@tools/dev/checkout-lock-selftest.sh

# wf/dx-scanner-immunity — runs FIRST: names any untracked stray .c/.h file
# under a scanned source dir as "untracked stray file (not a code
# violation)" before any OTHER gate has a chance to report its content as
# if it were a real defect. See tools/lint/check_no_stray_untracked_source.sh.
check-no-stray-untracked-source:
	@echo "══ LINT: no stray untracked source (DX1) ══"
	@./tools/lint/check_no_stray_untracked_source.sh

# The repository root is a curated list — source areas, top-level docs, and a
# short allowlist of generated/local entries. Anything else (a stray database,
# a nohup capture, a second scratch dir) is gitignored debris that `git status`
# never objected to. See tools/lint/check_no_stray_root_files.sh.
check-no-stray-root-files:
	@echo "══ LINT: no stray files in the repository root ══"
	@./tools/lint/check_no_stray_root_files.sh

check-no-retired-agent-protocol:
	@./tools/lint/check_no_retired_agent_protocol.sh

# Nothing under test, and no command an agent is told to copy, may be aimed at
# the OPERATOR'S LIVE NODE. Three prongs, all measured on this tree:
#   A  a test that constructs the exact live datadir path (~/.zclassic,
#      ~/.zclassic-c23) — shrink-only, 8 sites in 7 files today;
#   B  a test that resolves GetDataDir()/GetDefaultDataDir() and never calls
#      SetDataDir() — HARD, zero today. This is the shape that made
#      test_chain_integrity_failed_condition pass off the LIVE
#      blocks/blk00000.dat as its fixture, which a passing suite ON THIS HOST
#      structurally cannot reveal;
#   C  a doc/script showing an invocation of a leaf that ACCEPTS a `datadir`
#      input without naming one, so a copied line hits the live node —
#      shrink-only, 13 sites in 5 files, including the `app service access`
#      example that ran the boot ceremony on the operator's node.db.
# The datadir-taking leaf set is derived from argument 10 of the leaf macros in
# config/commands/*.def, never hand-listed.
check-live-datadir-isolation:
	@echo "══ LINT: nothing under test aims at the live datadir ══"
	@./tools/lint/check_live_datadir_isolation.sh --selftest
	@./tools/lint/check_live_datadir_isolation.sh

# The public installed-Commons target must run with every optional variable
# unset. The DHT harness refuses to start until each binary it names is
# executable; this proves the installed lane puts every one of those in the
# prefix outside every conditional, so no undocumented flag is load-bearing.
check-installed-acceptance-tools:
	@echo "══ LINT: installed Commons needs no optional flag ══"
	@./tools/lint/check_installed_acceptance_tools.sh

# wf/dx-scanner-immunity regression proof — plants a transient lint-gate
# fixture mid-scan and proves: (1) a production scan ignores it, (2) a
# selftest-style direct invocation still detects it (detection unweakened),
# (3) a REAL violation with a non-fixture name still fails every mode, and
# (4) an untracked stray file is named distinctly, not as a code violation.
# See tools/lint/selftest_scanner_immunity.sh.
check-scanner-immunity:
	@echo "══ LINT: scanner fixture-race immunity regression proof (DX1) ══"
	@./tools/lint/selftest_scanner_immunity.sh

# The in-tree compile cache wraps EVERY compile in this repository, so a wrong
# hit is a wrong binary underneath every other proof here. This gate builds a
# fixture five ways and requires identical bytes on a hit, replayed warnings,
# and a MISS after a header edit — the exact case an earlier version of
# tools/zcc.c got wrong. See tools/lint/check_zcc_cache.sh.
check-zcc-cache:
	@echo "══ LINT: compile cache serves correct bytes ══"
	@./tools/lint/check_zcc_cache.sh

# ── Lint umbrella ────────────────────────────────────────────────────────
# LINT_GATES is the single ordered source of truth for the lint umbrella
# (E11 check-doc-accuracy cross-checks it against DEFENSIVE_CODING.md).
#
# Two execution modes:
#   default            — tools/lint/run_lint.sh execs every gate's script
#                        directly (no per-gate Make parse), times each in ms
#                        (.cache/lint-timing/), and runs independent gates in
#                        parallel (ZCL_LINT_JOBS workers). All gates run even
#                        when some fail, so one pass reports every violation.
#   ZCL_LINT_SERIAL=1  — legacy fallback: gates run as plain Make
#                        prerequisites in listed order, no timing, stop at
#                        first failure. Use if parallel lint ever misbehaves
#                        on a host (and report it — the driver is the
#                        maintained path).
#
# Wall-time budget (SOFT, warn-only — never fails the build): the umbrella
# carries a budget in seconds — ZCL_LINT_BUDGET_SEC, defaulted in
# tools/lint/run_lint.sh and echoed into every timing artifact as
# "budget_sec", which is where to read its current value. Per-gate ms lands in
# .cache/lint-timing/last-run.json and every run prints the slowest 10, so a
# creeping gate is visible before it eats the budget. Do NOT type an observed
# duration into this comment — durations are per host and per commit, and the
# ones that used to live here had gone stale. Ask the host instead:
#   make timings   (says NOT MEASURED rather than quoting another machine)
# Workers for the parallel lint driver. Measured on a 32-core host: the
# umbrella burns ~4.5 min of CPU inside ~39 s of wall at 8 workers, so the
# driver is CPU-starved, not gate-bound. Derive the default from the host and
# keep headroom, because check-standalone-tools-link forks its own `make -j4`
# underneath one of these workers. Override with ZCL_LINT_JOBS=<n>.
ZCL_LINT_NPROC := $(shell nproc 2>/dev/null || echo 8)
ZCL_LINT_JOBS ?= $(shell j=$$(( $(ZCL_LINT_NPROC) * 3 / 4 )); \
                   if [ "$$j" -lt 8 ]; then j=8; fi; \
                   if [ "$$j" -gt 24 ]; then j=24; fi; echo "$$j")
LINT_GATES := \
    check-no-retired-agent-protocol \
    check-build-epoch-integrity \
    check-checkout-lock \
    check-no-stray-untracked-source \
    check-no-stray-root-files \
    check-scanner-immunity \
    check-git-hooks-installed \
    check-malloc \
    check-byte-order-codec-single \
    check-zcode-package-registry \
    check-hotswap-dev-only \
    check-hotswap-eligible-scope \
    check-hotswap-static-state \
    check-hotswap-service-islands \
    check-hotswap-swappable-shape \
    check-release-no-dev-symbols \
    check-stable-publish-contained \
    check-raw-sqlite \
    check-raw-malloc \
    check-json-value-init \
    check-blob-read-bounds \
    check-coins-lookup-nullcheck \
    check-observability-pairing \
    check-silent-errors-services \
    check-silent-errors-controllers \
    check-silent-errors-jobs \
    check-silent-errors-conditions \
    check-silent-errors-bool \
    check-log-macro-return-type \
    check-no-runtime-abort \
    check-wallet-raw-prepare-log \
    check-zcc-cache \
    check-equihash-params \
    check-before-save-hooks \
    check-pthread-create \
    check-model-validation \
    check-model-ar-lifecycle \
    check-long-functions \
    check-rpc-registrar \
    check-lag-slo-observable \
    check-lib-layering \
    check-lib-module-order \
    check-shape-include-direction \
    check-domain-purity \
    check-core-include-boundary \
    check-core-seal \
    check-accel-oracle-pinned \
    check-no-adx-overclaim \
    check-simd-os-support \
    check-supervisor-registration \
    check-test-registration \
    check-typed-blocker \
    check-blocker-escape-registered \
    check-blocker-remedy \
    check-blocker-handoff-declared \
    check-supervisor-progress-declared \
    check-stopwatch-skip-detector \
    check-proof-server-pin \
    check-promotion-receipt-chain \
    check-verification-coverage \
    check-ship-remote-transaction \
    check-z23-release-install \
    check-identity-parser-single \
    check-status-reason-single \
    check-pipefail-status-pipe \
    check-framework-shape \
    check-framework-filename-suffix \
    check-no-raw-clock-outside-platform \
    check-sysinit-ordering \
    check-sandbox-wired \
    check-no-shellouts \
    check-no-writer-below-sealed-frontier \
    check-peer-floor-single-source \
    check-proc-self-shim \
    check-no-raw-sqlite-in-controllers \
    check-supervisor-domain \
    check-thread-supervision \
    check-file-purpose \
    check-group-purpose \
    check-no-orphan-placement \
    check-file-size-ceiling \
    check-operator-needed-sink \
    check-systemd-memory-budget \
    check-condition-cooldown \
    check-doc-accuracy \
    check-doc-counts \
    check-no-stale-pinned-facts \
    check-no-uncited-victory \
    check-doc-claims \
    check-error-doc-refs \
    check-api-reference-generated \
    check-describe-budget \
    check-markdown-links \
    check-doc-inline-paths \
    check-hex-codec-single \
    check-one-result-type \
    check-service-result-convergence \
    check-shape-includes-header \
    check-projections-pure \
    check-one-write-path \
    check-frontier-single-writer \
    check-dumper-never-blocks \
    check-no-block-index-flat \
    check-no-utxo-projection \
    check-no-utxos-mirror-read \
    check-no-authoritative-ram-state \
    check-no-dev-history-in-contracts \
    check-no-live-lab-history \
    check-stage-advances-or-blocks \
    check-no-silent-ready \
    check-honest-witness \
    check-consensus-parity \
    check-no-new-repair-rung \
    check-no-new-borrowed-seed \
    check-no-new-coin-backfill-caller \
    check-route-command-parity \
    check-doc-no-false-deleted \
    check-zclassicd-reach-allowlist \
    check-stage-log-reorg-unsafe \
    check-no-csr-lock-on-finalize-drive \
    check-mint-skip-crypto-offline-only \
    check-wire-harness-security-gate \
    check-vcs-no-git \
    check-vcs-no-sha1 \
    check-vendor-provenance \
    check-command-contract \
    check-command-availability-truthful \
    check-command-input-keys \
    check-read-leaf-no-boot-ceremony \
    check-telemetry-ontology \
    check-privileged-transition-receipt \
    check-no-gnu-va-args \
    check-clang-portability \
    check-result-discard \
    check-c23-only \
    check-no-python \
    check-no-trust-state-ordering \
    check-no-warning-suppression \
    check-fuzz-artifact-ledger \
    check-live-datadir-isolation \
    check-installed-acceptance-tools \
    check-standalone-tools-link

# The driver execs gate scripts directly, so the two gates backed by a built
# tool (check-core-seal, check-observability-pairing, and the package root
# projection checker) need their binaries
# present before it starts; in serial mode those deps ride the check-* rules.
ifeq ($(ZCL_LINT_SERIAL),1)
lint: $(LINT_GATES)
	@echo "══ LINT: all checks passed (serial) ══"
else
lint: tools/core_seal tools/check_observability_pairing $(ZCODE_PACKAGE_REGISTRY_CHECK_BIN)
	@tools/lint/run_lint.sh --jobs "$(ZCL_LINT_JOBS)" --bin-dir "$(BIN_DIR)" $(LINT_GATES)
	@echo "══ LINT: all checks passed ══"
endif

# ── Result-cached lint (inner loop only) ─────────────────────────────────
# `make lint` above stays COLD, always, so the canonical gate and the
# pre-push path never accept a cached verdict. These two are the opt-ins:
#
#   make lint-cached      skip any gate whose entire scannable input is
#                         byte-identical to the last time it passed. Re-running
#                         on an unchanged tree is the case this exists for; a
#                         run where you edited anything gets no benefit,
#                         because the key covers the whole tree.
#   make lint-cold-audit  run every gate FRESH and assert that every gate
#                         carrying a stored PASS at its current key also
#                         passed the fresh run. This is what makes the cache
#                         trustworthy; run it after any change to the gate set
#                         or to tools/lint/lint_cache.sh. Warm the cache first
#                         (make lint-cached) or it has nothing to verify.
#
# 16 of the 117 gates are NEVER cached — they build binaries, run compilers,
# read build output, git config, /proc, or untracked worktree state. Each
# carries its reason in tools/lint/lint_cache.sh, and each always runs.
.PHONY: lint-cached lint-cold-audit
lint-cached: tools/core_seal tools/check_observability_pairing
	@tools/lint/run_lint.sh --cache --jobs "$(ZCL_LINT_JOBS)" --bin-dir "$(BIN_DIR)" $(LINT_GATES)
	@echo "══ LINT: all checks passed (cached where inputs were unchanged) ══"

lint-cold-audit: tools/core_seal tools/check_observability_pairing
	@tools/lint/run_lint.sh --cold-audit --jobs "$(ZCL_LINT_JOBS)" --bin-dir "$(BIN_DIR)" $(LINT_GATES)
	@echo "══ LINT: all checks passed, every cache hit verified against a fresh run ══"

# CI runs the PER-PROCESS isolated test runner (test_parallel), not the
# monolith (test_zcl). Both build from the same TEST_SRCS and cover the same
# groups; test_parallel forks each group into its own process so a global
# singleton set by one group (e.g. a chain_linkage HOLD or a registered
# active_chain_authority) cannot leak into a later group. The monolith shares
# one address space across all groups and currently SIGSEGVs on exactly that
# cross-group leak in test_chain_state_validator — a test-harness artifact, not
# a node bug (the parallel run is green). Using the isolated runner makes `make
# ci` (and the pre-push gate that runs it) reliable + armable. The monolith
# full run remains available as `make test-full` and its global-isolation
# hardening is tracked separately.
# ci-symbol-floor (C1 portability floor): pure-static objdump/ldd check of the
# built binary's GLIBC/GLIBCXX/CXXABI symbol-version floor — hermetic (no node,
# net, params, docker, wall-clock), so unlike ci-install* it lives IN `make ci`.
# SKIPs cleanly (exit 2 -> 0) when objdump/ldd are absent.
.PHONY: ci-symbol-floor
ci-symbol-floor: zclassic23
	@bash -c 'bash tools/scripts/ci_symbol_floor_gate.sh; rc=$$?; \
	 if [ "$$rc" -eq 2 ]; then echo "ci-symbol-floor: SKIP (objdump/ldd absent)"; exit 0; fi; exit $$rc'

# ci-reproducible: build-twice byte-identity gate. Builds the zclassic23 binary
# TWICE in two isolated temp build dirs under the EXACT release flag profile
# (shared with tools/release.sh via tools/scripts/repro_build_vars.sh) and
# asserts the two artifacts are byte-for-byte identical. Exit 0 = MATCH (prints
# the SHA3-256 + records it); exit 1 = MISMATCH with a diagnosing diff (first
# differing byte offset + likely-cause checklist: embedded build path,
# __DATE__/__TIME__, nondeterministic link order, build-id).
#
# DELIBERATELY opt-in (NOT in `make ci`) — it runs TWO full whole-program LTO
# links of zclassic23, so it is far too slow for the hot CI path. Like
# ci-stress / ci-install-linger / soak-ci it lives outside `make ci`. Run it
# before cutting a release (or on a worker) to PROVE the artifact is
# reproducible. This is the gate CLAUDE.md said was missing ("byte-identity is
# not yet proven by a build-twice-and-compare gate"). Does NOT set ZCL_NATIVE,
# so the test reflects the portable x86-64-v3 release baseline exactly.
# DECISION (Wave-2 lane B2, measured 2026-07-10): `make chaos` deliberately
# does NOT gate `make ci`. The 13-scenario corpus itself runs in ~1.6s once
# built — that part is cheap. The cost that matters is building the
# zclassic23-chaos binary in the first place: it is its own whole-program
# LTO link over $(ALL_SRCS) (same shape as zclassic23; test_parallel is now a
# cached per-TU non-LTO build, so it is no longer in this class), and a clean
# build of it alone measured 1m33s. `make ci` already pays for the whole-program
# LTO link of zclassic23 plus the cached test_parallel build; a THIRD full LTO
# link to cover 13 scenario replays that already run in every dev's `make
# sim-fast` would tax the hot CI path by roughly 50% for marginal coverage,
# the same "too slow for the hot path" reasoning that already keeps
# ci-reproducible (two links) and wire_sweep's nightly seed sweep
# ("never gates the normal build or make ci/make test", see wire-sweep
# above) out of `make ci`. The corpus regressions this lane exists to catch
# are covered instead by `make simnet-nightly` via the
# zclassic23-simnet-nightly.timer (deploy/), not by the hot loop.
.PHONY: ci-reproducible
ci-reproducible:
	@bash tools/scripts/check_reproducible_build.sh

# repro-verify: the STANDING two-builder byte-identity gate. Unlike
# ci-reproducible above (which builds twice in the SAME source directory,
# differing only by BUILD_DIR, under the release flag profile), repro-verify
# builds the node binary twice in two DIFFERENT absolute directories — a real
# two-builder simulation. That is the only configuration that exposes
# absolute-build-path nondeterminism (DW_AT_comp_dir in DWARF, which perturbs
# the split .debug sidecar's .gnu_debuglink CRC and the content-derived
# build-id); the default build's REPRO_CFLAGS (-ffile-prefix-map +
# -gno-record-gcc-switches, see near the CFLAGS definition) canonicalizes it so
# both builders produce a byte-identical build/bin/zclassic23. The gate compares
# the shipped (stripped) artifacts AS SHIPPED — it strips nothing itself and, on
# any residual divergence, reports the exact differing ELF sections + byte
# offsets rather than papering over them. See docs/SECURITY_AND_INTEGRITY.md
# "Reproducible build gate". DELIBERATELY opt-in (NOT in `make ci` / `make lint`)
# — it runs TWO full whole-program LTO links (~2x a normal `make zclassic23`).
.PHONY: repro-verify
repro-verify:
	@bash tools/scripts/repro-verify.sh

ci: vendor-ready lint bench-regress zclassic23 $(TEST_PARALLEL_REL_CANDIDATE)
	@echo "══ CI: portability symbol-floor (C1) ══"
	$(MAKE) ci-symbol-floor
	@echo "══ CI: test (per-process isolated runner) ══"
	@# Flake-tolerance: a rare resource-pressure flake under full 32-worker load
	@# (verified: green in isolation, ~1/4 under load) must not false-fail the
	@# gate. Retry ONCE — a real regression fails BOTH passes (deterministic); a
	@# flake passes on retry and is logged LOUDLY here so it stays visible and
	@# tracked, never silently swallowed. Deep root-cause of the flake is a
	@# separate follow-up; this keeps the gate trustworthy + armable now.
	@#
	@# The retry runs --no-cache, and that is load-bearing. "A real regression
	@# fails BOTH passes" holds only while both passes actually EXECUTE the same
	@# groups. With the cache enabled, pass 1 fails group G and still stores a
	@# PASS for the ~742 groups that succeeded; pass 2 would then skip those 742
	@# and re-run G alone on an unloaded box, where a load-sensitive failure
	@# gets lucky and stores its own PASS — after which G is skipped forever.
	@# The retry would launder a flake into a permanent cached green. Forcing
	@# the retry cold keeps it the independent second opinion it claims to be.
	@ulimit -s unlimited; if $(TEST_PARALLEL_REL_ACTIVE); then :; else \
		echo "[ci] !! test_parallel FAILED first pass — retrying ONCE, COLD (--no-cache: a cached retry would re-run only the failing group and launder a flake into a stored PASS) !!"; \
		ulimit -s unlimited; $(TEST_PARALLEL_REL_ACTIVE) --no-cache; \
	fi
	@echo ""
	@echo "══ CI: mvp-gates (hermetic MVP acceptance #3/#5/#7) ══"
	$(MAKE) ci-mvp-gates
	@echo ""
	@# C6 judge-logic regression guard: the soak-evidence verdict machine is the
	@# ONLY soak-side item that is fully hermetic (mktemp JSONL fixtures + injected
	@# timestamps, no node, no network, no params — <1s). Gating it here protects
	@# the VERDICT=MET|NOT_MET|INSUFFICIENT logic that scores the real 168h window.
	@# It does NOT shortcut the soak hours, so C6 stays ◐ — only the judge LOGIC is
	@# now CI-protected, not the soak claim itself.
	@echo "══ CI: soak-evidence-selftest (hermetic C6 verdict-judge guard) ══"
	$(MAKE) soak-evidence-selftest
	@echo ""
	@# The evidence ledgers that make an operational claim checkable: the
	@# intervention record (a config edit or binary swap with NO restart is
	@# an event), the declaration front door, and the only EXTERNAL
	@# availability probe. Hermetic, <2s, no node and no network.
	@echo "══ CI: evidence-selftest (intervention + external availability ledgers) ══"
	$(MAKE) evidence-selftest
	@echo ""
	@# The only evidence in this repo that compares a block HASH against
	@# genuinely remote peers instead of a height number against the
	@# sibling zclassicd on this box. Covers all three recorded outcomes,
	@# including the one that matters: an unreachable or interrupted source
	@# records could-not-ask and the judge does not pass on it. Hermetic,
	@# <5s, no node and no network.
	@echo "══ CI: tip-agreement-selftest (off-host tip-hash agreement ledger + judge) ══"
	$(MAKE) tip-agreement-selftest
	@echo ""
	@echo "══ CI: test-crash ══"
	$(MAKE) test-crash
	@echo ""
	@if [ "$(SKIP_FUZZ)" != "1" ]; then \
		echo "══ CI: fuzz-ci ══"; \
		$(MAKE) fuzz-ci || exit 1; \
		echo ""; \
		echo "══ CI: fuzz-replay (saved findings must not still reproduce) ══"; \
		$(MAKE) fuzz-replay || exit 1; \
		echo ""; \
	else \
		echo "══ CI: fuzz-ci + fuzz-replay (SKIPPED — SKIP_FUZZ=1) ══"; \
	fi
	@if [ "$(SKIP_COV)" != "1" ]; then \
		echo "══ CI: coverage ══"; \
		$(MAKE) coverage || exit 1; \
	else \
		echo "══ CI: coverage (SKIPPED — SKIP_COV=1) ══"; \
	fi
	@echo ""
	@# MVP scoreboard — VISIBLE per-criterion status report (AGENTS.md P1).
	@# Non-fatal: the synced-node-dependent criteria (C3 cold-start-to-tip,
	@# C6 168h soak, C8 parity-over-soak) are legitimately BLOCKED while the
	@# live node is stopped/wedged below tip, so this must NOT fail the build.
	@# A real hermetic-slice regression prints FAIL in the scoreboard and is
	@# the signal to investigate (the underlying slice ALSO fails in the
	@# build-fatal ci-mvp-gates stage above, so a regression still breaks CI).
	@echo "══ CI: mvp scoreboard (honest 8/8 status — non-fatal report) ══"
	$(MAKE) mvp
	@echo ""
	@echo "══ CI: ALL STAGES PASSED ══"

audit:
	@tools/dep_audit.sh

check-restart-follow:
	$(ZCL_NODECTL_BIN) verify-follow --restart

# ── postmortem_to_scenario: capsule -> chaos-scenario skeleton bridge ─────
# (Super-Reliability / Detective Node program, lane B5). Converts an
# unpacked postmortem crash capsule (lib/sim/include/sim/postmortem.h)
# into a .scenario SKELETON for the chaos DSL (tools/sim/chaos.c,
# docs/CHAOS_HARNESS.md "From Capsule To Scenario"). Automates ONLY the
# seed + best-effort boot-phase steps; translating the recorded events
# into chaos commands and adding the assertion that would have caught the
# bug stays manual — see the TODO block the tool emits. Standalone build:
# only the libs it directly uses (sim/postmortem + sim/seed_tape,
# platform/clock + platform/rng, util/signal_handler + util/clientversion
# + util/safe_alloc, lib/json) — no DB, no node libs, no Tor, same
# discipline as tools/gen_sha3_windows.c. Appended as a single
# self-contained block at the end of this file to minimize merge conflict
# surface with other in-flight sim/* lanes.
.PHONY: tools/postmortem_to_scenario
tools/postmortem_to_scenario: $(BIN_DIR)/postmortem_to_scenario
$(BIN_DIR)/postmortem_to_scenario: tools/postmortem_to_scenario.c \
		lib/sim/src/postmortem.c lib/sim/src/seed_tape.c \
		lib/platform/src/clock.c lib/platform/src/rng.c \
		lib/util/src/signal_handler.c lib/util/src/clientversion.c \
		lib/util/src/async_safe_write.c \
		lib/base/src/safe_alloc.c lib/base/src/log_level.c \
		lib/json/src/json.c
	@mkdir -p $(dir $@)
	$(CC) -std=c23 -O2 -Wall -Wextra -Werror -pedantic \
	    -Wno-format-truncation \
	    -Ilib/sim/include -Ilib/platform/include -Ilib/base/include -Ilib/util/include \
	    -Ilib/json/include \
	    -D_POSIX_C_SOURCE=200809L \
	    -o $@ $^ -Lvendor/lib -l:libz.a -lpthread -lm

.PHONY: postmortem-to-scenario
postmortem-to-scenario: tools/postmortem_to_scenario
	@if [ -z "$(CAP)" ]; then \
	    echo "usage: make postmortem-to-scenario CAP=<capsule-dir> [OUT=<path>]"; \
	    exit 2; \
	fi
	$(BIN_DIR)/postmortem_to_scenario --cap=$(CAP) $(if $(OUT),--out=$(OUT),)

# ── Entry points: help, setup, doctor, timings, pr-check ─────────────────
# Appended as one self-contained block at the end of the file to keep the
# merge surface with in-flight lanes minimal. The content of each lives in
# tools/scripts/, so the Makefile side stays a single line per target.
#
# These exist because this file had hundreds of targets and no front door:
# `make help` printed "No rule to make target 'help'", the prerequisite list
# lived in three prose files that disagreed with each other and with
# build_vendor.sh, and there was no way to ask the host how long anything
# actually takes. `make help` prints the live target count; do not restate it
# here.
.PHONY: help setup doctor timings pr-check help-selftest doctor-selftest timings-selftest first-build-timing first-build-timing-selftest

help:
	@tools/scripts/make_help.sh

# Idempotent, and it announces every file it touches: nothing should appear
# on disk that the operator did not see named first.
setup:
	@if [ -n "$(ZCL_SOVEREIGN_SOURCE_ROOT)" ]; then \
	    echo "══ setup: preparing Git-free sovereign source ══"; \
	    echo "  skipped Git hooks           no .git authority or metadata required"; \
	else \
	    echo "══ setup: arming this clone ══"; \
	    $(MAKE) --no-print-directory install-hooks; \
	    echo "  wrote  .git/config          core.hooksPath = tools/githooks"; \
	fi
	@$(MAKE) --no-print-directory compdb
	@echo "  wrote  compile_commands.json  (clangd/LSP; regenerate with make compdb)"
	@echo "  wrote  .cache/               (gitignored tool caches, created on demand)"
	@echo "setup: done. Next: make doctor"

# What is missing on THIS host, and the one command that installs it.
# Source of truth is tools/scripts/vendor_prereqs.tsv; the script fails if
# that table has fallen behind build_vendor.sh.
doctor:
	@tools/scripts/doctor.sh

# Where the wall time went, read from artifacts measured on this host.
# Never prints a duration it did not measure here.
timings:
	@tools/scripts/timings.sh

# What a newcomer's first build costs: clone this repository into a scratch
# directory, run the whole fresh-clone sequence, and time each stage. Writes
# .cache/first-build-timing/last-run.json, which `make timings` reads — that
# is how the published figure gets refreshed without editing markdown.
# It runs a full build and the full test suite, so it is not quick.
first-build-timing:
	@tools/scripts/first_build_timing.sh $(ARGS)

# What an outside contributor can run before opening a PR, with nothing built.
# Same two checks the public gate runs, in the same order.
pr-check:
	@echo "══ pr-check: lint + whole-tree syntax ══"
	@$(MAKE) --no-print-directory lint
	@$(MAKE) --no-print-directory syntax-check
	@tools/scripts/make_help.sh --self-test
	@tools/scripts/doctor.sh --prereq-coverage
	@tools/scripts/timings.sh --self-test
	@tools/scripts/first_build_timing.sh --self-test
	@echo "══ pr-check: passed ══"

help-selftest:
	@tools/scripts/make_help.sh --self-test

doctor-selftest:
	@tools/scripts/doctor.sh --self-test

timings-selftest:
	@tools/scripts/timings.sh --self-test

first-build-timing-selftest:
	@tools/scripts/first_build_timing.sh --self-test

# ── Lint gate: blanket warning suppressions stay named ───────────────────
# The unused-result suppression is the flag that ALSO disables [[nodiscard]]
# reporting on both GCC and Clang, so it silently voids the repository's
# result-type discipline; the stringop-overflow one hides a memory-safety
# diagnostic. Both arrived as unexplained copy-forward defaults in the first
# commit and had spread by copy-paste to seven compile rules. It does not ban
# them, it
# bans an UNEXPLAINED one: any instance needs a `suppression-ok: <reason>`
# marker on its line or the line above. Carries hermetic detector fixtures and
# runs them before it certifies the tree, so it cannot report clean while
# blind. Self-test: tools/lint/check_no_warning_suppression.sh --self-test
check-no-warning-suppression:
	@echo "══ LINT: unexplained warning suppressions ══"
	@./tools/lint/check_no_warning_suppression.sh .

# ── Entry point: build-bench ─────────────────────────────────────────────
# What the build and test loop costs on THIS host, measured with a wall clock
# and written to .cache/build-bench/last-run.json. It exists so that any claim
# about build speed — including the ones the build/test cache work is about to
# make — has a measured baseline to be compared against instead of a
# remembered one. Same honesty contract as `make timings`: a scenario that was
# skipped, failed, or did not measure what it claims publishes NO duration.
#
#   make build-bench                    full baseline (two cold builds + the
#                                       whole suite; not quick)
#   make build-bench ARGS=--quick       inner-loop subset, no cold work
#   make build-bench ARGS='--samples=5 --group=<substr>'
#   make build-bench ARGS=--report      re-read the last artifact, measure nothing
#
# The primary scenarios run with ZCL_USE_CCACHE=0 on purpose: this Makefile
# prepends any sccache/ccache it finds to $(CC) (see the top of this file), and
# a warm compiler cache reports a compile time the compiler never paid. The
# ccache-enabled variants are measured separately and labelled.
.PHONY: build-bench build-bench-selftest
build-bench:
	@tools/scripts/build_bench.sh $(ARGS)

build-bench-selftest:
	@tools/scripts/build_bench.sh --self-test
