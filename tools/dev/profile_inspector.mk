# Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
# Offline experimental inspector; invoke from the repository root:
#   devbuild --wait make -f tools/dev/profile_inspector.mk
# Run: build/bin/profile-inspector MANIFEST GENESIS [EXPECTED_CATALOG_HEX]
# Create: build/bin/profile-create OUTPUT_DIR TIMESTAMP START WINDOW REVISION_HEX ACTIVATION [REVISION_HEX ACTIVATION ...]
# Revisions must be strictly ascending raw bytes; the output directory must not exist.
# On Linux and Darwin, publish the complete directory with an exclusive rename.
# A process crash before publication may leave a private .z23-profile.* sibling.
# The same OUTPUT_DIR is available for retry. Read result/{manifest.bin,genesis.bin} there.
# Record the printed catalog as this new profile's pin. When checking someone
# else's network, use a previously agreed pin: an artifact's own catalog does
# not independently authenticate which chain was intended.
# This creates a fixture profile only; it does not install or activate network rules.
# Override OUT or CREATE_OUT to select different binary paths.
OUT ?= build/bin/profile-inspector
CREATE_OUT ?= build/bin/profile-create
INCLUDES := -Icore/modules/net/include -Iplatform/modules/platform/include \
 -Iengine/services/include -Icore/modules/primitives/include -Icore/modules/script/include \
 -Icore/modules/core/include -Icore/modules/sapling/include -Icore/modules/crypto/include \
 -Icore/math/include -Iplatform/modules/base/include -Iplatform/modules/util/include \
 -Iplatform/modules/sha3/include -Iplatform/modules/encoding/include
COMMON_SOURCES := tools/dev/profile_inspector/common.c engine/services/src/miner_signal_catalog.c \
 platform/modules/sha3/src/sha3.c platform/modules/base/src/result.c \
 platform/modules/base/src/log_level.c platform/modules/base/src/safe_alloc.c \
 platform/modules/encoding/src/utilstrencodings.c core/modules/primitives/src/transaction.c \
 core/modules/primitives/src/block.c core/math/src/serialize.c core/math/src/hash.c \
 core/math/src/arith_uint256.c core/math/src/uint256.c core/modules/crypto/src/sha256.c \
 core/modules/crypto/src/blake2b.c core/modules/crypto/src/blake2b_avx2.c \
 core/modules/crypto/src/simd_dispatch.c core/modules/crypto/src/equihash.c
CPPFLAGS_PROFILE := -D_POSIX_C_SOURCE=200809L
ifeq ($(shell uname -s),Darwin)
CPPFLAGS_PROFILE += -D_DARWIN_C_SOURCE
LDFLAGS_PROFILE := -Wl,-dead_strip
else
LDFLAGS_PROFILE := -Wl,--gc-sections
endif
.PHONY: all check
all: $(OUT) $(CREATE_OUT)
check: all
	@set -eu; tmp=$$(mktemp -d "$${TMPDIR:-/tmp}/z23-profile-check.XXXXXX"); \
	 trap 'rm -rf "$$tmp"' 0 HUP INT TERM; \
	 $(CREATE_OUT) "$$tmp/profile" 1795737600 1 20 \
	  36240f5b89f9b4f8f28a892e6aaedda851e7efff4dcb4393df34745bc2508865 23 \
	  c23e01cb45bb89ee8e32fa44c34aee8fd90d2aac0d057e2d447261b089e74a4e 25 > "$$tmp/create.out"; \
	 $(OUT) "$$tmp/profile/result/manifest.bin" "$$tmp/profile/result/genesis.bin" \
	  b1ca14677a23c6162d2ea3fbefcfa65e0b3039bc911f4b34c8ea6ebd2df9c373 > "$$tmp/inspect.out"; \
	 if $(OUT) "$$tmp/profile/result/manifest.bin" "$$tmp/profile/result/genesis.bin" \
	  2aafc4959fe4da89be30020ba5ff5b2b77638cf6d3af169d35d053e610741c6a > "$$tmp/wrong.out" 2> "$$tmp/wrong.err"; then \
	  echo 'wrong catalog unexpectedly accepted' >&2; exit 1; fi; \
	 test ! -s "$$tmp/wrong.out"; \
	 if $(OUT) "$$tmp/profile/result/manifest.bin" "$$tmp/profile/result/genesis.bin" \
	  >&- 2> "$$tmp/write.err"; then echo "closed stdout unexpectedly accepted" >&2; exit 1; fi; \
	 grep -q "output write failed" "$$tmp/write.err"; \
	 set -- 1795737600 1 20; i=1; \
	 while test $$i -le 64; do set -- "$$@" "$$(printf '%064x' "$$i")" 25; i=$$((i+1)); done; \
	 rc=0; (ulimit -c 0 && ulimit -f 1 && exec $(CREATE_OUT) "$$tmp/retry" "$$@") > "$$tmp/crash.out" 2>&1 || rc=$$?; \
	 case "$$(kill -l "$$rc")" in XFSZ|SIGXFSZ) ;; *) echo "unexpected exit $$rc from interrupted creator" >&2; exit 1;; esac; \
	 test ! -e "$$tmp/retry"; \
	 $(CREATE_OUT) "$$tmp/retry" "$$@" > "$$tmp/retry.out"; \
	 $(OUT) "$$tmp/retry/result/manifest.bin" "$$tmp/retry/result/genesis.bin" a32b54de083b29329e38d399f047ed032e1e8d02fd56797be980638177961187 > "$$tmp/retry-check.out"; \
	 echo 'profile-create: golden round-trip, wrong-pin refusal and interrupted retry passed'
$(OUT): TOOL_SOURCES := tools/dev/profile_inspector/main.c $(COMMON_SOURCES)
$(CREATE_OUT): TOOL_SOURCES := tools/dev/profile_inspector/create.c $(COMMON_SOURCES)
$(OUT): tools/dev/profile_inspector/main.c $(COMMON_SOURCES) tools/dev/profile_inspector.mk
$(CREATE_OUT): tools/dev/profile_inspector/create.c $(COMMON_SOURCES) tools/dev/profile_inspector.mk
$(OUT) $(CREATE_OUT):
	@mkdir -p $(dir $@)
	@set -eu; tmp=$$(mktemp -d "$(dir $@).profile-inspector.XXXXXX"); \
	 trap 'rm -rf "$$tmp"' 0 HUP INT TERM; \
	 $(CC) -std=c23 $(CPPFLAGS_PROFILE) $(INCLUDES) -MM -MP -MT $@ $(TOOL_SOURCES) > "$$tmp/deps"; \
	 $(CC) -std=c23 -O2 -Wall -Wextra -Werror -pedantic $(CPPFLAGS_PROFILE) \
	  -ffunction-sections -fdata-sections $(INCLUDES) $(TOOL_SOURCES) $(LDFLAGS_PROFILE) -o "$$tmp/binary"; \
	 mv "$$tmp/deps" $@.d; mv "$$tmp/binary" $@
-include $(OUT).d $(CREATE_OUT).d
