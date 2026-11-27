# Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
# Offline experimental inspector; invoke from the repository root:
#   devbuild --wait make -f tools/dev/profile_inspector.mk
# Run: build/bin/profile-inspector MANIFEST GENESIS [EXPECTED_CATALOG_HEX]
# Override OUT to select a different output path.
OUT ?= build/bin/profile-inspector
INCLUDES := -Icore/modules/net/include -Iplatform/modules/platform/include \
 -Iengine/services/include -Icore/modules/primitives/include -Icore/modules/script/include \
 -Icore/modules/core/include -Icore/modules/sapling/include -Icore/modules/crypto/include \
 -Icore/math/include -Iplatform/modules/base/include -Iplatform/modules/util/include \
 -Iplatform/modules/sha3/include -Iplatform/modules/encoding/include
SOURCES := tools/dev/profile_inspector/main.c engine/services/src/miner_signal_catalog.c \
 platform/modules/sha3/src/sha3.c platform/modules/base/src/result.c \
 platform/modules/base/src/log_level.c platform/modules/base/src/safe_alloc.c \
 platform/modules/encoding/src/utilstrencodings.c core/modules/primitives/src/transaction.c \
 core/modules/primitives/src/block.c core/math/src/serialize.c core/math/src/hash.c \
 core/math/src/arith_uint256.c core/math/src/uint256.c core/modules/crypto/src/sha256.c \
 core/modules/crypto/src/blake2b.c core/modules/crypto/src/blake2b_avx2.c \
 core/modules/crypto/src/simd_dispatch.c core/modules/crypto/src/equihash.c
ifeq ($(shell uname -s),Darwin)
LDFLAGS_PROFILE := -Wl,-dead_strip
else
LDFLAGS_PROFILE := -Wl,--gc-sections
endif
.PHONY: all
all: $(OUT)
$(OUT): $(SOURCES) tools/dev/profile_inspector.mk
	@mkdir -p $(dir $@)
	@set -eu; tmp=$$(mktemp -d "$(dir $@).profile-inspector.XXXXXX"); \
	 trap 'rm -rf "$$tmp"' 0 HUP INT TERM; \
	 $(CC) -std=c23 -D_POSIX_C_SOURCE=200809L $(INCLUDES) -MM -MP -MT $@ $(SOURCES) > "$$tmp/deps"; \
	 $(CC) -std=c23 -O2 -Wall -Wextra -Werror -pedantic -D_POSIX_C_SOURCE=200809L \
	  -ffunction-sections -fdata-sections $(INCLUDES) $(SOURCES) $(LDFLAGS_PROFILE) -o "$$tmp/binary"; \
	 mv "$$tmp/deps" $@.d; mv "$$tmp/binary" $@
-include $(OUT).d
