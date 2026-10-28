# Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
# Schedule single-goal fixture builds with the inherited GNU Make jobserver.
# Only synthetic numeric node names enter this graph; target/path values stay
# in private mapping files and are read as shell data. The caller checks every
# result, including missing results after a terminated recipe. Ignoring recipe
# errors here lets all independent nodes finish without exporting -k or -i to
# the real builds and changing their error policy.
.SUFFIXES:
.PHONY: all $(ZCL_TEST_NEED_IDS)
.IGNORE: $(ZCL_TEST_NEED_IDS)
all: $(ZCL_TEST_NEED_IDS)

$(ZCL_TEST_NEED_IDS):
	+@target=$$(cat "$${ZCL_TEST_NEED_DIR}/$@.target") || exit 2; \
	build_failed=0; \
	$(MAKE) --no-print-directory -f "$${ZCL_TEST_NEED_MAKEFILE}" "$$target" </dev/null || build_failed=1; \
	failed="$$build_failed"; \
	while read -r alias path; do \
	  if [ "$$build_failed" != 0 ] || [ ! -e "$$path" ]; then \
	    echo "FAIL test_need_unbuildable_$$alias: make $$target did not produce $$path" >&2; \
	    failed=1; \
	  fi; \
	done < "$${ZCL_TEST_NEED_DIR}/$@.outputs" || failed=1; \
	printf '%s\n' "$$failed" > "$${ZCL_TEST_NEED_DIR}/$@.rc"
