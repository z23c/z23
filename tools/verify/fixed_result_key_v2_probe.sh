#!/bin/sh
# Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0.
d=$(mktemp -d "${TMPDIR:?run through devbuild}/z23-probe.XXXXXX") || exit 2; trap 'rm -r -- "$d"' EXIT
trap 'exit 130' INT; trap 'exit 143' TERM; trap 'exit 129' HUP
${CC:-cc} -std=c23 -Wall -Wextra -Werror -pedantic -Itools -Iplatform/modules/sha3/include -Iplatform/modules/base/include tools/verify/fixed_result_key_v2_run.c tools/verify/probe_util.c -o "$d/probe" && "$d/probe" "$0" "$@"
