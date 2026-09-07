#!/usr/bin/env bash
# Phase-0 containment: no production path may create a network release until
# immutable quality/release evidence and the signed stable publisher exist.
# The Makefile recipe still passes this script's own --self-test spelling;
# z23-lint's flag is --selftest (no hyphen) — translated here, the one place
# that difference has to live.
if [[ "${1:-}" == "--self-test" ]]; then
    shift
    exec "$(dirname "$0")/../../build/bin/z23-lint" \
        check-stable-publish-contained --selftest "$@"
fi
exec "$(dirname "$0")/../../build/bin/z23-lint" check-stable-publish-contained "$@"
