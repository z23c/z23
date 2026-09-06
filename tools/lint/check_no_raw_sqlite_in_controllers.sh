#!/usr/bin/env bash
# Gate #20: controllers should not prepare/exec SQLite directly.
exec "$(dirname "$0")/../../build/bin/z23-lint" check-no-raw-sqlite-in-controllers "$@"
