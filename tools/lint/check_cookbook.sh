#!/bin/sh
# Copyright 2026 Rhett Creighton - Apache License 2.0
# purpose: every cookbook recipe still works and docs/dev/COOKBOOK.md matches the registry.
l=$(dirname "$0")/../../build/bin/z23-lint; [ -x "$l" ] || make -s -C "$(dirname "$0")/../.." build/bin/z23-lint >&2 || exit 2
exec "$l" check-cookbook "$@"
