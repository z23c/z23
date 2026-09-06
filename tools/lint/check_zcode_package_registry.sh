#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton. Licensed under Apache-2.0.
# Purpose: verify package roots and exact-once monolith source ownership.
exec "$(dirname "$0")/../../build/bin/z23-lint" check-zcode-package-registry "$@"
