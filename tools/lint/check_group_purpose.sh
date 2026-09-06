#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton. Licensed under Apache-2.0.
exec "$(dirname "$0")/../../build/bin/z23-lint" check-group-purpose "$@"
