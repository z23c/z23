#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton. Licensed under Apache-2.0.
# Enforce the physical five-authority architecture and its product rooms.
exec "$(dirname "$0")/../../build/bin/z23-lint" check-architecture-tree "$@"
