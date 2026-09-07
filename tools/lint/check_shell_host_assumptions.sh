#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
# Shrink-only rail for shell commands whose spellings silently assume Linux/GNU.


exec "$(dirname "$0")/../../build/bin/z23-lint" check-shell-host-assumptions "$@"
