#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
# purpose: HARD gate — every registry package compiles from its OWN declared
exec "$(dirname "$0")/../../build/bin/z23-lint" check-zcode-package-standalone "$@"
