#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
# Verify the checkout-local hook set selected for this host.

exec "$(dirname "$0")/../../build/bin/z23-lint" check-git-hooks-installed "$@"
