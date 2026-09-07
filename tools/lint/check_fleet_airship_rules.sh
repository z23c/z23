#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton. Licensed under Apache-2.0.
# Prove every paying fleet airship rule names a fact a peer observed.
exec "$(dirname "$0")/../../build/bin/z23-lint" check-fleet-airship-rules "$@"
