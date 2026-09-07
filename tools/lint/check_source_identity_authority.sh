#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton. Licensed under Apache-2.0.
# Ratchet the Q1/Q2 source_id_sha256 naming and reader authority classes.
exec "$(dirname "$0")/../../build/bin/z23-lint" check-source-identity-authority "$@"
