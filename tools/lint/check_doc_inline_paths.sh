#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
cd "$(dirname "$0")/../.." && exec build/bin/z23-lint check-doc-inline-paths "$@"
