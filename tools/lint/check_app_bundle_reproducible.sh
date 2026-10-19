#!/bin/sh
# Copyright 2026 Rhett Creighton - Apache License 2.0
# Gate wrapper - see tools/lint/lintc/gate_app_bundle_reproducible.c for the
# gate. The path stays because docs/node/MACOS_GUI_QUICKSTART.md invokes --bin here.
exec "$(dirname "$0")/../../build/bin/z23-lint" check-app-bundle-reproducible "$@"
