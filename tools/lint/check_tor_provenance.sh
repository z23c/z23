#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
"$ROOT/build/bin/z23-tor-provenance" --selftest &&
exec "$ROOT/build/bin/z23-tor-provenance" check "$ROOT/vendor/tor" --tor-commit "$(git -C "$ROOT/vendor/tor" rev-parse HEAD)"
