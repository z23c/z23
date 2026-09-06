#!/usr/bin/env bash
# Gate: HONEST WITNESS (Law 7 — "heal in the open, page when stuck").
exec "$(dirname "$0")/../../build/bin/z23-lint" check-honest-witness "$@"
