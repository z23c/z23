#!/usr/bin/env bash
# check_domain_purity — HARD domain/ include fence (native).
exec "$(dirname "$0")/../../build/bin/z23-lint" check-domain-purity "$@"
