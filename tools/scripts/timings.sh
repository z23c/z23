#!/bin/sh
# Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
# Compatibility entry point for the native timing artifact reader.
root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd) || exit 1
case ${ZCL_TIMINGS_CACHE-} in
    ''|/*) ;;
    *) ZCL_TIMINGS_CACHE=$PWD/$ZCL_TIMINGS_CACHE; export ZCL_TIMINGS_CACHE ;;
esac
cd "$root" || exit 1
exec "$root/build/bin/z23-timings" "$@"
