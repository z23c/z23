#!/usr/bin/env bash
# check_model_ar_lifecycle.sh
#
# Model saves must not hand-run the ActiveRecord callback internals. Use
# AR_BEGIN_SAVE / AR_ADHOC_SAVE / AR_FINISH_SAVE so validation, callbacks,
# logging, and future lifecycle hooks stay mechanically consistent.

exec "$(dirname "$0")/../../build/bin/z23-lint" check-model-ar-lifecycle "$@"
