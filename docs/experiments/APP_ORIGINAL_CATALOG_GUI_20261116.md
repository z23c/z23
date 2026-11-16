<!-- Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 -->
# Original catalog receiver graphical observation

The opt-in `--receiver --gui` mode retains the existing catalog retrieval and
checks the returned root, publisher and rebuilt image against the sender's
public expectation. It uses an allocated Xvfb display with TCP disabled and
passes only its generated display to child commands. A native driver checks a
visible Sky Combat window and changing pixels; ffmpeg captures the display to
an owned PNG. The opened process executable hash and start token are checked
before and after that observation. Window and process observations are
separate; neither establishes window-to-process ownership or input causality.
<!-- claim: symbol-present aj_gui_observe tools/app_journey_live.c # isolated receiver GUI observation -->

The mode requires Xvfb, ffmpeg and the native UI driver. Missing tools refuse
explicitly. Default tiny-app and non-GUI roles retain their existing behavior.
Focused checks and live original-share catalog retrieval and display: NOT RUN.
