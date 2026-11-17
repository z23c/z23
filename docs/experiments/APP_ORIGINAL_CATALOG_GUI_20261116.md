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
A forced-R2 focused selftest passed on source `af723415d67fb74be219526c6cafe59cb7a11641`. The optional real-Xvfb probe connected through x11grab and checked pathname artifact absence at its observation points and after TERM, KILL and supervised owner loss. It used Xvfb 2:21.1.12-1ubuntu1.6 and ffmpeg 7:6.1.1-3ubuntu5. The verified gate archive was retained and successful scratch released. Live original-share catalog retrieval and display: NOT RUN.
