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
A forced-R2 focused selftest on source
`50cc1e5422f8fc5adb4329721285621266cae2a8` passed, including real Xvfb
connection, TERM, KILL and supervised owner-loss checks. The combined
lint-fast preflight passed, including complexity, KPI floor and vendor
provenance, with zero new failures in 153 prechecks. Non-author review was
completed; verified gate evidence was retained and successful scratch released.

The same source and tree `2a14cf4673b3ad5f4eb22978084d27f539315e4b` ran on
two physical Linux hosts. The sender hosted the original share; the other
host used native catalog get to receive, rebuild and open it. The observed
package root was
`01c23f95253ea5113c25d9b2f0026b53e1a0e5d4cfff15a186b58ef55cf98e0a`, the
publisher was
`02f7291a387f374d10372fdec98443bac17388f418b9eb396c0e42e43f2019f28e`, and
the rebuilt image SHA3 was
`baf203b90f1f4149d93812ebee99695fec709aaacb5913e775fc52032f4ea0de`.
These matched the sender's public expectation. A retained frame showed the
Sky Combat HUD; its PNG SHA-256 was
`a7331ca02f85bb1495bfcde71ff3095e90c164dda3c1ea33e635de8c4d0521d2`.
The window observation and exact process/image/start-token observations are
separate. The pixel change does not establish input causality, and full
gameplay remains unproven. Both roles returned success; their supervised
processes exited and successful build scratch was released.
