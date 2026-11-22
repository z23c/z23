<!-- Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 -->

# Landing timer cadence

On 2026-11-22, disposable user timers on Linux with systemd 255 (255.4) ran one-shot fixtures on an AMD Ryzen 9 7950X3D. The fixtures slept for a specified first-run duration and then one second on later runs. Ubuntu Clang 20.1.8 was installed; no compilation was involved. Each result below is one observation, not a latency guarantee.

| Timer | First work | Finish-to-next-start |
| --- | ---: | ---: |
| `OnUnitInactiveSec=20s` | 38 s | 20.021 s |
| `OnUnitActiveSec=30s` and `OnUnitInactiveSec=20s` | 38 s | 0.018 s |
| `OnUnitInactiveSec=20s` | 22 s | 20.034 s |
| Both monotonic triggers | 22 s | 8.113 s |
| `OnUnitActiveSec=30s` | 38 s | 0.210 s |
| Calendar at seconds 00 and 30 | 38 s | 0.018 s |

In the one-second idle-like control, the combined timer and the inactive-only timer each started three times over the same observation period, with approximately 21-second start intervals. The active-only timer started twice at a 30-second interval. Last-activation service CPU readings were approximately 4–6 ms where systemd retained them; total host CPU was not measured.

The shipped timer retains the 20-second inactive trigger and adds the 30-second active trigger. Both use monotonic time, avoiding calendar-clock adjustments; the two-minute boot trigger and one-row service remain in place. An idle run of at most ten seconds cannot be started sooner by the active trigger. The change is reversible: remove the added `OnUnitActiveSec=30s` line from the timer source and reinstall the timer using the normal host unit installation procedure. No service or production unit was changed for this experiment.
