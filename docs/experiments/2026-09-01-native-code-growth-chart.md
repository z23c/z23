<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Native maintained-C23 growth chart

Date: 2026-09-01T09:41:22-04:00 / 2026-09-01T13:41:22Z

## Claim boundary

The instrument reconstructs daily maintained `.c` and `.h` line changes from
the repository's first-parent Git history. Commit timestamps are grouped by
UTC day. Merge commits are compared with their first parent and rename
detection is disabled so a path move cannot manufacture line retention.
Current source roots and prune rules come from
`cognition/modules/codeindex/include/codeindex/source_roots.def` and
`cognition/modules/codeindex/include/codeindex/source_prune_dirs.def`. Test and
non-test totals remain
separate across both the current authority tree and its earlier Git paths.

This is a maintained-source measurement, not a claim about executable machine
code, optimized link retention, or a platform-specific binary source closure.
The command refuses the complete history unless its final reconstructed totals
equal a fresh walk of the current maintained tree.

## Reproducible checks

Toolchain: GCC 16.1.1 20260430

CPU: AMD Ryzen 7 PRO 8840U with Radeon 780M Graphics

The strict syntax sweep used C23 with `-Wall -Wextra -Werror -pedantic` over
the collector, corpus census, native presentation backend, hover hit-testing,
command handler, and focused tests. It completed with zero diagnostics.

The standalone parser fixture passed all six assertions:

- two UTC days reconstruct in order;
- maintained roots exclude documentation and binary numstat rows;
- non-test and test totals remain separate;
- each day retains its exact last first-parent commit;
- deletion outside reconstructed history refuses;
- malformed Git headers refuse.

The real command acceptance is:

```bash
make -j"$(getconf _NPROCESSORS_ONLN)" t-fast ONLY=code_growth
make -j"$(getconf _NPROCESSORS_ONLN)" t-fast ONLY=qr
make -j"$(getconf _NPROCESSORS_ONLN)" z23
build/bin/z23 app presentation code-growth --input='{"output":"text"}'
build/bin/z23 app presentation code-growth
```

The text form exposes one ordered field dictionary and every exact plot-point
array without opening a window; repeated JSON key text is not copied into each
day. The native form opens one display-only software-rendered window and
selects the nearest exact UTC day when the pointer moves across the plot.

## Observed results

At commit `4eec2986763ad2b70b31c9363946471b7a60c842`, the real text command
returned 83 UTC-day plot points in 8,566 bytes and exited successfully. The
cold observation took 15.598 seconds while the host was also running an exact
proof build. The final fresh-tree cross-check was true at 1,123,346 non-test
lines and 692,795 test lines: 1,816,141 maintained C23 lines total.

The original object-per-day response exceeded both the inherited response
budget and a 65,536-byte command budget. Replacing repeated keys with one
ordered field dictionary and compact point arrays preserved every value and
made the real response fit. These failures are counterexamples to increasing
the response budget as the only remedy.

The compact Linux window was then reduced from 1280 by 760 pixels to 1000 by
620 pixels. Its embedded font changed from Noto Sans Regular to deterministic
Basic Latin subsets of Inter 4.1 Medium and SemiBold. The first font test
incorrectly expected the two weights to have different integer advance
widths; that proxy failed. The corrected test renders both fonts and requires
distinct exact RGB pixels while independently checking deterministic metrics.
The complete focused presentation group passed with zero failures or skips,
and the production C23 binary passed its pinned-dependency and glibc ABI audit.

Before this typography slice was committed, the real chart command refused
with `CODE_GROWTH_UNAVAILABLE` because Git reconstruction disagreed with the
dirty live C23 census. The refusal demonstrates that the chart does not
silently present committed history as current-tree evidence.

Pixel inspection used a private 1024 by 700 X virtual framebuffer after the
operator asked that further validation not open desktop windows. The compact
render exposed two presentation defects: the original computed y-axis labels
were visually irregular, and a middle-day hover panel covered the y-axis while
showing ungrouped integers. The corrected renderer uses an overflow-safe
four-interval decimal ceiling, labels each series at its endpoint, keeps hover
panels inside the plot boundary, and groups exact hover values with thousands
separators. The scale predicate proves `1,123,394` maps to `1,200,000`, `100`
maps to `120`, and `UINT64_MAX` cannot overflow. The complete focused
presentation group passed after these changes with zero failures and skips.

## Development-loop counterexample

A resident full-suite proof for commit `dec4be78fe8e9f52fb5c7ce5628f71d9f8962a32`
continued for 8 minutes 54 seconds and held the checkout lock after newer
uncommitted source made its exact receipt unavailable. Its status was already
`proof_toolchain_or_policy_unavailable`; continuing could not prove the current
identity. Terminating that exact obsolete process group released the lock, and
the queued focused presentation group then passed. Cooperative cancellation
of obsolete proof work remains a measured orientation/build-loop improvement.

## Readability and navigation acceptance

Date: 2026-09-02T12:40:58-04:00 / 2026-09-02T16:40:58Z

Live review on the 1280 by 800 laptop display rejected the original three-date
axis and 14 to 17 pixel supporting text as insufficiently legible. The revised
1120 by 680 instrument makes total C23 lines the primary series, retains
non-test and test lines as directly labeled supporting series, and adds daily
ticks, weekly grid lines and labels, stronger month boundaries, alternating
horizontal reading bands, and a pinned exact-day inspector above the plot.
The inspector no longer moves over the data.

The time axis now contains every UTC day in the observed range. A day without
a maintained-source commit carries the prior exact totals with zero commits,
additions, and deletions. The parser fixture proves that behavior across a
two-day commit gap; this prevents equal x spacing from implying that an
inactive calendar day did not exist.

The chart opens on the latest day. Pointer hover selects the nearest exact day;
the wheel and Left/Right step one day; Page Up/Down step seven days; and
Home/End select the bounds. Axis values, weekly dates, series labels, metrics,
and the navigation strip use the embedded Inter SemiBold face. The selected-day
inspector uses 24-pixel and 19-pixel SemiBold text.

Three complete native renderings provide bounded text-size adjustment without
recollecting evidence or reopening the command. The default is Medium; Minus
and Plus select Small, Medium, or Large while preserving the selected
day. The active scale and controls remain visible in the footer. The renderings
are fixed RGB8 bitmaps under the same display-only authority as the original
chart.

Focused acceptance remains:

```bash
make -j"$(getconf _NPROCESSORS_ONLN)" t-fast ONLY=code_growth
make -j"$(getconf _NPROCESSORS_ONLN)" t-fast ONLY=qr
make -j"$(getconf _NPROCESSORS_ONLN)" z23
build/bin/z23 app presentation code-growth --input='{"output":"text"}'
build/bin/z23 app presentation code-growth
```
