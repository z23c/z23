<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# apps/skycombat: where to change what

The game is one program. `main()` in `src/sky_combat_multiplayer_ultimate.c` is the
entry point and holds most visible tuning. Search for the symbols below; line
numbers move.

## Visible changes

- Player aircraft colour: in `main()`, the first call
  `aircraft_manager_add_with_team(game.aircraft_mgr, "PLAYER 1", RED, ...)`.
  Change its `Color` argument (any raylib colour such as `GREEN`). The other four
  calls right after it colour the AI aircraft. `render_aircraft_ultimate()` draws
  the plane from the `color` field of `managed_aircraft_t`.
- Speed, boost, throttle: `apply_boost_and_throttle()`. Boost sets
  `boost_timer = 0.75f` and `speed = AIRCRAFT_MAX_SPEED * 2.5f`; held throttle adds
  `60.0f * dt` up to `AIRCRAFT_MAX_SPEED * 1.2f`; coasting subtracts `25.0f * dt`
  down to `AIRCRAFT_MIN_SPEED`. The base limits `AIRCRAFT_MAX_SPEED` and
  `AIRCRAFT_MIN_SPEED` are `#define`s in `include/sky_combat/models/aircraft.h`.
- HUD: `render_hud_ultimate()` draws the timer, team score bars and status;
  `render_game_hud()` wraps it. The data-only HUD part (`--hud-part`, see
  `part/expr_format.md`) is fed by `update_part_hud()`, which fills the
  `XF_*` fields (`XF_BOOST_MS`, `XF_SHIELD`, ...) declared in `part/expr_format.h`.
- Enemy count and difficulty: the `aircraft_manager_add_with_team()` calls in
  `main()` are the roster (four AI entries marked as AI; add or remove calls, up
  to the manager's capacity). Difficulty is the `ai_skill` loop right below them
  (`0.6f + (float)(rand() % 40) / 100.0f`); the AI logic is `apps/skycombat/src/systems/ai_system.c`.
- Match rules: `game.match->rules.score_limit`, `time_limit`, `respawn_time`,
  `team_count` in `main()`.

## Build and preview

- Build: `make game` links `build/bin/z23-skycombat` and needs X11/GL; it does not run
  the game. `make game-check` compiles everything and links nothing (headless safe).
- Preview: run `build/bin/z23-skycombat` for a window, or
  `build/bin/z23-skycombat --qa-frames=N` to render N frames (1 to 3600,
  `SKY_COMBAT_QA_FRAMES_MAX`) and exit.
  Add `--capture=PATH` (needs `--qa-frames`) to also save the last frame as a PNG at PATH.
  On a host with no display (ssh, a server, a CI box), prefix either command with
  `xvfb-run -a`, for example `xvfb-run -a build/bin/z23-skycombat --qa-frames=120`.
  Wrap the command from the `Preview:` line that the app build step prints the same way:
  `xvfb-run -a <that command>`.

## Tests

Focused groups: `test_skycombat_models`, `test_skycombat_expr`, `test_skycombat_input`,
`test_skycombat_parts`, `test_skycombat_macho_parts`, `test_skycombat_qa_frames`,
`test_skycombat_fp_contract`. Run one with
`make t ONLY=test_skycombat_models`.
Colour and tuning edits are not covered by a unit test: confirm them with a
`--qa-frames` run. With `--capture=PATH` the frame is a fixed-step third-person
view with your aircraft at the centre, and the run also prints
`Sky Combat: player colour R,G,B at x,y` (the pixels sampled at the aircraft,
x,y in the PNG). A `RED` aircraft prints red-dominant values, `GREEN` green-dominant.
