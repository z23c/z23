@AGENTS.md

Claude Code notes:

- Skills: `.claude/skills/` (`z23-dev`, `z23-lane`) route to the documents above. Plugins: `.claude/plugin` (volunteer `z23-work` loop, local) and `.claude/plugin-fleet` (opt-in fleet adapters).
- Never read `docs/DEVELOPING.md` whole; list sections with `grep -n '^## ' docs/DEVELOPING.md` and open the linked one.
- Nested `CLAUDE.md` files import the `AGENTS.md` beside them and load when you work in that directory.
- Skills and plugins grant no extra consensus, custody, datadir, deployment or evidence authority.
