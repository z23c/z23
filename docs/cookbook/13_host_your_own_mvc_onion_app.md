# 13 — host your own MVC onion app

## What it demonstrates

Every z23 node is a .onion web server, and an "app" is not a
plugin system or a VM — it is one declarative manifest, one controller,
and one mount, all plain C, all reviewed like every other file in the
tree. This recipe walks the whole loop using the two apps that ship in
the repo as the worked examples:

- `contexts/commons/apps/blog/app.def` — the reference MVC/ActiveRecord application
  (signed posts, a publication projection, read-only public pages).
- `contexts/commons/apps/yardsale/app.def` — the for-sale-by-owner swap app: sellers pin
  signed, expiring ads into the gossip yardsale, and a buyer settles
  directly with the seller through the two-message ceremony. Never a
  matching engine — the app remembers signs and carries ceremony wires.

The shape, end to end:

1. **Write the manifest** — `apps/<id>/app.def`. This declares intent —
   it names the app, the capabilities it ASKS for
   (`ZCL_APP_CAPABILITY(...)`), its resources, its P2P topic, its web
   mount, and whether it binds the onion and a ZNAM name. The strict
   compiler (`engine/modules/framework/src/app_definition.c`) rejects anything else,
   and the `site_routes` test group proves the declared mount and the
   route registry can never drift apart. Copy the yardsale's:

   ```
   ZCL_APP("yardsale", "ZClassic Yardsale", "0.1.0")
   ZCL_APP_CAPABILITY(CHAIN_READ)
   ...
   ZCL_APP_RESOURCE("ads")
   ZCL_APP_TOPIC("yardsale.ads.v1", 1, 4096)
   ZCL_APP_WEB_MOUNT("/yardsale")
   ZCL_APP_ONION(true)
   ZCL_APP_ZNAM("yardsale")
   ZCL_APP_STATE_SCHEMA(1)
   ```

2. **Register the app id** — add it to `g_builtin_app_ids[]` in
   `engine/modules/framework/src/app_catalog.c`, and extend the catalog asserts in
   `tests/harness/src/test_dev_platform.c` (the strict-compiler test pins the
   builtin list; it will fail until you teach it your app exists).

3. **Write the controller** — `engine/controllers/src/<id>_controller.c`
   (plus its header under `engine/controllers/include/controllers/`). One
   function is the whole web contract, the same shape the blog uses:

   ```c
   size_t <id>_site_handle_request(const char *method, const char *path,
                                   const uint8_t *body, size_t body_len,
                                   uint8_t *response, size_t response_max);
   ```

   Parse the path, call your model layer, render into `response`, return
   the length. Read-only pages take the db from `app_runtime_node_db()`
   and fail closed (return 0 — the dispatcher serves 503) when the
   projection is absent. Look at
   `contexts/market/controllers/src/yardsale_site_controller.c` for the bounded
   version: security headers, urlencoded form parsing, named error pages,
   and the 800-line file-size ceiling in mind from the first keystroke.

4. **Mount it — one registry row.** Add a single `SITE_ROUTE(...)` row to
   `core/modules/net/include/net/site_routes.def`. That one row is expanded by
   every consumer at once: the onion dispatch chain, the HTTPS dispatch
   chain, the rate-limit cost classifier, the onion + app navs, and the
   landing-page grid. There is no step two — the days of hand-editing
   `onion_service.c` / `https_server.c` / `onion_ratelimit.c` and two nav
   tables in lockstep are over. Pick the flavor column by copying the
   nearest neighbor: `DATADIR` for read-only projection pages (zcode,
   metaverse), `FAILCLOSED` when a missing projection must be a 503
   (blog, yardsale), `ZCL_SITE_F_POST_ONION` when you take mutating form
   POSTs — POSTs are honored only on the onion transport, the public
   HTTPS listener is GET/HEAD-only, so mutating forms are onion-only by
   construction. Choose the cost class honestly: it is your DoS budget
   on an unauthenticated surface.

5. **Prove it** — a new `tests/harness/src/test_<id>_app.c` with
   `int test_<id>_app(void)`, registered in BOTH places the
   check-test-registration gate cross-checks: a
   `ZCL_TEST_GROUP(<id>_app)` row in `tools/dev/test_group_catalog.def`
   and an extern call in `tests/harness/src/test.c`. Add an
   `AGENT_IMPACT_RULE` row mapping your files to your group in
   `cognition/controllers/include/controllers/agent_impact_rules.def`. Then:

   ```bash
   make -j"$(nproc)"
   make -j"$(nproc)" t-fast ONLY=<id>_app
   make -j"$(nproc)" t-fast ONLY=site_routes   # registry <-> manifest drift check
   make lint
   ```

If your app carries P2P messages of its own, do it the yardsale way: a
dispatch row in `core/modules/net/src/msgprocessor.c`'s table plus an injected
port (core/modules/net never names your lib's symbols — the composition root in
`engine/composition/src/boot_msg_callbacks.c` wires it), and the ceremony/app logic
in your controller where tests can drive it in-process.

## Privacy posture — why the onion is the whole point

A marketplace where participants must expose an IP address is not a P2P
marketplace. The rules that keep it one:

- **Mutating forms are onion-only.** `ZCL_SITE_F_POST_ONION` rows are
  honored only on the onion transport; the clearnet HTTPS listener
  rejects non-GET/HEAD before dispatch. A buyer's `accept` never travels
  a path that reveals their IP to the seller's web logs — it arrives
  through a Tor rendezvous circuit like every other onion request.
- **The unauthenticated surface is budgeted.** Your row's cost class is
  enforced per-route with escalation to a proof-of-work puzzle; choose
  EXPENSIVE for anything that blocks or dials out (the `/n/` gateway
  precedent).
- **The whole response fits 64 KiB.** One dynhost buffer, no streaming —
  render with `SITE_APPEND` truncation guards from the first keystroke.
- **A node with no clearnet endpoint loses nothing.** Tor-only operators
  keep the full app surface; clearnet HTTPS is only ever a convenience
  mirror of the read-only pages.

To smoke two onion nodes trading, build the vendored Tor
(`git submodule update --init vendor/tor`, then per `docs/BUILD.md`),
boot two isolated datadirs with `-tor` (see
`tools/scripts/isolated_node_env.sh` for the port-discipline pattern),
and walk the seller → gossip → buyer-accept loop by hand.

## Build / run

Nothing to compile separately — the apps build into the one binary:

```bash
make -j"$(nproc)" && build/bin/z23 -tor
# then browse http://<your-node>.onion/yardsale
```

## Expected output sketch

```
$ build/bin/z23 dev app list
blog       ZClassic Blog       0.1.0
social     ZClassic Social     0.1.0
yardsale   ZClassic Yardsale   0.1.0

$ make -j"$(nproc)" t-fast ONLY=yardsale_app
  yardsale_app: manifest: yardsale app.def compiles... OK
  yardsale_app: ceremony: accept wire is the Stage-3 golden vector... OK
  yardsale_app: ceremony: partial wire is the Stage-3 golden vector... OK
  yardsale_app: ceremony: broadcast tx is the Stage-3 golden final tx... OK
  ...
=== yardsale_app complete: 0 failure(s) ===
```
