# AGENTS.md — PackeTTrino-Extended

Guidance for AI agents working in this repository. Current branch: `extend/info`.

## What this project is

PackeTTrino is a fully client-side, interactive network simulator (Packet Tracer clone) written in **pure vanilla JavaScript, HTML, and CSS**. There are **no runtime dependencies and no framework** — the simulation of devices, packets, and protocols (ARP, DHCP, DNS, ICMP, TCP, HTTP) is implemented from scratch. Per-device OS-like behaviour (Linux networking, `apt` packages, `systemctl` services) is also simulated.

Originally developed by Amín Pérez (2025–Present) as a thesis project; this repo is the extended fork.

## How to run

| Task | Command | Notes |
|---|---|---|
| Dev server | `pnpm dev` (Vite) | Or just open `index.html` — everything is plain `<script>` tags |
| Build | `pnpm build` (Vite) | |
| Lint | `pnpm lint` | ESLint `src/` only; **`tests/` is explicitly ignored** by the root eslint config |
| Tests | `cd tests && pnpm test` | Vitest, run from the `tests/` workspace, has its own `package.json`, lockfile, and lint config |

Package manager: **pnpm** (10.x). Test deps are isolated under `tests/` — install separately for the test scripts (test-only toolchain: `vitest`, `linkedom`, `supertest`).

## Architecture

### Load order is the build system

The app has **no module system at runtime**: `index.html` lists ~80 `<script>` tags in a deliberate order (DOM utilities → UI components/assemblers → menus → network elements → tables → libs → packages → parsers → processors → services → terminal-command utilities → `env.js` → `unix.js` → `app.js`).

Consequences for edits:

- Every shared function across files is effectively a **global**. Adding a file means adding a `<script>` tag to `index.html` in the correct position (after its dependencies).
- `src/env.js` declares ~50 mutable global variables (device registries, in-flight-request flags like `icmpFlag`, async buffers like `tcpBuffer`, timer handles, `connTrack`). Do not introduce duplicates — check `env.js` before creating similar state.
- Device state lives partly in `env.js` registries (`pcs`, `routers`, `switches`, `servers`) and partly as **HTML data attributes on the device DOM element** (`ip-eth0`, `netmask-eth0`, `mac-eth0`, `ipv4-forwarding`, etc.). Reading/writing this state always goes through `document.getElementById(...).getAttribute/setAttribute(...)` — keep this pattern; do not invent a parallel state store.

### Directory conventions

Everything is under `src/`, and each folder has a distinct layer role:

- `src/lib/` — shared plumbing. `dom_lib.js` defines the `$` / `$$` query helpers (used everywhere instead of raw `querySelector`); `network_lib.js` has IP/MAC validation and subnet math; `component_lib.js` defines the `componentToken` class used by `app.js` to mount UI; `packets_lib.js` builds/propagates packet objects (`routing()` decides per-hop delivery); `dynamic_routing_lib.js` handles RIP-like routing.
- `src/components/` — UI. `assemblers/` return DOM elements (board, panel, tooltips); `menus/` are device configuration modals (one per device/service); `network_elements/` are the canvas items (pc, router, switch, cable, servers — e.g. `SwitchObject(x, y)` creates the element); `tables/` render live ARP/MAC/routing/DNS/DHCP tables; `messages/`, `network_tools/` (terminal, browser).
- `src/utilities/` — one file per terminal command, named `<command>_util.js` with `<command>_util.js`-style entry functions like `command_ping(networkObjectId, args)` (some files deviate: `realnode.js`, `browser_Search.js`, `filesystem_utils.js`, `iface_util.js`). `unix.js` is the terminal key dispatcher: its `commandFunctions` map lists every recognized command.
- `src/processors/` — per-device-type packet processing dispatched by `packets_lib.js`: `packetProcessor_Host` (→ `packetProcessor_Router` if IPv4 forwarding is on; then INPUT chain firewall → `kernelProcessor` (ARP/ICMP/TCP) → `serviceProcessor`), `packetProcessor_Switch` (MAC learning/flooding), `routingProc.js` etc.
- `src/services/` — simulated daemons, one per real service: `icmp_service.js` (`ping()` returning numeric state codes 0=success 1=DNS fail 2=network addr 3=no reply 4=unconfigured), `tcp_service.js`, `dhclient/dhcpd/dhcrelay`, `named_service.js`, `apache2_service.js` (+ `http_service.js`), `iptablesd_service.js`, `systemd_service.js`/`systemctl`, plus general `arp_service.js`, `networkd_service.js`, `resolved_service.js`, `routing_service.js`.
- `src/packages/` — simulated `apt`-installable packages (`apache2_pkg.js`, `bind9_pkg.js`, `isc-dhcp-*_pkg.js`…). Utilities typically check `dpkg_packageIsInstalled` before running.
- `src/parsers/` — config-file parsers for simulated files (`/etc/network/interfaces` → `interfacesFileInterpreter`, dhcpd.conf, apache conf). Deviations from real Linux semantics are documented in file-top `/*** DIFFERENCES ... ***/` blocks and in JSDoc — keep doc and behavior in sync.
- `src/processors/` (see above) + `animations/` — canvas/sprite packet movement (`move-packet.js`, `firewall-block.js` fire animation).
- `styles/` — a single 3,600+ line `styles/0-main.css` (vars in `:root`, dark mode classes). `assets/` holds images/icons/packet sprites.
- `index.html` is in Spanish (`lang="es"`); UI copy and comments are typically English, terminal command help just uses English. README is English.

### Global Jaguars to be careful of (high-mutation globals)

In-flight request flags (`icmpFlag`, `arpFlag`, `traceFlag`, `tcpSyncFlag`, `dnsRequestFlag`, …) and payload buffers (`buffer`, `tcpBuffer`, `httpBuffer`, `dhcpOfferBuffer`, `traceBuffer`, `trace`, `traceReturn`) are keyed by composite strings like `sourceId|destId`. Always delete flags when a request completes/resolves — stale entries silently lock the sim.

## Code style & formatting

These conventions are observed consistently and expected in all edits:

- **JSDoc everywhere.** Every file starts with `/** @fileoverview ... */` and every exported/global function has a full JSDoc block: description in prose paragraphs (often numbered steps), `@param {type} name - description`, `@returns {Promise<T>|void|...}`, and frequently `@throws {}` (parsers) and `@example` blocks.
- **Indentation:** 4 spaces (`env.js` and newer files) — keep 4-space on files already using it; match the file you edit.
- **Naming:** global functions `camelCase` for libs (`getAvailableIps`, `isValidIp`) and `<command>_...` in utilities (`command_ping`); classes PascalCase (`componentToken`); per-hop packet processors `<name>Processor_<Device>` (`packetProcessor_Host`). Files are named either `snake_case_lib.js` / `<command>_util.js` or `kebab-case.js` — no consistent rule, **match the directory convention** (lib = `*_lib.js`, utilities = `*_util.js` / `snake_case.js`, services = `<daemon>_service.js`, packages = `<pkg>_pkg.js`, menus = `<camelCase>Menu.js` etc.).
- **Constants scoped by `$`** all-caps globals, e.g. `$ARPENTRYTTL`, `$MACENTRYTTL`, `$PWD` — plus leading-`$` DOM helpers `$()` (first match), `$$()` (all matches, with optional array conversion and context arg).
- **Variable naming:** prefixed nouns like `networkObjectId`, `$networkObject` for DOM nodes, camelCase throughout.
- **Comments:** lowercase explanatory one-liners appended with `//<--` or trailing `//reason`, and section breaks like `//evaluate the firewall INPUT chain`. Keep this conversational tone; occasional emoji/self-deprecating remarks are normal (e.g. "TODO: remove componentToken, it's a mess :P") but respect `// @codebuff delete markers` if present.
- **Strings:** double quotes mostly (`"eth0"`, `GET /... HTTP/1.1\r\n` style HTTP payloads are built as literal strings). Template literals for interpolation.
- **Async style:** plain `async`/`await` with per-step `await`; `setTimeout`/`setInterval` used for simulated timers (arp/MAC/DNS TTL expiry, DHCP leases) — remember these are raw handles stored in maps in `env.js`.

### The componentToken pattern

UI mounting uses `const x = new componentToken("selector")` then `x.render(...elements)` and `x.event(type, handler)` (see `src/app.js`). Components are functions returning `(Promise of) DOM elements` assembled via template strings + `innerHTML` or `document.createElement` assembles. SQL-free: never wonder about DBs; there are none.

## Tests

- Runner: **Vitest** in the `tests/` folder (separate workspace). `describe`/`suite`/`it` in `.spec.js` files (e.g. `tests/network_lib.spec.js`, `tests/switch.spec.js`).
- Harness: `tests/setup-globals.js` exports `createWindowWithScripts(...paths)` — it **reads the named source files and runs them in a `linkedom` DOM (via node `vm` context)** and returns `window` whose globals you extract. Tests therefore exercise the real impl functions with a fake DOM, no mocking beyond that.
- Fixtures: `tests/mockup.js` exports edge cases (`ips.valid`/`ips.invalid`, `macs.valid`/`macs.invalid` — add new cases here, tests iterate them).
- Known-when-writing-tests: some functions with DOM side-effects can't run under the bare harness yet (see the `it.skip` in `switch.spec.js` for `SwitchObject` — a pre-existing tracked bug), so a skip with a reason in a comment is acceptable; prefer fixing the test harness, though, over weakening assertions.
- Root ESLint ignores `tests/**`; the tests folder has its own `eslint.config.js` with a different `sourceType: module`. Keep the two configs functionally equivalent to their current intent.

## Gotchas for agents

- There is **no TypeScript**; JSDoc comments (`jsconfig.json` has `checkJs: false`) are documentation only, don't trust any type imports.
- Adding UI elements means updating matching CSS in `styles/0-main.css` (single-file stylesheet; section headers as `/*NAME */` banner comments).
- Devices find their neighbors via cables' DOM attributes & endpoints; you'll often see `getAvailableIps(networkObjectId)` / `getInterfaces(networkObjectId)` used to inspect a node — prefer reusing those helpers over re-deriving state manually.
- Sim protocol semantics (e.g. the custom `interfaces` file format above) intentionally diverge from real Linux; changing behavior should be accompanied by updating the corresponding header comment block in that file, README claims, and any `@description` wording.
