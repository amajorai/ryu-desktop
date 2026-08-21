<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="./icon-dark.png" />
    <img src="./icon-light.png" alt="Virtual Desktop" width="144" />
  </picture>
</p>

<div align="center">

# Virtual Desktop

</div>

An interactive virtual desktop for any Ryu node: the sidecar brings up a full headless Linux desktop (Xvfb + window manager + apps) with a VNC server on loopback, exposes it through the generic WebSocket ext-proxy, and the workspace panel streams it live with mouse/keyboard input. Ghost can drive the same display.

> **The public home of `ryu-desktop`.** Source, builds, and releases live here —
> binaries for every platform are attached to each release.
>
> This tree is generated from the Ryu monorepo, so commits pushed here
> directly are replaced on the next sync. **Pull requests are welcome** —
> open them here and they are ported into the monorepo, then flow back out.
> Ryu as a whole: https://github.com/amajorai/ryu

## Install

**App:** [Install](ryu://apps/@ryu/desktop) (opens the Ryu desktop app and asks you to confirm)

**CLI:**

```bash
ryu apps add @ryu/desktop
```

## Source & build

The **source of record** for this app: a dependency-free Bun/TypeScript
`sidecar/` Ryu runs locally as a grant-gated control capability, plus the
manifest `ui/`. The sidecar builds standalone — `cd sidecar && bun install &&
bun run build` compiles a single `ryu-desktop` executable; each release attaches
the per-platform binaries.

## License

Apache-2.0 — see [LICENSE](./LICENSE).

## Read this before you install

- **The virtual desktop is a whole computer, not a browser tab.** It runs on the
  node — a Hetzner cloud node, a self-hosted box, or your own Linux machine. On a
  cloud/self-hosted node only Core's port is exposed, so the stream rides Core's
  WebSocket ext-proxy; nothing new is opened on the firewall.
- **Interactive, not just a view.** The panel connects an RFB client (noVNC) to the
  sidecar's `/ws` websockify bridge; pixels come down and mouse/keyboard go up on the
  same socket. Requires the `desktop.control` permission level.
- **Linux nodes first.** The sidecar needs `xvfb`, a window manager (`openbox`), and
  a VNC server (`tigervnc` — `Xvnc` doubles as the X server + RFB server). On
  macOS/Windows the sidecar reports `available:false` and the panel degrades.
  Provisioning for Hetzner/managed nodes is in `infra/install.sh`.

## How it works

1. Core spawns `ryu-desktop` as a `local` manifest sidecar on port `8015` (loopback).
2. The sidecar brings up `Xvnc :99` (or Xvfb + x11vnc) + `openbox` + starter apps,
   bound to `127.0.0.1:5900`.
3. The desktop panel opens `wss://<node>/api/ext/ws/@ryu/desktop/ws` — Core's generic
   WebSocket tunnel authenticates the node token and bridges to the sidecar.
4. The sidecar's `/ws` pumps RFB-over-WebSocket ↔ the loopback VNC port.
5. Ghost, spawned with `DISPLAY=:99`, captures and drives the same desktop.

## Control API (loopback, bearer-gated)

Bound to `127.0.0.1:8015` (`RYU_DESKTOP_PORT` overrides; `+1000` under
`RYU_PROFILE=dev`). Every route except `GET /health` requires
`Authorization: Bearer <RYU_EXT_TOKEN | RYU_DESKTOP_TOKEN>` (fail-closed).

| Method | Path | Purpose |
|---|---|---|
| GET | `/health` | Liveness (unauthenticated). |
| GET | `/` | Capability root (`desktop.view`). |
| GET | `/capabilities` | `{ available, reason?, display, vncPort, resolution }`. |
| GET | `/screen` | Single PNG screenshot (fallback for non-WS surfaces). |
| WS   | `/ws` | Websockify bridge to the loopback VNC server (the interactive stream). |
| POST | `/input` | `{ type: click\|type\|key, ... }` JSON input fallback (xdotool). |

## Build

```sh
bun install
bun run build     # → dist/ryu-desktop (bun build --compile)
bun test          # control-router/auth unit tests (fake controller)
```

## Files

- `src/main/index.ts` — entrypoint (resolve port/token, start desktop, WS bridge).
- `src/main/control.ts` — pure request router + fail-closed bearer + HTTP server.
- `src/main/desktop.ts` — the `DesktopController` seam (Linux Xvfb/Xvnc lifecycle,
  screenshot, input; unavailable on other platforms).
- `src/main/control.test.ts` — routing/auth tests against a fake controller.
