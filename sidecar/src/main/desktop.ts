// Virtual-desktop controller for the Ryu Virtual Desktop sidecar.
//
// Owns the lifecycle of the node's headless graphical session: an Xvfb display, a
// lightweight window manager (so there is a real desktop to look at and click),
// a VNC server bound to LOOPBACK (TigerVNC `Xvnc` is both the X server AND the RFB
// server in one process), and a few starter apps. The `/ws` bridge in `index.ts`
// connects the panel's RFB-over-WebSocket to that loopback VNC port.
//
// The display is the SAME one Ghost drives: Core passes `DISPLAY=:<n>` through the MCP
// env allowlist (`apps/core/src/sidecar/env_scrub.rs`), so the agent's computer-use
// tools and the human's stream panel watch and control one screen. No copy, no
// indirection — the node genuinely has a desktop.
//
// Platform posture: Linux-first (Xvfb + TigerVNC + openbox). On macOS/Windows the
// controller reports `available:false` with a clear reason, and the panel degrades
// gracefully. A future revision can add a Wayland/shell backend.

import { spawn, type ChildProcess } from "node:child_process";
import { existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

export interface DesktopCapabilities {
	available: boolean;
	reason?: string;
	/** The X display number (`:99` style), when a session is running. */
	display?: string;
	/** Loopback RFB port the VNC server is bound to. */
	vncPort?: number;
	resolution?: string;
}

export interface InputRequest {
	type?: string;
	x?: number;
	y?: number;
	text?: string;
	key?: string;
	buttons?: number;
}

export interface InputResult {
	ok: boolean;
	error?: string;
}

interface DesktopOptions {
	/** The X display number to bring up (`99` ⇒ `:99`). */
	display?: number;
	/** Virtual screen resolution (`WxH`). */
	resolution?: string;
	/** Loopback RFB port for the VNC server. */
	vncPort?: number;
	/** Path to the TigerVNC `Xvnc` binary (auto-detected when unset). */
	xvncBin?: string;
	/** Window-manager command (auto-detected when unset). */
	windowManager?: string[];
	/** Extra apps to launch on the desktop (e.g. a terminal, a browser). */
	starterApps?: string[][];
	/** Whether the VNC server allows any RFB security type (loopback-only). */
	noAuth?: boolean;
}

const DEFAULT_DISPLAY = 99;
const DEFAULT_RESOLUTION = "1600x1000x24";
const DEFAULT_VNC_PORT = 5900;

function findOnPath(names: string[]): string | null {
	for (const name of names) {
		for (const dir of (process.env.PATH ?? "").split(":")) {
			const candidate = join(dir, name);
			if (existsSync(candidate)) {
				return candidate;
			}
		}
	}
	return null;
}

/**
 * Linux desktop controller. Spawns Xvfb → openbox → starter apps → VNC (TigerVNC
 * `Xvnc` doubles as the X server + RFB server, so when it is present we use it
 * INSTEAD of the separate Xvfb+VNC pair). Idempotent: `start()` returns fast when the
 * display is already up, so Core's lazy sidecar wake and the panel's first WS connect
 * agree on one session.
 */
export class LinuxDesktopController implements DesktopController {
	private readonly opts: Required<DesktopOptions>;
	private children: ChildProcess[] = [];
	private ready = false;
	private lastError: string | null = null;

	constructor(opts: DesktopOptions = {}) {
		this.opts = {
			display: opts.display ?? DEFAULT_DISPLAY,
			resolution: opts.resolution ?? DEFAULT_RESOLUTION,
			vncPort: opts.vncPort ?? DEFAULT_VNC_PORT,
			xvncBin: opts.xvncBin ?? findOnPath(["Xvnc", "xvnc"]) ?? "",
			windowManager: opts.windowManager ?? ["openbox"],
			starterApps: opts.starterApps ?? [],
			noAuth: opts.noAuth ?? true,
		};
	}

	displayNumber(): number {
		return this.opts.display;
	}

	vncPort(): number {
		return this.opts.vncPort;
	}

	/** The X display string Ghost should use (e.g. `:99`). */
	displayString(): string {
		return `:${this.opts.display}`;
	}

	async start(): Promise<{ ok: boolean; error?: string }> {
		if (this.ready) {
			return { ok: true };
		}
		try {
			this.teardown();
			if (this.opts.xvncBin) {
				// TigerVNC `Xvnc` = X server + RFB server in one. Loopback-only,
				// RFB SecurityTypes None is safe because the ONLY path to the port is
				// Core's authenticated WS tunnel (the firewall exposes no direct port).
				this.spawn(this.opts.xvncBin, [
					`-geometry`,
					this.opts.resolution,
					`:${this.opts.display}`,
					"-localhost",
					"-rfbport",
					String(this.opts.vncPort),
					"-SecurityTypes",
					this.opts.noAuth ? "None" : "VncAuth",
					"-ac",
					"-nolisten",
					"tcp",
				]);
			} else {
				// Fallback: separate Xvfb + x11vnc.
				const xvfb = findOnPath(["Xvfb"]) ?? "Xvfb";
				this.spawn(xvfb, [
					`:${this.opts.display}`,
					"-screen",
					"0",
					this.opts.resolution,
					"-ac",
					"-nolisten",
					"tcp",
				]);
				const x11vnc = findOnPath(["x11vnc"]) ?? "x11vnc";
				this.spawn(x11vnc, [
					"-display",
					this.displayString(),
					"-rfbport",
					String(this.opts.vncPort),
					"-localhost",
					"-nopw",
					"-forever",
					"-shared",
					"-quiet",
				]);
			}

			// Window manager on the new display (a bare X root is not a desktop).
			const wm = this.opts.windowManager;
			if (wm.length > 0) {
				this.spawn(wm[0], wm.slice(1), this.displayString());
			}
			for (const app of this.opts.starterApps) {
				this.spawn(app[0], app.slice(1), this.displayString());
			}

			this.ready = true;
			this.lastError = null;
			return { ok: true };
		} catch (error) {
			this.ready = false;
			this.lastError = error instanceof Error ? error.message : String(error);
			return { ok: false, error: this.lastError };
		}
	}

	private spawn(cmd: string, args: string[], display?: string): ChildProcess {
		const child = spawn(cmd, args, {
			env: {
				...process.env,
				DISPLAY: display ?? this.displayString(),
				HOME: process.env.HOME ?? tmpdir(),
			},
			stdio: ["ignore", "pipe", "pipe"],
		});
		child.stderr?.on("data", (d) => {
			// `-quiet` keeps the happy path silent; surface only the fatal lines.
			const line = String(d).trim();
			if (line && /error|fail|unable|cannot/i.test(line)) {
				this.lastError = line;
			}
		});
		child.on("exit", () => {
			// A crashed server should not leave a stale "ready" session.
			this.ready = false;
		});
		this.children.push(child);
		return child;
	}

	teardown(): void {
		for (const child of this.children) {
			try {
				child.kill("SIGTERM");
			} catch {
				// already gone
			}
		}
		this.children = [];
		this.ready = false;
	}

	capabilities(): DesktopCapabilities {
		return {
			available: this.ready,
			reason: this.ready ? undefined : this.lastError ?? "not started",
			display: this.ready ? this.displayString() : undefined,
			vncPort: this.ready ? this.opts.vncPort : undefined,
			resolution: this.ready ? this.opts.resolution : undefined,
		};
	}

	unavailableReason(): string {
		return this.lastError ?? "no virtual display running";
	}

	async screenshot(): Promise<string | null> {
		if (!this.ready) {
			return null;
		}
		return new Promise((resolve) => {
			const scrot = findOnPath(["scrot", "import"]);
			if (!scrot) {
				resolve(null);
				return;
			}
			const out = join(tmpdir(), `ryu-desktop-${this.opts.display}.png`);
			const args =
				scrot.endsWith("scrot")
					? ["-z", out]
					: ["-window", "root", out];
			const child = spawn(scrot, args, {
				env: { ...process.env, DISPLAY: this.displayString() },
			});
			const timer = setTimeout(() => child.kill("SIGKILL"), 10_000);
			child.on("close", (code) => {
				clearTimeout(timer);
				resolve(code === 0 && existsSync(out) ? out : null);
			});
		});
	}

	async input(req: InputRequest): Promise<InputResult> {
		if (!this.ready) {
			return { ok: false, error: this.unavailableReason() };
		}
		// Fallback input path for surfaces without a noVNC client. The primary
		// interactive path is the RFB-over-WebSocket bridge (`/ws`), which carries
		// mouse/keyboard natively; this JSON route is the thin, explicit fallback.
		const xdotool = findOnPath(["xdotool"]);
		if (!xdotool) {
			return { ok: false, error: "xdotool not installed" };
		}
		try {
			const env = { ...process.env, DISPLAY: this.displayString() };
			if (req.type === "click" && req.x !== undefined && req.y !== undefined) {
				await run(xdotool, ["mousemove", String(req.x), String(req.y), "click", "1"], env);
			} else if (req.type === "type" && req.text) {
				await run(xdotool, ["type", "--delay", "12", req.text], env);
			} else if (req.type === "key" && req.key) {
				await run(xdotool, ["key", req.key], env);
			} else {
				return { ok: false, error: "unsupported input request" };
			}
			return { ok: true };
		} catch (error) {
			return { ok: false, error: error instanceof Error ? error.message : String(error) };
		}
	}
}

function run(cmd: string, args: string[], env: NodeJS.ProcessEnv): Promise<void> {
	return new Promise((resolve, reject) => {
		const child = spawn(cmd, args, { env, stdio: "ignore" });
		child.on("error", reject);
		child.on("close", (code) =>
			code === 0 ? resolve() : reject(new Error(`${cmd} exited ${code}`))
		);
	});
}

/** The platform-selected controller (Linux when supported, else unavailable). */
export type DesktopController = {
	start(): Promise<{ ok: boolean; error?: string }>;
	teardown(): void;
	capabilities(): DesktopCapabilities;
	unavailableReason(): string;
	screenshot(): Promise<string | null>;
	input(req: InputRequest): Promise<InputResult>;
};

export function createDesktopController(opts?: DesktopOptions): DesktopController {
	if (process.platform === "linux") {
		return new LinuxDesktopController(opts);
	}
	return new UnavailableDesktopController(
		`virtual desktop requires a Linux node (this is ${process.platform})`
	);
}

/** Non-Linux / missing-tooling fallback: everything answers `available:false`. */
export class UnavailableDesktopController implements DesktopController {
	constructor(private readonly reason: string) {}

	async start(): Promise<{ ok: boolean; error?: string }> {
		return { ok: false, error: this.reason };
	}

	teardown(): void {}

	capabilities(): DesktopCapabilities {
		return { available: false, reason: this.reason };
	}

	unavailableReason(): string {
		return this.reason;
	}

	async screenshot(): Promise<string | null> {
		return null;
	}

	async input(_req: InputRequest): Promise<InputResult> {
		return { ok: false, error: this.reason };
	}
}
