// Virtual-desktop controller for the Ryu Virtual Desktop sidecar.
//
// Owns the lifecycle of the node's headless graphical session: an Xvfb display, a
// lightweight window manager (so there is a real desktop to look at and click),
// a VNC server bound to LOOPBACK (TigerVNC `Xvnc` is both the X server AND the RFB
// server in one process), and a few starter apps. The `/ws` bridge in `index.ts`
// connects the panel's RFB-over-WebSocket to that loopback VNC port.
//
// Core assigns one display per managed Bot and passes that display through the MCP
// env allowlist. The agent's computer-use tools and the human's stream panel then
// watch and control one Bot screen. Files and installed applications remain shared
// by the node; display routing is not an OS or tenant security boundary.
//
// Platform posture: Linux-first (Xvfb + TigerVNC + openbox). On macOS/Windows the
// controller reports `available:false` with a clear reason, and the panel degrades
// gracefully. A future revision can add a Wayland/shell backend.

import { type ChildProcess, spawn } from "node:child_process";
import {
	existsSync,
	mkdirSync,
	readFileSync,
	renameSync,
	writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

export interface DesktopCapabilities {
	available: boolean;
	/** The X display number (`:99` style), when a session is running. */
	display?: string;
	reason?: string;
	resolution?: string;
	/** Loopback RFB port the VNC server is bound to. */
	vncPort?: number;
}

export interface InputRequest {
	buttons?: number;
	key?: string;
	text?: string;
	type?: string;
	x?: number;
	y?: number;
}

export interface InputResult {
	error?: string;
	ok: boolean;
}

export interface DesktopSessionAllocation {
	agentId: string;
	display: number;
	vncPort: number;
}

export interface DesktopOptions {
	/** The X display number to bring up (`99` ⇒ `:99`). */
	display?: number;
	/** Whether the VNC server allows any RFB security type (loopback-only). */
	noAuth?: boolean;
	/** Virtual screen resolution (`WxH`). */
	resolution?: string;
	/** Extra apps to launch on the desktop (e.g. a terminal, a browser). */
	starterApps?: string[][];
	/** Loopback RFB port for the VNC server. */
	vncPort?: number;
	/** Window-manager command (auto-detected when unset). */
	windowManager?: string[];
	/** Path to the TigerVNC `Xvnc` binary (auto-detected when unset). */
	xvncBin?: string;
}

const DEFAULT_DISPLAY = 99;
const DEFAULT_RESOLUTION = "1600x1000x24";
const DEFAULT_VNC_PORT = 5900;
const DEFAULT_AGENT_ID = "ryu";
const SESSION_FILE_NAME = "computer-sessions.json";
const MAX_SESSIONS = 64;

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
				await this.spawn(this.opts.xvncBin, [
					"-geometry",
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
				await this.spawn(xvfb, [
					`:${this.opts.display}`,
					"-screen",
					"0",
					this.opts.resolution,
					"-ac",
					"-nolisten",
					"tcp",
				]);
				const x11vnc = findOnPath(["x11vnc"]) ?? "x11vnc";
				await this.spawn(x11vnc, [
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
				await this.spawn(wm[0], wm.slice(1), this.displayString());
			}
			for (const app of this.opts.starterApps) {
				await this.spawn(app[0], app.slice(1), this.displayString());
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

	private async spawn(
		cmd: string,
		args: string[],
		display?: string
	): Promise<ChildProcess> {
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
		child.on("error", (error) => {
			this.lastError = error.message;
			this.ready = false;
		});
		child.on("exit", () => {
			// A crashed server should not leave a stale "ready" session.
			this.ready = false;
		});
		this.children.push(child);
		await new Promise<void>((resolve, reject) => {
			child.once("spawn", resolve);
			child.once("error", reject);
		});
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
			reason: this.ready ? undefined : (this.lastError ?? "not started"),
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
			const args = scrot.endsWith("scrot")
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
				await run(
					xdotool,
					["mousemove", String(req.x), String(req.y), "click", "1"],
					env
				);
			} else if (req.type === "type" && req.text) {
				await run(xdotool, ["type", "--delay", "12", req.text], env);
			} else if (req.type === "key" && req.key) {
				await run(xdotool, ["key", req.key], env);
			} else {
				return { ok: false, error: "unsupported input request" };
			}
			return { ok: true };
		} catch (error) {
			return {
				ok: false,
				error: error instanceof Error ? error.message : String(error),
			};
		}
	}
}

function run(
	cmd: string,
	args: string[],
	env: NodeJS.ProcessEnv
): Promise<void> {
	return new Promise((resolve, reject) => {
		const child = spawn(cmd, args, { env, stdio: "ignore" });
		child.on("error", reject);
		child.on("close", (code) =>
			code === 0 ? resolve() : reject(new Error(`${cmd} exited ${code}`))
		);
	});
}

/** The platform-selected controller (Linux when supported, else unavailable). */
export interface DesktopController {
	capabilities(): DesktopCapabilities;
	input(req: InputRequest): Promise<InputResult>;
	screenshot(): Promise<string | null>;
	start(): Promise<{ ok: boolean; error?: string }>;
	teardown(): void;
	unavailableReason(): string;
}

export function createDesktopController(
	opts?: DesktopOptions
): DesktopController {
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

export type DesktopControllerFactory = (
	opts: DesktopOptions
) => DesktopController;

interface PersistedSessionFile {
	sessions?: unknown;
	version?: unknown;
}

/**
 * Owns the agent → display map and lazily starts one controller for each session.
 * It never accepts a display or VNC port from the request URL; `agent_id` is only
 * an opaque lookup key. Allocation stays inside this satellite and is persisted
 * atomically under `RYU_DIR` so Core needs no app-specific route or session logic.
 */
export class DesktopSessionManager {
	private readonly controllers = new Map<string, DesktopController>();
	private readonly pending = new Map<string, Promise<DesktopController>>();
	private allocations = new Map<string, DesktopSessionAllocation>();
	private hasAuthoritativeFile = false;
	private mapError: string | null = null;

	constructor(
		private readonly env: NodeJS.ProcessEnv = process.env,
		private readonly factory: DesktopControllerFactory = createDesktopController
	) {}

	/** Resolve and start the session for `agentId`, preserving legacy `ryu`. */
	async controllerFor(agentId?: string | null): Promise<DesktopController> {
		this.reloadAllocations();
		const key = normalizeAgentId(agentId);
		if (agentId != null && !key) {
			return new UnavailableDesktopController(
				"invalid computer session agent id"
			);
		}
		const resolvedKey = key ?? DEFAULT_AGENT_ID;
		const allocation =
			this.allocationFor(resolvedKey) ?? this.allocateFor(resolvedKey);
		if (!allocation) {
			return new UnavailableDesktopController(
				this.mapError ??
					`computer session '${resolvedKey}' could not be allocated`
			);
		}

		const current = this.controllers.get(resolvedKey);
		if (current) {
			return current;
		}
		const inFlight = this.pending.get(resolvedKey);
		if (inFlight) {
			return inFlight;
		}

		const promise = this.startAllocation(resolvedKey, allocation);
		this.pending.set(resolvedKey, promise);
		try {
			return await promise;
		} finally {
			this.pending.delete(resolvedKey);
		}
	}

	private async startAllocation(
		agentId: string,
		allocation: DesktopSessionAllocation
	): Promise<DesktopController> {
		const controller = this.factory({
			display: allocation.display,
			vncPort: allocation.vncPort,
		});
		const result = await controller.start();
		if (!result.ok) {
			return controller;
		}
		this.controllers.set(agentId, controller);
		return controller;
	}

	private allocationFor(agentId: string): DesktopSessionAllocation | null {
		const allocated = this.allocations.get(agentId);
		if (allocated) {
			return allocated;
		}
		// Older nodes have no map until the first Core allocation. Preserve the
		// original single-screen `ryu` contract at :99/5900 only.
		if (!this.hasAuthoritativeFile && agentId === DEFAULT_AGENT_ID) {
			return {
				agentId,
				display: DEFAULT_DISPLAY,
				vncPort: DEFAULT_VNC_PORT,
			};
		}
		return null;
	}

	private allocateFor(agentId: string): DesktopSessionAllocation | null {
		if (this.mapError) {
			return null;
		}
		// Keep the legacy default lane stable even when another Bot is selected
		// before Ryu itself has opened the panel.
		if (this.allocations.size === 0 && agentId !== DEFAULT_AGENT_ID) {
			this.allocations.set(DEFAULT_AGENT_ID, {
				agentId: DEFAULT_AGENT_ID,
				display: DEFAULT_DISPLAY,
				vncPort: DEFAULT_VNC_PORT,
			});
		}
		if (this.allocations.size >= MAX_SESSIONS) {
			this.mapError = `the node has reached its ${MAX_SESSIONS} virtual desktop limit`;
			return null;
		}
		const used = new Set(
			[...this.allocations.values()].map((entry) => entry.display)
		);
		let display = DEFAULT_DISPLAY;
		while (used.has(display) && display < DEFAULT_DISPLAY + MAX_SESSIONS) {
			display += 1;
		}
		if (display >= DEFAULT_DISPLAY + MAX_SESSIONS) {
			this.mapError = `the node has reached its ${MAX_SESSIONS} virtual desktop limit`;
			return null;
		}
		const allocation = {
			agentId,
			display,
			vncPort: DEFAULT_VNC_PORT + display - DEFAULT_DISPLAY,
		};
		this.allocations.set(agentId, allocation);
		try {
			this.persistAllocations();
		} catch (error) {
			this.allocations.delete(agentId);
			this.mapError = error instanceof Error ? error.message : String(error);
			return null;
		}
		return allocation;
	}

	private persistAllocations(): void {
		const filePath = this.sessionFilePath();
		if (!filePath) {
			return;
		}
		const sessions = Object.fromEntries(
			[...this.allocations.entries()].map(([agentId, allocation]) => [
				agentId,
				{
					agent_id: agentId,
					display: allocation.display,
					vnc_port: allocation.vncPort,
				},
			])
		);
		mkdirSync(this.env.RYU_DIR?.trim() ?? "", { recursive: true });
		const temporaryPath = `${filePath}.${process.pid}.tmp`;
		writeFileSync(
			temporaryPath,
			`${JSON.stringify({ sessions, version: 1 }, null, 2)}\n`,
			{ mode: 0o600 }
		);
		renameSync(temporaryPath, filePath);
		this.hasAuthoritativeFile = true;
	}

	private reloadAllocations(): void {
		const filePath = this.sessionFilePath();
		if (!(filePath && existsSync(filePath))) {
			this.allocations = new Map();
			this.hasAuthoritativeFile = false;
			this.mapError = null;
			return;
		}
		this.hasAuthoritativeFile = true;
		try {
			const parsed = JSON.parse(
				readFileSync(filePath, "utf8")
			) as PersistedSessionFile;
			if (
				parsed.version !== 1 ||
				typeof parsed.sessions !== "object" ||
				parsed.sessions === null ||
				Object.keys(parsed.sessions).length > MAX_SESSIONS
			) {
				throw new Error("unsupported computer session map");
			}
			const next = new Map<string, DesktopSessionAllocation>();
			const displays = new Set<number>();
			for (const [key, value] of Object.entries(parsed.sessions)) {
				const normalized = normalizeAgentId(key);
				if (
					!normalized ||
					normalized !== key ||
					typeof value !== "object" ||
					value === null
				) {
					throw new Error("invalid computer session entry");
				}
				const record = value as Record<string, unknown>;
				const display = Number(record.display);
				const vncPort = Number(record.vnc_port);
				if (
					record.agent_id !== key ||
					!Number.isInteger(display) ||
					!Number.isInteger(vncPort) ||
					display < DEFAULT_DISPLAY ||
					display >= DEFAULT_DISPLAY + MAX_SESSIONS ||
					vncPort !== DEFAULT_VNC_PORT + display - DEFAULT_DISPLAY
				) {
					throw new Error("invalid computer display allocation");
				}
				if (displays.has(display)) {
					throw new Error("duplicate computer display allocation");
				}
				displays.add(display);
				next.set(key, { agentId: key, display, vncPort });
			}
			this.allocations = next;
			this.mapError = null;
		} catch (error) {
			this.allocations = new Map();
			this.mapError = error instanceof Error ? error.message : String(error);
		}
	}

	private sessionFilePath(): string | null {
		const dir = this.env.RYU_DIR?.trim();
		return dir ? join(dir, SESSION_FILE_NAME) : null;
	}
}

function normalizeAgentId(value: string | null | undefined): string | null {
	const trimmed = value?.trim() ?? "";
	if (
		trimmed.length === 0 ||
		trimmed.length > 128 ||
		[...trimmed].some((char) => /\p{Cc}/u.test(char))
	) {
		return null;
	}
	return trimmed;
}
