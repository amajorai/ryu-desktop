// Virtual-desktop controller for the Ryu Virtual Desktop sidecar.
//
// Owns the lifecycle of the node's headless graphical session: a TigerVNC Xvnc display, a
// lightweight window manager (so there is a real desktop to look at and click),
// a VNC server on a private service-user Unix socket (TigerVNC `Xvnc` is both
// the X server AND the RFB server), and starter apps. The authenticated `/ws`
// bridge connects the panel's RFB-over-WebSocket to that socket.
//
// Core assigns one display per managed Bot and passes that display through the MCP
// env allowlist. The agent's computer-use tools and the human's stream panel then
// watch and control one Bot screen. Files and installed applications remain shared
// by the node; display routing is not an OS or tenant security boundary.
//
// Platform posture: Linux-first (TigerVNC Xvnc + xauth + openbox). On macOS/Windows the
// controller reports `available:false` with a clear reason, and the panel degrades
// gracefully. A future revision can add a Wayland/shell backend.

import { type ChildProcess, spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import {
	chmodSync,
	existsSync,
	lstatSync,
	mkdirSync,
	mkdtempSync,
	readFileSync,
	renameSync,
	rmSync,
	unlinkSync,
	writeFileSync,
} from "node:fs";
import { createConnection } from "node:net";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { resolvePluginDataDir } from "@ryu/sidecar-runtime";
import { z } from "zod";

export interface DesktopCapabilities {
	available: boolean;
	/** The X display number (`:99` style), when a session is running. */
	display?: string;
	reason?: string;
	resolution?: string;
	/** Loopback RFB port the VNC server is bound to. */
	vncPort?: number;
	/** Private service-user socket; no TCP RFB listener is exposed. */
	vncSocket?: string;
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
	/** Deprecated: RFB is always isolated by a private Unix socket. */
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
 * Older versions wrote the last screenshot of the agent's desktop to
 * `<tmp>/ryu-desktop-<display>.png` (often world-readable) and never removed
 * it. Delete that file when it is a regular file this account owns; a symlink
 * or another user's file is left alone.
 */
export function removeLegacyScreenshot(
	display: number,
	directory: string = tmpdir()
): void {
	const path = join(directory, `ryu-desktop-${display}.png`);
	try {
		const entry = lstatSync(path);
		const uid = process.getuid?.();
		if (!entry.isFile() || (uid !== undefined && entry.uid !== uid)) {
			return;
		}
		unlinkSync(path);
	} catch {
		// Absent, or not removable by this account.
	}
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
	private vncSocket: string | null = null;
	private authorityFile: string | null = null;
	private privateDir: string | null = null;
	private lifecycle: Promise<void> = Promise.resolve();
	private readonly closures = new Map<ChildProcess, Promise<void>>();
	private readonly criticalChildren = new Set<ChildProcess>();

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
		removeLegacyScreenshot(this.opts.display);
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

	start(): Promise<{ ok: boolean; error?: string }> {
		const operation = this.lifecycle.then(() => this.startSession());
		this.lifecycle = operation.then(
			() => undefined,
			() => undefined
		);
		return operation;
	}

	private async startSession(): Promise<{ ok: boolean; error?: string }> {
		if (this.ready) {
			return { ok: true };
		}
		try {
			await this.stopSession();
			if (!this.opts.xvncBin) {
				throw new Error(
					"TigerVNC Xvnc is required for a private virtual desktop"
				);
			}
			if (this.opts.xvncBin && !existsSync(this.opts.xvncBin)) {
				throw new Error(`ENOENT: display server ${this.opts.xvncBin}`);
			}
			const privateDir = mkdtempSync(join(tmpdir(), "ryu-desktop-"));
			this.privateDir = privateDir;
			chmodSync(privateDir, 0o700);
			this.vncSocket = join(privateDir, "rfb.sock");
			this.authorityFile = join(privateDir, "Xauthority");
			await this.prepareAuthority();
			if (this.opts.xvncBin) {
				// TCP RFB is disabled. The OS restricts this socket to the service
				// account; SSH-forwarding a loopback port cannot bypass the WS gate.
				const server = await this.spawn(
					this.opts.xvncBin,
					[
						"-geometry",
						this.opts.resolution,
						`:${this.opts.display}`,
						"-localhost",
						"-rfbport",
						"-1",
						"-rfbunixpath",
						this.vncSocket,
						"-rfbunixmode",
						"0600",
						"-SecurityTypes",
						"None",
						"-auth",
						this.authorityFile,
						"-nolisten",
						"tcp",
					],
					undefined,
					true
				);
				await this.waitForServer(server);
			}

			// Window manager on the new display (a bare X root is not a desktop).
			const wm = this.opts.windowManager;
			if (wm.length > 0) {
				await this.spawn(wm[0], wm.slice(1), this.displayString(), true);
			}
			for (const app of this.opts.starterApps) {
				await this.spawn(app[0], app.slice(1), this.displayString());
			}

			if (!this.criticalChildrenAlive()) {
				throw new Error(
					"Virtual desktop required process exited during startup"
				);
			}
			this.ready = true;
			this.lastError = null;
			return { ok: true };
		} catch (error) {
			await this.stopSession();
			this.ready = false;
			this.lastError = error instanceof Error ? error.message : String(error);
			return { ok: false, error: this.lastError };
		}
	}

	private async waitForServer(server: ChildProcess): Promise<void> {
		const socketPath = this.vncSocket;
		if (!socketPath) {
			throw new Error("Missing private RFB socket");
		}
		const deadline = Date.now() + 5000;
		while (Date.now() < deadline) {
			if (server.exitCode !== null || server.signalCode !== null) {
				throw new Error(
					"Virtual desktop display server exited before becoming ready"
				);
			}
			const connected = await new Promise<boolean>((resolve) => {
				const connection = createConnection(socketPath);
				const finish = (value: boolean) => {
					connection.destroy();
					resolve(value);
				};
				connection.once("connect", () => finish(true));
				connection.once("error", () => finish(false));
				connection.setTimeout(100, () => finish(false));
			});
			if (connected && server.exitCode === null && server.signalCode === null) {
				return;
			}
			await new Promise((resolve) => setTimeout(resolve, 25));
		}
		throw new Error("Virtual desktop private RFB socket did not become ready");
	}

	private async prepareAuthority(): Promise<void> {
		const authorityFile = this.authorityFile;
		if (!authorityFile) {
			throw new Error("Missing X authority file");
		}
		if (!existsSync(authorityFile)) {
			writeFileSync(authorityFile, "", { mode: 0o600, flag: "wx" });
		}
		chmodSync(authorityFile, 0o600);
		// xauth reads its command from a private file rather than a buffered pipe.
		// Only the path reaches argv; the cookie stays inside the mode-0700 directory.
		const privateDir = this.privateDir;
		if (!privateDir) {
			throw new Error("Missing private X authority directory");
		}
		const commandFile = join(privateDir, "xauth-input");
		writeFileSync(
			commandFile,
			`add :${this.opts.display} MIT-MAGIC-COOKIE-1 ${randomBytes(16).toString("hex")}\n`,
			{ mode: 0o600, flag: "wx" }
		);
		try {
			const child = spawn(
				findOnPath(["xauth"]) ?? "xauth",
				["-f", authorityFile, "-q", "source", commandFile],
				{ stdio: ["ignore", "ignore", "pipe"] }
			);
			this.trackChild(child);
			const timer = setTimeout(() => child.kill("SIGKILL"), 10_000);
			try {
				await new Promise<void>((resolve, reject) => {
					child.once("error", reject);
					child.once("close", (code) =>
						code === 0
							? resolve()
							: reject(
									new Error("Could not configure X display authentication")
								)
					);
				});
			} finally {
				clearTimeout(timer);
			}
		} finally {
			unlinkSync(commandFile);
		}
	}

	protected async spawn(
		cmd: string,
		args: string[],
		display?: string,
		critical = false
	): Promise<ChildProcess> {
		const child = spawn(cmd, args, {
			env: {
				...process.env,
				DISPLAY: display ?? this.displayString(),
				XAUTHORITY: this.authorityFile ?? undefined,
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
		if (critical) {
			this.criticalChildren.add(child);
			child.on("error", (error) => {
				this.lastError = error.message;
				this.ready = false;
			});
			child.on("exit", () => {
				this.lastError = "Virtual desktop required process exited";
				this.ready = false;
			});
		}
		this.trackChild(child);
		await new Promise<void>((resolve, reject) => {
			child.once("spawn", resolve);
			child.once("error", reject);
		});
		return child;
	}

	private criticalChildrenAlive(): boolean {
		return [...this.criticalChildren].every(
			(child) => child.exitCode === null && child.signalCode === null
		);
	}

	private trackChild(child: ChildProcess): void {
		this.children.push(child);
		this.closures.set(
			child,
			new Promise((resolve) => {
				child.once("close", () => resolve());
			})
		);
	}

	teardown(): Promise<void> {
		const operation = this.lifecycle.then(() => this.stopSession());
		this.lifecycle = operation.catch(() => undefined);
		return operation;
	}

	private async stopSession(): Promise<void> {
		this.ready = false;
		await Promise.all(
			this.children.map(async (child) => {
				const closed = this.closures.get(child);
				if (!closed) {
					throw new Error("Missing owned desktop child termination record");
				}
				if (child.exitCode === null && child.signalCode === null) {
					child.kill("SIGTERM");
				}
				const timer = setTimeout(() => child.kill("SIGKILL"), 2000);
				try {
					await closed;
				} finally {
					clearTimeout(timer);
				}
			})
		);
		this.children = [];
		this.closures.clear();
		this.criticalChildren.clear();
		if (this.privateDir) {
			rmSync(this.privateDir, { recursive: true, force: true });
		}
		this.privateDir = null;
		this.authorityFile = null;
		this.vncSocket = null;
	}

	capabilities(): DesktopCapabilities {
		if (this.ready && !this.criticalChildrenAlive()) {
			this.ready = false;
		}
		return {
			available: this.ready,
			reason: this.ready ? undefined : (this.lastError ?? "not started"),
			display: this.ready ? this.displayString() : undefined,
			vncPort: this.ready ? this.opts.vncPort : undefined,
			vncSocket: this.ready ? (this.vncSocket ?? undefined) : undefined,
			resolution: this.ready ? this.opts.resolution : undefined,
		};
	}

	unavailableReason(): string {
		return this.lastError ?? "no virtual display running";
	}

	/**
	 * Capture the display as PNG bytes. The capture tool needs a file path, so
	 * it writes a uniquely named file inside this session's private 0700
	 * directory (owner-only, never shared `/tmp`); the bytes are read back and the file is removed in `finally`,
	 * so no screenshot persists on disk.
	 */
	async screenshot(): Promise<Uint8Array | null> {
		const privateDir = this.privateDir;
		if (!(this.ready && privateDir)) {
			return null;
		}
		const tool = findOnPath(["scrot", "import"]);
		if (!tool) {
			return null;
		}
		const out = join(
			privateDir,
			`screen-${randomBytes(12).toString("hex")}.png`
		);
		try {
			const args = tool.endsWith("scrot")
				? ["-z", out]
				: ["-window", "root", out];
			const captured = await new Promise<boolean>((resolve) => {
				const child = spawn(tool, args, {
					env: {
						...process.env,
						DISPLAY: this.displayString(),
						XAUTHORITY: this.authorityFile ?? undefined,
					},
					stdio: "ignore",
				});
				this.trackChild(child);
				const timer = setTimeout(() => child.kill("SIGKILL"), 10_000);
				child.on("error", () => {
					clearTimeout(timer);
					resolve(false);
				});
				child.on("close", (code) => {
					clearTimeout(timer);
					resolve(code === 0);
				});
			});
			if (!captured) {
				return null;
			}
			const bytes = readFileSync(out);
			return bytes.length > 0 ? new Uint8Array(bytes) : null;
		} catch {
			return null;
		} finally {
			rmSync(out, { force: true });
		}
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
			const env = {
				...process.env,
				DISPLAY: this.displayString(),
				XAUTHORITY: this.authorityFile ?? undefined,
			};
			if (req.type === "click" && req.x !== undefined && req.y !== undefined) {
				await run(
					xdotool,
					["mousemove", String(req.x), String(req.y), "click", "1"],
					env,
					(child) => this.trackChild(child)
				);
			} else if (req.type === "type" && req.text) {
				await run(xdotool, ["type", "--delay", "12", req.text], env, (child) =>
					this.trackChild(child)
				);
			} else if (req.type === "key" && req.key) {
				await run(xdotool, ["key", req.key], env, (child) =>
					this.trackChild(child)
				);
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
	env: NodeJS.ProcessEnv,
	trackChild: (child: ChildProcess) => void
): Promise<void> {
	return new Promise((resolve, reject) => {
		const child = spawn(cmd, args, { env, stdio: "ignore" });
		trackChild(child);
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
	/** PNG bytes of the display, or null when there is none. */
	screenshot(): Promise<Uint8Array | null>;
	start(): Promise<{ ok: boolean; error?: string }>;
	teardown(): void | Promise<void>;
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

	async screenshot(): Promise<Uint8Array | null> {
		return null;
	}

	async input(_req: InputRequest): Promise<InputResult> {
		return { ok: false, error: this.reason };
	}
}

export type DesktopControllerFactory = (
	opts: DesktopOptions
) => DesktopController;

const persistedSessionSchema = z.object({
	version: z.literal(1),
	sessions: z
		.record(
			z.string(),
			z.object({
				agent_id: z.string(),
				display: z.number().int(),
				vnc_port: z.number().int(),
			})
		)
		.refine((sessions) => Object.keys(sessions).length <= MAX_SESSIONS),
});

/**
 * Owns the agent → display map and lazily starts one controller for each session.
 * It never accepts a display or VNC port from the request URL; `agent_id` is only
 * an opaque lookup key. Allocation stays inside this satellite and is persisted
 * atomically in the app's plugin data dir (`RYU_PLUGIN_DATA_DIR`) so Core needs no
 * app-specific route or session logic.
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
		if (current?.capabilities().available) {
			return current;
		}
		const inFlight = this.pending.get(resolvedKey);
		if (inFlight) {
			return inFlight;
		}

		const promise = this.startAllocation(resolvedKey, allocation, current);
		this.pending.set(resolvedKey, promise);
		try {
			return await promise;
		} finally {
			this.pending.delete(resolvedKey);
		}
	}

	private async startAllocation(
		agentId: string,
		allocation: DesktopSessionAllocation,
		previous?: DesktopController
	): Promise<DesktopController> {
		this.controllers.delete(agentId);
		await previous?.teardown();
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
		mkdirSync(dirname(filePath), { recursive: true });
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
			const parsed = persistedSessionSchema.parse(
				JSON.parse(readFileSync(filePath, "utf8"))
			);
			const next = new Map<string, DesktopSessionAllocation>();
			const displays = new Set<number>();
			for (const [key, value] of Object.entries(parsed.sessions)) {
				const normalized = normalizeAgentId(key);
				if (!normalized || normalized !== key) {
					throw new Error("invalid computer session entry");
				}
				const record = value;
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
		// Without a Core-provided data dir there is nowhere authoritative to
		// persist the map, so allocations stay in memory.
		if (!(this.env.RYU_PLUGIN_DATA_DIR?.trim() || this.env.RYU_DIR?.trim())) {
			return null;
		}
		return join(
			resolvePluginDataDir(this.env, "@ryu/desktop"),
			SESSION_FILE_NAME
		);
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
