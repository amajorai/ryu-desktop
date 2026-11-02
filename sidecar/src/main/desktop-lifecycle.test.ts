import { afterEach, expect, test } from "bun:test";
import type { ChildProcess } from "node:child_process";
import {
	chmodSync,
	existsSync,
	mkdtempSync,
	readFileSync,
	rmSync,
	statSync,
	writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { WebSocket } from "ws";
import { z } from "zod";
import { WsBridge } from "./bridge.ts";
import { startControlServer } from "./control.ts";
import { DesktopSessionManager, LinuxDesktopController } from "./desktop.ts";

const roots: string[] = [];
const controllers: LinuxDesktopController[] = [];
const originalPath = process.env.PATH;
// These drive the real LinuxDesktopController through `#!/usr/bin/env node`
// fixture binaries found on a `:`-joined PATH, private Unix sockets, POSIX mode
// bits and POSIX signals. Windows can run none of that, and production never
// builds this controller there (createDesktopController returns the
// unavailable controller off Linux), so they stay active on Linux and macOS.
const isWindows = process.platform === "win32";

afterEach(async () => {
	await Promise.all(
		controllers.splice(0).map((controller) => controller.teardown())
	);
	process.env.PATH = originalPath;
	for (const root of roots.splice(0)) {
		rmSync(root, { recursive: true, force: true });
	}
});

function fixture(authorityExit = 0, serverExit = false) {
	const root = mkdtempSync(join(tmpdir(), "ryu-desktop-lifecycle-"));
	roots.push(root);
	const trace = join(root, "trace.jsonl");
	const script = `#!/usr/bin/env node
const fs = require("node:fs");
const path = require("node:path");
const args = process.argv.slice(2);
const role = path.basename(process.argv[1]);
const trace = ${JSON.stringify(trace)};
const log = (value) => fs.appendFileSync(trace, JSON.stringify(value) + "\\n");
if (role === "xauth") {
 const command = args[args.indexOf("source") + 1];
 const input = fs.readFileSync(command, "utf8");
 const authority = args[1];
 fs.writeFileSync(authority, input);
 log({role,args,authority,input,inputBytes:Buffer.byteLength(input),writtenBytes:fs.statSync(authority).size,commandMode:fs.statSync(command).mode & 0o777});
 process.exitCode = ${authorityExit};
} else {
 if (role === "Xvnc" && ${serverExit}) { process.exit(9); }
 const server = role === "Xvnc" ? require("node:net").createServer(socket => socket.on("data", data => socket.write(data))) : null;
 if (server) setTimeout(() => server.listen(args[args.indexOf("-rfbunixpath") + 1]), 75);
 log({role,args,pid:process.pid,authority:process.env.XAUTHORITY,display:process.env.DISPLAY});
 if (args.includes("--exit")) { process.exit(0); }

 process.on("SIGTERM", () => setTimeout(() => {
  log({role,closing:true,exists:fs.existsSync(process.env.XAUTHORITY)});
  if (server) server.close();
  clearInterval(timer);
 }, 100));
 const timer = setInterval(() => {}, 1000);
}
`;
	for (const name of ["xauth", "Xvnc", "wm", "app"]) {
		writeFileSync(join(root, name), script);
		chmodSync(join(root, name), 0o700);
	}
	process.env.PATH = `${root}:${originalPath ?? ""}`;
	return { root, trace };
}

const traceRecordSchema = z.object({
	role: z.string(),
	args: z.array(z.string()).default([]),
	authority: z.string().optional(),
	input: z.string().optional(),
	inputBytes: z.number().optional(),
	writtenBytes: z.number().optional(),
	commandMode: z.number().optional(),
	display: z.string().optional(),
	pid: z.number().int().optional(),
	closing: z.boolean().optional(),
	exists: z.boolean().optional(),
});
// Fixture children append to the trace while the test reads it, so a read can
// catch a half-written final line. Only newline-terminated lines are complete
// records; every complete line is still parsed strictly.
function records(trace: string) {
	const lines = readFileSync(trace, "utf8").split("\n");
	lines.pop();
	return lines
		.filter((line) => line.trim() !== "")
		.map((line) => traceRecordSchema.parse(JSON.parse(line)));
}
const tcpAddressSchema = z.object({ port: z.number().int() });

async function waitForStarts(trace: string, count: number) {
	for (let attempt = 0; attempt < 100; attempt += 1) {
		if (
			existsSync(trace) &&
			records(trace).filter((record) => !record.closing).length >= count
		) {
			return;
		}
		await Bun.sleep(10);
	}
	throw new Error("Fixture children did not start");
}

test.skipIf(isWindows)(
	"real controller isolates session authority and closes children before removing owned resources",
	async () => {
		const { root, trace } = fixture();
		const make = (display: number) => {
			const controller = new LinuxDesktopController({
				display,
				xvncBin: join(root, "Xvnc"),
				windowManager: [join(root, "wm")],
				starterApps: [[join(root, "app")]],
			});
			controllers.push(controller);
			return controller;
		};
		const first = make(99);
		const second = make(100);
		expect(await first.start()).toEqual({ ok: true });
		expect(await second.start()).toEqual({ ok: true });
		await waitForStarts(trace, 8);
		const auth = records(trace).filter((record) => record.role === "xauth");
		expect(auth).toHaveLength(2);
		const paths = auth.map((record) => String(record.authority));
		expect(paths[0]).not.toBe(paths[1]);
		for (const entry of auth) {
			expect(entry.commandMode).toBe(0o600);
			expect(existsSync(entry.args[4] ?? "")).toBe(false);
		}
		for (const file of paths) {
			expect(statSync(file).mode & 0o777).toBe(0o600);
			expect(statSync(dirname(file)).mode & 0o777).toBe(0o700);
			const expectedBytes = Buffer.byteLength(
				`add :${paths.indexOf(file) === 0 ? 99 : 100} MIT-MAGIC-COOKIE-1 ${"0".repeat(32)}\n`
			);
			expect({
				traceInputBytes: auth.find((record) => record.authority === file)
					?.inputBytes,
				traceWrittenBytes: auth.find((record) => record.authority === file)
					?.writtenBytes,
				currentBytes: statSync(file).size,
			}).toEqual({
				traceInputBytes: expectedBytes,
				traceWrittenBytes: expectedBytes,
				currentBytes: expectedBytes,
			});
			expect(readFileSync(file, "utf8")).toMatch(
				/^add :(99|100) MIT-MAGIC-COOKIE-1 [a-f0-9]{32}\n$/
			);
		}
		expect(auth[0].input).not.toBe(auth[1].input);
		for (const record of records(trace).filter(
			(entry) => entry.role !== "xauth"
		)) {
			const index = record.display === ":99" ? 0 : 1;
			expect(record.authority).toBe(paths[index]);
			if (record.role === "Xvnc") {
				const args = record.args;
				expect(args[args.indexOf("-auth") + 1]).toBe(paths[index]);
				expect(args[args.indexOf("-rfbunixpath") + 1]).toBe(
					join(dirname(paths[index]), "rfb.sock")
				);
			}
		}
		const stopping = first.teardown();
		expect(existsSync(paths[0])).toBe(true);
		await stopping;
		expect(records(trace).filter((record) => record.closing)).toHaveLength(3);
		expect(
			records(trace)
				.filter((record) => record.closing)
				.every((record) => record.exists === true)
		).toBe(true);
		expect(existsSync(dirname(paths[0]))).toBe(false);
		expect(existsSync(paths[1])).toBe(true);
		expect(first.capabilities().available).toBe(false);
		await second.teardown();
		expect(existsSync(dirname(paths[1]))).toBe(false);
	},
	10_000
);

test.skipIf(isWindows)(
	"failed starter spawn waits for owned children and removes authority before returning refusal",
	async () => {
		const { root, trace } = fixture();
		const controller = new LinuxDesktopController({
			xvncBin: join(root, "Xvnc"),
			windowManager: [],
			starterApps: [[join(root, "missing-app")]],
		});
		controllers.push(controller);
		const result = await controller.start();
		expect(result.ok).toBe(false);
		expect(result.error).toContain("ENOENT");
		const authority = String(
			records(trace).find((record) => record.role === "xauth")?.authority
		);
		expect(existsSync(dirname(authority))).toBe(false);
		expect(controller.capabilities().available).toBe(false);
		await controller.teardown();
	}
);

test.skipIf(isWindows)(
	"authority command refusal removes only the owned private directory",
	async () => {
		const { root, trace } = fixture(7);
		const controller = new LinuxDesktopController({
			xvncBin: join(root, "Xvnc"),
			windowManager: [],
			starterApps: [],
		});
		controllers.push(controller);
		expect(await controller.start()).toEqual({
			ok: false,
			error: "Could not configure X display authentication",
		});
		const entries = records(trace);
		expect(entries).toHaveLength(1);
		expect(existsSync(dirname(String(entries[0].authority)))).toBe(false);
		expect(existsSync(root)).toBe(true);
	}
);

test.skipIf(isWindows)(
	"early display-server exit refuses readiness and cleans authority without launching apps",
	async () => {
		const { root, trace } = fixture(0, true);
		const controller = new LinuxDesktopController({
			xvncBin: join(root, "Xvnc"),
			windowManager: [join(root, "wm")],
			starterApps: [[join(root, "app")]],
		});
		controllers.push(controller);
		const result = await controller.start();
		expect(result.ok).toBe(false);
		expect(result.error).toContain("exited before becoming ready");
		expect(controller.capabilities().available).toBe(false);
		const entries = records(trace);
		expect(entries.map((entry) => entry.role)).toEqual(["xauth"]);
		expect(existsSync(dirname(String(entries[0].authority)))).toBe(false);
	}
);

async function waitForUnavailable(controller: LinuxDesktopController) {
	for (let attempt = 0; attempt < 100; attempt++) {
		if (!controller.capabilities().available) {
			return;
		}
		await Bun.sleep(10);
	}
	throw new Error("Required child exit did not invalidate desktop readiness");
}

test.skipIf(isWindows)(
	"optional starter exit leaves the critical desktop processes available",
	async () => {
		const { root, trace } = fixture();
		const controller = new LinuxDesktopController({
			xvncBin: join(root, "Xvnc"),
			windowManager: [join(root, "wm")],
			starterApps: [[join(root, "app"), "--exit"]],
		});
		controllers.push(controller);
		expect(await controller.start()).toEqual({ ok: true });
		await waitForStarts(trace, 4);
		await Bun.sleep(100);
		expect(controller.capabilities().available).toBe(true);
	}
);

test.skipIf(isWindows)(
	"a display-server exit during a later starter await cannot overwrite readiness",
	async () => {
		const { root, trace } = fixture();
		let releaseStarter: (() => void) | undefined;
		const starterCompletion = new Promise<void>((resolve) => {
			releaseStarter = resolve;
		});
		class HeldStarterController extends LinuxDesktopController {
			protected override async spawn(
				cmd: string,
				args: string[],
				display?: string,
				critical?: boolean
			): Promise<ChildProcess> {
				const child = await super.spawn(cmd, args, display, critical);
				if (cmd === join(root, "app")) {
					await starterCompletion;
				}
				return child;
			}
		}
		const controller = new HeldStarterController({
			xvncBin: join(root, "Xvnc"),
			windowManager: [join(root, "wm")],
			starterApps: [[join(root, "app")]],
		});
		controllers.push(controller);
		const starting = controller.start();
		try {
			await waitForStarts(trace, 4);
			const server = records(trace).find((entry) => entry.role === "Xvnc");
			if (!server?.pid) {
				throw new Error("Missing server PID");
			}
			process.kill(server.pid, "SIGKILL");
			let exited = false;
			for (let attempt = 0; attempt < 100; attempt++) {
				try {
					process.kill(server.pid, 0);
				} catch {
					exited = true;
					break;
				}
				await Bun.sleep(10);
			}
			expect(exited).toBe(true);
		} finally {
			releaseStarter?.();
		}
		expect((await starting).ok).toBe(false);
		expect(controller.capabilities().available).toBe(false);
		const auth = records(trace).find((entry) => entry.role === "xauth");
		expect(existsSync(dirname(String(auth?.authority)))).toBe(false);
	},
	10_000
);

const capabilitiesSchema = z.object({
	available: z.boolean(),
	display: z.string(),
	vncSocket: z.string(),
	resolution: z.string().optional(),
	vncPort: z.number().int().optional(),
});
async function readCapabilities(response: Response) {
	return capabilitiesSchema.parse(await response.json());
}

for (const role of ["Xvnc", "wm"]) {
	test.skipIf(isWindows)(
		`HTTP and WS same-Bot concurrent reconnect replace an exited ${role} once`,
		async () => {
			const { root, trace } = fixture();
			let creations = 0;
			const manager = new DesktopSessionManager(
				{ RYU_PLUGIN_DATA_DIR: root },
				(options) => {
					creations++;
					const controller = new LinuxDesktopController({
						...options,
						xvncBin: join(root, "Xvnc"),
						windowManager: [join(root, "wm")],
					});
					controllers.push(controller);
					return controller;
				}
			);
			const bridge = new WsBridge(manager);
			const server = startControlServer(
				manager,
				"reconnect-proof",
				0,
				(req, socket, head) => bridge.handleUpgrade(req, socket, head)
			);
			await new Promise<void>((resolve) => server.once("listening", resolve));
			const address = server.address();
			if (!tcpAddressSchema.safeParse(address).success) {
				throw new Error("Expected TCP server");
			}
			const base = `http://127.0.0.1:${tcpAddressSchema.parse(address).port}/bots/retained-bot`;
			const headers = { Authorization: "Bearer reconnect-proof" };
			const ws = new WebSocket(`${base.replace("http:", "ws:")}/ws`, {
				headers,
			});
			const opened = new Promise<void>((resolve, reject) => {
				ws.once("open", resolve);
				ws.once("error", reject);
			});
			try {
				await opened;
				await waitForStarts(trace, 3);
				const before = await readCapabilities(
					await fetch(`${base}/capabilities`, { headers })
				);
				const allocation = readFileSync(
					join(root, "computer-sessions.json"),
					"utf8"
				);
				const firstAuthority = String(
					records(trace).find((entry) => entry.role === "xauth")?.authority
				);
				const killed = records(trace).find((entry) => entry.role === role);
				if (!killed?.pid) {
					throw new Error("Missing child PID");
				}
				const closed = new Promise<void>((resolve) =>
					ws.once("close", () => resolve())
				);
				process.kill(killed.pid, "SIGKILL");
				const exitedController = controllers.at(-1);
				if (!exitedController) {
					throw new Error("Missing current controller");
				}
				await waitForUnavailable(exitedController);
				if (role === "Xvnc") {
					await closed;
				} else {
					ws.terminate();
				}
				const refused = await fetch(`${base}/capabilities`);
				expect(refused.status).toBe(401);
				expect(await refused.json()).toEqual({ error: "unauthorized" });
				expect(creations).toBe(1);
				expect(
					records(trace).filter((entry) => entry.role === "xauth")
				).toHaveLength(1);
				const replacement = new WebSocket(
					`${base.replace("http:", "ws:")}/ws`,
					{
						headers,
					}
				);
				const reopened = new Promise<void>((resolve, reject) => {
					replacement.once("open", resolve);
					replacement.once("error", reject);
				});
				try {
					const responses = await Promise.all([
						fetch(`${base}/capabilities`, { headers }),
						fetch(`${base}/capabilities`, { headers }),
						reopened,
					]);
					const firstResponse = responses[0];
					const secondResponse = responses[1];
					const after = await readCapabilities(firstResponse);
					expect(await secondResponse.json()).toEqual(after);
					expect(after.available).toBe(true);
					expect(after.display).toBe(before.display);
					expect(after.vncSocket).not.toBe(before.vncSocket);
					expect(creations).toBe(2);
					expect(
						readFileSync(join(root, "computer-sessions.json"), "utf8")
					).toBe(allocation);
					const authorities = records(trace).filter(
						(entry) => entry.role === "xauth"
					);
					expect(authorities).toHaveLength(2);
					expect(authorities[0]?.input).not.toBe(authorities[1]?.input);
					expect(existsSync(dirname(firstAuthority))).toBe(false);
					const echoed = new Promise<string>((resolve) =>
						replacement.once("message", (data) => resolve(data.toString()))
					);
					replacement.send(Buffer.from("RFB reconnect exact bytes\n"));
					expect(await echoed).toBe("RFB reconnect exact bytes\n");
				} finally {
					replacement.terminate();
				}
			} finally {
				ws.terminate();
				bridge.close();
				server.closeAllConnections();
				await new Promise<void>((resolve) => server.close(() => resolve()));
			}
		},
		15_000
	);
}
