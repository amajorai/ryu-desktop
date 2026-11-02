// Websockify bridge integration test for the Ryu Virtual Desktop sidecar.
//
// Proves the full interactive path WITHOUT a real X server: a fake VNC server on a
// loopback TCP port echoes bytes back; a real WebSocket client connects to the
// sidecar's `/ws` bridge through the real control server, sends RFB-shaped bytes, and
// asserts they round-trip through the TCP server and back. This is the exact pump the
// panel uses — if bytes round-trip here, mouse/keyboard and pixels will traverse it
// end to end on a real node.

import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { mkdtempSync, rmdirSync } from "node:fs";
import { createServer, type Server } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { type RawData, WebSocket } from "ws";
import { z } from "zod";
import { WsBridge } from "./bridge.ts";
import { startControlServer } from "./control.ts";

const tcpAddressSchema = z.object({ port: z.number().int() });
function messageBytes(data: RawData): Buffer {
	if (Array.isArray(data)) {
		return Buffer.concat(data);
	}
	return Buffer.isBuffer(data) ? data : Buffer.from(data);
}

/** A fake but faithful VNC stand-in: echoes each chunk back prefixed `OK:`. */
function echoVncServer(): Promise<{ server: Server; port: number }> {
	return new Promise((resolve) => {
		const server = createServer((socket) => {
			socket.on("data", (data) => {
				socket.write(Buffer.concat([Buffer.from("OK:"), data]));
			});
		});
		server.listen(0, "127.0.0.1", () => {
			resolve({ server, port: tcpAddressSchema.parse(server.address()).port });
		});
	});
}

/** A controller that reports ready WITHOUT touching a real display. */
class ReadyStubController {
	private readonly port: number;
	constructor(
		vncPort: number,
		private readonly socketPath?: string
	) {
		this.port = vncPort;
	}
	async start(): Promise<{ ok: boolean; error?: string }> {
		return { ok: true };
	}
	teardown(): void {}
	capabilities() {
		return {
			available: true,
			display: ":99",
			vncPort: this.port,
			vncSocket: this.socketPath,
			resolution: "1600x1000x24",
		};
	}
	unavailableReason(): string {
		return "";
	}
	async screenshot(): Promise<Uint8Array | null> {
		return null;
	}
	async input(): Promise<{ ok: boolean; error?: string }> {
		return { ok: true };
	}
}

test("authenticated bridge uses the private socket even when a TCP port is advertised", async () => {
	const root = mkdtempSync(join(tmpdir(), "ryu-rfb-proof-"));
	const socketPath =
		process.platform === "win32"
			? `\\\\.\\pipe\\ryu-rfb-${crypto.randomUUID()}`
			: join(root, "rfb.sock");
	const peer = createServer((socket) =>
		socket.on("data", (data) => socket.write(data))
	);
	await new Promise<void>((resolve, reject) => {
		peer.once("error", reject);
		peer.listen(socketPath, resolve);
	});
	const controller = new ReadyStubController(1, socketPath);
	const bridge = new WsBridge(controller);
	const server = startControlServer(
		controller,
		"private-socket-proof",
		0,
		(req, socket, head) => bridge.handleUpgrade(req, socket, head)
	);
	const address = server.address();
	if (!tcpAddressSchema.safeParse(address).success) {
		throw new Error("Expected TCP control listener");
	}
	const ws = new WebSocket(
		`ws://127.0.0.1:${tcpAddressSchema.parse(address).port}/ws`,
		{
			headers: { Authorization: "Bearer private-socket-proof" },
		}
	);
	try {
		await new Promise<void>((resolve, reject) => {
			ws.once("open", resolve);
			ws.once("error", reject);
		});
		const response = new Promise<Buffer>((resolve, reject) => {
			const timer = setTimeout(
				() => reject(new Error("Private socket timeout")),
				3000
			);
			ws.once("message", (data) => {
				clearTimeout(timer);
				resolve(messageBytes(data));
			});
		});
		ws.send(Buffer.from("RFB 003.008\n"));
		expect((await response).toString()).toBe("RFB 003.008\n");
	} finally {
		ws.terminate();
		bridge.close();
		server.close();
		await new Promise<void>((resolve) => peer.close(() => resolve()));
		rmdirSync(root);
	}
});

describe("ryu-desktop websockify bridge", () => {
	let vnc: { server: Server; port: number };
	let server: ReturnType<typeof startControlServer>;
	let controlPort: number;

	beforeAll(async () => {
		vnc = await echoVncServer();
		const controller = new ReadyStubController(vnc.port);
		const bridge = new WsBridge(controller);
		server = startControlServer(
			controller,
			"bridge-tok",
			0,
			(req, socket, head) => bridge.handleUpgrade(req, socket, head)
		);
		controlPort = tcpAddressSchema.parse(server.address()).port;
	});

	afterAll(() => {
		vnc.server.close();
		server.close();
	});

	test("WS → TCP → WS round-trips RFB bytes through the bridge", async () => {
		const ws = new WebSocket(`ws://127.0.0.1:${controlPort}/ws`, {
			headers: { Authorization: "Bearer bridge-tok" },
		});
		const opened = new Promise<void>((resolve, reject) => {
			ws.on("open", resolve);
			ws.on("error", reject);
		});
		await opened;

		// RFB-shaped binary: a 12-byte protocol handshake is just bytes to the pump.
		const sent = Buffer.from([
			0x52, 0x46, 0x42, 0x20, 0x30, 0x30, 0x33, 0x2e, 0x30, 0x30, 0x38, 0x0a,
		]);
		const echoed = new Promise<Buffer>((resolve, reject) => {
			const timer = setTimeout(
				() => reject(new Error("round-trip timeout")),
				5000
			);
			ws.on("message", (data) => {
				clearTimeout(timer);
				resolve(messageBytes(data));
			});
			ws.send(sent);
		});

		const got = await echoed;
		expect(Buffer.from(got).subarray(0, 3).toString()).toBe("OK:");
		expect(Buffer.from(got).subarray(3)).toEqual(sent);
		ws.close();
	});

	test("a socket to /ws without a bearer is refused by the control server", async () => {
		const ws = new WebSocket(`ws://127.0.0.1:${controlPort}/ws`);
		// The security property is "never establishes" — whether the client sees a 401
		// or a connection reset, no RFB bytes can be exchanged. Assert the `open` event
		// does not fire (the socket errors or closes instead).
		const outcome = await new Promise<string>((resolve) => {
			const timer = setTimeout(() => resolve("timeout"), 3000);
			ws.on("open", () => {
				clearTimeout(timer);
				resolve("OPENED");
			});
			ws.on("error", () => {
				clearTimeout(timer);
				resolve("ERROR");
			});
			ws.on("close", () => {
				clearTimeout(timer);
				resolve("CLOSED");
			});
		});
		expect(outcome).not.toBe("OPENED");
		ws.close();
	});
});
