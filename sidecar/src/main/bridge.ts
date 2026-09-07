// Websockify bridge for the Ryu Virtual Desktop sidecar.
//
// Accepts RFB-over-WebSocket connections (which arrive through Core's generic
// `/api/ext/ws/...` tunnel) and pumps bytes onto the loopback VNC TCP port. This is
// what makes the desktop stream interactive: pixels come down the socket, and the
// panel's mouse/keyboard events go back up the same socket into the VNC server.
//
// Exported as a class so the test suite can wire it against a fake echo VNC server
// and prove byte round-trips without an X server.

import type { IncomingMessage } from "node:http";
import { connect, type Socket } from "node:net";
import { WebSocket, WebSocketServer } from "ws";
import type { DesktopController, DesktopSessionManager } from "./desktop.ts";

type DesktopControllerSource =
	| DesktopController
	| Pick<DesktopSessionManager, "controllerFor">;

export class WsBridge {
	private readonly wss = new WebSocketServer({ noServer: true });

	constructor(private readonly source: DesktopControllerSource) {}

	/** Accept an upgraded socket from the control server's `upgrade` event. */
	async handleUpgrade(
		req: IncomingMessage,
		socket: Socket,
		head: Buffer
	): Promise<void> {
		const url = new URL(req.url ?? "/", "http://127.0.0.1");
		let agentId: string | undefined;
		if (url.pathname !== "/ws") {
			const match = url.pathname.match(/^\/bots\/([^/]+)\/ws$/);
			if (!match) {
				socket.end("HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n");
				return;
			}
			try {
				agentId = decodeURIComponent(match[1] ?? "").trim();
			} catch {
				socket.end("HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n");
				return;
			}
			if (!agentId) {
				socket.end("HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n");
				return;
			}
		}
		const controller =
			"controllerFor" in this.source
				? await this.source.controllerFor(agentId)
				: this.source;
		const capabilities = controller.capabilities();
		if (!capabilities.available) {
			socket.end(
				"HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\n\r\n"
			);
			return;
		}
		this.wss.handleUpgrade(req, socket, head, (ws) => {
			this.handleConnection(ws, controller);
		});
	}

	private handleConnection(ws: WebSocket, controller: DesktopController): void {
		const capabilities = controller.capabilities();
		if (!capabilities.available || capabilities.vncPort === undefined) {
			ws.close(1011, capabilities.reason ?? "no display");
			return;
		}

		const tcp = connect(capabilities.vncPort, "127.0.0.1");
		tcp.on("error", () => ws.close(1011, "vnc unreachable"));
		ws.on("error", () => tcp.destroy());

		tcp.on("data", (data) => {
			if (ws.readyState === WebSocket.OPEN) {
				ws.send(data);
			}
		});
		ws.on("message", (data) => {
			if (tcp.destroyed) {
				return;
			}
			// RFB is a binary protocol; `ws` delivers Buffer for binary, string for
			// text. Accept text as a lenient fallback but always send bytes.
			const bytes = Buffer.isBuffer(data) ? data : Buffer.from(String(data));
			tcp.write(bytes);
		});
		ws.on("close", () => tcp.destroy());
		tcp.on("close", () => ws.close());
	}

	close(): void {
		this.wss.close();
	}
}

export function createWsBridge(source: DesktopControllerSource): WsBridge {
	return new WsBridge(source);
}
