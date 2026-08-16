// Websockify bridge for the Ryu Virtual Desktop sidecar.
//
// Accepts RFB-over-WebSocket connections (which arrive through Core's generic
// `/api/ext/ws/...` tunnel) and pumps bytes onto the loopback VNC TCP port. This is
// what makes the desktop stream interactive: pixels come down the socket, and the
// panel's mouse/keyboard events go back up the same socket into the VNC server.
//
// Exported as a class so the test suite can wire it against a fake echo VNC server
// and prove byte round-trips without an X server.

import { connect, type Socket } from "node:net";
import type { IncomingMessage } from "node:http";
import { WebSocketServer, WebSocket } from "ws";
import type { DesktopController } from "./desktop.ts";

export class WsBridge {
	private readonly wss = new WebSocketServer({ noServer: true });

	constructor(private readonly controller: DesktopController) {
		this.wss.on("connection", (ws) => this.handleConnection(ws));
	}

	/** Accept an upgraded socket from the control server's `upgrade` event. */
	handleUpgrade(req: IncomingMessage, socket: Socket, head: Buffer): void {
		const capabilities = this.controller.capabilities();
		if (!capabilities.available) {
			socket.end(
				"HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\n\r\n"
			);
			return;
		}
		this.wss.handleUpgrade(req, socket, head, (ws) => {
			this.wss.emit("connection", ws, req);
		});
	}

	private handleConnection(ws: WebSocket): void {
		const capabilities = this.controller.capabilities();
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

export function createWsBridge(controller: DesktopController): WsBridge {
	return new WsBridge(controller);
}
